//! Spoofed-IP reachability and latency check mode ("IP tester").
//!
//! Sweeps a candidate list of spoofed source IPs and measures which ones can
//! round-trip a CandyTunnel SYN/SYN-ACK through the real path, and how fast.
//!
//! Improvements over the naive one-probe sweep:
//!   * **Multiple probes per IP** — several SYNs are fired per candidate and the
//!     *fastest* reply is kept, smoothing out single-packet loss/jitter. An
//!     unreachable IP still costs only one `timeout` because all probes are
//!     in-flight concurrently.
//!   * **Deduplicated input** — repeated IPs in the list are tested once.
//!   * **Ranked output** — reachable IPs are written fastest-first, followed by
//!     the timeouts, so the best spoof candidates are at the top of the file.
//!   * **Live progress + summary** — periodic progress with ETA and a final
//!     summary (reachable count, best/median latency).

use std::net::Ipv4Addr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{bail, Context, Result};
use async_channel as mpsc;
use bytes::Bytes;
use dashmap::DashMap;
use pnet_packet::tcp::TcpFlags;
use tokio::sync::Semaphore;

use crate::config::{Config, TunnelProtocol};
use crate::packet::{CandyPacket, PacketKind};
use crate::raw_socket::{InPacket, OutPacket, PortFilter, RawReceiver, RawSender};

#[derive(Debug, Clone)]
pub struct CheckOptions {
    pub ips_path: String,
    pub out_path: String,
    pub timeout: Duration,
    pub workers: usize,
    /// Number of SYN probes fired per candidate IP (fastest reply wins).
    pub probes: usize,
}

/// Outcome for a single candidate IP.
struct IpResult {
    ip: Ipv4Addr,
    /// Fastest round-trip latency in ms, or `None` if every probe timed out.
    latency_ms: Option<u64>,
}

pub async fn run_spoof_check(cfg: Arc<Config>, opts: CheckOptions) -> Result<()> {
    if cfg.uplink_protocol == TunnelProtocol::Quic || cfg.downlink_protocol == TunnelProtocol::Quic
    {
        bail!("check mode is not supported with quic transport");
    }

    let ips = read_ip_list(&opts.ips_path)?;
    if ips.is_empty() {
        bail!("no valid IPv4 addresses found in {}", opts.ips_path);
    }

    let probes = opts.probes.max(1);
    let workers = opts.workers.max(1);
    log::info!(
        "check start: {} unique IP(s), {} probe(s)/ip, timeout={}ms, workers={}",
        ips.len(),
        probes,
        opts.timeout.as_millis(),
        workers
    );

    let sender = RawSender::spawn(cfg.io_channel_capacity, cfg.xor_cipher(), cfg.dpi_obfuscation())?;

    let data_ports = cfg.build_data_port_pool()?;
    if let Some(ports) = &data_ports {
        log::debug!("check shuffle pool size={}", ports.len());
    }
    let port_filter = PortFilter::new(cfg.data_port, data_ports.clone(), cfg.shuffle_port_range());

    let mut allowed = cfg.allowed_peers.clone();
    allowed.push(cfg.peer_real_ip);
    allowed.extend(cfg.peer_spoofed_ips());

    let mut receiver = RawReceiver::spawn(
        cfg.downlink_protocol,
        port_filter,
        cfg.icmp_id,
        cfg.random_icmp_id,
        allowed,
        cfg.mux_fec_config(),
        cfg.io_channel_capacity,
        cfg.xor_cipher(),
        cfg.dpi_obfuscation(),
        cfg.effective_recv_batch(),
    )?;

    // tunnel_id -> notifier that the matching SYN-ACK has arrived.
    let pending: Arc<DashMap<u32, mpsc::Sender<()>>> = Arc::new(DashMap::new());
    let pending_rx = pending.clone();
    tokio::spawn(async move {
        while let Some(pkt) = receiver.recv().await {
            handle_incoming(pkt, &pending_rx);
        }
    });

    let total = ips.len();
    let done = Arc::new(AtomicUsize::new(0));
    let reachable = Arc::new(AtomicUsize::new(0));
    let sem = Arc::new(Semaphore::new(workers));
    let started = Instant::now();

    // Periodic progress reporter.
    let progress = {
        let done = done.clone();
        let reachable = reachable.clone();
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(Duration::from_secs(2)).await;
                let d = done.load(Ordering::Relaxed);
                if d >= total {
                    break;
                }
                let r = reachable.load(Ordering::Relaxed);
                let elapsed = started.elapsed().as_secs_f64().max(0.001);
                let rate = d as f64 / elapsed;
                let eta = if rate > 0.0 {
                    ((total - d) as f64 / rate) as u64
                } else {
                    0
                };
                log::info!(
                    "check progress: {}/{} ({:.0}%) reachable={} ~{}s left",
                    d,
                    total,
                    100.0 * d as f64 / total as f64,
                    r,
                    eta
                );
            }
        })
    };

    let mut tasks = Vec::with_capacity(total);
    for ip in ips {
        let permit = sem.clone().acquire_owned().await?;
        let sender = sender.clone();
        let pending = pending.clone();
        let cfg = cfg.clone();
        let data_ports = data_ports.clone();
        let timeout = opts.timeout;
        let done = done.clone();
        let reachable = reachable.clone();
        tasks.push(tokio::spawn(async move {
            let _permit = permit;
            let latency_ms =
                match check_one_ip(&cfg, &sender, &pending, ip, timeout, probes, &data_ports).await
                {
                    Ok(v) => v,
                    Err(e) => {
                        log::warn!("check {} failed: {}", ip, e);
                        None
                    }
                };
            done.fetch_add(1, Ordering::Relaxed);
            if latency_ms.is_some() {
                reachable.fetch_add(1, Ordering::Relaxed);
            }
            IpResult { ip, latency_ms }
        }));
    }

    let mut results = Vec::with_capacity(total);
    for t in tasks {
        if let Ok(r) = t.await {
            results.push(r);
        }
    }
    progress.abort();

    write_results(&opts.out_path, &mut results)
        .await
        .with_context(|| format!("writing results to {}", opts.out_path))?;

    log_summary(&results, &opts.out_path, started.elapsed());
    Ok(())
}

fn handle_incoming(pkt: InPacket, pending: &DashMap<u32, mpsc::Sender<()>>) {
    if pkt.pkt.kind != PacketKind::SynAck {
        return;
    }
    if let Some((_, tx)) = pending.remove(&pkt.pkt.tunnel_id) {
        // Non-blocking: the waiter only needs the first notification.
        let _ = tx.try_send(());
    }
}

/// Fire `probes` SYNs for one candidate IP and return the fastest RTT (ms).
async fn check_one_ip(
    cfg: &Config,
    sender: &RawSender,
    pending: &DashMap<u32, mpsc::Sender<()>>,
    spoof_ip: Ipv4Addr,
    timeout: Duration,
    probes: usize,
    data_ports: &Option<Arc<Vec<u16>>>,
) -> Result<Option<u64>> {
    // One notifier shared by all probes for this IP; the first reply wins.
    let (tx, rx) = mpsc::bounded::<()>(1);
    let mut tids = Vec::with_capacity(probes);

    let start = Instant::now();
    for _ in 0..probes {
        // Pick a tunnel_id not already in flight to avoid cross-probe aliasing.
        let tunnel_id = loop {
            let candidate: u32 = rand::random();
            if !pending.contains_key(&candidate) {
                break candidate;
            }
        };
        let seq: u32 = rand::random();
        let syn = CandyPacket::new_syn(tunnel_id, seq);
        pending.insert(tunnel_id, tx.clone());
        tids.push(tunnel_id);

        let out = build_out_packet(cfg, spoof_ip, syn.seq, syn.encode(), data_ports)?;
        sender.send(out).await?;
    }

    let latency = match tokio::time::timeout(timeout, rx.recv()).await {
        Ok(Ok(())) => Some(start.elapsed().as_millis() as u64),
        _ => None,
    };

    // Clean up any probes that never got a reply.
    for tid in tids {
        pending.remove(&tid);
    }

    Ok(latency)
}

/// Write results ranked fastest-first, timeouts last.
async fn write_results(path: &str, results: &mut [IpResult]) -> Result<()> {
    results.sort_by(|a, b| match (a.latency_ms, b.latency_ms) {
        (Some(x), Some(y)) => x.cmp(&y).then(a.ip.cmp(&b.ip)),
        (Some(_), None) => std::cmp::Ordering::Less,
        (None, Some(_)) => std::cmp::Ordering::Greater,
        (None, None) => a.ip.cmp(&b.ip),
    });

    let reachable = results.iter().filter(|r| r.latency_ms.is_some()).count();
    let mut out = String::with_capacity(results.len() * 24 + 128);
    out.push_str("# CandyTunnel spoofed-IP check results (ranked fastest-first)\n");
    out.push_str(&format!(
        "# total={} reachable={} timeouts={}\n",
        results.len(),
        reachable,
        results.len() - reachable
    ));
    out.push_str("# columns: ip  latency_ms|timeout\n");
    for r in results.iter() {
        match r.latency_ms {
            Some(ms) => out.push_str(&format!("{:<15} {}\n", r.ip, ms)),
            None => out.push_str(&format!("{:<15} timeout\n", r.ip)),
        }
    }

    tokio::fs::write(path, out).await.map_err(Into::into)
}

fn log_summary(results: &[IpResult], out_path: &str, elapsed: Duration) {
    let mut lats: Vec<u64> = results.iter().filter_map(|r| r.latency_ms).collect();
    lats.sort_unstable();
    let reachable = lats.len();
    log::info!("┌─ Check Complete ───────────────────────────────");
    log::info!(
        "│  tested={}  reachable={}  timeouts={}  in {:.1}s",
        results.len(),
        reachable,
        results.len() - reachable,
        elapsed.as_secs_f64()
    );
    if reachable > 0 {
        let best = lats[0];
        let median = lats[reachable / 2];
        let worst = lats[reachable - 1];
        // Best candidate IP is the first reachable entry (results are sorted).
        if let Some(best_ip) = results.iter().find(|r| r.latency_ms == Some(best)) {
            log::info!("│  best={}  ({}ms)", best_ip.ip, best);
        }
        log::info!("│  latency ms: min={} median={} max={}", best, median, worst);
    } else {
        log::warn!("│  no spoofed IPs were reachable — check server --check-allow-any");
    }
    log::info!("│  ranked results written to {}", out_path);
    log::info!("└────────────────────────────────────────────────");
}

fn build_out_packet(
    cfg: &Config,
    spoof_ip: Ipv4Addr,
    seq: u32,
    payload: Bytes,
    data_ports: &Option<Arc<Vec<u16>>>,
) -> Result<OutPacket> {
    let data_port = crate::config::pick_data_port(cfg.data_port, data_ports);
    match cfg.uplink_protocol {
        TunnelProtocol::Udp => Ok(OutPacket::Udp {
            src_ip: spoof_ip,
            dst_ip: cfg.peer_real_ip,
            src_port: data_port,
            dst_port: data_port,
            payload,
        }),
        TunnelProtocol::Icmp => Ok(OutPacket::Icmp {
            src_ip: spoof_ip,
            dst_ip: cfg.peer_real_ip,
            id: cfg.pick_icmp_id(),
            seq: (seq & 0xffff) as u16,
            payload,
        }),
        TunnelProtocol::Proto58 => Ok(OutPacket::Proto58 {
            src_ip: spoof_ip,
            dst_ip: cfg.peer_real_ip,
            payload,
        }),
        TunnelProtocol::Tcp => Ok(OutPacket::Tcp {
            src_ip: spoof_ip,
            dst_ip: cfg.peer_real_ip,
            src_port: data_port,
            dst_port: data_port,
            seq,
            ack: seq.wrapping_add(payload.len().max(1) as u32),
            flags: (TcpFlags::PSH | TcpFlags::ACK) as u8,
            payload,
        }),
        TunnelProtocol::Ipip => Ok(OutPacket::Ipip {
            src_ip: spoof_ip,
            dst_ip: cfg.peer_real_ip,
            payload,
        }),
        TunnelProtocol::Gre => Ok(OutPacket::Gre {
            src_ip: spoof_ip,
            dst_ip: cfg.peer_real_ip,
            payload,
        }),
        TunnelProtocol::Quic => bail!("check mode does not support quic"),
    }
}

/// Read and de-duplicate the candidate IP list (order-preserving).
fn read_ip_list(path: &str) -> Result<Vec<Ipv4Addr>> {
    let content = std::fs::read_to_string(path).with_context(|| format!("read {}", path))?;
    let mut seen = std::collections::HashSet::new();
    let mut out = Vec::new();
    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        // Accept bare IPs and "ip<whitespace>…" lines (e.g. a prior results file).
        let token = line.split_whitespace().next().unwrap_or("");
        if let Ok(ip) = token.parse::<Ipv4Addr>() {
            if seen.insert(ip) {
                out.push(ip);
            }
        }
    }
    Ok(out)
}
