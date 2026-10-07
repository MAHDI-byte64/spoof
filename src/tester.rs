//! Spoofed-IP tester: which source addresses survive the path, and how well.
//!
//! Two machines take part. The **sender** forges packets from every candidate
//! address towards the other machine; the **receiver** listens for them and
//! counts, per source address, how many arrived. An address whose packets come
//! through with no more than `max_loss_pct` loss can be used as a spoofed
//! source in that direction. Run it once each way: the receiver's list on the
//! Iran side is the list the foreign server may spoof from, and vice versa.
//!
//! Probes:
//! * `tcp`  — a bare SYN to `port` (what a firewall sees most often)
//! * `udp`  — a datagram to `port` carrying an 8-byte marker
//! * `icmp` — an echo request with the tester's identifier and marker
//!
//! The marker and port filters keep the receiver from counting ordinary traffic
//! that happens to come from a candidate address.

use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::os::unix::io::RawFd;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use anyhow::{bail, Result};
use serde::{Deserialize, Serialize};

use crate::iplist::IpRangeSet;
use crate::raw_socket::{
    build_icmp_echo, build_tcp_packet, build_udp_packet, create_raw_recv_socket,
    create_raw_send_socket, dst_sockaddr, raw_sendto_sa,
};

/// Payload carried by UDP and ICMP probes.
const MARKER: &[u8; 8] = b"CTIPTST1";
/// ICMP echo identifier used by probes.
const ICMP_ID: u16 = 0x4354;
/// Largest candidate list accepted.  A /12 at ten packets per address is
/// already ten million packets; past this it is a mistake, not a test.
pub const MAX_CANDIDATES: u64 = 1 << 20;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Mode {
    Sender,
    Receiver,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Probe {
    Tcp,
    Udp,
    Icmp,
}

impl Probe {
    fn ip_proto(self) -> libc::c_int {
        match self {
            Probe::Tcp => libc::IPPROTO_TCP,
            Probe::Udp => libc::IPPROTO_UDP,
            Probe::Icmp => libc::IPPROTO_ICMP,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TesterConfig {
    pub mode: Mode,
    pub protocol: Probe,
    /// Where the sender aims its probes (the receiver's real IP).
    #[serde(default)]
    pub target: Option<Ipv4Addr>,
    /// Destination port for TCP/UDP probes (both sides must agree).
    #[serde(default = "default_port")]
    pub port: u16,
    /// Probes per candidate address (both sides must agree).
    #[serde(default = "default_packets")]
    pub packets_per_ip: u32,
    /// How long the receiver listens, in seconds.
    #[serde(default = "default_timeout")]
    pub timeout_secs: u64,
    /// Highest loss, in percent, an address may show and still pass.
    #[serde(default = "default_max_loss")]
    pub max_loss_pct: f64,
    /// Sender pacing in packets per second (0 = as fast as possible).
    #[serde(default = "default_rate")]
    pub rate_pps: u32,
}

fn default_port() -> u16 { 443 }
fn default_packets() -> u32 { 10 }
fn default_timeout() -> u64 { 60 }
fn default_max_loss() -> f64 { 20.0 }
fn default_rate() -> u32 { 3000 }

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Status {
    Idle,
    Running,
    Done,
    Stopped,
    Error,
}

#[derive(Debug, Clone, Serialize)]
pub struct TesterState {
    pub status: Status,
    pub mode: Option<Mode>,
    pub protocol: Option<Probe>,
    pub error: Option<String>,
    /// 0–100.
    pub progress: u8,
    /// Candidate addresses in the list.
    pub total_ips: u64,
    /// Sender: probes put on the wire.  Receiver: probes counted.
    pub packets: u64,
    /// Receiver: candidates heard from at least once.
    pub heard_ips: u64,
    /// Receiver: candidates within the loss limit.
    pub passed_ips: u64,
    pub elapsed_secs: u64,
    pub config: Option<TesterConfig>,
}

#[derive(Debug, Clone, Serialize)]
pub struct IpResult {
    pub ip: Ipv4Addr,
    pub received: u32,
    pub expected: u32,
    pub loss_pct: f64,
    pub passed: bool,
}

struct Shared {
    state: TesterState,
    started: Option<Instant>,
    received: HashMap<Ipv4Addr, u32>,
}

/// One tester run at a time; cheap to clone and share.
#[derive(Clone)]
pub struct Tester {
    shared: Arc<Mutex<Shared>>,
    cancel: Arc<AtomicBool>,
}

impl Default for Tester {
    fn default() -> Self {
        Self::new()
    }
}

impl Tester {
    pub fn new() -> Self {
        Self {
            shared: Arc::new(Mutex::new(Shared {
                state: idle_state(),
                started: None,
                received: HashMap::new(),
            })),
            cancel: Arc::new(AtomicBool::new(false)),
        }
    }

    /// Start a run in the background.  Fails if one is already running or the
    /// raw socket cannot be opened (not root / no CAP_NET_RAW).
    pub fn start(&self, cfg: TesterConfig, candidates: IpRangeSet) -> Result<()> {
        if candidates.is_empty() {
            bail!("the candidate list is empty");
        }
        if candidates.total() > MAX_CANDIDATES {
            bail!("{} candidate addresses is more than the limit of {}", candidates.total(), MAX_CANDIDATES);
        }
        if cfg.packets_per_ip == 0 {
            bail!("packets per IP must be at least 1");
        }
        if cfg.mode == Mode::Sender && cfg.target.is_none() {
            bail!("the sender needs a target IP");
        }

        let fd = match cfg.mode {
            Mode::Sender => create_raw_send_socket()?,
            Mode::Receiver => {
                let fd = create_raw_recv_socket(cfg.protocol.ip_proto())?;
                set_recv_timeout(fd, Duration::from_millis(200));
                fd
            }
        };

        {
            let mut sh = self.shared.lock().unwrap();
            if sh.state.status == Status::Running {
                unsafe { libc::close(fd) };
                bail!("a test is already running");
            }
            sh.state = TesterState {
                status: Status::Running,
                mode: Some(cfg.mode),
                protocol: Some(cfg.protocol),
                total_ips: candidates.total(),
                config: Some(cfg.clone()),
                ..idle_state()
            };
            sh.started = Some(Instant::now());
            sh.received.clear();
        }
        self.cancel.store(false, Ordering::SeqCst);

        let me = self.clone();
        std::thread::Builder::new()
            .name(format!("iptest-{:?}", cfg.mode).to_lowercase())
            .spawn(move || {
                let res = match cfg.mode {
                    Mode::Sender => me.run_sender(fd, &cfg, &candidates),
                    Mode::Receiver => me.run_receiver(fd, &cfg, &candidates),
                };
                unsafe { libc::close(fd) };
                let mut sh = me.shared.lock().unwrap();
                sh.state.elapsed_secs = sh.started.map(|s| s.elapsed().as_secs()).unwrap_or(0);
                match res {
                    Err(e) => {
                        sh.state.status = Status::Error;
                        sh.state.error = Some(format!("{:#}", e));
                    }
                    Ok(()) if me.cancel.load(Ordering::SeqCst) => sh.state.status = Status::Stopped,
                    Ok(()) => {
                        sh.state.status = Status::Done;
                        sh.state.progress = 100;
                    }
                }
            })?;
        Ok(())
    }

    /// Ask a running test to stop.  A receiver keeps what it has counted.
    pub fn stop(&self) {
        self.cancel.store(true, Ordering::SeqCst);
    }

    pub fn state(&self) -> TesterState {
        let mut sh = self.shared.lock().unwrap();
        if sh.state.status == Status::Running {
            sh.state.elapsed_secs = sh.started.map(|s| s.elapsed().as_secs()).unwrap_or(0);
        }
        if sh.state.mode == Some(Mode::Receiver) {
            let (heard, passed) = tally(&sh.received, sh.state.config.as_ref());
            sh.state.heard_ips = heard;
            sh.state.passed_ips = passed;
        }
        sh.state.clone()
    }

    /// Receiver results, best first: fewest lost probes, then address order.
    pub fn results(&self) -> Vec<IpResult> {
        let sh = self.shared.lock().unwrap();
        let Some(cfg) = sh.state.config.as_ref() else { return Vec::new() };
        let mut out: Vec<IpResult> = sh
            .received
            .iter()
            .map(|(ip, n)| score(*ip, *n, cfg))
            .collect();
        out.sort_by(|a, b| {
            a.loss_pct
                .partial_cmp(&b.loss_pct)
                .unwrap_or(std::cmp::Ordering::Equal)
                .then(u32::from(a.ip).cmp(&u32::from(b.ip)))
        });
        out
    }

    fn run_sender(&self, fd: RawFd, cfg: &TesterConfig, candidates: &IpRangeSet) -> Result<()> {
        let target = cfg.target.expect("checked in start");
        let addr = dst_sockaddr(target);
        let total = candidates.total().max(1);
        let started = Instant::now();
        let mut sent: u64 = 0;
        let mut done_ips: u64 = 0;
        let mut first_err: Option<String> = None;
        let mut errors: u64 = 0;

        candidates.for_each(|src| {
            for i in 0..cfg.packets_per_ip {
                if self.cancel.load(Ordering::Relaxed) {
                    return false;
                }
                let pkt = build_probe(cfg, src, target, i);
                match raw_sendto_sa(fd, &pkt, &addr) {
                    Ok(()) => sent += 1,
                    Err(e) => {
                        errors += 1;
                        first_err.get_or_insert_with(|| format!("{:#}", e));
                    }
                }
                pace(started, sent + errors, cfg.rate_pps);
            }
            done_ips += 1;
            if done_ips.is_multiple_of(64) || done_ips == total {
                let mut sh = self.shared.lock().unwrap();
                sh.state.packets = sent;
                sh.state.progress = ((done_ips * 100) / total).min(100) as u8;
            }
            true
        });

        self.shared.lock().unwrap().state.packets = sent;
        if sent == 0 {
            if let Some(e) = first_err {
                bail!("no probe could be sent: {}", e);
            }
        }
        if errors > 0 {
            log::warn!("iptest sender: {} of {} probes failed to send", errors, sent + errors);
        }
        Ok(())
    }

    fn run_receiver(&self, fd: RawFd, cfg: &TesterConfig, candidates: &IpRangeSet) -> Result<()> {
        let deadline = Duration::from_secs(cfg.timeout_secs.max(1));
        let started = Instant::now();
        let mut buf = vec![0u8; 65535];
        let mut counted: u64 = 0;

        while started.elapsed() < deadline && !self.cancel.load(Ordering::Relaxed) {
            let n = unsafe {
                libc::recv(fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len(), 0)
            };
            if n > 0 {
                if let Some(src) = match_probe(&buf[..n as usize], cfg, candidates) {
                    counted += 1;
                    let mut sh = self.shared.lock().unwrap();
                    *sh.received.entry(src).or_insert(0) += 1;
                    sh.state.packets = counted;
                }
            }
            let pct = (started.elapsed().as_millis() * 100 / deadline.as_millis().max(1)).min(100);
            if let Ok(mut sh) = self.shared.try_lock() {
                sh.state.progress = pct as u8;
            }
        }
        Ok(())
    }
}

fn idle_state() -> TesterState {
    TesterState {
        status: Status::Idle,
        mode: None,
        protocol: None,
        error: None,
        progress: 0,
        total_ips: 0,
        packets: 0,
        heard_ips: 0,
        passed_ips: 0,
        elapsed_secs: 0,
        config: None,
    }
}

fn score(ip: Ipv4Addr, received: u32, cfg: &TesterConfig) -> IpResult {
    let expected = cfg.packets_per_ip.max(1);
    let got = received.min(expected);
    let loss = (expected - got) as f64 * 100.0 / expected as f64;
    IpResult {
        ip,
        received,
        expected,
        loss_pct: (loss * 10.0).round() / 10.0,
        passed: loss <= cfg.max_loss_pct + 1e-9,
    }
}

fn tally(received: &HashMap<Ipv4Addr, u32>, cfg: Option<&TesterConfig>) -> (u64, u64) {
    let Some(cfg) = cfg else { return (0, 0) };
    let passed = received
        .iter()
        .filter(|(ip, n)| score(**ip, **n, cfg).passed)
        .count();
    (received.len() as u64, passed as u64)
}

fn build_probe(cfg: &TesterConfig, src: Ipv4Addr, dst: Ipv4Addr, i: u32) -> Vec<u8> {
    let sport: u16 = 1024 + (rand::random::<u16>() % 64000);
    match cfg.protocol {
        Probe::Tcp => build_tcp_packet(
            src,
            dst,
            sport,
            cfg.port,
            rand::random(),
            0,
            pnet_packet::tcp::TcpFlags::SYN,
            &[],
        ),
        Probe::Udp => build_udp_packet(src, dst, sport, cfg.port, MARKER),
        Probe::Icmp => build_icmp_echo(src, dst, ICMP_ID, i as u16, MARKER, false),
    }
}

/// If `pkt` (a full IPv4 packet) is one of our probes from a candidate, return
/// its source address.
fn match_probe(pkt: &[u8], cfg: &TesterConfig, candidates: &IpRangeSet) -> Option<Ipv4Addr> {
    if pkt.len() < 20 || pkt[0] >> 4 != 4 {
        return None;
    }
    let ihl = ((pkt[0] & 0x0f) as usize) * 4;
    if pkt.len() < ihl + 8 {
        return None;
    }
    let src = Ipv4Addr::new(pkt[12], pkt[13], pkt[14], pkt[15]);
    if !candidates.contains(src) {
        return None;
    }
    let l4 = &pkt[ihl..];
    let ok = match cfg.protocol {
        Probe::Tcp => {
            l4.len() >= 14
                && u16::from_be_bytes([l4[2], l4[3]]) == cfg.port
                && l4[13] & 0x02 != 0
                && l4[13] & 0x10 == 0
        }
        Probe::Udp => {
            u16::from_be_bytes([l4[2], l4[3]]) == cfg.port && l4.get(8..16) == Some(&MARKER[..])
        }
        Probe::Icmp => {
            l4[0] == 8 && u16::from_be_bytes([l4[4], l4[5]]) == ICMP_ID && l4.get(8..16) == Some(&MARKER[..])
        }
    };
    ok.then_some(src)
}

fn pace(started: Instant, sent: u64, rate_pps: u32) {
    if rate_pps == 0 {
        return;
    }
    let due = Duration::from_secs_f64(sent as f64 / rate_pps as f64);
    let now = started.elapsed();
    if due > now {
        std::thread::sleep(due - now);
    }
}

fn set_recv_timeout(fd: RawFd, d: Duration) {
    let tv = libc::timeval {
        tv_sec: d.as_secs() as libc::time_t,
        tv_usec: d.subsec_micros() as libc::suseconds_t,
    };
    unsafe {
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_RCVTIMEO,
            &tv as *const _ as *const libc::c_void,
            std::mem::size_of::<libc::timeval>() as libc::socklen_t,
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg(protocol: Probe) -> TesterConfig {
        TesterConfig {
            mode: Mode::Receiver,
            protocol,
            target: None,
            port: 8443,
            packets_per_ip: 10,
            timeout_secs: 5,
            max_loss_pct: 20.0,
            rate_pps: 0,
        }
    }

    #[test]
    fn probes_match_only_their_own_kind() {
        let cands = IpRangeSet::parse("9.9.9.0/24").unwrap();
        let src: Ipv4Addr = "9.9.9.7".parse().unwrap();
        let dst: Ipv4Addr = "10.0.0.2".parse().unwrap();
        for p in [Probe::Tcp, Probe::Udp, Probe::Icmp] {
            let c = cfg(p);
            let pkt = build_probe(&c, src, dst, 3);
            assert_eq!(match_probe(&pkt, &c, &cands), Some(src), "{:?}", p);
            // Not a candidate.
            let stranger = build_probe(&c, "8.8.8.8".parse().unwrap(), dst, 3);
            assert_eq!(match_probe(&stranger, &c, &cands), None);
        }
        // Ordinary traffic on the same port without the marker is ignored.
        let c = cfg(Probe::Udp);
        let plain = build_udp_packet(src, dst, 5000, 8443, b"hello world!");
        assert_eq!(match_probe(&plain, &c, &cands), None);
        // A SYN-ACK is a reply, not a probe.
        let c = cfg(Probe::Tcp);
        let synack = build_tcp_packet(src, dst, 5000, 8443, 1, 1, 0x12, &[]);
        assert_eq!(match_probe(&synack, &c, &cands), None);
    }

    #[test]
    fn loss_and_pass_threshold() {
        let c = cfg(Probe::Tcp);
        let ip: Ipv4Addr = "1.1.1.1".parse().unwrap();
        assert!(score(ip, 10, &c).passed);
        assert_eq!(score(ip, 8, &c).loss_pct, 20.0);
        assert!(score(ip, 8, &c).passed);
        assert!(!score(ip, 7, &c).passed);
        // Duplicates never produce negative loss.
        assert_eq!(score(ip, 14, &c).loss_pct, 0.0);
    }

    #[test]
    fn config_defaults_from_json() {
        let c: TesterConfig =
            serde_json::from_str(r#"{"mode":"sender","protocol":"icmp","target":"1.2.3.4"}"#).unwrap();
        assert_eq!(c.packets_per_ip, 10);
        assert_eq!(c.rate_pps, 3000);
        assert_eq!(c.target, Some("1.2.3.4".parse().unwrap()));
    }
}
