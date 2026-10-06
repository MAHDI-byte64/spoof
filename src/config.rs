//! Configuration types for CandyTunnel.
//!
//! Both client and server share this configuration schema. Load with
//! `Config::from_file("config/client.toml")`.

use std::collections::HashSet;
use std::net::Ipv4Addr;
use std::sync::Arc;

use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};
use rand::seq::SliceRandom;
use serde::Deserialize;
use sha2::{Digest, Sha256};

use crate::mux_fec::MuxFecConfig;
use crate::xor::XorCipher;

// ── DPI obfuscation settings ──────────────────────────────────────────────────

/// All DPI bypass / obfuscation knobs bundled together.
/// Pass into [`RawSender::spawn`] and [`RawReceiver::spawn`].
#[derive(Debug, Clone)]
pub struct DpiObfuscation {
    /// Append 1–`max_pad` random bytes after every wire payload so packet
    /// lengths vary and length histograms cannot fingerprint the tunnel.
    pub packet_padding: bool,
    /// Maximum random padding bytes appended per frame (1–255).
    pub packet_padding_max: u8,

    /// Randomise the IPv4 TTL field from a pool of values seen in the wild
    /// (64, 128, 255) instead of always sending 64, which is a giveaway.
    pub ttl_jitter: bool,

    /// Prefix every TCP payload with a 5-byte fake TLS Application Data
    /// record header (`\x17\x03\x03<len16>`) so the stream looks like
    /// TLS to shallow DPI that only inspects the first few bytes.
    pub fake_tls_header: bool,

    /// Set a plausible DSCP value in the IPv4 ToS field (currently always 0,
    /// which is unusual for VoIP/video that ISPs route preferentially).
    /// When true, DSCP is randomly chosen from {0, 0x28 (AF11), 0x10 (CS1)}.
    pub random_dscp: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TunnelProtocol {
    Udp,
    Icmp,
    Proto58,
    Tcp,
    Quic,
    /// IP-in-IP encapsulation (IPv4 protocol 4).
    /// The CandyTunnel payload rides inside a bare IPv4 packet with
    /// protocol = 4 and no additional L4 header.  Looks like a
    /// legitimate IPIP tunnel to deep-packet inspection.
    Ipip,
    /// GRE encapsulation (IPv4 protocol 47, RFC 2784).
    /// Adds a minimal 4-byte GRE header (flags=0, proto=0x6558 Transparent
    /// Ethernet Bridging or 0x0800 IPv4) before the CandyTunnel payload.
    /// Looks like a standard GRE/VPN session to middleboxes.
    Gre,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TunnelRole {
    Client,
    Server,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PerfMode {
    Throughput,
    Latency,
    Balanced,
}

/// Top-level configuration loaded from a TOML file.
#[derive(Debug, Clone)]
pub struct Config {
    /// Whether this configuration is for client or server.
    pub role: TunnelRole,
    /// The real (physical) IPv4 address of this node.
    pub real_ip: Ipv4Addr,

    /// The real IPv4 address of the remote peer.
    pub peer_real_ip: Ipv4Addr,

    /// The spoofed source IP this node puts in outgoing packets.
    pub spoofed_ip: Ipv4Addr,

    /// The spoofed source IP the peer uses (expected in incoming packets).
    pub peer_spoofed_ip: Ipv4Addr,

    /// Optional pool of spoofed IPs for rotation.  If empty, `spoofed_ip` is
    /// always used.
    pub spoofed_ip_pool: Vec<Ipv4Addr>,

    /// Transport protocol used for packets sent by this node.
    pub uplink_protocol: TunnelProtocol,

    /// Transport protocol used for packets received by this node.
    pub downlink_protocol: TunnelProtocol,

    /// UDP/TCP destination port used for the data channel.
    pub data_port: u16,

    /// Enable random data port selection per packet (UDP/TCP only).
    pub shuffle_data_port: bool,

    /// Min UDP/TCP data port used when shuffle mode is enabled.
    pub shuffle_port_min: u16,

    /// Max UDP/TCP data port used when shuffle mode is enabled.
    pub shuffle_port_max: u16,

    /// Enable multiplexing for UDP/ICMP transports.
    pub enable_multiplex: bool,

    /// Multiplex flush interval (ms).
    pub multiplex_flush_ms: u64,

    /// Maximum payload size for multiplexed frames (bytes).
    pub multiplex_max_payload: usize,

    /// Enable XOR FEC for UDP/ICMP transports.
    pub enable_fec: bool,

    /// FEC group size (data frames per parity frame).
    pub fec_group_size: u8,

    /// QUIC SNI / server name (client only).
    pub quic_server_name: String,

    /// QUIC certificate (PEM) path (server only).
    pub quic_cert: String,

    /// QUIC private key (PEM) path (server only).
    pub quic_key: String,

    /// QUIC ALPN label (e.g. "h3").
    pub quic_alpn: String,

    /// QUIC idle timeout (ms).
    pub quic_idle_timeout_ms: u64,

    /// QUIC max connection data (bytes).
    pub quic_max_data: u64,

    /// QUIC max stream data per stream (bytes).
    pub quic_max_stream_data: u64,

    /// QUIC max bidirectional streams.
    pub quic_max_streams_bidi: u64,

    /// Performance tuning mode.
    pub perf_mode: PerfMode,

    /// Enable automatic tuning based on system resources.
    pub auto_tune: bool,

    /// ICMP echo identifier used to distinguish CandyTunnel control packets
    /// from regular ping traffic.
    pub icmp_id: u16,

    /// Randomize ICMP echo identifier per packet.
    pub random_icmp_id: bool,

    /// Whitelist of peer real IPs whose packets are accepted. In addition to
    /// `peer_real_ip`, any address in this list is trusted.
    pub allowed_peers: Vec<Ipv4Addr>,

    /// Number of independent parallel tunnels to maintain.
    pub tunnel_count: usize,

    /// Pre-shared key (hex string) used to authenticate packets.  Both sides
    /// must share the same key.
    pub pre_shared_key: String,

    /// Log level (e.g. trace, debug, info, warn, error).
    pub log_level: String,

    /// Network interface name to bind raw sockets to (e.g. "eth0", "ens3").
    pub interface: String,

    /// TUN interface name (e.g. "candy0").
    pub tun_name: String,

    /// Local TUN interface IPv4 address.
    pub tun_ip: Ipv4Addr,

    /// Remote TUN interface IPv4 address.
    pub tun_peer_ip: Ipv4Addr,

    /// Netmask for the TUN interface.
    pub tun_netmask: Ipv4Addr,

    /// Maximum payload size per tunnel packet (bytes, default 1380).
    pub mtu: usize,

    /// MTU for the TUN interface (clamped to `mtu`).
    pub tun_mtu: usize,

    /// Channel capacity for per-tunnel queues.
    pub channel_capacity: usize,

    /// Channel capacity for raw I/O and mux queues.
    pub io_channel_capacity: usize,

    /// Tokio runtime worker threads (0 = auto).
    pub runtime_worker_threads: usize,

    /// Number of parallel raw-socket send threads (0 = auto: one per core,
    /// capped at 8). Each thread owns its own raw socket and transmits with
    /// `sendmmsg`, so outbound packet building/sending scales across cores
    /// instead of funnelling through a single thread.
    pub send_threads: usize,

    /// Max packets coalesced into a single `sendmmsg` syscall.
    pub send_batch: usize,

    /// Max datagrams pulled per `recvmmsg` syscall on the receive path.
    pub recv_batch: usize,

    /// Client-side port filter (TCP/UDP). When set, overrides `forward_port`.
    pub forward_ports: Vec<u16>,

    /// Legacy single port (TCP/UDP). Used only if `forward_ports` is empty.
    /// Set to 0 to forward all ports.
    pub forward_port: u16,

    /// Enable XOR stream-cipher obfuscation on all wire frames.
    /// When true, every outgoing frame is encrypted and every incoming frame
    /// is decrypted using the `xor_key`.  Both sides must have the same
    /// setting and the same key.
    pub enable_xor: bool,

    /// Key string for the XOR cipher (any length, hashed internally with
    /// SHA-256).  Defaults to `pre_shared_key` when left empty so you only
    /// need to set one key in the config.
    pub xor_key: String,

    // ── DPI obfuscation ───────────────────────────────────────────────────

    /// Append random padding bytes to every wire frame to break length
    /// fingerprinting.  Receiver strips the padding automatically.
    pub packet_padding: bool,
    /// Maximum padding bytes per frame (1–255, default 64).
    pub packet_padding_max: u8,
    /// Randomise the IPv4 TTL from realistic OS values {64, 128, 255}.
    pub ttl_jitter: bool,
    /// Prefix TCP payloads with a fake TLS Application Data record header.
    pub fake_tls_header: bool,
    /// Set a random plausible DSCP value in the IPv4 ToS field.
    pub random_dscp: bool,
}

#[derive(Debug, Deserialize)]
struct ConfigFile {
    #[serde(default = "default_tunnel_role")]
    role: TunnelRole,
    real_ip: Ipv4Addr,
    peer_real_ip: Ipv4Addr,
    spoofed_ip: Ipv4Addr,
    peer_spoofed_ip: Ipv4Addr,
    #[serde(default)]
    spoofed_ip_pool: Vec<Ipv4Addr>,
    #[serde(default)]
    uplink_protocol: Option<TunnelProtocol>,
    #[serde(default)]
    downlink_protocol: Option<TunnelProtocol>,
    #[serde(default)]
    protocol: Option<TunnelProtocol>,
    data_port: u16,
    #[serde(default = "default_shuffle_port_min")]
    shuffle_port_min: u16,
    #[serde(default = "default_shuffle_port_max")]
    shuffle_port_max: u16,
    #[serde(default)]
    enable_multiplex: bool,
    #[serde(default = "default_multiplex_flush_ms")]
    multiplex_flush_ms: u64,
    #[serde(default = "default_multiplex_max_payload")]
    multiplex_max_payload: usize,
    #[serde(default)]
    enable_fec: bool,
    #[serde(default = "default_fec_group_size")]
    fec_group_size: u8,
    #[serde(default = "default_quic_server_name")]
    quic_server_name: String,
    #[serde(default = "default_quic_cert")]
    quic_cert: String,
    #[serde(default = "default_quic_key")]
    quic_key: String,
    #[serde(default = "default_quic_alpn")]
    quic_alpn: String,
    #[serde(default = "default_quic_idle_timeout_ms")]
    quic_idle_timeout_ms: u64,
    #[serde(default = "default_quic_max_data")]
    quic_max_data: u64,
    #[serde(default = "default_quic_max_stream_data")]
    quic_max_stream_data: u64,
    #[serde(default = "default_quic_max_streams_bidi")]
    quic_max_streams_bidi: u64,
    #[serde(default = "default_perf_mode")]
    perf_mode: PerfMode,
    #[serde(default = "default_auto_tune")]
    auto_tune: bool,
    icmp_id: u16,
    #[serde(default = "default_random_icmp_id")]
    random_icmp_id: bool,
    #[serde(default)]
    allowed_peers: Vec<Ipv4Addr>,
    #[serde(default = "default_tunnel_count")]
    tunnel_count: usize,
    pre_shared_key: String,
    #[serde(default = "default_log_level")]
    log_level: String,
    interface: String,
    #[serde(default = "default_tun_name")]
    tun_name: String,
    tun_ip: Ipv4Addr,
    tun_peer_ip: Ipv4Addr,
    #[serde(default = "default_tun_netmask")]
    tun_netmask: Ipv4Addr,
    #[serde(default = "default_mtu")]
    mtu: usize,
    #[serde(default = "default_tun_mtu")]
    tun_mtu: usize,
    #[serde(default = "default_channel_capacity")]
    channel_capacity: usize,
    #[serde(default = "default_io_channel_capacity")]
    io_channel_capacity: usize,
    #[serde(default = "default_runtime_worker_threads")]
    runtime_worker_threads: usize,
    #[serde(default)]
    send_threads: usize,
    #[serde(default = "default_send_batch")]
    send_batch: usize,
    #[serde(default = "default_recv_batch")]
    recv_batch: usize,
    #[serde(default)]
    forward_ports: Vec<u16>,
    #[serde(default = "default_forward_port")]
    forward_port: u16,
    #[serde(default = "default_shuffle_data_port")]
    shuffle_data_port: bool,
    #[serde(default = "default_enable_xor")]
    enable_xor: bool,
    #[serde(default)]
    xor_key: String,

    // DPI obfuscation
    #[serde(default)]
    packet_padding: bool,
    #[serde(default = "default_packet_padding_max")]
    packet_padding_max: u8,
    #[serde(default)]
    ttl_jitter: bool,
    #[serde(default)]
    fake_tls_header: bool,
    #[serde(default)]
    random_dscp: bool,
}

fn default_tunnel_count() -> usize { 4 }
fn default_mtu() -> usize { 1380 }
fn default_tunnel_protocol() -> TunnelProtocol { TunnelProtocol::Udp }
fn default_tunnel_role() -> TunnelRole { TunnelRole::Client }
fn default_tun_name() -> String { "candy0".to_string() }
fn default_tun_netmask() -> Ipv4Addr { Ipv4Addr::new(255, 255, 255, 252) }
fn default_tun_mtu() -> usize { default_mtu() }
fn default_channel_capacity() -> usize { 8192 }
fn default_forward_port() -> u16 { 0 }
fn default_shuffle_data_port() -> bool { false }
fn default_shuffle_port_min() -> u16 { SHUFFLE_PORT_MIN }
fn default_shuffle_port_max() -> u16 { SHUFFLE_PORT_MAX }
fn default_quic_server_name() -> String { "CandyTunnel".to_string() }
fn default_quic_cert() -> String { "config/quic_cert.pem".to_string() }
fn default_quic_key() -> String { "config/quic_key.pem".to_string() }
fn default_quic_alpn() -> String { "h3".to_string() }
fn default_quic_idle_timeout_ms() -> u64 { 30_000 }
// Raised from 10 MB → 128 MB so QUIC flow control does not throttle
// high-throughput tunnels over fast links.
fn default_quic_max_data() -> u64 { 128 * 1024 * 1024 }
// Raised from 1 MB → 16 MB per-stream window.
fn default_quic_max_stream_data() -> u64 { 16 * 1024 * 1024 }
// More concurrent bidirectional streams for multi-tunnel setups.
fn default_quic_max_streams_bidi() -> u64 { 256 }
fn default_perf_mode() -> PerfMode { PerfMode::Balanced }
fn default_auto_tune() -> bool { true }
fn default_multiplex_flush_ms() -> u64 { 1 }
fn default_multiplex_max_payload() -> usize { 1200 }
fn default_fec_group_size() -> u8 { 4 }
fn default_io_channel_capacity() -> usize { 16384 }
fn default_runtime_worker_threads() -> usize { 0 }
fn default_send_batch() -> usize { 64 }
fn default_recv_batch() -> usize { 64 }
fn default_random_icmp_id() -> bool { false }
fn default_log_level() -> String { "info".to_string() }
fn default_enable_xor() -> bool { false }
fn default_packet_padding_max() -> u8 { 64 }

const SHUFFLE_PORT_MIN: u16 = 49152;
const SHUFFLE_PORT_MAX: u16 = 65535;
const SHUFFLE_PORT_POOL_SIZE: usize = 512;
const SHUFFLE_PORT_ATTEMPTS: usize = SHUFFLE_PORT_POOL_SIZE * 20;

impl Config {
    /// Load configuration from a TOML file.
    pub fn from_file(path: &str) -> anyhow::Result<Self> {
        let content = std::fs::read_to_string(path)
            .map_err(|e| anyhow::anyhow!("Cannot read config '{}': {}", path, e))?;
        Self::from_toml_str(&content)
            .map_err(|e| anyhow::anyhow!("Invalid config '{}': {}", path, e))
    }

    /// Parse a configuration from a TOML string and run cross-field validation.
    ///
    /// Used both by [`from_file`] and by the web panel to validate an edited
    /// configuration before it is written to disk.
    pub fn from_toml_str(content: &str) -> anyhow::Result<Self> {
        let raw: ConfigFile = toml::from_str(content)?;

        let fallback_protocol = raw.protocol.unwrap_or_else(default_tunnel_protocol);

        let cfg = Self {
            role: raw.role,
            real_ip: raw.real_ip,
            peer_real_ip: raw.peer_real_ip,
            spoofed_ip: raw.spoofed_ip,
            peer_spoofed_ip: raw.peer_spoofed_ip,
            spoofed_ip_pool: raw.spoofed_ip_pool,
            uplink_protocol: raw.uplink_protocol.unwrap_or(fallback_protocol),
            downlink_protocol: raw.downlink_protocol.unwrap_or(fallback_protocol),
            data_port: raw.data_port,
            enable_multiplex: raw.enable_multiplex,
            multiplex_flush_ms: raw.multiplex_flush_ms,
            multiplex_max_payload: raw.multiplex_max_payload,
            enable_fec: raw.enable_fec,
            fec_group_size: raw.fec_group_size,
            quic_server_name: raw.quic_server_name,
            quic_cert: raw.quic_cert,
            quic_key: raw.quic_key,
            quic_alpn: raw.quic_alpn,
            quic_idle_timeout_ms: raw.quic_idle_timeout_ms,
            quic_max_data: raw.quic_max_data,
            quic_max_stream_data: raw.quic_max_stream_data,
            quic_max_streams_bidi: raw.quic_max_streams_bidi,
            perf_mode: raw.perf_mode,
            auto_tune: raw.auto_tune,
            icmp_id: raw.icmp_id,
            random_icmp_id: raw.random_icmp_id,
            allowed_peers: raw.allowed_peers,
            tunnel_count: raw.tunnel_count,
            pre_shared_key: raw.pre_shared_key.clone(),
            log_level: raw.log_level,
            interface: raw.interface,
            tun_name: raw.tun_name,
            tun_ip: raw.tun_ip,
            tun_peer_ip: raw.tun_peer_ip,
            tun_netmask: raw.tun_netmask,
            mtu: raw.mtu,
            tun_mtu: raw.tun_mtu,
            channel_capacity: raw.channel_capacity,
            io_channel_capacity: raw.io_channel_capacity,
            runtime_worker_threads: raw.runtime_worker_threads,
            send_threads: raw.send_threads,
            send_batch: raw.send_batch,
            recv_batch: raw.recv_batch,
            forward_ports: raw.forward_ports,
            forward_port: raw.forward_port,
            shuffle_data_port: raw.shuffle_data_port,
            shuffle_port_min: raw.shuffle_port_min,
            shuffle_port_max: raw.shuffle_port_max,
            enable_xor: raw.enable_xor,
            // When xor_key is not set, fall back to pre_shared_key so a user
            // only needs to configure one secret.
            xor_key: if raw.xor_key.is_empty() {
                raw.pre_shared_key
            } else {
                raw.xor_key
            },
            packet_padding:     raw.packet_padding,
            packet_padding_max: raw.packet_padding_max,
            ttl_jitter:         raw.ttl_jitter,
            fake_tls_header:    raw.fake_tls_header,
            random_dscp:        raw.random_dscp,
        };

        cfg.validate()?;
        Ok(cfg)
    }

    /// Cross-field sanity checks shared by file loading and panel editing.
    pub fn validate(&self) -> anyhow::Result<()> {
        use anyhow::bail;

        let up_quic = self.uplink_protocol == TunnelProtocol::Quic;
        let down_quic = self.downlink_protocol == TunnelProtocol::Quic;
        if up_quic != down_quic {
            bail!("quic requires both uplink_protocol and downlink_protocol = quic");
        }
        if (up_quic || down_quic) && self.shuffle_data_port {
            bail!("shuffle_data_port is not supported with quic transport");
        }
        if self.tun_ip == self.tun_peer_ip {
            bail!("tun_ip and tun_peer_ip must be different");
        }
        if self.mtu < 576 {
            bail!("mtu must be >= 576");
        }
        if self.shuffle_data_port && self.shuffle_port_min > self.shuffle_port_max {
            bail!("shuffle_port_min must be <= shuffle_port_max");
        }
        if self.enable_fec && self.fec_group_size < 2 {
            bail!("fec_group_size must be >= 2 when enable_fec is set");
        }
        if self.tunnel_count == 0 {
            bail!("tunnel_count must be > 0");
        }
        if self.channel_capacity == 0 {
            bail!("channel_capacity must be > 0");
        }
        Ok(())
    }

    /// Build a deterministic pool of data ports for shuffle mode.
    pub fn build_data_port_pool(&self) -> anyhow::Result<Option<Arc<Vec<u16>>>> {
        if !self.shuffle_data_port {
            return Ok(None);
        }

        if self.shuffle_port_min == 0 || self.shuffle_port_max == 0 {
            anyhow::bail!("shuffle_port_min/max must be between 1 and 65535");
        }
        if self.shuffle_port_min > self.shuffle_port_max {
            anyhow::bail!("shuffle_port_min must be <= shuffle_port_max");
        }

        let mut hasher = Sha256::new();
        hasher.update(self.pre_shared_key.as_bytes());
        hasher.update(self.data_port.to_be_bytes());
        let seed = hasher.finalize();
        let mut seed_bytes = [0u8; 32];
        seed_bytes.copy_from_slice(&seed);
        let mut rng = StdRng::from_seed(seed_bytes);

        let range_len = (self.shuffle_port_max - self.shuffle_port_min + 1) as usize;
        let pool_size = SHUFFLE_PORT_POOL_SIZE.min(range_len);
        let attempts = SHUFFLE_PORT_ATTEMPTS.min(range_len.saturating_mul(20)).max(range_len);
        let used_ports = read_used_ports(self.real_ip);

        let mut ports = Vec::with_capacity(pool_size);
        let mut seen = HashSet::with_capacity(pool_size * 2);

        for _ in 0..attempts {
            let port = rng.gen_range(self.shuffle_port_min..=self.shuffle_port_max);
            if !seen.insert(port) {
                continue;
            }
            if used_ports.contains(&port) {
                continue;
            }
            ports.push(port);
            if ports.len() >= pool_size {
                break;
            }
        }

        if ports.is_empty() {
            anyhow::bail!(
                "shuffle_data_port enabled but no available ports in range {}-{} on {}",
                self.shuffle_port_min,
                self.shuffle_port_max,
                self.real_ip
            );
        }

        Ok(Some(Arc::new(ports)))
    }

    pub fn shuffle_port_range(&self) -> Option<(u16, u16)> {
        if self.shuffle_data_port {
            Some((self.shuffle_port_min, self.shuffle_port_max))
        } else {
            None
        }
    }

    /// Returns true if `ip` is a trusted peer address.
    pub fn is_peer_allowed(&self, ip: &Ipv4Addr) -> bool {
        *ip == self.peer_real_ip
            || *ip == self.peer_spoofed_ip
            || self.allowed_peers.contains(ip)
    }

    /// Pick a (possibly random) spoofed source IP from the configured pool.
    /// Falls back to `spoofed_ip` when the pool is empty.
    pub fn pick_spoofed_ip(&self) -> Ipv4Addr {
        if self.spoofed_ip_pool.is_empty() {
            return self.spoofed_ip;
        }
        *self
            .spoofed_ip_pool
            .choose(&mut rand::thread_rng())
            .unwrap_or(&self.spoofed_ip)
    }

    /// Normalized client port filter list. Empty means "no filter".
    pub fn effective_forward_ports(&self) -> Vec<u16> {
        let mut ports = if !self.forward_ports.is_empty() {
            self.forward_ports.clone()
        } else if self.forward_port != 0 {
            vec![self.forward_port]
        } else {
            Vec::new()
        };

        ports.retain(|p| *p != 0);
        ports.sort_unstable();
        ports.dedup();
        ports
    }

    pub fn mux_fec_config(&self) -> MuxFecConfig {
        // Cap the on-wire mux-frame size so that, after the XOR nonce and any
        // DPI padding are appended, the resulting L4 payload still fits inside
        // the configured `mtu` budget. Without this reservation a full mux
        // frame + 12-byte nonce + up to 255 padding bytes could overflow the
        // path MTU and get IP-fragmented, which hurts both throughput and
        // stealth (fragmented spoofed packets are easy to fingerprint/drop).
        let budget = self.mtu.max(256).saturating_sub(self.frame_overhead());
        let cap = self.multiplex_max_payload.min(budget).max(64);
        MuxFecConfig {
            enable_multiplex: self.enable_multiplex,
            multiplex_flush_ms: self.multiplex_flush_ms,
            multiplex_max_payload: cap,
            enable_fec: self.enable_fec,
            fec_group_size: self.fec_group_size,
        }
    }

    /// Per-frame wire overhead added *after* the CandyPacket/mux framing:
    /// the XOR nonce (when encryption is on) and the DPI padding trailer
    /// (when padding is on). Used to keep frames within the MTU budget.
    pub fn frame_overhead(&self) -> usize {
        let mut o = 0usize;
        if self.enable_xor {
            o += crate::xor::XOR_NONCE_LEN;
        }
        if self.packet_padding {
            // random bytes (<= packet_padding_max) + 1-byte length marker
            o += self.packet_padding_max as usize + 1;
        }
        o
    }

    /// Total per-packet overhead between a TUN IP packet and the wire L4
    /// payload: CandyPacket header + optional mux header + frame overhead.
    /// Used to clamp the effective TUN MTU so a single TUN packet always fits
    /// in one wire frame without IP fragmentation.
    pub fn wire_overhead(&self) -> usize {
        // CandyPacket fixed header.
        let mut o = crate::packet::HEADER_SIZE;
        // Mux header (magic+ver+flags+group_id+group_size+index) + count byte
        // + per-packet length prefix, only when multiplexing is active for a
        // mux-capable transport.
        let mux_capable = matches!(
            self.uplink_protocol,
            TunnelProtocol::Udp
                | TunnelProtocol::Icmp
                | TunnelProtocol::Proto58
                | TunnelProtocol::Ipip
                | TunnelProtocol::Gre
        );
        if self.enable_multiplex && mux_capable {
            o += 9 /* mux header */ + 1 /* count */ + 2 /* length prefix */;
        }
        o += self.frame_overhead();
        o
    }

    /// The largest TUN MTU that still lets a full-size TUN packet travel in a
    /// single un-fragmented wire frame within the `mtu` budget. Callers clamp
    /// the user-requested `tun_mtu` to this value.
    pub fn max_safe_tun_mtu(&self) -> usize {
        self.mtu.saturating_sub(self.wire_overhead()).max(576)
    }

    /// Final TUN interface MTU: the user's `tun_mtu` (or `mtu` when unset),
    /// clamped both to `mtu` and to [`max_safe_tun_mtu`]. Returns the value
    /// plus an optional human-readable note when clamping occurred, so the
    /// caller can log it once.
    pub fn effective_tun_mtu(&self) -> (usize, Option<String>) {
        let requested = if self.tun_mtu == 0 { self.mtu } else { self.tun_mtu };
        let safe = self.max_safe_tun_mtu();
        let clamped = requested.min(self.mtu).min(safe);
        let note = if clamped < requested {
            Some(format!(
                "tun_mtu {} clamped to {} (mtu {} minus {}-byte wire overhead) to avoid IP fragmentation",
                requested, clamped, self.mtu, self.wire_overhead()
            ))
        } else {
            None
        };
        (clamped, note)
    }

    pub fn pick_icmp_id(&self) -> u16 {
        if self.random_icmp_id {
            rand::random()
        } else {
            self.icmp_id
        }
    }

    /// Number of raw-socket send threads to spawn (resolves the `0 = auto`
    /// case to one per core, capped at 8).
    pub fn effective_send_threads(&self) -> usize {
        if self.send_threads > 0 {
            return self.send_threads.min(32);
        }
        std::thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(1)
            .clamp(1, 8)
    }

    /// Packets per `sendmmsg` syscall (at least 1).
    pub fn effective_send_batch(&self) -> usize {
        self.send_batch.clamp(1, 1024)
    }

    /// Datagrams per `recvmmsg` syscall (at least 1).
    pub fn effective_recv_batch(&self) -> usize {
        self.recv_batch.clamp(1, 1024)
    }

    /// Return an [`XorCipher`] if XOR obfuscation is enabled, or `None`.
    pub fn xor_cipher(&self) -> Option<XorCipher> {
        if self.enable_xor {
            Some(XorCipher::new(&self.xor_key))
        } else {
            None
        }
    }

    /// Return a [`DpiObfuscation`] snapshot of the current settings.
    pub fn dpi_obfuscation(&self) -> DpiObfuscation {
        DpiObfuscation {
            packet_padding:     self.packet_padding,
            packet_padding_max: self.packet_padding_max,
            ttl_jitter:         self.ttl_jitter,
            fake_tls_header:    self.fake_tls_header,
            random_dscp:        self.random_dscp,
        }
    }
}

pub fn pick_data_port(data_port: u16, pool: &Option<Arc<Vec<u16>>>) -> u16 {
    if let Some(ports) = pool {
        if let Some(port) = ports.choose(&mut rand::thread_rng()).copied() {
            return port;
        }
    }
    data_port
}

fn read_used_ports(ip: Ipv4Addr) -> HashSet<u16> {
    let mut used = HashSet::new();
    if let Err(e) = collect_ports_from_proc("/proc/net/tcp", ip, &mut used) {
        log::warn!("unable to read /proc/net/tcp: {}", e);
    }
    if let Err(e) = collect_ports_from_proc("/proc/net/udp", ip, &mut used) {
        log::warn!("unable to read /proc/net/udp: {}", e);
    }
    used
}

fn collect_ports_from_proc(
    path: &str,
    ip: Ipv4Addr,
    out: &mut HashSet<u16>,
) -> std::io::Result<()> {
    let content = std::fs::read_to_string(path)?;
    for line in content.lines().skip(1) {
        let mut parts = line.split_whitespace();
        let _slot = parts.next();
        let Some(local) = parts.next() else { continue; };
        let mut local_parts = local.split(':');
        let Some(ip_hex) = local_parts.next() else { continue; };
        let Some(port_hex) = local_parts.next() else { continue; };

        let Ok(raw_ip) = u32::from_str_radix(ip_hex, 16) else { continue; };
        let local_ip = Ipv4Addr::from(u32::from_le(raw_ip));
        if local_ip != ip && local_ip != Ipv4Addr::UNSPECIFIED {
            continue;
        }

        if let Ok(port) = u16::from_str_radix(port_hex, 16) {
            out.insert(port);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const MINIMAL: &str = r#"
        real_ip = "10.0.0.1"
        peer_real_ip = "10.0.0.2"
        spoofed_ip = "8.8.4.4"
        peer_spoofed_ip = "1.2.3.4"
        data_port = 51820
        icmp_id = 1
        pre_shared_key = "k"
        interface = "eth0"
        tun_ip = "10.66.0.1"
        tun_peer_ip = "10.66.0.2"
    "#;

    #[test]
    fn minimal_config_loads() {
        let cfg = Config::from_toml_str(MINIMAL).unwrap();
        assert_eq!(cfg.data_port, 51820);
        // No xor/padding → no frame overhead.
        assert_eq!(cfg.frame_overhead(), 0);
    }

    #[test]
    fn frame_overhead_accounts_for_xor_and_padding() {
        let toml = format!("{}\nenable_xor = true\npacket_padding = true\npacket_padding_max = 64\n", MINIMAL);
        let cfg = Config::from_toml_str(&toml).unwrap();
        // 12-byte nonce + (64 pad + 1 length marker).
        assert_eq!(cfg.frame_overhead(), crate::xor::XOR_NONCE_LEN + 65);
    }

    #[test]
    fn tun_mtu_is_clamped_for_overhead() {
        let toml = format!("{}\nenable_xor = true\npacket_padding = true\npacket_padding_max = 64\n", MINIMAL);
        let cfg = Config::from_toml_str(&toml).unwrap();
        let (mtu, note) = cfg.effective_tun_mtu();
        assert!(mtu <= cfg.max_safe_tun_mtu());
        assert!(mtu < cfg.mtu, "clamped mtu {} should be below mtu {}", mtu, cfg.mtu);
        assert!(note.is_some(), "clamping should be reported");
    }

    #[test]
    fn mux_cap_stays_within_mtu_budget() {
        let toml = format!("{}\nenable_xor = true\npacket_padding = true\npacket_padding_max = 200\n", MINIMAL);
        let cfg = Config::from_toml_str(&toml).unwrap();
        let mux = cfg.mux_fec_config();
        assert!(mux.multiplex_max_payload + cfg.frame_overhead() <= cfg.mtu.max(256));
    }

    #[test]
    fn quic_one_sided_is_rejected() {
        let toml = format!("{}\nuplink_protocol = \"quic\"\ndownlink_protocol = \"udp\"\n", MINIMAL);
        assert!(Config::from_toml_str(&toml).is_err());
    }

    #[test]
    fn same_tun_ips_rejected() {
        let toml = MINIMAL.replace("10.66.0.2", "10.66.0.1");
        assert!(Config::from_toml_str(&toml).is_err());
    }
}
