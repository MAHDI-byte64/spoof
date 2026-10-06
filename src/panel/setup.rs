//! The one-step setup helpers behind the panel's simple flow:
//!
//! * **auto-detect** the server's own outbound IP and interface, so the forms
//!   start pre-filled;
//! * a **connection code** — a server exports one string that carries every
//!   setting both ends must share (key, ports, protocols, spoofed IPs, TUN
//!   addresses, obfuscation); the client imports it and only its own real IP is
//!   left to fill. The code is base64url of a small JSON payload, no secrets
//!   beyond what the operator already configured;
//! * **spoofed-IP list files** attached to an instance, edited as plain text.

use std::net::{Ipv4Addr, UdpSocket};
use std::path::PathBuf;
use std::sync::Arc;

use serde::{Deserialize, Serialize};
use serde_json::json;

use super::instances::PanelInstance;
use super::{valid_instance_name, PanelState, Request, Response};
use crate::config::Config;
use crate::iplist::IpRangeSet;

const CODE_PREFIX: &str = "CT1.";
/// A spoof list past this many addresses is a mistake in a text box.
const MAX_LIST_IPS: usize = 1 << 18;

// ── Auto-detect ────────────────────────────────────────────────────────────

/// The address a packet to the public internet would leave from. Uses a
/// connected UDP socket, which only sets the kernel's route choice — nothing is
/// sent. Falls back to the first non-loopback IPv4 of any interface.
pub fn detect_outbound_ip() -> Option<Ipv4Addr> {
    if let Ok(sock) = UdpSocket::bind("0.0.0.0:0") {
        if sock.connect("8.8.8.8:80").is_ok() {
            if let Ok(addr) = sock.local_addr() {
                if let std::net::IpAddr::V4(v4) = addr.ip() {
                    if !v4.is_loopback() && !v4.is_unspecified() {
                        return Some(v4);
                    }
                }
            }
        }
    }
    None
}

/// The interface carrying the default route, read from `/proc/net/route`.
pub fn detect_default_iface() -> Option<String> {
    let data = std::fs::read_to_string("/proc/net/route").ok()?;
    for line in data.lines().skip(1) {
        let mut cols = line.split_whitespace();
        let iface = cols.next()?;
        let dest = cols.next()?;
        if dest == "00000000" {
            return Some(iface.to_string());
        }
    }
    None
}

pub async fn netinfo(_state: &Arc<PanelState>) -> Response {
    Response::json(
        200,
        json!({
            "real_ip": detect_outbound_ip().map(|ip| ip.to_string()),
            "interface": detect_default_iface(),
        }),
    )
}

// ── Connection code ──────────────────────────────────────────────────────────

/// The shared half of a tunnel: everything both ends must agree on, plus the
/// server's own real IP and the two sides' spoofed addresses. The client's real
/// IP is deliberately absent — the importing side supplies it.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct CodePayload {
    v: u8,
    /// Server's real IP (becomes the client's `peer_real_ip`).
    sr: String,
    /// Data port.
    dp: u16,
    /// Server's uplink / downlink protocol (the client mirrors them).
    up: String,
    dn: String,
    id: u16,
    /// Pre-shared key and optional XOR settings.
    k: String,
    #[serde(default)]
    xe: bool,
    #[serde(default)]
    xk: String,
    /// Server's spoofed source addresses (become the client's expected peer).
    ss: Vec<String>,
    /// Client's spoofed source addresses (what the server expects from it).
    cs: Vec<String>,
    /// TUN addresses: server side and client side, plus the shared netmask/MTU.
    sti: String,
    cti: String,
    nm: String,
    mtu: usize,
    tmtu: usize,
    /// Wire settings that must match on both ends.
    mux: bool,
    mxf: u64,
    mxp: usize,
    fec: bool,
    fg: u8,
    sh: bool,
    shmin: u16,
    shmax: u16,
    pad: bool,
    padm: u8,
    ttl: bool,
    tls: bool,
    dscp: bool,
}

fn b64url_encode(data: &[u8]) -> String {
    const T: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut out = String::with_capacity(data.len().div_ceil(3) * 4);
    for chunk in data.chunks(3) {
        let b = [
            chunk[0],
            *chunk.get(1).unwrap_or(&0),
            *chunk.get(2).unwrap_or(&0),
        ];
        let n = (b[0] as u32) << 16 | (b[1] as u32) << 8 | b[2] as u32;
        out.push(T[(n >> 18 & 63) as usize] as char);
        out.push(T[(n >> 12 & 63) as usize] as char);
        if chunk.len() > 1 {
            out.push(T[(n >> 6 & 63) as usize] as char);
        }
        if chunk.len() > 2 {
            out.push(T[(n & 63) as usize] as char);
        }
    }
    out
}

fn b64url_decode(s: &str) -> Option<Vec<u8>> {
    fn val(c: u8) -> Option<u32> {
        match c {
            b'A'..=b'Z' => Some((c - b'A') as u32),
            b'a'..=b'z' => Some((c - b'a' + 26) as u32),
            b'0'..=b'9' => Some((c - b'0' + 52) as u32),
            b'-' => Some(62),
            b'_' => Some(63),
            _ => None,
        }
    }
    let s = s.trim().as_bytes();
    let mut out = Vec::with_capacity(s.len() / 4 * 3);
    for chunk in s.chunks(4) {
        let mut n = 0u32;
        let mut bits = 0;
        for &c in chunk {
            n = n << 6 | val(c)?;
            bits += 6;
        }
        n <<= 24 - bits;
        let bytes = bits / 8;
        for i in 0..bytes {
            out.push((n >> (16 - i * 8)) as u8);
        }
    }
    Some(out)
}

fn ips_to_strings(primary: &str, pool: &[String]) -> Vec<String> {
    let mut v = Vec::with_capacity(1 + pool.len());
    if !primary.is_empty() {
        v.push(primary.to_string());
    }
    for p in pool {
        if !v.contains(p) {
            v.push(p.clone());
        }
    }
    v
}

/// Build a connection code from a **server** instance.
pub fn make_code(inst: &PanelInstance) -> anyhow::Result<String> {
    if inst.role != "server" {
        anyhow::bail!("a connection code is generated from the server instance");
    }
    let payload = CodePayload {
        v: 1,
        sr: inst.real_ip.clone(),
        dp: inst.data_port,
        up: inst.uplink_protocol.clone(),
        dn: inst.downlink_protocol.clone(),
        id: inst.icmp_id,
        k: inst.pre_shared_key.clone(),
        xe: inst.enable_xor,
        xk: inst.xor_key.clone(),
        ss: ips_to_strings(&inst.spoofed_ip, &inst.spoofed_ip_pool),
        cs: ips_to_strings(&inst.peer_spoofed_ip, &inst.peer_spoofed_ip_pool),
        sti: inst.tun_ip.clone(),
        cti: inst.tun_peer_ip.clone(),
        nm: inst.tun_netmask.clone(),
        mtu: inst.mtu,
        tmtu: inst.tun_mtu,
        mux: inst.enable_multiplex,
        mxf: inst.multiplex_flush_ms,
        mxp: inst.multiplex_max_payload,
        fec: inst.enable_fec,
        fg: inst.fec_group_size,
        sh: inst.shuffle_data_port,
        shmin: inst.shuffle_port_min,
        shmax: inst.shuffle_port_max,
        pad: inst.packet_padding,
        padm: inst.packet_padding_max,
        ttl: inst.ttl_jitter,
        tls: inst.fake_tls_header,
        dscp: inst.random_dscp,
    };
    let json = serde_json::to_vec(&payload)?;
    Ok(format!("{}{}", CODE_PREFIX, b64url_encode(&json)))
}

/// Build a **client** instance from a connection code. `real_ip` is the
/// client's own real address (auto-detected or typed).
pub fn apply_code(code: &str, real_ip: &str) -> anyhow::Result<PanelInstance> {
    let body = code
        .trim()
        .strip_prefix(CODE_PREFIX)
        .ok_or_else(|| anyhow::anyhow!("not a CandyTunnel connection code"))?;
    let bytes = b64url_decode(body).ok_or_else(|| anyhow::anyhow!("corrupt connection code"))?;
    let p: CodePayload = serde_json::from_slice(&bytes)
        .map_err(|e| anyhow::anyhow!("unreadable connection code: {}", e))?;
    if p.v != 1 {
        anyhow::bail!("connection code version {} is not supported", p.v);
    }

    let mut inst = PanelInstance::default_client();
    inst.role = "client".into();
    inst.real_ip = real_ip.trim().to_string();
    inst.peer_real_ip = p.sr;
    // Client spoofs from the server-declared client set; expects the server set.
    inst.spoofed_ip = p.cs.first().cloned().unwrap_or_default();
    inst.spoofed_ip_pool = p.cs;
    inst.peer_spoofed_ip = p.ss.first().cloned().unwrap_or_default();
    inst.peer_spoofed_ip_pool = p.ss;
    inst.data_port = p.dp;
    // Protocols mirror: the client sends what the server receives and vice versa.
    inst.uplink_protocol = p.dn;
    inst.downlink_protocol = p.up;
    inst.icmp_id = p.id;
    inst.pre_shared_key = p.k;
    inst.enable_xor = p.xe;
    inst.xor_key = p.xk;
    inst.tun_ip = p.cti;
    inst.tun_peer_ip = p.sti;
    inst.tun_netmask = p.nm;
    inst.mtu = p.mtu;
    inst.tun_mtu = p.tmtu;
    inst.enable_multiplex = p.mux;
    inst.multiplex_flush_ms = p.mxf;
    inst.multiplex_max_payload = p.mxp;
    inst.enable_fec = p.fec;
    inst.fec_group_size = p.fg;
    inst.shuffle_data_port = p.sh;
    inst.shuffle_port_min = p.shmin;
    inst.shuffle_port_max = p.shmax;
    inst.packet_padding = p.pad;
    inst.packet_padding_max = p.padm;
    inst.ttl_jitter = p.ttl;
    inst.fake_tls_header = p.tls;
    inst.random_dscp = p.dscp;
    Ok(inst)
}

pub async fn gen_code(state: &Arc<PanelState>, name: &str) -> Response {
    if !valid_instance_name(name) {
        return Response::json(400, json!({ "error": "invalid instance name" }));
    }
    let path = PathBuf::from(&state.cfg.config_dir).join(format!("{}.toml", name));
    let inst: PanelInstance = match std::fs::read_to_string(&path)
        .ok()
        .and_then(|s| toml::from_str(&s).ok())
    {
        Some(i) => i,
        None => return Response::json(404, json!({ "error": "instance not found" })),
    };
    match make_code(&inst) {
        Ok(code) => Response::json(200, json!({ "code": code })),
        Err(e) => Response::json(400, json!({ "error": format!("{}", e) })),
    }
}

#[derive(Deserialize)]
struct ImportReq {
    code: String,
    name: String,
    #[serde(default)]
    real_ip: String,
    /// Only build and return the config for preview; do not write it.
    #[serde(default)]
    preview: bool,
}

pub async fn import_code(state: &Arc<PanelState>, req: &Request) -> Response {
    let body: ImportReq = match req.json() {
        Ok(b) => b,
        Err(e) => return Response::json(400, json!({ "error": format!("{}", e) })),
    };
    if !valid_instance_name(&body.name) {
        return Response::json(400, json!({ "error": "invalid instance name (A-Z a-z 0-9 _ -, 1-32)" }));
    }
    let real_ip = if body.real_ip.trim().is_empty() {
        detect_outbound_ip().map(|i| i.to_string()).unwrap_or_default()
    } else {
        body.real_ip.trim().to_string()
    };
    let inst = match apply_code(&body.code, &real_ip) {
        Ok(i) => i,
        Err(e) => return Response::json(400, json!({ "error": format!("{}", e) })),
    };

    if body.preview {
        return Response::json(200, json!({ "name": body.name, "config": inst }));
    }
    write_instance(state, &body.name, &inst)
}

#[derive(Deserialize)]
struct QuickAddReq {
    name: String,
    role: String,
    /// This machine's real IP (empty → auto-detect).
    #[serde(default)]
    real_ip: String,
    /// The peer's real IP.
    peer_real_ip: String,
    /// Protocol used both ways (simple form keeps uplink == downlink).
    #[serde(default = "qa_proto")]
    protocol: String,
    /// Spoofed source addresses this node uses.
    #[serde(default)]
    spoofed_ips: Vec<String>,
    /// Spoofed source addresses the peer uses.
    #[serde(default)]
    peer_spoofed_ips: Vec<String>,
    #[serde(default = "qa_port")]
    data_port: u16,
    /// Pre-shared key (empty → generated).
    #[serde(default)]
    pre_shared_key: String,
}

fn qa_proto() -> String { "udp".into() }
fn qa_port() -> u16 { 51820 }

pub async fn quickadd(state: &Arc<PanelState>, req: &Request) -> Response {
    let body: QuickAddReq = match req.json() {
        Ok(b) => b,
        Err(e) => return Response::json(400, json!({ "error": format!("{}", e) })),
    };
    if !valid_instance_name(&body.name) {
        return Response::json(400, json!({ "error": "invalid instance name (A-Z a-z 0-9 _ -, 1-32)" }));
    }
    if body.role != "client" && body.role != "server" {
        return Response::json(400, json!({ "error": "role must be client or server" }));
    }

    let real_ip = if body.real_ip.trim().is_empty() {
        detect_outbound_ip().map(|i| i.to_string()).unwrap_or_default()
    } else {
        body.real_ip.trim().to_string()
    };
    let key = if body.pre_shared_key.trim().is_empty() {
        super::auth::new_token()
    } else {
        body.pre_shared_key.trim().to_string()
    };

    let mut inst = PanelInstance::default_client();
    inst.role = body.role.clone();
    inst.real_ip = real_ip;
    inst.peer_real_ip = body.peer_real_ip.trim().to_string();
    inst.uplink_protocol = body.protocol.clone();
    inst.downlink_protocol = body.protocol.clone();
    inst.data_port = body.data_port;
    inst.pre_shared_key = key;
    inst.spoofed_ip = body.spoofed_ips.first().cloned().unwrap_or_default();
    inst.spoofed_ip_pool = dedup(body.spoofed_ips);
    inst.peer_spoofed_ip = body.peer_spoofed_ips.first().cloned().unwrap_or_default();
    inst.peer_spoofed_ip_pool = dedup(body.peer_spoofed_ips);
    if let Some(iface) = detect_default_iface() {
        inst.interface = iface;
    }
    // Give the two ends opposite TUN addresses by convention.
    if body.role == "server" {
        inst.tun_ip = "10.66.0.1".into();
        inst.tun_peer_ip = "10.66.0.2".into();
    } else {
        inst.tun_ip = "10.66.0.2".into();
        inst.tun_peer_ip = "10.66.0.1".into();
    }

    write_instance(state, &body.name, &inst)
}

fn dedup(mut v: Vec<String>) -> Vec<String> {
    v.retain(|s| !s.trim().is_empty());
    let mut seen = std::collections::HashSet::new();
    v.retain(|s| seen.insert(s.clone()));
    v
}

/// Render, validate and write an instance, returning the saved config.
fn write_instance(state: &Arc<PanelState>, name: &str, inst: &PanelInstance) -> Response {
    let toml_text = match toml::to_string_pretty(inst) {
        Ok(t) => t,
        Err(e) => return Response::json(400, json!({ "error": format!("render: {}", e) })),
    };
    if let Err(e) = Config::from_toml_str(&toml_text) {
        return Response::json(400, json!({ "error": format!("invalid config: {}", e) }));
    }
    if let Err(e) = std::fs::create_dir_all(&state.cfg.config_dir) {
        return Response::json(500, json!({ "error": format!("mkdir: {}", e) }));
    }
    let header = format!("# CandyTunnel instance '{}' — generated by the web panel\n\n", name);
    let path = PathBuf::from(&state.cfg.config_dir).join(format!("{}.toml", name));
    if let Err(e) = std::fs::write(&path, format!("{}{}", header, toml_text)) {
        return Response::json(500, json!({ "error": format!("write: {}", e) }));
    }
    Response::json(200, json!({ "ok": true, "name": name, "config": inst }))
}

// ── Spoofed-IP list files ──────────────────────────────────────────────────

fn list_path(state: &PanelState, name: &str, which: &str) -> PathBuf {
    PathBuf::from(&state.cfg.config_dir).join(format!("{}.{}.ips", name, which))
}

fn which_ok(which: &str) -> bool {
    which == "mine" || which == "peer"
}

pub async fn get_spoof_list(state: &Arc<PanelState>, name: &str, which: &str) -> Response {
    if !valid_instance_name(name) || !which_ok(which) {
        return Response::json(400, json!({ "error": "invalid request" }));
    }
    let path = list_path(state, name, which);
    let content = std::fs::read_to_string(&path).unwrap_or_default();
    let count = IpRangeSet::parse(&content).map(|s| s.total()).unwrap_or(0);
    Response::json(200, json!({ "content": content, "count": count }))
}

#[derive(Deserialize)]
struct ListReq {
    content: String,
}

pub async fn set_spoof_list(state: &Arc<PanelState>, req: &Request, name: &str, which: &str) -> Response {
    if !valid_instance_name(name) || !which_ok(which) {
        return Response::json(400, json!({ "error": "invalid request" }));
    }
    let body: ListReq = match req.json() {
        Ok(b) => b,
        Err(e) => return Response::json(400, json!({ "error": format!("{}", e) })),
    };

    let set = match IpRangeSet::parse(&body.content) {
        Ok(s) => s,
        Err(e) => return Response::json(400, json!({ "error": format!("invalid IP list: {:#}", e) })),
    };
    if set.total() > MAX_LIST_IPS as u64 {
        return Response::json(400, json!({ "error": format!("list has {} addresses, over the {} limit", set.total(), MAX_LIST_IPS) }));
    }

    if let Err(e) = std::fs::create_dir_all(&state.cfg.config_dir) {
        return Response::json(500, json!({ "error": format!("mkdir: {}", e) }));
    }
    let path = list_path(state, name, which);
    // An empty list clears the file and detaches it from the instance.
    let attach = !set.is_empty();
    if set.is_empty() {
        let _ = std::fs::remove_file(&path);
    } else if let Err(e) = std::fs::write(&path, body.content.as_bytes()) {
        return Response::json(500, json!({ "error": format!("write: {}", e) }));
    }

    // Point the instance's config at the file (or clear the pointer).
    let field = if which == "mine" { "spoofed_ip_file" } else { "peer_spoofed_ip_file" };
    let value = if attach { path.to_string_lossy().to_string() } else { String::new() };
    if let Err(e) = patch_instance_field(state, name, field, &value) {
        return Response::json(500, json!({ "error": format!("link file: {}", e) }));
    }

    Response::json(200, json!({ "ok": true, "count": set.total(), "attached": attach }))
}

/// Set one string field on an instance's stored config, then rewrite it.
fn patch_instance_field(state: &Arc<PanelState>, name: &str, field: &str, value: &str) -> anyhow::Result<()> {
    let path = PathBuf::from(&state.cfg.config_dir).join(format!("{}.toml", name));
    let text = std::fs::read_to_string(&path)?;
    let mut inst: PanelInstance = toml::from_str(&text)?;
    match field {
        "spoofed_ip_file" => inst.spoofed_ip_file = value.to_string(),
        "peer_spoofed_ip_file" => inst.peer_spoofed_ip_file = value.to_string(),
        _ => anyhow::bail!("unknown field"),
    }
    let header = format!("# CandyTunnel instance '{}' — generated by the web panel\n\n", name);
    let rendered = toml::to_string_pretty(&inst)?;
    std::fs::write(&path, format!("{}{}", header, rendered))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base64url_roundtrips() {
        for s in ["", "a", "ab", "abc", "abcd", "the quick brown fox \u{1f600}"] {
            let enc = b64url_encode(s.as_bytes());
            assert!(!enc.contains('='));
            assert_eq!(b64url_decode(&enc).unwrap(), s.as_bytes());
        }
    }

    fn server_instance() -> PanelInstance {
        let mut i = PanelInstance::default_client();
        i.role = "server".into();
        i.real_ip = "203.0.113.9".into();
        i.peer_real_ip = "0.0.0.0".into();
        i.spoofed_ip = "1.2.3.4".into();
        i.spoofed_ip_pool = vec!["1.2.3.4".into(), "5.6.7.8".into()];
        i.peer_spoofed_ip = "8.8.4.4".into();
        i.peer_spoofed_ip_pool = vec!["8.8.4.4".into(), "1.1.1.1".into()];
        i.data_port = 51820;
        i.icmp_id = 4321;
        i.pre_shared_key = "supersecretkey1234567890abcd".into();
        i.uplink_protocol = "icmp".into();
        i.downlink_protocol = "udp".into();
        i.tun_ip = "10.66.0.1".into();
        i.tun_peer_ip = "10.66.0.2".into();
        i
    }

    #[test]
    fn code_round_trips_into_mirrored_client() {
        let server = server_instance();
        let code = make_code(&server).unwrap();
        assert!(code.starts_with(CODE_PREFIX));

        let client = apply_code(&code, "10.0.0.5").unwrap();
        assert_eq!(client.role, "client");
        assert_eq!(client.real_ip, "10.0.0.5");
        assert_eq!(client.peer_real_ip, "203.0.113.9");
        // Spoof sets swap.
        assert_eq!(client.spoofed_ip_pool, vec!["8.8.4.4", "1.1.1.1"]);
        assert_eq!(client.peer_spoofed_ip_pool, vec!["1.2.3.4", "5.6.7.8"]);
        // TUN addresses swap.
        assert_eq!(client.tun_ip, "10.66.0.2");
        assert_eq!(client.tun_peer_ip, "10.66.0.1");
        // Protocols mirror: client.uplink == server.downlink.
        assert_eq!(client.uplink_protocol, "udp");
        assert_eq!(client.downlink_protocol, "icmp");
        assert_eq!(client.pre_shared_key, "supersecretkey1234567890abcd");

        // And the mirrored client renders to a config the real schema accepts.
        let toml_text = toml::to_string_pretty(&client).unwrap();
        Config::from_toml_str(&toml_text).expect("mirrored client should validate");
    }

    #[test]
    fn client_instance_cannot_make_a_code() {
        let mut c = server_instance();
        c.role = "client".into();
        assert!(make_code(&c).is_err());
    }

    #[test]
    fn bad_codes_are_rejected() {
        assert!(apply_code("nope", "1.1.1.1").is_err());
        assert!(apply_code("CT1.!!!!", "1.1.1.1").is_err());
    }
}
