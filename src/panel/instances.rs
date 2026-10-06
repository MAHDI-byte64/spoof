//! Instance management: list, read, create/update, delete, service control and
//! log tailing — the panel's equivalent of the `candy-manager.sh` operations.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use super::{run_cmd, valid_instance_name, PanelState, Response};
use crate::config::Config;

/// A full, panel-editable instance configuration. Every field has a serde
/// default so partial/legacy TOML files still load; IP-ish fields are kept as
/// strings so the rendered TOML round-trips cleanly and the real schema
/// (`Config::from_toml_str`) does the final validation on save.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PanelInstance {
    #[serde(default = "d_role")]
    pub role: String,

    #[serde(default)]
    pub real_ip: String,
    #[serde(default)]
    pub peer_real_ip: String,
    #[serde(default)]
    pub spoofed_ip: String,
    #[serde(default)]
    pub peer_spoofed_ip: String,
    #[serde(default)]
    pub spoofed_ip_pool: Vec<String>,
    #[serde(default)]
    pub allowed_peers: Vec<String>,

    #[serde(default = "d_proto")]
    pub uplink_protocol: String,
    #[serde(default = "d_proto")]
    pub downlink_protocol: String,
    #[serde(default = "d_data_port")]
    pub data_port: u16,
    #[serde(default)]
    pub shuffle_data_port: bool,
    #[serde(default = "d_sport_min")]
    pub shuffle_port_min: u16,
    #[serde(default = "d_sport_max")]
    pub shuffle_port_max: u16,
    #[serde(default = "d_icmp_id")]
    pub icmp_id: u16,
    #[serde(default)]
    pub random_icmp_id: bool,

    #[serde(default = "d_true")]
    pub enable_multiplex: bool,
    #[serde(default = "d_flush")]
    pub multiplex_flush_ms: u64,
    #[serde(default = "d_mux_payload")]
    pub multiplex_max_payload: usize,
    #[serde(default)]
    pub enable_fec: bool,
    #[serde(default = "d_fec")]
    pub fec_group_size: u8,

    #[serde(default = "d_quic_name")]
    pub quic_server_name: String,
    #[serde(default = "d_quic_cert")]
    pub quic_cert: String,
    #[serde(default = "d_quic_key")]
    pub quic_key: String,
    #[serde(default = "d_quic_alpn")]
    pub quic_alpn: String,
    #[serde(default = "d_quic_idle")]
    pub quic_idle_timeout_ms: u64,
    #[serde(default = "d_quic_max_data")]
    pub quic_max_data: u64,
    #[serde(default = "d_quic_stream")]
    pub quic_max_stream_data: u64,
    #[serde(default = "d_quic_streams")]
    pub quic_max_streams_bidi: u64,

    #[serde(default)]
    pub pre_shared_key: String,
    #[serde(default)]
    pub enable_xor: bool,
    #[serde(default)]
    pub xor_key: String,

    #[serde(default)]
    pub packet_padding: bool,
    #[serde(default = "d_pad_max")]
    pub packet_padding_max: u8,
    #[serde(default)]
    pub ttl_jitter: bool,
    #[serde(default)]
    pub fake_tls_header: bool,
    #[serde(default)]
    pub random_dscp: bool,

    #[serde(default = "d_tun_name")]
    pub tun_name: String,
    #[serde(default)]
    pub tun_ip: String,
    #[serde(default)]
    pub tun_peer_ip: String,
    #[serde(default = "d_netmask")]
    pub tun_netmask: String,
    #[serde(default = "d_mtu")]
    pub tun_mtu: usize,
    #[serde(default = "d_iface")]
    pub interface: String,
    #[serde(default)]
    pub forward_ports: Vec<u16>,
    #[serde(default)]
    pub forward_port: u16,

    #[serde(default = "d_perf")]
    pub perf_mode: String,
    #[serde(default = "d_true")]
    pub auto_tune: bool,
    #[serde(default = "d_tunnels")]
    pub tunnel_count: usize,
    #[serde(default = "d_mtu")]
    pub mtu: usize,
    #[serde(default = "d_chan")]
    pub channel_capacity: usize,
    #[serde(default = "d_iochan")]
    pub io_channel_capacity: usize,
    #[serde(default)]
    pub runtime_worker_threads: usize,
    #[serde(default)]
    pub send_threads: usize,
    #[serde(default = "d_send_batch")]
    pub send_batch: usize,
    #[serde(default = "d_recv_batch")]
    pub recv_batch: usize,

    #[serde(default = "d_log")]
    pub log_level: String,
}

fn d_role() -> String { "client".into() }
fn d_proto() -> String { "udp".into() }
fn d_data_port() -> u16 { 51820 }
fn d_sport_min() -> u16 { 49152 }
fn d_sport_max() -> u16 { 65535 }
fn d_icmp_id() -> u16 { 0x4321 }
fn d_true() -> bool { true }
fn d_flush() -> u64 { 1 }
fn d_mux_payload() -> usize { 1380 }
fn d_fec() -> u8 { 4 }
fn d_quic_name() -> String { "CandyTunnel".into() }
fn d_quic_cert() -> String { "/etc/candytunnel/quic_cert.pem".into() }
fn d_quic_key() -> String { "/etc/candytunnel/quic_key.pem".into() }
fn d_quic_alpn() -> String { "h3".into() }
fn d_quic_idle() -> u64 { 30000 }
fn d_quic_max_data() -> u64 { 134217728 }
fn d_quic_stream() -> u64 { 16777216 }
fn d_quic_streams() -> u64 { 256 }
fn d_pad_max() -> u8 { 64 }
fn d_tun_name() -> String { "candy0".into() }
fn d_netmask() -> String { "255.255.255.252".into() }
fn d_mtu() -> usize { 1380 }
fn d_iface() -> String { "eth0".into() }
fn d_perf() -> String { "throughput".into() }
fn d_tunnels() -> usize { 4 }
fn d_chan() -> usize { 8192 }
fn d_iochan() -> usize { 16384 }
fn d_send_batch() -> usize { 64 }
fn d_recv_batch() -> usize { 64 }
fn d_log() -> String { "info".into() }

fn cfg_path(state: &PanelState, name: &str) -> PathBuf {
    Path::new(&state.cfg.config_dir).join(format!("{}.toml", name))
}

fn service_name(state: &PanelState, name: &str) -> String {
    format!("{}@{}.service", state.cfg.service_prefix, name)
}

// ── List ──────────────────────────────────────────────────────────────────────

pub async fn list(state: &Arc<PanelState>) -> Response {
    let dir = PathBuf::from(&state.cfg.config_dir);
    let mut out = Vec::new();

    let entries = match std::fs::read_dir(&dir) {
        Ok(e) => e,
        Err(_) => return Response::json(200, json!({ "instances": [] })),
    };

    let mut names: Vec<String> = Vec::new();
    for entry in entries.flatten() {
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) == Some("toml") {
            // Skip the panel's own config if it lives in the same dir.
            if let Some(stem) = path.file_stem().and_then(|s| s.to_str()) {
                if stem == "panel" {
                    continue;
                }
                names.push(stem.to_string());
            }
        }
    }
    names.sort();

    for name in names {
        let path = cfg_path(state, &name);
        let (role, uplink, downlink, spoofing, valid) =
            match std::fs::read_to_string(&path).ok().and_then(|s| toml::from_str::<PanelInstance>(&s).ok()) {
                Some(inst) => {
                    let spoof = inst.spoofed_ip != inst.real_ip
                        || inst.peer_spoofed_ip != inst.peer_real_ip;
                    let valid = Config::from_toml_str(
                        &std::fs::read_to_string(&path).unwrap_or_default(),
                    )
                    .is_ok();
                    (inst.role, inst.uplink_protocol, inst.downlink_protocol, spoof, valid)
                }
                None => ("?".into(), "?".into(), "?".into(), false, false),
            };

        let svc = service_name(state, &name);
        let (_, active_out, _) = run_cmd("systemctl", vec!["is-active".into(), svc.clone()]).await;
        let (_, enabled_out, _) = run_cmd("systemctl", vec!["is-enabled".into(), svc.clone()]).await;

        out.push(json!({
            "name": name,
            "role": role,
            "uplink": uplink,
            "downlink": downlink,
            "spoofing": spoofing,
            "valid": valid,
            "active": active_out.trim() == "active",
            "status": active_out.trim(),
            "enabled": enabled_out.trim() == "enabled",
        }));
    }

    Response::json(200, json!({ "instances": out }))
}

// ── Read ────────────────────────────────────────────────────────────────────

pub async fn get(state: &Arc<PanelState>, name: &str) -> Response {
    if !valid_instance_name(name) {
        return Response::json(400, json!({ "error": "invalid instance name" }));
    }
    let path = cfg_path(state, name);
    match std::fs::read_to_string(&path) {
        Ok(s) => match toml::from_str::<PanelInstance>(&s) {
            Ok(inst) => Response::json(200, json!({ "name": name, "config": inst })),
            Err(e) => Response::json(500, json!({ "error": format!("parse: {}", e) })),
        },
        Err(_) => Response::json(404, json!({ "error": "instance not found" })),
    }
}

// ── Create / update ─────────────────────────────────────────────────────────

#[derive(Deserialize)]
struct SaveReq {
    name: String,
    config: PanelInstance,
}

pub async fn create_or_update(state: &Arc<PanelState>, req: &super::Request) -> Response {
    let body: SaveReq = match req.json() {
        Ok(b) => b,
        Err(e) => return Response::json(400, json!({ "error": format!("{}", e) })),
    };
    if !valid_instance_name(&body.name) {
        return Response::json(400, json!({ "error": "invalid instance name (A-Z a-z 0-9 _ - , 1-32 chars)" }));
    }

    let toml_text = match toml::to_string_pretty(&body.config) {
        Ok(t) => t,
        Err(e) => return Response::json(400, json!({ "error": format!("render: {}", e) })),
    };

    // Validate against the real schema before writing anything.
    if let Err(e) = Config::from_toml_str(&toml_text) {
        return Response::json(400, json!({ "error": format!("invalid config: {}", e) }));
    }

    if let Err(e) = std::fs::create_dir_all(&state.cfg.config_dir) {
        return Response::json(500, json!({ "error": format!("mkdir: {}", e) }));
    }

    let header = format!(
        "# CandyTunnel instance '{}' — generated by the web panel\n\n",
        body.name
    );
    let path = cfg_path(state, &body.name);
    if let Err(e) = std::fs::write(&path, format!("{}{}", header, toml_text)) {
        return Response::json(500, json!({ "error": format!("write: {}", e) }));
    }

    // The systemd template is only required to start/enable the service, so a
    // failure here (e.g. not root yet) must not block saving the config.
    if let Err(e) = ensure_template(state).await {
        log::debug!("systemd template not installed yet: {}", e);
    }

    Response::json(200, json!({ "ok": true, "name": body.name }))
}

// ── Delete ────────────────────────────────────────────────────────────────────

pub async fn remove(state: &Arc<PanelState>, name: &str) -> Response {
    if !valid_instance_name(name) {
        return Response::json(400, json!({ "error": "invalid instance name" }));
    }
    let svc = service_name(state, name);
    let _ = run_cmd("systemctl", vec!["stop".into(), svc.clone()]).await;
    let _ = run_cmd("systemctl", vec!["disable".into(), svc.clone()]).await;
    let path = cfg_path(state, name);
    let _ = std::fs::remove_file(&path);
    let _ = run_cmd("systemctl", vec!["daemon-reload".into()]).await;
    Response::json(200, json!({ "ok": true }))
}

// ── Service control ─────────────────────────────────────────────────────────

#[derive(Deserialize)]
struct ActionReq {
    action: String,
}

pub async fn action(state: &Arc<PanelState>, req: &super::Request, name: &str) -> Response {
    if !valid_instance_name(name) {
        return Response::json(400, json!({ "error": "invalid instance name" }));
    }
    let body: ActionReq = match req.json() {
        Ok(b) => b,
        Err(_) => return Response::json(400, json!({ "error": "bad request" })),
    };
    let verb = match body.action.as_str() {
        "start" | "stop" | "restart" | "enable" | "disable" => body.action.as_str(),
        _ => return Response::json(400, json!({ "error": "unknown action" })),
    };

    if matches!(verb, "start" | "enable") {
        if let Err(e) = ensure_template(state).await {
            return Response::json(500, json!({ "error": format!("systemd template: {}", e) }));
        }
    }

    let svc = service_name(state, name);
    let (ok, _out, err) = run_cmd("systemctl", vec![verb.into(), svc.clone()]).await;
    if ok {
        Response::json(200, json!({ "ok": true, "action": verb }))
    } else {
        Response::json(500, json!({ "error": err.trim() }))
    }
}

// ── Logs ──────────────────────────────────────────────────────────────────────

pub async fn logs(state: &Arc<PanelState>, req: &super::Request, name: &str) -> Response {
    if !valid_instance_name(name) {
        return Response::json(400, json!({ "error": "invalid instance name" }));
    }
    let lines = req
        .query
        .get("lines")
        .and_then(|v| v.parse::<u32>().ok())
        .unwrap_or(120)
        .min(2000);
    let svc = service_name(state, name);
    let (_, out, err) = run_cmd(
        "journalctl",
        vec![
            "-u".into(),
            svc,
            "-n".into(),
            lines.to_string(),
            "--no-pager".into(),
            "--output".into(),
            "short-iso".into(),
        ],
    )
    .await;
    let text = if out.trim().is_empty() { err } else { out };
    Response::json(200, json!({ "logs": text }))
}

// ── systemd template ───────────────────────────────────────────────────────

async fn ensure_template(state: &Arc<PanelState>) -> std::io::Result<()> {
    let template = format!(
        "/etc/systemd/system/{}@.service",
        state.cfg.service_prefix
    );
    if Path::new(&template).exists() {
        return Ok(());
    }
    let unit = format!(
        "[Unit]\n\
         Description=CandyTunnel instance %i\n\
         Documentation=https://github.com/MAHDI-byte64/spoof\n\
         After=network-online.target\n\
         Wants=network-online.target\n\
         StartLimitIntervalSec=60\n\
         StartLimitBurst=5\n\n\
         [Service]\n\
         Type=simple\n\
         User=root\n\
         ExecStart={bin} --config {dir}/%i.toml\n\
         Restart=on-failure\n\
         RestartSec=5\n\
         StandardOutput=journal\n\
         StandardError=journal\n\
         SyslogIdentifier={prefix}-%i\n\
         AmbientCapabilities=CAP_NET_RAW CAP_NET_ADMIN\n\
         CapabilityBoundingSet=CAP_NET_RAW CAP_NET_ADMIN\n\
         NoNewPrivileges=false\n\
         LimitNOFILE=65536\n\
         LimitMEMLOCK=infinity\n\n\
         [Install]\n\
         WantedBy=multi-user.target\n",
        bin = state.cfg.bin_path,
        dir = state.cfg.config_dir,
        prefix = state.cfg.service_prefix,
    );
    std::fs::write(&template, unit)?;
    let _ = run_cmd("systemctl", vec!["daemon-reload".into()]).await;
    Ok(())
}

/// Serialize helper reused by tests/other modules if needed.
pub fn _to_value(inst: &PanelInstance) -> Value {
    serde_json::to_value(inst).unwrap_or(Value::Null)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A fully-defaulted PanelInstance, once the required addressing fields are
    /// filled, must render to TOML that the real Config schema accepts.
    #[test]
    fn panel_instance_renders_valid_config() {
        let json = serde_json::json!({
            "role": "client",
            "real_ip": "10.0.0.2",
            "peer_real_ip": "203.0.113.9",
            "spoofed_ip": "8.8.4.4",
            "peer_spoofed_ip": "1.2.3.4",
            "data_port": 51820,
            "icmp_id": 17185,
            "pre_shared_key": "supersecretkey1234567890abcd",
            "interface": "eth0",
            "tun_ip": "10.66.0.2",
            "tun_peer_ip": "10.66.0.1",
            "send_threads": 4,
            "send_batch": 128,
            "recv_batch": 96
        });
        let inst: PanelInstance = serde_json::from_value(json).unwrap();
        let toml_text = toml::to_string_pretty(&inst).unwrap();
        let cfg = Config::from_toml_str(&toml_text).expect("rendered config should validate");
        assert_eq!(cfg.data_port, 51820);
        assert_eq!(cfg.send_threads, 4);
        assert_eq!(cfg.effective_send_batch(), 128);
    }

    /// Rejecting an invalid edit (identical TUN IPs) before it is written.
    #[test]
    fn invalid_panel_instance_is_rejected() {
        let json = serde_json::json!({
            "role": "client",
            "real_ip": "10.0.0.2", "peer_real_ip": "203.0.113.9",
            "spoofed_ip": "8.8.4.4", "peer_spoofed_ip": "1.2.3.4",
            "data_port": 51820, "icmp_id": 1, "pre_shared_key": "k",
            "interface": "eth0", "tun_ip": "10.66.0.1", "tun_peer_ip": "10.66.0.1"
        });
        let inst: PanelInstance = serde_json::from_value(json).unwrap();
        let toml_text = toml::to_string_pretty(&inst).unwrap();
        assert!(Config::from_toml_str(&toml_text).is_err());
    }
}
