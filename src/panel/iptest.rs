//! Panel bridge to the in-process spoofed-IP tester ([`crate::tester`]).
//!
//! The panel runs with `CAP_NET_RAW`, so the sender/receiver run inside the
//! panel process rather than shelling out. One run at a time, polled by the UI.

use std::sync::Arc;

use serde::Deserialize;
use serde_json::{json, Value};

use super::{PanelState, Request, Response};
use crate::iplist::IpRangeSet;
use crate::tester::{Mode, Probe, TesterConfig};

#[derive(Deserialize)]
struct StartReq {
    /// "sender" or "receiver".
    mode: String,
    /// "tcp", "udp" or "icmp".
    #[serde(default = "d_proto")]
    protocol: String,
    /// Candidate IPs: single, CIDR or a-b per line.
    ips: String,
    /// Sender: the receiver's real IP.
    #[serde(default)]
    target: String,
    #[serde(default = "d_port")]
    port: u16,
    #[serde(default = "d_packets")]
    packets_per_ip: u32,
    #[serde(default = "d_timeout")]
    timeout_secs: u64,
    #[serde(default = "d_loss")]
    max_loss_pct: f64,
    #[serde(default = "d_rate")]
    rate_pps: u32,
}

fn d_proto() -> String { "tcp".into() }
fn d_port() -> u16 { 443 }
fn d_packets() -> u32 { 10 }
fn d_timeout() -> u64 { 60 }
fn d_loss() -> f64 { 20.0 }
fn d_rate() -> u32 { 3000 }

pub async fn start(state: &Arc<PanelState>, req: &Request) -> Response {
    let body: StartReq = match req.json() {
        Ok(b) => b,
        Err(e) => return Response::json(400, json!({ "error": format!("{}", e) })),
    };

    let mode = match body.mode.as_str() {
        "sender" => Mode::Sender,
        "receiver" => Mode::Receiver,
        _ => return Response::json(400, json!({ "error": "mode must be sender or receiver" })),
    };
    let protocol = match body.protocol.as_str() {
        "tcp" => Probe::Tcp,
        "udp" => Probe::Udp,
        "icmp" => Probe::Icmp,
        _ => return Response::json(400, json!({ "error": "protocol must be tcp, udp or icmp" })),
    };
    let target = if body.target.trim().is_empty() {
        None
    } else {
        match body.target.trim().parse() {
            Ok(ip) => Some(ip),
            Err(_) => return Response::json(400, json!({ "error": "invalid target IP" })),
        }
    };

    let candidates = match IpRangeSet::parse(&body.ips) {
        Ok(s) => s,
        Err(e) => return Response::json(400, json!({ "error": format!("invalid IP list: {:#}", e) })),
    };

    let cfg = TesterConfig {
        mode,
        protocol,
        target,
        port: body.port,
        packets_per_ip: body.packets_per_ip,
        timeout_secs: body.timeout_secs,
        max_loss_pct: body.max_loss_pct,
        rate_pps: body.rate_pps,
    };

    match state.tester.start(cfg, candidates) {
        Ok(()) => Response::json(200, json!({ "ok": true })),
        Err(e) => Response::json(400, json!({ "error": format!("{:#}", e) })),
    }
}

pub fn stop(state: &Arc<PanelState>) -> Response {
    state.tester.stop();
    Response::json(200, json!({ "ok": true }))
}

pub fn status(state: &Arc<PanelState>) -> Response {
    let st = state.tester.state();
    let results: Vec<Value> = state
        .tester
        .results()
        .into_iter()
        .map(|r| {
            json!({
                "ip": r.ip.to_string(),
                "received": r.received,
                "expected": r.expected,
                "loss_pct": r.loss_pct,
                "passed": r.passed,
            })
        })
        .collect();
    Response::json(200, json!({ "state": st, "results": results }))
}
