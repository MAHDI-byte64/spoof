//! In-panel throughput test driven by `iperf3`.
//!
//! Runs `iperf3 -c <target> -J` as a background job (so the panel stays
//! responsive) and parses the JSON summary into send/receive Mbit/s. The other
//! end of the tunnel must be running `iperf3 -s`. Pointing `target` at the
//! peer's TUN IP measures real end-to-end tunnel throughput.

use std::sync::{Arc, Mutex};
use std::time::Instant;

use dashmap::DashMap;
use serde::Deserialize;
use serde_json::{json, Value};

use super::{PanelState, Request, Response};

struct SpeedJob {
    state: &'static str, // running | done | error
    started: Instant,
    elapsed_secs: u64,
    protocol: String,
    reverse: bool,
    mbps_sent: Option<f64>,
    mbps_recv: Option<f64>,
    error: Option<String>,
}

#[derive(Clone)]
pub struct SpeedStore {
    jobs: Arc<DashMap<String, Arc<Mutex<SpeedJob>>>>,
}

impl SpeedStore {
    pub fn new() -> Self {
        Self { jobs: Arc::new(DashMap::new()) }
    }
}

#[derive(Deserialize)]
struct StartReq {
    target: String,
    #[serde(default)]
    port: Option<u16>,
    #[serde(default)]
    duration: Option<u64>,
    #[serde(default)]
    udp: bool,
    /// Measure download (server → client) instead of upload.
    #[serde(default)]
    reverse: bool,
}

/// Only hostnames/IPs: letters, digits, dot, dash, colon (IPv6). Prevents any
/// surprising argv content even though we never use a shell.
fn valid_target(t: &str) -> bool {
    !t.is_empty()
        && t.len() <= 253
        && t.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | ':'))
}

pub async fn start(state: &Arc<PanelState>, req: &Request) -> Response {
    let body: StartReq = match req.json() {
        Ok(b) => b,
        Err(e) => return Response::json(400, json!({ "error": format!("{}", e) })),
    };
    if !valid_target(&body.target) {
        return Response::json(400, json!({ "error": "invalid target host/IP" }));
    }
    let duration = body.duration.unwrap_or(10).clamp(1, 60);
    let port = body.port.unwrap_or(5201);
    let protocol = if body.udp { "udp" } else { "tcp" }.to_string();

    let job = Arc::new(Mutex::new(SpeedJob {
        state: "running",
        started: Instant::now(),
        elapsed_secs: 0,
        protocol: protocol.clone(),
        reverse: body.reverse,
        mbps_sent: None,
        mbps_recv: None,
        error: None,
    }));
    let job_id = super::auth::new_token();
    state.speed.jobs.insert(job_id.clone(), job.clone());

    let mut args = vec![
        "-c".to_string(),
        body.target.clone(),
        "-p".to_string(),
        port.to_string(),
        "-t".to_string(),
        duration.to_string(),
        "-J".to_string(),
    ];
    if body.udp {
        args.push("-u".to_string());
        // Remove the default UDP bitrate cap so the test finds the ceiling.
        args.push("-b".to_string());
        args.push("0".to_string());
    }
    if body.reverse {
        args.push("-R".to_string());
    }

    tokio::spawn(async move {
        let (ok, out, err) = super::run_cmd("iperf3", args).await;
        let mut j = job.lock().unwrap();
        j.elapsed_secs = j.started.elapsed().as_secs();

        // iperf3 emits JSON on stdout even on error (with an "error" field).
        let parsed: Option<Value> = serde_json::from_str(&out).ok();
        if let Some(v) = parsed {
            if let Some(e) = v.get("error").and_then(|e| e.as_str()) {
                j.state = "error";
                j.error = Some(e.to_string());
            } else {
                let end = &v["end"];
                let bps = |path: &Value| path.get("bits_per_second").and_then(|b| b.as_f64());
                // TCP: sum_sent / sum_received. UDP: a single "sum".
                j.mbps_sent = bps(&end["sum_sent"]).or_else(|| bps(&end["sum"])).map(|b| b / 1e6);
                j.mbps_recv = bps(&end["sum_received"]).or_else(|| bps(&end["sum"])).map(|b| b / 1e6);
                j.state = "done";
            }
        } else if !ok {
            // No JSON at all — usually iperf3 missing or a connection failure.
            let msg = if err.contains("No such file") || err.contains("not found") {
                "iperf3 not installed on this host (apt-get install -y iperf3)".to_string()
            } else if err.trim().is_empty() {
                "iperf3 failed (is `iperf3 -s` running on the target?)".to_string()
            } else {
                err.trim().to_string()
            };
            j.state = "error";
            j.error = Some(msg);
        } else {
            j.state = "error";
            j.error = Some("could not parse iperf3 output".to_string());
        }
    });

    Response::json(200, json!({ "job_id": job_id }))
}

pub fn status(state: &Arc<PanelState>, id: &str) -> Response {
    let Some(job) = state.speed.jobs.get(id).map(|j| j.clone()) else {
        return Response::json(404, json!({ "error": "job not found" }));
    };
    let j = job.lock().unwrap();
    let elapsed = if j.state == "running" {
        j.started.elapsed().as_secs()
    } else {
        j.elapsed_secs
    };
    let resp = json!({
        "state": j.state,
        "elapsed_secs": elapsed,
        "protocol": j.protocol,
        "reverse": j.reverse,
        "mbps_sent": j.mbps_sent,
        "mbps_recv": j.mbps_recv,
        "error": j.error,
    });
    let finished = j.state != "running";
    drop(j);
    if finished {
        state.speed.jobs.retain(|_, v| {
            let g = v.lock().unwrap();
            g.state == "running" || g.started.elapsed().as_secs() < 600
        });
    }
    Response::json(200, resp)
}
