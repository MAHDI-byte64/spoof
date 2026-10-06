//! Background spoofed-IP test jobs driven from the panel.
//!
//! A job shells out to `candy-tunnel --config <instance> --check …` (so the
//! sweep runs with the same raw-socket code path as the CLI), then parses the
//! ranked result file when the process exits. Progress is polled via a job id.

use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Instant;

use dashmap::DashMap;
use serde::Deserialize;
use serde_json::{json, Value};

use super::{valid_instance_name, PanelState, Request, Response};

const MAX_IPS: usize = 20_000;

struct ResultRow {
    ip: String,
    latency_ms: Option<u64>,
}

struct Job {
    state: &'static str, // "running" | "done" | "error"
    started: Instant,
    elapsed_secs: u64,
    total: usize,
    reachable: usize,
    results: Vec<ResultRow>,
    error: Option<String>,
}

#[derive(Clone)]
pub struct JobStore {
    jobs: Arc<DashMap<String, Arc<Mutex<Job>>>>,
}

impl JobStore {
    pub fn new() -> Self {
        Self {
            jobs: Arc::new(DashMap::new()),
        }
    }
}

#[derive(Deserialize)]
struct StartReq {
    instance: String,
    ips: String,
    #[serde(default)]
    timeout_ms: Option<u64>,
    #[serde(default)]
    probes: Option<usize>,
    #[serde(default)]
    workers: Option<usize>,
}

pub async fn start(state: &Arc<PanelState>, req: &Request) -> Response {
    let body: StartReq = match req.json() {
        Ok(b) => b,
        Err(e) => return Response::json(400, json!({ "error": format!("{}", e) })),
    };
    if !valid_instance_name(&body.instance) {
        return Response::json(400, json!({ "error": "invalid instance name" }));
    }

    let cfg_path = PathBuf::from(&state.cfg.config_dir).join(format!("{}.toml", body.instance));
    if !cfg_path.exists() {
        return Response::json(404, json!({ "error": "instance config not found" }));
    }

    // Normalise the candidate list.
    let mut ip_lines: Vec<String> = Vec::new();
    for line in body.ips.lines() {
        let tok = line.trim().split_whitespace().next().unwrap_or("");
        if tok.is_empty() || tok.starts_with('#') {
            continue;
        }
        if tok.parse::<std::net::Ipv4Addr>().is_ok() {
            ip_lines.push(tok.to_string());
        }
    }
    ip_lines.sort();
    ip_lines.dedup();
    if ip_lines.is_empty() {
        return Response::json(400, json!({ "error": "no valid IPv4 addresses provided" }));
    }
    if ip_lines.len() > MAX_IPS {
        return Response::json(400, json!({ "error": format!("too many IPs (max {})", MAX_IPS) }));
    }
    let total = ip_lines.len();

    let timeout_ms = body.timeout_ms.unwrap_or(1500).clamp(100, 10_000);
    let probes = body.probes.unwrap_or(2).clamp(1, 10);
    let workers = body.workers.unwrap_or(64).clamp(1, 512);

    let job_id = super::auth::new_token();
    let tmp = std::env::temp_dir();
    let ips_path = tmp.join(format!("candytunnel-iptest-{}.ips", job_id));
    let out_path = tmp.join(format!("candytunnel-iptest-{}.out", job_id));

    if let Err(e) = std::fs::write(&ips_path, ip_lines.join("\n")) {
        return Response::json(500, json!({ "error": format!("write ip list: {}", e) }));
    }

    let job = Arc::new(Mutex::new(Job {
        state: "running",
        started: Instant::now(),
        elapsed_secs: 0,
        total,
        reachable: 0,
        results: Vec::new(),
        error: None,
    }));
    state.jobs.jobs.insert(job_id.clone(), job.clone());

    let bin = state.cfg.bin_path.clone();
    let cfg_str = cfg_path.to_string_lossy().to_string();
    let ips_str = ips_path.to_string_lossy().to_string();
    let out_str = out_path.to_string_lossy().to_string();

    tokio::spawn(async move {
        let args = vec![
            "--config".to_string(),
            cfg_str,
            "--check".to_string(),
            "--check-ips".to_string(),
            ips_str,
            "--check-out".to_string(),
            out_str.clone(),
            "--check-timeout-ms".to_string(),
            timeout_ms.to_string(),
            "--check-workers".to_string(),
            workers.to_string(),
            "--check-probes".to_string(),
            probes.to_string(),
            "--log-level".to_string(),
            "warn".to_string(),
        ];
        let (ok, _out, err) = super::run_cmd(&bin, args).await;

        let mut j = job.lock().unwrap();
        j.elapsed_secs = j.started.elapsed().as_secs();
        if !ok {
            j.state = "error";
            j.error = Some(if err.trim().is_empty() {
                "check process failed".into()
            } else {
                err.trim().to_string()
            });
        } else {
            match parse_results(&out_str) {
                Ok(rows) => {
                    j.reachable = rows.iter().filter(|r| r.latency_ms.is_some()).count();
                    j.results = rows;
                    j.state = "done";
                }
                Err(e) => {
                    j.state = "error";
                    j.error = Some(format!("parse results: {}", e));
                }
            }
        }
        drop(j);

        let _ = std::fs::remove_file(&ips_path);
        let _ = std::fs::remove_file(&out_path);
    });

    Response::json(200, json!({ "job_id": job_id, "total": total }))
}

pub fn status(state: &Arc<PanelState>, id: &str) -> Response {
    let Some(job) = state.jobs.jobs.get(id).map(|j| j.clone()) else {
        return Response::json(404, json!({ "error": "job not found" }));
    };
    let j = job.lock().unwrap();
    let elapsed = if j.state == "running" {
        j.started.elapsed().as_secs()
    } else {
        j.elapsed_secs
    };

    let results: Vec<Value> = j
        .results
        .iter()
        .map(|r| json!({ "ip": r.ip, "latency_ms": r.latency_ms }))
        .collect();

    let resp = json!({
        "state": j.state,
        "total": j.total,
        "reachable": j.reachable,
        "elapsed_secs": elapsed,
        "error": j.error,
        "results": results,
    });

    // Reap finished jobs after they've been read at least once to bound memory.
    let finished = j.state != "running";
    drop(j);
    if finished {
        // Keep it for a short grace window; drop very old finished jobs.
        state.jobs.jobs.retain(|_, v| {
            let g = v.lock().unwrap();
            g.state == "running" || g.started.elapsed().as_secs() < 600
        });
    }

    Response::json(200, resp)
}

fn parse_results(path: &str) -> std::io::Result<Vec<ResultRow>> {
    let content = std::fs::read_to_string(path)?;
    let mut rows = Vec::new();
    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let mut it = line.split_whitespace();
        let Some(ip) = it.next() else { continue };
        let latency_ms = match it.next() {
            Some("timeout") => None,
            Some(v) => v.parse::<u64>().ok(),
            None => None,
        };
        rows.push(ResultRow {
            ip: ip.to_string(),
            latency_ms,
        });
    }
    Ok(rows)
}
