//! Lightweight host facts for the panel dashboard.

use serde::Serialize;

#[derive(Serialize)]
pub struct SystemInfo {
    pub hostname: String,
    pub cpu_cores: usize,
    pub mem_total_gb: f64,
    pub mem_available_gb: f64,
    pub uptime_secs: u64,
    pub load_avg: [f64; 3],
    pub binary_version: String,
}

pub fn collect() -> SystemInfo {
    SystemInfo {
        hostname: read_hostname(),
        cpu_cores: std::thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(1),
        mem_total_gb: read_meminfo_gb("MemTotal:").unwrap_or(0.0),
        mem_available_gb: read_meminfo_gb("MemAvailable:").unwrap_or(0.0),
        uptime_secs: read_uptime().unwrap_or(0),
        load_avg: read_loadavg().unwrap_or([0.0, 0.0, 0.0]),
        binary_version: env!("CARGO_PKG_VERSION").to_string(),
    }
}

fn read_hostname() -> String {
    std::fs::read_to_string("/proc/sys/kernel/hostname")
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|_| "unknown".to_string())
}

fn read_meminfo_gb(key: &str) -> Option<f64> {
    let data = std::fs::read_to_string("/proc/meminfo").ok()?;
    for line in data.lines() {
        if let Some(rest) = line.strip_prefix(key) {
            let kb: f64 = rest.split_whitespace().next()?.parse().ok()?;
            return Some(kb / 1024.0 / 1024.0);
        }
    }
    None
}

fn read_uptime() -> Option<u64> {
    let data = std::fs::read_to_string("/proc/uptime").ok()?;
    let secs: f64 = data.split_whitespace().next()?.parse().ok()?;
    Some(secs as u64)
}

fn read_loadavg() -> Option<[f64; 3]> {
    let data = std::fs::read_to_string("/proc/loadavg").ok()?;
    let mut it = data.split_whitespace();
    Some([
        it.next()?.parse().ok()?,
        it.next()?.parse().ok()?,
        it.next()?.parse().ok()?,
    ])
}
