//! CandyTunnel unified binary (client/server/panel).
//!
//! Usage:
//!   candy-tunnel --config /etc/candytunnel/client.toml
//!   candy-tunnel panel  --config /etc/candytunnel/panel.toml

use std::sync::Arc;
use std::time::Duration;

use anyhow::{bail, Result};
use clap::{Parser, Subcommand};

use CandyTunnel::app::{run_client, run_server};
use CandyTunnel::check::{run_spoof_check, CheckOptions};
use CandyTunnel::config::{Config, TunnelRole};
use CandyTunnel::logging::{init_logging, log_tune_summary, print_banner};
use CandyTunnel::panel::{run_panel, set_password, PanelOptions};
use CandyTunnel::tuning::{apply_auto_tune, effective_runtime_threads};

#[derive(Parser, Debug)]
#[command(name = "candy-tunnel", about = "CandyTunnel unified client/server/panel")]
struct Args {
    #[command(subcommand)]
    command: Option<Command>,

    /// Path to the TOML configuration file.
    #[arg(short, long, default_value = "config/client.toml", global = true)]
    config: String,

    /// Override log level (e.g. debug, info, warn).
    #[arg(short, long, global = true)]
    log_level: Option<String>,

    /// Run spoofed IP check mode (client role only).
    #[arg(long)]
    check: bool,

    /// IP list file (one IPv4 per line) used for check mode.
    #[arg(long, required_if_eq("check", "true"))]
    check_ips: Option<String>,

    /// Output file for check results.
    #[arg(long, default_value = "check_latency.txt")]
    check_out: String,

    /// Timeout per IP in milliseconds.
    #[arg(long, default_value = "1500")]
    check_timeout_ms: u64,

    /// Concurrent workers for check mode.
    #[arg(long, default_value = "64")]
    check_workers: usize,

    /// SYN probes fired per candidate IP in check mode (fastest reply wins).
    #[arg(long, default_value = "2")]
    check_probes: usize,

    /// Allow any source IP (bypass allowlist) for check mode on server.
    #[arg(long)]
    check_allow_any: bool,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// Run the bilingual web management panel.
    Panel(PanelArgs),
}

#[derive(Parser, Debug)]
struct PanelArgs {
    /// Override the bind address (host:port). Defaults to the panel config.
    #[arg(long)]
    bind: Option<String>,

    /// Set the panel password interactively and exit.
    #[arg(long)]
    set_password: bool,

    /// One-shot password for this run (prefer --set-password for persistence).
    #[arg(long)]
    password: Option<String>,
}

fn main() -> Result<()> {
    let args = Args::parse();

    // ── Panel subcommand ──────────────────────────────────────────────────
    if let Some(Command::Panel(p)) = &args.command {
        // The panel's default config path differs from the tunnel default.
        let panel_config = if args.config == "config/client.toml" {
            "/etc/candytunnel/panel.toml".to_string()
        } else {
            args.config.clone()
        };

        if p.set_password {
            return set_password(&panel_config);
        }

        init_logging(args.log_level.as_deref().unwrap_or("info"));
        print_banner("panel", env!("CARGO_PKG_VERSION"));

        let opts = PanelOptions {
            config_path: panel_config,
            bind_override: p.bind.clone(),
            password_override: p.password.clone(),
        };

        let rt = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()?;
        return rt.block_on(run_panel(opts));
    }

    // ── Tunnel / check mode ───────────────────────────────────────────────
    let mut cfg = Config::from_file(&args.config)?;
    let level = args.log_level.as_deref().unwrap_or(cfg.log_level.as_str());
    init_logging(level);
    let role = format!("{:?}", cfg.role);
    print_banner(&role, env!("CARGO_PKG_VERSION"));
    let summary = apply_auto_tune(&mut cfg);
    if let Some(s) = &summary {
        log_tune_summary(s);
    }

    let cfg = Arc::new(cfg);
    let threads = effective_runtime_threads(&cfg);
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(threads)
        .enable_all()
        .build()?;
    rt.block_on(async_main(cfg, args))
}

async fn async_main(cfg: Arc<Config>, args: Args) -> Result<()> {
    match cfg.role {
        TunnelRole::Client => {
            if args.check {
                let ips_path = args.check_ips.unwrap_or_else(|| "check_ips.txt".to_string());
                let opts = CheckOptions {
                    ips_path,
                    out_path: args.check_out,
                    timeout: Duration::from_millis(args.check_timeout_ms),
                    workers: args.check_workers,
                    probes: args.check_probes,
                };
                return run_spoof_check(cfg, opts).await;
            }
            run_client(cfg).await
        }
        TunnelRole::Server => run_server(cfg, args.check_allow_any).await,
        #[allow(unreachable_patterns)]
        _ => bail!("unknown role"),
    }
}
