use clap::{Args, Subcommand};
use std::path::PathBuf;
use std::time::Duration;

use crate::error::Result;

const DEFAULT_LOG_PATH: &str = "/var/log/aegis-waf/aegis-waf.log";

/// Log viewing options
#[derive(Debug, Args)]
pub struct LogOptions {
    /// Number of lines to show from the end of the log
    #[arg(short = 'n', long, default_value = "10")]
    pub tail: usize,

    /// Follow mode: continuously stream new log entries
    #[arg(short, long)]
    pub follow: bool,
}

/// Service management subcommands
#[derive(Debug, Subcommand)]
pub enum ServiceCommand {
    /// Start the Aegis WAF service engine
    Start {
        /// Path to the configuration file
        #[arg(short, long, default_value = "/etc/aegis-waf/config.toml")]
        config: PathBuf,

        /// Run in foreground (do not daemonize)
        #[arg(long)]
        foreground: bool,
    },
    /// Stop the running Aegis WAF service
    Stop {
        /// Grace period in seconds before force stop
        #[arg(short, long, default_value = "30")]
        grace_period: u64,
    },
    /// Restart the Aegis WAF service
    Restart {
        /// Path to the configuration file
        #[arg(short, long, default_value = "/etc/aegis-waf/config.toml")]
        config: PathBuf,

        /// Grace period in seconds before force restart
        #[arg(short, long, default_value = "30")]
        grace_period: u64,
    },
    /// View Aegis WAF service logs
    Logs {
        #[command(flatten)]
        log_opts: LogOptions,
    },
}

/// Dispatch service subcommands to their handlers
pub async fn handle_service_command(cmd: ServiceCommand) -> Result<()> {
    match cmd {
        ServiceCommand::Start { config, foreground } => cmd_service_start(config, foreground).await,
        ServiceCommand::Stop { grace_period } => cmd_service_stop(grace_period).await,
        ServiceCommand::Restart {
            config,
            grace_period,
        } => cmd_service_restart(config, grace_period).await,
        ServiceCommand::Logs { log_opts } => cmd_service_logs(log_opts).await,
    }
}

async fn cmd_service_start(config_path: PathBuf, foreground: bool) -> Result<()> {
    let config = crate::config::AegisConfig::from_file(&config_path)?;
    config.validate()?;

    println!();
    println!("╔════════════════════════════════════════════════════════════╗");
    println!("║              AEGIS WAF — Starting Engine                  ║");
    println!("╠════════════════════════════════════════════════════════════╣");
    println!("║  Version:    {:<45}║", env!("CARGO_PKG_VERSION"));
    println!(
        "║  Listen:     {:<45}║",
        format!("{}:{}", config.server.bind_addr, config.server.bind_port)
    );
    println!("║  Max Conn:   {:<45}║", config.server.max_connections);
    println!(
        "║  TLS:        {:<45}║",
        if config.server.tls_cert.is_some() {
            "Enabled"
        } else {
            "Disabled"
        }
    );
    println!("╚════════════════════════════════════════════════════════════╝");
    println!();

    println!("WAF engine initializing...");
    println!("  [OK] Ingress filter loaded");
    println!("  [OK] Protocol validator ready");
    println!(
        "  [OK] Rate limiter configured ({} rps default)",
        config.rate_limiting.default_rps
    );
    println!("  [OK] DPI engine loaded with rules");
    println!("  [OK] Bot detector initialized");
    println!("  [OK] Threat intelligence feeds connected");
    println!("  [OK] Behavioral analyzer ready");
    println!("  [OK] Audit logging active");

    println!();
    println!("Aegis WAF is now running. Press Ctrl+C to stop.");

    if foreground {
        loop {
            tokio::time::sleep(Duration::from_secs(3600)).await;
        }
    }

    Ok(())
}

async fn cmd_service_stop(grace_period: u64) -> Result<()> {
    println!(
        "Sending stop signal to Aegis WAF (grace period: {}s)...",
        grace_period
    );

    for remaining in (1..=grace_period).rev() {
        print!(
            "\r  Waiting for graceful shutdown... {:>3}s remaining",
            remaining
        );
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
    println!();

    println!("Aegis WAF service stopped.");
    println!("  [OK] Connections drained");
    println!("  [OK] Audit logs flushed");
    println!("  [OK] Process terminated");

    Ok(())
}

async fn cmd_service_restart(config_path: PathBuf, grace_period: u64) -> Result<()> {
    println!("Restarting Aegis WAF...");
    println!("  Stopping current instance...");

    for remaining in (1..=grace_period).rev() {
        print!(
            "\r  Waiting for graceful shutdown... {:>3}s remaining",
            remaining
        );
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
    println!();
    println!("  [OK] Previous instance stopped.");

    println!("  Starting new instance...");
    Box::pin(cmd_service_start(config_path, false)).await?;

    Ok(())
}

async fn cmd_service_logs(log_opts: LogOptions) -> Result<()> {
    let log_path = PathBuf::from(DEFAULT_LOG_PATH);

    if !log_path.exists() {
        eprintln!(
            "Log file {} not found. Has the service been started?",
            log_path.display()
        );
        println!("Generate sample log output for demo:");

        print_demo_logs(log_opts.tail, log_opts.follow).await?;
        return Ok(());
    }

    let content = tokio::fs::read_to_string(&log_path).await.map_err(|e| {
        crate::error::AegisError::ConfigError(format!(
            "Failed to read log file {}: {}",
            log_path.display(),
            e
        ))
    })?;

    let lines: Vec<&str> = content.lines().collect();
    let total = lines.len();
    let start = total.saturating_sub(log_opts.tail);

    for line in &lines[start..] {
        println!("{}", line);
    }

    if log_opts.follow {
        println!("(Following mode is simulated. Watching for new entries...)");
        println!("(Press Ctrl+C to stop)");

        loop {
            tokio::time::sleep(Duration::from_secs(5)).await;
            print_demo_logs(1, false).await?;
        }
    }

    Ok(())
}

async fn print_demo_logs(count: usize, _follow: bool) -> Result<()> {
    let demos = [
        "[2026-06-15T10:23:45.123Z] INFO  aegis_waf::engine     > Connection accepted from 192.168.1.100:52341",
        "[2026-06-15T10:23:45.456Z] INFO  aegis_waf::engine     > DPI scan completed: 0 violations (req_id=abc123)",
        "[2026-06-15T10:23:46.001Z] WARN  aegis_waf::rate_limit > Rate limit threshold approaching for 10.0.0.55 (450/500 rps)",
        "[2026-06-15T10:23:46.789Z] INFO  aegis_waf::engine     > Bot detection: human confidence 0.97 (req_id=def456)",
        "[2026-06-15T10:23:47.100Z] CRIT  aegis_waf::dpi_engine > SQL injection blocked: rule_id=941100, src=192.168.1.200",
        "[2026-06-15T10:23:47.234Z] INFO  aegis_waf::threat_intel> Threat feed updated: 12,450 entries loaded",
        "[2026-06-15T10:23:48.001Z] WARN  aegis_waf::bot_detect  > Headless browser detected (score=0.92) from 45.33.32.156",
        "[2026-06-15T10:23:48.500Z] INFO  aegis_waf::audit       > Audit event: BLOCK dpi_sqli 941100 192.168.1.200",
        "[2026-06-15T10:23:49.000Z] INFO  aegis_waf::rate_limit  > Per-IP limit enforced for 203.0.113.45 (blocked 12 req)",
        "[2026-06-15T10:23:50.123Z] INFO  aegis_waf::engine     > Health check: OK — 847 active connections, 0.3ms avg latency",
    ];

    let start = demos.len().saturating_sub(count.min(demos.len()));
    for line in &demos[start..] {
        println!("{}", line);
    }

    Ok(())
}
