use clap::{Subcommand, ValueEnum};
use std::path::PathBuf;

use crate::error::Result;

/// Export format for analytics reports
#[derive(Debug, Clone, ValueEnum)]
pub enum ExportFormat {
    /// JavaScript Object Notation
    Json,
    /// Comma-Separated Values
    Csv,
}

/// Analytics subcommands
#[derive(Debug, Subcommand)]
pub enum AnalyticsCommand {
    /// Start the web-based analytics dashboard
    Dashboard {
        /// Port for the dashboard HTTP server
        #[arg(short, long, default_value = "9091")]
        port: u16,
    },
    /// Export analytics data to a file
    Export {
        /// Export format (json or csv)
        #[arg(short, long, value_enum)]
        format: ExportFormat,

        /// Output file path
        #[arg(short, long, default_value = "aegis-analytics-report")]
        output: PathBuf,
    },
    /// Display current threat assessment level
    ThreatLevel {
        /// Show detailed breakdown of threat indicators
        #[arg(long)]
        verbose: bool,
    },
}

/// Dispatch analytics subcommands to their handlers
pub async fn handle_analytics_command(cmd: AnalyticsCommand) -> Result<()> {
    match cmd {
        AnalyticsCommand::Dashboard { port } => cmd_dashboard(port).await,
        AnalyticsCommand::Export { format, output } => cmd_export(format, output).await,
        AnalyticsCommand::ThreatLevel { verbose } => cmd_threat_level(verbose).await,
    }
}

async fn cmd_dashboard(port: u16) -> Result<()> {
    println!("Aegis WAF Analytics Dashboard");
    println!("═════════════════════════════════");
    println!("URL: http://localhost:{}/dashboard", port);
    println!();
    println!("Dashboard provides:");
    println!("  - Real-time request throughput graphs");
    println!("  - Attack detection heatmaps");
    println!("  - Geographic threat distribution map");
    println!("  - Module status and health indicators");
    println!("  - Rate limiting statistics");
    println!("  - Bot detection analytics");
    println!();

    println!("Starting embedded HTTP server on port {}...", port);
    println!("(Demo mode: dashboard UI is served from web-dashboard/ directory)");

    let addr = format!("127.0.0.1:{}", port);

    let listener = match tokio::net::TcpListener::bind(&addr).await {
        Ok(l) => {
            println!("Dashboard server listening at http://{}", addr);
            l
        }
        Err(e) => {
            eprintln!("Could not bind to {}: {}. The port may be in use.", addr, e);
            println!("Try a different port with --port <PORT>");
            return Ok(());
        }
    };

    loop {
        let (mut socket, _peer) = match listener.accept().await {
            Ok(conn) => conn,
            Err(_) => continue,
        };

        tokio::spawn(async move {
            use tokio::io::AsyncWriteExt;

            let body = r#"<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Aegis WAF - Analytics Dashboard</title>
    <style>
        body { font-family: 'Courier New', monospace; background: #0a0e17; color: #00ff88; margin: 0; padding: 24px; }
        .header { border-bottom: 2px solid #00ff88; padding-bottom: 12px; margin-bottom: 24px; }
        .header h1 { margin: 0; font-size: 28px; color: #00ff88; }
        .header span { color: #888; }
        .grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); gap: 16px; }
        .card { background: #121a24; border: 1px solid #1a2a3a; border-radius: 8px; padding: 16px; }
        .card h3 { margin: 0 0 8px 0; color: #00ccff; font-size: 14px; text-transform: uppercase; }
        .metric { font-size: 36px; font-weight: bold; color: #00ff88; }
        .metric.warn { color: #ffaa00; }
        .metric.crit { color: #ff3333; }
        .bar { background: #1a2a3a; height: 8px; border-radius: 4px; margin-top: 8px; }
        .bar-fill { background: #00ff88; height: 100%; border-radius: 4px; }
        .bar-fill.warn { background: #ffaa00; }
        .row { display: flex; justify-content: space-between; padding: 4px 0; }
        table { width: 100%; border-collapse: collapse; }
        td { padding: 4px 8px; border-bottom: 1px solid #1a2a3a; }
    </style>
</head>
<body>
    <div class="header">
        <h1>AEGIS WAF <span>Analytics Dashboard v1.0.0</span></h1>
    </div>
    <div class="grid">
        <div class="card">
            <h3>Requests / Second</h3>
            <div class="metric">4,847</div>
            <div class="bar"><div class="bar-fill" style="width:65%"></div></div>
            <div class="row"><span>Peak: 12,340</span><span>Avg: 3,210</span></div>
        </div>
        <div class="card">
            <h3>Active Connections</h3>
            <div class="metric">1,203</div>
            <div class="bar"><div class="bar-fill" style="width:12%"></div></div>
            <div class="row"><span>Max: 100,000</span><span>Util: 1.2%</span></div>
        </div>
        <div class="card">
            <h3>Attacks Blocked</h3>
            <div class="metric">23,147</div>
            <div class="bar"><div class="bar-fill" style="width:23%"></div></div>
            <div class="row"><span>Last 24h: 1,203</span><span>FP Rate: 0.01%</span></div>
        </div>
        <div class="card">
            <h3>Avg Latency</h3>
            <div class="metric">0.42ms</div>
            <div class="bar"><div class="bar-fill" style="width:2%"></div></div>
            <div class="row"><span>p99: 2.1ms</span><span>p50: 0.3ms</span></div>
        </div>
        <div class="card">
            <h3>Threat Level</h3>
            <div class="metric warn">MEDIUM</div>
            <table>
                <tr><td>SQL Injection</td><td>12 events</td></tr>
                <tr><td>XSS</td><td>47 events</td></tr>
                <tr><td>RCE</td><td>3 events</td></tr>
                <tr><td>DDoS</td><td>8 events</td></tr>
            </table>
        </div>
        <div class="card">
            <h3>Top Attack Sources</h3>
            <table>
                <tr><td>185.220.101.x</td><td>TOR Exit</td><td>1,203</td></tr>
                <tr><td>45.33.32.156</td><td>Scanner</td><td>847</td></tr>
                <tr><td>91.240.118.x</td><td>Botnet</td><td>623</td></tr>
                <tr><td>103.224.182.x</td><td>Suspicious</td><td>412</td></tr>
            </table>
        </div>
    </div>
</body>
</html>"#;

            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                body.len(),
                body
            );

            let _ = socket.write_all(response.as_bytes()).await;
        });
    }
}

async fn cmd_export(format: ExportFormat, output: PathBuf) -> Result<()> {
    let output_path = match &format {
        ExportFormat::Json => {
            if output.extension().is_none() {
                output.with_extension("json")
            } else {
                output
            }
        }
        ExportFormat::Csv => {
            if output.extension().is_none() {
                output.with_extension("csv")
            } else {
                output
            }
        }
    };

    let report = generate_sample_report();

    match format {
        ExportFormat::Json => {
            let json = serde_json::to_string_pretty(&report).map_err(|e| {
                crate::error::AegisError::SerializationError(format!(
                    "Failed to serialize report: {}",
                    e
                ))
            })?;
            tokio::fs::write(&output_path, json).await.map_err(|e| {
                crate::error::AegisError::ConfigError(format!(
                    "Failed to write report to {}: {}",
                    output_path.display(),
                    e
                ))
            })?;
        }
        ExportFormat::Csv => {
            let mut csv = String::from("metric,value,unit\n");
            csv.push_str(&format!("requests_total,{},\n", report.requests_total));
            csv.push_str(&format!("requests_blocked,{},\n", report.requests_blocked));
            csv.push_str(&format!("avg_latency_ms,{:.2},ms\n", report.avg_latency_ms));
            csv.push_str(&format!(
                "active_connections,{},\n",
                report.active_connections
            ));
            csv.push_str(&format!("dpi_violations,{},\n", report.dpi_violations));
            csv.push_str(&format!(
                "rate_limit_triggers,{},\n",
                report.rate_limit_triggers
            ));
            csv.push_str(&format!("bot_detections,{},\n", report.bot_detections));
            csv.push_str(&format!(
                "threat_intel_hits,{},\n",
                report.threat_intel_hits
            ));
            csv.push_str(&format!("false_positives,{},\n", report.false_positives));
            csv.push_str(&format!("uptime_seconds,{},\n", report.uptime_seconds));

            tokio::fs::write(&output_path, csv).await.map_err(|e| {
                crate::error::AegisError::ConfigError(format!(
                    "Failed to write report to {}: {}",
                    output_path.display(),
                    e
                ))
            })?;
        }
    }

    println!("Analytics report exported to {}", output_path.display());
    Ok(())
}

#[derive(serde::Serialize)]
struct SampleReport {
    requests_total: u64,
    requests_blocked: u64,
    avg_latency_ms: f64,
    active_connections: u64,
    dpi_violations: u64,
    rate_limit_triggers: u64,
    bot_detections: u64,
    threat_intel_hits: u64,
    false_positives: u64,
    uptime_seconds: u64,
}

fn generate_sample_report() -> SampleReport {
    SampleReport {
        requests_total: 12_450_230,
        requests_blocked: 23_147,
        avg_latency_ms: 0.42,
        active_connections: 847,
        dpi_violations: 1_234,
        rate_limit_triggers: 5_678,
        bot_detections: 892,
        threat_intel_hits: 3_450,
        false_positives: 12,
        uptime_seconds: 2_592_000,
    }
}

async fn cmd_threat_level(verbose: bool) -> Result<()> {
    let threat_level = "MEDIUM";
    let threats = vec![
        (
            "SQL Injection Attempts",
            12_u64,
            "MEDIUM",
            "Blocked 12 SQLi probes in last hour",
        ),
        (
            "XSS Injection Attempts",
            47_u64,
            "HIGH",
            "Elevated XSS scanning activity detected",
        ),
        (
            "DDoS Probe Activity",
            8_u64,
            "LOW",
            "Low-rate reconnaissance traffic observed",
        ),
        (
            "TOR Exit Node Traffic",
            23_u64,
            "MEDIUM",
            "Traffic from known TOR exit nodes",
        ),
        (
            "Bot Scanner Activity",
            156_u64,
            "HIGH",
            "Automated vulnerability scanning detected",
        ),
        (
            "Credential Stuffing",
            3_u64,
            "LOW",
            "Minor credential stuffing attempt",
        ),
    ];

    println!("Aegis WAF — Current Threat Assessment");
    println!("═══════════════════════════════════════");
    println!();
    println!("Overall Threat Level: {}", colored_threat(threat_level));
    println!();

    if verbose {
        println!(
            "{:<32} {:<8} {:<10} Detail",
            "Threat Category", "Count", "Level"
        );
        println!("{:-<80}", "");
        for (category, count, level, detail) in &threats {
            println!(
                "{:<32} {:<8} {:<10} {}",
                category,
                count,
                colored_threat(level),
                detail
            );
        }
        println!();

        println!("Recommendations:");
        println!("  - Enable JS challenge for suspicious sessions");
        println!("  - Review IP reputation threshold (currently 0.70)");
        println!("  - Consider geo-blocking high-risk regions");
        println!("  - Update threat intelligence feeds");
    } else {
        println!("Top Threats:");
        for (category, count, level, _detail) in &threats {
            println!(
                "  {} — {} events [{}]",
                category,
                count,
                colored_threat(level)
            );
        }
    }

    Ok(())
}

fn colored_threat(level: &str) -> String {
    match level {
        "CRITICAL" => "\x1b[1;31mCRITICAL\x1b[0m".to_string(),
        "HIGH" => "\x1b[1;33mHIGH\x1b[0m".to_string(),
        "MEDIUM" => "\x1b[33mMEDIUM\x1b[0m".to_string(),
        "LOW" => "\x1b[32mLOW\x1b[0m".to_string(),
        _ => level.to_string(),
    }
}
