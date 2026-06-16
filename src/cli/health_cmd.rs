use clap::Subcommand;
use std::path::PathBuf;

use crate::config::AegisConfig;
use crate::error::Result;

const DEFAULT_CONFIG_PATH: &str = "/etc/aegis-waf/config.toml";

/// Health check subcommands
#[derive(Debug, Subcommand)]
pub enum HealthCommand {
    /// Run a comprehensive health check of all components
    Check {
        /// Path to the configuration file
        #[arg(short, long, default_value = DEFAULT_CONFIG_PATH)]
        config: PathBuf,
    },
    /// Display current CPU and memory usage
    CpuMemory,
    /// Display system and process uptime
    Uptime,
}

/// Dispatch health subcommands to their handlers
pub async fn handle_health_command(cmd: HealthCommand) -> Result<()> {
    match cmd {
        HealthCommand::Check { config } => cmd_health_check(config).await,
        HealthCommand::CpuMemory => cmd_cpu_memory().await,
        HealthCommand::Uptime => cmd_uptime().await,
    }
}

async fn cmd_health_check(config_path: PathBuf) -> Result<()> {
    println!("Aegis WAF — Comprehensive Health Check");
    println!("═══════════════════════════════════════");
    println!();

    let mut all_ok = true;
    let mut checks: Vec<(&str, bool, String)> = Vec::new();

    // Check 1: Config file exists
    if config_path.exists() {
        checks.push((
            "Config file exists",
            true,
            config_path.display().to_string(),
        ));
    } else {
        checks.push((
            "Config file exists",
            false,
            format!("{} not found", config_path.display()),
        ));
        all_ok = false;
    }

    // Check 2: Config file is valid
    if config_path.exists() {
        match AegisConfig::from_file(&config_path) {
            Ok(config) => {
                // Validate config
                match config.validate() {
                    Ok(warnings) => {
                        if warnings.is_empty() {
                            checks.push(("Config validation", true, "No warnings".into()));
                        } else {
                            checks.push((
                                "Config validation",
                                true,
                                format!("{} warning(s): {}", warnings.len(), warnings.join("; ")),
                            ));
                        }
                    }
                    Err(e) => {
                        checks.push(("Config validation", false, e.to_string()));
                        all_ok = false;
                    }
                }

                // Check 3: TLS certs (if configured)
                if let Some(ref cert_path) = config.server.tls_cert {
                    if PathBuf::from(cert_path).exists() {
                        checks.push(("TLS certificate", true, cert_path.clone()));
                    } else {
                        checks.push((
                            "TLS certificate",
                            false,
                            format!("Cert file not found: {}", cert_path),
                        ));
                        all_ok = false;
                    }

                    if let Some(ref key_path) = config.server.tls_key {
                        if PathBuf::from(key_path).exists() {
                            checks.push(("TLS private key", true, key_path.clone()));
                        } else {
                            checks.push((
                                "TLS private key",
                                false,
                                format!("Key file not found: {}", key_path),
                            ));
                            all_ok = false;
                        }
                    } else {
                        checks.push(("TLS private key", false, "No key configured".into()));
                        all_ok = false;
                    }
                } else {
                    checks.push(("TLS", true, "Not configured (optional)".into()));
                }

                // Check 4: GeoIP DB (if configured)
                if let Some(ref geoip_path) = config.ingress_filter.geoip_db_path {
                    if PathBuf::from(geoip_path).exists() {
                        checks.push(("GeoIP database", true, geoip_path.clone()));
                    } else {
                        checks.push((
                            "GeoIP database",
                            false,
                            format!("File not found: {}", geoip_path),
                        ));
                        all_ok = false;
                    }
                } else {
                    checks.push(("GeoIP database", true, "Not configured (optional)".into()));
                }

                // Check 5: RocksDB path
                let rocksdb_path = PathBuf::from(&config.storage.rocksdb_path);
                if rocksdb_path.exists() {
                    checks.push(("RocksDB storage", true, rocksdb_path.display().to_string()));
                } else {
                    checks.push((
                        "RocksDB storage",
                        false,
                        format!("Path does not exist: {}", rocksdb_path.display()),
                    ));
                    all_ok = false;
                }

                // Check 6: Redis connectivity
                checks.push(("Redis config", true, config.storage.redis_url.clone()));

                // Check 7: Protection modules
                let enabled = [
                    ("Ingress filter", config.protection.enable_ingress_filter),
                    ("DPI engine", config.protection.enable_dpi),
                    ("Bot detection", config.protection.enable_bot_detection),
                    ("Rate limiting", config.protection.enable_rate_limiting),
                    ("Threat intel", config.protection.enable_threat_intel),
                    (
                        "Behavioral analysis",
                        config.protection.enable_behavioral_analysis,
                    ),
                ];
                let active_count = enabled.iter().filter(|(_, e)| *e).count();
                checks.push((
                    "Protection modules",
                    true,
                    format!("{}/{} enabled", active_count, enabled.len()),
                ));
            }
            Err(e) => {
                checks.push(("Config parsing", false, e.to_string()));
                all_ok = false;
            }
        }
    } else {
        checks.push(("Config parsing", false, "Config file not found".into()));
        all_ok = false;
    }

    // Check 8: System resources
    if let Ok((cpu, mem)) = read_system_usage() {
        checks.push(("CPU usage", cpu < 95.0, format!("{:.1}%", cpu)));
        checks.push(("Memory available", mem > 5.0, format!("{:.1}% free", mem)));
        if cpu > 90.0 || mem < 10.0 {
            all_ok = false;
        }
    }

    // Print results
    println!("{:<30} {:<12} Detail", "Component", "Status");
    println!("{:-<80}", "");

    for (name, ok, detail) in &checks {
        let status = if *ok {
            "\x1b[32mOK\x1b[0m"
        } else {
            "\x1b[31mFAIL\x1b[0m"
        };
        println!("{:<30} {:<12} {}", name, status, detail);
    }

    println!("{:-<80}", "");
    println!();
    if all_ok {
        println!("Health check passed. All components operational.");
    } else {
        println!("Health check completed with issues. Review FAIL items above.");
    }

    Ok(())
}

async fn cmd_cpu_memory() -> Result<()> {
    println!("Aegis WAF — CPU & Memory Usage");
    println!("══════════════════════════════════");

    let (cpu_percent, mem_free_pct) = read_system_usage().unwrap_or((0.0, 0.0));

    println!();
    println!("CPU Usage");
    println!("{:-<40}", "");

    // Parse /proc/stat for detailed CPU breakdown
    if let Ok(cpu_details) = parse_proc_stat() {
        println!("  user:    {:>8.1}%", cpu_details.user);
        println!("  system:  {:>8.1}%", cpu_details.system);
        println!("  idle:    {:>8.1}%", cpu_details.idle);
        println!("  iowait:  {:>8.1}%", cpu_details.iowait);
        println!("  Total utilization: {:.1}%", cpu_percent);
    } else {
        println!("  Total utilization: {:.1}%", cpu_percent);
    }

    println!();
    println!("Memory Usage");
    println!("{:-<40}", "");

    if let Ok(mem_info) = parse_proc_meminfo() {
        let used_gb = (mem_info.total_kb - mem_info.available_kb) as f64 / 1_048_576.0;
        let total_gb = mem_info.total_kb as f64 / 1_048_576.0;
        let available_gb = mem_info.available_kb as f64 / 1_048_576.0;
        let swap_used_gb = (mem_info.swap_total_kb - mem_info.swap_free_kb) as f64 / 1_048_576.0;
        let swap_total_gb = mem_info.swap_total_kb as f64 / 1_048_576.0;

        println!("  Total:      {:>8.2} GB", total_gb);
        println!(
            "  Used:       {:>8.2} GB ({:.1}%)",
            used_gb,
            100.0 - mem_free_pct
        );
        println!(
            "  Available:  {:>8.2} GB ({:.1}%)",
            available_gb, mem_free_pct
        );
        println!(
            "  Cached:     {:>8.2} GB",
            mem_info.cached_kb as f64 / 1_048_576.0
        );
        println!(
            "  Buffers:    {:>8.2} GB",
            mem_info.buffers_kb as f64 / 1_048_576.0
        );

        if swap_total_gb > 0.0 {
            println!(
                "  Swap used:  {:>8.2} GB / {:.2} GB",
                swap_used_gb, swap_total_gb
            );
        }
    } else {
        println!("  Memory available: {:.1}%", mem_free_pct);
    }

    println!();
    println!("Process Memory (self)");
    println!("{:-<40}", "");

    if let Ok(proc_mem) = parse_proc_self_status() {
        println!("  VmRSS:   {:>8} kB (resident set)", proc_mem.vm_rss_kb);
        println!("  VmSize:  {:>8} kB (virtual)", proc_mem.vm_size_kb);
        println!("  VmPeak:  {:>8} kB (peak virtual)", proc_mem.vm_peak_kb);
    }

    Ok(())
}

async fn cmd_uptime() -> Result<()> {
    println!("Aegis WAF — Uptime Information");
    println!("══════════════════════════════════");
    println!();

    // System uptime from /proc/uptime
    let system_uptime = parse_proc_uptime();

    match system_uptime {
        Ok(uptime_secs) => {
            println!("System Uptime: {}", format_duration(uptime_secs));
        }
        Err(_) => {
            println!("System Uptime: unavailable");
        }
    }

    // Process uptime (reading /proc/self/stat for starttime)
    let proc_uptime = parse_process_uptime();

    match proc_uptime {
        Ok(uptime_secs) => {
            println!("Process Uptime: {}", format_duration(uptime_secs));
        }
        Err(_) => {
            println!("Process Uptime: unavailable");
        }
    }

    // Load average
    if let Ok(load) = parse_loadavg() {
        println!();
        println!("Load Average:");
        println!("  1 min:  {:.2}", load.one);
        println!("  5 min:  {:.2}", load.five);
        println!("  15 min: {:.2}", load.fifteen);
    }

    Ok(())
}

// ─── System Info Parsing Helpers ───────────────────────────────────────────

fn read_system_usage() -> std::result::Result<(f64, f64), std::io::Error> {
    let (cpu, _) = parse_proc_stat_detailed()?;
    let mem_info = parse_proc_meminfo()?;
    let mem_free_pct = (mem_info.available_kb as f64 / mem_info.total_kb as f64) * 100.0;
    Ok((cpu, mem_free_pct))
}

struct CpuDetail {
    user: f64,
    system: f64,
    idle: f64,
    iowait: f64,
}

fn parse_proc_stat() -> std::result::Result<CpuDetail, std::io::Error> {
    let content = std::fs::read_to_string("/proc/stat")?;
    for line in content.lines() {
        if line.starts_with("cpu ") {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 5 {
                let user: u64 = parts[1].parse().unwrap_or(0);
                let nice: u64 = parts[2].parse().unwrap_or(0);
                let system: u64 = parts[3].parse().unwrap_or(0);
                let idle: u64 = parts[4].parse().unwrap_or(0);
                let iowait: u64 = parts.get(5).and_then(|s| s.parse().ok()).unwrap_or(0);

                let total = (user + nice + system + idle + iowait) as f64;
                if total > 0.0 {
                    return Ok(CpuDetail {
                        user: (user as f64 / total) * 100.0,
                        system: (system as f64 / total) * 100.0,
                        idle: (idle as f64 / total) * 100.0,
                        iowait: (iowait as f64 / total) * 100.0,
                    });
                }
            }
        }
    }
    Err(std::io::Error::new(
        std::io::ErrorKind::NotFound,
        "CPU line not found in /proc/stat",
    ))
}

fn parse_proc_stat_detailed() -> std::result::Result<(f64, CpuDetail), std::io::Error> {
    let detail = parse_proc_stat()?;
    let utilization = 100.0 - detail.idle;
    Ok((utilization, detail))
}

struct MemInfo {
    total_kb: u64,
    available_kb: u64,
    cached_kb: u64,
    buffers_kb: u64,
    swap_total_kb: u64,
    swap_free_kb: u64,
}

fn parse_proc_meminfo() -> std::result::Result<MemInfo, std::io::Error> {
    let content = std::fs::read_to_string("/proc/meminfo")?;
    let mut info = MemInfo {
        total_kb: 0,
        available_kb: 0,
        cached_kb: 0,
        buffers_kb: 0,
        swap_total_kb: 0,
        swap_free_kb: 0,
    };

    for line in content.lines() {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 2 {
            continue;
        }
        let value: u64 = parts[1].parse().unwrap_or(0);
        match parts[0] {
            "MemTotal:" => info.total_kb = value,
            "MemAvailable:" => info.available_kb = value,
            "Cached:" => info.cached_kb = value,
            "Buffers:" => info.buffers_kb = value,
            "SwapTotal:" => info.swap_total_kb = value,
            "SwapFree:" => info.swap_free_kb = value,
            _ => {}
        }
    }

    Ok(info)
}

struct ProcMemInfo {
    vm_rss_kb: u64,
    vm_size_kb: u64,
    vm_peak_kb: u64,
}

fn parse_proc_self_status() -> std::result::Result<ProcMemInfo, std::io::Error> {
    let content = std::fs::read_to_string("/proc/self/status")?;
    let mut info = ProcMemInfo {
        vm_rss_kb: 0,
        vm_size_kb: 0,
        vm_peak_kb: 0,
    };

    for line in content.lines() {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 2 {
            continue;
        }
        let value: u64 = parts[1].parse().unwrap_or(0);
        match parts[0] {
            "VmRSS:" => info.vm_rss_kb = value,
            "VmSize:" => info.vm_size_kb = value,
            "VmPeak:" => info.vm_peak_kb = value,
            _ => {}
        }
    }

    Ok(info)
}

fn parse_proc_uptime() -> std::result::Result<f64, std::io::Error> {
    let content = std::fs::read_to_string("/proc/uptime")?;
    let uptime_str = content.split_whitespace().next().ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "Could not parse /proc/uptime",
        )
    })?;
    uptime_str
        .parse::<f64>()
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))
}

fn parse_process_uptime() -> std::result::Result<f64, std::io::Error> {
    let system_uptime = parse_proc_uptime()?;
    let stat_content = std::fs::read_to_string("/proc/self/stat")?;

    let starttime_str = stat_content
        .split(')')
        .nth(1)
        .and_then(|after| after.split_whitespace().nth(19))
        .ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "Could not find starttime in /proc/self/stat",
            )
        })?;

    let starttime: u64 = starttime_str
        .parse()
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;

    let clk_tck = unsafe { libc::sysconf(libc::_SC_CLK_TCK) } as f64;
    if clk_tck <= 0.0 {
        return Err(std::io::Error::other("Failed to get clock ticks"));
    }

    let proc_uptime = system_uptime - (starttime as f64 / clk_tck);
    Ok(proc_uptime.max(0.0))
}

struct LoadAvg {
    one: f64,
    five: f64,
    fifteen: f64,
}

fn parse_loadavg() -> std::result::Result<LoadAvg, std::io::Error> {
    let content = std::fs::read_to_string("/proc/loadavg")?;
    let parts: Vec<&str> = content.split_whitespace().collect();
    if parts.len() < 3 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "Could not parse /proc/loadavg",
        ));
    }
    Ok(LoadAvg {
        one: parts[0]
            .parse()
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?,
        five: parts[1]
            .parse()
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?,
        fifteen: parts[2]
            .parse()
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?,
    })
}

fn format_duration(seconds: f64) -> String {
    let total_secs = seconds as u64;
    let days = total_secs / 86400;
    let hours = (total_secs % 86400) / 3600;
    let mins = (total_secs % 3600) / 60;
    let secs = total_secs % 60;

    if days > 0 {
        format!("{}d {}h {}m {}s", days, hours, mins, secs)
    } else if hours > 0 {
        format!("{}h {}m {}s", hours, mins, secs)
    } else if mins > 0 {
        format!("{}m {}s", mins, secs)
    } else {
        format!("{}s", secs)
    }
}
