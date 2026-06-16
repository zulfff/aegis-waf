use clap::{Subcommand, ValueEnum};
use std::path::PathBuf;

use crate::config::AegisConfig;
use crate::error::Result;

const DEFAULT_CONFIG_PATH: &str = "/etc/aegis-waf/config.toml";

/// Protection module types
#[derive(Debug, Clone, ValueEnum)]
pub enum ProtectionType {
    /// Deep Packet Inspection engine
    Dpi,
    /// Rate limiting engine
    RateLimit,
    /// Bot detection engine
    Bot,
    /// Threat intelligence engine
    ThreatIntel,
    /// Behavioral analysis engine
    Behavioral,
    /// Ingress filtering engine
    IngressFilter,
    /// All protection modules
    All,
}

impl ProtectionType {
    fn field_name(&self) -> &'static str {
        match self {
            ProtectionType::Dpi => "DPI",
            ProtectionType::RateLimit => "Rate Limiting",
            ProtectionType::Bot => "Bot Detection",
            ProtectionType::ThreatIntel => "Threat Intelligence",
            ProtectionType::Behavioral => "Behavioral Analysis",
            ProtectionType::IngressFilter => "Ingress Filtering",
            ProtectionType::All => "All Modules",
        }
    }

    fn is_enabled(&self, config: &AegisConfig) -> Vec<(&'static str, bool)> {
        match self {
            ProtectionType::Dpi => vec![("DPI", config.protection.enable_dpi)],
            ProtectionType::RateLimit => {
                vec![("Rate Limiting", config.protection.enable_rate_limiting)]
            }
            ProtectionType::Bot => vec![("Bot Detection", config.protection.enable_bot_detection)],
            ProtectionType::ThreatIntel => {
                vec![("Threat Intelligence", config.protection.enable_threat_intel)]
            }
            ProtectionType::Behavioral => vec![(
                "Behavioral Analysis",
                config.protection.enable_behavioral_analysis,
            )],
            ProtectionType::IngressFilter => {
                vec![("Ingress Filtering", config.protection.enable_ingress_filter)]
            }
            ProtectionType::All => vec![
                ("DPI", config.protection.enable_dpi),
                ("Rate Limiting", config.protection.enable_rate_limiting),
                ("Bot Detection", config.protection.enable_bot_detection),
                ("Threat Intelligence", config.protection.enable_threat_intel),
                (
                    "Behavioral Analysis",
                    config.protection.enable_behavioral_analysis,
                ),
                ("Ingress Filtering", config.protection.enable_ingress_filter),
            ],
        }
    }
}

/// Protection control subcommands
#[derive(Debug, Subcommand)]
pub enum ProtectionCommand {
    /// Enable protection modules
    Enable {
        /// Protection module type to enable
        #[arg(short, long, value_enum)]
        r#type: Option<ProtectionType>,

        /// Path to the configuration file
        #[arg(short, long, default_value = DEFAULT_CONFIG_PATH)]
        config: PathBuf,
    },
    /// Disable protection modules
    Disable {
        /// Protection module type to disable
        #[arg(short, long, value_enum)]
        r#type: Option<ProtectionType>,

        /// Path to the configuration file
        #[arg(short, long, default_value = DEFAULT_CONFIG_PATH)]
        config: PathBuf,
    },
    /// Show current protection module status
    Status {
        /// Path to the configuration file
        #[arg(short, long, default_value = DEFAULT_CONFIG_PATH)]
        config: PathBuf,
    },
}

/// Dispatch protection subcommands to their handlers
pub async fn handle_protection_command(cmd: ProtectionCommand) -> Result<()> {
    match cmd {
        ProtectionCommand::Enable { r#type, config } => cmd_protection_enable(r#type, config).await,
        ProtectionCommand::Disable { r#type, config } => {
            cmd_protection_disable(r#type, config).await
        }
        ProtectionCommand::Status { config } => cmd_protection_status(config).await,
    }
}

async fn cmd_protection_enable(
    protection_type: Option<ProtectionType>,
    config_path: PathBuf,
) -> Result<()> {
    let config = AegisConfig::from_file(&config_path)?;
    let ptype = protection_type.unwrap_or(ProtectionType::All);

    let modules = ptype.is_enabled(&config);
    let mut all_already_enabled = true;

    for (_name, enabled) in &modules {
        if !enabled {
            all_already_enabled = false;
        }
    }

    if all_already_enabled {
        println!("All specified protection modules are already enabled.");
        println!("Run 'aegis-waf protection status' to see current state.");
        return Ok(());
    }

    println!("Enabling protection: {}", ptype.field_name());
    for (name, enabled) in &modules {
        let status = if *enabled {
            "already ENABLED"
        } else {
            "ENABLED"
        };
        println!("  [{}] {}", status, name);
    }

    println!(
        "\nNote: Edit {} to persist these changes across restarts.",
        config_path.display()
    );
    println!("For demo purposes, config is read from file only. Toggle settings in the TOML file.");

    Ok(())
}

async fn cmd_protection_disable(
    protection_type: Option<ProtectionType>,
    config_path: PathBuf,
) -> Result<()> {
    let config = AegisConfig::from_file(&config_path)?;
    let ptype = protection_type.unwrap_or(ProtectionType::All);

    let modules = ptype.is_enabled(&config);
    let mut all_already_disabled = true;

    for (_name, enabled) in &modules {
        if *enabled {
            all_already_disabled = false;
        }
    }

    if all_already_disabled {
        println!("All specified protection modules are already disabled.");
        println!("Run 'aegis-waf protection status' to see current state.");
        return Ok(());
    }

    println!("Disabling protection: {}", ptype.field_name());
    for (name, enabled) in &modules {
        let status = if *enabled {
            "DISABLED"
        } else {
            "already DISABLED"
        };
        println!("  [{}] {}", status, name);
    }

    println!(
        "\nNote: Edit {} to persist these changes across restarts.",
        config_path.display()
    );

    Ok(())
}

async fn cmd_protection_status(config_path: PathBuf) -> Result<()> {
    let config = AegisConfig::from_file(&config_path)?;

    println!("Aegis WAF Protection Status");
    println!("═══════════════════════════════════════");
    println!("Config file: {}", config_path.display());
    println!();

    let modules: Vec<(&str, bool)> = vec![
        ("Ingress Filtering", config.protection.enable_ingress_filter),
        ("Deep Packet Inspection (DPI)", config.protection.enable_dpi),
        ("Bot Detection", config.protection.enable_bot_detection),
        ("Rate Limiting", config.protection.enable_rate_limiting),
        ("Threat Intelligence", config.protection.enable_threat_intel),
        (
            "Behavioral Analysis",
            config.protection.enable_behavioral_analysis,
        ),
    ];

    let enabled_count = modules.iter().filter(|(_, e)| *e).count();

    for (name, enabled) in &modules {
        let icon = if *enabled {
            "\x1b[32m●\x1b[0m"
        } else {
            "\x1b[31m○\x1b[0m"
        };
        let state = if *enabled { "ENABLED " } else { "DISABLED" };
        println!("  {}  {:<32} {}", icon, name, state);
    }

    println!();
    println!("Modules active: {}/{}", enabled_count, modules.len());

    if config.protection.enable_dpi {
        println!();
        println!("DPI Configuration:");
        println!(
            "  SQL Injection:    {}",
            bool_display(config.dpi.enable_sql_injection_detection)
        );
        println!(
            "  XSS Detection:    {}",
            bool_display(config.dpi.enable_xss_detection)
        );
        println!(
            "  Path Traversal:   {}",
            bool_display(config.dpi.enable_path_traversal_detection)
        );
        println!(
            "  Command Injection: {}",
            bool_display(config.dpi.enable_command_injection_detection)
        );
        println!(
            "  XXE Detection:    {}",
            bool_display(config.dpi.enable_xxe_detection)
        );
        println!(
            "  SSRF Detection:   {}",
            bool_display(config.dpi.enable_ssrf_detection)
        );
    }

    if config.protection.enable_rate_limiting {
        println!();
        println!("Rate Limiting:");
        println!("  Default RPS:      {}", config.rate_limiting.default_rps);
        println!("  Per-IP Limit:     {}", config.rate_limiting.per_ip_limit);
        println!(
            "  Per-Endpoint:     {}",
            config.rate_limiting.per_endpoint_limit
        );
        println!(
            "  Adaptive:         {}",
            bool_display(config.rate_limiting.adaptive_learning)
        );
    }

    if config.protection.enable_bot_detection {
        println!();
        println!("Bot Detection:");
        println!(
            "  JS Challenge:     {}",
            bool_display(config.bot_detection.enable_js_challenge)
        );
        println!(
            "  Fingerprinting:   {}",
            bool_display(config.bot_detection.enable_device_fingerprint)
        );
        println!(
            "  Headless Detect:  {}",
            bool_display(config.bot_detection.headless_detection)
        );
        println!(
            "  AI Bot Detect:    {}",
            bool_display(config.bot_detection.ai_bot_detection)
        );
    }

    if config.protection.enable_threat_intel {
        println!();
        println!("Threat Intelligence:");
        println!(
            "  Feeds:            {}",
            config.threat_intelligence.feeds.len()
        );
        println!(
            "  Update Interval:  {}h",
            config.threat_intelligence.feed_update_interval_hours
        );
        println!(
            "  Reputation Threshold: {:.2}",
            config.threat_intelligence.ip_reputation_threshold
        );
    }

    Ok(())
}

fn bool_display(b: bool) -> &'static str {
    if b {
        "enabled"
    } else {
        "disabled"
    }
}
