use clap::Subcommand;
use std::path::PathBuf;

use crate::config::AegisConfig;
use crate::error::Result;

const DEFAULT_CONFIG_PATH: &str = "/etc/aegis-waf/config.toml";

/// Configuration management subcommands
#[derive(Debug, Subcommand)]
pub enum ConfigCommand {
    /// Generate a default configuration and write it to a file
    Generate {
        /// Output file path for the generated config
        #[arg(short, long, default_value = DEFAULT_CONFIG_PATH)]
        output: PathBuf,
    },
    /// Validate an existing configuration file
    Validate {
        /// Path to the configuration file to validate
        #[arg(short, long, default_value = DEFAULT_CONFIG_PATH)]
        config: PathBuf,
    },
    /// Reset configuration to defaults at the standard location
    Reset {
        /// Overwrite without confirmation prompt
        #[arg(long)]
        force: bool,
    },
}

/// Dispatch config subcommands to their handlers
pub async fn handle_config_command(cmd: ConfigCommand) -> Result<()> {
    match cmd {
        ConfigCommand::Generate { output } => cmd_generate(output).await,
        ConfigCommand::Validate { config } => cmd_validate(config).await,
        ConfigCommand::Reset { force } => cmd_reset(force).await,
    }
}

async fn cmd_generate(output: PathBuf) -> Result<()> {
    if let Some(parent) = output.parent() {
        tokio::fs::create_dir_all(parent).await.map_err(|e| {
            crate::error::AegisError::ConfigError(format!(
                "Failed to create parent directory {}: {}",
                parent.display(),
                e
            ))
        })?;
    }

    AegisConfig::generate_default(&output)?;
    println!("Default configuration written to {}", output.display());
    println!("Review and adjust the settings before starting the service.");
    Ok(())
}

async fn cmd_validate(config_path: PathBuf) -> Result<()> {
    let config = AegisConfig::from_file(&config_path)?;

    match config.validate() {
        Ok(warnings) => {
            if warnings.is_empty() {
                println!("Configuration at {} is valid.", config_path.display());
            } else {
                println!(
                    "Configuration at {} is valid with warnings:",
                    config_path.display()
                );
                for (i, warning) in warnings.iter().enumerate() {
                    println!("  [WARN {}] {}", i + 1, warning);
                }
            }
        }
        Err(e) => {
            eprintln!("Configuration validation failed: {}", e);
            return Err(e);
        }
    }

    Ok(())
}

async fn cmd_reset(force: bool) -> Result<()> {
    let config_path = PathBuf::from(DEFAULT_CONFIG_PATH);

    if config_path.exists() && !force {
        eprintln!(
            "Config file {} already exists. Use --force to overwrite.",
            config_path.display()
        );
        println!("Run with --force to overwrite the existing configuration.");
        return Ok(());
    }

    if let Some(parent) = config_path.parent() {
        tokio::fs::create_dir_all(parent).await.map_err(|e| {
            crate::error::AegisError::ConfigError(format!(
                "Failed to create config directory {}: {}",
                parent.display(),
                e
            ))
        })?;
    }

    AegisConfig::generate_default(&config_path)?;
    println!(
        "Configuration reset to defaults at {}",
        config_path.display()
    );
    Ok(())
}
