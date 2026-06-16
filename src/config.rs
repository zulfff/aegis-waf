use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;

use crate::error::Result;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerConfig {
    #[serde(default = "default_bind_addr")]
    pub bind_addr: String,
    #[serde(default = "default_bind_port")]
    pub bind_port: u16,
    pub tls_cert: Option<String>,
    pub tls_key: Option<String>,
    #[serde(default = "default_max_connections")]
    pub max_connections: u64,
    #[serde(default = "default_request_timeout")]
    pub request_timeout_ms: u64,
}

fn default_bind_addr() -> String {
    "0.0.0.0".to_string()
}
fn default_bind_port() -> u16 {
    8443
}
fn default_max_connections() -> u64 {
    100_000
}
fn default_request_timeout() -> u64 {
    60_000
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            bind_addr: default_bind_addr(),
            bind_port: default_bind_port(),
            tls_cert: None,
            tls_key: None,
            max_connections: default_max_connections(),
            request_timeout_ms: default_request_timeout(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProtectionConfig {
    #[serde(default = "default_true")]
    pub enable_ingress_filter: bool,
    #[serde(default = "default_true")]
    pub enable_dpi: bool,
    #[serde(default = "default_true")]
    pub enable_bot_detection: bool,
    #[serde(default = "default_true")]
    pub enable_rate_limiting: bool,
    #[serde(default = "default_true")]
    pub enable_threat_intel: bool,
    #[serde(default = "default_true")]
    pub enable_behavioral_analysis: bool,
}

fn default_true() -> bool {
    true
}

impl Default for ProtectionConfig {
    fn default() -> Self {
        Self {
            enable_ingress_filter: true,
            enable_dpi: true,
            enable_bot_detection: true,
            enable_rate_limiting: true,
            enable_threat_intel: true,
            enable_behavioral_analysis: true,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RateLimitingConfig {
    #[serde(default = "default_rps")]
    pub default_rps: u64,
    #[serde(default = "default_burst")]
    pub burst_size: u64,
    #[serde(default = "default_per_ip")]
    pub per_ip_limit: u64,
    #[serde(default = "default_per_endpoint")]
    pub per_endpoint_limit: u64,
    #[serde(default = "default_per_session")]
    pub per_session_limit: u64,
    #[serde(default = "default_true")]
    pub adaptive_learning: bool,
}

fn default_rps() -> u64 {
    1000
}
fn default_burst() -> u64 {
    5000
}
fn default_per_ip() -> u64 {
    500
}
fn default_per_endpoint() -> u64 {
    200
}
fn default_per_session() -> u64 {
    100
}

impl Default for RateLimitingConfig {
    fn default() -> Self {
        Self {
            default_rps: default_rps(),
            burst_size: default_burst(),
            per_ip_limit: default_per_ip(),
            per_endpoint_limit: default_per_endpoint(),
            per_session_limit: default_per_session(),
            adaptive_learning: true,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BotDetectionConfig {
    #[serde(default = "default_true")]
    pub enable_js_challenge: bool,
    #[serde(default = "default_true")]
    pub enable_device_fingerprint: bool,
    #[serde(default = "default_true")]
    pub enable_behavioral_analysis: bool,
    #[serde(default = "default_true")]
    pub headless_detection: bool,
    #[serde(default = "default_true")]
    pub ai_bot_detection: bool,
}

impl Default for BotDetectionConfig {
    fn default() -> Self {
        Self {
            enable_js_challenge: true,
            enable_device_fingerprint: true,
            enable_behavioral_analysis: true,
            headless_detection: true,
            ai_bot_detection: true,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatIntelligenceConfig {
    #[serde(default = "default_true")]
    pub enable_threat_feeds: bool,
    #[serde(default = "default_feed_interval")]
    pub feed_update_interval_hours: u64,
    #[serde(default = "default_feeds")]
    pub feeds: Vec<String>,
    #[serde(default = "default_threshold")]
    pub ip_reputation_threshold: f64,
    #[serde(default = "default_ttl")]
    pub score_cache_ttl_seconds: u64,
}

fn default_feed_interval() -> u64 {
    6
}
fn default_feeds() -> Vec<String> {
    vec![
        "https://cisa.gov/feeds/".to_string(),
        "https://shodan.io/feeds/".to_string(),
    ]
}
fn default_threshold() -> f64 {
    0.7
}
fn default_ttl() -> u64 {
    3600
}

impl Default for ThreatIntelligenceConfig {
    fn default() -> Self {
        Self {
            enable_threat_feeds: true,
            feed_update_interval_hours: default_feed_interval(),
            feeds: default_feeds(),
            ip_reputation_threshold: default_threshold(),
            score_cache_ttl_seconds: default_ttl(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StorageConfig {
    #[serde(default = "default_redis_url")]
    pub redis_url: String,
    #[serde(default = "default_rocksdb_path")]
    pub rocksdb_path: String,
    #[serde(default = "default_log_retention")]
    pub log_retention_days: u64,
}

fn default_redis_url() -> String {
    "redis://localhost:6379".to_string()
}
fn default_rocksdb_path() -> String {
    "/var/lib/aegis-waf/db".to_string()
}
fn default_log_retention() -> u64 {
    90
}

impl Default for StorageConfig {
    fn default() -> Self {
        Self {
            redis_url: default_redis_url(),
            rocksdb_path: default_rocksdb_path(),
            log_retention_days: default_log_retention(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComplianceConfig {
    #[serde(default)]
    pub gdpr_mode: bool,
    #[serde(default)]
    pub pci_dss_mode: bool,
    #[serde(default)]
    pub hipaa_mode: bool,
    #[serde(default = "default_true")]
    pub audit_logging: bool,
    #[serde(default = "default_data_retention")]
    pub data_retention_days: u64,
}

fn default_data_retention() -> u64 {
    365
}

impl Default for ComplianceConfig {
    fn default() -> Self {
        Self {
            gdpr_mode: true,
            pci_dss_mode: false,
            hipaa_mode: false,
            audit_logging: true,
            data_retention_days: default_data_retention(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DashboardConfig {
    #[serde(default = "default_dash_port")]
    pub port: u16,
    #[serde(default = "default_true")]
    pub enabled: bool,
}

fn default_dash_port() -> u16 {
    9090
}

impl Default for DashboardConfig {
    fn default() -> Self {
        Self {
            port: default_dash_port(),
            enabled: true,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetricsConfig {
    #[serde(default = "default_true")]
    pub prometheus_enabled: bool,
    #[serde(default = "default_dash_port")]
    pub prometheus_port: u16,
    #[serde(default = "default_true")]
    pub tracing_enabled: bool,
    pub tracing_endpoint: Option<String>,
}

impl Default for MetricsConfig {
    fn default() -> Self {
        Self {
            prometheus_enabled: true,
            prometheus_port: default_dash_port(),
            tracing_enabled: true,
            tracing_endpoint: None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DpiConfig {
    #[serde(default = "default_payload_size")]
    pub max_payload_size: u64,
    #[serde(default = "default_true")]
    pub enable_sql_injection_detection: bool,
    #[serde(default = "default_true")]
    pub enable_xss_detection: bool,
    #[serde(default = "default_true")]
    pub enable_path_traversal_detection: bool,
    #[serde(default = "default_true")]
    pub enable_command_injection_detection: bool,
    #[serde(default = "default_true")]
    pub enable_xxe_detection: bool,
    #[serde(default = "default_true")]
    pub enable_ssrf_detection: bool,
    #[serde(default)]
    pub custom_patterns: Vec<String>,
}

fn default_payload_size() -> u64 {
    10_485_760
}

impl Default for DpiConfig {
    fn default() -> Self {
        Self {
            max_payload_size: default_payload_size(),
            enable_sql_injection_detection: true,
            enable_xss_detection: true,
            enable_path_traversal_detection: true,
            enable_command_injection_detection: true,
            enable_xxe_detection: true,
            enable_ssrf_detection: true,
            custom_patterns: vec![],
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IngressFilterConfig {
    #[serde(default)]
    pub enable_geoip: bool,
    pub geoip_db_path: Option<String>,
    #[serde(default)]
    pub blocked_countries: Vec<String>,
    #[serde(default)]
    pub blocked_ip_ranges: Vec<String>,
    #[serde(default)]
    pub allowed_ip_ranges: Vec<String>,
    #[serde(default = "default_packet_size")]
    pub max_packet_size: u64,
}

fn default_packet_size() -> u64 {
    65535
}

impl Default for IngressFilterConfig {
    fn default() -> Self {
        Self {
            enable_geoip: false,
            geoip_db_path: None,
            blocked_countries: vec![],
            blocked_ip_ranges: vec![],
            allowed_ip_ranges: vec![],
            max_packet_size: default_packet_size(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BehavioralConfig {
    #[serde(default = "default_learning_period")]
    pub learning_period_seconds: u64,
    #[serde(default = "default_anomaly_threshold")]
    pub anomaly_threshold: f64,
    #[serde(default = "default_ema_alpha")]
    pub ema_alpha: f64,
    #[serde(default = "default_detection_window")]
    pub detection_window_seconds: u64,
    #[serde(default = "default_min_data_points")]
    pub min_data_points: u64,
}

fn default_learning_period() -> u64 {
    300
}
fn default_anomaly_threshold() -> f64 {
    0.85
}
fn default_ema_alpha() -> f64 {
    0.1
}
fn default_detection_window() -> u64 {
    60
}
fn default_min_data_points() -> u64 {
    100
}

impl Default for BehavioralConfig {
    fn default() -> Self {
        Self {
            learning_period_seconds: default_learning_period(),
            anomaly_threshold: default_anomaly_threshold(),
            ema_alpha: default_ema_alpha(),
            detection_window_seconds: default_detection_window(),
            min_data_points: default_min_data_points(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AegisConfig {
    #[serde(default)]
    pub log_level: String,
    pub log_file: Option<String>,
    #[serde(default)]
    pub dashboard: DashboardConfig,
    #[serde(default)]
    pub metrics: MetricsConfig,
    #[serde(default = "default_report_dir")]
    pub report_dir: String,
    pub audit_log_dir: Option<String>,
    #[serde(default)]
    pub server: ServerConfig,
    #[serde(default)]
    pub protection: ProtectionConfig,
    #[serde(default)]
    pub ingress_filter: IngressFilterConfig,
    #[serde(default)]
    pub dpi: DpiConfig,
    #[serde(default)]
    pub behavioral: BehavioralConfig,
    #[serde(default)]
    pub bot_detection: BotDetectionConfig,
    #[serde(default)]
    pub rate_limiting: RateLimitingConfig,
    #[serde(default)]
    pub threat_intelligence: ThreatIntelligenceConfig,
    #[serde(default)]
    pub storage: StorageConfig,
    #[serde(default)]
    pub compliance: ComplianceConfig,
}

fn default_report_dir() -> String {
    "./reports".to_string()
}

impl Default for AegisConfig {
    fn default() -> Self {
        Self {
            log_level: "info".to_string(),
            log_file: None,
            dashboard: DashboardConfig::default(),
            metrics: MetricsConfig::default(),
            report_dir: default_report_dir(),
            audit_log_dir: None,
            server: ServerConfig::default(),
            protection: ProtectionConfig::default(),
            ingress_filter: IngressFilterConfig::default(),
            dpi: DpiConfig::default(),
            behavioral: BehavioralConfig::default(),
            bot_detection: BotDetectionConfig::default(),
            rate_limiting: RateLimitingConfig::default(),
            threat_intelligence: ThreatIntelligenceConfig::default(),
            storage: StorageConfig::default(),
            compliance: ComplianceConfig::default(),
        }
    }
}

impl AegisConfig {
    pub fn from_file(path: &Path) -> Result<Self> {
        let content = fs::read_to_string(path).map_err(|e| {
            crate::error::AegisError::ConfigError(format!(
                "Failed to read config file {}: {}",
                path.display(),
                e
            ))
        })?;
        let config: AegisConfig = toml::from_str(&content).map_err(|e| {
            crate::error::AegisError::ConfigError(format!("Failed to parse config: {}", e))
        })?;
        Ok(config)
    }

    pub fn generate_default(path: &Path) -> Result<()> {
        let config = AegisConfig::default();
        let toml_str = toml::to_string_pretty(&config).map_err(|e| {
            crate::error::AegisError::ConfigError(format!(
                "Failed to serialize default config: {}",
                e
            ))
        })?;
        fs::write(path, toml_str).map_err(|e| {
            crate::error::AegisError::ConfigError(format!(
                "Failed to write config to {}: {}",
                path.display(),
                e
            ))
        })?;
        Ok(())
    }

    pub fn validate(&self) -> Result<Vec<String>> {
        let mut warnings = Vec::new();
        if self.server.max_connections == 0 {
            return Err(crate::error::AegisError::ConfigError(
                "max_connections must be greater than 0".into(),
            ));
        }
        if self.rate_limiting.default_rps == 0 {
            warnings.push("default_rps is 0; rate limiting is effectively disabled".into());
        }
        if self.dpi.max_payload_size > 100_000_000 {
            warnings.push("max_payload_size > 100MB; may cause memory pressure".into());
        }
        if self.storage.log_retention_days == 0 {
            warnings.push("log_retention_days is 0; no logs will be retained".into());
        }
        Ok(warnings)
    }
}
