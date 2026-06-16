use std::fmt;
use std::fs::{self, File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

use chrono::{DateTime, Utc};
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use tracing::warn;

use crate::config::AegisConfig;
use crate::error::{AegisError, Result};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum AuditSeverity {
    Info,
    Warning,
    Critical,
}

impl fmt::Display for AuditSeverity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AuditSeverity::Info => write!(f, "INFO"),
            AuditSeverity::Warning => write!(f, "WARNING"),
            AuditSeverity::Critical => write!(f, "CRITICAL"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEvent {
    pub event_id: u64,
    pub timestamp: DateTime<Utc>,
    pub event_type: String,
    pub severity: AuditSeverity,
    pub details: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source_ip: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub session_id: Option<String>,
}

impl AuditEvent {
    pub fn new(event_id: u64, event_type: &str, severity: AuditSeverity, details: &str) -> Self {
        Self {
            event_id,
            timestamp: Utc::now(),
            event_type: event_type.to_string(),
            severity,
            details: details.to_string(),
            source_ip: None,
            user: None,
            session_id: None,
        }
    }

    pub fn with_source_ip(mut self, ip: &str) -> Self {
        self.source_ip = Some(ip.to_string());
        self
    }

    pub fn with_user(mut self, user: &str) -> Self {
        self.user = Some(user.to_string());
        self
    }

    pub fn with_session(mut self, session_id: &str) -> Self {
        self.session_id = Some(session_id.to_string());
        self
    }

    pub fn to_json(&self) -> String {
        serde_json::to_string(self).unwrap_or_else(|_| {
            format!(
                r#"{{"error":"serialization_failed","event_id":{}}}"#,
                self.event_id
            )
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct AuditLogEntry {
    pub event: AuditEvent,
    pub checksum: String,
}

pub struct AuditLogger {
    log_dir: PathBuf,
    current_log_file: RwLock<Option<File>>,
    event_counter: AtomicU64,
    max_file_size: u64,
    retention_days: u64,
    gdpr_mode: bool,
    rotation_lock: RwLock<()>,
}

impl AuditLogger {
    pub fn new(config: &AegisConfig) -> Result<Self> {
        let log_dir = PathBuf::from(&config.storage.rocksdb_path)
            .parent()
            .map(|p| p.join("audit"))
            .unwrap_or_else(|| PathBuf::from("/var/log/aegis-waf/audit"));

        fs::create_dir_all(&log_dir).map_err(|e| {
            AegisError::ConfigError(format!(
                "Failed to create audit log directory {}: {}",
                log_dir.display(),
                e
            ))
        })?;

        let logger = Self {
            log_dir,
            current_log_file: RwLock::new(None),
            event_counter: AtomicU64::new(Self::load_last_event_id(config).unwrap_or(0)),
            max_file_size: 104_857_600,
            retention_days: config.storage.log_retention_days,
            gdpr_mode: config.compliance.gdpr_mode,
            rotation_lock: RwLock::new(()),
        };

        logger.open_current_log()?;

        Ok(logger)
    }

    fn load_last_event_id(config: &AegisConfig) -> Option<u64> {
        let log_dir = PathBuf::from(&config.storage.rocksdb_path)
            .parent()
            .map(|p| p.join("audit"))
            .unwrap_or_else(|| PathBuf::from("/var/log/aegis-waf/audit"));

        let mut max_id: u64 = 0;

        if let Ok(entries) = fs::read_dir(&log_dir) {
            for entry in entries.flatten() {
                let path = entry.path();
                if path.extension().is_some_and(|ext| ext == "jsonl") {
                    if let Ok(file) = File::open(&path) {
                        let reader = BufReader::new(file);
                        for line in reader.lines().map_while(std::result::Result::ok) {
                            if let Ok(event) = serde_json::from_str::<AuditLogEntry>(&line) {
                                let event_id = event.event.event_id;
                                if event_id > max_id {
                                    max_id = event_id;
                                }
                            }
                        }
                    }
                }
            }
        }

        if max_id > 0 {
            Some(max_id)
        } else {
            None
        }
    }

    fn current_log_path(&self) -> PathBuf {
        let today = Utc::now().format("%Y-%m-%d");
        self.log_dir.join(format!("audit-{}.jsonl", today))
    }

    fn open_current_log(&self) -> Result<()> {
        let path = self.current_log_path();
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)
            .map_err(|e| {
                AegisError::ConfigError(format!(
                    "Failed to open audit log {}: {}",
                    path.display(),
                    e
                ))
            })?;

        let mut current = self.current_log_file.write();
        *current = Some(file);
        Ok(())
    }

    fn needs_rotation(&self) -> bool {
        let path = self.current_log_path();
        if let Ok(metadata) = fs::metadata(&path) {
            metadata.len() >= self.max_file_size
        } else {
            false
        }
    }

    fn rotate_if_needed(&self) -> Result<()> {
        if !self.needs_rotation() {
            return Ok(());
        }

        let _lock = self.rotation_lock.write();

        if !self.needs_rotation() {
            return Ok(());
        }

        self.open_current_log()
    }

    pub fn log_event(&self, event: AuditEvent) -> Result<()> {
        self.rotate_if_needed()?;

        let event = if self.gdpr_mode {
            AuditEvent {
                source_ip: event.source_ip.map(|ip| Self::anonymize_ip(&ip)),
                user: event.user.map(|u| Self::anonymize_user(&u)),
                ..event
            }
        } else {
            event
        };

        let checksum = Self::compute_checksum(&event);
        let entry = AuditLogEntry { event, checksum };

        let line = serde_json::to_string(&entry).map_err(|e| {
            AegisError::SerializationError(format!("Failed to serialize audit event: {}", e))
        })?;

        let mut current = self.current_log_file.write();
        if let Some(ref mut file) = *current {
            writeln!(file, "{}", line)
                .map_err(|e| AegisError::IoError(format!("Failed to write audit event: {}", e)))?;
            file.flush()
                .map_err(|e| AegisError::IoError(format!("Failed to flush audit log: {}", e)))?;
        } else {
            return Err(AegisError::ConfigError("Audit log file not open".into()));
        }

        Ok(())
    }

    pub fn log_with_details(
        &self,
        event_type: &str,
        severity: AuditSeverity,
        details: &str,
    ) -> Result<()> {
        let event_id = self.event_counter.fetch_add(1, Ordering::AcqRel) + 1;
        let event = AuditEvent::new(event_id, event_type, severity, details);
        self.log_event(event)
    }

    pub fn query_logs(
        &self,
        since: Option<DateTime<Utc>>,
        filter: Option<&str>,
    ) -> Result<Vec<AuditEvent>> {
        let mut events = Vec::new();
        let since_ts =
            since.unwrap_or_else(|| DateTime::from_timestamp(0, 0).unwrap_or(Utc::now()));

        let dir_entries = fs::read_dir(&self.log_dir).map_err(|e| {
            AegisError::ConfigError(format!("Failed to read audit log directory: {}", e))
        })?;

        let mut log_files: Vec<PathBuf> = Vec::new();
        for entry in dir_entries {
            let entry = entry.map_err(|e| {
                AegisError::ConfigError(format!("Failed to read directory entry: {}", e))
            })?;
            let path = entry.path();
            if path.extension().is_some_and(|ext| ext == "jsonl") {
                log_files.push(path);
            }
        }

        log_files.sort();

        for path in &log_files {
            let file = File::open(path).map_err(|e| {
                AegisError::ConfigError(format!(
                    "Failed to open audit log {}: {}",
                    path.display(),
                    e
                ))
            })?;

            let reader = BufReader::new(file);
            for line in reader.lines() {
                let line = line.map_err(|e| {
                    AegisError::ConfigError(format!("Failed to read audit log line: {}", e))
                })?;

                if let Ok(entry) = serde_json::from_str::<AuditLogEntry>(&line) {
                    if entry.event.timestamp >= since_ts {
                        if let Some(filter_str) = filter {
                            let filter_lower = filter_str.to_lowercase();
                            if entry
                                .event
                                .event_type
                                .to_lowercase()
                                .contains(&filter_lower)
                                || entry.event.details.to_lowercase().contains(&filter_lower)
                                || format!("{:?}", entry.event.severity)
                                    .to_lowercase()
                                    .contains(&filter_lower)
                            {
                                events.push(entry.event);
                            }
                        } else {
                            events.push(entry.event);
                        }
                    }
                }
            }
        }

        events.sort_by_key(|a| a.event_id);
        Ok(events)
    }

    pub fn export_logs(&self, format: &str, since: Option<DateTime<Utc>>) -> Result<String> {
        let events = self.query_logs(since, None)?;

        match format.to_lowercase().as_str() {
            "json" => serde_json::to_string_pretty(&events).map_err(|e| {
                AegisError::SerializationError(format!(
                    "Failed to serialize audit events to JSON: {}",
                    e
                ))
            }),
            "jsonl" => {
                let mut output = String::new();
                for event in &events {
                    let line = serde_json::to_string(event).map_err(|e| {
                        AegisError::SerializationError(format!(
                            "Failed to serialize audit event: {}",
                            e
                        ))
                    })?;
                    output.push_str(&line);
                    output.push('\n');
                }
                Ok(output)
            }
            other => Err(AegisError::ConfigError(format!(
                "Unsupported export format: {}. Supported: json, jsonl",
                other
            ))),
        }
    }

    pub fn rotate_logs(&self) -> Result<()> {
        let cutoff = Utc::now()
            .timestamp()
            .saturating_sub((self.retention_days * 86400) as i64);

        let dir_entries = fs::read_dir(&self.log_dir).map_err(|e| {
            AegisError::ConfigError(format!("Failed to read audit log directory: {}", e))
        })?;

        let mut removed = 0u64;

        for entry in dir_entries {
            let entry = entry.map_err(|e| {
                AegisError::ConfigError(format!("Failed to read directory entry: {}", e))
            })?;
            let path = entry.path();

            if path.extension().is_some_and(|ext| ext == "jsonl") {
                if let Ok(metadata) = fs::metadata(&path) {
                    if let Ok(modified) = metadata.modified() {
                        let modified_secs = modified
                            .duration_since(std::time::UNIX_EPOCH)
                            .map(|d| d.as_secs() as i64)
                            .unwrap_or(0);

                        if modified_secs < cutoff && fs::remove_file(&path).is_ok() {
                            removed += 1;
                        }
                    }
                }
            }
        }

        if removed > 0 {
            warn!(
                target: "aegis.audit",
                "Audit log rotation removed {} files older than {} days",
                removed,
                self.retention_days
            );
        }

        Ok(())
    }

    fn compute_checksum(event: &AuditEvent) -> String {
        use sha2::{Digest, Sha256};
        let payload = format!(
            "{}|{}|{}|{}",
            event.event_id,
            event.timestamp.to_rfc3339(),
            event.event_type,
            event.details
        );
        let digest = Sha256::digest(payload.as_bytes());
        format!("{:x}", digest)
    }

    fn anonymize_ip(ip: &str) -> String {
        let parts: Vec<&str> = ip.split('.').collect();
        if parts.len() == 4 {
            format!("{}.{}.0.0", parts[0], parts[1])
        } else {
            let parts: Vec<&str> = ip.split(':').collect();
            if parts.len() >= 4 {
                format!("{}:{}::", parts[0], parts[1])
            } else {
                "anonymized".to_string()
            }
        }
    }

    fn anonymize_user(user: &str) -> String {
        if user.len() <= 4 {
            "****".to_string()
        } else {
            format!("{}****", &user[..user.len().min(4)])
        }
    }

    pub fn next_event_id(&self) -> u64 {
        self.event_counter.fetch_add(1, Ordering::AcqRel) + 1
    }

    pub fn current_event_id(&self) -> u64 {
        self.event_counter.load(Ordering::Acquire)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_config() -> AegisConfig {
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let id = COUNTER.fetch_add(1, Ordering::Relaxed);
        let mut config = AegisConfig::default();
        let tmp =
            std::env::temp_dir().join(format!("aegis-audit-test-{}-{}", std::process::id(), id));
        let rocksdb_path = tmp.join("db");
        let _ = fs::create_dir_all(&rocksdb_path);
        config.storage.rocksdb_path = rocksdb_path.to_string_lossy().to_string();
        config.storage.log_retention_days = 90;
        config.compliance.gdpr_mode = false;
        config
    }

    #[test]
    fn test_audit_log_creation_and_write() {
        let config = test_config();
        let logger = AuditLogger::new(&config).unwrap();

        let event = AuditEvent::new(
            1,
            "access_control",
            AuditSeverity::Warning,
            "Blocked unauthorized access attempt",
        )
        .with_source_ip("192.168.1.100");

        assert!(logger.log_event(event).is_ok());
    }

    #[test]
    fn test_query_logs_by_time() {
        let config = test_config();
        let logger = AuditLogger::new(&config).unwrap();

        logger
            .log_with_details("test_event", AuditSeverity::Info, "Test message 1")
            .unwrap();
        logger
            .log_with_details("test_event", AuditSeverity::Warning, "Test message 2")
            .unwrap();

        {
            let mut file = logger.current_log_file.write();
            if let Some(ref mut f) = *file {
                f.sync_all().ok();
            }
        }

        let events = logger.query_logs(None, None).unwrap();
        assert!(
            events.len() >= 2,
            "Expected at least 2 events, got {}",
            events.len()
        );
    }

    #[test]
    fn test_export_logs_json() {
        let config = test_config();
        let logger = AuditLogger::new(&config).unwrap();

        logger
            .log_with_details("export_test", AuditSeverity::Info, "Export test")
            .unwrap();

        {
            let mut file = logger.current_log_file.write();
            if let Some(ref mut f) = *file {
                f.sync_all().ok();
            }
        }

        let exported = logger.export_logs("json", None).unwrap();
        assert!(
            exported.contains("event_type") || exported.contains("export_test"),
            "Expected export to contain event data, got: {}",
            &exported[..exported.len().min(200)]
        );
    }

    #[test]
    fn test_anonymize_ip_v4() {
        let result = AuditLogger::anonymize_ip("192.168.1.100");
        assert_eq!(result, "192.168.0.0");
    }

    #[test]
    fn test_anonymize_user() {
        let result = AuditLogger::anonymize_user("admin");
        assert!(
            result.ends_with("****"),
            "Anonymized short user should end with ****, got: {}",
            result
        );

        let result = AuditLogger::anonymize_user("administrator");
        assert!(
            result.ends_with("****"),
            "Anonymized long user should end with ****, got: {}",
            result
        );
        assert!(
            result.starts_with("admi"),
            "Should keep first 4 chars, got: {}",
            result
        );
    }
}
