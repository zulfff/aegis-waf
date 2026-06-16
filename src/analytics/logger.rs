use crate::config::AegisConfig;
use crate::error::Result;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;
use tracing::{debug, error, info, trace, warn};
use tracing_subscriber::fmt::format::FmtSpan;
use tracing_subscriber::EnvFilter;

static LOG_ROTATION_COUNT: AtomicU64 = AtomicU64::new(0);

pub struct Logger {
    pub rotation_count: u64,
}

impl Logger {
    pub fn rotation_count(&self) -> u64 {
        LOG_ROTATION_COUNT.load(Ordering::Relaxed)
    }

    pub fn increment_rotation(&self) {
        LOG_ROTATION_COUNT.fetch_add(1, Ordering::Relaxed);
    }
}

pub fn init_logging(config: &AegisConfig) -> Result<Logger> {
    let filter = std::env::var("RUST_LOG")
        .unwrap_or_else(|_| config.log_level.clone())
        .parse::<EnvFilter>()
        .unwrap_or_else(|_| EnvFilter::new("INFO"));

    let subscriber = tracing_subscriber::fmt()
        .json()
        .with_env_filter(filter.clone());
    let subscriber = subscriber
        .with_span_events(FmtSpan::CLOSE)
        .with_target(true)
        .with_thread_ids(true)
        .with_thread_names(true)
        .with_file(true)
        .with_line_number(true)
        .with_timer(tracing_subscriber::fmt::time::SystemTime)
        .with_level(true)
        .try_init();

    match subscriber {
        Ok(()) => {
            info!("Logging system initialized with JSON format");
        }
        Err(e) => {
            if e.to_string().contains("repeated") {
                debug!("Tracing subscriber already initialized");
            } else {
                tracing_subscriber::fmt()
                    .json()
                    .with_env_filter(filter.clone())
                    .try_init()
                    .ok();
            }
        }
    }

    Ok(Logger { rotation_count: 0 })
}

#[tracing::instrument(skip_all, fields(
    http.method = %method,
    http.path = %path,
    http.status_code = %status,
    http.latency_ms = %latency.as_millis(),
    client.ip = %client_ip
))]
pub fn log_request(method: &str, path: &str, status: u16, latency: Duration, client_ip: &str) {
    let latency_ms = latency.as_millis();

    if status >= 500 {
        error!(
            method = %method,
            path = %path,
            status = %status,
            latency_ms = %latency_ms,
            client_ip = %client_ip,
            "Request completed with server error"
        );
    } else if status >= 400 {
        warn!(
            method = %method,
            path = %path,
            status = %status,
            latency_ms = %latency_ms,
            client_ip = %client_ip,
            "Request completed with client error"
        );
    } else {
        info!(
            method = %method,
            path = %path,
            status = %status,
            latency_ms = %latency_ms,
            client_ip = %client_ip,
            "Request completed successfully"
        );
    }
}

#[tracing::instrument(skip_all, fields(
    security.attack_type = %attack_type,
    security.severity = %severity,
    security.source_ip = %source_ip
))]
pub fn log_attack(attack_type: &str, severity: &str, source_ip: &str, details: &str) {
    let severity_upper = severity.to_uppercase();

    match severity_upper.as_str() {
        "CRITICAL" => {
            error!(
                attack_type = %attack_type,
                severity = %severity,
                source_ip = %source_ip,
                details = %details,
                event = "attack_detected",
                "CRITICAL attack detected"
            );
        }
        "HIGH" => {
            error!(
                attack_type = %attack_type,
                severity = %severity,
                source_ip = %source_ip,
                details = %details,
                event = "attack_detected",
                "HIGH severity attack detected"
            );
        }
        "MEDIUM" | "MODERATE" => {
            warn!(
                attack_type = %attack_type,
                severity = %severity,
                source_ip = %source_ip,
                details = %details,
                event = "attack_detected",
                "Medium severity attack detected"
            );
        }
        _ => {
            info!(
                attack_type = %attack_type,
                severity = %severity,
                source_ip = %source_ip,
                details = %details,
                event = "attack_detected",
                "Low severity attack detected"
            );
        }
    }

    audit_log_entry(
        "ATTACK_DETECTED",
        &format!(
            "Type: {}, Severity: {}, Source: {}, Details: {}",
            attack_type, severity, source_ip, details
        ),
    );
}

#[tracing::instrument(skip_all, fields(
    security.event_type = %event_type,
    audit.event = true
))]
pub fn log_security_event(event_type: &str, details: &str) {
    let event_upper = event_type.to_uppercase();

    match event_upper.as_str() {
        "LOGIN_FAILURE" | "AUTH_FAILURE" | "UNAUTHORIZED_ACCESS" => {
            warn!(
                event_type = %event_type,
                details = %details,
                "Security event: {}", event_type
            );
        }
        "CONFIG_CHANGE" | "RULE_UPDATE" | "CERTIFICATE_EXPIRY" => {
            info!(
                event_type = %event_type,
                details = %details,
                "Security event: {}", event_type
            );
        }
        "RATE_LIMIT" | "IP_BLOCKED" | "GEO_BLOCK" => {
            warn!(
                event_type = %event_type,
                details = %details,
                "Security event: {}", event_type
            );
        }
        _ => {
            info!(
                event_type = %event_type,
                details = %details,
                "Security event: {}", event_type
            );
        }
    }

    audit_log_entry(event_type, details);
}

pub fn audit_log_entry(event_type: &str, details: &str) {
    info!(
        event_type = %event_type,
        details = %details,
        audit = true,
        timestamp = %chrono::Utc::now().to_rfc3339(),
        "AUDIT: {} | {}", event_type, details
    );
}

#[tracing::instrument(skip_all, fields(
    perf.metric = %metric_name,
    perf.value = %value
))]
pub fn log_performance_metric(metric_name: &str, value: f64) {
    if value < 0.0 {
        warn!(
            metric_name = %metric_name,
            value = %value,
            "Negative performance metric value detected"
        );
        return;
    }

    trace!(
        metric_name = %metric_name,
        value = %value,
        "Performance metric recorded"
    );

    let is_anomalous = match metric_name {
        "request_latency_p99" => value > 1000.0,
        "request_latency_p50" => value > 200.0,
        "error_rate" => value > 5.0,
        "cpu_usage" => value > 90.0,
        "memory_usage" => value > 90.0,
        _ => false,
    };

    if is_anomalous {
        warn!(
            metric_name = %metric_name,
            value = %value,
            anomaly = true,
            "Anomalous performance metric detected: {} = {}",
            metric_name, value
        );
    } else {
        debug!(
            metric_name = %metric_name,
            value = %value,
            "Performance metric: {} = {}",
            metric_name, value
        );
    }
}

pub fn track_log_rotation() -> u64 {
    LOG_ROTATION_COUNT.fetch_add(1, Ordering::Relaxed) + 1
}
