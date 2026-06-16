use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;

#[derive(Debug, Default)]
pub struct Metrics {
    pub requests_total: AtomicU64,
    pub attacks_blocked: AtomicU64,
    pub connections_active: AtomicU64,
    pub bytes_processed: AtomicU64,
    pub violations: Mutex<Vec<ViolationRecord>>,
    pub attack_counts: Mutex<std::collections::HashMap<String, u64>>,
    pub uptime_start: Mutex<Option<std::time::Instant>>,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct ViolationRecord {
    pub timestamp: String,
    pub attack_type: String,
    pub severity: String,
    pub source_ip: String,
    pub details: String,
    pub action: String,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct AttackStat {
    pub attack_type: String,
    pub count: u64,
    pub severity: String,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct ConnectionStat {
    pub timestamp: String,
    pub active: u64,
    pub total: u64,
    pub bytes: u64,
}

pub static METRICS: once_cell::sync::Lazy<Metrics> = once_cell::sync::Lazy::new(|| {
    let m = Metrics::default();
    *m.uptime_start.lock().unwrap() = Some(std::time::Instant::now());
    m
});

pub struct SimpleCounter {
    count: AtomicU64,
}

impl SimpleCounter {
    const fn new() -> Self {
        SimpleCounter {
            count: AtomicU64::new(0),
        }
    }

    pub fn inc(&self) {
        self.count.fetch_add(1, Ordering::Relaxed);
    }

    pub fn dec(&self) {
        self.count.fetch_sub(1, Ordering::Relaxed);
    }

    pub fn get(&self) -> u64 {
        self.count.load(Ordering::Relaxed)
    }

    pub fn with_label_values(&self, _labels: &[&str]) -> &Self {
        self.count.fetch_add(1, Ordering::Relaxed);
        self
    }
}

pub static DPI_VIOLATIONS: SimpleCounter = SimpleCounter::new();
pub static ATTACKS_DETECTED: SimpleCounter = SimpleCounter::new();
pub static BOT_DETECTIONS: SimpleCounter = SimpleCounter::new();
pub static THREAT_INTEL_HITS: SimpleCounter = SimpleCounter::new();
pub static BLOCKED_REQUESTS: SimpleCounter = SimpleCounter::new();
pub static CONNECTIONS_ACTIVE: SimpleCounter = SimpleCounter::new();
pub static REQUEST_TOTAL: SimpleCounter = SimpleCounter::new();
pub static REQUEST_LATENCY: SimpleCounter = SimpleCounter::new();
pub static RATE_LIMIT_TRIGGERED: SimpleCounter = SimpleCounter::new();
pub static TLS_HANDSHAKES: SimpleCounter = SimpleCounter::new();

impl Metrics {
    pub fn record_request(&self, _bytes: u64) {
        self.requests_total.fetch_add(1, Ordering::Relaxed);
        self.bytes_processed.fetch_add(_bytes, Ordering::Relaxed);
    }

    pub fn record_attack(&self, attack_type: &str, severity: &str, source_ip: &str, details: &str) {
        self.attacks_blocked.fetch_add(1, Ordering::Relaxed);
        let key = attack_type.to_string();
        let mut map = self.attack_counts.lock().unwrap();
        *map.entry(key).or_insert(0) += 1;
        let mut violations = self.violations.lock().unwrap();
        violations.push(ViolationRecord {
            timestamp: chrono::Utc::now().to_rfc3339(),
            attack_type: attack_type.to_string(),
            severity: severity.to_string(),
            source_ip: source_ip.to_string(),
            details: details.to_string(),
            action: "blocked".to_string(),
        });
        if violations.len() > 1000 {
            violations.remove(0);
        }
    }

    pub fn connection_inc(&self) {
        self.connections_active.fetch_add(1, Ordering::Relaxed);
    }

    pub fn connection_dec(&self) {
        self.connections_active.fetch_sub(1, Ordering::Relaxed);
    }

    pub fn get_requests_per_sec(&self) -> f64 {
        self.requests_total.load(Ordering::Relaxed) as f64
    }

    pub fn get_attacks_blocked(&self) -> u64 {
        self.attacks_blocked.load(Ordering::Relaxed)
    }

    pub fn get_active_connections(&self) -> u64 {
        self.connections_active.load(Ordering::Relaxed)
    }

    pub fn get_bytes_processed(&self) -> u64 {
        self.bytes_processed.load(Ordering::Relaxed)
    }

    pub fn get_violations(&self) -> Vec<ViolationRecord> {
        self.violations.lock().unwrap().clone()
    }

    pub fn get_attack_stats(&self) -> Vec<AttackStat> {
        let map = self.attack_counts.lock().unwrap();
        map.iter()
            .map(|(k, v)| AttackStat {
                attack_type: k.clone(),
                count: *v,
                severity: classify_severity(k),
            })
            .collect()
    }

    pub fn get_uptime_secs(&self) -> u64 {
        if let Some(start) = *self.uptime_start.lock().unwrap() {
            start.elapsed().as_secs()
        } else {
            0
        }
    }
}

fn classify_severity(attack_type: &str) -> String {
    match attack_type.to_lowercase().as_str() {
        "sqli" | "xss" | "rce" | "lfi" => "Critical".into(),
        "ddos" | "bruteforce" | "scanner" => "High".into(),
        "invalid_input" | "csrf" | "open_redirect" => "Medium".into(),
        _ => "Low".into(),
    }
}
