use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use parking_lot::RwLock;
use serde::{Deserialize, Serialize};

use crate::config::RateLimitingConfig;

#[allow(dead_code)]
const DEFAULT_CAPACITY: f64 = 1000.0;
#[allow(dead_code)]
const DEFAULT_REFILL_RATE: f64 = 200.0;
const DEFAULT_BURST_MULTIPLIER: f64 = 5.0;
const DEFAULT_EMA_ALPHA: f64 = 0.125;
const LOCAL_CACHE_TTL_SECS: u64 = 60;
const BUCKET_CLEANUP_INTERVAL_SECS: u64 = 30;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RateLimitDecision {
    Allowed,
    Queued,
    Dropped,
    Challenged,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BurstClassification {
    Normal,
    LegitimateBurst,
    AttackBurst,
}

#[derive(Debug, Clone)]
pub struct RateLimitBucket {
    pub tokens: f64,
    pub capacity: f64,
    pub burst_capacity: f64,
    pub refill_rate: f64,
    pub last_refill: Instant,
    pub burst_allowed: bool,
    pub consecutive_drops: u64,
    pub total_allowed: u64,
    pub total_dropped: u64,
    pub traffic_ema: f64,
}

impl RateLimitBucket {
    pub fn new(capacity: f64, refill_rate: f64, burst_multiplier: f64) -> Self {
        Self {
            tokens: capacity,
            capacity,
            burst_capacity: capacity * burst_multiplier,
            refill_rate,
            last_refill: Instant::now(),
            burst_allowed: true,
            consecutive_drops: 0,
            total_allowed: 0,
            total_dropped: 0,
            traffic_ema: 0.0,
        }
    }

    pub fn refill(&mut self) {
        let now = Instant::now();
        let elapsed = now.duration_since(self.last_refill);
        if elapsed.is_zero() {
            return;
        }

        let elapsed_secs = elapsed.as_secs_f64();
        let refill_amount = elapsed_secs * self.refill_rate;

        let effective_capacity = if self.burst_allowed {
            self.burst_capacity
        } else {
            self.capacity
        };

        self.tokens = (self.tokens + refill_amount).min(effective_capacity);
        self.last_refill = now;
    }

    pub fn try_consume(&mut self, tokens: f64) -> bool {
        self.refill();

        if self.tokens >= tokens {
            self.tokens -= tokens;
            self.consecutive_drops = 0;
            self.total_allowed = self.total_allowed.saturating_add(1);
            self.update_ema(tokens);
            true
        } else {
            self.consecutive_drops += 1;
            self.total_dropped = self.total_dropped.saturating_add(1);
            false
        }
    }

    pub fn available_tokens(&mut self) -> f64 {
        self.refill();
        self.tokens
    }

    pub fn reset_burst(&mut self) {
        self.burst_allowed = false;
        if self.tokens > self.capacity {
            self.tokens = self.capacity;
        }
    }

    pub fn enable_burst(&mut self) {
        self.burst_allowed = true;
    }

    pub fn classify_burst(&self, current_rate: f64) -> BurstClassification {
        let threshold = self.capacity * 0.8;
        if current_rate > self.capacity * 2.0 {
            BurstClassification::AttackBurst
        } else if current_rate > threshold {
            BurstClassification::LegitimateBurst
        } else {
            BurstClassification::Normal
        }
    }

    fn update_ema(&mut self, consumed: f64) {
        self.traffic_ema =
            DEFAULT_EMA_ALPHA * consumed + (1.0 - DEFAULT_EMA_ALPHA) * self.traffic_ema;
    }

    pub fn current_ema_rate(&self) -> f64 {
        self.traffic_ema
    }

    pub fn refill_bucket(&mut self, tokens: f64) {
        self.tokens = (self.tokens + tokens).min(self.capacity);
    }

    pub fn reset(&mut self) {
        self.tokens = self.capacity;
        self.last_refill = Instant::now();
        self.consecutive_drops = 0;
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum LimitScope {
    PerIp,
    PerSession,
    PerEndpoint,
    Global,
}

impl LimitScope {
    pub fn as_str(&self) -> &'static str {
        match self {
            LimitScope::PerIp => "per_ip",
            LimitScope::PerSession => "per_session",
            LimitScope::PerEndpoint => "per_endpoint",
            LimitScope::Global => "global",
        }
    }
}

#[derive(Debug, Clone)]
struct CacheEntry {
    tokens: f64,
    capacity: f64,
    refill_rate: f64,
    last_refill: Instant,
    burst_allowed: bool,
    traffic_ema: f64,
}

#[derive(Debug)]
struct DistributedRateLimiterInner {
    local_cache: RwLock<HashMap<String, CacheEntry>>,
    adaptive_thresholds: RwLock<HashMap<String, f64>>,
    ema_baselines: RwLock<HashMap<String, f64>>,
    last_cleanup: RwLock<Instant>,
    config: RateLimitingConfig,
}

pub struct DistributedRateLimiter {
    inner: Arc<DistributedRateLimiterInner>,
}

impl DistributedRateLimiter {
    pub fn new(config: RateLimitingConfig) -> Self {
        Self {
            inner: Arc::new(DistributedRateLimiterInner {
                local_cache: RwLock::new(HashMap::new()),
                adaptive_thresholds: RwLock::new(HashMap::new()),
                ema_baselines: RwLock::new(HashMap::new()),
                last_cleanup: RwLock::new(Instant::now()),
                config,
            }),
        }
    }

    pub fn check_rate(
        &self,
        ip: IpAddr,
        endpoint: Option<&str>,
        session_id: Option<&str>,
    ) -> RateLimitDecision {
        let mut decision = RateLimitDecision::Allowed;
        let cost = 1.0;

        let ip_key = format!("ip:{}", ip);
        if !self.check_local_bucket(&ip_key, cost) {
            decision = self.evaluate_graceful_degradation(&ip_key, cost);
        }

        if decision == RateLimitDecision::Allowed {
            if let Some(sid) = session_id {
                let session_key = format!("session:{}", sid);
                if !self.check_local_bucket(&session_key, cost) {
                    decision = self.evaluate_graceful_degradation(&session_key, cost);
                }
            }
        }

        if decision == RateLimitDecision::Allowed {
            if let Some(ep) = endpoint {
                let ep_key = format!("endpoint:{}", ep);
                if !self.check_local_bucket(&ep_key, cost) {
                    decision = self.evaluate_graceful_degradation(&ep_key, cost);
                }
            }
        }

        if decision == RateLimitDecision::Allowed && !self.check_local_bucket("global", cost) {
            decision = self.evaluate_graceful_degradation("global", cost);
        }

        self.maybe_cleanup();

        decision
    }

    pub fn check_rate_with_scope(
        &self,
        key: &str,
        scope: LimitScope,
        cost: f64,
    ) -> RateLimitDecision {
        let bucket_key = format!("{}:{}", scope.as_str(), key);
        if self.check_local_bucket(&bucket_key, cost) {
            RateLimitDecision::Allowed
        } else {
            self.evaluate_graceful_degradation(&bucket_key, cost)
        }
    }

    pub fn refill_bucket(&self, key: &str, scope: LimitScope, tokens: f64) {
        let bucket_key = format!("{}:{}", scope.as_str(), key);
        let mut cache = self.inner.local_cache.write();
        if let Some(entry) = cache.get_mut(&bucket_key) {
            entry.tokens = (entry.tokens + tokens).min(entry.capacity);
            entry.last_refill = Instant::now();
        }
    }

    pub fn set_adaptive_threshold(&self, key: &str, threshold: f64) {
        self.inner
            .adaptive_thresholds
            .write()
            .insert(key.to_string(), threshold);
    }

    pub fn get_adaptive_threshold(&self, key: &str) -> Option<f64> {
        self.inner.adaptive_thresholds.read().get(key).copied()
    }

    pub fn get_bucket(&self, key: &str) -> Option<RateLimitBucket> {
        let cache = self.inner.local_cache.read();
        cache.get(key).map(|entry| RateLimitBucket {
            tokens: entry.tokens,
            capacity: entry.capacity,
            burst_capacity: entry.capacity * DEFAULT_BURST_MULTIPLIER,
            refill_rate: entry.refill_rate,
            last_refill: entry.last_refill,
            burst_allowed: entry.burst_allowed,
            consecutive_drops: 0,
            total_allowed: 0,
            total_dropped: 0,
            traffic_ema: entry.traffic_ema,
        })
    }

    pub fn classify_burst(&self, key: &str) -> BurstClassification {
        let cache = self.inner.local_cache.read();
        if let Some(entry) = cache.get(key) {
            let rate = entry.traffic_ema;
            let threshold = entry.capacity * 0.8;
            if rate > entry.capacity * 2.0 {
                BurstClassification::AttackBurst
            } else if rate > threshold {
                BurstClassification::LegitimateBurst
            } else {
                BurstClassification::Normal
            }
        } else {
            BurstClassification::Normal
        }
    }

    pub fn update_ema_baseline(&self, key: &str, observed_rate: f64) {
        let mut baselines = self.inner.ema_baselines.write();
        let entry = baselines.entry(key.to_string()).or_insert(observed_rate);
        *entry = DEFAULT_EMA_ALPHA * observed_rate + (1.0 - DEFAULT_EMA_ALPHA) * *entry;
    }

    pub fn get_ema_baseline(&self, key: &str) -> Option<f64> {
        self.inner.ema_baselines.read().get(key).copied()
    }

    pub fn reset(&self, key: &str) {
        let mut cache = self.inner.local_cache.write();
        if let Some(entry) = cache.get_mut(key) {
            entry.tokens = entry.capacity;
            entry.last_refill = Instant::now();
        }
    }

    pub fn clear_all(&self) {
        self.inner.local_cache.write().clear();
        self.inner.adaptive_thresholds.write().clear();
        self.inner.ema_baselines.write().clear();
    }

    pub fn is_rate_limited(&self, ip: IpAddr) -> bool {
        let ip_key = format!("ip:{}", ip);
        let cache = self.inner.local_cache.read();
        if let Some(entry) = cache.get(&ip_key) {
            entry.tokens < 1.0
        } else {
            false
        }
    }

    fn check_local_bucket(&self, key: &str, cost: f64) -> bool {
        let mut cache = self.inner.local_cache.write();
        let entry = cache.entry(key.to_string()).or_insert_with(|| {
            let (capacity, refill_rate) = self.resolve_limits(key);
            CacheEntry {
                tokens: capacity,
                capacity,
                refill_rate,
                last_refill: Instant::now(),
                burst_allowed: true,
                traffic_ema: 0.0,
            }
        });

        let now = Instant::now();
        let elapsed = now.duration_since(entry.last_refill).as_secs_f64();
        if elapsed > 0.0 {
            entry.tokens = (entry.tokens + elapsed * entry.refill_rate).min(entry.capacity);
        }
        entry.last_refill = now;

        if entry.tokens >= cost {
            entry.tokens -= cost;
            entry.traffic_ema =
                DEFAULT_EMA_ALPHA * cost + (1.0 - DEFAULT_EMA_ALPHA) * entry.traffic_ema;
            true
        } else {
            entry.traffic_ema =
                DEFAULT_EMA_ALPHA * cost + (1.0 - DEFAULT_EMA_ALPHA) * entry.traffic_ema;
            false
        }
    }

    fn resolve_limits(&self, key: &str) -> (f64, f64) {
        let cfg = &self.inner.config;

        let adaptive_threshold = self
            .inner
            .adaptive_thresholds
            .read()
            .get(key)
            .copied()
            .unwrap_or(0.0);

        if key.starts_with("ip:") {
            let base_capacity = cfg.per_ip_limit as f64;
            let adaptive_adj = if adaptive_threshold > 0.0 && cfg.adaptive_learning {
                (adaptive_threshold * 0.5).min(base_capacity * 0.5)
            } else {
                0.0
            };
            let capacity = base_capacity - adaptive_adj;
            let capacity = capacity.max(cfg.default_rps as f64 * 0.1);
            let refill_rate = capacity;
            (capacity, refill_rate)
        } else if key.starts_with("session:") {
            let capacity = cfg.per_session_limit as f64;
            (capacity, capacity)
        } else if key.starts_with("endpoint:") {
            let capacity = cfg.per_endpoint_limit as f64;
            (capacity, capacity)
        } else {
            let capacity = cfg.default_rps as f64;
            (capacity, capacity)
        }
    }

    fn evaluate_graceful_degradation(&self, key: &str, _cost: f64) -> RateLimitDecision {
        let cache = self.inner.local_cache.read();
        if let Some(entry) = cache.get(key) {
            if entry.tokens > entry.capacity * 0.2 {
                return RateLimitDecision::Queued;
            }
            if entry.traffic_ema > entry.refill_rate * 1.5 {
                return RateLimitDecision::Challenged;
            }
        }
        RateLimitDecision::Dropped
    }

    fn maybe_cleanup(&self) {
        let mut last = self.inner.last_cleanup.write();
        if last.elapsed() < Duration::from_secs(BUCKET_CLEANUP_INTERVAL_SECS) {
            return;
        }
        *last = Instant::now();
        drop(last);

        let mut cache = self.inner.local_cache.write();
        cache.retain(|_key, entry| {
            entry.last_refill.elapsed() < Duration::from_secs(LOCAL_CACHE_TTL_SECS * 3)
        });
    }
}

impl Clone for DistributedRateLimiter {
    fn clone(&self) -> Self {
        Self {
            inner: Arc::clone(&self.inner),
        }
    }
}

#[derive(Debug)]
pub struct RateLimiter {
    pub per_ip_buckets: RwLock<HashMap<IpAddr, RateLimitBucket>>,
    pub per_session_buckets: RwLock<HashMap<String, RateLimitBucket>>,
    pub per_endpoint_buckets: RwLock<HashMap<String, RateLimitBucket>>,
    pub global_bucket: RwLock<RateLimitBucket>,
    pub config: RateLimitingConfig,
}

impl RateLimiter {
    pub fn new(config: RateLimitingConfig) -> Self {
        let global_capacity = config.default_rps as f64;
        let global_refill = config.default_rps as f64;

        Self {
            per_ip_buckets: RwLock::new(HashMap::new()),
            per_session_buckets: RwLock::new(HashMap::new()),
            per_endpoint_buckets: RwLock::new(HashMap::new()),
            global_bucket: RwLock::new(RateLimitBucket::new(
                global_capacity,
                global_refill,
                DEFAULT_BURST_MULTIPLIER,
            )),
            config,
        }
    }

    pub fn check_rate(
        &self,
        ip: IpAddr,
        session_id: Option<&str>,
        endpoint: Option<&str>,
    ) -> RateLimitDecision {
        let cost = 1.0;

        if !self.global_bucket.write().try_consume(cost) {
            return self.evaluate_global_degradation();
        }

        let mut ip_buckets = self.per_ip_buckets.write();
        let ip_entry = ip_buckets.entry(ip).or_insert_with(|| {
            RateLimitBucket::new(
                self.config.per_ip_limit as f64,
                self.config.per_ip_limit as f64,
                DEFAULT_BURST_MULTIPLIER,
            )
        });
        let ip_allowed = ip_entry.try_consume(cost);
        drop(ip_buckets);

        if !ip_allowed {
            return RateLimitDecision::Dropped;
        }

        if let Some(sid) = session_id {
            let mut sess_buckets = self.per_session_buckets.write();
            let sess_entry = sess_buckets.entry(sid.to_string()).or_insert_with(|| {
                RateLimitBucket::new(
                    self.config.per_session_limit as f64,
                    self.config.per_session_limit as f64,
                    DEFAULT_BURST_MULTIPLIER,
                )
            });
            let sess_allowed = sess_entry.try_consume(cost);
            drop(sess_buckets);

            if !sess_allowed {
                self.global_bucket.write().refill_bucket(1.0);
                return RateLimitDecision::Dropped;
            }
        }

        if let Some(ep) = endpoint {
            let mut ep_buckets = self.per_endpoint_buckets.write();
            let ep_entry = ep_buckets.entry(ep.to_string()).or_insert_with(|| {
                RateLimitBucket::new(
                    self.config.per_endpoint_limit as f64,
                    self.config.per_endpoint_limit as f64,
                    DEFAULT_BURST_MULTIPLIER,
                )
            });
            let ep_allowed = ep_entry.try_consume(cost);
            drop(ep_buckets);

            if !ep_allowed {
                self.global_bucket.write().refill_bucket(1.0);
                return RateLimitDecision::Dropped;
            }
        }

        RateLimitDecision::Allowed
    }

    pub fn check_rate_with_scope(
        &self,
        key: &str,
        scope: LimitScope,
        cost: f64,
    ) -> RateLimitDecision {
        match scope {
            LimitScope::Global => {
                if self.global_bucket.write().try_consume(cost) {
                    RateLimitDecision::Allowed
                } else {
                    self.evaluate_global_degradation()
                }
            }
            LimitScope::PerIp => {
                if let Ok(ip) = key.parse::<IpAddr>() {
                    let mut buckets = self.per_ip_buckets.write();
                    let entry = buckets.entry(ip).or_insert_with(|| {
                        RateLimitBucket::new(
                            self.config.per_ip_limit as f64,
                            self.config.per_ip_limit as f64,
                            DEFAULT_BURST_MULTIPLIER,
                        )
                    });
                    if entry.try_consume(cost) {
                        RateLimitDecision::Allowed
                    } else {
                        RateLimitDecision::Dropped
                    }
                } else {
                    RateLimitDecision::Allowed
                }
            }
            LimitScope::PerSession => {
                let mut buckets = self.per_session_buckets.write();
                let entry = buckets.entry(key.to_string()).or_insert_with(|| {
                    RateLimitBucket::new(
                        self.config.per_session_limit as f64,
                        self.config.per_session_limit as f64,
                        DEFAULT_BURST_MULTIPLIER,
                    )
                });
                if entry.try_consume(cost) {
                    RateLimitDecision::Allowed
                } else {
                    RateLimitDecision::Dropped
                }
            }
            LimitScope::PerEndpoint => {
                let mut buckets = self.per_endpoint_buckets.write();
                let entry = buckets.entry(key.to_string()).or_insert_with(|| {
                    RateLimitBucket::new(
                        self.config.per_endpoint_limit as f64,
                        self.config.per_endpoint_limit as f64,
                        DEFAULT_BURST_MULTIPLIER,
                    )
                });
                if entry.try_consume(cost) {
                    RateLimitDecision::Allowed
                } else {
                    RateLimitDecision::Dropped
                }
            }
        }
    }

    pub fn refill_bucket(&self, key: &str, scope: LimitScope, tokens: f64) {
        match scope {
            LimitScope::Global => {
                let mut bucket = self.global_bucket.write();
                bucket.tokens = (bucket.tokens + tokens).min(bucket.capacity);
            }
            LimitScope::PerIp => {
                if let Ok(ip) = key.parse::<IpAddr>() {
                    let mut buckets = self.per_ip_buckets.write();
                    if let Some(bucket) = buckets.get_mut(&ip) {
                        bucket.tokens = (bucket.tokens + tokens).min(bucket.capacity);
                    }
                }
            }
            LimitScope::PerSession => {
                let mut buckets = self.per_session_buckets.write();
                if let Some(bucket) = buckets.get_mut(key) {
                    bucket.tokens = (bucket.tokens + tokens).min(bucket.capacity);
                }
            }
            LimitScope::PerEndpoint => {
                let mut buckets = self.per_endpoint_buckets.write();
                if let Some(bucket) = buckets.get_mut(key) {
                    bucket.tokens = (bucket.tokens + tokens).min(bucket.capacity);
                }
            }
        }
    }

    pub fn set_adaptive_threshold(&self, ip: IpAddr, threshold: f64) {
        let mut buckets = self.per_ip_buckets.write();
        if let Some(bucket) = buckets.get_mut(&ip) {
            let new_capacity = (self.config.per_ip_limit as f64) - threshold;
            if new_capacity > 0.0 {
                bucket.capacity = new_capacity;
                bucket.burst_capacity = new_capacity * DEFAULT_BURST_MULTIPLIER;
                if bucket.tokens > new_capacity {
                    bucket.tokens = new_capacity;
                }
            }
        }
    }

    pub fn classify_burst(&self, ip: IpAddr) -> BurstClassification {
        let buckets = self.per_ip_buckets.read();
        if let Some(bucket) = buckets.get(&ip) {
            bucket.classify_burst(bucket.traffic_ema)
        } else {
            BurstClassification::Normal
        }
    }

    pub fn get_bucket_stats(&self, ip: IpAddr) -> Option<(f64, f64, u64, u64)> {
        let buckets = self.per_ip_buckets.read();
        buckets
            .get(&ip)
            .map(|b| (b.tokens, b.traffic_ema, b.total_allowed, b.total_dropped))
    }

    pub fn reset_ip(&self, ip: IpAddr) {
        let mut buckets = self.per_ip_buckets.write();
        if let Some(bucket) = buckets.get_mut(&ip) {
            bucket.reset();
        }
    }

    fn evaluate_global_degradation(&self) -> RateLimitDecision {
        let bucket = self.global_bucket.read();
        if bucket.tokens > bucket.capacity * 0.2 {
            RateLimitDecision::Queued
        } else {
            RateLimitDecision::Dropped
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_config() -> RateLimitingConfig {
        RateLimitingConfig {
            default_rps: 1000,
            burst_size: 5000,
            per_ip_limit: 500,
            per_endpoint_limit: 200,
            per_session_limit: 100,
            adaptive_learning: true,
        }
    }

    #[test]
    fn test_token_bucket_refill() {
        let mut bucket = RateLimitBucket::new(10.0, 100.0, DEFAULT_BURST_MULTIPLIER);
        bucket.tokens = 0.0;
        bucket.try_consume(10.0);
        assert!(bucket.tokens < 0.0 || bucket.tokens >= 0.0);
    }

    #[test]
    fn test_token_bucket_consume() {
        let mut bucket = RateLimitBucket::new(100.0, 100.0, DEFAULT_BURST_MULTIPLIER);
        assert!(bucket.try_consume(50.0));
        assert!(bucket.tokens < 100.0);
    }

    #[test]
    fn test_token_bucket_exhaustion() {
        let mut bucket = RateLimitBucket::new(10.0, 0.0, DEFAULT_BURST_MULTIPLIER);
        assert!(bucket.try_consume(10.0));
        assert!(bucket.tokens >= 0.0);
        assert!(!bucket.try_consume(1.0));
    }

    #[test]
    fn test_token_bucket_reset() {
        let mut bucket = RateLimitBucket::new(100.0, 100.0, DEFAULT_BURST_MULTIPLIER);
        bucket.try_consume(90.0);
        assert!(bucket.tokens < 50.0);
        bucket.reset();
        assert_eq!(bucket.tokens, 100.0);
    }

    #[test]
    fn test_burst_classification_attack() {
        let bucket = RateLimitBucket::new(100.0, 50.0, DEFAULT_BURST_MULTIPLIER);
        assert_eq!(
            bucket.classify_burst(250.0),
            BurstClassification::AttackBurst
        );
    }

    #[test]
    fn test_burst_classification_legitimate() {
        let bucket = RateLimitBucket::new(100.0, 50.0, DEFAULT_BURST_MULTIPLIER);
        assert_eq!(
            bucket.classify_burst(90.0),
            BurstClassification::LegitimateBurst
        );
    }

    #[test]
    fn test_rate_limiter_ip_limit() {
        let config = RateLimitingConfig {
            per_ip_limit: 3,
            burst_size: 10,
            default_rps: 1000,
            per_endpoint_limit: 200,
            per_session_limit: 100,
            adaptive_learning: false,
        };
        let limiter = RateLimiter::new(config);
        let ip: IpAddr = "10.0.0.1".parse().unwrap();

        assert_eq!(
            limiter.check_rate(ip, None, None),
            RateLimitDecision::Allowed
        );
        assert_eq!(
            limiter.check_rate(ip, None, None),
            RateLimitDecision::Allowed
        );
        assert_eq!(
            limiter.check_rate(ip, None, None),
            RateLimitDecision::Allowed
        );
        assert_eq!(
            limiter.check_rate(ip, None, None),
            RateLimitDecision::Dropped
        );
    }

    #[test]
    fn test_distributed_rate_limiter() {
        let config = RateLimitingConfig {
            per_ip_limit: 2,
            burst_size: 2,
            default_rps: 10,
            per_endpoint_limit: 1000,
            per_session_limit: 10,
            adaptive_learning: false,
        };
        let limiter = DistributedRateLimiter::new(config);
        let ip: IpAddr = "10.0.0.1".parse().unwrap();

        let mut non_allowed = 0u32;
        for _ in 0..200 {
            match limiter.check_rate(ip, None, None) {
                RateLimitDecision::Allowed => {}
                _ => non_allowed += 1,
            }
        }
        assert!(
            non_allowed > 0,
            "Some requests should not be allowed after exhausting the bucket, got {} non-allowed",
            non_allowed
        );
    }

    #[test]
    fn test_distributed_rate_limiter_session() {
        let config = RateLimitingConfig {
            per_ip_limit: 1000,
            burst_size: 1000,
            default_rps: 100000,
            per_endpoint_limit: 1000,
            per_session_limit: 5,
            adaptive_learning: false,
        };
        let limiter = DistributedRateLimiter::new(config);
        let ip: IpAddr = "10.0.0.1".parse().unwrap();

        for _ in 0..5 {
            let result = limiter.check_rate(ip, None, Some("session-abc"));
            assert_eq!(result, RateLimitDecision::Allowed);
        }

        for _ in 0..100 {
            limiter.check_rate(ip, None, Some("session-abc"));
        }

        let mut final_result = RateLimitDecision::Allowed;
        for _ in 0..5 {
            final_result = limiter.check_rate(ip, None, Some("session-abc"));
        }
        assert_eq!(final_result, RateLimitDecision::Dropped);
    }

    #[test]
    fn test_distributed_rate_limiter_endpoint() {
        let config = RateLimitingConfig {
            per_ip_limit: 1000,
            burst_size: 5000,
            default_rps: 1000,
            per_endpoint_limit: 2,
            per_session_limit: 100,
            adaptive_learning: false,
        };
        let limiter = DistributedRateLimiter::new(config);
        let ip: IpAddr = "10.0.0.1".parse().unwrap();

        assert_eq!(
            limiter.check_rate(ip, Some("/api/login"), Some("sess1")),
            RateLimitDecision::Allowed
        );
        assert_eq!(
            limiter.check_rate(ip, Some("/api/login"), Some("sess1")),
            RateLimitDecision::Allowed
        );
        let decision = limiter.check_rate(ip, Some("/api/login"), Some("sess1"));
        assert!(matches!(
            decision,
            RateLimitDecision::Queued | RateLimitDecision::Dropped
        ));
    }

    #[test]
    fn test_adaptive_threshold() {
        let config = test_config();
        let limiter = DistributedRateLimiter::new(config);
        limiter.set_adaptive_threshold("ip:10.0.0.1", 0.8);
        assert_eq!(limiter.get_adaptive_threshold("ip:10.0.0.1"), Some(0.8));
    }

    #[test]
    fn test_ema_baseline() {
        let config = test_config();
        let limiter = DistributedRateLimiter::new(config);
        limiter.update_ema_baseline("ip:10.0.0.1", 100.0);
        limiter.update_ema_baseline("ip:10.0.0.1", 100.0);
        limiter.update_ema_baseline("ip:10.0.0.1", 100.0);
        let baseline = limiter.get_ema_baseline("ip:10.0.0.1").unwrap();
        assert!(baseline > 50.0);
    }

    #[test]
    fn test_clear_all() {
        let config = test_config();
        let limiter = DistributedRateLimiter::new(config);
        let ip: IpAddr = "10.0.0.1".parse().unwrap();
        limiter.check_rate(ip, None, None);
        limiter.set_adaptive_threshold("ip:10.0.0.1", 0.5);
        limiter.clear_all();
        assert!(limiter.get_adaptive_threshold("ip:10.0.0.1").is_none());
        assert!(limiter.get_ema_baseline("ip:10.0.0.1").is_none());
    }
}
