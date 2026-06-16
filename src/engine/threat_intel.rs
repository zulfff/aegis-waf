use crate::config::ThreatIntelligenceConfig;
use crate::error::AegisError;
use crate::metrics::THREAT_INTEL_HITS;
use chrono::Utc;
use hashbrown::HashMap;
use parking_lot::RwLock;

const DEFAULT_IP_THRESHOLD: f32 = 0.7;
const DEFAULT_CACHE_TTL: i64 = 3600;

#[derive(Debug, Clone)]
pub struct ThreatIntelFeed {
    pub name: String,
    pub url: String,
    pub last_update: i64,
    pub ip_entries: HashMap<String, f32>,
    pub domain_entries: HashMap<String, f32>,
    pub enabled: bool,
}

#[derive(Debug, Clone)]
pub struct ThreatScore {
    pub ip_score: f32,
    pub domain_score: f32,
    pub combined_score: f32,
    pub sources: Vec<String>,
}

impl ThreatScore {
    pub fn is_malicious(&self, threshold: f32) -> bool {
        self.combined_score >= threshold
    }
}

#[derive(Debug, Clone)]
struct CachedScore {
    score: ThreatScore,
    cached_at: i64,
    ttl: i64,
}

#[derive(Debug)]
pub struct ThreatIntelligence {
    #[allow(dead_code)]
    config: ThreatIntelligenceConfig,
    feeds: RwLock<HashMap<String, ThreatIntelFeed>>,
    score_cache: RwLock<HashMap<String, CachedScore>>,
    generated_rules: RwLock<Vec<String>>,
}

impl ThreatIntelligence {
    pub fn new(config: ThreatIntelligenceConfig) -> Self {
        ThreatIntelligence {
            config,
            feeds: RwLock::new(HashMap::new()),
            score_cache: RwLock::new(HashMap::new()),
            generated_rules: RwLock::new(Vec::new()),
        }
    }

    pub fn add_feed(&self, name: &str, url: &str) -> crate::error::Result<()> {
        let mut feeds = self.feeds.write();
        if feeds.contains_key(name) {
            return Err(AegisError::ThreatIntelError(format!(
                "Feed '{}' already exists",
                name
            )));
        }

        feeds.insert(
            name.to_string(),
            ThreatIntelFeed {
                name: name.to_string(),
                url: url.to_string(),
                last_update: 0,
                ip_entries: HashMap::new(),
                domain_entries: HashMap::new(),
                enabled: true,
            },
        );

        Ok(())
    }

    pub fn remove_feed(&self, name: &str) -> crate::error::Result<()> {
        let mut feeds = self.feeds.write();
        if feeds.remove(name).is_none() {
            return Err(AegisError::ThreatIntelError(format!(
                "Feed '{}' not found",
                name
            )));
        }
        Ok(())
    }

    pub fn update_feeds(&self) -> crate::error::Result<usize> {
        let mut updated = 0;
        let mut feeds = self.feeds.write();

        for (name, feed) in feeds.iter_mut() {
            if !feed.enabled {
                continue;
            }

            match self.fetch_feed_sync(&feed.url) {
                Ok((ips, domains)) => {
                    feed.ip_entries = ips;
                    feed.domain_entries = domains;
                    feed.last_update = Utc::now().timestamp();
                    updated += 1;
                }
                Err(e) => {
                    tracing::warn!(
                        feed_name = %name,
                        feed_url = %feed.url,
                        error = %e,
                        "Failed to update threat intel feed"
                    );
                }
            }
        }

        Ok(updated)
    }

    #[allow(clippy::await_holding_lock)]
    pub async fn update_feeds_async(&self) -> crate::error::Result<usize> {
        let mut updated = 0;
        let mut feeds = self.feeds.write();

        let feed_updates: Vec<_> = feeds
            .iter()
            .filter(|(_, f)| f.enabled)
            .map(|(name, feed)| {
                let name = name.clone();
                let url = feed.url.clone();
                tokio::spawn(async move {
                    match fetch_feed_http(&url).await {
                        Ok((ips, domains)) => Some((name, ips, domains)),
                        Err(e) => {
                            tracing::warn!(feed_name = %name, error = %e, "Async feed update failed");
                            None
                        }
                    }
                })
            })
            .collect();

        for join_handle in feed_updates {
            if let Ok(Some((name, ips, domains))) = join_handle.await {
                if let Some(feed) = feeds.get_mut(&name) {
                    feed.ip_entries = ips;
                    feed.domain_entries = domains;
                    feed.last_update = Utc::now().timestamp();
                    updated += 1;
                }
            }
        }

        Ok(updated)
    }

    fn fetch_feed_sync(
        &self,
        url: &str,
    ) -> crate::error::Result<(HashMap<String, f32>, HashMap<String, f32>)> {
        if url.starts_with("file://") {
            let path = url.trim_start_matches("file://");
            let content = std::fs::read_to_string(path).map_err(|e| {
                AegisError::ThreatIntelError(format!("Failed to read feed file {}: {}", path, e))
            })?;
            parse_feed_content(&content).map_err(AegisError::ThreatIntelError)
        } else if url.starts_with("stub://") {
            let stub_data = url.trim_start_matches("stub://");
            parse_feed_content(stub_data).map_err(AegisError::ThreatIntelError)
        } else {
            Ok((HashMap::new(), HashMap::new()))
        }
    }

    pub fn check_ip(&self, ip: &str) -> Option<ThreatScore> {
        let cache_key = format!("ip:{}", ip);

        {
            let cache = self.score_cache.read();
            if let Some(cached) = cache.get(&cache_key) {
                let now = Utc::now().timestamp();
                if now - cached.cached_at < cached.ttl {
                    return Some(cached.score.clone());
                }
            }
        }

        let feeds = self.feeds.read();
        let mut ip_score: f32 = 0.0;
        let mut sources: Vec<String> = Vec::new();
        let mut contributing_feeds = 0u32;

        for (_, feed) in feeds.iter() {
            if !feed.enabled {
                continue;
            }
            if let Some(&score) = feed.ip_entries.get(ip) {
                ip_score += score;
                sources.push(feed.name.clone());
                contributing_feeds += 1;
            }
        }

        if contributing_feeds > 0 {
            ip_score /= contributing_feeds as f32;
        } else {
            return None;
        }

        let combined_score = ip_score;
        let score = ThreatScore {
            ip_score,
            domain_score: 0.0,
            combined_score,
            sources,
        };

        if score.is_malicious(DEFAULT_IP_THRESHOLD) {
            let _ = THREAT_INTEL_HITS.with_label_values(&["ip", "malicious"]);
        }

        let mut cache = self.score_cache.write();
        cache.insert(
            cache_key,
            CachedScore {
                score: score.clone(),
                cached_at: Utc::now().timestamp(),
                ttl: DEFAULT_CACHE_TTL,
            },
        );

        Some(score)
    }

    pub fn check_domain(&self, domain: &str) -> Option<ThreatScore> {
        let cache_key = format!("domain:{}", domain);

        {
            let cache = self.score_cache.read();
            if let Some(cached) = cache.get(&cache_key) {
                let now = Utc::now().timestamp();
                if now - cached.cached_at < cached.ttl {
                    return Some(cached.score.clone());
                }
            }
        }

        let feeds = self.feeds.read();
        let mut domain_score: f32 = 0.0;
        let mut sources: Vec<String> = Vec::new();
        let mut contributing_feeds = 0u32;

        let normalized = domain.to_lowercase();
        let parts: Vec<&str> = normalized.split('.').collect();

        for (_, feed) in feeds.iter() {
            if !feed.enabled {
                continue;
            }
            for (entry, &score) in &feed.domain_entries {
                if entry.as_str() == normalized {
                    domain_score += score;
                    sources.push(feed.name.clone());
                    contributing_feeds += 1;
                    break;
                }
                if parts.len() >= 2 && parts.len() <= 4 {
                    let parent = parts[parts.len().saturating_sub(2)..].join(".");
                    if entry.as_str() == parent {
                        domain_score += score * 0.7;
                        sources.push(feed.name.clone());
                        contributing_feeds += 1;
                        break;
                    }
                }
            }
        }

        if contributing_feeds > 0 {
            domain_score /= contributing_feeds as f32;
        } else {
            return None;
        }

        let combined_score = domain_score;
        let score = ThreatScore {
            ip_score: 0.0,
            domain_score,
            combined_score,
            sources,
        };

        if score.is_malicious(DEFAULT_IP_THRESHOLD) {
            let _ = THREAT_INTEL_HITS.with_label_values(&["domain", "malicious"]);
        }

        let mut cache = self.score_cache.write();
        cache.insert(
            cache_key,
            CachedScore {
                score: score.clone(),
                cached_at: Utc::now().timestamp(),
                ttl: DEFAULT_CACHE_TTL,
            },
        );

        Some(score)
    }

    pub fn check_both(&self, ip: &str, domain: &str) -> ThreatScore {
        let ip_part = self.check_ip(ip);
        let domain_part = self.check_domain(domain);

        let ip_score = ip_part.as_ref().map(|s| s.ip_score).unwrap_or(0.0);
        let domain_score = domain_part.as_ref().map(|s| s.domain_score).unwrap_or(0.0);

        let mut sources: Vec<String> = Vec::new();
        if let Some(ref s) = ip_part {
            sources.extend(s.sources.iter().cloned());
        }
        if let Some(ref s) = domain_part {
            for src in &s.sources {
                if !sources.contains(src) {
                    sources.push(src.clone());
                }
            }
        }

        let combined_score = if ip_score > 0.0 && domain_score > 0.0 {
            (ip_score + domain_score) / 2.0
        } else {
            ip_score.max(domain_score)
        };

        ThreatScore {
            ip_score,
            domain_score,
            combined_score,
            sources,
        }
    }

    pub fn calculate_threat_score(&self, ip: &str, domain: Option<&str>) -> ThreatScore {
        match domain {
            Some(d) => self.check_both(ip, d),
            None => {
                let ip_result = self.check_ip(ip);
                ip_result.unwrap_or(ThreatScore {
                    ip_score: 0.0,
                    domain_score: 0.0,
                    combined_score: 0.0,
                    sources: Vec::new(),
                })
            }
        }
    }

    pub fn generate_rules_from_detections(&self, ip: &str, threshold: f32) -> Vec<String> {
        let score = self.check_ip(ip);
        let mut rules = Vec::new();

        if let Some(score) = score {
            if score.combined_score >= threshold {
                let rule = format!(
                    "block ip:{} # score={:.3} sources=[{}]",
                    ip,
                    score.combined_score,
                    score.sources.join(",")
                );
                rules.push(rule);
            }
        }

        let mut generated = self.generated_rules.write();
        for rule in &rules {
            if !generated.contains(rule) {
                generated.push(rule.clone());
            }
        }

        if generated.len() > 10000 {
            generated.drain(0..5000);
        }

        rules
    }

    pub fn get_feeds(&self) -> Vec<ThreatIntelFeed> {
        self.feeds.read().values().cloned().collect()
    }

    pub fn clear_cache(&self) {
        self.score_cache.write().clear();
    }

    pub fn get_cache_stats(&self) -> (usize, usize) {
        let cache = self.score_cache.read();
        let total = cache.len();
        let now = Utc::now().timestamp();
        let expired = cache
            .values()
            .filter(|c| now - c.cached_at >= c.ttl)
            .count();
        (total, expired)
    }

    pub fn feed_count(&self) -> usize {
        self.feeds.read().len()
    }
}

#[allow(clippy::type_complexity)]
fn parse_feed_content(
    content: &str,
) -> std::result::Result<(HashMap<String, f32>, HashMap<String, f32>), String> {
    let mut ips: HashMap<String, f32> = HashMap::new();
    let mut domains: HashMap<String, f32> = HashMap::new();

    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }

        let parts: Vec<&str> = line.splitn(3, ',').collect();
        if parts.len() < 2 {
            continue;
        }

        let entry = parts[0].trim();
        let score: f32 = parts[1].trim().parse().unwrap_or(0.8);

        if entry.contains(':') || entry.parse::<std::net::IpAddr>().is_ok() {
            ips.insert(entry.to_string(), score.clamp(0.0, 1.0));
        } else if entry.contains('.') {
            domains.insert(entry.to_lowercase(), score.clamp(0.0, 1.0));
        }
    }

    Ok((ips, domains))
}

async fn fetch_feed_http(
    url: &str,
) -> std::result::Result<(HashMap<String, f32>, HashMap<String, f32>), String> {
    if url.starts_with("file://") {
        let path = url.trim_start_matches("file://");
        let content = std::fs::read_to_string(path).map_err(|e| e.to_string())?;
        return parse_feed_content(&content);
    }
    if url.starts_with("stub://") {
        let data = url.trim_start_matches("stub://");
        return parse_feed_content(data);
    }
    Ok((HashMap::new(), HashMap::new()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_intel() -> ThreatIntelligence {
        ThreatIntelligence::new(ThreatIntelligenceConfig::default())
    }

    #[test]
    fn test_add_remove_feed() {
        let intel = test_intel();
        intel
            .add_feed("test_feed", "https://example.com/feed.txt")
            .unwrap();
        assert_eq!(intel.feed_count(), 1);
        intel.remove_feed("test_feed").unwrap();
        assert_eq!(intel.feed_count(), 0);
    }

    #[test]
    fn test_add_duplicate_feed() {
        let intel = test_intel();
        intel.add_feed("dup", "stub://").unwrap();
        assert!(intel.add_feed("dup", "stub://").is_err());
    }

    #[test]
    fn test_remove_nonexistent_feed() {
        let intel = test_intel();
        assert!(intel.remove_feed("nonexistent").is_err());
    }

    #[test]
    fn test_fetch_stub_feed_and_check_ip() {
        let intel = test_intel();
        let stub_data = "1.2.3.4,0.95\n5.6.7.8,0.8\nevilsite.com,0.9";
        intel
            .add_feed("stub", &format!("stub://{}", stub_data))
            .unwrap();
        intel.update_feeds().unwrap();

        let score = intel.check_ip("1.2.3.4");
        assert!(score.is_some());
        let s = score.unwrap();
        assert!(s.ip_score > 0.9);
        assert!(s.is_malicious(0.5));

        let score = intel.check_ip("10.0.0.1");
        assert!(score.is_none());
    }

    #[test]
    fn test_check_domain() {
        let intel = test_intel();
        let stub_data = "evilsite.com,0.95\nmalware.org,0.85";
        intel
            .add_feed("stub2", &format!("stub://{}", stub_data))
            .unwrap();
        intel.update_feeds().unwrap();

        let score = intel.check_domain("evilsite.com");
        assert!(score.is_some());
        let s = score.unwrap();
        assert!(s.domain_score > 0.9);

        let score = intel.check_domain("safe.com");
        assert!(score.is_none());
    }

    #[test]
    fn test_calculate_threat_score() {
        let intel = test_intel();
        let stub_data = "1.2.3.4,0.9\nevilsite.com,0.8";
        intel
            .add_feed("stub3", &format!("stub://{}", stub_data))
            .unwrap();
        intel.update_feeds().unwrap();

        let score = intel.calculate_threat_score("1.2.3.4", Some("evilsite.com"));
        assert!(score.combined_score > 0.7);

        let score = intel.calculate_threat_score("1.2.3.4", None);
        assert!(score.ip_score > 0.8);

        let score = intel.calculate_threat_score("10.0.0.99", None);
        assert_eq!(score.combined_score, 0.0);
    }

    #[test]
    fn test_generate_rules() {
        let intel = test_intel();
        let stub_data = "10.99.99.99,0.95";
        intel
            .add_feed("stub4", &format!("stub://{}", stub_data))
            .unwrap();
        intel.update_feeds().unwrap();

        let rules = intel.generate_rules_from_detections("10.99.99.99", 0.5);
        assert!(!rules.is_empty());
        assert!(rules[0].contains("block ip:10.99.99.99"));
    }

    #[test]
    fn test_score_caching() {
        let intel = test_intel();
        let stub_data = "5.5.5.5,0.99";
        intel
            .add_feed("cache_test", &format!("stub://{}", stub_data))
            .unwrap();
        intel.update_feeds().unwrap();

        let _ = intel.check_ip("5.5.5.5");
        let (total, _expired) = intel.get_cache_stats();
        assert!(total > 0);
    }

    #[test]
    fn test_parse_feed_content() {
        let content = "10.0.0.1,0.95,comment\nbad.domain.com,0.8\n# comment line\n\nnotenough";
        let (ips, domains) = parse_feed_content(content).unwrap();
        assert_eq!(ips.len(), 1);
        assert_eq!(domains.len(), 1);
    }

    #[test]
    fn test_feed_empty() {
        let intel = test_intel();
        assert_eq!(intel.feed_count(), 0);
        let score = intel.check_ip("127.0.0.1");
        assert!(score.is_none());
    }

    #[test]
    fn test_clear_cache() {
        let intel = test_intel();
        let stub_data = "1.1.1.1,0.5";
        intel
            .add_feed("clear", &format!("stub://{}", stub_data))
            .unwrap();
        intel.update_feeds().unwrap();
        intel.check_ip("1.1.1.1");
        intel.clear_cache();
        let (total, _) = intel.get_cache_stats();
        assert_eq!(total, 0);
    }
}
