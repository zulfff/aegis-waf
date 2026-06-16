use crate::config::BehavioralConfig;
use crate::metrics::ATTACKS_DETECTED;
use chrono::{DateTime, Datelike, Timelike, Utc, Weekday};
use hashbrown::HashMap;
use parking_lot::RwLock;
use std::collections::VecDeque;

#[derive(Debug, Clone)]
pub struct TrafficBaseline {
    pub mean: f64,
    pub stddev: f64,
    pub min: f64,
    pub max: f64,
    pub ema: f64,
    pub sample_count: u64,
}

impl Default for TrafficBaseline {
    fn default() -> Self {
        TrafficBaseline {
            mean: 0.0,
            stddev: 0.0,
            min: f64::MAX,
            max: f64::MIN,
            ema: 0.0,
            sample_count: 0,
        }
    }
}

#[derive(Debug, Clone)]
pub struct DeviceFingerprint {
    pub hash: u64,
    pub entropy: f32,
    pub components: HashMap<String, String>,
}

#[derive(Debug, Clone)]
pub struct AnomalyScore {
    pub overall: f32,
    pub components: Vec<(String, f32)>,
}

#[derive(Debug, Clone)]
#[allow(dead_code)]
struct HourlyBucket {
    hour: u32,
    request_count: u64,
    avg_latency: f64,
    unique_paths: usize,
    error_ratio: f64,
}

#[derive(Debug, Clone)]
#[allow(dead_code)]
struct TransitionRecord {
    from_path: String,
    to_path: String,
    count: u64,
    last_seen: i64,
}

#[derive(Debug)]
pub struct BehavioralAnalyzer {
    config: BehavioralConfig,
    baseline: RwLock<TrafficBaseline>,
    hourly_patterns: RwLock<Vec<HourlyBucket>>,
    samples: RwLock<VecDeque<f64>>,
    path_transitions: RwLock<HashMap<(String, String), u64>>,
    path_sequence: RwLock<VecDeque<String>>,
    transition_history: RwLock<Vec<TransitionRecord>>,
    #[allow(dead_code)]
    markov_states: RwLock<HashMap<String, Vec<(String, f64)>>>,
}

impl BehavioralAnalyzer {
    pub fn new(config: BehavioralConfig) -> Self {
        let hourly = (0..24)
            .map(|h| HourlyBucket {
                hour: h,
                request_count: 0,
                avg_latency: 0.0,
                unique_paths: 0,
                error_ratio: 0.0,
            })
            .collect();

        BehavioralAnalyzer {
            config,
            baseline: RwLock::new(TrafficBaseline::default()),
            hourly_patterns: RwLock::new(hourly),
            samples: RwLock::new(VecDeque::with_capacity(100_000)),
            path_transitions: RwLock::new(HashMap::new()),
            path_sequence: RwLock::new(VecDeque::with_capacity(1000)),
            transition_history: RwLock::new(Vec::with_capacity(10_000)),
            markov_states: RwLock::new(HashMap::new()),
        }
    }

    pub fn calculate_baseline(&self, samples: &[f64]) -> TrafficBaseline {
        if samples.is_empty() {
            return TrafficBaseline::default();
        }

        let n = samples.len() as f64;
        let mean: f64 = samples.iter().sum::<f64>() / n;
        let variance: f64 = samples.iter().map(|s| (s - mean).powi(2)).sum::<f64>() / n;
        let stddev = variance.sqrt();
        let min = samples.iter().cloned().fold(f64::INFINITY, f64::min);
        let max = samples.iter().cloned().fold(f64::NEG_INFINITY, f64::max);
        let ema = compute_ema(samples, self.config.ema_alpha);

        TrafficBaseline {
            mean,
            stddev,
            min,
            max,
            ema,
            sample_count: samples.len() as u64,
        }
    }

    pub fn update_baseline(&self, sample: f64) {
        let mut baseline = self.baseline.write();
        let mut samples = self.samples.write();

        samples.push_back(sample);
        if samples.len() > self.config.detection_window_seconds as usize * 100 {
            samples.pop_front();
        }

        let window: Vec<f64> = samples.iter().cloned().collect();
        *baseline = self.calculate_baseline(&window);
    }

    pub fn score_anomaly(&self, sample: f64, baseline: &TrafficBaseline) -> AnomalyScore {
        let mut components: Vec<(String, f32)> = Vec::new();

        let z_score = if baseline.stddev > 0.0 && baseline.sample_count > 3 {
            (sample - baseline.mean).abs() / baseline.stddev
        } else {
            0.0
        };
        components.push(("z_score".to_string(), normalize_score(z_score, 3.0)));

        let ema_deviation = if baseline.ema > 0.0 {
            (sample - baseline.ema).abs() / baseline.ema
        } else {
            0.0
        };
        components.push((
            "ema_deviation".to_string(),
            normalize_score(ema_deviation, 2.0),
        ));

        let range = baseline.max - baseline.min;
        let percentile_deviation = if range > 0.0 && baseline.sample_count > 5 {
            let position = (sample - baseline.min) / range;
            if !(0.0..=1.0).contains(&position) {
                (position - 0.5).abs() * 2.0
            } else {
                0.0
            }
        } else {
            0.0
        };
        components.push((
            "percentile_outlier".to_string(),
            normalize_score(percentile_deviation, 0.95),
        ));

        let overall: f64 = components
            .iter()
            .map(|(_, score)| *score as f64)
            .sum::<f64>()
            / components.len() as f64;

        if overall > self.config.anomaly_threshold {
            let _ = ATTACKS_DETECTED.with_label_values(&["behavioral_anomaly", "medium"]);
        }

        AnomalyScore {
            overall: overall.min(1.0) as f32,
            components,
        }
    }

    pub fn detect_temporal_anomaly(&self, timestamp: DateTime<Utc>) -> AnomalyScore {
        let hour = timestamp.hour();
        let day = timestamp.weekday();
        let mut components: Vec<(String, f32)> = Vec::new();

        let patterns = self.hourly_patterns.read();
        let current_hour_bucket = &patterns[hour as usize];

        let is_night_hour = (1..=5).contains(&hour);
        let is_weekend = matches!(day, Weekday::Sat | Weekday::Sun);

        if current_hour_bucket.request_count > 0 {
            let night_factor = if is_night_hour { 0.15 } else { 0.0 };
            components.push(("off_hours".to_string(), night_factor));
        } else {
            components.push(("off_hours".to_string(), 0.0));
        }

        let weekend_factor = if is_weekend { 0.10 } else { 0.0 };
        components.push(("weekend".to_string(), weekend_factor));

        drop(patterns);

        let overall: f32 = components.iter().map(|(_, score)| *score).sum::<f32>()
            / components.len().max(1) as f32;

        AnomalyScore {
            overall: overall.min(1.0f32),
            components,
        }
    }

    pub fn record_sample(&self, value: f64, timestamp: DateTime<Utc>) {
        self.update_baseline(value);

        let hour = timestamp.hour();
        let mut patterns = self.hourly_patterns.write();
        if hour < 24 {
            let bucket = &mut patterns[hour as usize];
            let prev_count = bucket.request_count as f64;
            bucket.request_count += 1;
            bucket.avg_latency = (bucket.avg_latency * prev_count + value) / (prev_count + 1.0);
        }
    }

    pub fn track_request_sequence(&self, path: &str) {
        let mut sequence = self.path_sequence.write();

        if let Some(last_path) = sequence.back() {
            let key = (last_path.clone(), path.to_string());
            let mut transitions = self.path_transitions.write();
            let count = transitions.entry(key).or_insert(0);
            *count += 1;

            let mut history = self.transition_history.write();
            history.push(TransitionRecord {
                from_path: last_path.clone(),
                to_path: path.to_string(),
                count: *count,
                last_seen: Utc::now().timestamp(),
            });

            if history.len() > 10_000 {
                history.drain(0..1000);
            }
        }

        sequence.push_back(path.to_string());
        if sequence.len() > 1000 {
            sequence.pop_front();
        }
    }

    pub fn check_pattern_deviation(&self, current_path: &str) -> AnomalyScore {
        let mut components = Vec::new();
        let sequence = self.path_sequence.read();

        let path_repeat_score = if sequence.len() > 5 {
            let recent: Vec<_> = sequence.iter().rev().take(10).collect();
            let same_count = recent.iter().filter(|p| p.as_str() == current_path).count();
            if same_count > 7 {
                0.7
            } else if same_count > 4 {
                0.3
            } else {
                0.0
            }
        } else {
            0.0
        };
        components.push(("path_repetition".to_string(), path_repeat_score as f32));

        drop(sequence);

        let transitions = self.path_transitions.read();
        if let Some(last_path) = self.path_sequence.read().back() {
            let key = (last_path.clone(), current_path.to_string());
            let transition_count = transitions.get(&key).copied().unwrap_or(0);
            let novelty_score = if transition_count == 0 && !transitions.is_empty() {
                0.5
            } else {
                0.0
            };
            components.push(("novel_transition".to_string(), novelty_score as f32));
        }
        drop(transitions);

        let overall = if components.is_empty() {
            0.0
        } else {
            components.iter().map(|(_, s)| s).sum::<f32>() / components.len() as f32
        };

        AnomalyScore {
            overall: overall.min(1.0),
            components,
        }
    }

    pub fn generate_fingerprint(
        &self,
        headers: &HashMap<String, String>,
        ip: &str,
    ) -> DeviceFingerprint {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};

        let mut hasher = DefaultHasher::new();
        let mut components: HashMap<String, String> = HashMap::new();

        let ua = headers.get("user-agent").cloned().unwrap_or_default();
        components.insert("user_agent".to_string(), ua.clone());
        ua.hash(&mut hasher);

        let accept_lang = headers.get("accept-language").cloned().unwrap_or_default();
        components.insert("accept_language".to_string(), accept_lang.clone());
        accept_lang.hash(&mut hasher);

        let accept_enc = headers.get("accept-encoding").cloned().unwrap_or_default();
        components.insert("accept_encoding".to_string(), accept_enc.clone());
        accept_enc.hash(&mut hasher);

        let sec_ch_ua = headers.get("sec-ch-ua").cloned().unwrap_or_default();
        components.insert("sec_ch_ua".to_string(), sec_ch_ua.clone());
        sec_ch_ua.hash(&mut hasher);

        let sec_ch_ua_platform = headers
            .get("sec-ch-ua-platform")
            .cloned()
            .unwrap_or_default();
        components.insert("sec_ch_ua_platform".to_string(), sec_ch_ua_platform.clone());
        sec_ch_ua_platform.hash(&mut hasher);

        ip.hash(&mut hasher);

        let hash = hasher.finish();
        let entropy = compute_entropy(&ua);

        DeviceFingerprint {
            hash,
            entropy,
            components,
        }
    }

    pub fn get_baseline(&self) -> TrafficBaseline {
        self.baseline.read().clone()
    }

    pub fn detect_threat_actor_pattern(&self, fingerprint: &DeviceFingerprint) -> f32 {
        let mut score = 0.0f32;

        if fingerprint.entropy < 1.0 {
            score += 0.2;
        }

        if fingerprint.entropy > 7.0 {
            score += 0.15;
        }

        let ua = fingerprint
            .components
            .get("user_agent")
            .map(|s| s.as_str())
            .unwrap_or("");
        if ua.is_empty() {
            score += 0.4;
        }

        let accept_lang = fingerprint
            .components
            .get("accept_language")
            .map(|s| s.as_str())
            .unwrap_or("");
        if accept_lang.is_empty() && !ua.is_empty() {
            score += 0.25;
        }

        score.min(1.0)
    }
}

fn compute_ema(samples: &[f64], alpha: f64) -> f64 {
    if samples.is_empty() {
        return 0.0;
    }
    let clamped_alpha = alpha.clamp(0.0, 1.0);
    let mut ema = samples[0];
    for &sample in &samples[1..] {
        ema = clamped_alpha * sample + (1.0 - clamped_alpha) * ema;
    }
    ema
}

fn normalize_score(raw: f64, threshold: f64) -> f32 {
    if threshold <= 0.0 {
        return 0.0;
    }
    (raw / threshold).min(1.0) as f32
}

fn compute_entropy(s: &str) -> f32 {
    if s.is_empty() {
        return 0.0;
    }
    let len = s.len() as f32;
    let mut freq: HashMap<char, f32> = HashMap::new();
    for ch in s.chars() {
        *freq.entry(ch).or_insert(0.0) += 1.0;
    }
    let entropy: f32 = freq
        .values()
        .map(|&count| {
            let p = count / len;
            if p > 0.0 {
                -p * p.log2()
            } else {
                0.0
            }
        })
        .sum();
    entropy
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_analyzer() -> BehavioralAnalyzer {
        BehavioralAnalyzer::new(BehavioralConfig::default())
    }

    #[test]
    fn test_calculate_baseline() {
        let analyzer = test_analyzer();
        let samples = vec![10.0, 12.0, 11.0, 9.0, 13.0, 10.0, 11.0, 12.0, 10.0, 11.0];
        let baseline = analyzer.calculate_baseline(&samples);
        assert!((baseline.mean - 10.9).abs() < 0.2);
        assert!(baseline.stddev > 0.0);
        assert_eq!(baseline.sample_count, 10);
    }

    #[test]
    fn test_baseline_empty() {
        let analyzer = test_analyzer();
        let baseline = analyzer.calculate_baseline(&[]);
        assert_eq!(baseline.mean, 0.0);
        assert_eq!(baseline.sample_count, 0);
    }

    #[test]
    fn test_score_anomaly_normal() {
        let analyzer = test_analyzer();
        let samples: Vec<f64> = (0..100).map(|i| 50.0 + (i as f64 % 10.0)).collect();
        let baseline = analyzer.calculate_baseline(&samples);
        let score = analyzer.score_anomaly(52.0, &baseline);
        assert!(
            score.overall < 0.5,
            "Expected low anomaly for normal sample, got {}",
            score.overall
        );
    }

    #[test]
    fn test_score_anomaly_extreme() {
        let analyzer = test_analyzer();
        let samples: Vec<f64> = (0..100).map(|i| 50.0 + (i as f64 % 10.0)).collect();
        let baseline = analyzer.calculate_baseline(&samples);
        let score = analyzer.score_anomaly(1000.0, &baseline);
        assert!(
            score.overall > 0.5,
            "Expected high anomaly for extreme sample, got {}",
            score.overall
        );
    }

    #[test]
    fn test_update_baseline_incremental() {
        let analyzer = test_analyzer();
        for i in 0..10 {
            analyzer.update_baseline(100.0 + i as f64);
        }
        let baseline = analyzer.get_baseline();
        assert!(baseline.mean > 100.0);
        assert!(baseline.sample_count > 0);
    }

    #[test]
    fn test_temporal_anomaly() {
        let analyzer = test_analyzer();
        let night_time = Utc::now()
            .with_hour(3)
            .unwrap_or_default()
            .with_minute(0)
            .unwrap_or_default()
            .with_second(0)
            .unwrap_or_default();
        let score = analyzer.detect_temporal_anomaly(night_time);
        assert!(score.overall <= 1.0);
    }

    #[test]
    fn test_request_sequence_tracking() {
        let analyzer = test_analyzer();
        analyzer.track_request_sequence("/api/users");
        analyzer.track_request_sequence("/api/products");
        analyzer.track_request_sequence("/api/users");
        let _score = analyzer.check_pattern_deviation("/api/users");
    }

    #[test]
    fn test_fingerprint_generation() {
        let analyzer = test_analyzer();
        let mut headers = HashMap::new();
        headers.insert("user-agent".to_string(), "Mozilla/5.0 Test".to_string());
        headers.insert("accept-language".to_string(), "en-US".to_string());
        let fp = analyzer.generate_fingerprint(&headers, "192.168.1.1");
        assert!(fp.hash != 0);
        assert!(fp.components.contains_key("user_agent"));
    }

    #[test]
    fn test_threat_actor_detection() {
        let analyzer = test_analyzer();
        let mut components = HashMap::new();
        components.insert("user_agent".to_string(), String::new());
        components.insert("accept_language".to_string(), String::new());
        let fp = DeviceFingerprint {
            hash: 0,
            entropy: 0.5,
            components,
        };
        let score = analyzer.detect_threat_actor_pattern(&fp);
        assert!(score > 0.3);
    }

    #[test]
    fn test_ema_computation() {
        let samples = vec![10.0, 12.0, 11.0, 13.0, 10.0];
        let ema = compute_ema(&samples, 0.1);
        assert!(ema > 10.0 && ema < 13.0);
    }
}
