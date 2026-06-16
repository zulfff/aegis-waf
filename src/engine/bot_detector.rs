use crate::config::BotDetectionConfig;
use crate::metrics::BOT_DETECTIONS;
use chrono::Utc;
use hashbrown::HashMap;
use parking_lot::RwLock;
use rand::Rng;
use sha2::{Digest, Sha256};
use std::time::{Duration, Instant};

#[derive(Debug, Clone)]
pub struct JavaScriptChallenge {
    pub challenge_id: String,
    pub solution: String,
    pub issued_at: i64,
    pub expires_at: i64,
    pub difficulty: u32,
    pub validation_hash: String,
}

#[derive(Debug, Clone)]
pub struct BotScore {
    pub probability: f32,
    pub indicators: Vec<String>,
    pub confidence: f32,
    pub bot_type: Option<String>,
}

impl BotScore {
    pub fn is_bot(&self) -> bool {
        self.probability > 0.5
    }
}

#[derive(Debug, Clone)]
struct RequestSample {
    timestamp: Instant,
    #[allow(dead_code)]
    path: String,
}

#[derive(Debug)]
struct ChallengeStore {
    challenges: HashMap<String, JavaScriptChallenge>,
    active_challenges: HashMap<String, String>,
}

#[derive(Debug)]
pub struct BotDetector {
    #[allow(dead_code)]
    config: BotDetectionConfig,
    challenges: RwLock<ChallengeStore>,
    request_history: RwLock<HashMap<String, Vec<RequestSample>>>,
    cookie_registry: RwLock<HashMap<String, Vec<String>>>,
    known_patterns: Vec<BotPattern>,
}

#[derive(Debug, Clone)]
struct BotPattern {
    name: &'static str,
    indicators: &'static [&'static str],
    confidence: f32,
    category: BotCategory,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(dead_code)]
enum BotCategory {
    Headless,
    AiBot,
    Automation,
    Crawler,
    Scraper,
}

impl BotCategory {
    fn as_str(&self) -> &'static str {
        match self {
            BotCategory::Headless => "headless_browser",
            BotCategory::AiBot => "ai_bot",
            BotCategory::Automation => "automation_tool",
            BotCategory::Crawler => "crawler",
            BotCategory::Scraper => "scraper",
        }
    }
}

static KNOWN_PATTERNS: &[BotPattern] = &[
    BotPattern {
        name: "puppeteer",
        indicators: &["HeadlessChrome", "Headless", "puppeteer"],
        confidence: 0.95,
        category: BotCategory::Headless,
    },
    BotPattern {
        name: "playwright",
        indicators: &["Playwright", "com.microsoft.playwright"],
        confidence: 0.95,
        category: BotCategory::Headless,
    },
    BotPattern {
        name: "selenium",
        indicators: &["Selenium", "WebDriver", "webdriver"],
        confidence: 0.92,
        category: BotCategory::Automation,
    },
    BotPattern {
        name: "chatgpt",
        indicators: &["ChatGPT-User", "GPTBot", "ChatGPT", "OAI-SearchBot"],
        confidence: 0.97,
        category: BotCategory::AiBot,
    },
    BotPattern {
        name: "claude",
        indicators: &["Claude-Web", "ClaudeBot", "anthropic-ai", "Claude"],
        confidence: 0.97,
        category: BotCategory::AiBot,
    },
    BotPattern {
        name: "gemini",
        indicators: &[
            "Gemini",
            "Google-Extended",
            "GoogleOther-Image",
            "GoogleOther-Video",
        ],
        confidence: 0.94,
        category: BotCategory::AiBot,
    },
    BotPattern {
        name: "perplexity",
        indicators: &["PerplexityBot", "Perplexity-User"],
        confidence: 0.95,
        category: BotCategory::AiBot,
    },
    BotPattern {
        name: "copilot",
        indicators: &["Copilot", "BingPreview", "bingbot"],
        confidence: 0.90,
        category: BotCategory::AiBot,
    },
    BotPattern {
        name: "generic_headless",
        indicators: &[
            "Mozilla/5.0 (X11; Linux x86_64)",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
        ],
        confidence: 0.15,
        category: BotCategory::Headless,
    },
    BotPattern {
        name: "missing_headers",
        indicators: &[
            "missing_accept_language",
            "missing_accept_encoding",
            "missing_sec_fetch",
        ],
        confidence: 0.70,
        category: BotCategory::Automation,
    },
];

static HEADLESS_NAVIGATOR_PROPERTIES: &[&str] = &[
    "webdriver",
    "__webdriver_evaluate",
    "__selenium_evaluate",
    "__webDriver",
    "__driver_evaluate",
    "__fxdriver_evaluate",
    "__webdriverFunc",
    "_Selenium_IDE_Recorder",
    "_selenium",
    "callSelenium",
    "calledSelenium",
];

impl BotDetector {
    pub fn new(config: BotDetectionConfig) -> Self {
        BotDetector {
            config,
            challenges: RwLock::new(ChallengeStore {
                challenges: HashMap::new(),
                active_challenges: HashMap::new(),
            }),
            request_history: RwLock::new(HashMap::new()),
            cookie_registry: RwLock::new(HashMap::new()),
            known_patterns: KNOWN_PATTERNS.to_vec(),
        }
    }

    pub fn generate_challenge(&self, session_id: &str, remote_ip: &str) -> JavaScriptChallenge {
        let mut rng = rand::thread_rng();

        let a: u64 = rng.gen_range(1000..100_000);
        let b: u64 = rng.gen_range(1000..100_000);
        let c: u64 = rng.gen_range(100..10_000);

        let operation = rng.gen_range(0..4);
        let (_challenge_expr, solution_val) = match operation {
            0 => (
                format!("{} * {} + {}", a, b, c),
                a.wrapping_mul(b).wrapping_add(c),
            ),
            1 => (
                format!("({} + {}) * {}", a, b, c),
                a.wrapping_add(b).wrapping_mul(c),
            ),
            2 => (
                format!("{} * {} - {}", a, b, c),
                a.wrapping_mul(b).wrapping_sub(c),
            ),
            _ => (
                format!("({} - {}) * {}", a, b, c),
                a.wrapping_sub(b).wrapping_mul(c),
            ),
        };

        let challenge_id = format!("aegis-{:x}", rng.gen::<u64>());
        let solution = solution_val.to_string();

        let now = Utc::now().timestamp();
        let expires_at = now + 300;

        let hash_input = format!("{}:{}:{}:{}", challenge_id, solution, remote_ip, now);
        let validation_hash = hex::encode(Sha256::digest(hash_input.as_bytes()));

        let challenge = JavaScriptChallenge {
            challenge_id,
            solution,
            issued_at: now,
            expires_at,
            difficulty: 2,
            validation_hash,
        };

        let mut store = self.challenges.write();
        store
            .challenges
            .insert(challenge.challenge_id.clone(), challenge.clone());
        store
            .active_challenges
            .insert(session_id.to_string(), challenge.challenge_id.clone());

        challenge
    }

    pub fn validate_challenge(&self, challenge_id: &str, answer: &str) -> bool {
        let store = self.challenges.read();
        let now = Utc::now().timestamp();

        if let Some(challenge) = store.challenges.get(challenge_id) {
            if now > challenge.expires_at {
                return false;
            }

            let _expected_hash = {
                let input = format!(
                    "{}:{}:{}:{}",
                    challenge.challenge_id, challenge.solution, "validate", challenge.issued_at
                );
                hex::encode(Sha256::digest(input.as_bytes()))
            };

            challenge.solution == answer
        } else {
            false
        }
    }

    pub fn calculate_bot_score(
        &self,
        user_agent: &str,
        headers: &HashMap<String, String>,
        _session_id: &str,
        ip: &str,
    ) -> BotScore {
        let mut indicators: Vec<String> = Vec::new();
        let mut total_confidence: f32 = 0.0;
        let mut bot_type: Option<String> = None;

        if self.is_headless_browser(user_agent, headers) {
            indicators.push("headless_browser_detected".to_string());
            total_confidence += 0.85;
            bot_type = Some("headless_browser".to_string());
        }

        if let Some(ai_type) = self.detect_ai_bot(user_agent) {
            indicators.push(format!("ai_bot_detected:{}", ai_type));
            total_confidence += 0.90;
            bot_type = Some(ai_type);
        }

        if let Some(tool) = self.detect_automation_tool(user_agent, headers) {
            indicators.push(format!("automation_tool:{}", tool));
            total_confidence += 0.88;
            if bot_type.is_none() {
                bot_type = Some(tool);
            }
        }

        let ua_lower = user_agent.to_lowercase();
        for pattern in &self.known_patterns {
            for indicator in pattern.indicators {
                let lower_ind = indicator.to_lowercase();
                if ua_lower.contains(&lower_ind) {
                    indicators.push(format!("pattern_match:{}", pattern.name));
                    total_confidence += pattern.confidence * 0.5;
                    if bot_type.is_none() {
                        bot_type = Some(pattern.category.as_str().to_string());
                    }
                    break;
                }
            }
        }

        let inconsistency_score = self.detect_browser_inconsistency(user_agent, headers);
        if inconsistency_score > 0.5 {
            indicators.push("browser_inconsistency".to_string());
            total_confidence += inconsistency_score * 0.6;
        }

        let velocity_score = self.analyze_request_velocity(ip);
        if velocity_score > 0.6 {
            indicators.push("high_request_velocity".to_string());
            total_confidence += velocity_score * 0.4;
        }

        let probability = (total_confidence / (indicators.len().max(1) as f32)).min(1.0);
        let confidence = 0.5 + (indicators.len() as f32 * 0.1).min(0.5);

        if probability > 0.5 {
            let bt_str = bot_type.as_deref().unwrap_or("unknown");
            let conf_str = format!("{:.2}", confidence);
            let _ = BOT_DETECTIONS.with_label_values(&[bt_str, &conf_str]);
        }

        BotScore {
            probability,
            indicators,
            confidence,
            bot_type,
        }
    }

    pub fn is_headless_browser(&self, user_agent: &str, headers: &HashMap<String, String>) -> bool {
        let ua_lower = user_agent.to_lowercase();

        if ua_lower.contains("headless") {
            return true;
        }

        if ua_lower.contains("headlesschrome") {
            return true;
        }

        for prop in HEADLESS_NAVIGATOR_PROPERTIES {
            if ua_lower.contains(&prop.to_lowercase()) {
                return true;
            }
        }

        let accept_lang = headers
            .get("accept-language")
            .map(|s| s.as_str())
            .unwrap_or("");
        let sec_ch_ua = headers.get("sec-ch-ua").map(|s| s.as_str()).unwrap_or("");

        if !ua_lower.is_empty()
            && accept_lang.is_empty()
            && sec_ch_ua.is_empty()
            && ua_lower.contains("mozilla")
        {
            return true;
        }

        false
    }

    pub fn detect_ai_bot(&self, user_agent: &str) -> Option<String> {
        let ua_lower = user_agent.to_lowercase();

        let ai_patterns: &[(&str, &str)] = &[
            ("chatgpt-user", "ChatGPT"),
            ("gptbot", "GPTBot"),
            ("oai-searchbot", "OpenAI"),
            ("claudebot", "Claude"),
            ("claude-web", "Claude"),
            ("anthropic-ai", "Anthropic"),
            ("gemini", "Gemini"),
            ("google-extended", "Google AI"),
            ("googleother", "Google AI"),
            ("perplexitybot", "Perplexity"),
            ("copilot", "Copilot"),
            ("ccbot", "CommonCrawl"),
            ("facebookexternalhit", "Facebook"),
            ("bytespider", "ByteDance"),
            ("omgili", "Webz.io"),
            ("panscient", "Panscient"),
            ("peer39", "Peer39"),
            ("grapeshot", "Oracle Data Cloud"),
            ("semrush", "SEMrush"),
            ("ahrefsbot", "Ahrefs"),
            ("dotbot", "Moz"),
            ("rogerbot", "Moz"),
            ("petalbot", "Huawei"),
            ("mj12bot", "Majestic-12"),
        ];

        for (pattern, name) in ai_patterns {
            if ua_lower.contains(pattern) {
                return Some(name.to_string());
            }
        }

        None
    }

    pub fn detect_automation_tool(
        &self,
        user_agent: &str,
        headers: &HashMap<String, String>,
    ) -> Option<String> {
        let ua_lower = user_agent.to_lowercase();

        if ua_lower.contains("selenium") || ua_lower.contains("webdriver") {
            return Some("Selenium".to_string());
        }
        if ua_lower.contains("puppeteer") {
            return Some("Puppeteer".to_string());
        }
        if ua_lower.contains("playwright") {
            return Some("Playwright".to_string());
        }
        if ua_lower.contains("phantomjs") || ua_lower.contains("phantom") {
            return Some("PhantomJS".to_string());
        }
        if ua_lower.contains("nightmare") {
            return Some("Nightmare.js".to_string());
        }
        if ua_lower.contains("cypress") {
            return Some("Cypress".to_string());
        }
        if ua_lower.contains("electron") {
            return Some("Electron".to_string());
        }
        if ua_lower.contains("curl") || ua_lower.contains("wget") || ua_lower.contains("libwww") {
            return Some("CLI HTTP Client".to_string());
        }
        if ua_lower.contains("zgrab") || ua_lower.contains("masscan") || ua_lower.contains("nmap") {
            return Some("Network Scanner".to_string());
        }
        if ua_lower.contains("go-http-client")
            || ua_lower.contains("python-requests")
            || ua_lower.contains("python-urllib")
            || ua_lower.contains("okhttp")
        {
            return Some("Scripted HTTP Client".to_string());
        }

        let sec_ch_ua = headers.get("sec-ch-ua").map(|s| s.as_str()).unwrap_or("");
        if sec_ch_ua.contains("HeadlessChrome") {
            return Some("Headless Chrome".to_string());
        }

        None
    }

    pub fn detect_browser_inconsistency(
        &self,
        user_agent: &str,
        headers: &HashMap<String, String>,
    ) -> f32 {
        let mut score = 0.0f32;
        let ua_lower = user_agent.to_lowercase();

        let accept_lang = headers
            .get("accept-language")
            .map(|s| s.as_str())
            .unwrap_or("");
        let accept_enc = headers
            .get("accept-encoding")
            .map(|s| s.as_str())
            .unwrap_or("");
        let accept = headers.get("accept").map(|s| s.as_str()).unwrap_or("");
        let sec_fetch_site = headers
            .get("sec-fetch-site")
            .map(|s| s.as_str())
            .unwrap_or("");
        let sec_fetch_mode = headers
            .get("sec-fetch-mode")
            .map(|s| s.as_str())
            .unwrap_or("");
        let sec_fetch_dest = headers
            .get("sec-fetch-dest")
            .map(|s| s.as_str())
            .unwrap_or("");
        let sec_ch_ua = headers.get("sec-ch-ua").map(|s| s.as_str()).unwrap_or("");
        let _sec_ch_ua_platform = headers
            .get("sec-ch-ua-platform")
            .map(|s| s.as_str())
            .unwrap_or("");

        if ua_lower.contains("mozilla") && !ua_lower.contains("bot") && !ua_lower.contains("spider")
        {
            if accept_lang.is_empty() {
                score += 0.3;
            }

            if accept_enc.is_empty() {
                score += 0.15;
            }

            if accept.is_empty() {
                score += 0.1;
            }

            if ua_lower.contains("chrome")
                || ua_lower.contains("chromium")
                || ua_lower.contains("edg")
            {
                if sec_ch_ua.is_empty() {
                    score += 0.2;
                }

                if sec_fetch_site.is_empty()
                    && sec_fetch_mode.is_empty()
                    && sec_fetch_dest.is_empty()
                {
                    score += 0.25;
                }
            }

            if ua_lower.contains("firefox")
                && (accept_enc.is_empty() || !accept_enc.contains("gzip"))
            {
                score += 0.1;
            }
        }

        if !ua_lower.is_empty() && !accept_lang.is_empty() {
            let lang_parts: Vec<&str> = accept_lang.split(',').collect();
            let first_lang = lang_parts
                .first()
                .map(|s| s.split(';').next().unwrap_or(""))
                .unwrap_or("");
            let first_lang_lower = first_lang.to_lowercase();

            if ua_lower.contains("zh-cn") && !first_lang_lower.starts_with("zh") {
                score += 0.1;
            }
            if ua_lower.contains("ja") && !first_lang_lower.starts_with("ja") {
                score += 0.1;
            }
            if ua_lower.contains("ko") && !first_lang_lower.starts_with("ko") {
                score += 0.1;
            }
        }

        score.min(1.0)
    }

    pub fn analyze_request_velocity(&self, ip: &str) -> f32 {
        let mut history = self.request_history.write();
        let now = Instant::now();
        let window = Duration::from_secs(10);

        let samples = history.entry(ip.to_string()).or_default();

        samples.retain(|s| now.duration_since(s.timestamp) < window);

        samples.push(RequestSample {
            timestamp: now,
            path: String::new(),
        });

        let count = samples.len();

        if count < 3 {
            return 0.0;
        }

        if count > 100 {
            return 1.0;
        }

        let inter_arrival: Vec<f64> = samples
            .windows(2)
            .map(|w| w[1].timestamp.duration_since(w[0].timestamp).as_secs_f64())
            .collect();

        if inter_arrival.is_empty() {
            return 0.0;
        }

        let avg_interval: f64 = inter_arrival.iter().sum::<f64>() / inter_arrival.len() as f64;

        if avg_interval < 0.01 {
            return 1.0;
        }
        if avg_interval < 0.05 {
            return 0.9;
        }
        if avg_interval < 0.1 {
            return 0.7;
        }
        if avg_interval < 0.5 {
            return 0.4;
        }

        if count > 50 {
            return 0.6;
        }
        if count > 20 {
            return 0.3;
        }

        0.0
    }

    pub fn track_cookie(&self, session_id: &str, cookie_value: &str) {
        let mut registry = self.cookie_registry.write();
        let cookies = registry.entry(session_id.to_string()).or_default();
        if !cookies.contains(&cookie_value.to_string()) {
            cookies.push(cookie_value.to_string());
        }
        if cookies.len() > 50 {
            cookies.drain(0..10);
        }
    }

    pub fn validate_cookie_persistence(&self, session_id: &str, cookie_value: &str) -> bool {
        let registry = self.cookie_registry.read();
        if let Some(cookies) = registry.get(session_id) {
            cookies.contains(&cookie_value.to_string())
        } else {
            false
        }
    }
}

mod hex {
    pub fn encode(bytes: impl AsRef<[u8]>) -> String {
        let bytes = bytes.as_ref();
        let mut s = String::with_capacity(bytes.len() * 2);
        for &b in bytes {
            s.push(char::from_digit((b >> 4) as u32, 16).unwrap_or('0'));
            s.push(char::from_digit((b & 0x0f) as u32, 16).unwrap_or('0'));
        }
        s
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_detector() -> BotDetector {
        BotDetector::new(BotDetectionConfig::default())
    }

    fn test_headers() -> HashMap<String, String> {
        let mut h = HashMap::new();
        h.insert("accept-language".to_string(), "en-US,en;q=0.9".to_string());
        h.insert(
            "accept-encoding".to_string(),
            "gzip, deflate, br".to_string(),
        );
        h.insert(
            "accept".to_string(),
            "text/html,application/xhtml+xml".to_string(),
        );
        h.insert("sec-fetch-site".to_string(), "same-origin".to_string());
        h.insert("sec-fetch-mode".to_string(), "navigate".to_string());
        h.insert("sec-fetch-dest".to_string(), "document".to_string());
        h.insert(
            "sec-ch-ua".to_string(),
            "\"Google Chrome\";v=\"120\"".to_string(),
        );
        h.insert("sec-ch-ua-platform".to_string(), "\"Windows\"".to_string());
        h
    }

    #[test]
    fn test_challenge_generation() {
        let detector = test_detector();
        let challenge = detector.generate_challenge("session1", "1.2.3.4");
        assert!(!challenge.challenge_id.is_empty());
        assert!(!challenge.solution.is_empty());
        assert!(challenge.expires_at > challenge.issued_at);
    }

    #[test]
    fn test_challenge_validation_correct() {
        let detector = test_detector();
        let challenge = detector.generate_challenge("session2", "5.6.7.8");
        assert!(detector.validate_challenge(&challenge.challenge_id, &challenge.solution));
    }

    #[test]
    fn test_challenge_validation_incorrect() {
        let detector = test_detector();
        let challenge = detector.generate_challenge("session3", "9.10.11.12");
        assert!(!detector.validate_challenge(&challenge.challenge_id, "wrong_answer"));
    }

    #[test]
    fn test_ai_bot_detection_chatgpt() {
        let detector = test_detector();
        let result = detector.detect_ai_bot("Mozilla/5.0 ChatGPT-User");
        assert_eq!(result, Some("ChatGPT".to_string()));

        let result = detector.detect_ai_bot("ClaudeBot/1.0");
        assert_eq!(result, Some("Claude".to_string()));

        let result = detector.detect_ai_bot("GoogleOther");
        assert_eq!(result, Some("Google AI".to_string()));

        let result = detector.detect_ai_bot("Mozilla/5.0 Firefox/120.0");
        assert_eq!(result, None);
    }

    #[test]
    fn test_headless_detection() {
        let detector = test_detector();
        let headers = test_headers();
        assert!(detector.is_headless_browser("HeadlessChrome/120.0", &headers));
        assert!(!detector.is_headless_browser(
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0",
            &headers
        ));
    }

    #[test]
    fn test_automation_tool_detection() {
        let detector = test_detector();
        let headers = test_headers();
        assert_eq!(
            detector.detect_automation_tool("Selenium/4.0", &headers),
            Some("Selenium".to_string())
        );
        assert_eq!(
            detector.detect_automation_tool("python-requests/2.31", &headers),
            Some("Scripted HTTP Client".to_string())
        );
        assert_eq!(
            detector.detect_automation_tool("curl/8.0", &headers),
            Some("CLI HTTP Client".to_string())
        );
    }

    #[test]
    fn test_browser_inconsistency() {
        let detector = test_detector();
        let headers = test_headers();
        let score = detector.detect_browser_inconsistency("Mozilla/5.0 Chrome/120.0", &headers);
        assert!(score < 0.5);

        let weird_headers = HashMap::new();
        let score2 =
            detector.detect_browser_inconsistency("Mozilla/5.0 Chrome/120.0", &weird_headers);
        assert!(score2 > 0.3);
    }

    #[test]
    fn test_bot_score_normal_browser() {
        let detector = test_detector();
        let headers = test_headers();
        let score = detector.calculate_bot_score(
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0 Safari/537.36",
            &headers,
            "session_normal",
            "192.168.1.100",
        );
        assert!(
            score.probability < 0.5,
            "Normal browser should have low bot score, got {}",
            score.probability
        );
    }

    #[test]
    fn test_bot_score_headless() {
        let detector = test_detector();
        let headers = test_headers();
        let score = detector.calculate_bot_score(
            "HeadlessChrome/120.0",
            &headers,
            "session_headless",
            "10.0.0.1",
        );
        assert!(score.probability > 0.5);
    }

    #[test]
    fn test_request_velocity_normal() {
        let detector = test_detector();
        let score = detector.analyze_request_velocity("192.168.1.200");
        assert!(score < 0.3);
    }

    #[test]
    fn test_cookie_tracking() {
        let detector = test_detector();
        detector.track_cookie("session_a", "cookie_abc");
        assert!(detector.validate_cookie_persistence("session_a", "cookie_abc"));
        assert!(!detector.validate_cookie_persistence("session_a", "cookie_xyz"));
        assert!(!detector.validate_cookie_persistence("session_b", "cookie_abc"));
    }
}
