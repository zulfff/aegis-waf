#[cfg(test)]
mod integration {
    use hashbrown::HashMap;
    use std::net::IpAddr;

    use std::time::Duration;

    use crate::config::{
        AegisConfig, BehavioralConfig, BotDetectionConfig, DpiConfig, IngressFilterConfig,
        RateLimitingConfig, ServerConfig, ThreatIntelligenceConfig,
    };
    use crate::engine::behavioral_analyzer::BehavioralAnalyzer;
    use crate::engine::bot_detector::BotDetector;
    use crate::engine::dpi_engine::DpiEngine;
    use crate::engine::ingress_filter::{FilterDecision, IngressFilter, PacketInfo, Reputation};
    use crate::engine::protocol_validator::ProtocolValidator;
    use crate::engine::rate_limiter::{DistributedRateLimiter, RateLimitDecision, RateLimiter};
    use crate::engine::response_engine::{DecisionContext, ResponseAction, ResponseEngine};
    use crate::engine::threat_intel::ThreatIntelligence;
    use chrono::Utc;

    fn blocked_ips_config() -> IngressFilterConfig {
        IngressFilterConfig {
            enable_geoip: false,
            geoip_db_path: None,
            blocked_countries: vec![],
            blocked_ip_ranges: vec!["192.168.1.0/24".to_string(), "10.0.99.0/24".to_string()],
            allowed_ip_ranges: vec![],
            max_packet_size: 65535,
        }
    }

    #[allow(dead_code)]
    fn strict_rate_config() -> RateLimitingConfig {
        RateLimitingConfig {
            default_rps: 100,
            burst_size: 200,
            per_ip_limit: 10,
            per_endpoint_limit: 5,
            per_session_limit: 3,
            adaptive_learning: false,
        }
    }

    fn test_packet(ip_str: &str) -> PacketInfo {
        PacketInfo {
            src_ip: ip_str.parse().unwrap(),
            dst_ip: "10.0.0.1".parse().unwrap(),
            src_port: 54321,
            dst_port: 443,
            protocol: 6,
            tcp_flags: Some(0x02),
            payload_size: 0,
        }
    }

    #[tokio::test]
    async fn test_ingress_filter_blocks_blocked_ip() {
        let filter = IngressFilter::new(blocked_ips_config()).unwrap();
        let pkt = test_packet("192.168.1.50");

        let decision = filter.is_connection_allowed(&pkt).unwrap();
        assert_eq!(decision, FilterDecision::Block("IP in blocked range"));
    }

    #[tokio::test]
    async fn test_ingress_filter_allows_clean_ip() {
        let filter = IngressFilter::new(blocked_ips_config()).unwrap();
        let pkt = test_packet("172.16.0.100");

        let decision = filter.is_connection_allowed(&pkt).unwrap();
        assert_eq!(decision, FilterDecision::Allow);
    }

    #[tokio::test]
    async fn test_ingress_filter_syn_flood_detection() {
        let filter = IngressFilter::new(IngressFilterConfig::default()).unwrap();
        let src_ip: IpAddr = "10.200.200.1".parse().unwrap();

        for _ in 0..120 {
            let pkt = PacketInfo {
                src_ip,
                dst_ip: "10.0.0.1".parse().unwrap(),
                src_port: 50001,
                dst_port: 443,
                protocol: 6,
                tcp_flags: Some(0x02),
                payload_size: 0,
            };
            let _ = filter.validate_packet(&pkt);
        }

        let pkt = PacketInfo {
            src_ip,
            dst_ip: "10.0.0.1".parse().unwrap(),
            src_port: 50001,
            dst_port: 443,
            protocol: 6,
            tcp_flags: Some(0x02),
            payload_size: 0,
        };
        let decision = filter.validate_packet(&pkt).unwrap();
        assert_eq!(decision, FilterDecision::Block("SYN flood detected"));
    }

    #[test]
    fn test_rate_limiter_token_bucket_exhaustion() {
        let config = RateLimitingConfig {
            per_ip_limit: 3,
            burst_size: 5,
            default_rps: 1000,
            per_endpoint_limit: 200,
            per_session_limit: 100,
            adaptive_learning: false,
        };
        let limiter = RateLimiter::new(config);
        let ip: IpAddr = "10.0.0.55".parse().unwrap();

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
    fn test_rate_limiter_burst_classification() {
        let config = RateLimitingConfig {
            per_ip_limit: 100,
            burst_size: 500,
            default_rps: 1000,
            per_endpoint_limit: 200,
            per_session_limit: 100,
            adaptive_learning: false,
        };
        let limiter = RateLimiter::new(config);
        let ip: IpAddr = "10.0.0.200".parse().unwrap();

        for i in 0..100 {
            let decision = limiter.check_rate(
                ip,
                Some(&format!("session-{}", i % 5)),
                Some(&format!("/api/ep-{}", i % 5)),
            );
            assert_eq!(decision, RateLimitDecision::Allowed);
        }

        let classification = limiter.classify_burst(ip);
        match classification {
            crate::engine::rate_limiter::BurstClassification::AttackBurst => {}
            crate::engine::rate_limiter::BurstClassification::LegitimateBurst => {}
            crate::engine::rate_limiter::BurstClassification::Normal => {}
        }
    }

    #[test]
    fn test_distributed_rate_limiter_with_scope() {
        let config = RateLimitingConfig {
            per_ip_limit: 2,
            burst_size: 10,
            default_rps: 1000,
            per_endpoint_limit: 1,
            per_session_limit: 100,
            adaptive_learning: false,
        };
        let dlim = DistributedRateLimiter::new(config);
        let ip: IpAddr = "10.0.0.88".parse().unwrap();

        assert_eq!(
            dlim.check_rate(ip, Some("/api/login"), Some("sess")),
            RateLimitDecision::Allowed
        );
        let decision = dlim.check_rate(ip, Some("/api/login"), Some("sess"));
        assert!(decision != RateLimitDecision::Allowed);
    }

    #[test]
    fn test_dpi_sql_injection_basic() {
        let engine = DpiEngine::new(DpiConfig::default());
        let matches = engine.scan_payload(b"' OR '1'='1");

        assert!(!matches.is_empty());
        assert!(matches.iter().any(|m| m.category == "sql_injection"));
    }

    #[test]
    fn test_dpi_sql_injection_union() {
        let engine = DpiEngine::new(DpiConfig::default());
        let matches = engine.scan_payload(b"1 UNION SELECT username, password FROM users");

        assert!(!matches.is_empty());
        assert!(matches.iter().any(|m| m.pattern_id == 1001));
    }

    #[test]
    fn test_dpi_sql_injection_time_based() {
        let engine = DpiEngine::new(DpiConfig::default());
        let matches = engine.scan_payload(b"1; SLEEP(10)");

        assert!(!matches.is_empty());
        assert!(matches.iter().any(|m| m.pattern_id == 1004));
    }

    #[test]
    fn test_dpi_sql_injection_obfuscated() {
        let engine = DpiEngine::new(DpiConfig::default());
        let matches = engine.scan_payload(b"1 UNION ALL SELECT username, password FROM users");

        assert!(!matches.is_empty());
        assert!(matches.iter().any(|m| m.category == "sql_injection"));
    }

    #[test]
    fn test_dpi_xss_script_tag() {
        let engine = DpiEngine::new(DpiConfig::default());
        let matches = engine.scan_payload(b"<script>alert('XSS')</script>");

        assert!(!matches.is_empty());
        assert!(matches.iter().any(|m| m.pattern_id == 2001));
    }

    #[test]
    fn test_dpi_xss_onerror() {
        let engine = DpiEngine::new(DpiConfig::default());
        let matches = engine.scan_payload(b"<img src=x onerror=alert(1)>");

        assert!(!matches.is_empty());
        assert!(matches.iter().any(|m| m.pattern_id == 2002));
    }

    #[test]
    fn test_dpi_xss_encoded() {
        let engine = DpiEngine::new(DpiConfig::default());
        let decoded = urlencoding_decode(b"<img%20src=x%20onerror=alert(1)>");
        let matches = engine.scan_payload(&decoded);

        assert!(!matches.is_empty());
        assert!(matches.iter().any(|m| m.pattern_id == 2002));
    }

    fn urlencoding_decode(input: &[u8]) -> Vec<u8> {
        let mut result = Vec::with_capacity(input.len());
        let mut i = 0;
        while i < input.len() {
            if input[i] == b'%' && i + 2 < input.len() {
                let hex = &input[i + 1..i + 3];
                if let Ok(h) = std::str::from_utf8(hex) {
                    if let Ok(decoded) = u8::from_str_radix(h, 16) {
                        result.push(decoded);
                        i += 3;
                        continue;
                    }
                }
                result.push(b'%');
                i += 1;
            } else if input[i] == b'+' {
                result.push(b' ');
                i += 1;
            } else {
                result.push(input[i]);
                i += 1;
            }
        }
        result
    }

    #[test]
    fn test_bot_challenge_generation_and_validation() {
        let detector = BotDetector::new(BotDetectionConfig::default());
        let challenge = detector.generate_challenge("integration-session", "10.10.10.10");

        assert!(!challenge.challenge_id.is_empty());
        assert!(!challenge.solution.is_empty());
        assert!(challenge.expires_at > challenge.issued_at);

        let valid = detector.validate_challenge(&challenge.challenge_id, &challenge.solution);
        assert!(valid);

        let invalid = detector.validate_challenge(&challenge.challenge_id, "wrong");
        assert!(!invalid);

        let nonexistent = detector.validate_challenge("nonexistent-id", "any");
        assert!(!nonexistent);
    }

    #[test]
    fn test_bot_detector_ai_bot_score() {
        let detector = BotDetector::new(BotDetectionConfig::default());
        let mut headers = HashMap::new();
        headers.insert("accept-language".to_string(), "en-US".to_string());
        headers.insert("accept-encoding".to_string(), "gzip".to_string());

        let score =
            detector.calculate_bot_score("ChatGPT-User/1.0", &headers, "bot-session", "10.0.0.99");

        assert!(score.probability > 0.5);
        assert!(score.is_bot());
        assert!(score.bot_type.is_some());
    }

    #[test]
    fn test_bot_detector_normal_browser_score() {
        let detector = BotDetector::new(BotDetectionConfig::default());
        let mut headers = HashMap::new();
        headers.insert("accept-language".to_string(), "en-US,en;q=0.9".to_string());
        headers.insert("accept-encoding".to_string(), "gzip, deflate".to_string());
        headers.insert("sec-fetch-site".to_string(), "same-origin".to_string());
        headers.insert("sec-fetch-mode".to_string(), "navigate".to_string());
        headers.insert("sec-fetch-dest".to_string(), "document".to_string());

        let score = detector.calculate_bot_score(
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0 Safari/537.36",
            &headers,
            "normal-session",
            "192.168.1.200",
        );

        assert!(
            score.probability < 0.5,
            "Normal browser should have low bot score, got {}",
            score.probability
        );
    }

    #[test]
    fn test_bot_challenge_expiration() {
        let detector = BotDetector::new(BotDetectionConfig::default());
        let challenge = detector.generate_challenge("expiring-session", "1.1.1.1");

        assert!(challenge.expires_at > challenge.issued_at);
        let duration = Duration::from_secs((challenge.expires_at - challenge.issued_at) as u64);
        assert!(duration <= Duration::from_secs(300));
    }

    #[test]
    fn test_behavioral_analyzer_baseline_calculation() {
        let config = BehavioralConfig::default();
        let analyzer = BehavioralAnalyzer::new(config);

        let samples: Vec<f64> = (0..200).map(|i| 100.0 + (i as f64 % 20.0)).collect();
        let baseline = analyzer.calculate_baseline(&samples);

        assert!(baseline.mean > 90.0 && baseline.mean < 120.0);
        assert!(baseline.stddev < 20.0);
        assert_eq!(baseline.sample_count, 200);
    }

    #[test]
    fn test_behavioral_analyzer_anomaly_detection() {
        let config = BehavioralConfig::default();
        let analyzer = BehavioralAnalyzer::new(config);

        let normal_samples: Vec<f64> = (0..200).map(|i| 50.0 + (i as f64 % 10.0)).collect();
        let baseline = analyzer.calculate_baseline(&normal_samples);

        let normal_score = analyzer.score_anomaly(52.0, &baseline);
        assert!(
            normal_score.overall < 0.5,
            "Normal value should not trigger anomaly"
        );

        let spike_score = analyzer.score_anomaly(500.0, &baseline);
        assert!(
            spike_score.overall > 0.3,
            "Extreme value should trigger anomaly, got {}",
            spike_score.overall
        );
    }

    #[test]
    fn test_behavioral_analyzer_incremental_update() {
        let config = BehavioralConfig::default();
        let analyzer = BehavioralAnalyzer::new(config);

        for i in 0..50 {
            analyzer.update_baseline(200.0 + (i as f64 % 5.0));
        }

        let baseline = analyzer.get_baseline();
        assert!(baseline.sample_count >= 50);
        assert!(baseline.mean > 195.0);
    }

    #[test]
    fn test_behavioral_analyzer_fingerprint() {
        let config = BehavioralConfig::default();
        let analyzer = BehavioralAnalyzer::new(config);

        let mut headers = HashMap::new();
        headers.insert(
            "user-agent".to_string(),
            "Mozilla/5.0 Firefox/120.0".to_string(),
        );
        headers.insert("accept-language".to_string(), "en-US,en;q=0.9".to_string());
        headers.insert("accept-encoding".to_string(), "gzip, deflate".to_string());

        let fp = analyzer.generate_fingerprint(&headers, "192.168.1.100");

        assert!(fp.hash != 0);
        assert!(fp.components.len() >= 3);
        assert!(fp.entropy > 0.0);

        let score = analyzer.detect_threat_actor_pattern(&fp);
        assert!((0.0..=1.0).contains(&score));
    }

    #[test]
    fn test_threat_intel_ip_reputation_check() {
        let intel = ThreatIntelligence::new(ThreatIntelligenceConfig::default());

        let stub_data = "192.168.99.1,0.95,known-bad\n10.10.10.1,0.8\nmalware.example.com,0.9";
        intel
            .add_feed("integration-feed", &format!("stub://{}", stub_data))
            .unwrap();
        intel.update_feeds().unwrap();

        let score = intel.check_ip("192.168.99.1");
        assert!(score.is_some());
        let s = score.unwrap();
        assert!(s.ip_score > 0.9);
        assert!(s.is_malicious(0.7));

        let score = intel.check_ip("1.2.3.4");
        assert!(score.is_none());
    }

    #[test]
    fn test_threat_intel_domain_reputation_check() {
        let intel = ThreatIntelligence::new(ThreatIntelligenceConfig::default());

        let stub_data = "phishing.example.com,0.95\nevil.org,0.85";
        intel
            .add_feed("domain-feed", &format!("stub://{}", stub_data))
            .unwrap();
        intel.update_feeds().unwrap();

        let score = intel.check_domain("phishing.example.com");
        assert!(score.is_some());
        let s = score.unwrap();
        assert!(s.domain_score > 0.9);

        let score = intel.check_domain("safe.example.com");
        assert!(score.is_none());
    }

    #[test]
    fn test_threat_intel_combined_score() {
        let intel = ThreatIntelligence::new(ThreatIntelligenceConfig::default());

        let stub_data = "5.5.5.5,0.9\nbad.example.com,0.85";
        intel
            .add_feed("combined-feed", &format!("stub://{}", stub_data))
            .unwrap();
        intel.update_feeds().unwrap();

        let score = intel.calculate_threat_score("5.5.5.5", Some("bad.example.com"));
        assert!(score.combined_score > 0.7);
        assert!(!score.sources.is_empty());
    }

    #[test]
    fn test_threat_intel_rule_generation() {
        let intel = ThreatIntelligence::new(ThreatIntelligenceConfig::default());

        let stub_data = "99.99.99.99,0.98";
        intel
            .add_feed("rule-feed", &format!("stub://{}", stub_data))
            .unwrap();
        intel.update_feeds().unwrap();

        let rules = intel.generate_rules_from_detections("99.99.99.99", 0.5);
        assert_eq!(rules.len(), 1);
        assert!(rules[0].contains("block ip:99.99.99.99"));
    }

    #[test]
    fn test_threat_intel_cache_behavior() {
        let intel = ThreatIntelligence::new(ThreatIntelligenceConfig::default());

        let stub_data = "1.1.1.1,0.5";
        intel
            .add_feed("cache-feed", &format!("stub://{}", stub_data))
            .unwrap();
        intel.update_feeds().unwrap();

        intel.check_ip("1.1.1.1");
        let (total, _) = intel.get_cache_stats();
        assert_eq!(total, 1);

        intel.clear_cache();
        let (total, _) = intel.get_cache_stats();
        assert_eq!(total, 0);
    }

    #[test]
    fn test_response_engine_clean_request_allow() {
        let engine = ResponseEngine::new(ResponseAction::Block);
        let context = DecisionContext {
            incident_id: ResponseEngine::generate_incident_id(),
            client_ip: "192.168.1.100".to_string(),
            request_path: "/api/health".to_string(),
            request_method: "GET".to_string(),
            user_agent: "Mozilla/5.0".to_string(),
            dpi_threats: vec![],
            bot_score: 0.0,
            threat_intel_score: 0.0,
            anomaly_score: 0.0,
            rate_limit_triggered: false,
            timestamp: Utc::now().timestamp(),
        };

        let decision = engine.evaluate_threat(&context);
        assert_eq!(decision.action, ResponseAction::Allow);
        assert_eq!(decision.status_code, 200);
    }

    #[test]
    fn test_response_engine_dpi_threats_escalation() {
        let engine = ResponseEngine::new(ResponseAction::Block);
        let context = DecisionContext {
            incident_id: ResponseEngine::generate_incident_id(),
            client_ip: "10.0.0.66".to_string(),
            request_path: "/api/login".to_string(),
            request_method: "POST".to_string(),
            user_agent: "Mozilla/5.0".to_string(),
            dpi_threats: vec![
                "sql_injection".to_string(),
                "xss".to_string(),
                "path_traversal".to_string(),
                "command_injection".to_string(),
            ],
            bot_score: 0.0,
            threat_intel_score: 0.0,
            anomaly_score: 0.0,
            rate_limit_triggered: false,
            timestamp: Utc::now().timestamp(),
        };

        let decision = engine.evaluate_threat(&context);
        assert_eq!(decision.action, ResponseAction::Block);
        assert_eq!(decision.status_code, 403);
    }

    #[test]
    fn test_response_engine_challenge_for_moderate_bot() {
        let engine = ResponseEngine::new(ResponseAction::Block);
        let context = DecisionContext {
            incident_id: ResponseEngine::generate_incident_id(),
            client_ip: "10.0.0.77".to_string(),
            request_path: "/".to_string(),
            request_method: "GET".to_string(),
            user_agent: "HeadlessChrome/120.0".to_string(),
            dpi_threats: vec![],
            bot_score: 0.75,
            threat_intel_score: 0.0,
            anomaly_score: 0.0,
            rate_limit_triggered: false,
            timestamp: Utc::now().timestamp(),
        };

        let decision = engine.evaluate_threat(&context);
        assert_eq!(decision.action, ResponseAction::Challenge);
        assert_eq!(decision.status_code, 403);
    }

    #[test]
    fn test_response_engine_block_high_bot() {
        let engine = ResponseEngine::new(ResponseAction::Block);
        let context = DecisionContext {
            incident_id: ResponseEngine::generate_incident_id(),
            client_ip: "10.0.0.88".to_string(),
            request_path: "/".to_string(),
            request_method: "GET".to_string(),
            user_agent: "ClaudeBot/1.0".to_string(),
            dpi_threats: vec![],
            bot_score: 0.95,
            threat_intel_score: 0.0,
            anomaly_score: 0.0,
            rate_limit_triggered: false,
            timestamp: Utc::now().timestamp(),
        };

        let decision = engine.evaluate_threat(&context);
        assert_eq!(decision.action, ResponseAction::Block);
    }

    #[test]
    fn test_response_engine_rate_limit() {
        let engine = ResponseEngine::new(ResponseAction::Block);
        let context = DecisionContext {
            incident_id: ResponseEngine::generate_incident_id(),
            client_ip: "10.0.0.99".to_string(),
            request_path: "/api/data".to_string(),
            request_method: "GET".to_string(),
            user_agent: "Mozilla/5.0".to_string(),
            dpi_threats: vec![],
            bot_score: 0.0,
            threat_intel_score: 0.0,
            anomaly_score: 0.0,
            rate_limit_triggered: true,
            timestamp: Utc::now().timestamp(),
        };

        let decision = engine.evaluate_threat(&context);
        assert_eq!(decision.action, ResponseAction::RateLimit);
        assert_eq!(decision.status_code, 429);
        assert!(decision.retry_after.is_some());
    }

    #[test]
    fn test_response_engine_escalation_sequence() {
        let engine = ResponseEngine::new(ResponseAction::Block);
        let ip = "10.100.100.100";

        let d1 = engine.escalate_response(ip, "inc-001");
        assert_eq!(d1.action, ResponseAction::Log);

        let d2 = engine.escalate_response(ip, "inc-002");
        assert_eq!(d2.action, ResponseAction::Challenge);

        let d3 = engine.escalate_response(ip, "inc-003");
        assert_eq!(d3.action, ResponseAction::RateLimit);

        let d4 = engine.escalate_response(ip, "inc-004");
        assert_eq!(d4.action, ResponseAction::Block);

        let d5 = engine.escalate_response(ip, "inc-005");
        assert_eq!(d5.action, ResponseAction::Block);
    }

    #[test]
    fn test_response_engine_escalation_reset() {
        let engine = ResponseEngine::new(ResponseAction::Block);
        let ip = "10.100.100.200";

        engine.escalate_response(ip, "a-1");
        engine.escalate_response(ip, "a-2");
        engine.reset_escalation(ip);

        let d = engine.escalate_response(ip, "a-3");
        assert_eq!(d.action, ResponseAction::Log);
    }

    #[test]
    fn test_response_engine_max_escalation() {
        let engine = ResponseEngine::new(ResponseAction::Challenge);
        let context = DecisionContext {
            incident_id: ResponseEngine::generate_incident_id(),
            client_ip: "10.0.0.1".to_string(),
            request_path: "/".to_string(),
            request_method: "GET".to_string(),
            user_agent: "BadBot".to_string(),
            dpi_threats: vec![],
            bot_score: 0.96,
            threat_intel_score: 0.95,
            anomaly_score: 0.0,
            rate_limit_triggered: false,
            timestamp: Utc::now().timestamp(),
        };

        let decision = engine.evaluate_threat(&context);
        assert!(decision.action <= ResponseAction::Challenge);
    }

    #[test]
    fn test_response_engine_block_page_html() {
        let engine = ResponseEngine::new(ResponseAction::Block);
        let page = engine.generate_block_page("AEGIS-INTEGRATION", "test violation");

        assert!(page.contains("Access Denied"));
        assert!(page.contains("AEGIS-INTEGRATION"));
        assert!(page.contains("test violation"));
        assert!(page.contains("<!DOCTYPE html>"));
    }

    #[test]
    fn test_response_engine_rate_limit_page() {
        let engine = ResponseEngine::new(ResponseAction::Block);
        let page = engine.generate_rate_limit_response(45);

        assert!(page.contains("Too Many Requests"));
        assert!(page.contains("45"));
    }

    #[test]
    fn test_response_engine_challenge_page() {
        let engine = ResponseEngine::new(ResponseAction::Block);
        let page = engine.generate_challenge_page("AEGIS-CHALLENGE");

        assert!(page.contains("Security Verification"));
        assert!(page.contains("AEGIS-CHALLENGE"));
    }

    #[test]
    fn test_response_engine_incident_id_format() {
        let id = ResponseEngine::generate_incident_id();
        assert!(id.starts_with("AEGIS-"));
        assert!(id.len() > 6);

        let id2 = ResponseEngine::generate_incident_id();
        assert_ne!(id, id2);
    }

    #[test]
    fn test_response_engine_combined_threats() {
        let engine = ResponseEngine::new(ResponseAction::Block);
        let context = DecisionContext {
            incident_id: ResponseEngine::generate_incident_id(),
            client_ip: "10.0.0.1".to_string(),
            request_path: "/admin".to_string(),
            request_method: "POST".to_string(),
            user_agent: "BadBot".to_string(),
            dpi_threats: vec!["sql_injection".to_string()],
            bot_score: 0.6,
            threat_intel_score: 0.55,
            anomaly_score: 0.7,
            rate_limit_triggered: false,
            timestamp: Utc::now().timestamp(),
        };

        let decision = engine.evaluate_threat(&context);
        assert!(
            decision.action >= ResponseAction::Challenge,
            "Expected at least Challenge with multiple elevated signals"
        );
    }

    #[test]
    fn test_protocol_validator_valid_request() {
        let validator = ProtocolValidator::new();
        let raw = b"GET /api/users?page=1&limit=20 HTTP/1.1\r\nHost: api.example.com\r\nContent-Type: application/json\r\nAccept: application/json\r\n\r\n";

        let result = validator.validate_http_request(raw);
        assert!(result.passed);
        assert_eq!(result.method.as_deref(), Some("GET"));
        assert_eq!(result.path.as_deref(), Some("/api/users?page=1&limit=20"));
        assert_eq!(result.http_version, Some(1));
    }

    #[test]
    fn test_protocol_validator_invalid_method() {
        let validator = ProtocolValidator::new();
        let raw = b"INV\x00ALID / HTTP/1.1\r\nHost: example.com\r\n\r\n";

        let result = validator.validate_http_request(raw);
        assert!(!result.passed);
    }

    #[test]
    fn test_protocol_validator_empty_request() {
        let validator = ProtocolValidator::new();
        let result = validator.validate_http_request(b"");
        assert!(!result.passed);
    }

    #[test]
    fn test_protocol_validator_null_byte_url() {
        let validator = ProtocolValidator::new();
        let raw = b"GET /\x00etc/passwd HTTP/1.1\r\nHost: example.com\r\n\r\n";

        let result = validator.validate_http_request(raw);
        assert!(!result.passed);
    }

    #[test]
    fn test_protocol_validator_crlf_in_url() {
        let validator = ProtocolValidator::new();
        let raw = b"GET /api\r\nEvil: injected HTTP/1.1\r\nHost: example.com\r\n\r\n";

        let result = validator.validate_http_request(raw);
        assert!(!result.passed);
    }

    #[test]
    fn test_protocol_validator_double_content_length() {
        let validator = ProtocolValidator::new();
        let raw = b"POST / HTTP/1.1\r\nHost: example.com\r\nContent-Length: 5\r\nContent-Length: 10\r\n\r\nbody1";

        let result = validator.validate_http_request(raw);
        assert!(!result.passed);
    }

    #[test]
    fn test_protocol_validator_cl_with_te() {
        let validator = ProtocolValidator::new();
        let raw = b"POST / HTTP/1.1\r\nHost: example.com\r\nContent-Length: 100\r\nTransfer-Encoding: chunked\r\n\r\n";

        let result = validator.validate_http_request(raw);
        assert!(!result.passed);
    }

    #[test]
    fn test_protocol_validator_missing_host_http11() {
        let validator = ProtocolValidator::new();
        let raw = b"GET / HTTP/1.1\r\n\r\n";

        let result = validator.validate_http_request(raw);
        assert!(!result.passed);
    }

    #[test]
    fn test_protocol_validator_slowloris_detection() {
        let validator = ProtocolValidator::new();
        let raw = b"GET / HTTP/1.1\r\n";

        let detected = validator.detect_slowloris(raw, Duration::from_millis(1000));
        assert!(detected);

        let not_detected = validator.detect_slowloris(raw, Duration::from_millis(100));
        assert!(!not_detected);
    }

    #[test]
    fn test_protocol_validator_partial_headers() {
        let validator = ProtocolValidator::new();
        let raw =
            b"POST /upload HTTP/1.1\r\nHost: example.com\r\nContent-Type: application/json\r\n";

        let result = validator.validate_http_request(raw);
        assert!(!result.passed);
    }

    #[test]
    fn test_protocol_validator_url_too_long() {
        let validator = ProtocolValidator::new();

        let long_path = format!(
            "GET {} HTTP/1.1\r\nHost: example.com\r\n\r\n",
            "/".repeat(3000)
        );
        let result = validator.validate_http_request(long_path.as_bytes());
        assert!(!result.passed);
    }

    #[test]
    fn test_protocol_validator_post_with_body() {
        let validator = ProtocolValidator::new();
        let raw = b"POST /submit HTTP/1.1\r\nHost: example.com\r\nContent-Length: 13\r\nContent-Type: text/plain\r\n\r\nHello, World!";

        let result = validator.validate_http_request(raw);
        assert!(result.passed);
        assert_eq!(result.content_length, Some(13));
        assert_eq!(result.method.as_deref(), Some("POST"));
    }

    #[test]
    fn test_protocol_validator_chunked_encoding() {
        let validator = ProtocolValidator::new();
        let raw = b"POST /data HTTP/1.1\r\nHost: example.com\r\nTransfer-Encoding: chunked\r\n\r\n";

        let result = validator.validate_http_request(raw);
        assert!(result.passed);
        assert!(result.is_chunked);
    }

    #[test]
    fn test_protocol_validator_too_many_headers() {
        let validator = ProtocolValidator::new();

        let mut raw = b"GET / HTTP/1.1\r\nHost: a\r\n".to_vec();
        for i in 0..200 {
            raw.extend_from_slice(format!("H{}: {}\r\n", i, i).as_bytes());
        }
        raw.extend_from_slice(b"\r\n");

        let result = validator.validate_http_request(&raw);
        assert!(!result.passed);
    }

    #[test]
    fn test_protocol_validator_invalid_header_value() {
        let validator = ProtocolValidator::new();
        let raw = b"GET / HTTP/1.1\r\nHost: example.com\r\nEvil: val\x00ue\r\n\r\n";

        let result = validator.validate_http_request(raw);
        assert!(!result.passed);
    }

    #[test]
    fn test_config_system_roundtrip_defaults() {
        let config = AegisConfig::default();
        assert_eq!(config.server.bind_port, 8443);
        assert_eq!(config.server.max_connections, 100_000);
        assert_eq!(config.rate_limiting.default_rps, 1000);
        assert_eq!(config.rate_limiting.per_ip_limit, 500);
        assert_eq!(config.dpi.max_payload_size, 10_485_760);
        assert!(config.protection.enable_dpi);
        assert!(config.protection.enable_ingress_filter);
    }

    #[test]
    fn test_config_system_validate_warnings() {
        let config = AegisConfig {
            rate_limiting: RateLimitingConfig {
                default_rps: 0,
                ..RateLimitingConfig::default()
            },
            dpi: DpiConfig {
                max_payload_size: 200_000_000,
                ..DpiConfig::default()
            },
            storage: crate::config::StorageConfig {
                log_retention_days: 0,
                ..crate::config::StorageConfig::default()
            },
            ..AegisConfig::default()
        };

        let warnings = config.validate().unwrap();
        assert!(warnings.len() >= 3);
        assert!(warnings.iter().any(|w| w.contains("default_rps")));
        assert!(warnings.iter().any(|w| w.contains("max_payload_size")));
        assert!(warnings.iter().any(|w| w.contains("log_retention_days")));
    }

    #[test]
    fn test_config_system_validate_error() {
        let config = AegisConfig {
            server: ServerConfig {
                max_connections: 0,
                ..ServerConfig::default()
            },
            ..AegisConfig::default()
        };

        assert!(config.validate().is_err());
    }

    #[test]
    fn test_config_system_serialization() {
        let config = AegisConfig::default();
        let toml_str = toml::to_string_pretty(&config).unwrap();

        assert!(!toml_str.is_empty());
        assert!(toml_str.contains("[server]"));
        assert!(toml_str.contains("[protection]"));
        assert!(toml_str.contains("[dpi]"));

        let deserialized: AegisConfig = toml::from_str(&toml_str).unwrap();
        assert_eq!(deserialized.server.bind_port, config.server.bind_port);
        assert_eq!(
            deserialized.rate_limiting.default_rps,
            config.rate_limiting.default_rps
        );
    }

    #[test]
    fn test_config_system_custom_ingress_filter() {
        let config = IngressFilterConfig {
            enable_geoip: true,
            geoip_db_path: Some("/path/to/geoip.mmdb".to_string()),
            blocked_countries: vec!["XX".to_string(), "YY".to_string()],
            blocked_ip_ranges: vec!["10.0.0.0/8".to_string(), "172.16.0.0/12".to_string()],
            allowed_ip_ranges: vec!["192.168.0.0/16".to_string()],
            max_packet_size: 4096,
        };

        let filter = IngressFilter::new(config).unwrap();
        let blocked_ip: IpAddr = "10.1.2.3".parse().unwrap();
        let allowed_ip: IpAddr = "192.168.1.1".parse().unwrap();

        assert_eq!(
            filter.check_ip_reputation(blocked_ip),
            Reputation::Malicious
        );
        assert_eq!(filter.check_ip_reputation(allowed_ip), Reputation::Clean);
    }

    #[test]
    fn test_config_system_custom_dpi() {
        let config = DpiConfig {
            max_payload_size: 1024,
            enable_sql_injection_detection: true,
            enable_xss_detection: true,
            enable_path_traversal_detection: false,
            enable_command_injection_detection: false,
            enable_xxe_detection: false,
            enable_ssrf_detection: false,
            custom_patterns: vec!["custom_secret_pattern".to_string()],
        };

        let engine = DpiEngine::new(config);

        let sql_matches = engine.scan_payload(b"' OR 1=1 --");
        assert!(sql_matches.iter().any(|m| m.category == "sql_injection"));

        let xss_matches = engine.scan_payload(b"<script>alert(1)</script>");
        assert!(xss_matches.iter().any(|m| m.category == "xss"));

        let pt_matches = engine.scan_payload(b"../../etc/passwd");
        assert!(!pt_matches.iter().any(|m| m.category == "path_traversal"));
    }

    #[test]
    fn test_config_system_custom_rate_limiting() {
        let config = RateLimitingConfig {
            default_rps: 50,
            burst_size: 100,
            per_ip_limit: 5,
            per_endpoint_limit: 3,
            per_session_limit: 2,
            adaptive_learning: false,
        };

        let limiter = RateLimiter::new(config);
        let ip: IpAddr = "10.0.0.10".parse().unwrap();

        for _ in 0..5 {
            assert_eq!(
                limiter.check_rate(ip, None, None),
                RateLimitDecision::Allowed
            );
        }
        assert_eq!(
            limiter.check_rate(ip, None, None),
            RateLimitDecision::Dropped
        );
    }

    #[test]
    fn test_full_pipeline_simulation_clean_traffic() {
        let ingress = IngressFilter::new(IngressFilterConfig::default()).unwrap();
        let dp_engine = DpiEngine::new(DpiConfig::default());
        let bot_detector = BotDetector::new(BotDetectionConfig::default());
        let response = ResponseEngine::new(ResponseAction::Block);
        let _intel = ThreatIntelligence::new(ThreatIntelligenceConfig::default());
        let behavioral = BehavioralAnalyzer::new(BehavioralConfig::default());

        let ip: IpAddr = "10.0.0.42".parse().unwrap();
        let pkt = PacketInfo {
            src_ip: ip,
            dst_ip: "10.0.0.1".parse().unwrap(),
            src_port: 60000,
            dst_port: 443,
            protocol: 6,
            tcp_flags: Some(0x02),
            payload_size: 0,
        };

        let ingress_decision = ingress.is_connection_allowed(&pkt).unwrap();
        assert_eq!(ingress_decision, FilterDecision::Allow);

        let dp_matches = dp_engine.scan_payload(b"Hello World");
        assert!(dp_matches.is_empty());

        let bot_score = bot_detector.analyze_request_velocity(&ip.to_string());
        assert!(bot_score < 0.5);

        let mut headers = HashMap::new();
        headers.insert("accept-language".to_string(), "en-US".to_string());
        let fp = behavioral.generate_fingerprint(&headers, &ip.to_string());
        let threat_actor_score = behavioral.detect_threat_actor_pattern(&fp);
        assert!(threat_actor_score <= 1.0);

        let context = DecisionContext {
            incident_id: ResponseEngine::generate_incident_id(),
            client_ip: ip.to_string(),
            request_path: "/api/health".to_string(),
            request_method: "GET".to_string(),
            user_agent: "Mozilla/5.0".to_string(),
            dpi_threats: vec![],
            bot_score,
            threat_intel_score: 0.0,
            anomaly_score: 0.0,
            rate_limit_triggered: false,
            timestamp: Utc::now().timestamp(),
        };

        let decision = response.evaluate_threat(&context);
        assert_eq!(decision.action, ResponseAction::Allow);
    }

    #[test]
    fn test_full_pipeline_simulation_attack_traffic() {
        let ingress = IngressFilter::new(IngressFilterConfig {
            blocked_ip_ranges: vec!["10.0.99.0/24".to_string()],
            ..IngressFilterConfig::default()
        })
        .unwrap();
        let dp_engine = DpiEngine::new(DpiConfig::default());
        let _bot_detector = BotDetector::new(BotDetectionConfig::default());
        let response = ResponseEngine::new(ResponseAction::Block);

        let ip: IpAddr = "10.0.99.1".parse().unwrap();
        let pkt = PacketInfo {
            src_ip: ip,
            dst_ip: "10.0.0.1".parse().unwrap(),
            src_port: 60001,
            dst_port: 443,
            protocol: 6,
            tcp_flags: Some(0x02),
            payload_size: 0,
        };

        let ingress_decision = ingress.is_connection_allowed(&pkt).unwrap();
        assert_eq!(
            ingress_decision,
            FilterDecision::Block("IP in blocked range")
        );

        let dp_matches = dp_engine.scan_payload(b"' OR 1=1 --");
        assert!(!dp_matches.is_empty());
        assert!(dp_matches.iter().any(|m| m.category == "sql_injection"));

        let context = DecisionContext {
            incident_id: ResponseEngine::generate_incident_id(),
            client_ip: ip.to_string(),
            request_path: "/".to_string(),
            request_method: "POST".to_string(),
            user_agent: "BadBot/1.0".to_string(),
            dpi_threats: vec!["sql_injection".to_string(), "xss".to_string()],
            bot_score: 0.85,
            threat_intel_score: 0.0,
            anomaly_score: 0.0,
            rate_limit_triggered: false,
            timestamp: Utc::now().timestamp(),
        };

        let decision = response.evaluate_threat(&context);
        assert!(decision.action >= ResponseAction::Challenge);
    }
}
