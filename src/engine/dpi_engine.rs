use crate::config::DpiConfig;
use crate::metrics::DPI_VIOLATIONS;
use once_cell::sync::Lazy;
use regex::Regex;

use std::collections::HashMap;

#[derive(Debug, Clone, PartialEq)]
pub struct SignatureMatch {
    pub pattern_id: u32,
    pub confidence: f32,
    pub category: String,
    pub matched_content: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AttackCategory {
    SqlInjection,
    Xss,
    PathTraversal,
    CommandInjection,
    Xxe,
    Ssrf,
}

impl AttackCategory {
    fn as_str(&self) -> &'static str {
        match self {
            AttackCategory::SqlInjection => "sql_injection",
            AttackCategory::Xss => "xss",
            AttackCategory::PathTraversal => "path_traversal",
            AttackCategory::CommandInjection => "command_injection",
            AttackCategory::Xxe => "xxe",
            AttackCategory::Ssrf => "ssrf",
        }
    }
}

struct CompiledPattern {
    regex: Regex,
    pattern_id: u32,
    confidence: f32,
    category: AttackCategory,
    description: &'static str,
}

impl std::fmt::Debug for CompiledPattern {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CompiledPattern")
            .field("pattern_id", &self.pattern_id)
            .field("confidence", &self.confidence)
            .field("category", &self.category)
            .field("description", &self.description)
            .finish()
    }
}

static SQL_PATTERNS: Lazy<Vec<CompiledPattern>> = Lazy::new(|| {
    vec![
        CompiledPattern {
            regex: Regex::new(r"(?i)\bUNION\s+(?:ALL\s+)?SELECT\b").expect("invalid regex"),
            pattern_id: 1001,
            confidence: 0.95,
            category: AttackCategory::SqlInjection,
            description: "UNION SELECT injection",
        },
        CompiledPattern {
            regex: Regex::new(r"(?i)\bDROP\s+TABLE\b").expect("invalid regex"),
            pattern_id: 1002,
            confidence: 0.90,
            category: AttackCategory::SqlInjection,
            description: "DROP TABLE injection",
        },
        CompiledPattern {
            regex: Regex::new(r"(?i)\bINSERT\s+INTO\b").expect("invalid regex"),
            pattern_id: 1003,
            confidence: 0.85,
            category: AttackCategory::SqlInjection,
            description: "INSERT INTO injection",
        },
        CompiledPattern {
            regex: Regex::new(r"(?i)\bSLEEP\s*\(\s*\d+\s*\)").expect("invalid regex"),
            pattern_id: 1004,
            confidence: 0.92,
            category: AttackCategory::SqlInjection,
            description: "SLEEP() timing injection",
        },
        CompiledPattern {
            regex: Regex::new(r"(?i)\bBENCHMARK\s*\(\s*\d+\s*,").expect("invalid regex"),
            pattern_id: 1005,
            confidence: 0.92,
            category: AttackCategory::SqlInjection,
            description: "BENCHMARK() timing injection",
        },
        CompiledPattern {
            regex: Regex::new(r"(?i)information_schema\b").expect("invalid regex"),
            pattern_id: 1006,
            confidence: 0.88,
            category: AttackCategory::SqlInjection,
            description: "information_schema access",
        },
        CompiledPattern {
            regex: Regex::new(r"(?i)(?:0x[0-9a-fA-F]+|\\x[0-9a-fA-F]{2})+").expect("invalid regex"),
            pattern_id: 1007,
            confidence: 0.78,
            category: AttackCategory::SqlInjection,
            description: "Hex-encoded SQL payload",
        },
        CompiledPattern {
            regex: Regex::new(r#"(?i)(?:'|")\s*(?:OR|AND)\s+(?:'|")?\s*(?:\d+|'[^']*')\s*=\s*(?:'|")?\s*(?:\d+|'[^']*')"#).expect("invalid regex"),
            pattern_id: 1008,
            confidence: 0.93,
            category: AttackCategory::SqlInjection,
            description: "OR/AND tautology injection",
        },
        CompiledPattern {
            regex: Regex::new(r"(?i)/\*!?\s*(?:SELECT|UNION|INSERT|UPDATE|DELETE|DROP)\b").expect("invalid regex"),
            pattern_id: 1009,
            confidence: 0.91,
            category: AttackCategory::SqlInjection,
            description: "MySQL comment-obfuscated injection",
        },
        CompiledPattern {
            regex: Regex::new(r"(?i)\b(?:EXEC|EXECUTE)\s*(?:\(|sp_|xp_)\w+").expect("invalid regex"),
            pattern_id: 1010,
            confidence: 0.94,
            category: AttackCategory::SqlInjection,
            description: "Stored procedure execution",
        },
        CompiledPattern {
            regex: Regex::new(r"(?i)SELECT\s+.*\bFROM\b.*\bWHERE\b").expect("invalid regex"),
            pattern_id: 1011,
            confidence: 0.70,
            category: AttackCategory::SqlInjection,
            description: "Generic SELECT statement in payload",
        },
        CompiledPattern {
            regex: Regex::new(r"(?i)\bLOAD_FILE\s*\(|INTO\s+(?:OUT|DUMP)FILE\b").expect("invalid regex"),
            pattern_id: 1012,
            confidence: 0.93,
            category: AttackCategory::SqlInjection,
            description: "File read/write via SQL injection",
        },
        CompiledPattern {
            regex: Regex::new(r"(?i)\bCAST\s*\(|CONVERT\s*\(.*\b(?:CHAR|INT|DECIMAL)\b").expect("invalid regex"),
            pattern_id: 1013,
            confidence: 0.75,
            category: AttackCategory::SqlInjection,
            description: "Type conversion in SQL injection",
        },
    ]
});

static XSS_PATTERNS: Lazy<Vec<CompiledPattern>> = Lazy::new(|| {
    vec![
        CompiledPattern {
            regex: Regex::new(r"(?i)<\s*script[^>]*>").expect("invalid regex"),
            pattern_id: 2001,
            confidence: 0.96,
            category: AttackCategory::Xss,
            description: "Script tag injection",
        },
        CompiledPattern {
            regex: Regex::new(r"(?i)\bonerror\s*=").expect("invalid regex"),
            pattern_id: 2002,
            confidence: 0.95,
            category: AttackCategory::Xss,
            description: "onerror event handler",
        },
        CompiledPattern {
            regex: Regex::new(r"(?i)\bonload\s*=").expect("invalid regex"),
            pattern_id: 2003,
            confidence: 0.93,
            category: AttackCategory::Xss,
            description: "onload event handler",
        },
        CompiledPattern {
            regex: Regex::new(r"(?i)\bonclick\s*=").expect("invalid regex"),
            pattern_id: 2004,
            confidence: 0.90,
            category: AttackCategory::Xss,
            description: "onclick event handler",
        },
        CompiledPattern {
            regex: Regex::new(r"(?i)javascript\s*:").expect("invalid regex"),
            pattern_id: 2005,
            confidence: 0.94,
            category: AttackCategory::Xss,
            description: "javascript: URI",
        },
        CompiledPattern {
            regex: Regex::new(r"(?i)\beval\s*\(\s*(?:[^)]*)\s*\)").expect("invalid regex"),
            pattern_id: 2006,
            confidence: 0.92,
            category: AttackCategory::Xss,
            description: "eval() call",
        },
        CompiledPattern {
            regex: Regex::new(r"(?i)document\s*\.\s*cookie").expect("invalid regex"),
            pattern_id: 2007,
            confidence: 0.93,
            category: AttackCategory::Xss,
            description: "document.cookie access",
        },
        CompiledPattern {
            regex: Regex::new(r"(?i)\binnerHTML\s*=").expect("invalid regex"),
            pattern_id: 2008,
            confidence: 0.88,
            category: AttackCategory::Xss,
            description: "innerHTML assignment",
        },
        CompiledPattern {
            regex: Regex::new(r"(?i)\bonfocus\s*=|onblur\s*=|onkeydown\s*=|onkeyup\s*=|onkeypress\s*=|onchange\s*=").expect("invalid regex"),
            pattern_id: 2009,
            confidence: 0.91,
            category: AttackCategory::Xss,
            description: "Other event handlers",
        },
        CompiledPattern {
            regex: Regex::new(r"(?i)onmouseover\s*=|onmouseout\s*=|onmousedown\s*=|onmouseup\s*=").expect("invalid regex"),
            pattern_id: 2010,
            confidence: 0.89,
            category: AttackCategory::Xss,
            description: "Mouse event handlers",
        },
        CompiledPattern {
            regex: Regex::new(r"(?i)alert\s*\(\s*(?:\d+|[^)]*)\s*\)").expect("invalid regex"),
            pattern_id: 2011,
            confidence: 0.85,
            category: AttackCategory::Xss,
            description: "alert() probing",
        },
        CompiledPattern {
            regex: Regex::new(r"(?i)String\s*\.\s*fromCharCode\s*\(").expect("invalid regex"),
            pattern_id: 2012,
            confidence: 0.87,
            category: AttackCategory::Xss,
            description: "Obfuscated XSS via fromCharCode",
        },
        CompiledPattern {
            regex: Regex::new(r"(?i)(?:&#\d+;|&#x[0-9a-fA-F]+;)+").expect("invalid regex"),
            pattern_id: 2013,
            confidence: 0.76,
            category: AttackCategory::Xss,
            description: "HTML entity encoded XSS",
        },
    ]
});

static PATH_TRAVERSAL_PATTERNS: Lazy<Vec<CompiledPattern>> = Lazy::new(|| {
    vec![
        CompiledPattern {
            regex: Regex::new(r"(?:\.{2}[/\\]){2,}").expect("invalid regex"),
            pattern_id: 3001,
            confidence: 0.95,
            category: AttackCategory::PathTraversal,
            description: "Multiple ../ sequences",
        },
        CompiledPattern {
            regex: Regex::new(r"(?i)%2e%2e%2f|%2e%2e%5c").expect("invalid regex"),
            pattern_id: 3002,
            confidence: 0.96,
            category: AttackCategory::PathTraversal,
            description: "URL-encoded ../ (%2e%2e%2f)",
        },
        CompiledPattern {
            regex: Regex::new(r"(?i)%252e%252e%252f|%252e%252e%255c").expect("invalid regex"),
            pattern_id: 3003,
            confidence: 0.97,
            category: AttackCategory::PathTraversal,
            description: "Double-encoded ../ (%252e%252e%252f)",
        },
        CompiledPattern {
            regex: Regex::new(r"(?i)\.%00|%00\.|\.\\%00|%00\.\\").expect("invalid regex"),
            pattern_id: 3004,
            confidence: 0.94,
            category: AttackCategory::PathTraversal,
            description: "Null-byte path truncation",
        },
        CompiledPattern {
            regex: Regex::new(
                r"(?i)(?:/|\\|%2f|%5c)(?:etc|var|proc|sys|tmp|home|root|boot|dev)(?:/|\\|%2f|%5c)",
            )
            .expect("invalid regex"),
            pattern_id: 3005,
            confidence: 0.92,
            category: AttackCategory::PathTraversal,
            description: "System directory traversal",
        },
        CompiledPattern {
            regex: Regex::new(r"(?i)file:///").expect("invalid regex"),
            pattern_id: 3006,
            confidence: 0.78,
            category: AttackCategory::PathTraversal,
            description: "file:// URI for local file access",
        },
    ]
});

static COMMAND_INJECTION_PATTERNS: Lazy<Vec<CompiledPattern>> = Lazy::new(|| {
    vec![
        CompiledPattern {
            regex: Regex::new(r"[|;&]\s*(?:ls|cat|rm|wget|curl|nc|bash|sh|python|perl|php|ruby)\b")
                .expect("invalid regex"),
            pattern_id: 4001,
            confidence: 0.94,
            category: AttackCategory::CommandInjection,
            description: "Pipe/semi command injection",
        },
        CompiledPattern {
            regex: Regex::new(r"\$\(\s*(?:ls|cat|id|whoami|uname|pwd|env)").expect("invalid regex"),
            pattern_id: 4002,
            confidence: 0.93,
            category: AttackCategory::CommandInjection,
            description: "$() command substitution",
        },
        CompiledPattern {
            regex: Regex::new(r"`[^`]*`").expect("invalid regex"),
            pattern_id: 4003,
            confidence: 0.88,
            category: AttackCategory::CommandInjection,
            description: "Backtick command substitution",
        },
        CompiledPattern {
            regex: Regex::new(r"/etc/(?:passwd|shadow|group|hosts|sudoers)\b")
                .expect("invalid regex"),
            pattern_id: 4004,
            confidence: 0.96,
            category: AttackCategory::CommandInjection,
            description: "Access to /etc/passwd and similar",
        },
        CompiledPattern {
            regex: Regex::new(r"/bin/(?:sh|bash|dash|ksh|zsh|tcsh)\b").expect("invalid regex"),
            pattern_id: 4005,
            confidence: 0.95,
            category: AttackCategory::CommandInjection,
            description: "Shell binary access",
        },
        CompiledPattern {
            regex: Regex::new(
                r"(?i)[|;&]\s*(?:whoami|id|uname|hostname|ipconfig|ifconfig|netstat)\b",
            )
            .expect("invalid regex"),
            pattern_id: 4006,
            confidence: 0.92,
            category: AttackCategory::CommandInjection,
            description: "Reconnaissance commands",
        },
        CompiledPattern {
            regex: Regex::new(r"(?i)[|;&]\s*(?:nc\s+-[eln]|ncat\b|socat\b|telnet\b|ssh\b)")
                .expect("invalid regex"),
            pattern_id: 4007,
            confidence: 0.93,
            category: AttackCategory::CommandInjection,
            description: "Network tool injection",
        },
        CompiledPattern {
            regex: Regex::new(r"(?i)(?:wget|curl)\s+\S+\s*(?:\|\s*(?:sh|bash|python)|-o\s*\S+)?")
                .expect("invalid regex"),
            pattern_id: 4008,
            confidence: 0.91,
            category: AttackCategory::CommandInjection,
            description: "Remote file download and execution",
        },
        CompiledPattern {
            regex: Regex::new(r"(?i)/dev/(?:null|zero|random|urandom|tcp|udp)\b")
                .expect("invalid regex"),
            pattern_id: 4009,
            confidence: 0.85,
            category: AttackCategory::CommandInjection,
            description: "/dev/ device access",
        },
    ]
});

static XXE_PATTERNS: Lazy<Vec<CompiledPattern>> = Lazy::new(|| {
    vec![
        CompiledPattern {
            regex: Regex::new(r#"(?i)<!ENTITY\s+\w+\s+(?:SYSTEM|PUBLIC)\s+["'][^"']+["']\s*>"#)
                .expect("invalid regex"),
            pattern_id: 5001,
            confidence: 0.96,
            category: AttackCategory::Xxe,
            description: "ENTITY SYSTEM/PUBLIC declaration",
        },
        CompiledPattern {
            regex: Regex::new(r"(?i)<!DOCTYPE\s+\w+\s+\[").expect("invalid regex"),
            pattern_id: 5002,
            confidence: 0.90,
            category: AttackCategory::Xxe,
            description: "DOCTYPE with internal subset",
        },
        CompiledPattern {
            regex: Regex::new(r"(?i)%\w+;").expect("invalid regex"),
            pattern_id: 5003,
            confidence: 0.72,
            category: AttackCategory::Xxe,
            description: "Parameter entity reference",
        },
        CompiledPattern {
            regex: Regex::new(r"(?i)<!ENTITY\s+%\s+\w+").expect("invalid regex"),
            pattern_id: 5004,
            confidence: 0.94,
            category: AttackCategory::Xxe,
            description: "Parameter entity declaration",
        },
        CompiledPattern {
            regex: Regex::new(
                r#"(?i)SYSTEM\s+["'](?:file|http|https|ftp|gopher|expect|php|jar)://"#,
            )
            .expect("invalid regex"),
            pattern_id: 5005,
            confidence: 0.97,
            category: AttackCategory::Xxe,
            description: "External entity with known protocol",
        },
    ]
});

static SSRF_PATTERNS: Lazy<Vec<CompiledPattern>> = Lazy::new(|| {
    vec![
        CompiledPattern {
            regex: Regex::new(r"http://(?:localhost|127\.\d+\.\d+\.\d+)(?::\d+)?/?").expect("invalid regex"),
            pattern_id: 6001,
            confidence: 0.96,
            category: AttackCategory::Ssrf,
            description: "localhost/127.0.0.1 access",
        },
        CompiledPattern {
            regex: Regex::new(r"http://(?:10\.\d+\.\d+\.\d+|172\.(?:1[6-9]|2\d|3[01])\.\d+\.\d+|192\.168\.\d+\.\d+)(?::\d+)?/?").expect("invalid regex"),
            pattern_id: 6002,
            confidence: 0.94,
            category: AttackCategory::Ssrf,
            description: "Private IP ranges (RFC 1918)",
        },
        CompiledPattern {
            regex: Regex::new(r"(?:169\.254\.169\.254|metadata\.google\.internal)").expect("invalid regex"),
            pattern_id: 6003,
            confidence: 0.98,
            category: AttackCategory::Ssrf,
            description: "AWS/cloud metadata endpoint",
        },
        CompiledPattern {
            regex: Regex::new(r"http://\[?(?:0+:+)+0+\]?(?::\d+)?").expect("invalid regex"),
            pattern_id: 6004,
            confidence: 0.91,
            category: AttackCategory::Ssrf,
            description: "IPv6 loopback/zero address",
        },
        CompiledPattern {
            regex: Regex::new(r"(?i)http://(?:0\.0\.0\.0|127\.0\.0\.\d+|127\.\d+\.\d+\.\d+)").expect("invalid regex"),
            pattern_id: 6005,
            confidence: 0.95,
            category: AttackCategory::Ssrf,
            description: "0.0.0.0 / loopback variants",
        },
        CompiledPattern {
            regex: Regex::new(r"http://127\.\d+\.\d+\.\d+\.(?:nip\.io|xip\.io|sslip\.io)").expect("invalid regex"),
            pattern_id: 6006,
            confidence: 0.93,
            category: AttackCategory::Ssrf,
            description: "DNS rebinding services (nip.io etc.)",
        },
        CompiledPattern {
            regex: Regex::new(r"(?i)(?:169\.254\.169\.254|metadata\s*\.\s*google\s*\.\s*internal)").expect("invalid regex"),
            pattern_id: 6007,
            confidence: 0.98,
            category: AttackCategory::Ssrf,
            description: "GCP metadata endpoint",
        },
    ]
});

static ALL_PATTERNS: Lazy<Vec<&CompiledPattern>> = Lazy::new(|| {
    let mut all: Vec<&CompiledPattern> = Vec::new();
    all.extend(SQL_PATTERNS.iter());
    all.extend(XSS_PATTERNS.iter());
    all.extend(PATH_TRAVERSAL_PATTERNS.iter());
    all.extend(COMMAND_INJECTION_PATTERNS.iter());
    all.extend(XXE_PATTERNS.iter());
    all.extend(SSRF_PATTERNS.iter());
    all
});

static SQL_COMMENT_STRIP: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"(?s)/\*.*?\*/|--[^\n]*").expect("invalid regex"));

static WHITESPACE_COLLAPSE: Lazy<Regex> = Lazy::new(|| Regex::new(r"\s+").expect("invalid regex"));

#[derive(Debug)]
pub struct DpiEngine {
    config: DpiConfig,
    custom_patterns: Vec<CompiledPattern>,
    enabled_categories: HashMap<AttackCategory, bool>,
}

impl DpiEngine {
    pub fn new(config: DpiConfig) -> Self {
        let mut enabled_categories = HashMap::new();
        enabled_categories.insert(
            AttackCategory::SqlInjection,
            config.enable_sql_injection_detection,
        );
        enabled_categories.insert(AttackCategory::Xss, config.enable_xss_detection);
        enabled_categories.insert(
            AttackCategory::PathTraversal,
            config.enable_path_traversal_detection,
        );
        enabled_categories.insert(
            AttackCategory::CommandInjection,
            config.enable_command_injection_detection,
        );
        enabled_categories.insert(AttackCategory::Xxe, config.enable_xxe_detection);
        enabled_categories.insert(AttackCategory::Ssrf, config.enable_ssrf_detection);

        let custom_patterns = config
            .custom_patterns
            .iter()
            .enumerate()
            .filter_map(|(idx, raw)| {
                Regex::new(raw).ok().map(|re| CompiledPattern {
                    regex: re,
                    pattern_id: 9000u32 + idx as u32,
                    confidence: 0.85,
                    category: AttackCategory::Xss,
                    description: "custom",
                })
            })
            .collect();

        DpiEngine {
            config,
            custom_patterns,
            enabled_categories,
        }
    }

    pub fn scan_payload(&self, payload: &[u8]) -> Vec<SignatureMatch> {
        if payload.len() > self.config.max_payload_size as usize {
            let mut matches = Vec::new();
            matches.push(SignatureMatch {
                pattern_id: 0,
                confidence: 1.0,
                category: "payload_size".to_string(),
                matched_content: format!("payload too large: {} bytes", payload.len()),
            });
            return matches;
        }

        let payload_str = match std::str::from_utf8(payload) {
            Ok(s) => s.to_string(),
            Err(_) => String::from_utf8_lossy(payload).to_string(),
        };

        self.scan_text(&payload_str)
    }

    pub fn scan_headers(&self, headers: &HashMap<String, String>) -> Vec<SignatureMatch> {
        let mut matches = Vec::new();

        for (name, value) in headers {
            let combined = format!("{}: {}", name, value);
            let mut header_matches = self.scan_text(&combined);
            matches.append(&mut header_matches);
        }

        matches
    }

    pub fn scan_url(&self, url: &str) -> Vec<SignatureMatch> {
        let mut all_matches = self.scan_text(url);

        let decoded = urlencoding_maybe_decode(url);
        let lower = decoded.to_lowercase();

        let mut url_str = decoded.to_string();
        if let Some(query_start) = url.find('?') {
            url_str = format!("{}{}", &url[..query_start], &lower[query_start..]);
        }

        let mut decoded_matches = self.scan_text(&url_str);
        all_matches.append(&mut decoded_matches);
        all_matches
    }

    fn scan_text(&self, text: &str) -> Vec<SignatureMatch> {
        let mut matches = Vec::new();

        let normalized = normalize_payload(text);
        let nosql = SQL_COMMENT_STRIP.replace_all(&normalized, " ").to_string();

        for pattern in ALL_PATTERNS.iter() {
            if let Some(enabled) = self.enabled_categories.get(&pattern.category) {
                if !enabled {
                    continue;
                }
            }

            let search_text = match pattern.category {
                AttackCategory::SqlInjection => &nosql,
                _ => &normalized,
            };

            if pattern.regex.is_match(search_text) {
                if let Some(cap) = pattern.regex.find(search_text) {
                    let start = cap.start().saturating_sub(20);
                    let end = (cap.end() + 20).min(search_text.len());
                    let context = &search_text[start..end];

                    matches.push(SignatureMatch {
                        pattern_id: pattern.pattern_id,
                        confidence: pattern.confidence,
                        category: pattern.category.as_str().to_string(),
                        matched_content: context.to_string(),
                    });
                }
            }
        }

        for pattern in &self.custom_patterns {
            if pattern.regex.is_match(&normalized) {
                if let Some(cap) = pattern.regex.find(&normalized) {
                    matches.push(SignatureMatch {
                        pattern_id: pattern.pattern_id,
                        confidence: pattern.confidence,
                        category: "custom".to_string(),
                        matched_content: cap.as_str().to_string(),
                    });
                }
            }
        }

        for m in &matches {
            let _ = DPI_VIOLATIONS.with_label_values(&[&m.pattern_id.to_string(), &m.category]);
        }

        matches
    }

    pub fn is_valid_mime(&self, content_type: &str, body: &[u8]) -> bool {
        let ct = content_type.to_lowercase();

        if ct.contains("text/html") || ct.contains("text/xml") || ct.contains("application/xml") {
            let body_str = match std::str::from_utf8(body) {
                Ok(s) => s,
                Err(_) => return false,
            };

            if ct.contains("html")
                && !body_str.to_lowercase().contains("<!doctype")
                && !body_str.to_lowercase().contains("<html")
            {
                return body_str.len() < 100 || body_str.contains('<');
            }

            if ct.contains("xml") {
                let trimmed = body_str.trim();
                if !trimmed.starts_with("<?xml") && !trimmed.starts_with('<') {
                    return false;
                }
            }
        }

        if ct.contains("application/json") {
            let body_str = match std::str::from_utf8(body) {
                Ok(s) => s.trim(),
                Err(_) => return false,
            };
            let first = body_str.chars().next();
            if first != Some('{')
                && first != Some('[')
                && first != Some('"')
                && first != Some('n')
                && first != Some('t')
                && first != Some('f')
                && first != Some('-')
                && !first.is_some_and(|c| c.is_ascii_digit())
            {
                return false;
            }
        }

        true
    }

    pub fn payload_size_exceeded(&self, payload: &[u8]) -> bool {
        payload.len() > self.config.max_payload_size as usize
    }
}

fn normalize_payload(text: &str) -> String {
    let decoded = urlencoding_maybe_decode(text);
    let collapsed = WHITESPACE_COLLAPSE.replace_all(&decoded, " ").to_string();
    collapsed.trim().to_string()
}

fn urlencoding_maybe_decode(input: &str) -> String {
    if input.contains('%') {
        let decoded = percent_decode(input);
        if decoded != input.as_bytes() {
            if let Ok(s) = String::from_utf8(decoded.to_vec()) {
                return s;
            }
        }
    }
    input.to_string()
}

fn percent_decode(input: &str) -> Vec<u8> {
    let bytes = input.as_bytes();
    let mut result = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            let hex = &bytes[i + 1..i + 3];
            if let Ok(h) = std::str::from_utf8(hex) {
                if let Ok(decoded) = u8::from_str_radix(h, 16) {
                    result.push(decoded);
                    i += 3;
                    continue;
                }
            }
            result.push(b'%');
            i += 1;
        } else if bytes[i] == b'+' {
            result.push(b' ');
            i += 1;
        } else {
            result.push(bytes[i]);
            i += 1;
        }
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_engine() -> DpiEngine {
        let config = crate::config::DpiConfig {
            max_payload_size: 1024 * 1024,
            ..Default::default()
        };
        DpiEngine::new(config)
    }

    #[test]
    fn test_sql_injection_union_select() {
        let engine = test_engine();
        let matches = engine.scan_payload(b"1 UNION SELECT username, password FROM users");
        assert!(!matches.is_empty());
        assert!(matches.iter().any(|m| m.pattern_id == 1001));
    }

    #[test]
    fn test_sql_injection_sleep() {
        let engine = test_engine();
        let matches = engine.scan_payload(b"1; SLEEP(5)");
        assert!(matches.iter().any(|m| m.pattern_id == 1004));
    }

    #[test]
    fn test_sql_obfuscated_comment() {
        let engine = test_engine();
        let matches = engine.scan_payload(b"1'/**/UNION/**/SELECT/**/1,2,3");
        assert!(matches.iter().any(|m| m.category == "sql_injection"));
    }

    #[test]
    fn test_xss_script_tag() {
        let engine = test_engine();
        let matches = engine.scan_payload(b"<script>alert('xss')</script>");
        assert!(matches.iter().any(|m| m.pattern_id == 2001));
    }

    #[test]
    fn test_xss_onerror() {
        let engine = test_engine();
        let matches = engine.scan_payload(b"<img src=x onerror=alert(1)>");
        assert!(matches.iter().any(|m| m.pattern_id == 2002));
    }

    #[test]
    fn test_path_traversal() {
        let engine = test_engine();
        let matches = engine.scan_payload(b"../../../../etc/passwd");
        assert!(matches.iter().any(|m| m.pattern_id == 3001));
    }

    #[test]
    fn test_path_traversal_encoded() {
        let engine = test_engine();
        let matches = engine.scan_url("/files?path=%2e%2e%2f%2e%2e%2fetc%2fpasswd");
        assert!(matches
            .iter()
            .any(|m| m.pattern_id == 3001 || m.pattern_id == 3002));
    }

    #[test]
    fn test_command_injection_pipe() {
        let engine = test_engine();
        let matches = engine.scan_payload(b"foo | cat /etc/passwd");
        assert!(matches.iter().any(|m| m.pattern_id == 4001));
    }

    #[test]
    fn test_command_injection_subshell() {
        let engine = test_engine();
        let matches = engine.scan_payload(b"$(whoami)");
        assert!(matches
            .iter()
            .any(|m| m.pattern_id == 4003 || m.pattern_id == 4002));
    }

    #[test]
    fn test_xxe_entity() {
        let engine = test_engine();
        let matches = engine.scan_payload(b"<!ENTITY xxe SYSTEM \"file:///etc/passwd\">");
        assert!(matches.iter().any(|m| m.pattern_id == 5001));
    }

    #[test]
    fn test_ssrf_localhost() {
        let engine = test_engine();
        let matches = engine.scan_payload(b"http://127.0.0.1:8080/admin");
        assert!(matches.iter().any(|m| m.pattern_id == 6001));
    }

    #[test]
    fn test_ssrf_metadata() {
        let engine = test_engine();
        let matches = engine.scan_payload(b"169.254.169.254/latest/meta-data/");
        assert!(matches.iter().any(|m| m.pattern_id == 6003));
    }

    #[test]
    fn test_payload_size_limit() {
        let engine = test_engine();
        let large = vec![b'A'; 2 * 1024 * 1024];
        let matches = engine.scan_payload(&large);
        assert!(matches.iter().any(|m| m.category == "payload_size"));
    }

    #[test]
    fn test_mime_validation_json() {
        let engine = test_engine();
        assert!(engine.is_valid_mime("application/json", b"{\"key\": \"value\"}"));
        assert!(!engine.is_valid_mime("application/json", b"<html>not json</html>"));
    }

    #[test]
    fn test_mime_validation_xml() {
        let engine = test_engine();
        assert!(engine.is_valid_mime("application/xml", b"<?xml version=\"1.0\"?><root/>"));
        assert!(!engine.is_valid_mime("application/xml", b"plain text not xml"));
    }

    #[test]
    fn test_clean_payload_no_match() {
        let engine = test_engine();
        let matches = engine.scan_payload(b"Hello, this is a normal request body");
        assert!(matches.is_empty());
    }

    #[test]
    fn test_drop_table_injection() {
        let engine = test_engine();
        let matches = engine.scan_payload(b"1; DROP TABLE users; --");
        assert!(matches.iter().any(|m| m.pattern_id == 1002));
    }
}
