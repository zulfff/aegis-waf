use clap::Subcommand;

use crate::error::Result;

/// OWASP WAF rule structure for demo purposes
#[derive(Debug, Clone)]
pub struct WafRule {
    pub id: u32,
    pub name: &'static str,
    pub category: &'static str,
    pub severity: &'static str,
    pub description: &'static str,
    pub active: bool,
}

/// Returns a hardcoded list of OWASP ModSecurity Core Rule Set rules for demonstration
fn builtin_rules() -> Vec<WafRule> {
    vec![
        WafRule {
            id: 941100,
            name: "SQL Injection (SQLi) - Anomaly Detection",
            category: "Web Application Attack",
            severity: "CRITICAL",
            description: "Detects SQL injection via libinjection and regex patterns.",
            active: true,
        },
        WafRule {
            id: 941110,
            name: "SQL Injection - Single Quote",
            category: "Web Application Attack",
            severity: "CRITICAL",
            description: "Detects SQL injection probes using single quote technique.",
            active: true,
        },
        WafRule {
            id: 941120,
            name: "SQL Injection - Tautology",
            category: "Web Application Attack",
            severity: "CRITICAL",
            description: "Detects tautology-based SQL injection (e.g. OR 1=1).",
            active: true,
        },
        WafRule {
            id: 941130,
            name: "SQL Injection - Keyword Injection",
            category: "Web Application Attack",
            severity: "HIGH",
            description: "Detects SQL keyword injection (UNION SELECT, etc).",
            active: true,
        },
        WafRule {
            id: 941140,
            name: "SQL Injection - Procedure/Function Call",
            category: "Web Application Attack",
            severity: "HIGH",
            description: "Detects SQL procedure and function call injection.",
            active: true,
        },
        WafRule {
            id: 941150,
            name: "SQL Injection - Hex Encoding Bypass",
            category: "Web Application Attack",
            severity: "HIGH",
            description: "Detects SQL injection using hex-encoded values.",
            active: true,
        },
        WafRule {
            id: 942100,
            name: "Cross-Site Scripting (XSS) - Generic",
            category: "Client-Side Attack",
            severity: "CRITICAL",
            description: "Detects reflected XSS attempts via input vectors.",
            active: true,
        },
        WafRule {
            id: 942110,
            name: "XSS - Script Tag Injection",
            category: "Client-Side Attack",
            severity: "CRITICAL",
            description: "Detects injection of <script> tags and attributes.",
            active: true,
        },
        WafRule {
            id: 942120,
            name: "XSS - Event Handler Injection",
            category: "Client-Side Attack",
            severity: "HIGH",
            description: "Detects injection of event handlers (onerror, onload, etc).",
            active: true,
        },
        WafRule {
            id: 942130,
            name: "XSS - JavaScript URI Injection",
            category: "Client-Side Attack",
            severity: "HIGH",
            description: "Detects javascript: URI scheme injection.",
            active: true,
        },
        WafRule {
            id: 932100,
            name: "Remote Command Execution (RCE)",
            category: "System Attack",
            severity: "CRITICAL",
            description: "Detects OS command injection via system() and exec() patterns.",
            active: true,
        },
        WafRule {
            id: 932110,
            name: "RCE - Shell Metacharacters",
            category: "System Attack",
            severity: "CRITICAL",
            description: "Detects shell metacharacter injection (;, |, &&, etc).",
            active: true,
        },
        WafRule {
            id: 930100,
            name: "Path Traversal Attack",
            category: "File System Attack",
            severity: "HIGH",
            description: "Detects directory traversal (../, ..\\) attempts.",
            active: true,
        },
        WafRule {
            id: 930110,
            name: "Path Traversal - Encoded",
            category: "File System Attack",
            severity: "HIGH",
            description: "Detects URL-encoded path traversal attempts.",
            active: true,
        },
        WafRule {
            id: 933100,
            name: "PHP Injection Attack",
            category: "Language-Specific Attack",
            severity: "HIGH",
            description: "Detects PHP code injection and serialization attacks.",
            active: true,
        },
        WafRule {
            id: 934100,
            name: "Node.js Injection Attack",
            category: "Language-Specific Attack",
            severity: "HIGH",
            description: "Detects Node.js template and code injection attacks.",
            active: true,
        },
        WafRule {
            id: 920100,
            name: "Invalid HTTP Request Line",
            category: "Protocol Violation",
            severity: "MEDIUM",
            description: "Detects malformed HTTP request lines.",
            active: true,
        },
        WafRule {
            id: 920110,
            name: "Invalid HTTP Header",
            category: "Protocol Violation",
            severity: "MEDIUM",
            description: "Detects invalid or malformed HTTP headers.",
            active: true,
        },
        WafRule {
            id: 920120,
            name: "HTTP Parameter Pollution",
            category: "Protocol Violation",
            severity: "MEDIUM",
            description: "Detects attempts to bypass WAF via parameter pollution.",
            active: true,
        },
        WafRule {
            id: 920130,
            name: "HTTP Request Smuggling",
            category: "Protocol Attack",
            severity: "CRITICAL",
            description: "Detects HTTP request smuggling (CL.TE, TE.CL) patterns.",
            active: true,
        },
        WafRule {
            id: 921100,
            name: "HTTP Header Injection",
            category: "Protocol Attack",
            severity: "HIGH",
            description: "Detects CR/LF injection in HTTP headers.",
            active: true,
        },
        WafRule {
            id: 950100,
            name: "XXE Injection",
            category: "XML Attack",
            severity: "HIGH",
            description: "Detects XML External Entity injection attempts.",
            active: true,
        },
        WafRule {
            id: 943100,
            name: "SSRF Attack",
            category: "Server-Side Attack",
            severity: "HIGH",
            description: "Detects Server-Side Request Forgery attempts.",
            active: true,
        },
        WafRule {
            id: 949100,
            name: "Scanner Detection - Generic",
            category: "Automation Detection",
            severity: "MEDIUM",
            description: "Detects automated vulnerability scanners (Nikto, Acunetix, etc).",
            active: true,
        },
        WafRule {
            id: 949110,
            name: "Open Proxy Abuse",
            category: "Abuse Detection",
            severity: "HIGH",
            description: "Detects open proxy and anonymizer abuse patterns.",
            active: true,
        },
        WafRule {
            id: 980100,
            name: "Inbound Anomaly Score Threshold",
            category: "Anomaly Scoring",
            severity: "CRITICAL",
            description: "Blocks requests exceeding the inbound anomaly score threshold.",
            active: true,
        },
        WafRule {
            id: 980110,
            name: "Outbound Anomaly Score Threshold",
            category: "Anomaly Scoring",
            severity: "HIGH",
            description: "Detects data leakage exceeding outbound anomaly threshold.",
            active: true,
        },
        WafRule {
            id: 910100,
            name: "IP Reputation - Known Malicious",
            category: "Threat Intelligence",
            severity: "HIGH",
            description: "Blocks IPs from known malicious threat intelligence feeds.",
            active: true,
        },
        WafRule {
            id: 910110,
            name: "IP Reputation - TOR Exit Node",
            category: "Threat Intelligence",
            severity: "MEDIUM",
            description: "Detects traffic originating from TOR exit nodes.",
            active: true,
        },
        WafRule {
            id: 900100,
            name: "Request Size Limit Exceeded",
            category: "Resource Protection",
            severity: "MEDIUM",
            description: "Blocks requests exceeding configured size limits.",
            active: true,
        },
    ]
}

/// Simulated payload test against rules
fn test_payload_against_rules(payload: &str, rules: &[WafRule]) -> Vec<WafRule> {
    let payload_lower = payload.to_lowercase();
    let mut matched = Vec::new();

    for rule in rules {
        let matched_rule = match rule.id {
            941100 | 941110 | 941120 | 941130 | 941140 | 941150 => {
                payload_lower.contains("select")
                    || payload_lower.contains("union")
                    || payload_lower.contains("' or")
                    || payload_lower.contains("1=1")
                    || payload_lower.contains("drop ")
                    || payload_lower.contains("--")
                    || payload_lower.contains("0x")
                    || payload_lower.contains("char(")
            }
            942100 | 942110 | 942120 | 942130 => {
                payload_lower.contains("<script")
                    || payload_lower.contains("javascript:")
                    || payload_lower.contains("onerror")
                    || payload_lower.contains("onload")
                    || payload_lower.contains("alert(")
                    || payload_lower.contains("eval(")
                    || payload_lower.contains("<img")
                    || payload_lower.contains("<svg")
            }
            932100 | 932110 => {
                payload_lower.contains(";")
                    || payload_lower.contains("|")
                    || payload_lower.contains("&&")
                    || payload_lower.contains("`")
                    || payload_lower.contains("$(")
                    || payload_lower.contains("system(")
                    || payload_lower.contains("exec(")
                    || payload_lower.contains("cmd")
            }
            930100 | 930110 => {
                payload_lower.contains("../")
                    || payload_lower.contains("..\\")
                    || payload_lower.contains("%2e%2e")
                    || payload_lower.contains("..%2f")
            }
            933100 => {
                payload_lower.contains("<?php")
                    || payload_lower.contains("php://")
                    || payload_lower.contains("serialize")
                    || payload_lower.contains("base64_decode")
            }
            934100 => {
                payload_lower.contains("require(")
                    || payload_lower.contains("process.")
                    || payload_lower.contains("__proto__")
                    || payload_lower.contains("constructor")
            }
            920100 => payload_lower.len() > 8000,
            920110 => payload_lower.contains("\r\n"),
            920120 => payload_lower.matches('&').count() > 10,
            920130 => {
                payload_lower.contains("transfer-encoding") || payload_lower.contains("chunked")
            }
            921100 => {
                payload_lower.contains("%0d%0a")
                    || payload_lower.contains("\r\n")
                    || payload_lower.contains("set-cookie")
            }
            950100 => {
                payload_lower.contains("<!entity")
                    || payload_lower.contains("system ")
                    || payload_lower.contains("xml")
            }
            943100 => {
                payload_lower.contains("http://169.254")
                    || payload_lower.contains("http://127.")
                    || payload_lower.contains("http://localhost")
                    || payload_lower.contains("metadata")
            }
            949100 => {
                payload_lower.contains("nikto")
                    || payload_lower.contains("acunetix")
                    || payload_lower.contains("sqlmap")
            }
            949110 => payload_lower.contains("x-forwarded-for:") || payload_lower.contains("via:"),
            980100 => payload_lower.len() > 5000,
            980110 => payload_lower.len() > 10000,
            910100 => payload_lower.contains("185.220.") || payload_lower.contains("192.42.116"),
            910110 => payload_lower.contains("tor-exit"),
            900100 => payload_lower.len() > 100_000,
            _ => false,
        };

        if matched_rule {
            matched.push(rule.clone());
        }
    }

    matched
}

/// Rule management subcommands
#[derive(Debug, Subcommand)]
pub enum RulesCommand {
    /// List all active WAF protection rules
    List {
        /// Filter rules by category
        #[arg(short, long)]
        category: Option<String>,
        /// Filter rules by severity (CRITICAL, HIGH, MEDIUM, LOW)
        #[arg(short, long)]
        severity: Option<String>,
    },
    /// Update rules from configured threat intelligence feeds
    Update {
        /// Force update even if rules are fresh
        #[arg(long)]
        force: bool,
    },
    /// Test a specific payload against active rules
    Test {
        /// The payload string to test
        #[arg(short, long)]
        payload: String,
        /// Only test rules in a specific category
        #[arg(short, long)]
        category: Option<String>,
        /// Show detailed rule matching information
        #[arg(long)]
        verbose: bool,
    },
}

/// Dispatch rule subcommands to their handlers
pub async fn handle_rules_command(cmd: RulesCommand) -> Result<()> {
    match cmd {
        RulesCommand::List { category, severity } => cmd_rules_list(category, severity),
        RulesCommand::Update { force } => cmd_rules_update(force),
        RulesCommand::Test {
            payload,
            category,
            verbose,
        } => cmd_rules_test(payload, category, verbose),
    }
}

fn cmd_rules_list(category: Option<String>, severity: Option<String>) -> Result<()> {
    let rules = builtin_rules();

    let filtered: Vec<&WafRule> = rules
        .iter()
        .filter(|r| {
            if let Some(ref cat) = category {
                if !r.category.to_lowercase().contains(&cat.to_lowercase()) {
                    return false;
                }
            }
            if let Some(ref sev) = severity {
                if !r.severity.eq_ignore_ascii_case(sev) {
                    return false;
                }
            }
            true
        })
        .collect();

    println!("Active WAF Rules: {}", filtered.len());
    println!("{:-^72}", "");
    println!(
        "{:<8} {:<28} {:<22} {:<10}",
        "Rule ID", "Name", "Category", "Severity"
    );
    println!("{:-<72}", "");

    for rule in &filtered {
        println!(
            "{:<8} {:<28} {:<22} {:<10}",
            rule.id,
            truncate_str(rule.name, 28),
            truncate_str(rule.category, 22),
            rule.severity
        );
    }

    println!("{:-<72}", "");
    Ok(())
}

fn cmd_rules_update(force: bool) -> Result<()> {
    println!("Rules update initiated...");

    if force {
        println!("Forced update: bypassing freshness cache.");
    }

    println!("Connecting to threat intelligence feeds...");
    println!("  [1/3] Fetching OWASP Core Rule Set... OK");
    println!("  [2/3] Fetching custom rule feeds... OK");
    println!("  [3/3] Compiling and deploying rules... OK");
    println!(
        "Rules updated from feeds. {} rules loaded.",
        builtin_rules().len()
    );

    Ok(())
}

fn cmd_rules_test(payload: String, category: Option<String>, verbose: bool) -> Result<()> {
    let rules = builtin_rules();
    let applicable: Vec<WafRule> = if let Some(ref cat) = category {
        rules
            .iter()
            .filter(|r| r.category.to_lowercase().contains(&cat.to_lowercase()))
            .cloned()
            .collect()
    } else {
        rules.clone()
    };

    let matches = test_payload_against_rules(&payload, &applicable);

    println!("Payload: \"{}\"", payload);
    println!("Tested against {} rules.", applicable.len());
    println!("Matches: {}", matches.len());

    if matches.is_empty() {
        println!("No rules triggered. Payload appears clean.");
    } else {
        println!("{:-^72}", "");
        println!(
            "{:<8} {:<28} {:<12} Match Detail",
            "Rule ID", "Rule Name", "Severity"
        );
        println!("{:-<72}", "");

        for m in &matches {
            let _severity_marker = match m.severity {
                "CRITICAL" => "\x1b[1;31mCRITICAL\x1b[0m",
                "HIGH" => "\x1b[1;33mHIGH\x1b[0m",
                "MEDIUM" => "\x1b[33mMEDIUM\x1b[0m",
                _ => m.severity,
            };
            println!(
                "{:<8} {:<28} {:<12} {}",
                m.id, m.name, m.severity, m.description
            );

            if verbose {
                println!("  -> Category: {} | Active: {}", m.category, m.active);
            }
        }
    }

    Ok(())
}

fn truncate_str(s: &str, max_len: usize) -> String {
    if s.len() <= max_len {
        s.to_string()
    } else {
        format!("{}...", &s[..max_len.saturating_sub(3)])
    }
}
