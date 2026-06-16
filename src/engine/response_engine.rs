use crate::metrics::BLOCKED_REQUESTS;
use chrono::Utc;
use hashbrown::HashMap;
use parking_lot::RwLock;
use std::collections::VecDeque;
use uuid::Uuid;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum ResponseAction {
    Allow,
    Log,
    Challenge,
    RateLimit,
    Block,
    Redirect,
}

impl ResponseAction {
    pub fn as_str(&self) -> &'static str {
        match self {
            ResponseAction::Allow => "allow",
            ResponseAction::Log => "log",
            ResponseAction::Challenge => "challenge",
            ResponseAction::RateLimit => "rate_limit",
            ResponseAction::Block => "block",
            ResponseAction::Redirect => "redirect",
        }
    }

    pub fn escalation_level(&self) -> u8 {
        match self {
            ResponseAction::Allow => 0,
            ResponseAction::Log => 1,
            ResponseAction::Challenge => 2,
            ResponseAction::RateLimit => 3,
            ResponseAction::Block => 4,
            ResponseAction::Redirect => 5,
        }
    }
}

#[derive(Debug, Clone)]
pub struct DecisionContext {
    pub incident_id: String,
    pub client_ip: String,
    pub request_path: String,
    pub request_method: String,
    pub user_agent: String,
    pub dpi_threats: Vec<String>,
    pub bot_score: f32,
    pub threat_intel_score: f32,
    pub anomaly_score: f32,
    pub rate_limit_triggered: bool,
    pub timestamp: i64,
}

#[derive(Debug, Clone)]
pub struct ResponseDecision {
    pub action: ResponseAction,
    pub status_code: u16,
    pub incident_id: String,
    pub reason: String,
    pub headers: Vec<(String, String)>,
    pub body: Option<String>,
    pub redirect_url: Option<String>,
    pub retry_after: Option<u64>,
}

#[derive(Debug, Clone)]
pub struct EscalationState {
    #[allow(dead_code)]
    ip: String,
    current_level: u8,
    violations: Vec<String>,
    first_seen: i64,
    last_seen: i64,
    block_until: Option<i64>,
}

#[derive(Debug)]
pub struct ResponseEngine {
    escalation_states: RwLock<HashMap<String, EscalationState>>,
    recent_decisions: RwLock<VecDeque<ResponseDecision>>,
    block_page_template: String,
    rate_limit_template: String,
    challenge_page_template: String,
    max_escalation: ResponseAction,
    escalation_window_seconds: i64,
    escalation_violation_threshold: u32,
}

impl ResponseEngine {
    pub fn new(max_escalation: ResponseAction) -> Self {
        ResponseEngine {
            escalation_states: RwLock::new(HashMap::new()),
            recent_decisions: RwLock::new(VecDeque::with_capacity(1000)),
            block_page_template: default_block_page(),
            rate_limit_template: default_rate_limit_page(),
            challenge_page_template: default_challenge_page(),
            max_escalation,
            escalation_window_seconds: 300,
            escalation_violation_threshold: 3,
        }
    }

    pub fn evaluate_threat(&self, context: &DecisionContext) -> ResponseDecision {
        let mut action = ResponseAction::Allow;
        let mut reasons: Vec<String> = Vec::new();

        if !context.dpi_threats.is_empty() {
            if context.dpi_threats.len() > 3 {
                action = action.max(ResponseAction::Block);
            } else if context.dpi_threats.len() > 1 {
                action = action.max(ResponseAction::Challenge);
            } else {
                action = action.max(ResponseAction::Log);
            }
            reasons.push(format!("dpi_threats:{}", context.dpi_threats.len()));
        }

        if context.bot_score > 0.9 {
            action = action.max(ResponseAction::Block);
            reasons.push("high_bot_score".to_string());
        } else if context.bot_score > 0.7 {
            action = action.max(ResponseAction::Challenge);
            reasons.push("elevated_bot_score".to_string());
        } else if context.bot_score > 0.4 {
            reasons.push("moderate_bot_score".to_string());
            if action == ResponseAction::Allow {
                action = ResponseAction::Log;
            }
        }

        if context.threat_intel_score > 0.8 {
            action = action.max(ResponseAction::Block);
            reasons.push("high_threat_intel_score".to_string());
        } else if context.threat_intel_score > 0.5 {
            action = action.max(ResponseAction::Challenge);
            reasons.push("elevated_threat_intel_score".to_string());
        }

        if context.anomaly_score > 0.85 {
            action = action.max(ResponseAction::Block);
            reasons.push("high_anomaly_score".to_string());
        } else if context.anomaly_score > 0.6 {
            action = action.max(ResponseAction::Challenge);
            reasons.push("elevated_anomaly_score".to_string());
        }

        if context.rate_limit_triggered {
            action = action.max(ResponseAction::RateLimit);
            reasons.push("rate_limit_triggered".to_string());
        }

        action = self.apply_escalation(&context.client_ip, action, &reasons);

        if action > self.max_escalation {
            action = self.max_escalation;
        }

        let (status_code, body, headers, redirect_url, retry_after) = match action {
            ResponseAction::Allow => (200, None, default_security_headers(), None, None),
            ResponseAction::Log => (200, None, default_security_headers(), None, None),
            ResponseAction::Challenge => {
                let challenge_page = self.generate_challenge_page(&context.incident_id);
                (
                    403,
                    Some(challenge_page),
                    default_security_headers(),
                    None,
                    None,
                )
            }
            ResponseAction::RateLimit => {
                let rl_page = self.generate_rate_limit_response(30);
                (429, Some(rl_page), rate_limit_headers(30), None, Some(30))
            }
            ResponseAction::Block => {
                let block_page =
                    self.generate_block_page(&context.incident_id, &reasons.join(", "));
                (403, Some(block_page), block_headers(), None, None)
            }
            ResponseAction::Redirect => {
                let redirect_url = String::from("/blocked");
                let headers = redirect_headers(&redirect_url);
                (302, None, headers, Some(redirect_url), None)
            }
        };

        if action >= ResponseAction::Block {
            let _ = BLOCKED_REQUESTS.with_label_values(&[&reasons.join("+"), &context.client_ip]);
        }

        let decision = ResponseDecision {
            action,
            status_code,
            incident_id: context.incident_id.clone(),
            reason: reasons.join(", "),
            headers,
            body,
            redirect_url,
            retry_after,
        };

        let mut recent = self.recent_decisions.write();
        recent.push_back(decision.clone());
        if recent.len() > 1000 {
            recent.pop_front();
        }

        decision
    }

    fn apply_escalation(
        &self,
        ip: &str,
        proposed_action: ResponseAction,
        reasons: &[String],
    ) -> ResponseAction {
        let now = Utc::now().timestamp();
        let mut states = self.escalation_states.write();

        let state = states
            .entry(ip.to_string())
            .or_insert_with(|| EscalationState {
                ip: ip.to_string(),
                current_level: 0,
                violations: Vec::new(),
                first_seen: now,
                last_seen: now,
                block_until: None,
            });

        if let Some(block_until) = state.block_until {
            if now < block_until {
                return ResponseAction::Block;
            } else {
                state.block_until = None;
                state.current_level = 0;
            }
        }

        state.last_seen = now;

        if proposed_action > ResponseAction::Log {
            for reason in reasons {
                if !state.violations.contains(reason) {
                    state.violations.push(reason.clone());
                }
            }
        }

        let window_expired = now - state.first_seen > self.escalation_window_seconds;
        if window_expired {
            state.first_seen = now;
            state.violations.clear();
            state.current_level = 0;
        }

        let violations = state.violations.len() as u32;
        if violations >= self.escalation_violation_threshold * 3 {
            state.current_level = ResponseAction::Block.escalation_level();
            state.block_until = Some(now + 3600);
            return ResponseAction::Block;
        } else if violations >= self.escalation_violation_threshold * 2 {
            state.current_level = ResponseAction::RateLimit.escalation_level();
            return proposed_action.max(ResponseAction::RateLimit);
        } else if violations >= self.escalation_violation_threshold {
            state.current_level = ResponseAction::Challenge.escalation_level();
            return proposed_action.max(ResponseAction::Challenge);
        }

        proposed_action
    }

    pub fn escalate_response(&self, ip: &str, incident_id: &str) -> ResponseDecision {
        let now = Utc::now().timestamp();
        let mut states = self.escalation_states.write();

        let state = states
            .entry(ip.to_string())
            .or_insert_with(|| EscalationState {
                ip: ip.to_string(),
                current_level: 0,
                violations: Vec::new(),
                first_seen: now,
                last_seen: now,
                block_until: None,
            });

        if let Some(block_until) = state.block_until {
            if now < block_until {
                return ResponseDecision {
                    action: ResponseAction::Block,
                    status_code: 403,
                    incident_id: incident_id.to_string(),
                    reason: "escalated_block".to_string(),
                    headers: block_headers(),
                    body: Some(self.generate_block_page(incident_id, "escalated")),
                    redirect_url: None,
                    retry_after: None,
                };
            } else {
                state.block_until = None;
                state.current_level = 0;
            }
        }

        state.current_level += 1;

        let action = match state.current_level {
            1 => ResponseAction::Log,
            2 => ResponseAction::Challenge,
            3 => ResponseAction::RateLimit,
            _ => {
                state.block_until = Some(now + 3600);
                ResponseAction::Block
            }
        };

        let (status_code, body, headers) = match action {
            ResponseAction::Log => (200, None, default_security_headers()),
            ResponseAction::Challenge => (
                403,
                Some(self.generate_challenge_page(incident_id)),
                default_security_headers(),
            ),
            ResponseAction::RateLimit => (
                429,
                Some(self.generate_rate_limit_response(30)),
                rate_limit_headers(30),
            ),
            ResponseAction::Block => (
                403,
                Some(self.generate_block_page(incident_id, "escalated")),
                block_headers(),
            ),
            _ => (200, None, default_security_headers()),
        };

        ResponseDecision {
            action,
            status_code,
            incident_id: incident_id.to_string(),
            reason: format!("escalation_level_{}", state.current_level),
            headers,
            body,
            redirect_url: None,
            retry_after: if action == ResponseAction::RateLimit {
                Some(30)
            } else {
                None
            },
        }
    }

    pub fn generate_block_page(&self, incident_id: &str, reason: &str) -> String {
        let now = Utc::now().format("%Y-%m-%d %H:%M:%S UTC").to_string();
        self.block_page_template
            .replace("{INCIDENT_ID}", incident_id)
            .replace("{REASON}", reason)
            .replace("{TIMESTAMP}", &now)
            .replace("{RETRY_HINT}",
                "Your request has been blocked by our security system. If you believe this is an error, please contact your system administrator.")
    }

    pub fn generate_challenge_page(&self, incident_id: &str) -> String {
        let challenge_code = Uuid::new_v4().to_string();
        self.challenge_page_template
            .replace("{INCIDENT_ID}", incident_id)
            .replace("{CHALLENGE_CODE}", &challenge_code)
    }

    pub fn generate_rate_limit_response(&self, retry_after_seconds: u64) -> String {
        self.rate_limit_template
            .replace("{RETRY_AFTER}", &retry_after_seconds.to_string())
            .replace("{TIMESTAMP}", &Utc::now().to_rfc3339())
    }

    pub fn generate_incident_id() -> String {
        format!(
            "AEGIS-{}",
            Uuid::new_v4()
                .to_string()
                .split('-')
                .next()
                .unwrap_or("00000000")
                .to_uppercase()
        )
    }

    pub fn reset_escalation(&self, ip: &str) {
        self.escalation_states.write().remove(ip);
    }

    pub fn get_escalation_state(&self, ip: &str) -> Option<EscalationState> {
        self.escalation_states.read().get(ip).cloned()
    }

    pub fn custom_block_template(&mut self, template: String) {
        self.block_page_template = template;
    }

    pub fn custom_rate_limit_template(&mut self, template: String) {
        self.rate_limit_template = template;
    }

    pub fn custom_challenge_template(&mut self, template: String) {
        self.challenge_page_template = template;
    }
}

fn default_security_headers() -> Vec<(String, String)> {
    vec![
        ("X-Content-Type-Options".to_string(), "nosniff".to_string()),
        ("X-Frame-Options".to_string(), "DENY".to_string()),
        ("X-XSS-Protection".to_string(), "1; mode=block".to_string()),
        (
            "Referrer-Policy".to_string(),
            "strict-origin-when-cross-origin".to_string(),
        ),
        (
            "Permissions-Policy".to_string(),
            "camera=(), microphone=(), geolocation=(), interest-cohort=()".to_string(),
        ),
        (
            "Cache-Control".to_string(),
            "no-store, no-cache, must-revalidate".to_string(),
        ),
        ("Pragma".to_string(), "no-cache".to_string()),
    ]
}

fn block_headers() -> Vec<(String, String)> {
    let mut headers = default_security_headers();
    headers.push((
        "Content-Type".to_string(),
        "text/html; charset=utf-8".to_string(),
    ));
    headers
}

fn rate_limit_headers(retry_after: u64) -> Vec<(String, String)> {
    let mut headers = default_security_headers();
    headers.push((
        "Content-Type".to_string(),
        "text/html; charset=utf-8".to_string(),
    ));
    headers.push(("Retry-After".to_string(), retry_after.to_string()));
    headers
}

fn redirect_headers(location: &str) -> Vec<(String, String)> {
    let mut headers = default_security_headers();
    headers.push(("Location".to_string(), location.to_string()));
    headers
}

fn default_block_page() -> String {
    r#"<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Access Denied - Aegis WAF</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
               background: #0f0f1a; color: #e0e0e0; display: flex; align-items: center;
               justify-content: center; min-height: 100vh; }
        .container { text-align: center; max-width: 600px; padding: 40px; }
        .shield { font-size: 64px; margin-bottom: 20px; }
        h1 { font-size: 28px; margin-bottom: 12px; color: #ef5350; }
        p { font-size: 14px; color: #9090a0; margin-bottom: 8px; line-height: 1.5; }
        .details { background: #1a1a2e; border: 1px solid #2a2a3e; border-radius: 8px;
                    padding: 16px; margin-top: 24px; font-size: 12px; text-align: left; }
        .detail-row { margin-bottom: 6px; }
        .label { color: #6a6a8a; }
        .value { color: #c0c0d0; font-family: monospace; }
    </style>
</head>
<body>
    <div class="container">
        <div class="shield">&#x1F6E1;</div>
        <h1>Access Denied</h1>
        <p>Your request has been blocked by Aegis Web Application Firewall.</p>
        <div class="details">
            <div class="detail-row"><span class="label">Incident ID: </span><span class="value">{INCIDENT_ID}</span></div>
            <div class="detail-row"><span class="label">Timestamp: </span><span class="value">{TIMESTAMP}</span></div>
            <div class="detail-row"><span class="label">Reason: </span><span class="value">{REASON}</span></div>
        </div>
        <p style="margin-top: 20px;">{RETRY_HINT}</p>
    </div>
</body>
</html>"#.to_string()
}

fn default_rate_limit_page() -> String {
    r#"<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Rate Limited - Aegis WAF</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
               background: #0f0f1a; color: #e0e0e0; display: flex; align-items: center;
               justify-content: center; min-height: 100vh; }
        .container { text-align: center; max-width: 500px; padding: 40px; }
        h1 { font-size: 28px; margin-bottom: 12px; color: #ffa726; }
        p { font-size: 14px; color: #9090a0; margin-bottom: 12px; }
        .retry { font-size: 36px; color: #ffa726; font-weight: bold; }
    </style>
    <meta http-equiv="refresh" content="{RETRY_AFTER}">
</head>
<body>
    <div class="container">
        <h1>Too Many Requests</h1>
        <p>Please slow down. You have exceeded the rate limit.</p>
        <p>Retry after <span class="retry">{RETRY_AFTER}</span> seconds</p>
    </div>
</body>
</html>"#
        .to_string()
}

fn default_challenge_page() -> String {
    r#"<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Security Check - Aegis WAF</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
               background: #0f0f1a; color: #e0e0e0; display: flex; align-items: center;
               justify-content: center; min-height: 100vh; }
        .container { text-align: center; max-width: 500px; padding: 40px; }
        h1 { font-size: 24px; margin-bottom: 12px; color: #42a5f5; }
        p { font-size: 14px; color: #9090a0; margin-bottom: 8px; }
        .challenge { background: #1a1a2e; border: 1px solid #2a2a3e; border-radius: 8px;
                      padding: 20px; margin-top: 20px; }
        #challenge-script { font-family: monospace; font-size: 13px; color: #7c4dff; }
        .hidden { display: none; }
    </style>
</head>
<body>
    <div class="container">
        <h1>Security Verification</h1>
        <p>Aegis WAF is verifying your browser before allowing access.</p>
        <div class="challenge">
            <div id="challenge-script">
            </div>
            <p style="margin-top: 12px; font-size: 12px;">Incident: {INCIDENT_ID}</p>
            <input type="hidden" id="challenge-input" value="{CHALLENGE_CODE}">
        </div>
        <p style="margin-top: 16px; font-size: 12px;">This check is performed for security purposes only.</p>
    </div>
    <script>
    </script>
</body>
</html>"#.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_engine() -> ResponseEngine {
        ResponseEngine::new(ResponseAction::Block)
    }

    fn test_context() -> DecisionContext {
        DecisionContext {
            incident_id: ResponseEngine::generate_incident_id(),
            client_ip: "192.168.1.100".to_string(),
            request_path: "/api/test".to_string(),
            request_method: "GET".to_string(),
            user_agent: "Mozilla/5.0 Test".to_string(),
            dpi_threats: Vec::new(),
            bot_score: 0.0,
            threat_intel_score: 0.0,
            anomaly_score: 0.0,
            rate_limit_triggered: false,
            timestamp: Utc::now().timestamp(),
        }
    }

    #[test]
    fn test_allow_clean_request() {
        let engine = test_engine();
        let context = test_context();
        let decision = engine.evaluate_threat(&context);
        assert_eq!(decision.action, ResponseAction::Allow);
        assert_eq!(decision.status_code, 200);
    }

    #[test]
    fn test_block_dpi_threats() {
        let engine = test_engine();
        let mut context = test_context();
        context.dpi_threats = vec![
            "sql_injection".to_string(),
            "xss".to_string(),
            "path_traversal".to_string(),
            "command_injection".to_string(),
        ];
        let decision = engine.evaluate_threat(&context);
        assert!(decision.action >= ResponseAction::Block);
    }

    #[test]
    fn test_challenge_bot_score() {
        let engine = test_engine();
        let mut context = test_context();
        context.bot_score = 0.75;
        let decision = engine.evaluate_threat(&context);
        assert_eq!(decision.action, ResponseAction::Challenge);
    }

    #[test]
    fn test_block_high_bot_score() {
        let engine = test_engine();
        let mut context = test_context();
        context.bot_score = 0.95;
        let decision = engine.evaluate_threat(&context);
        assert_eq!(decision.action, ResponseAction::Block);
    }

    #[test]
    fn test_rate_limit() {
        let engine = test_engine();
        let mut context = test_context();
        context.rate_limit_triggered = true;
        let decision = engine.evaluate_threat(&context);
        assert_eq!(decision.action, ResponseAction::RateLimit);
        assert_eq!(decision.status_code, 429);
    }

    #[test]
    fn test_block_page_generation() {
        let engine = test_engine();
        let page = engine.generate_block_page("AEGIS-12345", "test_reason");
        assert!(page.contains("AEGIS-12345"));
        assert!(page.contains("test_reason"));
        assert!(page.contains("Access Denied"));
    }

    #[test]
    fn test_rate_limit_page() {
        let engine = test_engine();
        let page = engine.generate_rate_limit_response(60);
        assert!(page.contains("60"));
        assert!(page.contains("Too Many Requests"));
    }

    #[test]
    fn test_challenge_page() {
        let engine = test_engine();
        let page = engine.generate_challenge_page("AEGIS-67890");
        assert!(page.contains("AEGIS-67890"));
        assert!(page.contains("Security Verification"));
    }

    #[test]
    fn test_escalation_sequence() {
        let engine = test_engine();
        let ip = "10.0.0.99";

        let d1 = engine.escalate_response(ip, "incident-1");
        assert_eq!(d1.action, ResponseAction::Log);

        let d2 = engine.escalate_response(ip, "incident-2");
        assert_eq!(d2.action, ResponseAction::Challenge);

        let d3 = engine.escalate_response(ip, "incident-3");
        assert_eq!(d3.action, ResponseAction::RateLimit);

        let d4 = engine.escalate_response(ip, "incident-4");
        assert_eq!(d4.action, ResponseAction::Block);
    }

    #[test]
    fn test_reset_escalation() {
        let engine = test_engine();
        let ip = "10.0.0.50";

        engine.escalate_response(ip, "incident-a");
        engine.escalate_response(ip, "incident-b");
        engine.reset_escalation(ip);

        let d = engine.escalate_response(ip, "incident-c");
        assert_eq!(d.action, ResponseAction::Log);
    }

    #[test]
    fn test_incident_id_generation() {
        let id = ResponseEngine::generate_incident_id();
        assert!(id.starts_with("AEGIS-"));
        assert!(id.len() > 6);
    }

    #[test]
    fn test_max_escalation_limit() {
        let engine = ResponseEngine::new(ResponseAction::Challenge);
        let mut context = test_context();
        context.bot_score = 0.95;
        context.threat_intel_score = 0.9;
        let decision = engine.evaluate_threat(&context);
        assert!(decision.action <= ResponseAction::Challenge);
    }

    #[test]
    fn test_custom_templates() {
        let mut engine = test_engine();
        engine.custom_block_template("<html>blocked {INCIDENT_ID}</html>".to_string());
        let page = engine.generate_block_page("TEST", "custom");
        assert!(page.contains("blocked TEST"));
    }
}
