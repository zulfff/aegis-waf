use std::convert::Infallible;
use std::net::IpAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use hashbrown::HashMap;
use hyper::server::conn::Http;
use hyper::service::service_fn;
use hyper::{Body, Request, Response, StatusCode};
use parking_lot::RwLock;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Notify;
use tokio::time::timeout;
use tracing::{debug, error, info, warn, Instrument};

use crate::config::AegisConfig;
use crate::engine::behavioral_analyzer::BehavioralAnalyzer;
use crate::engine::bot_detector::BotDetector;
use crate::engine::dpi_engine::{DpiEngine, SignatureMatch};
use crate::engine::ingress_filter::{IngressFilter, PacketInfo};
use crate::engine::protocol_validator::ProtocolValidator;
use crate::engine::rate_limiter::{LimitScope, RateLimitDecision, RateLimiter};
use crate::engine::response_engine::{DecisionContext, ResponseAction, ResponseEngine};
use crate::engine::threat_intel::ThreatIntelligence;
use crate::error::{AegisError, Result};
use crate::metrics;

#[derive(Debug, Clone, Copy, Hash, PartialEq, Eq)]
pub struct ConnectionFiveTuple {
    pub src_ip: IpAddr,
    pub src_port: u16,
    pub dst_ip: IpAddr,
    pub dst_port: u16,
    pub protocol: u8,
}

impl ConnectionFiveTuple {
    pub fn from_tcp(stream: &TcpStream) -> std::io::Result<Self> {
        let local = stream.local_addr()?;
        let remote = stream.peer_addr()?;
        Ok(Self {
            src_ip: remote.ip(),
            src_port: remote.port(),
            dst_ip: local.ip(),
            dst_port: local.port(),
            protocol: 6,
        })
    }
}

#[derive(Debug)]
#[allow(dead_code)]
struct ConnectionEntry {
    tuple: ConnectionFiveTuple,
    created_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug)]
pub struct ConnectionTracker {
    active: RwLock<hashbrown::HashMap<ConnectionFiveTuple, ConnectionEntry>>,
    count: AtomicU64,
    max_connections: u64,
}

impl ConnectionTracker {
    pub fn new(max_connections: u64) -> Self {
        Self {
            active: RwLock::new(hashbrown::HashMap::new()),
            count: AtomicU64::new(0),
            max_connections,
        }
    }

    pub fn try_add(&self, tuple: ConnectionFiveTuple) -> Result<()> {
        let current = self.count.load(Ordering::Acquire);
        if current >= self.max_connections {
            return Err(AegisError::ConnectionLimitReached {
                current,
                max: self.max_connections,
            });
        }

        let mut active = self.active.write();
        if active.contains_key(&tuple) {
            return Ok(());
        }

        active.insert(
            tuple,
            ConnectionEntry {
                tuple,
                created_at: chrono::Utc::now(),
            },
        );
        let new_count = self.count.fetch_add(1, Ordering::AcqRel) + 1;

        metrics::CONNECTIONS_ACTIVE.with_label_values(&["tcp"]);

        if new_count > self.max_connections {
            self.remove(&tuple);
            return Err(AegisError::ConnectionLimitReached {
                current: new_count,
                max: self.max_connections,
            });
        }
        Ok(())
    }

    pub fn remove(&self, tuple: &ConnectionFiveTuple) {
        let mut active = self.active.write();
        if active.remove(tuple).is_some() {
            let _new_count = self.count.fetch_sub(1, Ordering::AcqRel) - 1;
            metrics::CONNECTIONS_ACTIVE.with_label_values(&["tcp"]);
        }
    }

    pub fn active_count(&self) -> u64 {
        self.count.load(Ordering::Acquire)
    }
}

#[derive(Debug)]
pub struct AppState {
    pub config: Arc<AegisConfig>,
    pub connection_tracker: ConnectionTracker,
    pub shutdown: Notify,
    pub ingress_filter: IngressFilter,
    pub protocol_validator: ProtocolValidator,
    pub rate_limiter: RateLimiter,
    pub dpi_engine: DpiEngine,
    pub behavioral_analyzer: BehavioralAnalyzer,
    pub threat_intel: ThreatIntelligence,
    pub bot_detector: BotDetector,
    pub response_engine: ResponseEngine,
}

impl AppState {
    pub fn new(config: AegisConfig) -> Self {
        let max_conn = config.server.max_connections;
        let ingress_filter = IngressFilter::new(config.ingress_filter.clone())
            .expect("Failed to create ingress filter");
        let protocol_validator = ProtocolValidator::from_config(&config);
        let rate_limiter = RateLimiter::new(config.rate_limiting.clone());
        let dpi_engine = DpiEngine::new(config.dpi.clone());
        let behavioral_analyzer = BehavioralAnalyzer::new(config.behavioral.clone());
        let threat_intel = ThreatIntelligence::new(config.threat_intelligence.clone());
        let bot_detector = BotDetector::new(config.bot_detection.clone());
        let response_engine = ResponseEngine::new(ResponseAction::Block);

        Self {
            config: Arc::new(config),
            connection_tracker: ConnectionTracker::new(max_conn),
            shutdown: Notify::new(),
            ingress_filter,
            protocol_validator,
            rate_limiter,
            dpi_engine,
            behavioral_analyzer,
            threat_intel,
            bot_detector,
            response_engine,
        }
    }
}

pub struct NetworkStack {
    state: Arc<AppState>,
}

impl NetworkStack {
    pub fn new(config: AegisConfig) -> Self {
        Self {
            state: Arc::new(AppState::new(config)),
        }
    }

    pub async fn start_server(config: AegisConfig) -> Result<()> {
        let stack = Self::new(config);
        let bind_addr = format!(
            "{}:{}",
            stack.state.config.server.bind_addr, stack.state.config.server.bind_port
        );

        let listener = TcpListener::bind(&bind_addr).await.map_err(|e| {
            AegisError::NetworkError(format!("Failed to bind {}: {}", bind_addr, e))
        })?;

        info!(
            target: "aegis.network",
            "Server listening on {} (max_connections: {})",
            bind_addr,
            stack.state.config.server.max_connections
        );

        let mut accept_id: u64 = 0;

        loop {
            tokio::select! {
                result = listener.accept() => {
                    match result {
                        Ok((stream, peer_addr)) => {
                            accept_id += 1;
                            let state = stack.state.clone();
                            let request_timeout_ms = state.config.server.request_timeout_ms;

                            tokio::spawn(
                                async move {
                                    if let Err(e) = stream.set_nodelay(true) {
                                        warn!(target: "aegis.network", "Failed to set TCP_NODELAY: {}", e);
                                    }

                                    let tuple = match ConnectionFiveTuple::from_tcp(&stream) {
                                        Ok(t) => t,
                                        Err(e) => {
                                            error!(target: "aegis.network", "Failed to extract 5-tuple: {}", e);
                                            return;
                                        }
                                    };

                                    match state.connection_tracker.try_add(tuple) {
                                        Ok(()) => {}
                                        Err(e) => {
                                            debug!(target: "aegis.network", "Connection rejected: {}", e);
                                            metrics::BLOCKED_REQUESTS
                                                .with_label_values(&["connection_limit", &peer_addr.ip().to_string()])
                                                .inc();
                                            return;
                                        }
                                    }

                                    let conn_timeout = Duration::from_millis(request_timeout_ms);
                                    if let Err(e) = timeout(conn_timeout, Self::handle_connection(
                                        stream,
                                        state.clone(),
                                        tuple,
                                    ))
                                    .await
                                    {
                                        warn!(target: "aegis.network",
                                            "Connection handler timed out after {}ms: {}",
                                            request_timeout_ms, e
                                        );
                                    }

                                    state.connection_tracker.remove(&tuple);
                                }
                                .instrument(tracing::info_span!("connection", id = accept_id, peer = %peer_addr)),
                            );
                        }
                        Err(e) => {
                            error!(target: "aegis.network", "Accept error: {}", e);
                            tokio::time::sleep(Duration::from_millis(10)).await;
                        }
                    }
                }
                _ = stack.state.shutdown.notified() => {
                    info!(target: "aegis.network", "Shutdown signal received, draining connections...");
                    while stack.state.connection_tracker.active_count() > 0 {
                        tokio::time::sleep(Duration::from_millis(100)).await;
                    }
                    info!(target: "aegis.network", "All connections drained, server stopped");
                    return Ok(());
                }
                _ = Self::wait_for_shutdown_signal() => {
                    info!(target: "aegis.network", "OS signal received, initiating graceful shutdown");
                    stack.state.shutdown.notify_waiters();
                }
            }
        }
    }

    async fn handle_connection(
        stream: TcpStream,
        state: Arc<AppState>,
        tuple: ConnectionFiveTuple,
    ) -> Result<()> {
        let peer_addr = tuple.src_ip.to_string();
        let service = service_fn(move |req: Request<Body>| {
            let state = state.clone();
            let peer = peer_addr.clone();

            async move {
                let result = Self::process_request(req, state, peer).await;
                match result {
                    Ok(response) => Ok::<_, Infallible>(response),
                    Err(aegis_err) => {
                        let status = match &aegis_err {
                            AegisError::RateLimitExceeded { .. } => StatusCode::TOO_MANY_REQUESTS,
                            AegisError::ProtocolViolation(_) => StatusCode::BAD_REQUEST,
                            AegisError::DPIViolation { .. } => StatusCode::FORBIDDEN,
                            AegisError::BotDetected { .. } => StatusCode::FORBIDDEN,
                            AegisError::SecurityViolation { .. } => StatusCode::FORBIDDEN,
                            _ => StatusCode::INTERNAL_SERVER_ERROR,
                        };
                        let body =
                            Body::from(status.canonical_reason().unwrap_or("Error").to_string());
                        Ok(Response::builder()
                            .status(status)
                            .body(body)
                            .unwrap_or_else(|_| {
                                Response::builder()
                                    .status(StatusCode::INTERNAL_SERVER_ERROR)
                                    .body(Body::from("Internal Server Error"))
                                    .unwrap()
                            }))
                    }
                }
            }
        });

        let http = Http::new();
        http.serve_connection(stream, service).await.map_err(|e| {
            if e.is_incomplete_message() || e.is_parse() {
                debug!(target: "aegis.network", "HTTP parse error (likely non-HTTP): {}", e);
                AegisError::NetworkError(format!("HTTP connection error: {}", e))
            } else {
                AegisError::NetworkError(format!("HTTP connection error: {}", e))
            }
        })?;

        Ok(())
    }

    async fn process_request(
        req: Request<Body>,
        state: Arc<AppState>,
        peer_ip: String,
    ) -> std::result::Result<Response<Body>, AegisError> {
        let method = req.method().to_string();
        let uri_path = req.uri().path().to_string();
        let headers = req.headers().clone();
        let user_agent = headers
            .get("user-agent")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .to_string();
        let start = std::time::Instant::now();

        let (parts, body) = req.into_parts();
        let body_bytes = hyper::body::to_bytes(body)
            .await
            .map_err(|e| AegisError::NetworkError(format!("Failed to read body: {}", e)))?;

        let mut headers_map: HashMap<String, String> = HashMap::new();
        for (name, value) in parts.headers.iter() {
            if let Ok(v) = value.to_str() {
                headers_map.insert(name.as_str().to_string(), v.to_string());
            }
        }

        let result = Self::run_pipeline(
            &method,
            &uri_path,
            &user_agent,
            &headers_map,
            &body_bytes,
            &peer_ip,
            &state,
        )
        .await;

        let _latency_ms = start.elapsed().as_millis() as f64;

        let status = match &result {
            Ok(_) => "200",
            Err(AegisError::RateLimitExceeded { .. }) => "429",
            Err(AegisError::DPIViolation { .. }) => "403",
            Err(AegisError::BotDetected { .. }) => "403",
            Err(AegisError::ProtocolViolation(_)) => "400",
            Err(AegisError::SecurityViolation { .. }) => "403",
            Err(_) => "500",
        };

        metrics::REQUEST_TOTAL
            .with_label_values(&[&method, &uri_path, status])
            .inc();
        metrics::REQUEST_LATENCY.with_label_values(&[&method, &uri_path]);

        match &result {
            Err(AegisError::RateLimitExceeded { ip }) => {
                metrics::RATE_LIMIT_TRIGGERED
                    .with_label_values(&["default", ip])
                    .inc();
                metrics::BLOCKED_REQUESTS
                    .with_label_values(&["rate_limit", ip])
                    .inc();
            }
            Err(AegisError::DPIViolation { rule_id, .. }) => {
                metrics::DPI_VIOLATIONS
                    .with_label_values(&[&rule_id.to_string(), "attack"])
                    .inc();
                metrics::BLOCKED_REQUESTS
                    .with_label_values(&["dpi", &peer_ip])
                    .inc();
            }
            Err(AegisError::BotDetected { .. }) => {
                metrics::BOT_DETECTIONS
                    .with_label_values(&["automated", "high"])
                    .inc();
                metrics::BLOCKED_REQUESTS
                    .with_label_values(&["bot", &peer_ip])
                    .inc();
            }
            _ => {}
        }

        match result {
            Ok(()) => {
                let resp = Response::builder()
                    .status(StatusCode::OK)
                    .header("X-Aegis-WAF", "1.0")
                    .body(Body::from("OK"))
                    .map_err(|e| {
                        AegisError::InvalidRequest(format!("Failed to build response: {}", e))
                    })?;
                Ok(resp)
            }
            Err(e) => Err(e),
        }
    }

    async fn run_pipeline(
        method: &str,
        uri_path: &str,
        user_agent: &str,
        headers_map: &HashMap<String, String>,
        body_bytes: &[u8],
        peer_ip: &str,
        state: &AppState,
    ) -> Result<()> {
        let mut dpi_threats: Vec<String> = Vec::new();
        let mut bot_score: f32 = 0.0;
        let mut threat_intel_score: f32 = 0.0;
        let mut anomaly_score_val: f32 = 0.0;
        let mut rate_limit_triggered = false;

        if state.config.protection.enable_ingress_filter {
            let peer_ip_parsed: IpAddr = peer_ip
                .parse()
                .map_err(|e| AegisError::NetworkError(format!("Invalid IP {}: {}", peer_ip, e)))?;
            let packet = PacketInfo {
                src_ip: peer_ip_parsed,
                dst_ip: peer_ip_parsed,
                src_port: 0,
                dst_port: state.config.server.bind_port,
                protocol: 6,
                tcp_flags: None,
                payload_size: body_bytes.len() as u64,
            };
            let _ = state.ingress_filter.validate_packet(&packet)?;
        }

        let result = state.protocol_validator.validate_http_request(body_bytes);
        if !result.passed {
            return Err(AegisError::ProtocolViolation(
                result
                    .rejection_reason()
                    .unwrap_or_else(|| "protocol validation failed".into()),
            ));
        }

        if state.config.protection.enable_rate_limiting {
            let decision =
                state
                    .rate_limiter
                    .check_rate_with_scope(peer_ip, LimitScope::PerIp, 1.0);
            if decision != RateLimitDecision::Allowed {
                rate_limit_triggered = true;
            }
        }

        if state.config.protection.enable_dpi {
            let matches: Vec<SignatureMatch> = state.dpi_engine.scan_payload(body_bytes);
            if !matches.is_empty() {
                dpi_threats = matches.iter().map(|m| m.category.clone()).collect();
            }
        }

        if state.config.protection.enable_behavioral_analysis {
            state.behavioral_analyzer.track_request_sequence(uri_path);
            let score = state.behavioral_analyzer.check_pattern_deviation(uri_path);
            anomaly_score_val = score.overall;
        }

        if state.config.protection.enable_threat_intel {
            if let Some(score) = state.threat_intel.check_ip(peer_ip) {
                threat_intel_score = score.combined_score;
            }
        }

        if state.config.protection.enable_bot_detection {
            let score =
                state
                    .bot_detector
                    .calculate_bot_score(user_agent, headers_map, "", peer_ip);
            bot_score = score.probability;
        }

        let context = DecisionContext {
            incident_id: ResponseEngine::generate_incident_id(),
            client_ip: peer_ip.to_string(),
            request_path: uri_path.to_string(),
            request_method: method.to_string(),
            user_agent: user_agent.to_string(),
            dpi_threats,
            bot_score,
            threat_intel_score,
            anomaly_score: anomaly_score_val,
            rate_limit_triggered,
            timestamp: chrono::Utc::now().timestamp(),
        };

        let decision = state.response_engine.evaluate_threat(&context);
        if decision.action >= ResponseAction::Block {
            return Err(AegisError::SecurityViolation {
                reason: decision.reason,
            });
        }
        if decision.action >= ResponseAction::RateLimit {
            return Err(AegisError::RateLimitExceeded {
                ip: peer_ip.to_string(),
            });
        }

        Ok(())
    }

    async fn wait_for_shutdown_signal() {
        let ctrl_c = async {
            tokio::signal::ctrl_c()
                .await
                .expect("Failed to install Ctrl+C handler");
        };

        #[cfg(unix)]
        let terminate = async {
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
                .expect("Failed to install SIGTERM handler")
                .recv()
                .await;
        };

        #[cfg(not(unix))]
        let terminate = std::future::pending::<()>();

        tokio::select! {
            _ = ctrl_c => {},
            _ = terminate => {},
        }

        info!(target: "aegis.network", "Shutdown signal captured");
    }
}
