use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use parking_lot::RwLock;
use quinn::{Connection, Endpoint, RecvStream, SendStream, ServerConfig, VarInt};
use tokio::sync::Notify;
use tokio::time::timeout;
use tracing::{debug, info, warn};

use crate::config::AegisConfig;
use crate::error::{AegisError, Result};
use crate::metrics;

const QUIC_HANDSHAKE_TIMEOUT_MS: u64 = 10_000;
#[allow(dead_code)]
const QUIC_IDLE_TIMEOUT_MS: u64 = 30_000;
#[allow(dead_code)]
const MAX_CONCURRENT_HANDSHAKES: u64 = 1000;

#[derive(Debug, Clone)]
pub struct QuicConnectionId {
    pub initial_dcid: Vec<u8>,
    pub current_dcid: Vec<u8>,
    pub src_addr: SocketAddr,
    pub dst_addr: SocketAddr,
}

pub struct QuicConnectionState {
    pub connection_id: usize,
    pub ids: Vec<QuicConnectionId>,
    pub established_at: Instant,
    pub last_activity: Instant,
    pub migrated_count: u64,
}

struct HandshakeRateLimiter {
    active_handshakes: AtomicU64,
    max_concurrent: u64,
}

impl HandshakeRateLimiter {
    fn new(max_concurrent: u64) -> Self {
        Self {
            active_handshakes: AtomicU64::new(0),
            max_concurrent,
        }
    }

    fn try_acquire(&self) -> Result<()> {
        let current = self.active_handshakes.fetch_add(1, Ordering::AcqRel);
        if current >= self.max_concurrent {
            self.active_handshakes.fetch_sub(1, Ordering::AcqRel);
            return Err(AegisError::RateLimitExceeded {
                ip: "quic_handshake".into(),
            });
        }
        Ok(())
    }

    fn release(&self) {
        self.active_handshakes.fetch_sub(1, Ordering::AcqRel);
    }
}

pub struct QuicHandler {
    endpoint: Endpoint,
    handshake_limiter: Arc<HandshakeRateLimiter>,
    active_connections: Arc<RwLock<HashMap<usize, QuicConnectionState>>>,
    shutdown: Arc<Notify>,
}

impl QuicHandler {
    pub fn new_quic_endpoint(
        config: &AegisConfig,
        tls_server_config: rustls::ServerConfig,
    ) -> Result<Endpoint> {
        let quic_port = config.server.bind_port + 1;
        let bind_addr: SocketAddr = format!("{}:{}", config.server.bind_addr, quic_port)
            .parse()
            .map_err(|e| {
                AegisError::NetworkError(format!(
                    "Invalid bind address {}:{}: {}",
                    config.server.bind_addr, quic_port, e
                ))
            })?;

        let mut quic_server_config = ServerConfig::with_crypto(Arc::new(tls_server_config));
        quic_server_config.migration(true);

        let endpoint = Endpoint::server(quic_server_config, bind_addr).map_err(|e| {
            AegisError::NetworkError(format!("Failed to create QUIC endpoint: {}", e))
        })?;

        info!(
            target: "aegis.quic",
            "QUIC endpoint created on {} (migration enabled)",
            bind_addr
        );

        Ok(endpoint)
    }

    pub fn new(endpoint: Endpoint, max_handshakes: u64) -> Self {
        Self {
            endpoint,
            handshake_limiter: Arc::new(HandshakeRateLimiter::new(max_handshakes)),
            active_connections: Arc::new(RwLock::new(HashMap::new())),
            shutdown: Arc::new(Notify::new()),
        }
    }

    pub fn shutdown_signal(&self) -> Arc<Notify> {
        self.shutdown.clone()
    }

    pub fn active_connections_count(&self) -> usize {
        self.active_connections.read().len()
    }

    pub async fn accept_loop(&self) -> Result<()> {
        let mut conn_id_seq: usize = 0;

        loop {
            let accept_future = self.endpoint.accept();

            tokio::select! {
                incoming = accept_future => {
                    match incoming {
                        Some(connecting) => {
                            conn_id_seq += 1;
                            self.handshake_limiter.try_acquire()?;

                            let handshake_limiter = self.handshake_limiter.clone();
                            let active_connections = self.active_connections.clone();
                            let current_id = conn_id_seq;

                            let timeout_dur = Duration::from_millis(QUIC_HANDSHAKE_TIMEOUT_MS);

                            tokio::spawn(async move {
                                let handshake_result = timeout(timeout_dur, connecting).await;
                                handshake_limiter.release();

                                match handshake_result {
                                    Ok(Ok(connection)) => {
                                        Self::handle_quic_connection_inner(
                                            connection,
                                            current_id,
                                            active_connections,
                                        )
                                        .await;
                                    }
                                    Ok(Err(e)) => {
                                        warn!(
                                            target: "aegis.quic",
                                            "QUIC connection failed (connection_id={}): {}",
                                            current_id, e
                                        );
                                    }
                                    Err(_) => {
                                        warn!(
                                            target: "aegis.quic",
                                            "QUIC handshake timed out (connection_id={}) after {}ms",
                                            current_id, QUIC_HANDSHAKE_TIMEOUT_MS
                                        );
                                        metrics::TLS_HANDSHAKES
                                            .with_label_values(&["quic", "timeout"])
                                            .inc();
                                    }
                                }
                            });
                        }
                        None => {
                            info!(target: "aegis.quic", "QUIC endpoint closed");
                            return Ok(());
                        }
                    }
                }
                _ = self.shutdown.notified() => {
                    info!(target: "aegis.quic", "QUIC shutdown signal received");
                    self.endpoint.close(VarInt::from_u32(0), b"server shutdown");
                    self.endpoint.wait_idle().await;
                    info!(target: "aegis.quic", "QUIC endpoint shut down cleanly");
                    return Ok(());
                }
            }
        }
    }

    async fn handle_quic_connection_inner(
        connection: Connection,
        conn_id: usize,
        active_connections: Arc<RwLock<HashMap<usize, QuicConnectionState>>>,
    ) {
        let remote_addr = connection.remote_address();
        let established_at = Instant::now();

        let initial_state = QuicConnectionState {
            connection_id: conn_id,
            ids: Vec::new(),
            established_at,
            last_activity: established_at,
            migrated_count: 0,
        };

        {
            let mut conns = active_connections.write();
            conns.insert(conn_id, initial_state);
        }

        metrics::CONNECTIONS_ACTIVE
            .with_label_values(&["quic"])
            .inc();

        info!(
            target: "aegis.quic",
            "QUIC connection established: id={}, remote={}",
            conn_id, remote_addr
        );

        let conn = connection.clone();
        let conns = active_connections.clone();

        loop {
            tokio::select! {
                stream_result = conn.accept_bi() => {
                    match stream_result {
                        Ok((send, recv)) => {
                            let c = conn.clone();
                            let addr = c.remote_address();
                            tokio::spawn(async move {
                                Self::handle_http3_stream(send, recv, addr).await;
                            });
                        }
                        Err(e) => {
                            debug!(target: "aegis.quic",
                                "QUIC connection {} closed: {}", conn_id, e);
                            break;
                        }
                    }
                }
                uni_result = conn.accept_uni() => {
                    match uni_result {
                        Ok(recv) => {
                            tokio::spawn(async move {
                                if let Err(e) = Self::handle_unidirectional_stream(recv).await {
                                    debug!(target: "aegis.quic",
                                        "Unidirectional stream error: {}", e);
                                }
                            });
                        }
                        Err(_) => {
                            break;
                        }
                    }
                }
            }
        }

        let mut conns = conns.write();
        if conns.remove(&conn_id).is_some() {
            metrics::CONNECTIONS_ACTIVE
                .with_label_values(&["quic"])
                .dec();
            debug!(target: "aegis.quic", "QUIC connection {} cleaned up", conn_id);
        }
    }

    async fn handle_http3_stream(send: SendStream, recv: RecvStream, peer_addr: SocketAddr) {
        let mut recv = recv;
        let mut send = send;

        let mut buf = vec![0u8; 65536];
        match recv.read(&mut buf).await {
            Ok(Some(n)) => {
                buf.truncate(n);
                debug!(
                    target: "aegis.quic",
                    "HTTP/3 stream received {} bytes from {}",
                    n, peer_addr
                );

                let response = b"HTTP/3 200 OK\r\n\
                    server: aegis-waf/1.0\r\n\
                    alt-svc: h3=\":443\"\r\n\
                    content-length: 2\r\n\
                    \r\n\
                    OK";

                if let Err(e) = send.write_all(response).await {
                    warn!(target: "aegis.quic", "Failed to write response: {}", e);
                }
                if let Err(e) = send.finish().await {
                    warn!(target: "aegis.quic", "Failed to finish send stream: {}", e);
                }
            }
            Ok(None) => {
                debug!(target: "aegis.quic", "Empty HTTP/3 stream from {}", peer_addr);
            }
            Err(e) => {
                debug!(target: "aegis.quic", "HTTP/3 stream read error: {}", e);
            }
        }
    }

    async fn handle_unidirectional_stream(mut recv: RecvStream) -> Result<()> {
        let mut buf = vec![0u8; 16384];
        match recv.read(&mut buf).await {
            Ok(Some(n)) => {
                debug!(
                    target: "aegis.quic",
                    "Unidirectional stream received {} bytes", n
                );
                Ok(())
            }
            Ok(None) => Ok(()),
            Err(e) => Err(AegisError::NetworkError(format!(
                "Unidirectional stream read error: {}",
                e
            ))),
        }
    }

    pub fn track_connection_id(
        &self,
        conn_id: usize,
        initial_dcid: Vec<u8>,
        current_dcid: Vec<u8>,
        src_addr: SocketAddr,
        dst_addr: SocketAddr,
    ) {
        let qid = QuicConnectionId {
            initial_dcid,
            current_dcid,
            src_addr,
            dst_addr,
        };

        let mut conns = self.active_connections.write();
        if let Some(state) = conns.get_mut(&conn_id) {
            if let Some(last_id) = state.ids.last() {
                if last_id.src_addr != src_addr || last_id.dst_addr != dst_addr {
                    state.migrated_count += 1;
                    info!(
                        target: "aegis.quic",
                        "Connection migration detected: conn_id={}, count={}, old={}->{}, new={}->{}",
                        conn_id,
                        state.migrated_count,
                        last_id.src_addr,
                        last_id.dst_addr,
                        src_addr,
                        dst_addr,
                    );
                }
            }
            state.ids.push(qid);
            state.last_activity = Instant::now();
        }
    }

    pub fn detect_connection_migration(&self, conn_id: usize) -> Option<u64> {
        let conns = self.active_connections.read();
        conns.get(&conn_id).map(|state| state.migrated_count)
    }
}
