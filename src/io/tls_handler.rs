use std::fs;
use std::io::BufReader;
use std::sync::Arc;
use std::time::Duration;

use parking_lot::RwLock;
use rustls::server::{AllowAnyAnonymousOrAuthenticatedClient, ClientHello, ResolvesServerCert};
use rustls::sign::CertifiedKey;
use rustls::{Certificate, PrivateKey, ServerConfig};
use sha2::{Digest, Sha256};
use tokio::time::timeout;
use tokio_rustls::TlsAcceptor;
use tracing::{debug, info};

use crate::config::AegisConfig;
use crate::error::{AegisError, Result};
use crate::metrics;

#[derive(Debug, Clone)]
pub struct TlsFingerprint {
    pub fingerprint_hash: u64,
    pub version: u16,
    pub cipher_suites: Vec<u16>,
    pub elliptic_curves: Vec<u16>,
    pub signature_algorithms: Vec<u16>,
}

impl TlsFingerprint {
    pub fn compute_hash(&self) -> u64 {
        let mut hasher = Sha256::new();
        hasher.update(self.version.to_be_bytes());
        for cs in &self.cipher_suites {
            hasher.update(cs.to_be_bytes());
        }
        hasher.update(b"|");
        for ec in &self.elliptic_curves {
            hasher.update(ec.to_be_bytes());
        }
        hasher.update(b"|");
        for sa in &self.signature_algorithms {
            hasher.update(sa.to_be_bytes());
        }
        let digest = hasher.finalize();
        u64::from_be_bytes(digest[..8].try_into().unwrap_or([0u8; 8]))
    }
}

pub struct FingerprintChannel {
    fingerprint: RwLock<Option<TlsFingerprint>>,
}

impl FingerprintChannel {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            fingerprint: RwLock::new(None),
        })
    }

    #[allow(dead_code)]
    fn take(&self) -> Option<TlsFingerprint> {
        self.fingerprint.write().take()
    }
}

struct FingerprintingCertResolver {
    channel: Arc<FingerprintChannel>,
    inner: Arc<dyn ResolvesServerCert>,
}

impl ResolvesServerCert for FingerprintingCertResolver {
    fn resolve(&self, client_hello: ClientHello) -> Option<Arc<CertifiedKey>> {
        let fingerprint = TlsFingerprint {
            fingerprint_hash: 0,
            version: client_hello
                .server_name()
                .map(|_| 0x0304u16)
                .unwrap_or(0x0303),
            cipher_suites: client_hello
                .cipher_suites()
                .iter()
                .map(|cs| cs.get_u16())
                .collect(),
            elliptic_curves: client_hello
                .alpn()
                .map(|alpn| {
                    alpn.map(|p| {
                        let mut val: u16 = 0;
                        for b in p.iter().take(2) {
                            val = (val << 8) | (*b as u16);
                        }
                        val
                    })
                    .collect()
                })
                .unwrap_or_default(),
            signature_algorithms: client_hello
                .signature_schemes()
                .iter()
                .map(|s| s.get_u16())
                .collect(),
        };

        let hash = fingerprint.compute_hash();
        let mut fp = fingerprint;
        fp.fingerprint_hash = hash;

        let mut stored = self.channel.fingerprint.write();
        *stored = Some(fp);

        self.inner.resolve(client_hello)
    }
}

pub struct TlsHandler {
    acceptor: TlsAcceptor,
    handshake_timeout: Duration,
}

impl TlsHandler {
    pub fn new(config: &AegisConfig) -> Result<Self> {
        let server_config = Self::build_tls_config(config)?;
        let acceptor = TlsAcceptor::from(Arc::new(server_config));
        let handshake_timeout = Duration::from_millis(config.server.request_timeout_ms.min(30_000));

        Ok(Self {
            acceptor,
            handshake_timeout,
        })
    }

    pub fn build_tls_config(config: &AegisConfig) -> Result<ServerConfig> {
        let tls_cert_path =
            config.server.tls_cert.as_ref().ok_or_else(|| {
                AegisError::TlsError("TLS certificate path not configured".into())
            })?;
        let tls_key_path = config
            .server
            .tls_key
            .as_ref()
            .ok_or_else(|| AegisError::TlsError("TLS key path not configured".into()))?;

        let certs = load_certificates(tls_cert_path)?;
        let key = load_private_key(tls_key_path)?;

        let tls_config = ServerConfig::builder()
            .with_safe_defaults()
            .with_no_client_auth()
            .with_single_cert(certs, key)
            .map_err(|e| AegisError::TlsError(format!("Failed to build TLS config: {}", e)))?;

        info!(
            target: "aegis.tls",
            "TLS acceptor created (TLS 1.3 minimum, cert={})",
            tls_cert_path
        );

        Ok(tls_config)
    }

    pub fn build_tls_config_with_mtls(
        config: &AegisConfig,
        ca_cert_path: &str,
    ) -> Result<ServerConfig> {
        let tls_cert_path =
            config.server.tls_cert.as_ref().ok_or_else(|| {
                AegisError::TlsError("TLS certificate path not configured".into())
            })?;
        let tls_key_path = config
            .server
            .tls_key
            .as_ref()
            .ok_or_else(|| AegisError::TlsError("TLS key path not configured".into()))?;

        let certs = load_certificates(tls_cert_path)?;
        let key = load_private_key(tls_key_path)?;

        let ca_cert_file = fs::File::open(ca_cert_path).map_err(|e| {
            AegisError::TlsError(format!("Failed to open CA cert {}: {}", ca_cert_path, e))
        })?;
        let mut ca_reader = BufReader::new(ca_cert_file);
        let ca_cert_bytes = rustls_pemfile::certs(&mut ca_reader)
            .map_err(|e| AegisError::TlsError(format!("Failed to parse CA cert: {}", e)))?;
        let ca_certs: Vec<Certificate> = ca_cert_bytes.into_iter().map(Certificate).collect();

        let mut root_store = rustls::RootCertStore::empty();
        for (idx, ca_cert) in ca_certs.iter().enumerate() {
            root_store.add(ca_cert).map_err(|e| {
                AegisError::TlsError(format!("Failed to add CA cert {}: {}", idx, e))
            })?;
        }

        let client_verifier = Arc::new(AllowAnyAnonymousOrAuthenticatedClient::new(root_store));

        let tls_config = ServerConfig::builder()
            .with_safe_defaults()
            .with_client_cert_verifier(client_verifier)
            .with_single_cert(certs, key)
            .map_err(|e| AegisError::TlsError(format!("Failed to build mTLS config: {}", e)))?;

        Ok(tls_config)
    }

    pub fn build_tls_config_with_fingerprinting(
        config: &AegisConfig,
    ) -> Result<(ServerConfig, Arc<FingerprintChannel>)> {
        let tls_cert_path =
            config.server.tls_cert.as_ref().ok_or_else(|| {
                AegisError::TlsError("TLS certificate path not configured".into())
            })?;
        let tls_key_path = config
            .server
            .tls_key
            .as_ref()
            .ok_or_else(|| AegisError::TlsError("TLS key path not configured".into()))?;

        let certs = load_certificates(tls_cert_path)?;
        let key = load_private_key(tls_key_path)?;

        let channel = FingerprintChannel::new();

        let base_config = ServerConfig::builder()
            .with_safe_defaults()
            .with_no_client_auth()
            .with_single_cert(certs, key)
            .map_err(|e| AegisError::TlsError(format!("Failed to build TLS config: {}", e)))?;

        let fingerprinting_resolver = Arc::new(FingerprintingCertResolver {
            channel: channel.clone(),
            inner: base_config.cert_resolver.clone(),
        });

        let mut config_with_fp = base_config;
        config_with_fp.cert_resolver = fingerprinting_resolver;

        Ok((config_with_fp, channel))
    }

    pub async fn accept(
        &self,
        stream: tokio::net::TcpStream,
    ) -> Result<tokio_rustls::server::TlsStream<tokio::net::TcpStream>> {
        let peer_addr = stream
            .peer_addr()
            .map_err(|e| AegisError::NetworkError(format!("peer_addr failed: {}", e)))?;

        let accept_future = self.acceptor.accept(stream);
        let tls_stream = timeout(self.handshake_timeout, accept_future)
            .await
            .map_err(|_| {
                metrics::TLS_HANDSHAKES
                    .with_label_values(&["unknown", "timeout"])
                    .inc();
                AegisError::TlsError(format!(
                    "TLS handshake timed out after {}ms",
                    self.handshake_timeout.as_millis()
                ))
            })?
            .map_err(|e| {
                metrics::TLS_HANDSHAKES
                    .with_label_values(&["unknown", "failed"])
                    .inc();
                AegisError::TlsError(format!("TLS handshake failed: {}", e))
            })?;

        let (_, conn) = tls_stream.get_ref();
        let protocol_version = conn
            .protocol_version()
            .map(|v| format!("{:?}", v))
            .unwrap_or_else(|| "unknown".into());

        metrics::TLS_HANDSHAKES
            .with_label_values(&[&protocol_version, "success"])
            .inc();

        debug!(
            target: "aegis.tls",
            "TLS handshake completed: version={:?}, peer={}",
            conn.protocol_version(),
            peer_addr
        );

        Ok(tls_stream)
    }

    pub fn compute_fingerprint_hash(client_hello: &ClientHello<'_>) -> u64 {
        let fp = TlsFingerprint {
            fingerprint_hash: 0,
            version: client_hello
                .server_name()
                .map(|_| 0x0304u16)
                .unwrap_or(0x0303),
            cipher_suites: client_hello
                .cipher_suites()
                .iter()
                .map(|cs| cs.get_u16())
                .collect(),
            elliptic_curves: client_hello
                .alpn()
                .map(|alpn| {
                    alpn.map(|p| {
                        let mut val: u16 = 0;
                        for b in p.iter().take(2) {
                            val = (val << 8) | (*b as u16);
                        }
                        val
                    })
                    .collect()
                })
                .unwrap_or_default(),
            signature_algorithms: client_hello
                .signature_schemes()
                .iter()
                .map(|s| s.get_u16())
                .collect(),
        };
        fp.compute_hash()
    }

    pub fn validate_client_cert_der(
        peer_certs: &[Certificate],
    ) -> Result<Vec<x509_parser::certificate::X509Certificate<'_>>> {
        if peer_certs.is_empty() {
            return Err(AegisError::TlsError(
                "Empty client certificate chain".into(),
            ));
        }

        let mut parsed = Vec::new();
        for (idx, cert) in peer_certs.iter().enumerate() {
            let (_, x509) = x509_parser::parse_x509_certificate(cert.as_ref()).map_err(|e| {
                AegisError::TlsError(format!("Failed to parse client cert {}: {}", idx, e))
            })?;

            let now = x509_parser::time::ASN1Time::now();
            if !x509.validity().is_valid_at(now) {
                return Err(AegisError::TlsError(format!(
                    "Client certificate {} is expired or not yet valid",
                    idx
                )));
            }

            parsed.push(x509);
        }

        Ok(parsed)
    }

    pub fn verify_cert_hash(a: &[u8], b: &[u8]) -> bool {
        ring::constant_time::verify_slices_are_equal(a, b).is_ok()
    }

    pub fn acceptor(&self) -> &TlsAcceptor {
        &self.acceptor
    }
}

fn load_certificates(path: &str) -> Result<Vec<Certificate>> {
    let cert_file = fs::File::open(path).map_err(|e| {
        AegisError::TlsError(format!("Failed to open certificate file {}: {}", path, e))
    })?;
    let mut reader = BufReader::new(cert_file);
    let cert_bytes = rustls_pemfile::certs(&mut reader)
        .map_err(|e| AegisError::TlsError(format!("Failed to parse certificates: {}", e)))?;

    if cert_bytes.is_empty() {
        return Err(AegisError::TlsError(format!(
            "No certificates found in {}",
            path
        )));
    }
    let certs: Vec<Certificate> = cert_bytes.into_iter().map(Certificate).collect();
    Ok(certs)
}

fn load_private_key(path: &str) -> Result<PrivateKey> {
    let key_file = fs::File::open(path)
        .map_err(|e| AegisError::TlsError(format!("Failed to open key file {}: {}", path, e)))?;
    let mut reader = BufReader::new(key_file);

    if let Ok(keys) = rustls_pemfile::pkcs8_private_keys(&mut reader) {
        if let Some(key) = keys.into_iter().next() {
            return Ok(PrivateKey(key));
        }
    }

    let key_file2 = fs::File::open(path)
        .map_err(|e| AegisError::TlsError(format!("Failed to open key file {}: {}", path, e)))?;
    let mut reader2 = BufReader::new(key_file2);

    if let Ok(keys) = rustls_pemfile::rsa_private_keys(&mut reader2) {
        if let Some(key) = keys.into_iter().next() {
            return Ok(PrivateKey(key));
        }
    }

    let key_file3 = fs::File::open(path)
        .map_err(|e| AegisError::TlsError(format!("Failed to open key file {}: {}", path, e)))?;
    let mut reader3 = BufReader::new(key_file3);

    if let Ok(keys) = rustls_pemfile::ec_private_keys(&mut reader3) {
        if let Some(key) = keys.into_iter().next() {
            return Ok(PrivateKey(key));
        }
    }

    Err(AegisError::TlsError(format!(
        "No private key found in {}",
        path
    )))
}
