use std::fmt;
use std::io;

#[derive(Debug)]
pub enum AegisError {
    Io(io::Error),
    IoError(String),
    Config(String),
    ConfigError(String),
    Server(String),
    Report(String),
    Serialization(serde_json::Error),
    SerializationError(String),
    ThreatIntelError(String),
    Internal(String),
    NetworkError(String),
    RateLimitExceeded { ip: String },
    ProtocolViolation(String),
    DPIViolation { rule_id: u32, detail: String },
    BotDetected { confidence: f32, indicators: String },
    SecurityViolation { reason: String },
    ConnectionLimitReached { current: u64, max: u64 },
    TlsError(String),
    InvalidRequest(String),
    AuthError(String),
    BehavioralError(String),
    RateLimiterError(String),
}

impl fmt::Display for AegisError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AegisError::Io(e) => write!(f, "IO error: {}", e),
            AegisError::IoError(msg) => write!(f, "IO error: {}", msg),
            AegisError::Config(msg) => write!(f, "Config error: {}", msg),
            AegisError::ConfigError(msg) => write!(f, "Config error: {}", msg),
            AegisError::Server(msg) => write!(f, "Server error: {}", msg),
            AegisError::Report(msg) => write!(f, "Report error: {}", msg),
            AegisError::Serialization(e) => write!(f, "Serialization error: {}", e),
            AegisError::SerializationError(msg) => write!(f, "Serialization error: {}", msg),
            AegisError::ThreatIntelError(msg) => write!(f, "Threat intel error: {}", msg),
            AegisError::Internal(msg) => write!(f, "Internal error: {}", msg),
            AegisError::NetworkError(msg) => write!(f, "Network error: {}", msg),
            AegisError::RateLimitExceeded { ip } => write!(f, "Rate limit exceeded for {}", ip),
            AegisError::ProtocolViolation(msg) => write!(f, "Protocol violation: {}", msg),
            AegisError::DPIViolation { rule_id, detail } => {
                write!(f, "DPI violation (rule {}): {}", rule_id, detail)
            }
            AegisError::BotDetected {
                confidence,
                indicators,
            } => {
                write!(
                    f,
                    "Bot detected ({:.1}%): {}",
                    confidence * 100.0,
                    indicators
                )
            }
            AegisError::SecurityViolation { reason } => {
                write!(f, "Security violation: {}", reason)
            }
            AegisError::ConnectionLimitReached { current, max } => {
                write!(f, "Connection limit reached: {}/{}", current, max)
            }
            AegisError::TlsError(msg) => write!(f, "TLS error: {}", msg),
            AegisError::InvalidRequest(msg) => write!(f, "Invalid request: {}", msg),
            AegisError::AuthError(msg) => write!(f, "Auth error: {}", msg),
            AegisError::BehavioralError(msg) => write!(f, "Behavioral error: {}", msg),
            AegisError::RateLimiterError(msg) => write!(f, "Rate limiter error: {}", msg),
        }
    }
}

impl std::error::Error for AegisError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            AegisError::Io(e) => Some(e),
            AegisError::Serialization(e) => Some(e),
            _ => None,
        }
    }
}

impl From<io::Error> for AegisError {
    fn from(e: io::Error) -> Self {
        AegisError::Io(e)
    }
}

impl From<serde_json::Error> for AegisError {
    fn from(e: serde_json::Error) -> Self {
        AegisError::Serialization(e)
    }
}

impl From<String> for AegisError {
    fn from(s: String) -> Self {
        AegisError::Internal(s)
    }
}

impl From<&str> for AegisError {
    fn from(s: &str) -> Self {
        AegisError::Internal(s.to_string())
    }
}

pub type Result<T> = std::result::Result<T, AegisError>;
