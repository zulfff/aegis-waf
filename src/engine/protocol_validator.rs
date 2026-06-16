use std::time::Duration;

use crate::config::AegisConfig;

const MAX_HEADER_SIZE: usize = 8192;
const MAX_URL_LENGTH: usize = 2048;
const MAX_METHOD_LENGTH: usize = 16;
const MAX_HEADERS_COUNT: usize = 128;
const SLOWLORIS_HEADER_INTERVAL_MS: u64 = 500;

const VALID_METHODS: &[&str] = &[
    "GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS", "PATCH", "CONNECT", "TRACE",
];

const INVALID_HEADER_PREFIXES: &[&str] = &["proxy-", "x-forwarded-for", "x-real-ip"];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ValidationSeverity {
    Pass,
    Warn,
    Reject,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ValidationErrorKind {
    IncompleteHeaders,
    InvalidMethod,
    InvalidUrl,
    UrlTooLong,
    MethodTooLong,
    HeaderTooLarge,
    TooManyHeaders,
    InvalidHeaderName,
    InvalidHeaderValue,
    MalformedRequest,
    ContentLengthMismatch,
    TransferEncodingInvalid,
    InvalidHttpVersion,
    SlowlorisDetected,
    InvalidHost,
    HostHeaderMissing,
    DoubleContentLength,
    ConflictingContentLength,
    TransferEncodingWithContentLength,
    NonStandardEncoding,
    InvalidChunkSize,
    AcceptEncodingInvalid,
    ExpectHeaderInvalid,
    RangeHeaderInvalid,
    LineFoldingDetected,
}

#[derive(Debug, Clone)]
pub struct ValidationEntry {
    pub kind: ValidationErrorKind,
    pub severity: ValidationSeverity,
    pub detail: String,
}

#[derive(Debug, Clone)]
pub struct ProtocolValidResult {
    pub passed: bool,
    pub severity: ValidationSeverity,
    pub errors: Vec<ValidationEntry>,
    pub method: Option<String>,
    pub path: Option<String>,
    pub http_version: Option<u8>,
    pub content_length: Option<u64>,
    pub is_chunked: bool,
    pub headers_count: usize,
    pub header_received_duration: Option<Duration>,
}

impl ProtocolValidResult {
    pub fn new() -> Self {
        Self {
            passed: true,
            severity: ValidationSeverity::Pass,
            errors: Vec::new(),
            method: None,
            path: None,
            http_version: None,
            content_length: None,
            is_chunked: false,
            headers_count: 0,
            header_received_duration: None,
        }
    }

    fn add_error(
        &mut self,
        kind: ValidationErrorKind,
        severity: ValidationSeverity,
        detail: String,
    ) {
        if severity == ValidationSeverity::Reject {
            self.passed = false;
        }
        if self.severity != ValidationSeverity::Reject {
            self.severity = severity;
        }
        self.errors.push(ValidationEntry {
            kind,
            severity,
            detail,
        });
    }

    pub fn rejection_reason(&self) -> Option<String> {
        self.errors
            .iter()
            .filter(|e| e.severity == ValidationSeverity::Reject)
            .map(|e| format!("{:?}: {}", e.kind, e.detail))
            .next()
    }
}

impl Default for ProtocolValidResult {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug)]
pub struct ProtocolValidator {
    max_header_size: usize,
    max_url_length: usize,
    max_method_length: usize,
    max_headers_count: usize,
    slowloris_header_interval: Duration,
}

impl ProtocolValidator {
    pub fn new() -> Self {
        Self {
            max_header_size: MAX_HEADER_SIZE,
            max_url_length: MAX_URL_LENGTH,
            max_method_length: MAX_METHOD_LENGTH,
            max_headers_count: MAX_HEADERS_COUNT,
            slowloris_header_interval: Duration::from_millis(SLOWLORIS_HEADER_INTERVAL_MS),
        }
    }

    pub fn from_config(_config: &AegisConfig) -> Self {
        Self::new()
    }

    pub fn validate_http_request(&self, data: &[u8]) -> ProtocolValidResult {
        let mut result = ProtocolValidResult::new();

        if data.is_empty() {
            result.add_error(
                ValidationErrorKind::MalformedRequest,
                ValidationSeverity::Reject,
                "empty request body".into(),
            );
            return result;
        }

        let mut headers = [httparse::EMPTY_HEADER; MAX_HEADERS_COUNT];
        let mut request = httparse::Request::new(&mut headers);

        let parse_result = match request.parse(data) {
            Ok(status) => status,
            Err(e) => {
                result.add_error(
                    ValidationErrorKind::MalformedRequest,
                    ValidationSeverity::Reject,
                    format!("httparse error: {}", e),
                );
                return result;
            }
        };

        match parse_result {
            httparse::Status::Complete(header_len) => {
                let parse_duration = None;
                self.validate_parsed_request(&request, header_len, parse_duration, &mut result);
            }
            httparse::Status::Partial => {
                if data.len() >= self.max_header_size {
                    result.add_error(
                        ValidationErrorKind::HeaderTooLarge,
                        ValidationSeverity::Reject,
                        format!(
                            "headers exceeded max size of {} bytes",
                            self.max_header_size
                        ),
                    );
                } else {
                    result.add_error(
                        ValidationErrorKind::IncompleteHeaders,
                        ValidationSeverity::Reject,
                        "incomplete HTTP headers received".into(),
                    );
                }
            }
        }

        result
    }

    fn validate_parsed_request(
        &self,
        request: &httparse::Request,
        _header_len: usize,
        _parse_duration: Option<Duration>,
        result: &mut ProtocolValidResult,
    ) {
        if let Some(method) = request.method {
            result.method = Some(method.to_string());
            self.validate_method(method, result);
        } else {
            result.add_error(
                ValidationErrorKind::InvalidMethod,
                ValidationSeverity::Reject,
                "missing HTTP method".into(),
            );
        }

        if let Some(path) = request.path {
            self.validate_path(path, result);
        } else {
            result.add_error(
                ValidationErrorKind::InvalidUrl,
                ValidationSeverity::Reject,
                "missing URL path".into(),
            );
        }

        if let Some(version) = request.version {
            result.http_version = Some(version);
            if version != 1 && version != 0 {
                result.add_error(
                    ValidationErrorKind::InvalidHttpVersion,
                    ValidationSeverity::Warn,
                    format!("unsupported HTTP version {}", version),
                );
            }
        }

        let headers = &request.headers[..];
        result.headers_count = headers.len();

        if headers.len() > self.max_headers_count {
            result.add_error(
                ValidationErrorKind::TooManyHeaders,
                ValidationSeverity::Reject,
                format!(
                    "too many headers: {} > max {}",
                    headers.len(),
                    self.max_headers_count
                ),
            );
        }

        for header in headers.iter() {
            if !self.is_valid_header_name(header.name) {
                result.add_error(
                    ValidationErrorKind::InvalidHeaderName,
                    ValidationSeverity::Reject,
                    format!("invalid header name: {}", header.name),
                );
            }
            if !self.is_valid_header_value(header.value) {
                result.add_error(
                    ValidationErrorKind::InvalidHeaderValue,
                    ValidationSeverity::Reject,
                    format!("invalid header value for '{}'", header.name),
                );
            }
        }

        if let Some(_cl_value) = self.find_header_value(headers, "content-length") {
            self.validate_content_length(headers, result);
        }

        if let Some(te_value) = self.find_header_value(headers, "transfer-encoding") {
            self.validate_transfer_encoding(te_value, headers, result);
        }

        let has_host = self.find_header_value(headers, "host").is_some();
        if !has_host && request.version == Some(1) {
            result.add_error(
                ValidationErrorKind::HostHeaderMissing,
                ValidationSeverity::Reject,
                "Host header is required for HTTP/1.1".into(),
            );
        }

        if let Some(host) = self.find_header_value(headers, "host") {
            if host.is_empty() || host.len() > 256 {
                result.add_error(
                    ValidationErrorKind::InvalidHost,
                    ValidationSeverity::Reject,
                    "invalid Host header value".into(),
                );
            }
        }

        self.detect_slow_attacks(request, result);
    }

    fn validate_method(&self, method: &str, result: &mut ProtocolValidResult) {
        if method.len() > self.max_method_length {
            result.add_error(
                ValidationErrorKind::MethodTooLong,
                ValidationSeverity::Reject,
                format!(
                    "method '{}' exceeds max length {}",
                    method, self.max_method_length
                ),
            );
            return;
        }

        if method.is_empty() {
            result.add_error(
                ValidationErrorKind::InvalidMethod,
                ValidationSeverity::Reject,
                "empty HTTP method".into(),
            );
            return;
        }

        for ch in method.bytes() {
            if !ch.is_ascii_uppercase() && !ch.is_ascii_digit() && ch != b'-' && ch != b'_' {
                result.add_error(
                    ValidationErrorKind::InvalidMethod,
                    ValidationSeverity::Reject,
                    format!("invalid character in HTTP method '{}'", method),
                );
                return;
            }
        }

        if !VALID_METHODS.contains(&method) {
            result.add_error(
                ValidationErrorKind::InvalidMethod,
                ValidationSeverity::Warn,
                format!("non-standard HTTP method: {}", method),
            );
        }
    }

    fn validate_path(&self, path: &str, result: &mut ProtocolValidResult) {
        if path.len() > self.max_url_length {
            result.add_error(
                ValidationErrorKind::UrlTooLong,
                ValidationSeverity::Reject,
                format!(
                    "URL path exceeds max length: {} > {}",
                    path.len(),
                    self.max_url_length
                ),
            );
            return;
        }

        if path.is_empty() {
            result.add_error(
                ValidationErrorKind::InvalidUrl,
                ValidationSeverity::Reject,
                "empty URL path".into(),
            );
            return;
        }

        if path.bytes().any(|b| b == 0x00) {
            result.add_error(
                ValidationErrorKind::InvalidUrl,
                ValidationSeverity::Reject,
                "URL contains null byte".into(),
            );
        }

        if path.bytes().any(|b| b == 0x0A || b == 0x0D) {
            result.add_error(
                ValidationErrorKind::InvalidUrl,
                ValidationSeverity::Reject,
                "URL contains CR/LF characters".into(),
            );
        }

        if path.contains("//")
            && !path.starts_with("//")
            && path.len() > 8
            && path.bytes().filter(|&b| b == b'/').count() > 10
        {
            result.add_error(
                ValidationErrorKind::InvalidUrl,
                ValidationSeverity::Warn,
                "URL contains suspicious double-slash pattern".into(),
            );
        }

        result.path = Some(path.to_string());
    }

    fn validate_content_length(
        &self,
        headers: &[httparse::Header],
        result: &mut ProtocolValidResult,
    ) {
        let cl_headers: Vec<&[u8]> = headers
            .iter()
            .filter(|h| h.name.eq_ignore_ascii_case("content-length"))
            .map(|h| h.value)
            .collect();

        if cl_headers.len() > 1 {
            let first_val = std::str::from_utf8(cl_headers[0]).unwrap_or("");
            let all_same = cl_headers
                .iter()
                .all(|v| std::str::from_utf8(v).unwrap_or("") == first_val);

            if all_same {
                result.add_error(
                    ValidationErrorKind::DoubleContentLength,
                    ValidationSeverity::Warn,
                    "multiple Content-Length headers with same value".into(),
                );
            } else {
                result.add_error(
                    ValidationErrorKind::ConflictingContentLength,
                    ValidationSeverity::Reject,
                    "conflicting Content-Length headers".into(),
                );
                return;
            }
        }

        let cl_str = match std::str::from_utf8(cl_headers[0]) {
            Ok(s) => s.trim(),
            Err(_) => {
                result.add_error(
                    ValidationErrorKind::ContentLengthMismatch,
                    ValidationSeverity::Reject,
                    "Content-Length contains invalid UTF-8".into(),
                );
                return;
            }
        };

        match cl_str.parse::<u64>() {
            Ok(len) => {
                result.content_length = Some(len);
            }
            Err(_) => {
                if cl_str.starts_with('-') || cl_str.starts_with('+') {
                    result.add_error(
                        ValidationErrorKind::ContentLengthMismatch,
                        ValidationSeverity::Reject,
                        format!("invalid Content-Length value: {}", cl_str),
                    );
                } else {
                    result.add_error(
                        ValidationErrorKind::ContentLengthMismatch,
                        ValidationSeverity::Warn,
                        format!("non-numeric Content-Length: {}", cl_str),
                    );
                }
            }
        }
    }

    fn validate_transfer_encoding(
        &self,
        te_value: &[u8],
        headers: &[httparse::Header],
        result: &mut ProtocolValidResult,
    ) {
        let te_str = match std::str::from_utf8(te_value) {
            Ok(s) => s.trim(),
            Err(_) => {
                result.add_error(
                    ValidationErrorKind::TransferEncodingInvalid,
                    ValidationSeverity::Reject,
                    "Transfer-Encoding contains invalid UTF-8".into(),
                );
                return;
            }
        };

        let has_cl = self.find_header_value(headers, "content-length").is_some();
        if has_cl {
            result.add_error(
                ValidationErrorKind::TransferEncodingWithContentLength,
                ValidationSeverity::Reject,
                "Transfer-Encoding and Content-Length cannot be used together".into(),
            );
        }

        let encodings: Vec<&str> = te_str.split(',').map(|s| s.trim()).collect();

        for encoding in &encodings {
            match encoding.to_lowercase().as_str() {
                "chunked" => {
                    result.is_chunked = true;
                }
                "gzip" | "compress" | "deflate" | "br" | "identity" => {}
                "" => {
                    result.add_error(
                        ValidationErrorKind::TransferEncodingInvalid,
                        ValidationSeverity::Reject,
                        "empty Transfer-Encoding token".into(),
                    );
                }
                _ => {
                    result.add_error(
                        ValidationErrorKind::NonStandardEncoding,
                        ValidationSeverity::Warn,
                        format!("non-standard Transfer-Encoding: {}", encoding),
                    );
                }
            }
        }

        if encodings.len() > 1
            && encodings.iter().any(|e| e.eq_ignore_ascii_case("chunked"))
            && encodings
                .last()
                .map(|e| !e.eq_ignore_ascii_case("chunked"))
                .unwrap_or(false)
        {
            result.add_error(
                ValidationErrorKind::InvalidChunkSize,
                ValidationSeverity::Warn,
                "chunked should be the last Transfer-Encoding".into(),
            );
        }
    }

    fn detect_slow_attacks(&self, request: &httparse::Request, result: &mut ProtocolValidResult) {
        let headers = &request.headers[..];

        for hp in INVALID_HEADER_PREFIXES {
            for header in headers.iter() {
                if header.name.len() >= hp.len() && header.name[..hp.len()].eq_ignore_ascii_case(hp)
                {
                    result.add_error(
                        ValidationErrorKind::LineFoldingDetected,
                        ValidationSeverity::Reject,
                        format!("header '{}' not permitted", header.name),
                    );
                }
            }
        }

        if (request.method == Some("GET") || request.method == Some("HEAD"))
            && request.path.is_some_and(|p| p.len() > 1500)
        {
            result.add_error(
                ValidationErrorKind::SlowlorisDetected,
                ValidationSeverity::Warn,
                "unusually long URL path on GET/HEAD request".into(),
            );
        }

        if headers.len() > 50 {
            result.add_error(
                ValidationErrorKind::SlowlorisDetected,
                ValidationSeverity::Warn,
                format!("high header count: {}", headers.len()),
            );
        }
    }

    pub fn validate_headers(&self, headers: &[httparse::Header]) -> ProtocolValidResult {
        let mut result = ProtocolValidResult::new();
        result.headers_count = headers.len();

        if headers.len() > self.max_headers_count {
            result.add_error(
                ValidationErrorKind::TooManyHeaders,
                ValidationSeverity::Reject,
                format!(
                    "too many headers: {} > max {}",
                    headers.len(),
                    self.max_headers_count
                ),
            );
        }

        let mut has_cl = false;
        let mut has_te = false;

        for header in headers {
            if !self.is_valid_header_name(header.name) {
                result.add_error(
                    ValidationErrorKind::InvalidHeaderName,
                    ValidationSeverity::Reject,
                    format!("invalid header name: {}", header.name),
                );
            }

            if !self.is_valid_header_value(header.value) {
                result.add_error(
                    ValidationErrorKind::InvalidHeaderValue,
                    ValidationSeverity::Reject,
                    format!("invalid header value for '{}'", header.name),
                );
            }

            if header.name.eq_ignore_ascii_case("content-length") {
                if has_cl {
                    result.add_error(
                        ValidationErrorKind::DoubleContentLength,
                        ValidationSeverity::Reject,
                        "duplicate Content-Length header".into(),
                    );
                }
                has_cl = true;

                if let Ok(val_str) = std::str::from_utf8(header.value) {
                    if val_str.trim().parse::<u64>().is_err() {
                        result.add_error(
                            ValidationErrorKind::ContentLengthMismatch,
                            ValidationSeverity::Reject,
                            format!("invalid Content-Length value: {}", val_str.trim()),
                        );
                    } else {
                        result.content_length = val_str.trim().parse().ok();
                    }
                }
            }

            if header.name.eq_ignore_ascii_case("transfer-encoding") {
                has_te = true;
            }
        }

        if has_cl && has_te {
            result.add_error(
                ValidationErrorKind::TransferEncodingWithContentLength,
                ValidationSeverity::Reject,
                "Transfer-Encoding and Content-Length present simultaneously".into(),
            );
        }

        result
    }

    pub fn detect_slowloris(&self, data: &[u8], time_since_first_byte: Duration) -> bool {
        let mut headers = [httparse::EMPTY_HEADER; MAX_HEADERS_COUNT];
        let mut req = httparse::Request::new(&mut headers);

        match req.parse(data) {
            Ok(httparse::Status::Complete(_)) => {
                time_since_first_byte > self.slowloris_header_interval
            }
            Ok(httparse::Status::Partial) => {
                if data.len() < self.max_header_size {
                    time_since_first_byte > self.slowloris_header_interval
                } else {
                    false
                }
            }
            Err(_) => false,
        }
    }

    fn find_header_value<'a>(
        &self,
        headers: &'a [httparse::Header],
        name: &str,
    ) -> Option<&'a [u8]> {
        headers
            .iter()
            .find(|h| h.name.eq_ignore_ascii_case(name))
            .map(|h| h.value)
    }

    fn is_valid_header_name(&self, name: &str) -> bool {
        if name.is_empty() || name.len() > 256 {
            return false;
        }

        name.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_' || b == b'.')
            && name
                .bytes()
                .next()
                .is_some_and(|b| b.is_ascii_alphanumeric())
    }

    fn is_valid_header_value(&self, value: &[u8]) -> bool {
        if value.is_empty() {
            return true;
        }

        if value.len() > 32768 {
            return false;
        }

        let has_non_ascii = value.iter().any(|&b| b == 0x00 || b == 0x0A || b == 0x0D);
        if has_non_ascii {
            return false;
        }

        true
    }
}

impl Default for ProtocolValidator {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_valid_get_request() {
        let validator = ProtocolValidator::new();
        let data = b"GET /api/health HTTP/1.1\r\nHost: example.com\r\n\r\n";
        let result = validator.validate_http_request(data);
        assert!(result.passed);
        assert_eq!(result.method.as_deref(), Some("GET"));
        assert_eq!(result.path.as_deref(), Some("/api/health"));
    }

    #[test]
    fn test_empty_request() {
        let validator = ProtocolValidator::new();
        let result = validator.validate_http_request(b"");
        assert!(!result.passed);
    }

    #[test]
    fn test_invalid_method() {
        let validator = ProtocolValidator::new();
        let data = b"INVALID / HTTP/1.1\r\nHost: example.com\r\n\r\n";
        let result = validator.validate_http_request(data);
        assert!(result.passed);
        assert!(!result.errors.is_empty());
    }

    #[test]
    fn test_url_with_null_byte() {
        let validator = ProtocolValidator::new();
        let data = b"GET /\x00admin HTTP/1.1\r\nHost: example.com\r\n\r\n";
        let result = validator.validate_http_request(data);
        assert!(!result.passed);
    }

    #[test]
    fn test_url_with_crlf() {
        let validator = ProtocolValidator::new();
        let data = b"GET /path\r\ninjection HTTP/1.1\r\nHost: example.com\r\n\r\n";
        let result = validator.validate_http_request(data);
        assert!(!result.passed);
    }

    #[test]
    fn test_url_too_long() {
        let validator = ProtocolValidator {
            max_url_length: 10,
            ..ProtocolValidator::new()
        };
        let data = b"GET /this/is/a/very/long/path HTTP/1.1\r\nHost: example.com\r\n\r\n";
        let result = validator.validate_http_request(data);
        assert!(!result.passed);
    }

    #[test]
    fn test_double_content_length() {
        let validator = ProtocolValidator::new();
        let data = b"POST / HTTP/1.1\r\nHost: example.com\r\nContent-Length: 5\r\nContent-Length: 10\r\n\r\nbody1";
        let result = validator.validate_http_request(data);
        assert!(!result.passed);
    }

    #[test]
    fn test_transfer_encoding_with_content_length() {
        let validator = ProtocolValidator::new();
        let data = b"POST / HTTP/1.1\r\nHost: example.com\r\nContent-Length: 5\r\nTransfer-Encoding: chunked\r\n\r\n";
        let result = validator.validate_http_request(data);
        assert!(!result.passed);
    }

    #[test]
    fn test_missing_host_http11() {
        let validator = ProtocolValidator::new();
        let data = b"GET / HTTP/1.1\r\n\r\n";
        let result = validator.validate_http_request(data);
        assert!(!result.passed);
    }

    #[test]
    fn test_slowloris_detection() {
        let validator = ProtocolValidator::new();
        let data = b"GET / HTTP/1.1\r\n";
        let is_slow = validator.detect_slowloris(data, Duration::from_millis(600));
        assert!(is_slow);
    }

    #[test]
    fn test_slowloris_not_detected_fast() {
        let validator = ProtocolValidator::new();
        let data = b"GET / HTTP/1.1\r\n";
        let is_slow = validator.detect_slowloris(data, Duration::from_millis(100));
        assert!(!is_slow);
    }

    #[test]
    fn test_partial_headers() {
        let validator = ProtocolValidator::new();
        let data = b"GET / HTTP/1.1\r\nHost: example.com\r\n";
        let result = validator.validate_http_request(data);
        assert!(!result.passed);
    }

    #[test]
    fn test_post_with_content_length() {
        let validator = ProtocolValidator::new();
        let data = b"POST /submit HTTP/1.1\r\nHost: example.com\r\nContent-Length: 13\r\n\r\nHello, World!";
        let result = validator.validate_http_request(data);
        assert!(result.passed);
        assert_eq!(result.content_length, Some(13));
    }

    #[test]
    fn test_chunked_transfer_encoding() {
        let validator = ProtocolValidator::new();
        let data = b"POST / HTTP/1.1\r\nHost: example.com\r\nTransfer-Encoding: chunked\r\n\r\n";
        let result = validator.validate_http_request(data);
        assert!(result.passed);
        assert!(result.is_chunked);
    }

    #[test]
    fn test_invalid_header_name() {
        let validator = ProtocolValidator::new();
        let data = b"GET / HTTP/1.1\r\nHost: example.com\r\nInvalid\0Name: value\r\n\r\n";
        let result = validator.validate_http_request(data);
        assert!(!result.passed);
    }

    #[test]
    fn test_validate_headers_standalone() {
        let validator = ProtocolValidator::new();
        let headers = [httparse::Header {
            name: "Content-Type",
            value: b"application/json",
        }];
        let result = validator.validate_headers(&headers);
        assert!(result.passed);
    }

    #[test]
    fn test_validate_headers_duplicate_cl() {
        let validator = ProtocolValidator::new();
        let headers = [
            httparse::Header {
                name: "Content-Length",
                value: b"5",
            },
            httparse::Header {
                name: "Content-Length",
                value: b"10",
            },
        ];
        let result = validator.validate_headers(&headers);
        assert!(!result.passed);
    }

    #[test]
    fn test_validate_headers_te_with_cl() {
        let validator = ProtocolValidator::new();
        let headers = [
            httparse::Header {
                name: "Content-Length",
                value: b"5",
            },
            httparse::Header {
                name: "Transfer-Encoding",
                value: b"chunked",
            },
        ];
        let result = validator.validate_headers(&headers);
        assert!(!result.passed);
    }
}
