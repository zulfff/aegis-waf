# Security Guide

## Threat Model

### Trust Boundaries

```
┌───────────────────────────────────────────────────────────┐
│                     Untrusted Zone                         │
│                                                           │
│   ┌─────────┐   ┌─────────┐   ┌──────────────┐          │
│   │ Malicious│   │ Legit   │   │  Automated   │          │
│   │  Actor   │   │  User   │   │    Scanner   │          │
│   └────┬─────┘   └────┬────┘   └──────┬───────┘          │
│        └──────────────┼───────────────┘                  │
│                       │                                   │
├───────────────────────┼───────────────────────────────────┤
│                   Trust Boundary                          │
│                       │                                   │
│              ┌────────▼────────┐                          │
│              │   AEGIS WAF     │  ── Zero Trust Zone      │
│              └────────┬────────┘                          │
│                       │                                   │
├───────────────────────┼───────────────────────────────────┤
│                   Trust Boundary                          │
│                       │                                   │
│              ┌────────▼────────┐                          │
│              │    Upstream     │  ── Internal Zone         │
│              └─────────────────┘                          │
└───────────────────────────────────────────────────────────┘
```

### Threat Categories

| Threat                          | Severity | Mitigation                              |
| ------------------------------- | -------- | --------------------------------------- |
| SQL Injection                   | Critical | WAF rules (SQLI-*)                      |
| Cross-Site Scripting (XSS)      | High     | WAF rules (XSS-*), CSP headers          |
| Command Injection               | Critical | WAF rules (CMDI-*)                      |
| Path Traversal                  | High     | WAF rules (PATH-*), path normalization  |
| Request Smuggling               | Critical | Strict HTTP parsing, HTTP/2 enforcement |
| Rate-Limit Bypass               | Medium   | Token bucket with hash-based keys       |
| TLS Downgrade                   | High     | Minimum TLS 1.2 enforced                |
| Credential Exposure             | Critical | Env var substitution, no plaintext logs |
| Denial of Service               | High     | Connection limits, body size limits     |
| WAF Rule Bypass                 | High     | Paranoia levels, chained rules          |
| Configuration Injection         | Medium   | Schema validation on load               |
| Side-Channel (Timing)           | Low      | Constant-time comparisons               |

## TLS Configuration

### Recommended Settings

```toml
[tls]
min_protocol_version = "TLSv1.2"
ciphers = [
    "TLS13_CHACHA20_POLY1305_SHA256",
    "TLS13_AES_256_GCM_SHA384",
    "TLS13_AES_128_GCM_SHA256",
]
```

### Cipher Suite Prioritization

The default cipher order prefers forward secrecy and authenticated
encryption (AEAD):

1. CHACHA20_POLY1305 (faster on CPUs without AES-NI)
2. AES_256_GCM (strongest, hardware-accelerated)
3. AES_128_GCM (balanced security/performance)

TLS 1.0 and 1.1 are disabled. TLS 1.2 is the minimum with only AEAD
ciphers.

### Certificate Management

```bash
# Generate ECDSA certificate (P-256, recommended)
openssl ecparam -genkey -name prime256v1 -out tls.key
openssl req -new -x509 -days 90 -key tls.key -out tls.crt \
  -subj "/CN=aegis-waf.example.com"

# Rotate certificates without downtime
aegis-waf reload          # SIGHUP triggers cert reload
```

## WAF Hardening

### Paranoia Levels

| Level | Description                       | When to Use                    |
| ----- | --------------------------------- | ------------------------------ |
| 1     | Core rules, low false positives   | General purpose                |
| 2     | Extended rules, moderate FP rate  | Financial / healthcare apps    |
| 3     | Aggressive rules, higher FP rate  | High-security environments     |
| 4     | Maximum coverage, expect false +  | Incident response / forensics  |

### Custom Rule Creation

Rules should be tested before deployment:

```bash
# Validate rules
aegis-waf validate --rules custom-rules.toml

# Test with curl (dry-run mode)
curl -k https://localhost:8443/test \
  -H "X-Aegis-Dry-Run: true" \
  -d "test payload"

# Check logs for WAF action
tail -f /var/log/aegis-waf/access.log | jq '.waf_action'
```

### Rule Evasion Prevention

Common evasion techniques and countermeasures:

| Technique              | Countermeasure                                  |
| ---------------------- | ----------------------------------------------- |
| URL encoding           | `urlDecode` transform                           |
| HTML entities          | `htmlEntityDecode` transform                    |
| Mixed case             | `lowercase` transform                           |
| Whitespace insertion   | `removeWhitespace` transform                    |
| Null byte injection    | Null byte stripping in parser                   |
| Unicode normalization  | NFC normalization before WAF inspection         |
| Chunked encoding       | Full body reassembly before inspection          |
| Header splitting       | CR/LF encoding enforcement                      |

## Rate Limiting

### Key Selection

| Key Type         | Use Case                            |
| ---------------- | ----------------------------------- |
| `client_ip`      | General protection (default)        |
| `header`         | Reverse proxy behind CDN (use XFF)  |
| `jwt_claim`      | Authenticated API endpoint          |

When using `header` key type behind a proxy:

```toml
[rate_limit]
rate_limit_key = "header"
rate_limit_header = "X-Forwarded-For"
# Only trust XFF from known proxies
[access_control]
allow_list = ["10.0.0.0/8"]  # Your CDN/proxy IPs
```

### Distributed Rate Limiting

Redis provides consistent rate limiting across replicas:

```
┌─────────┐     ┌─────────┐     ┌─────────┐
│ WAF-01  │     │ WAF-02  │     │ WAF-03  │
└────┬─────┘     └────┬─────┘     └────┬─────┘
     └────────────────┼────────────────┘
                      │
              ┌───────▼───────┐
              │     Redis     │
              │  (sentinel /  │
              │   cluster)    │
              └───────────────┘
```

Redis configuration:

```toml
[rate_limit]
redis_url = "redis://:password@redis-sentinel:26379?service=mymaster"
redis_pool_size = 32
```

## Security Headers

Enable automatic security headers:

```toml
[headers]
add_security_headers = true
custom_headers = {
    "X-Frame-Options" = "DENY",
    "X-Content-Type-Options" = "nosniff",
    "Referrer-Policy" = "strict-origin-when-cross-origin",
    "Permissions-Policy" = "camera=(), microphone=(), geolocation=()",
}
```

Headers automatically added when `add_security_headers = true`:

| Header                       | Value                         |
| ---------------------------- | ----------------------------- |
| Strict-Transport-Security    | max-age=31536000; includeSubDomains |
| X-Content-Type-Options       | nosniff                       |
| X-Frame-Options              | DENY                          |
| X-XSS-Protection             | 0 (deprecated, removed by CSP)|

## Audit Logging

### Sensitive Data Masking

```toml
[logging]
access_log_fields = [
    "timestamp", "client_ip", "method", "path",
    "status", "latency_ms", "waf_action", "request_id"
]
# IMPORTANT: Never log raw bodies, cookies, or authorization headers
```

Fields excluded by default from access logs:

- `Authorization` header
- `Cookie` header
- Request body
- Response body
- `X-Api-Key` and similar headers

### Log Retention

```bash
# Rotate logs daily, keep 30 days
cat > /etc/logrotate.d/aegis-waf << 'EOF'
/var/log/aegis-waf/*.log {
    daily
    rotate 30
    compress
    delaycompress
    missingok
    notifempty
    sharedscripts
    postrotate
        /usr/local/bin/aegis-waf reload --signal usr1
    endscript
}
EOF
```

## Deployment Checklist

### Pre-Production

- [ ] TLS certificates are from a trusted CA (not self-signed)
- [ ] TLS cert and key files are `chmod 600`
- [ ] Config file is `chmod 640`, owned by aegis-waf user
- [ ] Admin API is not exposed to the internet
- [ ] Environment variables for secrets, not hardcoded
- [ ] Rate limiting is configured and tested
- [ ] WAF rules validated with `aegis-waf validate`
- [ ] Log drain / SIEM integration configured
- [ ] Monitoring alerts for error rate and WAF blocks
- [ ] Run as non-root user

### Production

- [ ] Redis with authentication and TLS (if external)
- [ ] Read-only root filesystem for containers
- [ ] No privileged containers
- [ ] Network policies restricting egress/ingress
- [ ] Regular rule updates and testing
- [ ] Incident response plan for WAF bypass
- [ ] Backup and restore procedure documented

## Incident Response

### If a WAF bypass is detected:

1. **Isolate**: Increase paranoia level temporarily
   ```bash
   curl -X POST http://localhost:9091/admin/config \
     -H "X-Api-Key: $AEGIS_ADMIN_API_KEY" \
     -d '{"waf":{"paranoia_level":4}}'
   ```

2. **Investigate**: Check logs for the bypass pattern
   ```bash
   grep "action.*pass" /var/log/aegis-waf/access.log | jq .
   ```

3. **Mitigate**: Add a custom blocking rule
   ```toml
   [[rules]]
   id = "EMERGENCY-001"
   pattern = "pattern_that_bypassed"
   action = "block"
   severity = "critical"
   ```

4. **Recover**: Deploy permanent fix, reset paranoia level

## Reporting Vulnerabilities

See [SECURITY.md](../.github/SECURITY.md) for our vulnerability
disclosure policy.

## Memory Safety

Aegis WAF is written in Rust, providing memory safety guarantees:

- **No use-after-free**: Ownership and borrowing prevent dangling pointers
- **No buffer overflows**: Bounds checking on all array/slice access
- **No data races**: Thread safety enforced by `Send`/`Sync` traits
- **No null dereferences**: `Option<T>` for nullable values
- **Zero `unsafe` in parsing paths**: All HTTP and WAF parsing is safe Rust

The codebase maintains a zero-`unsafe` policy in the core request
parsing and rule matching paths. Any `unsafe` block (if required for
FFI or performance) must be documented with `// SAFETY:` comments and
reviewed independently.
