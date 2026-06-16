# API Reference

## Health & Metrics API

These endpoints are served on the metrics port (default `9090`).

### GET /health

Health check endpoint. Returns the current health status of the server.

**Request:**

```
GET /health HTTP/1.1
Host: localhost:9090
```

**Response (200 OK):**

```json
{
  "status": "healthy",
  "version": "1.0.0",
  "uptime_secs": 86400,
  "connections_active": 42,
  "waf_rules_loaded": 156,
  "upstream_healthy": true,
  "rate_limiter": "active"
}
```

| Field               | Type    | Description                       |
| ------------------- | ------- | --------------------------------- |
| `status`            | string  | `healthy`, `degraded`, `unhealthy`|
| `version`           | string  | Server version                    |
| `uptime_secs`       | int     | Seconds since startup             |
| `connections_active`| int     | Current active connections        |
| `waf_rules_loaded`  | int     | Number of rules loaded            |
| `upstream_healthy`  | bool    | Upstream health check status      |
| `rate_limiter`      | string  | `active`, `degraded`, `disabled`  |

---

### GET /ready

Readiness probe. Returns 200 when the server is ready to accept traffic.

**Request:**

```
GET /ready HTTP/1.1
Host: localhost:9090
```

**Response (200 OK):**

```json
{
  "ready": true,
  "tls_bound": true,
  "waf_initialized": true,
  "redis_connected": true
}
```

**Response (503 Service Unavailable):**

```json
{
  "ready": false,
  "tls_bound": true,
  "waf_initialized": false,
  "redis_connected": false,
  "reason": "WAF rules failed to load"
}
```

---

### GET /metrics

Prometheus-formatted metrics endpoint.

**Request:**

```
GET /metrics HTTP/1.1
Host: localhost:9090
```

**Response (200 OK, text/plain):**

```
# HELP aegis_http_requests_total Total HTTP requests processed
# TYPE aegis_http_requests_total counter
aegis_http_requests_total{host="api.example.com",status="200"} 15234
aegis_http_requests_total{host="api.example.com",status="403"} 89

# HELP aegis_http_request_duration_seconds Request duration histogram
# TYPE aegis_http_request_duration_seconds histogram
aegis_http_request_duration_seconds_bucket{le="0.001"} 1000
aegis_http_request_duration_seconds_bucket{le="0.005"} 5000
aegis_http_request_duration_seconds_bucket{le="0.01"} 8000
aegis_http_request_duration_seconds_sum 123.45
aegis_http_request_duration_seconds_count 15234

# HELP aegis_waf_blocks_total Total WAF blocks
# TYPE aegis_waf_blocks_total counter
aegis_waf_blocks_total{rule_id="SQLI-001",severity="critical"} 12
aegis_waf_blocks_total{rule_id="XSS-001",severity="high"} 45

# HELP aegis_ratelimit_throttled_total Total rate limit rejections
# TYPE aegis_ratelimit_throttled_total counter
aegis_ratelimit_throttled_total 3

# HELP aegis_connections_active Active connections
# TYPE aegis_connections_active gauge
aegis_connections_active 42

# HELP aegis_tls_handshakes_total Total TLS handshakes
# TYPE aegis_tls_handshakes_total counter
aegis_tls_handshakes_total{version="TLSv1.3"} 10000
aegis_tls_handshakes_total{version="TLSv1.2"} 5234
```

### Available Metrics

| Metric                                    | Type      | Labels                                  |
| ----------------------------------------- | --------- | --------------------------------------- |
| `aegis_http_requests_total`               | Counter   | `host`, `method`, `status`, `waf_action`|
| `aegis_http_request_duration_seconds`     | Histogram | `host`, `method`, `status`              |
| `aegis_http_request_size_bytes`           | Histogram | `host`                                  |
| `aegis_http_response_size_bytes`          | Histogram | `host`                                  |
| `aegis_waf_blocks_total`                  | Counter   | `rule_id`, `severity`, `action`         |
| `aegis_waf_matches_total`                 | Counter   | `rule_id`, `phase`                      |
| `aegis_waf_score_current`                 | Gauge     | `host`                                  |
| `aegis_ratelimit_throttled_total`         | Counter   | `key_type`                              |
| `aegis_ratelimit_bucket_level`            | Gauge     | `client_hash`                           |
| `aegis_connections_active`                | Gauge     | -                                       |
| `aegis_connections_total`                 | Counter   | -                                       |
| `aegis_tls_handshakes_total`              | Counter   | `version`, `cipher`                     |
| `aegis_upstream_health_status`            | Gauge     | `upstream_addr`                         |
| `aegis_upstream_requests_total`           | Counter   | `upstream_addr`, `status`               |
| `aegis_upstream_request_duration_seconds` | Histogram | `upstream_addr`                         |
| `aegis_redis_pool_size`                   | Gauge     | -                                       |
| `aegis_redis_pool_available`              | Gauge     | -                                       |

---

## Admin API

The Admin API runs on a separate port (default `9091`) and requires
authentication.

### Authentication

All Admin API requests require an API key:

```
X-Api-Key: <admin_api_key>
```

---

### GET /admin/config

Retrieve the current running configuration.

**Request:**

```
GET /admin/config HTTP/1.1
Host: localhost:9091
X-Api-Key: <key>
```

**Response (200 OK):**

```json
{
  "server": {
    "listen_addr": "0.0.0.0",
    "tls_port": 8443,
    "metrics_port": 9090
  },
  "waf": {
    "enabled": true,
    "paranoia_level": 1,
    "rules_loaded": 156
  },
  "rate_limit": {
    "enabled": true,
    "requests_per_second": 100
  }
}
```

---

### PUT /admin/config

Update configuration at runtime. Only a subset of fields support hot reload
(see Hot-Reloadable Fields below).

**Request:**

```
PUT /admin/config HTTP/1.1
Host: localhost:9091
X-Api-Key: <key>
Content-Type: application/json

{
  "waf": {
    "paranoia_level": 2
  },
  "rate_limit": {
    "requests_per_second": 200
  }
}
```

**Response (200 OK):**

```json
{
  "status": "applied",
  "restart_required": false,
  "changes": ["waf.paranoia_level", "rate_limit.requests_per_second"]
}
```

**Response (400 Bad Request):**

```json
{
  "status": "rejected",
  "error": "Invalid field value",
  "details": "paranoia_level must be between 1 and 4"
}
```

**Hot-Reloadable Fields:**

| Field                              | Requires Reload |
| ---------------------------------- | --------------- |
| `waf.enabled`                      | No              |
| `waf.paranoia_level`               | No              |
| `waf.default_action`               | No              |
| `rate_limit.enabled`               | No              |
| `rate_limit.requests_per_second`   | No              |
| `rate_limit.burst_size`            | No              |
| `logging.level`                    | No              |
| `waf.rules_path`                   | Yes (reload)    |
| `tls.cert_path`                    | Yes (reload)    |
| `server.tls_port`                  | Yes (restart)   |

---

### POST /admin/reload

Trigger a configuration and rule reload.

**Request:**

```
POST /admin/reload HTTP/1.1
Host: localhost:9091
X-Api-Key: <key>
```

**Response (200 OK):**

```json
{
  "status": "reloaded",
  "config_applied": true,
  "rules_applied": true,
  "rules_loaded": 158,
  "rules_errors": [],
  "duration_ms": 42
}
```

**Response (500 Internal Server Error):**

```json
{
  "status": "failed",
  "config_applied": true,
  "rules_applied": false,
  "rules_errors": [
    {
      "line": 45,
      "rule_id": "CUSTOM-001",
      "error": "Invalid regex: unmatched parenthesis"
    }
  ]
}
```

---

### GET /admin/stats

Retrieve current runtime statistics.

**Request:**

```
GET /admin/stats HTTP/1.1
Host: localhost:9091
X-Api-Key: <key>
```

**Response (200 OK):**

```json
{
  "uptime_secs": 3600,
  "connections": {
    "active": 42,
    "total": 10000,
    "max_concurrent": 150
  },
  "requests": {
    "total": 50000,
    "blocked": 89,
    "passed": 49811,
    "challenged": 100
  },
  "rate_limiter": {
    "throttled": 3,
    "active_buckets": 1500
  },
  "waf": {
    "rules_matched": 500,
    "top_rules": [
      {"rule_id": "SQLI-001", "matches": 120},
      {"rule_id": "XSS-001", "matches": 85},
      {"rule_id": "PATH-001", "matches": 45}
    ]
  },
  "upstream": {
    "healthy": true,
    "latency_p50_ms": 12,
    "latency_p99_ms": 45
  }
}
```

---

### GET /admin/stats/connections

List current connections.

**Request:**

```
GET /admin/stats/connections HTTP/1.1
Host: localhost:9091
X-Api-Key: <key>
```

**Response (200 OK):**

```json
{
  "connections": [
    {
      "id": "01JQKXZ...",
      "client_ip": "203.0.113.1",
      "started_at": "2025-01-15T10:30:00Z",
      "duration_ms": 1200,
      "method": "GET",
      "path": "/api/users",
      "status": 200,
      "tls_version": "TLSv1.3"
    }
  ],
  "total": 1
}
```

**Query Parameters:**

| Parameter | Type   | Default | Description                       |
| --------- | ------ | ------- | --------------------------------- |
| `limit`   | int    | `100`   | Maximum connections to return     |
| `filter`  | string | -       | Filter by status: `active`, `idle`|

---

### DELETE /admin/cache

Clears the internal response cache.

**Request:**

```
DELETE /admin/cache HTTP/1.1
Host: localhost:9091
X-Api-Key: <key>
```

**Response (200 OK):**

```json
{
  "status": "flushed",
  "entries_removed": 256
}
```

---

### POST /admin/ban

Temporarily ban an IP address.

**Request:**

```
POST /admin/ban HTTP/1.1
Host: localhost:9091
X-Api-Key: <key>
Content-Type: application/json

{
  "ip": "203.0.113.42",
  "duration_secs": 3600,
  "reason": "Automated attack detected"
}
```

**Response (200 OK):**

```json
{
  "status": "banned",
  "ip": "203.0.113.42",
  "expires_at": "2025-01-15T11:30:00Z",
  "reason": "Automated attack detected"
}
```

---

### DELETE /admin/ban/{ip}

Remove an IP ban.

```
DELETE /admin/ban/203.0.113.42 HTTP/1.1
Host: localhost:9091
X-Api-Key: <key>
```

**Response (200 OK):**

```json
{
  "status": "unbanned",
  "ip": "203.0.113.42"
}
```

---

### GET /admin/bans

List active bans.

**Response (200 OK):**

```json
{
  "bans": [
    {
      "ip": "203.0.113.42",
      "expires_at": "2025-01-15T11:30:00Z",
      "reason": "Automated attack detected",
      "duration_remaining_secs": 1800
    }
  ]
}
```

---

## Error Responses

All API endpoints return standard error formats.

### 401 Unauthorized

```json
{
  "error": "unauthorized",
  "message": "Missing or invalid API key"
}
```

### 403 Forbidden

```json
{
  "error": "forbidden",
  "message": "Admin API is disabled"
}
```

### 404 Not Found

```json
{
  "error": "not_found",
  "message": "Unknown endpoint"
}
```

### 429 Too Many Requests

```json
{
  "error": "rate_limited",
  "message": "Admin API rate limit exceeded",
  "retry_after_secs": 30
}
```

### 500 Internal Server Error

```json
{
  "error": "internal_error",
  "message": "An unexpected error occurred",
  "request_id": "01JQKXY..."
}
```

## Rate Limiting

The Admin API is rate-limited independently of the main WAF traffic.
Defaults:

- 10 requests per second per IP on the Admin API
- Configurable via `admin.rate_limit` in config.toml

## API Versioning

The current API version is `v1`. The version is implicit in the URL prefix:

```
http://localhost:9091/admin/v1/stats
```

Future breaking changes will increment the version.
