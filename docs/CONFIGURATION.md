# Configuration Reference

Aegis WAF uses TOML for configuration. The default config path is
`/etc/aegis-waf/config.toml`. Override with `--config <path>` or
the `AEGIS_CONFIG` environment variable.

## Full Configuration Example

```toml
[server]
listen_addr = "0.0.0.0"
tls_port = 8443
metrics_port = 9090
max_connections = 65535
request_timeout_secs = 30
max_body_size_bytes = 10485760  # 10 MiB
http_keep_alive = true
graceful_shutdown_secs = 10

[tls]
cert_path = "/etc/aegis-waf/certs/tls.crt"
key_path = "/etc/aegis-waf/certs/tls.key"
min_protocol_version = "TLSv1.2"
ciphers = [
    "TLS13_CHACHA20_POLY1305_SHA256",
    "TLS13_AES_256_GCM_SHA384",
    "TLS13_AES_128_GCM_SHA256",
]
require_client_cert = false
client_ca_path = "/etc/aegis-waf/certs/ca.crt"

[waf]
enabled = true
rules_path = "/etc/aegis-waf/rules.toml"
default_action = "block"          # block | log | pass
paranoia_level = 1                # 1-4
request_body_inspection = true
response_body_inspection = false
max_rule_depth = 100
arg_separator = "&"

[rate_limit]
enabled = true
requests_per_second = 100
burst_size = 200
window_secs = 60
redis_url = "redis://127.0.0.1:6379"
redis_pool_size = 16
rate_limit_key = "client_ip"      # client_ip | header | jwt_claim
rate_limit_header = "X-Forwarded-For"
rate_limit_actions = ["block"]    # block | log | challenge

[access_control]
enabled = true
allow_list = ["10.0.0.0/8", "172.16.0.0/12"]
deny_list = ["0.0.0.0/0"]
geoip_db_path = "/usr/share/GeoIP/GeoLite2-Country.mmdb"
allowed_countries = ["US", "CA", "GB"]
denied_countries = ["CN", "RU", "KP"]

[proxy]
connect_timeout_secs = 5
read_timeout_secs = 30
write_timeout_secs = 30
max_idle_connections = 256
follow_redirects = false
preserve_host_header = false
add_forwarded_headers = true

[upstream]
default = { url = "http://localhost:8080", weight = 1 }
health_check_path = "/health"
health_check_interval_secs = 10
retry_attempts = 2
retry_backoff_ms = 100

[[upstream.routes]]
match_host = "api.example.com"
backend = { url = "http://api-internal:8081", weight = 1 }

[[upstream.routes]]
match_host = "*.admin.example.com"
backend = { url = "http://admin:8082", weight = 1 }
require_mtls = true

[logging]
level = "info"                    # trace | debug | info | warn | error
format = "json"                   # json | text
access_log_path = "/var/log/aegis-waf/access.log"
error_log_path = "/var/log/aegis-waf/error.log"
access_log_fields = [
    "timestamp",
    "client_ip",
    "method",
    "path",
    "status",
    "latency_ms",
    "bytes_sent",
    "user_agent",
    "waf_action",
]
ansi_colors = false

[metrics]
prometheus_format = true
metrics_path = "/metrics"
buckets = [0.001, 0.005, 0.01, 0.05, 0.1, 0.5, 1.0]
labels = ["host", "status_code", "waf_action"]

[headers]
hide_server = true
server_name = "aegis-waf"
add_security_headers = true
remove_headers = ["X-Powered-By", "Server"]
custom_headers = { "X-Frame-Options" = "DENY" }

[compression]
enabled = true
algorithms = ["gzip", "br", "zstd"]
min_size_bytes = 1024

[cache]
enabled = false
max_size_mb = 256
ttl_secs = 300
cacheable_methods = ["GET", "HEAD"]

[admin]
enabled = true
listen_addr = "127.0.0.1"
port = 9091
api_key = "${AEGIS_ADMIN_API_KEY}"

[auth]
enabled = false
jwt_secret = "${AEGIS_JWT_SECRET}"
jwt_issuer = "aegis-waf"
jwt_expiry_secs = 3600
cookie_name = "aegis_session"
```

## Server

| Key                      | Type   | Default     | Description                     |
| ------------------------ | ------ | ----------- | ------------------------------- |
| `listen_addr`            | string | `"0.0.0.0"` | TLS listen address              |
| `tls_port`               | int    | `8443`      | TLS listen port                 |
| `metrics_port`           | int    | `9090`      | Prometheus metrics port         |
| `max_connections`        | int    | `65535`     | Max concurrent connections      |
| `request_timeout_secs`   | int    | `30`        | Request read timeout            |
| `max_body_size_bytes`    | int    | `10485760`  | Max request body (bytes)        |
| `http_keep_alive`        | bool   | `true`      | Enable HTTP keep-alive          |
| `graceful_shutdown_secs` | int    | `10`        | Graceful shutdown wait          |

## TLS

| Key                    | Type     | Default    | Description                  |
| ---------------------- | -------- | ---------- | ---------------------------- |
| `cert_path`            | string   | *required* | TLS certificate file (PEM)   |
| `key_path`             | string   | *required* | TLS private key file (PEM)   |
| `min_protocol_version` | string   | `"TLSv1.2"`| Minimum TLS version          |
| `ciphers`              | string[] | *secure*   | Allowed cipher suites        |
| `require_client_cert`  | bool     | `false`    | Enable mTLS                  |
| `client_ca_path`       | string   | -          | CA cert for client auth      |

## WAF Engine

| Key                         | Type   | Default    | Description                 |
| --------------------------- | ------ | ---------- | --------------------------- |
| `enabled`                   | bool   | `true`     | Enable WAF inspection       |
| `rules_path`                | string | *required* | Path to WAF rules file      |
| `default_action`            | string | `"block"`  | Default when no rule match  |
| `paranoia_level`            | int    | `1`        | 1 (low) to 4 (paranoid)     |
| `request_body_inspection`   | bool   | `true`     | Inspect POST/PUT bodies     |
| `response_body_inspection`  | bool   | `false`    | Inspect upstream responses  |
| `max_rule_depth`            | int    | `100`      | Max recursion for chained   |
| `arg_separator`             | string | `"&"`      | Query string separator      |

### WAF Rules File Format

```toml
[[rules]]
id = "SQLI-001"
description = "Generic SQL injection detection"
phase = "request"
locations = ["args", "body", "headers", "cookies"]
pattern = "(?i)(union\\s+select|select.+from|--|;--)"
action = "block"
severity = "critical"
score = 10
transform = ["lowercase", "removeWhitespace"]

[[rules]]
id = "XSS-001"
description = "Cross-site scripting detection"
phase = "request"
locations = ["args", "body", "headers"]
pattern = "(?i)(<script|javascript:|onerror=|onload=)"
action = "block"
severity = "high"
score = 8

[[rules]]
id = "PATH-001"
description = "Path traversal detection"
phase = "request"
locations = ["path"]
pattern = "\\.\\.[/\\\\]"
action = "block"
severity = "high"
score = 7
```

Rule fields:

| Field         | Type     | Description                                    |
| ------------- | -------- | ---------------------------------------------- |
| `id`          | string   | Unique rule identifier                         |
| `description` | string   | Human-readable description                     |
| `phase`       | string   | `request` or `response`                        |
| `locations`   | string[] | `args`, `body`, `headers`, `cookies`, `path`   |
| `pattern`     | string   | Regex pattern to match                         |
| `action`      | string   | `block`, `log`, `pass`, `challenge`            |
| `severity`    | string   | `critical`, `high`, `medium`, `low`            |
| `score`       | int      | Anomaly score contribution                     |
| `transform`   | string[] | Pre-match transforms                           |

## Rate Limiting

| Key                  | Type   | Default       | Description                   |
| -------------------- | ------ | ------------- | ----------------------------- |
| `enabled`            | bool   | `true`        | Enable rate limiting          |
| `requests_per_second`| int    | `100`         | Sustained rate                |
| `burst_size`         | int    | `200`         | Maximum burst                 |
| `window_secs`        | int    | `60`          | Sliding window size           |
| `redis_url`          | string | -             | Redis for distributed limits  |
| `redis_pool_size`    | int    | `16`          | Redis connection pool         |
| `rate_limit_key`     | string | `"client_ip"` | Key for rate limit grouping   |
| `rate_limit_header`  | string | -             | Header to extract client IP   |
| `rate_limit_actions` | string[]| `["block"]`  | Action when limit exceeded    |

## Access Control

| Key                | Type     | Default | Description                  |
| ------------------ | -------- | ------- | ---------------------------- |
| `enabled`          | bool     | `false` | Enable ACL                   |
| `allow_list`       | string[] | `[]`    | Allowed CIDR ranges          |
| `deny_list`        | string[] | `[]`    | Denied CIDR ranges           |
| `geoip_db_path`    | string   | -       | MaxMind GeoLite2 DB path     |
| `allowed_countries`| string[] | `[]`    | Allowed ISO country codes    |
| `denied_countries` | string[] | `[]`    | Denied ISO country codes     |

## Upstream Proxy

| Key                       | Type   | Default | Description                  |
| ------------------------- | ------ | ------- | ---------------------------- |
| `default.url`             | string | -       | Default upstream URL         |
| `default.weight`          | int    | `1`     | Load balancing weight        |
| `health_check_path`       | string | -       | Health check endpoint        |
| `health_check_interval_secs`| int  | `10`    | Health check interval        |
| `retry_attempts`          | int    | `2`     | Retry on upstream failure    |
| `retry_backoff_ms`        | int    | `100`   | Backoff between retries      |

### Route-based Upstreams

```toml
[[upstream.routes]]
match_host = "api.example.com"
backend = { url = "http://api-internal:8081", weight = 1 }

[[upstream.routes]]
match_path = "/admin/*"
backend = { url = "http://admin:8082", weight = 1 }
```

Route fields:

| Field          | Type   | Description                |
| -------------- | ------ | -------------------------- |
| `match_host`   | string | Host header match (glob)   |
| `match_path`   | string | URL path match (glob)      |
| `backend.url`  | string | Upstream URL               |
| `backend.weight`| int   | Load balance weight        |
| `require_mtls` | bool   | Require mTLS for this route|

## Logging

| Key                | Type     | Default                         | Description           |
| ------------------ | -------- | ------------------------------- | --------------------- |
| `level`            | string   | `"info"`                        | Log level             |
| `format`           | string   | `"json"`                        | `json` or `text`      |
| `access_log_path`  | string   | -                               | Access log output     |
| `error_log_path`   | string   | -                               | Error log output      |
| `access_log_fields`| string[] | *all*                           | Fields to include     |
| `ansi_colors`      | bool     | `false`                         | Terminal colors       |

Available access log fields:

```
timestamp, client_ip, method, path, query, http_version,
status, latency_ms, bytes_sent, bytes_received, user_agent,
referer, waf_action, waf_rule_id, waf_score, tls_version,
tls_cipher, upstream_addr, request_id
```

## Environment Variable Substitution

Any config value can reference an environment variable with `${VAR_NAME}`:

```toml
[admin]
api_key = "${AEGIS_ADMIN_API_KEY}"

[rate_limit]
redis_url = "${REDIS_URL}"
```
