# Architecture

## System Overview

Aegis WAF is a layer-7 reverse proxy with integrated WAF capabilities,
built on Tokio's async runtime in Rust. It sits between clients and
upstream applications, inspecting every request and response.

```
                          ┌─────────────┐
                          │   Clients    │
                          └──────┬───────┘
                                 │ HTTPS (TLS 1.2/1.3)
                                 │
                    ┌────────────▼────────────┐
                    │     TLS Listener         │
                    │   (rustls / tokio-rustls)│
                    └────────────┬────────────┘
                                 │
                    ┌────────────▼────────────┐
                    │   Connection Handler     │
                    │   (connection pool)       │
                    └────────────┬────────────┘
                                 │
              ┌──────────────────┼──────────────────┐
              │                  │                  │
    ┌─────────▼────────┐ ┌──────▼──────┐ ┌─────────▼────────┐
    │  Access Control   │ │  WAF Engine  │ │  Rate Limiter    │
    │  (IP/GeoIP ACL)  │ │ (rule match) │ │  (token bucket)  │
    └─────────┬────────┘ └──────┬──────┘ └─────────┬────────┘
              │                  │                  │
              └──────────────────┼──────────────────┘
                                 │
                    ┌────────────▼────────────┐
                    │    Request Sanitizer     │
                    │ (header normalization)   │
                    └────────────┬────────────┘
                                 │
                    ┌────────────▼────────────┐
                    │   Upstream Router        │
                    │ (host/path-based routing) │
                    └────────────┬────────────┘
                                 │
                  ┌──────────────┼──────────────┐
                  │              │              │
         ┌────────▼─────┐ ┌─────▼──────┐ ┌─────▼──────┐
         │  Upstream A   │ │ Upstream B  │ │ Upstream C  │
         └──────────────┘ └────────────┘ └────────────┘
```

## Component Details

### TLS Listener

```
┌──────────────────────────────────────────┐
│              TLS Listener                 │
│                                           │
│  ┌─────────────┐  ┌───────────────────┐  │
│  │   Acceptor   │  │  Cert Resolver     │  │
│  │  (TCP bind)  │  │  (SNI-based)       │  │
│  └──────┬──────┘  └───────────────────┘  │
│         │                                 │
│  ┌──────▼──────────────────────────────┐ │
│  │        TLS Handshake                 │ │
│  │  - ALPN negotiation (h2, http/1.1)  │ │
│  │  - mTLS verification (optional)     │ │
│  │  - Cipher suite selection           │ │
│  └─────────────────────────────────────┘ │
└──────────────────────────────────────────┘
```

- Uses `rustls` for TLS implementation
- Supports HTTP/1.1 and HTTP/2 via ALPN negotiation
- SNI-based certificate selection for multi-tenant deployments
- mTLS support with configurable CA trust stores

### Connection Handler

Manages a pool of persistent connections to upstream servers:

```
┌───────────────────────────────────────────┐
│           Connection Handler               │
│                                            │
│  ┌──────────────┐  ┌───────────────────┐  │
│  │  Listener     │  │  Connection Pool   │  │
│  │  (accept)     │  │  (idle reuse)      │  │
│  └──────┬───────┘  └───────────────────┘  │
│         │                                  │
│  ┌──────▼───────────────────────────────┐ │
│  │          HTTP Parser (httparse)       │ │
│  │  - Request line parsing              │ │
│  │  - Header parsing & validation       │ │
│  │  - Body buffering / streaming         │ │
│  └──────────────────────────────────────┘ │
│                                            │
│  ┌──────────────────────────────────────┐ │
│  │          Request Context              │ │
│  │  - Metadata extraction                │ │
│  │  - Request ID generation (ULID)       │ │
│  │  - Span context (tracing)             │ │
│  └──────────────────────────────────────┘ │
└───────────────────────────────────────────┘
```

### WAF Engine

```
┌───────────────────────────────────────────────┐
│                WAF Engine                      │
│                                                │
│  ┌─────────────────────────────────────────┐  │
│  │         Rule Compiler                     │  │
│  │  ┌───────────┐ ┌───────────┐ ┌────────┐  │  │
│  │  │  Regex    │ │  CIDR     │ │  Glob  │  │  │
│  │  │  Compiler  │ │  Compiler │ │  Comp  │  │  │
│  │  └───────────┘ └───────────┘ └────────┘  │  │
│  └─────────────────────────────────────────┘  │
│                                                │
│  ┌─────────────────────────────────────────┐  │
│  │         Rule Matcher                     │  │
│  │                                          │  │
│  │  Phases:                                 │  │
│  │  ┌──────────┐ ┌──────────┐ ┌─────────┐  │  │
│  │  │ Phase 1  │ │ Phase 2  │ │ Phase 3 │  │  │
│  │  │ Headers  │─▶│ Body     │─▶│ Response│  │  │
│  │  │ + URL    │  │ + Args   │  │         │  │  │
│  │  └──────────┘ └──────────┘ └─────────┘  │  │
│  └─────────────────────────────────────────┘  │
│                                                │
│  ┌─────────────────────────────────────────┐  │
│  │       Anomaly Scorer                     │  │
│  │  - Cumulative score per transaction      │  │
│  │  - Threshold-based blocking              │  │
│  │  - Paranoia level multiplier             │  │
│  └─────────────────────────────────────────┘  │
└───────────────────────────────────────────────┘
```

**Rule Matching Phases:**

| Phase   | Inspected Data         | Example Rules                  |
| ------- | ---------------------- | ------------------------------ |
| 1       | URL, headers, cookies  | SQLi in query params, UA block |
| 2       | Request body           | XSS in POST, file upload scan  |
| 3       | Response body          | Data leak detection             |

**Transformation Pipeline (per rule):**

```
Raw Input → lowercase → removeWhitespace → urlDecode → htmlEntityDecode → Pattern Match
```

### Rate Limiter

```
┌────────────────────────────────────┐
│           Rate Limiter              │
│                                     │
│  ┌────────────────────────────────┐│
│  │      Key Extractor              ││
│  │  ┌───────┐ ┌───────┐ ┌───────┐ ││
│  │  │  IP   │ │Header │ │ JWT   │ ││
│  │  │  Key  │ │ Key   │ │ Key   │ ││
│  │  └───┬───┘ └───┬───┘ └───┬───┘ ││
│  └──────┼─────────┼─────────┼─────┘│
│         └─────────┼─────────┘      │
│          ┌────────▼────────┐       │
│          │  Token Bucket   │       │
│          │  ┌────────────┐ │       │
│          │  │  In-Memory  │ │       │
│          │  │  (single)   │ │       │
│          │  ├────────────┤ │       │
│          │  │   Redis     │ │       │
│          │  │ (distributed│ │       │
│          │  └────────────┘ │       │
│          └─────────────────┘       │
└────────────────────────────────────┘
```

**Token Bucket Algorithm:**

```
rate  = requests_per_second
burst = burst_size

if (tokens - cost) >= 0:
    tokens -= cost
    ALLOW
else:
    DENY / CHALLENGE

tokens = min(tokens + rate * elapsed, burst)
```

When Redis is configured, token state is stored under the key
`aegis:ratelimit:{key_hash}:{window}` with TTL-based expiry.

### Upstream Router

```
┌──────────────────────────────────────┐
│          Upstream Router              │
│                                       │
│  ┌──────────────────────────────────┐│
│  │      Route Resolution             ││
│  │  ┌──────────┐ ┌────────────────┐ ││
│  │  │  Host    │ │  Path Match     │ ││
│  │  │  Match   │ │  (glob/regex)  │ ││
│  │  └────┬─────┘ └───────┬────────┘ ││
│  │       └───────┬───────┘          ││
│  │        ┌──────▼──────┐           ││
│  │        │   Backend   │           ││
│  │        │  Selection  │           ││
│  │        └──────┬──────┘           ││
│  └───────────────┼──────────────────┘│
│                  │                   │
│  ┌───────────────▼──────────────────┐│
│  │        Load Balancer              ││
│  │  - Weighted round-robin           ││
│  │  - Least connections (optional)   ││
│  │  - Health check integration       ││
│  │  - Circuit breaker                ││
│  └──────────────────────────────────┘│
└──────────────────────────────────────┘
```

### Observability Pipeline

```
┌─────────────────────────────────────────┐
│            Observability                 │
│                                          │
│  ┌──────────────┐  ┌──────────────────┐ │
│  │   Metrics    │  │     Logging       │ │
│  │  /metrics    │  │  JSON / text      │ │
│  │  Prometheus  │  │  stdout / file    │ │
│  └──────────────┘  └──────────────────┘ │
│                                          │
│  ┌──────────────────────────────────────┐│
│  │              Tracing (OTLP)           ││
│  │  - Request span lifecycle            ││
│  │  - WAF rule match events             ││
│  │  - Upstream call spans               ││
│  │  - Rate limit decisions              ││
│  └──────────────────────────────────────┘│
└─────────────────────────────────────────┘
```

## Data Flow

### Request Lifecycle

```
TIME ──────────────────────────────────────────────────────────▶

 CLIENT          AEGIS WAF               UPSTREAM
   │                │                       │
   │──TLS Hello───▶│                       │
   │◀──TLS Accept──│                       │
   │──HTTP Req────▶│                       │
   │               │──Parse Request───────▶│
   │               │──Extract Metadata────▶│
   │               │──ACL Check───────────▶│
   │               │──Rate Limit Check────▶│
   │               │──WAF Phase 1────────▶│
   │               │──WAF Phase 2────────▶│
   │               │──Sanitize Headers───▶│
   │               │──Route Resolution───▶│
   │               │──Connect Upstream───▶│
   │               │                      │──Process Request─▶│
   │               │                      │◀──Response────────│
   │               │──WAF Phase 3────────▶│
   │               │──Process Response───▶│
   │               │──Log & Metrics──────▶│
   │◀──HTTP Resp───│                       │
   │               │                       │
```

## Memory Model

```
┌────────────────────────────────────────────────┐
│                Memory Layout                     │
│                                                  │
│  ┌──────────────┐  ┌──────────────┐             │
│  │  Static Data  │  │  Heap Arena   │             │
│  │               │  │               │             │
│  │  - Config     │  │  - Conn pool  │             │
│  │  - Rules      │  │  - Request    │             │
│  │  - Regex       │  │    buffers    │             │
│  │    cache      │  │  - Rate limit │             │
│  │               │  │    state      │             │
│  └──────────────┘  └──────────────┘             │
│                                                  │
│  Allocation strategy:                            │
│  - Zero-copy for static config and rules         │
│  - Arena allocator for request-scoped data       │
│  - Lazy regex compilation with LRU cache         │
│  - Optional jemalloc feature                    │
└────────────────────────────────────────────────┘
```

## Concurrency Model

```
tokio::main (multi-threaded runtime)
│
├── Listener task: accept() loop
│   └── spawn per-connection task
│       ├── TLS handshake
│       ├── HTTP parse (line-based streaming)
│       ├── WAF pipeline (sequential phases)
│       ├── Proxy to upstream (concurrent)
│       └── Log/metrics emission
│
├── Health check task: periodic upstream probing
├── Redis pool: connection management (bb8)
├── Metrics server: axum-based HTTP endpoint
└── Admin server: management API (optional)
```

The runtime uses `tokio::main` with worker threads equal to CPU cores.
Each connection runs as an independent task with cooperative scheduling.

## Crate Structure

```
aegis-waf/
├── src/
│   └── main.rs              # Entry point, CLI parsing
├── crates/
│   ├── aegis-core/           # Shared types, config, error types
│   ├── aegis-tls/            # TLS acceptor, cert management
│   ├── aegis-waf/            # Rule engine, matcher, scorer
│   ├── aegis-ratelimit/     # Token bucket, Redis integration
│   ├── aegis-proxy/          # Upstream routing, connection pool
│   ├── aegis-acl/            # IP/GeoIP access control
│   ├── aegis-metrics/        # Prometheus exposition
│   └── aegis-logging/        # Structured logging
└── config/
    └── default.toml          # Default configuration
```
