# Aegis WAF

[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)

A high-performance, memory-safe Web Application Firewall written in Rust.
Aegis WAF operates as a reverse proxy with TLS termination, rate limiting,
and configurable WAF rule engine.

## Quick Start

```bash
# 1. Pull and run with Docker
docker run -d \
  -p 8443:8443 \
  -p 9090:9090 \
  -v $(pwd)/config:/etc/aegis-waf \
  ghcr.io/aegis-waf/aegis-waf:latest

# 2. Or run with docker-compose
docker-compose up -d

# 3. Verify
curl -k https://localhost:8443/health
```

## Features

| Category          | Capability                                             |
| ----------------- | ------------------------------------------------------ |
| **WAF Engine**    | Rule-based pattern matching with regex and CIDR        |
| **TLS**           | Terminates TLS 1.2/1.3 with configurable ciphers       |
| **Rate Limiting** | Token bucket algorithm with optional Redis clustering  |
| **Access Control**| IP allow/deny lists, GeoIP filtering                   |
| **Observability** | Prometheus metrics, structured JSON logging, tracing   |
| **Hot Reload**    | Config and rule reload without dropping connections    |
| **Performance**   | Built on Tokio async runtime, <1ms added latency       |

## Architecture

```
            │  Internet   │
            └──────┬──────┘
                   │ HTTPS :443
            ┌──────▼──────┐
            │  TLS Term   │  Rustls
            └──────┬──────┘
                   │
            ┌──────▼──────┐
            │  WAF Engine │  Rule matching · Scoring
            └──────┬──────┘
                   │
            ┌──────▼──────┐
            │    Proxy    │  Request forwarding
            └──────┬──────┘
                   │
            ┌──────▼──────┐
            │   Upstream  │  Your application
            └─────────────┘
```

## Documentation

| Document                                | Description                       |
| --------------------------------------- | --------------------------------- |
| [Installation](INSTALLATION.md)         | Platform-specific setup           |
| [Configuration](CONFIGURATION.md)       | All configuration options         |
| [CLI Guide](CLI_GUIDE.md)               | Command reference                 |
| [Architecture](ARCHITECTURE.md)         | System design and data flow       |
| [Security](SECURITY.md)                 | Best practices and threat model   |
| [API](API.md)                           | HTTP API endpoints                |

## License

Aegis WAF is licensed under the Apache License, Version 2.0.
See [LICENSE](../LICENSE) for the full text.
