# Installation Guide

## Prerequisites

| Dependency | Minimum Version | Required For           |
| ---------- | --------------- | ---------------------- |
| Rust       | 1.76+           | Source builds          |
| OpenSSL    | 3.0+            | TLS and crypto         |
| Redis      | 7.0+            | Distributed rate limit |
| Docker     | 24+             | Container deployment   |

## Binary Releases

Pre-built binaries are available on [GitHub Releases](https://github.com/aegis-waf/aegis-waf/releases).

### Linux (x86_64)

```bash
curl -LO https://github.com/aegis-waf/aegis-waf/releases/latest/download/aegis-waf-linux-x86_64.tar.gz
tar -xzf aegis-waf-linux-x86_64.tar.gz
sudo mv aegis-waf /usr/local/bin/
sudo chmod +x /usr/local/bin/aegis-waf
```

### Linux (ARM64)

```bash
curl -LO https://github.com/aegis-waf/aegis-waf/releases/latest/download/aegis-waf-linux-arm64.tar.gz
tar -xzf aegis-waf-linux-arm64.tar.gz
sudo mv aegis-waf /usr/local/bin/
sudo chmod +x /usr/local/bin/aegis-waf
```

### macOS (x86_64 / ARM64)

```bash
# x86_64
curl -LO https://github.com/aegis-waf/aegis-waf/releases/latest/download/aegis-waf-macos-x86_64.tar.gz

# ARM64 (Apple Silicon)
curl -LO https://github.com/aegis-waf/aegis-waf/releases/latest/download/aegis-waf-macos-arm64.tar.gz

tar -xzf aegis-waf-macos-*.tar.gz
sudo mv aegis-waf /usr/local/bin/
sudo chmod +x /usr/local/bin/aegis-waf
```

### Verify Checksums

```bash
curl -LO https://github.com/aegis-waf/aegis-waf/releases/latest/download/checksums-sha256.txt
sha256sum -c checksums-sha256.txt 2>&1 | grep OK
```

## Build from Source

```bash
git clone https://github.com/aegis-waf/aegis-waf.git
cd aegis-waf

# Linux: install build dependencies
sudo apt-get install -y pkg-config libssl-dev

# macOS: OpenSSL via Homebrew
brew install openssl@3

cargo build --release
sudo cp target/release/aegis-waf /usr/local/bin/
```

### Feature Flags

```bash
cargo build --release --features "jemalloc,geoip,vendored-openssl"
```

| Feature           | Description                           |
| ----------------- | ------------------------------------- |
| `jemalloc`        | Use jemalloc allocator for perf       |
| `geoip`           | GeoIP-based access control            |
| `vendored-openssl`| Statically link OpenSSL               |
| `tracing`         | OpenTelemetry tracing integration     |

## Docker

### From GitHub Container Registry

```bash
docker pull ghcr.io/aegis-waf/aegis-waf:latest
```

### Build Locally

```bash
git clone https://github.com/aegis-waf/aegis-waf.git
cd aegis-waf
docker build -t aegis-waf:latest .
```

### Docker Compose

```bash
docker-compose up -d
```

## Kubernetes

```bash
kubectl apply -f examples/kubernetes_deployment.yaml
```

See [examples/kubernetes_deployment.yaml](../examples/kubernetes_deployment.yaml) for the full manifest.

## Post-Installation

### 1. Generate Configuration

```bash
aegis-waf init --output /etc/aegis-waf/config.toml
```

### 2. Create TLS Certificates

```bash
mkdir -p /etc/aegis-waf/certs
openssl req -x509 -nodes -days 365 -newkey rsa:4096 \
  -keyout /etc/aegis-waf/certs/tls.key \
  -out /etc/aegis-waf/certs/tls.crt \
  -subj "/CN=aegis-waf"
```

### 3. Start the Service

```bash
# Foreground
aegis-waf run --config /etc/aegis-waf/config.toml

# systemd
sudo systemctl enable --now aegis-waf
```

### 4. Verify

```bash
curl -k https://localhost:8443/health
# {"status":"healthy","version":"1.0.0"}
```

## Upgrading

```bash
# Binary upgrade
sudo systemctl stop aegis-waf
curl -LO https://github.com/aegis-waf/aegis-waf/releases/latest/download/aegis-waf-linux-x86_64.tar.gz
tar -xzf aegis-waf-linux-x86_64.tar.gz -C /usr/local/bin/
sudo systemctl start aegis-waf
aegis-waf --version
```

## Uninstall

```bash
sudo systemctl stop aegis-waf
sudo systemctl disable aegis-waf
sudo rm /usr/local/bin/aegis-waf
sudo rm -rf /etc/aegis-waf /var/log/aegis-waf
```

## Troubleshooting

| Symptom                          | Solution                                     |
| -------------------------------- | -------------------------------------------- |
| `error while loading shared libs`| Install `libssl3`: `apt install libssl3`     |
| Port already in use              | Change `tls_port` / `metrics_port` in config |
| Redis connection refused         | Verify Redis is running: `redis-cli ping`    |
| Permission denied (certs)        | `chmod 600 /etc/aegis-waf/certs/*`           |
