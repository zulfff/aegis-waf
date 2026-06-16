# Stage 1: Build
FROM rust:1.76-slim-bookworm AS builder

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        pkg-config \
        libssl-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /usr/src/aegis-waf

COPY Cargo.toml Cargo.lock ./
RUN cargo fetch

COPY src/ src/
COPY crates/ crates/
COPY examples/ examples/

RUN cargo build --release && \
    strip target/release/aegis-waf

# Stage 2: Runtime
FROM debian:bookworm-slim

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        libssl3 \
        ca-certificates \
    && rm -rf /var/lib/apt/lists/*

RUN groupadd -r aegis-waf && \
    useradd -r -g aegis-waf -d /var/lib/aegis-waf -s /sbin/nologin aegis-waf

COPY --from=builder /usr/src/aegis-waf/target/release/aegis-waf /usr/local/bin/aegis-waf

RUN mkdir -p /etc/aegis-waf /var/lib/aegis-waf/certs /var/log/aegis-waf && \
    chown -R aegis-waf:aegis-waf /etc/aegis-waf /var/lib/aegis-waf /var/log/aegis-waf

COPY config/ /etc/aegis-waf/
RUN chown -R aegis-waf:aegis-waf /etc/aegis-waf

EXPOSE 8443 9090

HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
    CMD /usr/local/bin/aegis-waf healthcheck || exit 1

USER aegis-waf
WORKDIR /var/lib/aegis-waf

ENTRYPOINT ["/usr/local/bin/aegis-waf"]
