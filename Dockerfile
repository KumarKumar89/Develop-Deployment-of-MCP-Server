# syntax=docker/dockerfile:1

# ---- builder ----
FROM rust:1.88-slim-bookworm AS builder
WORKDIR /build

RUN apt-get update && apt-get install -y --no-install-recommends \
    pkg-config \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Prefer locked builds when Cargo.lock is present.
COPY Cargo.toml ./
COPY Cargo.lock* ./
COPY src ./src

RUN if [ -f Cargo.lock ]; then \
      cargo build --release --locked; \
    else \
      cargo build --release; \
    fi \
    && strip /build/target/release/cybersecurity-mcp-server

# ---- runtime ----
FROM debian:bookworm-slim AS runtime

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --system --gid 10001 app \
    && useradd --system --uid 10001 --gid app \
        --home-dir /nonexistent --shell /usr/sbin/nologin app

WORKDIR /app
COPY --from=builder /build/target/release/cybersecurity-mcp-server /usr/local/bin/cybersecurity-mcp-server

ENV MCP_TRANSPORT=stdio \
    MCP_BIND=127.0.0.1:8080 \
    RUST_LOG=info

USER 10001:10001
EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/cybersecurity-mcp-server"]
