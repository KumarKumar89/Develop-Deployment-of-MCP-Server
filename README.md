# Develop & Deployment of MCP Server

**Secure Rust MCP server starter for defensive cybersecurity workflows**

This repository provides a small, security-conscious starting point for a Model Context Protocol (MCP) server that can run locally over **stdio** or as an authenticated **Streamable HTTP** service. The same Rust tool implementation can be registered with Claude and Grok. For one shared service used by both cloud clients, deploy HTTP mode behind HTTPS and configure both clients to the same URL.

> **Status:** starter scaffold, not a production-certified security product. Complete your company's review and replace the included static-token bootstrap with enterprise identity controls before handling sensitive production workloads.

## Repository layout

```
src/                 Rust MCP server (tools + HTTP/stdio transports)
deploy/              Docker Compose + Caddy HTTPS sample
docs/                Architecture, deployment runbook, threat model
config/              Client config examples (Claude remote)
.grok/               Grok Build config example
.github/workflows/   CI (fmt, clippy, test, audit, Docker build)
scripts/             Smoke test and repo bootstrap helpers
Dockerfile           Multi-stage, non-root, dependency-cached image
```

## Included tools

| Tool | What it does | What it does not do |
|---|---|---|
| `get_security_baseline` | Returns a concise defensive-control checklist | Does not inspect or configure hosts |
| `assess_indicator` | Syntax-checks and normalizes an IP, domain, HTTP(S) URL, or SHA-256 digest | Does not resolve DNS, visit URLs, query reputation, or determine maliciousness |
| `triage_security_alert` | Maps caller-supplied severity to priority and analyst steps | Does not query SIEM/EDR or execute containment |
| `sha256_text` | Computes a SHA-256 digest of text up to 8 KiB | Does not read or hash host files; does not store/log the input |

## Security design

- Rust and the official `rmcp` SDK.
- Stdio mode for local clients; diagnostics only on stderr so stdout remains the MCP protocol channel.
- Streamable HTTP mode for remote clients; bearer auth required for `/mcp`, constant-time comparison for equal-length token values, and a 1 MiB request-body limit.
- HTTP binds to `127.0.0.1:8080` by default. Compose binds inside the private container network and fronts it with Caddy HTTPS; port 8080 is not published to the host.
- Non-root container, read-only root filesystem, dropped Linux capabilities, and `no-new-privileges` in Compose.
- CI runs rustfmt, Clippy, unit tests, and `cargo audit`; Dependabot watches Cargo dependencies and GitHub Actions.
- No arbitrary shell tool, no automatic destructive response, no live outbound integrations, no provider API keys in the MCP service.

See [architecture](docs/architecture.md), [threat model](docs/threat-model.md), and the [deployment runbook](docs/deployment.md).

## Quick start

Requirements: Rust 1.75+, Cargo, Git. In Codespaces, the included devcontainer provides a Rust development environment.

```bash
rustup component add rustfmt clippy
cargo generate-lockfile   # commit Cargo.lock after generation
cargo test --all-targets --locked
cargo build --release --locked
```

Or use the Makefile:

```bash
make check test release
```

### Local stdio

```bash
MCP_TRANSPORT=stdio cargo run --release
```

Use an MCP client or the MCP Inspector to communicate with the process; it expects MCP JSON-RPC on stdin/stdout, not interactive shell input.

### Authenticated HTTP

```bash
cp .env.example .env
# Create a token and place it in .env:
openssl rand -hex 32
# Set MCP_DOMAIN to a DNS name you control.
docker compose --env-file .env -f deploy/compose.yml up --build -d
./scripts/smoke_test.sh
```

The app uses `MCP_BEARER_TOKEN` in HTTP mode and offers `/healthz` for liveness. Follow all TLS, secret-handling, and release steps in [docs/deployment.md](docs/deployment.md).

## Use with clients

- **Claude local development:** build the binary and register stdio with `claude mcp add --transport stdio ...`
- **Grok local development:** the Grok Build CLI supports stdio MCP servers.
- **One shared Claude + Grok endpoint:** deploy authenticated HTTPS and point both clients at `https://YOUR_DOMAIN/mcp`.

Example Grok Build config is in `.grok/config.toml.example`. The Claude remote config template is in `config/claude-code.remote.example.json`; fill it locally through an approved secret-management workflow and never commit a real token.

## License

MIT — see [LICENSE](LICENSE).

## Suggested next increments

1. Replace static bearer auth with reviewed OAuth 2.1/OIDC validation and per-user authorization.
2. Add approved integrations one at a time (asset inventory, SIEM, EDR, ticketing) behind least-privilege interfaces and mocked tests.
3. Add structured audit events with strict field redaction, rate limits, metrics, SBOMs, image scanning, and signed releases.
4. Add integration/conformance tests against the protocol versions and clients your company officially supports.
