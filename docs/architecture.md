# Architecture

## Operating modes

```text
                         shared Rust tool implementation
                       ┌────────────────────────────────┐
Claude Code / Desktop ─┤                                ├─ get_security_baseline
    local stdio ────────┤  cybersecurity-mcp-server      ├─ assess_indicator
                       │  bounded, deterministic tools  ├─ triage_security_alert
Grok / Claude remote ──┤                                ├─ sha256_text
    HTTPS /mcp ────────┤  Bearer auth + body limit       │
                       └────────────────────────────────┘
                                 │
                 TLS at Caddy / ingress / load balancer
```

- **Local mode (`MCP_TRANSPORT=stdio`)**: a compatible client starts the binary as a child process. MCP messages use stdin/stdout. Diagnostics go to stderr. Each stdio client usually owns its process instance.
- **Remote mode (`MCP_TRANSPORT=http`)**: the server exposes Streamable HTTP at `/mcp`, checks a bearer token before MCP requests, and enforces a 1 MiB request-body limit. `/healthz` returns minimal liveness information. Put the app behind HTTPS termination and a network policy.
- **Shared service for Claude and Grok**: deploy one remote instance and configure both clients to the same HTTPS `/mcp` URL. Do not expose an unprotected Codespaces port or a raw HTTP listener to the Internet.

## Trust boundaries

1. The MCP client/model is untrusted input. All tool parameters must be validated server-side.
2. The MCP server is a policy boundary, not an autonomous incident-response operator.
3. LLM-provider credentials belong in the relevant client or provider secret manager. This server does not need Anthropic or xAI model API keys.
4. The initial tools are deterministic and do not connect to live SIEM, EDR, threat-intelligence feeds, internal networks, or the host filesystem.
5. For enterprise operation, replace shared static-token authentication with the organization's OAuth 2.1/OIDC resource-server pattern, audience validation, per-user authorization, and auditable identity context.

## Tool contracts

| Tool | Purpose | Side effects |
|---|---|---|
| `get_security_baseline` | Return defensive baseline guidance and limitations | None |
| `assess_indicator` | Syntax-check and normalize an IP, domain, HTTP(S) URL, or SHA-256 digest | None; no network lookups |
| `triage_security_alert` | Prioritize caller-provided alert metadata and recommend analyst steps | None; no containment or live query |
| `sha256_text` | Calculate SHA-256 over a supplied text string up to 8 KiB | None; input is not stored or logged |
