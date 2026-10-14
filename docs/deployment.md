# Deployment runbook

## Prerequisites

- Docker and Docker Compose
- A DNS name you control (`MCP_DOMAIN`)
- A strong bearer token: `openssl rand -hex 32`

## Deploy with Compose + Caddy

```bash
cp .env.example .env
# Edit .env: set MCP_BEARER_TOKEN and MCP_DOMAIN
docker compose --env-file .env -f deploy/compose.yml up --build -d
./scripts/smoke_test.sh
```

- The MCP process listens on `0.0.0.0:8080` **inside** the compose network only.
- Caddy terminates TLS for `MCP_DOMAIN` and reverse-proxies to `mcp:8080`.
- Ports 80/443 are published; 8080 is not published to the host.

## Environment variables

| Variable | Required | Description |
|---|---|---|
| `MCP_TRANSPORT` | yes (http in compose) | `stdio` or `http` |
| `MCP_BIND` | no | Default `127.0.0.1:8080`; compose uses `0.0.0.0:8080` |
| `MCP_BEARER_TOKEN` | yes for http | Min 32 bytes, no leading/trailing whitespace |
| `MCP_DOMAIN` | yes for Caddy | Public DNS name for HTTPS |

## Client configuration

Point Claude and Grok remote MCP configs at `https://YOUR_DOMAIN/mcp` with `Authorization: Bearer <token>`.

Templates: `config/claude-code.remote.example.json`, `.grok/config.toml.example`.

## Hardening checklist

- [ ] Token stored in a secret manager, not in git
- [ ] TLS certificates valid and auto-renewing
- [ ] Network policy limits who can reach Caddy
- [ ] Image rebuilt on dependency updates; `cargo audit` clean
- [ ] Plan to replace static bearer with OAuth 2.1/OIDC

## Rollback

```bash
docker compose -f deploy/compose.yml down
# Redeploy previous image tag or prior commit
```
