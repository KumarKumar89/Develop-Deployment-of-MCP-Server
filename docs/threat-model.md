# Threat model

## Assets

- Integrity and confidentiality of tool inputs and outputs (indicators, alert metadata, hashed evidence).
- Availability of the MCP service for authorized clients.
- Authentication secrets used for HTTP mode.
- Host and container isolation boundaries.

## Adversaries

- Untrusted LLM clients that may send malformed or adversarial tool arguments.
- Network attackers who can reach an exposed HTTP listener.
- Operators with partial access to configuration or container orchestration.

## Mitigations in this scaffold

| Threat | Control in this repo | Residual recommendation |
|---|---|---|
| Prompt injection / malicious tool args | Strict server-side validation, size limits, no shell or filesystem tools | Keep tools deterministic; never trust model-supplied paths or commands |
| Token theft / replay | Bearer required on `/mcp`; constant-time compare; min length 32 | Rotate tokens; prefer OAuth/OIDC; short-lived credentials |
| Path/query secret leakage | URL normalization redacts path, query, fragment | Minimize sent data; redact telemetry end-to-end |
| Vulnerable dependency | CI `cargo audit`; Dependabot | Review advisories; pin; SBOM |
| Compromised container | Non-root, read-only FS, dropped caps | Image provenance, host hardening, runtime monitoring |
| TLS misconfiguration | Caddy sample for real DNS name | Confirm certs, HSTS, network segmentation |

## Residual risks / non-goals

- A static bearer token is a bootstrap mechanism, not a complete enterprise identity system.
- The health endpoint is public in the sample and reports only service liveness.
- Alert prioritization is deterministic example logic, not a validated detection engine.
- A syntax-valid indicator is not necessarily malicious, reachable, or attributable.
- Complete a security review before production use.
