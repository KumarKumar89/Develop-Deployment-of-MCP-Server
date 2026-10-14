# Security policy

## Scope

This repository is an initial defensive cybersecurity MCP server scaffold. It intentionally has no arbitrary command execution, host-file browsing, automatic containment, or live outbound indicator lookup.

## Reporting a vulnerability

Do not post credentials, personal data, customer logs, or exploitable details in a public issue. For a private company deployment, report suspected vulnerabilities through the company's approved security contact or private vulnerability-reporting channel. Replace this note with the company's monitored disclosure address and SLA before use outside a private repository.

## Maintainer response expectations

- Acknowledge a report through the approved channel.
- Reproduce the issue in an isolated environment and assess impact.
- Patch and test the issue, rotate affected credentials if needed, and document mitigations.
- Publish advisories only after coordinated disclosure approval.

## Deployment notes

The included shared bearer token is a bootstrap control, not full production-grade identity. Use TLS, a secret manager, least privilege, rotation, and a reviewed OAuth 2.1/OIDC pattern for production. Do not expose the server directly to the public Internet without authentication and transport security.
