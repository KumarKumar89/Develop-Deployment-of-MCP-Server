# Contributing

Thank you for improving this defensive MCP server starter.

## Development

1. Use Rust 1.75+ (CI uses stable).
2. Run `make check` and `make test` before opening a PR.
3. Prefer small, focused changes that keep tools read-only and deterministic.
4. Do not add shell execution, host filesystem browsing, automatic containment, or unauthenticated remote access.
5. Never commit secrets, real tokens, or production credentials.

## Pull requests

- Describe the threat-model impact of any new tool or transport change.
- Include unit tests for validation and normalization logic.
- Keep dependencies minimal and review new crates for maintenance and license fit.
