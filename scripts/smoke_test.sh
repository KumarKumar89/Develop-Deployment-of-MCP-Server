#!/usr/bin/env bash
set -euo pipefail

BASE_URL="${MCP_URL:-http://127.0.0.1:8080}"
TOKEN="${MCP_BEARER_TOKEN:?Set MCP_BEARER_TOKEN to the configured HTTP server token}"
TMP_BODY="$(mktemp)"
trap 'rm -f "$TMP_BODY"' EXIT

printf '1/3 Checking unauthenticated requests are rejected... '
STATUS="$(curl --silent --show-error -o "$TMP_BODY" -w '%{http_code}' \
  -X POST "${BASE_URL%/}/mcp" \
  -H 'Content-Type: application/json' \
  --data '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"smoke-test","version":"0.1.0"}}}')"
if [[ "$STATUS" != "401" ]]; then
  echo "FAIL (expected 401, received $STATUS)" >&2
  exit 1
fi
echo OK

printf '2/3 Checking health endpoint... '
curl --fail --silent --show-error "${BASE_URL%/}/healthz" | grep -q '"status":"ok"'
echo OK

printf '3/3 Checking authenticated MCP initialization... '
STATUS="$(curl --silent --show-error -o "$TMP_BODY" -w '%{http_code}' \
  -X POST "${BASE_URL%/}/mcp" \
  -H "Authorization: Bearer ${TOKEN}" \
  -H 'Content-Type: application/json' \
  -H 'Accept: application/json, text/event-stream' \
  --data '{"jsonrpc":"2.0","id":2,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"smoke-test","version":"0.1.0"}}}')"
if [[ "$STATUS" -lt 200 || "$STATUS" -ge 300 ]]; then
  echo "FAIL (expected 2xx, received $STATUS)" >&2
  cat "$TMP_BODY" >&2
  exit 1
fi
if ! grep -Eq '"result"|event: message' "$TMP_BODY"; then
  echo "FAIL (response did not appear to contain an MCP result)" >&2
  cat "$TMP_BODY" >&2
  exit 1
fi
echo OK

echo "Smoke checks passed. Use an MCP client to verify tool discovery and each tool call as well."
