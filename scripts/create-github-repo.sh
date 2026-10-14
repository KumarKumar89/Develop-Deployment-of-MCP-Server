#!/usr/bin/env bash
set -euo pipefail

REPO_FULL_NAME="${REPO_FULL_NAME:-KumarKumar89/Develop-Deployment-of-MCP-Server}"
REPO_VISIBILITY="${REPO_VISIBILITY:-private}"
DESCRIPTION="${REPO_DESCRIPTION:-Secure Rust MCP server starter for defensive cybersecurity workflows}"

if ! command -v gh >/dev/null 2>&1; then
  echo "GitHub CLI (gh) is required. Install it and run: gh auth login" >&2
  exit 1
fi
if ! gh auth status >/dev/null 2>&1; then
  echo "GitHub CLI is not authenticated. Run: gh auth login" >&2
  exit 1
fi
if [[ "$REPO_VISIBILITY" != "private" && "$REPO_VISIBILITY" != "public" ]]; then
  echo "REPO_VISIBILITY must be private or public" >&2
  exit 1
fi

if [[ -d .git ]]; then
  echo "This directory already has a .git repository; refusing to reinitialize it." >&2
  exit 1
fi

git init --initial-branch=main
git add .
git commit -m "Initial secure Rust MCP server scaffold"

visibility_flag="--private"
[[ "$REPO_VISIBILITY" == "public" ]] && visibility_flag="--public"

gh repo create "$REPO_FULL_NAME" "$visibility_flag" \
  --description "$DESCRIPTION" \
  --source . --remote origin --push

echo "Created and pushed https://github.com/${REPO_FULL_NAME}"
echo "Review repository visibility, branch protection, secret scanning, and Actions settings before production use."
