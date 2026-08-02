#!/usr/bin/env bash
set -euo pipefail
# Requires: gh auth login   OR   export GH_TOKEN=...
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
NAME="${1:-grc-pdf-mapper}"
VIS="${2:-public}"
DESC="GRC policy document mapper using Firecrawl pdf-inspector"

if ! git remote get-url origin >/dev/null 2>&1; then
  gh repo create "$NAME" --"$VIS" --source=. --remote=origin --push --description "$DESC"
else
  git push -u origin HEAD
fi

# Host docs/ (examples gallery) on GitHub Pages.
gh api -X POST "repos/{owner}/{repo}/pages" \
  -f build_type=legacy \
  -f source[branch]=main \
  -f source[path]=/docs \
  2>/dev/null || gh api -X PUT "repos/{owner}/{repo}/pages" \
  --input - <<'JSON' 2>/dev/null || true
{"build_type":"legacy","source":{"branch":"main","path":"/docs"}}
JSON

OWNER="$(gh repo view --json owner -q .owner.login)"
REPO="$(gh repo view --json name -q .name)"
gh repo edit "$OWNER/$REPO" --homepage "https://${OWNER}.github.io/${REPO}/" 2>/dev/null || true
echo "Repository: https://github.com/${OWNER}/${REPO}"
echo "Examples gallery: https://${OWNER}.github.io/${REPO}/"
