#!/usr/bin/env bash
set -euo pipefail
# Requires: gh auth login   OR   export GH_TOKEN=...
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
NAME="${1:-grc-pdf-mapper}"
VIS="${2:-public}"
DESC="GRC policy document mapper using Firecrawl pdf-inspector"
gh repo create "$NAME" --"$VIS" --source=. --remote=origin --push --description "$DESC"
gh browse
