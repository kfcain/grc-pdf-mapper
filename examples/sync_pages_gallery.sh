#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
bash "$ROOT/examples/generate_viewer_data.sh"
cp -a "$ROOT/examples/viewer/index.html" "$ROOT/docs/index.html"
cp -a "$ROOT/examples/viewer/data/." "$ROOT/docs/data/"
echo "Updated docs/ from examples/viewer for GitHub Pages."
