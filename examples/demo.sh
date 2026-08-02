#!/usr/bin/env bash
# Demo: analyze two policy versions, show drift and questionnaire assist.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
STORE="$ROOT/.grc-lineage-demo"
REPORT="$ROOT/examples/report-v1.json"
rm -rf "$STORE"
mkdir -p "$ROOT/examples"

PYTHON="${PYTHON:-python3}"

"$PYTHON" -m grc_pdf_mapper.cli analyze \
  "$ROOT/tests/fixtures/access_control_policy_v1.md" \
  --doc-id pol-ac-001 --version v2.1 --offline --store "$STORE" --json "$REPORT"

"$PYTHON" -m grc_pdf_mapper.cli analyze \
  "$ROOT/tests/fixtures/access_control_policy_v2.md" \
  --doc-id pol-ac-001 --version v2.2 --offline --store "$STORE"

echo
echo "=== History ==="
"$PYTHON" -m grc_pdf_mapper.cli history pol-ac-001 --store "$STORE"

OLDER=$("$PYTHON" - <<PY
from grc_pdf_mapper.lineage import PolicyLineageStore
h = PolicyLineageStore("$STORE").history("pol-ac-001")
print(h[1].snapshot_id)
PY
)
NEWER=$("$PYTHON" - <<PY
from grc_pdf_mapper.lineage import PolicyLineageStore
h = PolicyLineageStore("$STORE").history("pol-ac-001")
print(h[0].snapshot_id)
PY
)

echo
echo "=== Drift $OLDER -> $NEWER ==="
"$PYTHON" -m grc_pdf_mapper.cli drift pol-ac-001 "$OLDER" "$NEWER" --store "$STORE"

echo
echo "=== Questionnaire suggest ==="
"$PYTHON" -m grc_pdf_mapper.cli ask "$REPORT" "Do privileged accounts require MFA?"

echo
echo "=== OSCAL component export ==="
"$PYTHON" -m grc_pdf_mapper.cli oscal "$REPORT" --out "$ROOT/examples/component-definition.json"
echo "Wrote examples/component-definition.json"
