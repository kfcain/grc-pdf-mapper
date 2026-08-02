#!/usr/bin/env bash
# Demo: version a policy change and emit framework/assessment impact alerts.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
STORE="$ROOT/.grc-lineage-demo"
PYTHON="${PYTHON:-python3}"
rm -rf "$STORE"

echo "=== Baseline commit (no alert) ==="
"$PYTHON" -m grc_pdf_mapper.cli analyze \
  "$ROOT/tests/fixtures/access_control_policy_v1.md" \
  --doc-id pol-ac-001 --version v2.1 --offline --store "$STORE" --no-alert

echo
echo "=== Changed version (impact alert expected) ==="
"$PYTHON" -m grc_pdf_mapper.cli analyze \
  "$ROOT/tests/fixtures/access_control_policy_v2.md" \
  --doc-id pol-ac-001 --version v2.2 --offline --store "$STORE"

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
echo "=== Impact report $OLDER -> $NEWER ==="
"$PYTHON" -m grc_pdf_mapper.cli impact pol-ac-001 "$OLDER" "$NEWER" \
  --store "$STORE" --offline --json "$ROOT/examples/impact-alert.json"

echo
echo "=== Alert feed ==="
"$PYTHON" -m grc_pdf_mapper.cli alerts --store "$STORE" --min-severity medium

echo
echo "Wrote examples/impact-alert.json"
