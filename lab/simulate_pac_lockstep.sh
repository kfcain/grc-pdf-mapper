#!/usr/bin/env bash
# Demonstrate docs ↔ Terraform lock-step alerts.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
PYTHON="${PYTHON:-python3}"
TMP="$ROOT/.grc-pac-lab"
rm -rf "$TMP"
mkdir -p "$TMP"

echo "=== 1) Completeness on healthy baseline ==="
"$PYTHON" -m grc_pdf_mapper.cli sync-check \
  --policy "$ROOT/lab/policies/access-control.md" \
  --terraform-root "$ROOT/lab/iac" \
  --links "$ROOT/lab/policy-as-code-links.json" \
  --doc-id pol-ac-001

echo
echo "=== 2) Terraform changed without doc update ==="
cp "$ROOT/lab/iac/access_control/main.tf" "$TMP/base.tf"
cp "$ROOT/lab/iac/access_control/main.tf" "$TMP/head.tf"
"$PYTHON" - <<PY
from pathlib import Path
p = Path("$TMP/head.tf")
text = p.read_text(encoding="utf-8")
text = text.replace('"aws:MultiFactorAuthPresent" = "false"', '"aws:MultiFactorAuthPresent" = "true"')
p.write_text(text, encoding="utf-8")
print("Weakened MFA deny condition in Terraform head revision.")
PY

set +e
"$PYTHON" "$ROOT/scripts/ci_pac_sync.py" \
  --mode iac-changed \
  --links "$ROOT/lab/policy-as-code-links.json" \
  --policy "$ROOT/lab/policies/access-control.md" \
  --doc-id pol-ac-001 \
  --base-tf "$TMP/base.tf" \
  --head-tf "$TMP/head.tf" \
  --fail-on high \
  --comment-out "$TMP/iac-comment.md" \
  --json-out "$TMP/iac-alert.json" \
  --store "$TMP/store"
IAC_RC=$?
set -e
echo "IaC impact exit=$IAC_RC"
sed -n '1,60p' "$TMP/iac-comment.md"

echo
echo "=== 3) Policy softened while Terraform still enforces old MUST ==="
cp "$ROOT/lab/policies/access-control.md" "$TMP/policy-base.md"
cp "$ROOT/lab/policies/access-control.md" "$TMP/policy-head.md"
"$PYTHON" - <<PY
from pathlib import Path
p = Path("$TMP/policy-head.md")
text = p.read_text(encoding="utf-8")
text = text.replace(
    "Privileged accounts must use multi-factor authentication.",
    "Privileged accounts should use multi-factor authentication when convenient.",
)
p.write_text(text, encoding="utf-8")
print("Softened MFA policy language in head revision.")
PY

set +e
"$PYTHON" "$ROOT/scripts/ci_pac_sync.py" \
  --mode doc-changed \
  --links "$ROOT/lab/policy-as-code-links.json" \
  --terraform-root "$ROOT/lab/iac" \
  --doc-id pol-ac-001 \
  --base-policy "$TMP/policy-base.md" \
  --head-policy "$TMP/policy-head.md" \
  --fail-on high \
  --comment-out "$TMP/doc-comment.md" \
  --json-out "$TMP/doc-alert.json" \
  --store "$TMP/store"
DOC_RC=$?
set -e
echo "Doc impact exit=$DOC_RC"
sed -n '1,60p' "$TMP/doc-comment.md"

if [ "$IAC_RC" -ne 1 ] || [ "$DOC_RC" -ne 1 ]; then
  echo "Expected both change directions to fail the lock-step gate."
  exit 1
fi
echo "Lock-step lab OK: both IaC-only and doc-only changes were blocked."
