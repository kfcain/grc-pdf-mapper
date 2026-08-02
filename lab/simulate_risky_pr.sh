#!/usr/bin/env bash
# Local simulation of a risky policy PR impact check.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
PYTHON="${PYTHON:-python3}"
BASE="/tmp/grc-lab-base.md"
HEAD="/tmp/grc-lab-head.md"
COMMENT="/tmp/grc-lab-impact-comment.md"
JSON="/tmp/grc-lab-impact-alert.json"

cp "$ROOT/lab/policies/access-control.md" "$BASE"
cp "$ROOT/lab/policies/access-control.md" "$HEAD"

"$PYTHON" - <<PY
from pathlib import Path
p = Path("$HEAD")
text = p.read_text(encoding="utf-8")
text = text.replace(
    "Privileged accounts must use multi-factor authentication.",
    "Privileged accounts should use multi-factor authentication when feasible.",
)
text = text.replace("**Version:** 2.1", "**Version:** 2.2-DRAFT")
p.write_text(text, encoding="utf-8")
print("Prepared risky head revision (MUST MFA -> SHOULD).")
PY

set +e
"$PYTHON" "$ROOT/scripts/ci_doc_impact.py" \
  --base-file "$BASE" \
  --head-file "$HEAD" \
  --doc-id pol-ac-001 \
  --assessments "$ROOT/lab/assessments.json" \
  --store "$ROOT/.grc-lineage-lab" \
  --fail-on high \
  --comment-out "$COMMENT" \
  --json-out "$JSON" \
  --offline
RC=$?
set -e

echo
echo "======= PR COMMENT PREVIEW ======="
sed -n '1,100p' "$COMMENT"
echo "======= END PREVIEW (exit=$RC) ======="
echo "JSON: $JSON"
exit "$RC"
