#!/usr/bin/env bash
# Generate static artifacts for examples/viewer
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
PYTHON="${PYTHON:-python3}"
OUT="$ROOT/examples/viewer/data"
STORE="$ROOT/examples/viewer/.store"
mkdir -p "$OUT"
rm -rf "$STORE"

export PYTHONPATH="$ROOT/src${PYTHONPATH:+:$PYTHONPATH}"

echo "Generating document impact sample..."
"$PYTHON" -m grc_pdf_mapper.cli analyze \
  "$ROOT/tests/fixtures/access_control_policy_v1.md" \
  --doc-id pol-ac-001 --version v2.1 --offline --store "$STORE" --no-alert \
  --json "$OUT/report-v1.json" >/dev/null

"$PYTHON" -m grc_pdf_mapper.cli analyze \
  "$ROOT/tests/fixtures/access_control_policy_v2.md" \
  --doc-id pol-ac-001 --version v2.2 --offline --store "$STORE" \
  --assessments "$ROOT/lab/assessments.json" \
  --json "$OUT/report-v2.json" >/dev/null

OLDER=$("$PYTHON" - <<PY
from grc_pdf_mapper.lineage import PolicyLineageStore
print(PolicyLineageStore("$STORE").history("pol-ac-001")[1].snapshot_id)
PY
)
NEWER=$("$PYTHON" - <<PY
from grc_pdf_mapper.lineage import PolicyLineageStore
print(PolicyLineageStore("$STORE").history("pol-ac-001")[0].snapshot_id)
PY
)

"$PYTHON" -m grc_pdf_mapper.cli impact pol-ac-001 "$OLDER" "$NEWER" \
  --store "$STORE" --assessments "$ROOT/lab/assessments.json" --offline \
  --json "$OUT/impact-alert.json" >/dev/null

echo "Generating policy-as-code samples..."
cp "$ROOT/lab/iac/access_control/main.tf" "$OUT/tf-base.tf"
cp "$ROOT/lab/iac/access_control/main.tf" "$OUT/tf-head.tf"
"$PYTHON" - <<PY
from pathlib import Path
p = Path("$OUT/tf-head.tf")
text = p.read_text(encoding="utf-8")
text = text.replace('"aws:MultiFactorAuthPresent" = "false"', '"aws:MultiFactorAuthPresent" = "true"')
p.write_text(text, encoding="utf-8")
PY

"$PYTHON" "$ROOT/scripts/ci_pac_sync.py" \
  --mode completeness \
  --links "$ROOT/lab/policy-as-code-links.json" \
  --policy "$ROOT/lab/policies/access-control.md" \
  --terraform-root "$ROOT/lab/iac" \
  --doc-id pol-ac-001 \
  --fail-on critical \
  --comment-out "$OUT/pac-completeness.md" \
  --json-out "$OUT/pac-completeness.json" \
  --store "$STORE" >/dev/null || true

"$PYTHON" "$ROOT/scripts/ci_pac_sync.py" \
  --mode iac-changed \
  --links "$ROOT/lab/policy-as-code-links.json" \
  --policy "$ROOT/lab/policies/access-control.md" \
  --doc-id pol-ac-001 \
  --base-tf "$OUT/tf-base.tf" \
  --head-tf "$OUT/tf-head.tf" \
  --fail-on critical \
  --comment-out "$OUT/pac-iac-impact.md" \
  --json-out "$OUT/pac-iac-impact.json" \
  --store "$STORE" >/dev/null || true

echo "Generating FedRAMP class samples..."
for cls in a b c d; do
  "$PYTHON" - <<PY
import json
from grc_pdf_mapper.fedramp import FedRampKSICatalog
cat = FedRampKSICatalog("$ROOT/lab/fedramp/cr26_ksi_catalog.json")
rows = cat.for_class("$cls")
docs = cat.documentation_matrix("$cls")
payload = {
  "class": "$cls",
  "catalog_version": cat.version,
  "ksi_count": len(rows),
  "ksi": [{"id": r["id"], "name": r.get("name"), "status": r.get("class_status"), "controls": r.get("controls_nist", [])[:6]} for r in rows],
  "documentation": docs,
}
Path = __import__('pathlib').Path
Path("$OUT/fedramp-class-$cls.json").write_text(json.dumps(payload, indent=2), encoding="utf-8")
PY
done

# Keep only viewer-needed tf snippets small
rm -f "$OUT/tf-base.tf" "$OUT/tf-head.tf"

# Build index manifest
"$PYTHON" - <<PY
import json
from pathlib import Path
out = Path("$OUT")
files = sorted(p.name for p in out.iterdir() if p.is_file())
manifest = {
  "title": "GRC PDF Mapper examples",
  "sections": [
    {"id": "impact", "title": "Document change impact", "files": ["impact-alert.json", "report-v1.json", "report-v2.json"]},
    {"id": "pac", "title": "Policy-as-code lock-step", "files": ["pac-completeness.json", "pac-iac-impact.json", "pac-completeness.md", "pac-iac-impact.md"]},
    {"id": "fedramp", "title": "FedRAMP CR26 KSI by class", "files": ["fedramp-class-a.json", "fedramp-class-b.json", "fedramp-class-c.json", "fedramp-class-d.json"]},
  ],
  "files": files,
}
(out / "manifest.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")
print("Wrote", len(files), "viewer data files")
PY

echo "Done. Open examples/viewer with: python3 -m http.server 8765 --directory examples/viewer"
