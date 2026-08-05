# GRC PDF Mapper

GRC tooling for policy documents. Ingests Markdown natively; uses
[Firecrawl anydoc](https://github.com/firecrawl/anydoc) for Word, PowerPoint,
Excel, OpenDocument, RTF, EPUB, and CSV; and uses
[Firecrawl pdf-inspector](https://github.com/firecrawl/pdf-inspector) for PDF
classification and extraction (anydoc is the PDF fallback when pdf-inspector is
not installed).

## What it does

1. Extract control-related statements from policy and procedure documents.
2. Keep content-addressed version history for corporate docs.
3. Map statements to frameworks via the [SCF API](https://grcengclub.github.io/scf-api/) (Secure Controls Framework), plus OpenCRE, OSA, NIST OSCAL, FedRAMP CR26 KSI, and seed maps.
4. Alert when wording changes may affect frameworks, assessments, or certifications.
5. Keep documentation and policy-as-code (Terraform) in lock-step.

## Install

These commands install this repository into your Python environment in
**editable** mode (`-e`): code changes apply without reinstall.

| Extra | What it adds |
|---|---|
| *(none)* | Core library + `grc-pdf` CLI |
| `dev` | `pytest` (for tests) |
| `pdf` | [pdf-inspector](https://github.com/firecrawl/pdf-inspector) for PDF class / OCR hints |
| `anydoc` | [anydoc](https://github.com/firecrawl/anydoc) for office formats (+ PDF fallback) |
| `docs` | Both `pdf` and `anydoc` |
| `ui` | Local dark GUI (`grc-pdf ui`) via FastAPI + uvicorn |

From the repository root (`grc-pdf-mapper/`):

```bash
cd grc-pdf-mapper

python3 -m pip install -e ".[dev]"
```

Optional document ingest (Markdown works without these):

```bash
python3 -m pip install -e ".[docs,ui,dev]"
```

Office-only (no pdf-inspector):

```bash
python3 -m pip install -e ".[anydoc,dev]"
```

## Local GUI

Install UI deps, then open a dark local workbench in the browser:

```bash
python3 -m pip install -e ".[docs,ui]"
grc-pdf ui
```

Open http://127.0.0.1:8765/ (the command opens a tab by default). Drop a policy file or choose one. The page shows obligations, framework hits, CSV exports, Markdown, and downloadable JSON. The server binds to localhost only.

```bash
grc-pdf ui --port 8765 --no-browser
```

If `grc-pdf` is not found, add your user script path (common on Linux):

```bash
export PATH="$HOME/.local/bin:$PATH"
```

Or run as a module:

```bash
python3 -m grc_pdf_mapper --help
```

Confirm the CLI:

```bash
grc-pdf --help
```

## Quick start

```bash
grc-pdf analyze tests/fixtures/access_control_policy_v1.md \
  --doc-id pol-ac-001 --version v2.1 --offline --json report.json \
  --csv-frameworks frameworks.csv --csv-controls controls.csv

grc-pdf analyze tests/fixtures/access_control_policy.docx \
  --doc-id pol-ac-docx --version v1 --offline --no-commit

grc-pdf analyze tests/fixtures/access_control_policy_v2.md \
  --doc-id pol-ac-001 --version v2.2 --offline

grc-pdf history pol-ac-001
grc-pdf ask report.json "Do you require MFA for privileged production access?"
grc-pdf evidence report.json AC-2
```

## View examples

Live gallery (GitHub Pages):

https://kfcain.github.io/grc-pdf-mapper/

Gallery source: [`examples/viewer/`](examples/viewer/). Published from [`docs/`](docs/) on the `main` branch.

Regenerate demo artifacts:

```bash
bash examples/sync_pages_gallery.sh
```

## Labs

| Lab | Path |
|---|---|
| Document change control + GitHub Actions | [`lab/README.md`](lab/README.md) |
| Policy-as-code lock-step (docs ↔ Terraform) | [`lab/POLICY-AS-CODE.md`](lab/POLICY-AS-CODE.md) |
| FedRAMP CR26 KSI (Classes A–D) | [`lab/FEDRAMP-CR26-KSI.md`](lab/FEDRAMP-CR26-KSI.md) |

Local simulations:

```bash
bash lab/simulate_risky_pr.sh
bash lab/simulate_pac_lockstep.sh
```

## Pipeline

```
Markdown / PDF / Word / Excel / RTF / …
    → Markdown or txt (native)
    → pdf-inspector (PDF; class + OCR hints)
    → anydoc (office formats; PDF fallback)
    → control statement miner
    → crosswalk (seed / OpenCRE / OSA / OSCAL / FedRAMP KSI)
    → lineage store
    → alerts · blast radius · questionnaire · evidence · OSCAL · sync
```

## Supported ingest formats

| Engine | Formats |
|---|---|
| Native | `.md`, `.markdown`, `.txt` |
| pdf-inspector | `.pdf` (preferred when installed) |
| anydoc | `.doc` `.docx` `.docm` · `.ppt` `.pptx` … · `.xls` `.xlsx` … · `.odt` `.ods` `.odp` · `.rtf` · `.epub` · `.csv` · `.pdf` (fallback) |

## Crosswalk sources

| Source | Role |
|---|---|
| **SCF API** | Primary backbone — 1,468 SCF controls × 249 framework crosswalks ([grcengclub.github.io/scf-api](https://grcengclub.github.io/scf-api/), by ethanolivertroy / GRCEngClub) |
| OpenCRE | Standard sections → Common Requirements |
| Open Security Architecture (OSA) | Framework crosswalks |
| NIST OSCAL | SP 800-53 control titles |
| FedRAMP CR26 KSI | Key Security Indicators + certification doc FRRs by class |
| Seed map | Offline topic → control hints |

Use `--offline` for air-gapped runs (bundled SCF seed + local catalogs).

Map one control through SCF:

```bash
grc-pdf scf-map AC-2
grc-pdf scf-map IAC-01 --offline
```

## Notable commands

```bash
grc-pdf impact <doc-id> <older-snap> <newer-snap>
grc-pdf watch ./policies/access-control.md --doc-id pol-ac-001
grc-pdf ui
grc-pdf sync-check
grc-pdf pac-impact iac-changed --base-tf base.tf --head-tf head.tf
grc-pdf fedramp-ksi --class c --control IA-2
grc-pdf fedramp-docs --class c --must-only
grc-pdf scf-map AC-2
```

## Project layout

```
src/grc_pdf_mapper/   # library + CLI (incl. SCF API client)
lab/                  # sample policies, IaC, FedRAMP catalog, playbooks
examples/viewer/      # static example gallery
docs/                 # GitHub Pages gallery + architecture notes
scripts/              # CI helpers
tests/                # pytest suite
.github/workflows/    # document + policy-as-code gates
```

## Tests

```bash
pytest -q
```

Office ingest tests need `firecrawl-anydoc`:

```bash
python3 -m pip install -e ".[anydoc,dev]"
pytest -q tests/test_ingest_anydoc.py
```

## Attribution

Office conversion uses [Firecrawl anydoc](https://github.com/firecrawl/anydoc).

PDF classification and extraction use [Firecrawl pdf-inspector](https://github.com/firecrawl/pdf-inspector) when installed.

Control mappings use the [Secure Controls Framework](https://securecontrolsframework.com) via the [SCF API](https://grcengclub.github.io/scf-api/) (CC BY-ND 4.0).

## License

MIT
