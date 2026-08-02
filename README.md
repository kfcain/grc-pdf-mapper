# GRC PDF Mapper

GRC tooling for policy documents. Uses [Firecrawl pdf-inspector](https://github.com/firecrawl/pdf-inspector) to classify PDFs and extract Markdown locally.

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
| `pdf` | [pdf-inspector](https://github.com/firecrawl/pdf-inspector) for PDF ingest |

From the repository root (`grc-pdf-mapper/`):

```bash
cd grc-pdf-mapper

python3 -m pip install -e ".[dev]"
```

Optional PDF support (Markdown works without this):

```bash
python3 -m pip install -e ".[pdf,dev]"
```

Then confirm:

```bash
grc-pdf --help
```

If `grc-pdf` is not found, add your user script path (common on Linux):

```bash
export PATH="$HOME/.local/bin:$PATH"
```

Or run as a module:

```bash
python3 -m grc_pdf_mapper --help
```

## Quick start

```bash
grc-pdf analyze tests/fixtures/access_control_policy_v1.md \
  --doc-id pol-ac-001 --version v2.1 --offline --json report.json

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
PDF / Markdown
    → pdf-inspector (or Markdown ingest)
    → control statement miner
    → crosswalk (seed / OpenCRE / OSA / OSCAL / FedRAMP KSI)
    → lineage store
    → alerts · blast radius · questionnaire · evidence · OSCAL · sync
```

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

## Attribution

PDF classification and extraction use [Firecrawl pdf-inspector](https://github.com/firecrawl/pdf-inspector).

Control mappings use the [Secure Controls Framework](https://securecontrolsframework.com) via the [SCF API](https://grcengclub.github.io/scf-api/) (CC BY-ND 4.0).

## License

MIT
