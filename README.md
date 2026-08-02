# GRC PDF Mapper

GRC tooling for policy documents. Uses [Firecrawl pdf-inspector](https://github.com/firecrawl/pdf-inspector) to classify PDFs and extract Markdown locally.

## What it does

1. Extract control-related statements from policy and procedure documents.
2. Keep content-addressed version history for corporate docs.
3. Map statements to frameworks (OpenCRE, OSA, NIST OSCAL, FedRAMP CR26 KSI, seed maps).
4. Alert when wording changes may affect frameworks, assessments, or certifications.
5. Keep documentation and policy-as-code (Terraform) in lock-step.

## Install

```bash
pip install -e ".[dev]"
# Optional PDF support:
pip install -e ".[pdf,dev]"
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

Hosted gallery on GitHub Pages after the repository is published:

https://kfcain.github.io/grc-pdf-mapper/


The gallery source is [`examples/viewer/`](examples/viewer/). Each push to `main` deploys it with [`.github/workflows/pages-examples.yml`](.github/workflows/pages-examples.yml).

Regenerate demo artifacts:

```bash
bash examples/generate_viewer_data.sh
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
| OpenCRE | Standard sections → Common Requirements |
| Open Security Architecture (OSA) | Framework crosswalks |
| NIST OSCAL | SP 800-53 control titles |
| FedRAMP CR26 KSI | Key Security Indicators + certification doc FRRs by class |
| Seed map | Offline topic → control hints |

Use `--offline` for air-gapped runs.

## Notable commands

```bash
grc-pdf impact <doc-id> <older-snap> <newer-snap>
grc-pdf watch ./policies/access-control.md --doc-id pol-ac-001
grc-pdf sync-check
grc-pdf pac-impact iac-changed --base-tf base.tf --head-tf head.tf
grc-pdf fedramp-ksi --class c --control IA-2
grc-pdf fedramp-docs --class c --must-only
```

## Project layout

```
src/grc_pdf_mapper/   # library + CLI
lab/                  # sample policies, IaC, FedRAMP catalog, playbooks
examples/viewer/      # static example gallery
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

## License

MIT
