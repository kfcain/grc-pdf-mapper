# FedRAMP CR26 KSI mappings (Classes A–D)

For organizations with **FedRAMP certification**, policy and procedure documents are
not optional narrative — they are part of the certification package lifecycle.

This lab wires [FedRAMP Consolidated Rules for 2026 (CR26)](https://github.com/FedRAMP/rules)
**Key Security Indicators (KSIs)** into document change control and policy-as-code lock-step.

## Classes at a glance

| Class | Legacy impact | KSI automation (FRC-CSX-VVK) | Package maintenance (CPO-CSX-CPM) |
|---|---|---|---|
| **A** | Pilot / minimal | MAY automate KSI validation | SHOULD refresh package every **3 months** |
| **B** | Low | SHOULD (≥1 automated method / KSI) | MUST refresh package every **month** |
| **C** | Moderate | MUST (≥2 automated methods / KSI) | MUST refresh package every **2 weeks** |
| **D** | High | MUST (≥4 automated methods / KSI) | MUST refresh package every **week** |

Source catalog version is embedded in `lab/fedramp/cr26_ksi_catalog.json`
(extracted from `FedRAMP/rules` `fedramp-consolidated-rules.json`).

## What ships here

| Asset | Role |
|---|---|
| `lab/fedramp/cr26_ksi_catalog.json` | 46 KSIs across 10 domains + class applicability + doc FRRs |
| `grc-pdf fedramp-ksi --class c` | List KSIs for a class |
| `grc-pdf fedramp-docs --class c --must-only` | Show MUST documentation obligations |
| Crosswalk integration | Policy statements map to `FedRAMP KSI` hits |
| Assessment registry | Class A/B/C/D FedRAMP certifications |
| Impact alerts | Doc changes notify FedRAMP assessments + package maintenance actions |

## KSI domains (CR26)

- **CED** — Cybersecurity Education
- **CMT** — Change Management
- **CNA** — Cloud Native Architecture
- **IAM** — Identity and Access Management
- **INR** — Incident Response
- **MLA** — Monitoring, Logging, and Auditing
- **PIY** — Policy and Inventory
- **RPL** — Recovery Planning
- **SCR** — Supply Chain Risk
- **SVC** — Service Configuration

Five KSIs **vary by class** (optional on B, required on C/D; optional on A):

- `KSI-CNA-EIS` Enforcing Intended State
- `KSI-MLA-ALA` Authorizing Log Access
- `KSI-SVC-PRR` Preventing Residual Risk
- `KSI-SVC-RUD` Removing Unwanted Data
- `KSI-SVC-VCM` Validating Communications

## Documentation requirements that certifications enforce

These CR26 FRRs are tracked in the catalog and surfaced by `fedramp-docs`:

| ID | Name | Why it matters for document change control |
|---|---|---|
| `CPO-CSX-CPM` | Certification Package Maintenance for 20x | Policy updates must land in the package on the class cadence |
| `CPO-CSO-OSA` | Overall Summary of Assessment | Assessor summary stays aligned with current control language |
| `CPO-CSO-OVR` / `CPO-CSO-MTD` | Package overview + metadata | Document identity / version metadata |
| `FRC-CSX-VVK` | Automated V&V of KSIs | Automation rigor rises A→D |
| `FRC-CSX-MOT` | Metrics over time for KSIs | Historical KSI evidence windows |
| `SDR-CSX-KMT` | KSI metrics in Security Decision Record | Decision-record documentation |

## Quick commands

```bash
# All KSIs applicable to Class C
grc-pdf fedramp-ksi --class c

# Which KSIs does AC-2 / IA-2 touch for Class D?
grc-pdf fedramp-ksi --class d --control AC-2
grc-pdf fedramp-ksi --class d --control IA-2

# MUST documentation obligations for Class C
grc-pdf fedramp-docs --class c --must-only

# Compare optional vs required across classes for a varies-by-class KSI
python3 - <<'PY'
from grc_pdf_mapper.fedramp import FedRampKSICatalog
cat = FedRampKSICatalog('lab/fedramp/cr26_ksi_catalog.json')
for cls in 'a','b','c','d':
    row = next(i for i in cat.for_class(cls) if i['id']=='KSI-SVC-VCM')
    print(cls, row['class_status'])
PY
```

## End-to-end flow for FedRAMP orgs

```
Policy PR changes MFA MUST → SHOULD
        │
        ▼
 Document impact engine
        │
        ├─ Frameworks: NIST 800-53, FedRAMP KSI (e.g. KSI-IAM-*)
        ├─ Assessments: FedRAMP 20x Class A/B/C/D
        └─ Actions: update Certification Package per CPO-CSX-CPM cadence
        │
        ▼
 Policy-as-code lock-step
        │
        └─ Verify Terraform still matches documented KSI outcomes
```

**Rule for certified CSOs:** a documentation change that affects KSI-mapped controls is incomplete until:

1. The policy/procedure text is approved,
2. Linked compliance-as-code still validates the KSI outcome,
3. Certification package / SDR artifacts are refreshed within the class maintenance window.

## Refresh catalog from upstream

```bash
python3 scripts/refresh_cr26_ksi_catalog.py
# or from a local download:
python3 scripts/refresh_cr26_ksi_catalog.py --from-file /tmp/cr26.json
```
