## Policy-as-code lock-step check

**Trigger:** `iac_changed`  
**Severity:** `high`  
**Alert ID:** `d1d1248111c65899`

[HIGH] Terraform change touches policy-as-code links: 1 resource delta(s), 1 lifecycle gap(s). Documentation review required to keep the control lifecycle complete.

### Changed IaC paths

- `/agent/grc-pdf-mapper/examples/viewer/data/tf-head.tf`

### Linked policy statements

- Privileged accounts must use multi-factor authentication

### Linked Terraform

- `aws_iam_policy.require_mfa`

### Lifecycle gaps

| Kind | Severity | Detail | Action |
|---|---|---|---|
| `iac_changed_requires_doc_review` | `high` | Terraform aws_iam_policy.require_mfa was changed. Linked policy language: 'Privileged accounts must… | Open/update document 'pol-ac-001' so the obligation remains accurate for this Terraform behavior, t… |

### Recommended actions

- Open/update document 'pol-ac-001' so the obligation remains accurate for this Terraform behavior, then re-run sync-check.

---
_Docs and compliance-as-code must move together. Do not merge only one side of a control change._
