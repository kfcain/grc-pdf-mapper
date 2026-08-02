# Lab: Policy-as-code / compliance-as-code lock-step

**Goal:** Keep documentation and executable controls on the same lifecycle.

When Terraform (or other compliance-as-code) changes, the system alerts that
linked policy statements may need an update. When policy wording changes, the
system alerts that linked Terraform must be verified or updated. Completeness
scans catch missing links on either side.

```
 Policy statement (MUST MFA)
            │
            │  link_id = lnk-mfa-privileged
            ▼
 Terraform aws_iam_policy.require_mfa
            │
            ▼
 Evidence for IA-2 / SOC 2 CC6.1 / ISO 5.15
```

## Why this matters for organizations

| Role | Benefit |
|---|---|
| GRC | Policy text and technical enforcement stay aligned for audits |
| Platform / IaC | Code PRs cannot silently weaken a documented control |
| Document Control | Doc PRs cannot drop obligations that automation still enforces (or vice versa) |
| Security engineering | Clear ownership via `# grc:` annotations and link manifests |
| Auditors | Traceable path: statement → link → Terraform → control IDs |

## Lab assets

| Path | Role |
|---|---|
| `lab/policies/access-control.md` | Controlled policy |
| `lab/iac/access_control/main.tf` | Terraform implementing policy obligations |
| `lab/policy-as-code-links.json` | Explicit doc ↔ code bindings |
| `scripts/ci_pac_sync.py` | CI lock-step engine |
| `.github/workflows/policy-as-code-lockstep.yml` | GitHub Action |

## Local demo

```bash
bash lab/simulate_pac_lockstep.sh
```

This runs three checks:

1. **Completeness** on the healthy baseline (should pass).
2. **IaC weakened** without a doc update (should fail / alert).
3. **Policy softened** while Terraform still enforces the old MUST (should fail / alert).

Manual commands:

```bash
# Healthy baseline
grc-pdf sync-check

# Terraform changed → demand doc review
grc-pdf pac-impact iac-changed \
  --base-tf /tmp/base.tf --head-tf /tmp/head.tf

# Policy changed → demand IaC verification
grc-pdf pac-impact doc-changed \
  --base-policy /tmp/base.md --head-policy /tmp/head.md
```

## Annotation contract

In Terraform, declare the link above the resource:

```hcl
# grc: link_id=lnk-mfa-privileged; doc_id=pol-ac-001; control_id=IA-2
# grc: statement=Privileged accounts must use multi-factor authentication
resource "aws_iam_policy" "require_mfa" {
  tags = {
    link_id    = "lnk-mfa-privileged"
    doc_id     = "pol-ac-001"
    control_id = "IA-2"
  }
}
```

Then register the same `link_id` in `lab/policy-as-code-links.json`.

## GitHub workflow

1. Open a PR that changes only `lab/iac/access_control/main.tf`.
2. Action posts a **Policy-as-code lock-step** comment.
3. Check fails until the linked policy is reviewed/updated in the same PR (or risk is accepted).
4. Open a PR that softens policy MFA language without Terraform changes.
5. Action fails and lists the Terraform resources that still enforce the old control.

## End-to-end lifecycle rule

**One control change = one change set covering:**

1. Policy / procedure language
2. Policy-as-code / Terraform (or an explicit “manual control” exception)
3. Assessment / evidence notes if an audit window is active

If any layer moves alone, the lock-step gate alerts and can block merge.
