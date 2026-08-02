# Document change control (organization playbook)

Use this playbook for **any** controlled document: policies, procedures, standards,
runbooks, HR handbooks, privacy notices, and vendor addenda.

## Why put documents in GitHub

| Need | How GitHub helps |
|---|---|
| Version history | Every revision is a commit with author + timestamp |
| Approval gate | Pull requests + CODEOWNERS (Legal, GRC, Doc Control) |
| Traceability | PR discussion is the change-control record |
| Automation | GitHub Actions runs impact checks before merge |
| Audit evidence | PR + Action logs show who approved what, when |

This is not only a security/GRC pattern. It is **document change control** for the whole organization.

## Roles

| Role | Responsibility |
|---|---|
| Author | Opens a PR with the proposed wording |
| Document owner | Confirms business intent |
| GRC / compliance | Reviews framework and assessment impact |
| Legal / privacy (as needed) | Reviews regulatory wording |
| Document Control | Confirms template, ID, version, and retention metadata |

## Required PR checklist

1. State why the document must change.
2. List affected products, teams, or regions.
3. Note any external commitment that may break (customer contract, audit window, SLA).
4. Wait for the **Document Change Impact** Action to finish.
5. Resolve critical / high findings before merge, or record an accepted risk.

## Severity guide for merge decisions

| Alert severity | Merge rule |
|---|---|
| critical | Block merge until GRC accepts or wording is restored |
| high | Require GRC approval comment |
| medium | Proceed with owner + Doc Control review |
| low / info | Normal review |

## Mapping to common frameworks

- **ISO 27001** — documented information control (A.5.1 / related clauses)
- **SOC 2** — change management and logical access criteria evidence
- **NIST 800-53** — CM / IR / AC family narratives
- Internal quality systems — controlled document revisioning
