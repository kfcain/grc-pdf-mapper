# Lab: GitHub document change control + impact alerts

**Goal:** Show how any organization can use GitHub + GitHub Actions to version controlled documents and get real-time warnings when wording changes may affect frameworks, audits, or customer trust work.

This lab is useful for:

- GRC / compliance teams
- Document Control / quality teams
- Legal and privacy reviewers
- Security governance
- Platform engineering (CI owners)

## What you will see

1. A policy lives in Git (`lab/policies/access-control.md`).
2. Someone opens a PR that softens MFA language.
3. GitHub Actions compares base vs head wording.
4. The Action comments on the PR with:
   - language deltas
   - frameworks at risk
   - assessments at risk
5. The check **fails** on `high` / `critical` so merge needs deliberate approval.

```
Author edits policy
        │
        ▼
   Pull Request  ──► CODEOWNERS (Doc Control + GRC)
        │
        ▼
 GitHub Action: Document Change Impact
        │
        ├─ version base + head
        ├─ detect verbiage risk
        ├─ map frameworks / assessments
        └─ PR comment + optional fail gate
```

## Lab files

| Path | Role |
|---|---|
| `lab/policies/access-control.md` | Sample controlled policy (approved baseline) |
| `lab/assessments.json` | Active assessments that depend on this policy |
| `lab/DOCUMENT-CHANGE-CONTROL.md` | Org playbook for document revisioning |
| `.github/workflows/doc-change-impact.yml` | CI workflow |
| `.github/CODEOWNERS` | Required reviewers |
| `.github/PULL_REQUEST_TEMPLATE/document-change.md` | PR intake form |
| `scripts/ci_doc_impact.py` | Impact engine used by CI |

## Part A — Run the impact check locally (5 minutes)

```bash
cd /path/to/grc-pdf-mapper
pip install -e ".[dev]"

# Simulate a risky PR edit
cp lab/policies/access-control.md /tmp/policy-base.md
cp lab/policies/access-control.md /tmp/policy-head.md
python3 - <<'PY'
from pathlib import Path
p = Path('/tmp/policy-head.md')
text = p.read_text()
text = text.replace(
    'Privileged accounts must use multi-factor authentication.',
    'Privileged accounts should use multi-factor authentication when feasible.',
)
text = text.replace('**Version:** 2.1', '**Version:** 2.2-DRAFT')
p.write_text(text)
print('Softened MFA obligation in /tmp/policy-head.md')
PY

python3 scripts/ci_doc_impact.py \
  --base-file /tmp/policy-base.md \
  --head-file /tmp/policy-head.md \
  --doc-id pol-ac-001 \
  --assessments lab/assessments.json \
  --fail-on high \
  --comment-out /tmp/impact-comment.md \
  --json-out /tmp/impact-alert.json \
  --offline

echo "Exit code was $? (1 means blocked as high/critical)"
sed -n '1,80p' /tmp/impact-comment.md
```

Expected result:

- Severity is `critical` or `high` because MUST → SHOULD is obligation softening.
- Frameworks listed include NIST 800-53 / ISO 27001 / SOC 2 / CSF.
- Assessments listed include SOC 2 Type II and ISO surveillance.
- Process exits `1` (merge gate would fail).

Or run the packaged helper:

```bash
bash lab/simulate_risky_pr.sh
```

## Part B — GitHub Actions walkthrough

### 1. Push this project to GitHub

```bash
gh repo create your-org/doc-change-control-lab --private --source=. --remote=origin --push
```

Or create an empty repo in the GitHub UI and push:

```bash
git remote add origin git@github.com:your-org/doc-change-control-lab.git
git push -u origin HEAD:main
```

### 2. Enable required checks (optional but recommended)

In the repo:

1. Settings → Branches → Branch protection rule for `main`
2. Require a pull request before merging
3. Require status checks: **Framework & assessment impact**
4. Require review from CODEOWNERS

Replace `@document-control` / `@grc-team` in `.github/CODEOWNERS` with real teams.

### 3. Open a risky document PR

```bash
git checkout -b lab/soften-mfa
# edit lab/policies/access-control.md — change MUST MFA to SHOULD
git add lab/policies/access-control.md
git commit -m "Lab: soften privileged MFA language"
git push -u origin lab/soften-mfa
gh pr create --title "Lab: soften privileged MFA language" \
  --body-file .github/PULL_REQUEST_TEMPLATE/document-change.md
```

### 4. Observe the Action

On the PR:

1. Open the **Checks** tab → **Document Change Impact**
2. Read the bot comment with frameworks + assessments at risk
3. Download the `document-change-impact` artifact (`impact-alert.json`)
4. Confirm the check failed for high/critical wording risk

### 5. Fix or accept risk

Two clean lab endings:

**Restore control language (preferred demo):**

```bash
# restore MUST MFA wording, push, watch check go green/low
```

**Accepted risk path:**

- GRC comments on the PR: risk accepted until date X
- Temporarily set workflow `fail-on` to `critical` only, or use an environment approval gate

## Part C — Make this appealing beyond security

Frame the same pipeline as **enterprise document change control**:

| Audience | Value |
|---|---|
| Document Control | Immutable revision history + required reviewers |
| GRC | Instant view of audit/framework blast radius |
| Legal / Privacy | Early warning before public or customer-facing wording ships |
| Business owners | PR template forces purpose + rollback plan |
| Auditors | PR + Action logs are ready-made change records |
| Platform teams | One reusable workflow for all controlled docs |

### Adoption tips

1. Start with Markdown exports of Word policies in `lab/policies/` (or `policies/`).
2. Keep PDFs as published artifacts; keep Git as the system of record for wording.
3. Register active audits in `lab/assessments.json` so alerts name real initiatives.
4. Use CODEOWNERS so Legal/GRC are not optional.
5. Keep `fail-on: high` for production; use `medium` only while onboarding.

### Optional webhook

Add a repository secret `DOC_IMPACT_WEBHOOK_URL` and extend the workflow to POST `impact-alert.json` to Slack/Teams for real-time awareness outside GitHub.

## Success criteria

You completed the lab when:

- [ ] Local CI script blocks a softened MFA obligation
- [ ] A GitHub PR receives an impact comment
- [ ] CODEOWNERS requests GRC / Document Control review
- [ ] Stakeholders can name at least one assessment that would be affected
- [ ] You also ran the policy-as-code lock-step lab in [`POLICY-AS-CODE.md`](POLICY-AS-CODE.md)
- [ ] You reviewed FedRAMP CR26 KSI class mappings in [`FEDRAMP-CR26-KSI.md`](FEDRAMP-CR26-KSI.md)
