# Production cross-repository monitoring

Use `production-monitor` when controlled documents and production Terraform are in different Git repositories. The monitor reads local, trusted checkouts. The CI system is responsible for authentication and checkout. The engine does not store repository credentials.

## Decision flow

One monitor run does these checks:

1. Verify each checkout against a full commit ID. Reject dirty, untracked, ignored, symbolic-link, or missing monitored inputs.
2. Scan all configured Terraform roots in all enrolled IaC repositories.
3. Compare the current policy and IaC against each human-reviewed link.
4. Compare current commits with the last aligned commits. This detects policy-only, IaC-only, and coordinated changes.
5. Require exact policy and Terraform domain labels from the shared taxonomy.
6. Map the affected controls through the offline SCF catalog to framework and assessment context.
7. Write an evidence report and a durable finding state.
8. Fail CI and send a webhook for a new mismatch. Send a new webhook when a new source revision has the same active finding. Suppress only a repeat evaluation of the same finding and the same source revisions. Send a recovery event after alignment is restored.

Run the monitor on source-repository events and on a schedule. A source event supplies only an enrolled source alias and a full commit ID. It cannot supply a repository name or path. A scheduled run resolves the protected source refs to full commit IDs. Thus, it can find missed events and out-of-band changes.

To add more documentation or IaC repositories, add each repository to `repositories`. Each target selects one policy file from one enrolled documentation repository and one or more roots from the enrolled IaC repositories. Use `iac_repositories` and module-qualified `terraform_addresses` in each link. An unqualified address that matches more than one module is a critical ambiguity.

## What the monitor proves

For each run, the report records:

- The full Git commit ID for each documentation and IaC repository.
- The full evaluator commit ID.
- A SHA-256 digest for the configuration, link manifest, classifier corpus, and offline SCF catalog.
- A decision fingerprint that includes the digest of each evaluated policy and IaC source file.
- A SHA-256 digest and parser count for each monitored IaC input file.
- Explicit links between policy statements and repository-qualified Terraform resources.
- Policy, Terraform, wording-change, alignment, and SCF classifier-gate results.
- SCF-enriched framework and assessment context.
- The final severity, finding fingerprint, notification result, and recovery state.

The monitor fails closed when a required input is missing, a repository is dirty, a monitored file is not a regular Git-tracked file at the selected commit, a Terraform root is missing, the classifier corpus gate fails, protected state is missing or incomplete, or a required notification cannot be delivered. `require_existing_state` is fixed to `true` by the production schema and cannot be disabled. Use the explicit bootstrap control only for the approved baseline run. The example workflow also checks for state before it starts the evaluator.

## Required repository layout

Keep a strict link manifest in the documentation repository:

```json
{
  "schema_version": 1,
  "links": [
    {
      "link_id": "lnk-prod-mfa",
      "doc_id": "pol-ac-prod",
      "statement_anchor": "Privileged accounts must use multi-factor authentication",
      "expected_domains": ["access_control"],
      "expected_statement_kind": "obligation",
      "expected_strength": "must",
      "expected_action_polarity": "positive",
      "control_ids": ["IA-2", "AC-3"],
      "iac_repositories": ["production-platform-iac"],
      "iac_paths": ["environments/production/identity/main.tf"],
      "terraform_resource_types": ["aws_iam_policy"],
      "owner": "Identity Engineering"
    }
  ]
}
```

`expected_domains`, `expected_statement_kind`, `expected_strength`, and `expected_action_polarity` are human-reviewed ground truth. The production manifest requires all four. The policy duty and both classifiers must match this ground truth. Thus, a waiver cannot replace a required duty only because it has the same security domain. A missing or unexpected value blocks the production gate. Use a Terraform annotation when a provider resource is not in the reviewed rules:

```hcl
# grc: link_id=lnk-prod-mfa; domain=access_control; control_id=IA-2; role=preventive
resource "custom_identity_guard" "mfa" {
  enabled = true
}
```

## Run locally

Create a virtual environment. Do not install into the Homebrew-managed Python environment.

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -e ".[docs,ui,dev]"
```

Copy `examples/production-monitor.json` and change its repository roots, targets, and environment variable names. Then run:

```bash
export GRC_DOCS_SHA="$(git -C ../production-docs rev-parse HEAD)"
export GRC_PLATFORM_IAC_SHA="$(git -C ../platform-iac rev-parse HEAD)"
export GRC_SECURITY_IAC_SHA="$(git -C ../security-iac rev-parse HEAD)"
export GRC_TOOL_REVISION="$(git rev-parse HEAD)"
export GRC_ALERT_WEBHOOK="https://your-approved-alert-endpoint.example"

grc-pdf classifier-validate tests/fixtures/classifier_corpus.json \
  --minimum-score 0.95 \
  --json classifier-validation.json

export GRC_MONITOR_ALLOW_STATE_BOOTSTRAP=true
grc-pdf production-monitor production-monitor.json \
  --state /protected/grc-state/production.json \
  --fail-on medium \
  --json production-monitor-report.json
unset GRC_MONITOR_ALLOW_STATE_BOOTSTRAP
```

Use `GRC_MONITOR_ALLOW_STATE_BOOTSTRAP=true` only for the one approved aligned baseline. The configuration must have `require_existing_state` set to `true`; `false` is invalid. Remove the variable after that run. All later local, scheduled, and event runs must stop if the protected state is not available.

## Alert lifecycle

The finding fingerprint does not include the run time or source commit IDs. Equal active findings get the same finding fingerprint. Notification de-duplication uses the finding fingerprint and the input fingerprint together. Thus, a repeat run of the same source revisions is quiet, but each new source revision with an active finding sends a new notification.

The state keeps two revision sets:

- `last_observed_revisions` records the most recent run.
- `last_accepted_revisions` moves only after an aligned result.

This rule keeps an unapproved change active. A scheduled run does not clear an alert only because it has already seen the new commit.

Start with one aligned baseline run. Make this run with the explicit manual `bootstrap_state` input. A schedule or a `repository_dispatch` event cannot create a baseline. Before the first run, an approver must verify the selected source revisions. Keep `require_existing_state` set to `true` during and after bootstrap. The one-run bootstrap control is the only exception. The monitor does not accept a mismatch as the historical baseline. Its state also records the finding state, first and last seen times, and the occurrence count.

Use one protected state file for one `monitor_id`. Do not put this file in a source repository that the monitor scans. Use CI concurrency control or an external state service to prevent two writers. The example uses the GitHub Actions cache and stops if the cache does not restore the state file. For stronger retention, replace the cache steps with a protected durable object or state service. Never silently make a new baseline after state loss.

## Notification routes

Set webhook URLs only through environment variables. Do not put secrets in the JSON configuration. The webhook receives a compact event with these fields:

- Event name: `grc.policy_iac.misaligned` or `grc.policy_iac.recovered`.
- Monitor ID, severity, and status.
- Input and finding fingerprints.
- Repository commit IDs.
- Up to 30 findings.

The generic payload has a top-level `text` field for simple chat webhooks. Route it through an approved relay when Slack, Teams, PagerDuty, email, a SIEM, or an issue tracker needs a vendor-specific format.

## CI security boundary

The example workflow in `examples/github/production-cross-repo-lockstep.yml` uses these controls:

- A trusted evaluator commit is selected by the protected `GRC_TOOL_SHA` variable.
- Protected repository and ref variables enroll the three source repositories. The workflow resolves each ref to a full commit ID before checkout.
- A `repository_dispatch` event can replace one resolved source commit. It must use a known alias and a full commit ID. Checkout verifies that the commit belongs to the enrolled repository.
- All third-party actions use full commit IDs.
- The evaluator installs pinned build and runtime versions from `requirements-production.lock` and disables isolated, unpinned build dependency resolution.
- Source checkout credentials are not kept in Git configuration.
- The analysis job has read-only repository permissions.
- The private-repository token has `contents:read` access only to approved source repositories.
- The alert webhook is available only to the trusted evaluator step.
- Evidence is required even when the gate fails.
- A concurrency group prevents state races.

Set these protected source variables:

- `GRC_DOCS_REPOSITORY` and `GRC_DOCS_REF`
- `GRC_PLATFORM_IAC_REPOSITORY` and `GRC_PLATFORM_IAC_REF`
- `GRC_SECURITY_IAC_REPOSITORY` and `GRC_SECURITY_IAC_REF`

The source repository must send this client payload to the monitor repository:

```json
{
  "event_type": "grc-production-source-changed",
  "client_payload": {
    "source_alias": "platform-iac",
    "source_sha": "0123456789abcdef0123456789abcdef01234567"
  }
}
```

The allowed aliases are `documentation`, `platform-iac`, and `security-iac`. Do not add a repository, ref, path, or checkout URL to the event payload.

Use a GitHub App installation token instead of a personal token when possible. GitHub documents that a workflow can check out another private repository with a token, and it recommends a GitHub App as a more durable option.

## Limits

The deterministic classifiers cannot be perfect for all policy language or all Terraform providers. The corpus gate proves performance only for the reviewed cases in that corpus. Add real false positives and false negatives to the corpus before the classifier rule changes.

The monitor does not follow symbolic links. Every evaluated policy and IaC input must be a regular file tracked at the selected Git commit. This prevents an ignored file or an external link target from changing the decision outside the recorded source revision.

The Terraform parser classifies resource blocks. A change to another monitored IaC input, such as a variable, local value, module source, provider setting, `.tfvars` file, or policy template, creates a high-severity `unclassified_iac_file_change`. This rule also applies when the same `.tf` file has a parsed resource change. Tracked `vendor` directories are scanned; only known generated cache directories are excluded. Add Terraform plan and control-test evidence before approval.

SCF enrichment shows control context. It does not prove that a Terraform plan enforces the policy. Keep plan assertions, owner approval, and assessment evidence as separate approval inputs.
