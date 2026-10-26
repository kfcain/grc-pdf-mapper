# Review: Cursor pass (2026-10-26)

Repository: kfcain/grc-pdf-mapper, public `main` at `c340144`. Review only. No application code was changed.

Checked on 2026-10-26 against `https://raw.githubusercontent.com/FedRAMP/rules/main/fedramp-consolidated-rules.json` (upstream `info.version` `2026.10.13.01`, `last_updated` `2026-10-13`).

## 1. Verdict

Yes. This repo is useful as a local review workbench and a lab harness. It is not useful as a system of record that a control is met. The production monitor, the lineage store, and the policy-as-code diff are the parts worth keeping. The FedRAMP map and the OSCAL export need a correction pass before anyone teaches from them or wires them to a bot.

The three highest-value uses:

1. **Evidence pipelines and the GRC bot fleet.** `production-monitor` already pins full commit ids, rejects symlinks and dirty trees, records file and catalog digests, and fails closed. That is a review queue, not a determination. Point bots at the mismatch and recovery events.
2. **Proofyard GRC labs.** The document-change and Terraform lock-step labs (`lab/`, the two gate workflows, `lab/simulate_risky_pr.sh`, `lab/simulate_pac_lockstep.sh`) are a concrete exercise in "wording changed, code did not" and the reverse. Fix the first-file gap in the workflows before treating a green check as coverage of the whole pull request.
3. **Control Current, FedRAMP 20x Classes A–D.** The class-aware KSI catalog, `grc-pdf fedramp-ksi`, and the impact actions are the right shape for a teaching site. Refresh the catalog first. The published pages still show machine severity badges and assessment names that read as live, and the lab notes still equate Class B/C/D with Low/Moderate/High.

## 2. Correctness

### Tests

Command: `python3 -m pip install -e ".[dev]"` then `python3 -m pytest -q`.

**112 passed, 0 failed, 2 skipped** (93.61s).

Skips, both at import, because the brief's install does not include the optional extras:

- `tests/test_ui.py:9` — `fastapi` is not installed, so the GUI tests did not run.
- `tests/test_ingest_anydoc.py:15` — `anydoc` is not installed, so office-ingest tests did not run.

A green run does not mean the FedRAMP catalog is current. `tests/test_fedramp_ksi.py:16` only requires a version that starts with `2026` and exactly 46 indicators. Both are still true of the July extract.

### Mapping

Explicit citations are handled with care. `src/grc_pdf_mapper/scf/__init__.py:203` does not replace an unknown citation with an unrelated domain hit, and `tests/test_scf_crosswalk.py:65` locks that. Offline SCF hits are a **96-control seed** (`src/grc_pdf_mapper/scf/offline_seed.json`, key `controls`), not the 1,468 controls named in `README.md:158`. The seed's NIST reverse index is larger (810 keys) than the control records. The GUI defaults to offline (`src/grc_pdf_mapper/ui/static/index.html:21`), and the doc-impact workflow passes `--offline`, so CI is on this subset. Offline hits are still labeled `source="scf-api"` at `src/grc_pdf_mapper/scf/__init__.py:290`.

The FedRAMP keyword map over-matches. `src/grc_pdf_mapper/fedramp/__init__.py:124` uses `token in text`, so the letters `log` inside "logical" select the whole MLA domain, and `policy` selects every PIY indicator. A one-line probe of "This policy defines how the organization manages logical access." returned 10 KSI hits (every PIY KSI and every MLA KSI). "User accounts must be uniquely assigned to an individual." returned all 6 IAM KSIs. On `lab/policies/access-control.md`, 23 statements produced mostly topic hits of that shape. `_family_base_match` at `src/grc_pdf_mapper/fedramp/__init__.py:269` also treats a base control as a hit for every enhancement.

OpenCRE online matching (`src/grc_pdf_mapper/crosswalk/__init__.py:268`) downloads one ISO page and keeps a section when any keyword is a substring of the section name. OSA is not a live API: `GET https://opensecurityarchitecture.org/api/v1/frameworks` returned **404** on this review. Callers at `src/grc_pdf_mapper/crosswalk/__init__.py:14` and `:167` swallow that and return no rows.

### Classifier

The policy and Terraform classifiers are the strongest local logic. They record kind, confidence, and reasons, and the regression tests passed. Confidence is capped by the classifier when an SCF hit is built (`src/grc_pdf_mapper/scf/__init__.py:286`). That is the right direction. The FedRAMP topic hits above ignore that care and stamp `0.55` on a whole domain.

### CR26 KSI catalog freshness

The KSI **id set** is still current: 46 ids, same 10 domains, no ids added or removed.

The **catalog body is not current.** Local source is `2026.07.14.01` (`lab/fedramp/cr26_ksi_catalog.json:3`). Upstream on 2026-10-26 is `2026.10.13.01`.

- 40 of 46 indicators have a different `controls` list. Counted against upstream: **191 control ids present upstream and missing locally, 6 present locally and absent upstream.**
- `FRC-CSX-MOT` is still a Class C/D MUST at `lab/fedramp/cr26_ksi_catalog.json:1952`. That id is **gone** from upstream `FRR`. A refresh today KeyErrors: `src/grc_pdf_mapper/fedramp/extract.py:45` hard-codes the id and `:53` indexes it.
- `SDR-CSX-KMT` Class B is `MUST` at `lab/fedramp/cr26_ksi_catalog.json:2003`. Upstream force for that class is `SHOULD`.
- Package-maintenance numbers for `CPO-CSX-CPM` still match upstream (Class A 3 months, B 1 month, C 2 weeks, D 1 week).
- When `varies_by_class` omits a class, `src/grc_pdf_mapper/fedramp/extract.py:86` invents Class A as optional and Class D as required, copying the Class C statement. Upstream still publishes only `b` and `c` for the five varying KSIs (`KSI-CNA-EIS`, `KSI-MLA-ALA`, `KSI-SVC-PRR`, `KSI-SVC-RUD`, `KSI-SVC-VCM`). Those class statements match for `b` and `c`. The A/D rows are local inventions.
- `src/grc_pdf_mapper/fedramp/extract.py:57` writes `REQUIRED` when `force` is missing. The KSI path at `:137` does honor a leading `**Optional:**`. The documentation path does not.

### SCF crosswalk

Usable offline for cited NIST ids that the seed can reverse, and honest about unknown SCF ids. Not a full SCF mirror. Online mode calls `https://grcengclub.github.io/scf-api/` and falls back to the seed on HTTP errors (`src/grc_pdf_mapper/scf/__init__.py:352`). The bundled file copies SCF titles and descriptions under a CC BY-ND 4.0 attribution (`src/grc_pdf_mapper/scf/offline_seed.json:1`). That license is named. A public no-derivatives copy still needs a rights check before this seed is treated as redistributable.

### OSCAL output

`grc-pdf oscal` writes an OSCAL-shaped component definition and an assessment-results sketch (`src/grc_pdf_mapper/oscal/__init__.py:12` and `:83`). It is not a NIST-valid document. Control ids are lowercased as stored, so SCF's zero-padded forms (`CP-01`) become `cp-01` at `:41`. OSCAL Rev 5 ids are unpadded (`cp-1`). The offline title index is six hard-coded controls (`src/grc_pdf_mapper/crosswalk/__init__.py:323`). The assessment export sets `satisfied_as_documented` at `src/grc_pdf_mapper/oscal/__init__.py:105` for every must, shall, and prohibited sentence. That status says the control is met because the policy says so.

### Change-impact alerts

The verbiage diff (softened, removed, reversed, scope reduced) is implemented and covered by tests. Recommended actions tell a person to review before approval (`src/grc_pdf_mapper/impact/__init__.py:928`). That part is sound.

The cadence sentence is not. `src/grc_pdf_mapper/impact/__init__.py:988` prints `every {n} {timeframe_type}` with the raw plural, so the published sample says "every 1 months" and "every 1 weeks" (`docs/data/impact-alert.json:262` and `:266`). The same pattern is in `src/grc_pdf_mapper/cli.py:773`. FedRAMP actions in those alerts also still name `FRC-CSX-MOT` and treat Class B `SDR-CSX-KMT` as MUST, because they read the stale catalog.

### Terraform lock-step

The library compares linked resources, flags an IaC-only or doc-only change, and asks for review (`src/grc_pdf_mapper/sync/__init__.py:501` and `:675`). It does not claim the plan enforces the policy. Symlinks are rejected (`src/grc_pdf_mapper/terraform_scan/__init__.py:51`). `production-monitor` is stricter: full commit ids, repository-qualified addresses, corpus gate, and no silent re-baseline.

The GitHub gates do not cover the pull request they claim to cover. Both workflows keep only the first changed policy file:

- `.github/workflows/doc-change-impact.yml:69`
- `.github/workflows/policy-as-code-lockstep.yml:57`

A second policy file in the same pull request is never scored. Terraform scanning in the lock-step job does walk the tree. The document side does not.

## 3. Security

No secret values are written here. Findings are file and line only.

**Names.** A search of the work tree and of all git history found no `Onebrief` and no `Workstreet`. No other employer, client, or personal name stood out. `CODEOWNERS` uses placeholder teams. Public attribution (the GitHub owner, SCF API authors, FedRAMP) is expected in a public repo.

**Secrets in code and history.** No private-key blocks and no AWS-style access-key ids in the current tree or in `git log -G` over all history. The production example reads a token from GitHub secrets (`examples/github/production-cross-repo-lockstep.yml:41`) and does not store it in the repo. Webhook URLs in docs are placeholders.

**File handling.** The GUI takes `Path(name).name`, so an upload filename cannot leave the temp directory (`src/grc_pdf_mapper/ui/app.py:130`). The 40 MB cap is applied only after `file.read()` loads the body (`src/grc_pdf_mapper/ui/app.py:120`). CLI ingest reads the whole file with no cap (`src/grc_pdf_mapper/ingest/__init__.py:72`). Office and PDF parsing is delegated to anydoc and pdf-inspector with no decompression limit, so a zip-backed document can expand far past the upload cap. Unreadable converter errors are returned to the client at `src/grc_pdf_mapper/ui/app.py:148`. `Content-Disposition` quotes `doc_id` directly at `:156`.

**FastAPI UI.** Default bind is loopback (`src/grc_pdf_mapper/cli.py:417`, `src/grc_pdf_mapper/ui/app.py:217`). There is no auth and no CORS middleware. A caller can pass `--host` and listen on a non-loopback address with the same unauthenticated upload route. API docs are disabled (`src/grc_pdf_mapper/ui/app.py:25`). The browser escapes row HTML (`src/grc_pdf_mapper/ui/static/app.js:103`).

**CI permissions and pins.**

- `ci.yml` sets no `permissions` and pins nothing: `actions/checkout@v4` and `actions/setup-python@v5` at `.github/workflows/ci.yml:11`.
- The two gate workflows set `contents: read` and `pull-requests: write`, and use floating tags: `actions/checkout@v4`, `actions/setup-python@v5`, `actions/upload-artifact@v4`, `actions/github-script@v7` (`.github/workflows/doc-change-impact.yml:31`, `:36`, `:120`, `:131` and `.github/workflows/policy-as-code-lockstep.yml:25`, `:29`, `:123`, `:133`).
- The production **example** workflow does pin checkout and cache restore by commit (`examples/github/production-cross-repo-lockstep.yml:109` and `:149`). The workflows that run on this repo do not.
- Script injection: `workflow_dispatch` inputs are interpolated into the shell at `.github/workflows/doc-change-impact.yml:51`. The changed path is written to `$GITHUB_OUTPUT` and later expanded with `${{ }}` at `:85`. The lock-step job does the same at `.github/workflows/policy-as-code-lockstep.yml:87`. A pull-request filename can break out of the quotes. `pull_request` from a fork gets a read-only token, and this repo's workflows do not use `pull_request_target`. The write permission is still on the job for same-repo pull requests, and the runner still executes the injected script.

**Dependency risk.** `requirements-production.lock` is a freeze from 2026-08-05 with no hashes, and CI does not install from it. This review's `.[dev]` install resolved pydantic 2.14.1; the lock says 2.13.4. Ranges in `pyproject.toml` are `>=` only.

**Public gallery.** Published JSON and Markdown include absolute build paths, for example `docs/data/report-v1.json:5` and `docs/data/pac-iac-impact.md:11` (same lines under `examples/viewer/data/`). They are machine paths, not credentials. They should not be on a public Pages site.

## 4. GRC accuracy

FedRAMP wording in the product path uses Class A/B/C/D, and the impact sample names "FedRAMP 20x Class A Certification" rather than an impact level. That part matches 20x.

The lab and the extractor undo it. `lab/FEDRAMP-CR26-KSI.md:14` equates Class B with Low, Class C with Moderate, and Class D with High. `src/grc_pdf_mapper/fedramp/extract.py:25` writes those words into every refresh, and the catalog stores them at `lab/fedramp/cr26_ksi_catalog.json:17`, `:22`, and `:27`. 20x classes are not those baselines. The words should not appear.

No "authority to operate" or standalone ATO wording turned up in the tree.

Two places talk like a tool can prove an outcome:

- `src/grc_pdf_mapper/oscal/__init__.py:105` sets assessment status `satisfied_as_documented` from policy sentences alone. The component text at `:73` calls those "Implemented controls inferred from policy obligations."
- `docs/PRODUCTION-CROSS-REPO.md:22` is titled "What the monitor proves." The paragraph at `:179` is the accurate one: SCF context does not prove a Terraform plan enforces the policy. The heading should follow that paragraph.

Demo data is not labeled demo. The Pages lede says "Example outputs" and the chip says "offline samples" (`docs/index.html:184` and `:188`). Severity badges render the raw value (`docs/index.html:279`). `lab/assessments.json:6` marks sample assessments `active`, and the gate workflows comment with those names, including four "FedRAMP 20x Class … Certification" rows. A reader can take the public gallery for a live program.

## 5. UI

Reviewed from source. This pass did not start the GUI and did not publish Pages.

**Local GUI** (`src/grc_pdf_mapper/ui/static/`). Dark, one column, drop zone, underline tabs, IBM Plex, 150–220ms transform and opacity, and a `prefers-reduced-motion` still at `app.css:221`. No pulsing dots and no three-dot loader. The status line is a sentence. Those parts meet the motion rule and the local DESIGN.md night-audit palette.

They do not meet the kit:

- Base is `oklch(0.12 0 0)` and the accent is moss hue 160 (`app.css:2` and `:8`), not `#0B0C0F` and `#1A8CFF`.
- Amber is the color of every must and shall (`app.css:384`), not a spare `#FF9900`.
- No colored left-edge bar. Good.
- Machine control hits render as `framework:id` in the accent color (`app.js:80`, `app.css:416`) with no muted red **Not verified** outline chip.
- Copy is short, and two lines are wrong or clipped: the tagline "Local policy parse · control map" (`index.html:18`) and "Mapping export from the crosswalk API results." (`index.html:102`) while "Offline maps" is checked by default.
- The page loads IBM Plex from Google (`index.html:10`) on a tool that is supposed to stay on the machine.

**Pages viewer** (`docs/index.html`, identical to `examples/viewer/index.html`). Cream paper `#f3efe4`, Newsreader display type, teal `#0f6b5c` (`docs/index.html:12`). That is the parchment editorial look DESIGN.md rejects, and it is not the kit. A summary card uses a 3px left accent bar at `:166`. There is no reduced-motion rule because there is no motion. There is no Not verified chip. The severity chip uses live words (`critical`, `high`) at `:151` and `:279`. The empty state is the static sentence "Loading hosted example data…" (`:205`), not an animated loader. Fonts again come from Google (`:9`).

## 6. Prioritized list

### Must-fix

- `lab/fedramp/cr26_ksi_catalog.json:3` — Re-extract from FedRAMP/rules `2026.10.13.01`, drop `FRC-CSX-MOT` (`:1952`), set Class B `SDR-CSX-KMT` to SHOULD (`:2003`), and replace the 40 stale NIST control lists.
- `src/grc_pdf_mapper/fedramp/extract.py:45` — Look up documentation ids that exist, and do not KeyError when upstream removes one; do not default a missing `force` to REQUIRED (`:57`).
- `lab/FEDRAMP-CR26-KSI.md:14` — Delete the Low / Moderate / High column, and stop writing those strings in `src/grc_pdf_mapper/fedramp/extract.py:25` and `lab/fedramp/cr26_ksi_catalog.json:17`.
- `src/grc_pdf_mapper/fedramp/__init__.py:124` — Match whole words, and attach only the KSI that fits the sentence or an explicit control, not every indicator in the domain.
- `src/grc_pdf_mapper/oscal/__init__.py:105` — Emit a not-verified review state, and do not mark a policy sentence as satisfied or implemented.
- `.github/workflows/doc-change-impact.yml:69` — Score every changed policy file; the lock-step workflow has the same first-file cut at `.github/workflows/policy-as-code-lockstep.yml:57`.
- `.github/workflows/doc-change-impact.yml:85` — Pass paths and `workflow_dispatch` inputs (`:51`) through the environment; do the same at `.github/workflows/policy-as-code-lockstep.yml:87`.
- `docs/index.html:184` — Label the gallery and the severity badge (`:279`) as demo, and mark `lab/assessments.json:6` as demo so CI comments cannot read as a live certification.

### Should-fix

- `src/grc_pdf_mapper/impact/__init__.py:988` — Pluralize from the number so Class B reads "every 1 month" and Class D reads "every 1 week" (same pattern at `src/grc_pdf_mapper/cli.py:773`).
- `src/grc_pdf_mapper/fedramp/extract.py:86` — Leave Class A and Class D unset when upstream does not publish them.
- `src/grc_pdf_mapper/crosswalk/__init__.py:14` — Remove the OSA client until a real endpoint exists (the documented URL returned 404).
- `src/grc_pdf_mapper/crosswalk/__init__.py:286` — Require a control id or a whole-word match before keeping an OpenCRE section.
- `src/grc_pdf_mapper/scf/__init__.py:290` — Label offline hits `seed`, and change `README.md:158` so it does not say the bundle is 1,468 controls.
- `src/grc_pdf_mapper/scf/offline_seed.json:1` — Confirm CC BY-ND allows this public copy, or ship identifiers without SCF description text.
- `src/grc_pdf_mapper/oscal/__init__.py:41` — Emit unpadded OSCAL Rev 5 control ids.
- `src/grc_pdf_mapper/fedramp/__init__.py:269` — Do not treat a base control as every enhancement.
- `docs/index.html:12` — Restyle the Pages viewer to `#0B0C0F` / `#1A8CFF` / spare `#FF9900`, and remove the left bar at `:166` (same file under `examples/viewer/`).
- `src/grc_pdf_mapper/ui/static/app.css:2` — Switch the local GUI to the kit colors, and add a muted red "Not verified" outline chip on each machine hit (`src/grc_pdf_mapper/ui/static/app.js:80`).
- `src/grc_pdf_mapper/ui/static/index.html:102` — Say "offline seed" when the offline box is checked.
- `docs/PRODUCTION-CROSS-REPO.md:22` — Rename the section so it describes recorded evidence, and keep the limit already stated at `:179`.
- `src/grc_pdf_mapper/ui/app.py:120` — Enforce the size limit while reading, and reject a non-loopback `--host` unless the operator sets an explicit flag (`src/grc_pdf_mapper/cli.py:417`).
- `src/grc_pdf_mapper/ui/app.py:156` — Strip quotes and newlines from the download filename.
- `src/grc_pdf_mapper/ingest/__init__.py:72` — Cap read size and decompressed size for CLI and UI.
- `.github/workflows/ci.yml:11` — Set `permissions: contents: read` and pin every action to a commit SHA, including both gate workflows.
- `docs/data/report-v1.json:5` — Regenerate the gallery with repo-relative paths (also `docs/data/pac-iac-impact.md:11` and the `examples/viewer/data/` copies).
- `requirements-production.lock:1` — Install CI from a hash-locked file, or stop calling this freeze the production set.

### Nice-to-have

- `src/grc_pdf_mapper/ui/static/index.html:10` — Vendor the fonts so the local GUI does not call Google; same for `docs/index.html:9`.
- `src/grc_pdf_mapper/ui/static/index.html:18` — Rewrite the tagline in full Simplified Technical English: "Map a local policy file to control statements."
- `scripts/ci_doc_impact.py:31` — The `--offline` flag is stored and then ignored; `offline` is `not args.online` at `:35`.
- `src/grc_pdf_mapper/fedramp/__init__.py:14` — Ship the KSI catalog inside the package so a pip install does not depend on `lab/` and the current working directory.
- `docs/index.html:205` — Use "Loading example data." without an ellipsis.

## 7. Integration ideas

Keep the boundary the monitor already states: the tool flags a queue, and a person decides.

**Control Current.** Teach Classes A–D from `grc-pdf fedramp-ksi` and `fedramp-docs` after the catalog refresh. A vendor "Policies" card can show three demo-labeled fields from a `MappingReport`: document id, content hash (`ingest.source_hash`), and the count of must/shall statements. Link the card to the latest impact summary, with the severity chip prefixed "Demo" until a reviewer accepts the snapshot. Do not show Low/Moderate/High, and do not show an OSCAL satisfied state.

**Proofyard.** The existing labs are the lesson. One station runs `lab/simulate_risky_pr.sh` and reads the impact comment. A second station changes only `lab/iac/` and reads the lock-step comment. After the workflows score every changed file, those stations can be the graded exercise. Published gallery JSON can be the handout if the paths are relative and the banner says demo.

**Jev / Clef.** Feed one record per statement: `statement_id`, text, `statement_kind`, `classification_confidence`, and `classification_reasons` (already on the GUI payload at `src/grc_pdf_mapper/ui/app.py:177`). Suggested thresholds, as review gates rather than acceptance gates: at or above 0.90, queue for a person with the machine kind pre-filled; from 0.55 to 0.90, queue as "Not verified" with no pre-filled kind; below 0.55, do not classify. Do not auto-file a FedRAMP topic hit from today's domain fan-out. Domain-wide 0.55 KSI hits should stay out of the card until matching is per indicator.

**Bot fleet and evidence pipelines.** Call `production-monitor` on the schedule and `repository_dispatch` pattern in `examples/github/production-cross-repo-lockstep.yml`. Store the commit ids, the decision fingerprint, and the webhook payload as evidence that a review was requested. Recovery events close the queue item. They do not close a control. The bot message should be the monitor summary plus "Needs review", never "control met."
