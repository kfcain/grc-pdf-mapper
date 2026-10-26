# Astra review — GRC PDF Mapper

Reviewed October 26, 2026. Base: `c340144b3b4071bd569b5fd15669300ee666dc88`. Review only; no application changes, deployments, issues, or Pages publication.

## 1. Verdict

**Yes. This is useful as a policy analysis and review-routing engine. It is not yet a dependable compliance gate or evidence authority.** Keep it and improve the existing pipeline. Its strongest features are traceable policy excerpts, semantic change alerts, explicit policy-to-Terraform links, and the stricter production monitor. The passing regression suite is meaningful, but it does not cover several failures reproduced below.

The three highest-value uses are:

1. **Proofyard change-control labs.** Let a learner weaken a policy, alter Terraform, inspect the proposed framework impact, and record a human decision. This teaches the difference between a policy requirement, a configuration signal, and evidence that a control operates.
2. **Control Current policy cards and teaching examples.** Feed vendor “Policies” cards with document versions, exact excerpts, candidate control links, catalog provenance, and a “Not verified” state. Refresh the CR26 data before teaching current requirements.
3. **Fleet and evidence-pipeline intake.** Give Jev/Clef and other GRC agents structured statements and change events to triage. Retain the source, hashes, parser version, classifier reasons, and reviewer decisions. Use the production monitor's pinned revisions and input digests as a foundation; add operational evidence separately.

The immediate recommendation is a local, synthetic-data pilot. Resolve the must-fix items before making this an authoritative gate, accepting hostile uploads, or distributing its output as current FedRAMP guidance.

## 2. Correctness

### Test results and review scope

Python **3.12.14**, isolated virtual environment, exact base commit:

| Run | Result |
|---|---|
| `python3 -m pip install -e ".[dev]"`, then `pytest -q -ra` | **112 passed, 0 failed, 2 skipped**, 6.94 seconds |
| Install `.[anydoc,ui,dev]`, then `pytest -q -ra` | **128 passed, 0 failed, 0 skipped**, 7.79 seconds; one Starlette/httpx deprecation warning |
| Classifier corpus evaluation | **106/106 passed**: 32 policy, 29 Terraform, 36 change, 6 alignment, 3 SCF cases |
| Wheel build | Succeeded; **CR26 catalog absent from wheel** |

The first run skipped the Office and GUI test modules because their extras were absent. Initial installation attempts encountered runtime network and read-only user-site restrictions; the isolated environment and allowed network access resolved them. An earlier optional-suite attempt stalled under restricted execution; the completed run above is the reported result. No live webhook was sent. No Terraform was applied.

The pass covered the 120 tracked-file repository surface: library/CLI, local UI, viewer and generated samples, labs, CI, packaging, and tests, with focused execution of suspicious paths. This was source/API review, not a penetration test or production-control assessment. Browser rendering could not be checked because the runtime lacked a Chromium executable. Live SCF/OpenCRE/OSA interoperability and the optional pdf-inspector engine were not end-to-end tested. No OSCAL schema-validator pass was completed.

### CR26 freshness: IDs current, mappings stale, refresh broken

`lab/fedramp/cr26_ksi_catalog.json:4` identifies **2026.07.14.01**. The official [FedRAMP consolidated rules](https://github.com/FedRAMP/rules/blob/main/fedramp-consolidated-rules.json), retrieved during this review, identify **2026.10.13.01**, last updated October 13. Retrieved file blob: `4ed99953efa576bcfc81fa41631f50ea53e19f0c`.

Both contain **46 KSI IDs**, with no added or removed IDs. The shared top-level statement text is unchanged, but **40 of 46 control-reference lists differ**. For example, the current `KSI-IAM-ELP` record adds references including `ac-18.4`, `ac-2.11`, and `ac-2.7`. Counting IDs alone would falsely suggest freshness.

Calling the existing `extract_catalog()` on the retrieved official JSON raises **`KeyError: 'FRC-CSX-MOT'`** at `src/grc_pdf_mapper/fedramp/extract.py:53`. The current FRC/20x/CSX keys are `FRC-CSX-VVK`, `FRC-CSX-VVR`, and `FRC-CSX-MAS`. Update the extraction schema and requirement selection, then regenerate the catalog and viewer data. Record source commit/digest, retrieval date, and semantic differences. Do not silently skip missing requirements.

The extractor also invents missing-class applicability: `fedramp/extract.py:86` makes Class A optional and `:91` makes Class D required by inheritance. Those are local interpretations, not fields copied from the source. Separate them from authoritative rule data and document the applicable rule basis.

### Mapping and classifier

The deterministic classifier handles wrapped text, modal lists, negative duties, headings, tables, and several quantitative changes. Its reasons and regression corpus are useful. The numeric confidence values are rule constants, however, not calibrated probabilities (`extract/__init__.py:488`). Passing the curated corpus does not establish accuracy on new organizations, writing styles, or Terraform providers.

SCF citation normalization, source-confidence caps, explicit unknown-citation handling, and attribution are positive. Important limitations remain:

- `scf/__init__.py:290` and `:314` label offline/fallback data `scf-api`. HTTP failures fall back to the seed at `:352` and `:385` without recording degradation or the actual catalog version. Consumers cannot reliably distinguish a live result from a small bundled sample.
- SCF domain inference selects at most six seeded/family controls (`:256`); it is topical retrieval, not complete coverage. Expansion confidence can exceed the uncertain domain-to-SCF step (`:283`, `:319`). Carry uncertainty through the whole mapping chain.
- The aggregate crosswalk still adds broad seed and KSI topic hits alongside citations (`crosswalk/__init__.py:124`), even though the SCF client itself avoids replacing unresolved citations with unrelated domains. Preserve relationship types and present these as suggestions.
- `fedramp/__init__.py:269` loosely matches any enhancement sharing a base. Reproduced: an invented `AC-2(999)` maps to multiple KSIs. Validate identifiers and distinguish exact, parent, and related-enhancement relationships.
- `analytics/__init__.py:153` uses substring matching. Reproduced: an evidence request for `AC-2` returns a row mapped only to `AC-20`. Use canonical framework-qualified identifiers.
- `crosswalk/__init__.py:314` does not catch OSA transport/status errors, unlike several other adapters. An optional provider failure can abort analysis. OpenCRE only inspects page one (`:277`); neither adapter establishes complete coverage.
- The normal pipeline does not accept a FedRAMP class (`pipeline.py:38`). Impact analysis uses the highest class across registered assessments (`impact/__init__.py:173`), rather than preserving separate class applicability for each assessment.

### Lineage and alerts

Two small, temporary-directory reproductions exposed defects:

- **History cycle:** commit the same document, content, and version label twice. The second snapshot has `snapshot_id == parent_snapshot_id`. The store overwrites the original snapshot (`lineage/__init__.py:52`, `:67`), and `history()` has no cycle guard (`:100`). Repeating the default CLI version can therefore make history loop indefinitely. Make identical commits idempotent and prevent overwriting immutable snapshots; add cycle detection and atomic updates.
- **Path escape:** committing with document ID `../../escape` creates `HEAD` outside the store. See security section.

Change matching is heuristic and greedy; equal-score candidates originate from sets (`impact/__init__.py:224`), so add deterministic tie-breaking before relying on stable serialized alerts. The watcher silently skips deleted files (`watch/__init__.py:61`), and local alert delivery stops at the first sink exception (`alerts/__init__.py:85`). Add deletion events and a durable retry queue so a failed webhook does not lose a committed change notification.

### OSCAL

The module explicitly describes its output as OSCAL-inspired (`oscal/__init__.py:19`), which is honest. It should not be advertised as import-ready OSCAL:

- Assessment results lack required assessment structure, such as `import-ap` and result timing, and put `status: satisfied_as_documented` directly on each result (`:105`). More importantly, text extraction is not assessment evidence.
- Component generation discards all but the first statement for each control (`:33`). It lowercases SCF-style padded identifiers without normalizing them to catalog identifiers (`:40`), so `AC-02` and enhancement syntax can fail to resolve against the referenced NIST catalog.
- The source catalog URL is mutable (`:71`). Preserve all supporting statements, normalize IDs, pin the catalog, and validate both document types against a named OSCAL schema before claiming interoperability.

### Terraform lock-step

The combined evaluator retains risk even when both sides change (`sync/__init__.py:892`); that is correct. Repository-qualified resources, symlink checks, explicit expected domains, accepted-baseline state, digests, and pinned evaluator/source revisions in the production monitor are materially stronger than the lab workflows.

The shipped workflows have coverage gaps:

- Document impact excludes deleted files (`doc-change-impact.yml:58`) and evaluates only the first changed document (`:69`). A harmless first edit can hide a risky second edit.
- Lock-step scans all Terraform files but selects one policy (`policy-as-code-lockstep.yml:58`), hardcodes `pol-ac-001` and lab links (`:110`), and does not recognize every `policies/**` path in its document-selection condition (`:51`). Its dispatch comparison defaults to the current SHA, yielding no change baseline (`:43`).
- The scanner is a lexical HCL scanner, not a Terraform plan evaluator. The production monitor flags additional unclassified inputs, but the simpler lab path does not establish the effects of variable/module/provider changes.
- The example policy object is not attached to a principal (`lab/iac/access_control/main.tf:30`); the password-policy resource does not enforce MFA (`:15`); the account-cleanup role has no cleanup implementation (`:75`). These are useful linkage fixtures, not operating controls.

Packaging also matters: `fedramp/__init__.py:218` searches a repository-relative `lab/` path. The built wheel omits that catalog, and `crosswalk/__init__.py:230` silently drops KSI mappings when it is absent. Package the catalog as a resource and test the installed wheel outside the checkout.

## 3. Security

### Public repository and history

Scanned all **10 reachable commits** in the non-shallow checkout, **156 unique blobs**, and commit messages for the two prohibited names. **No hits found.** High-specificity AWS/GitHub/token/private-key patterns across those blobs also returned no hits. A current-file scan for suspicious literal credential assignments returned no candidates. This is not an entropy-complete secret scan, does not inspect unreachable/deleted remote objects, and does not cover GitHub settings, artifacts, or logs.

Public attribution/identity locations include `LICENSE:3`, `README.md:107`, `README.md:158`, and `src/grc_pdf_mapper/scf/__init__.py:3`. These appear to be project ownership and upstream attribution, not customer evidence. Preserve required attribution; confirm that owner identity is intentional. The person-like sample account at `lab/iac/access_control/main.tf:62` should be explicitly labeled synthetic. No confirmed private employer/client identity was found. Generic roles, example addresses, and organization-like resource names still need demo labels. Avoid putting real assessment names, policy text, internal paths, or production reports into the public viewer.

### Confirmed and potential weaknesses

- **Unchecked store paths:** `lineage/__init__.py:64`, `:92`, and `:108` join caller-controlled IDs/hash strings without containment checks. A malicious manifest or CLI argument can read/write outside the lineage root under the process's permissions. The GUI's `store=None` means this is not a demonstrated GUI upload-to-store exploit. Validate IDs, use canonical containment checks, and reject symlinks at the storage boundary.
- **CI shell injection:** `doc-change-impact.yml:52`, `:85`, and `:111`, plus `policy-as-code-lockstep.yml:87`, interpolate dispatch inputs or filename-derived outputs directly into shell code. A quote or shell substitution in a repository filename can become executable syntax. Pass values through environment variables/structured arguments; use NUL-delimited file lists and safe output encoding. Analysis jobs also execute PR-controlled Python while holding job-level PR-write permission. Split untrusted analysis from trusted comment publication, set explicit least privileges, and disable persisted checkout credentials.
- **Webhook secret leakage on failure:** `production_monitor.py:913` serializes the full HTTP exception. HTTP status exceptions include request URLs; webhook URLs often contain credentials. Redact URLs and credentials from reports/logs. No real webhook secret was used or exposed in this review.
- **Uploads and parsers:** `ui/app.py:120` reads the entire upload before the 40 MiB check. Multipart parsing/spooling also occurs before this application check. `:133` runs synchronous conversion and online mapping inside an async request handler. The application supplies no decompressed-size, archive-entry, page, CPU, memory, concurrency, or conversion-time limits. DOCX/EPUB and other compressed formats are potential resource-exhaustion inputs; no actual zip-bomb exploit was run. Stream with a hard limit, enforce ingress limits, and isolate parsers in bounded workers without unnecessary filesystem/network access.
- **Local UI boundary:** loopback default is good (`ui/app.py:217`), and there is no permissive CORS middleware. Filename basenaming and temporary-directory cleanup are good (`:129`). But `--host` permits wider binding (`cli.py:417`), and there is no authentication, trusted-host, origin/CSRF, or rate-limit layer. Lack of CORS does not prevent cross-origin form submissions. Keep loopback as the supported default and protect it against unintended browser requests; require explicit secure configuration for shared use. Raw parser exception details are returned at `ui/app.py:148`.
- **CSV injection:** `export/__init__.py:110` writes untrusted statement IDs, titles, and text without spreadsheet formula neutralization. CSV quoting alone does not neutralize `=`, `+`, `-`, or `@` formula prefixes. Add a spreadsheet-safe export mode and document any text changes.

### Dependencies and workflows

Core and optional dependencies use open lower bounds (`pyproject.toml:12`). The production lockfile pins versions, but has no artifact hashes and is not used by ordinary CI (`.github/workflows/ci.yml:18`). All actions in the three active workflows use mutable tags; `ci.yml:7` lacks explicit token permissions. In contrast, the production workflow example pins action SHAs, restricts contents permission, disables persisted credentials, and constrains Python dependencies. Carry that discipline into active workflows.

`pip-audit` on the expanded review environment reported **12 advisory records for one package, the virtual environment's bootstrap pip 25.0.1**; those records contain duplicate advisory IDs. This is a review-environment tooling issue, not a declared application dependency finding. No other installed package had a reported advisory. The local project itself was skipped because it is not on PyPI. This audit did not include the optional pdf-inspector extra or independently establish safety of native parsing code. Upgrade bootstrap tooling, audit the actual locked deployment environment, and add repeatable dependency/secret scanning.

## 4. GRC accuracy

Use **FedRAMP Class A/B/C/D** throughout product-owned guidance. Remove the legacy impact column at `lab/FEDRAMP-CR26-KSI.md:11` and legacy fields at `fedramp/extract.py:25` and `lab/fedramp/cr26_ksi_catalog.json:17`. Risk severities such as high/critical are a separate concept and need not be renamed. No standalone ATO wording was found in the tracked current source scan.

Keep requirement text, topic mapping, implementation claim, observed operation, and reviewer decision separate. `oscal/__init__.py:105` must not assign satisfaction from a policy sentence. Likewise, `terraform_classify/__init__.py:305` assigns `implemented` from heuristics or self-declared annotations; an exception ID string at `:298` is not an approved exception with scope and expiry. Treat these as candidate interpretations until supported by trusted review and control tests.

Rename “What the monitor proves” at `docs/PRODUCTION-CROSS-REPO.md:22` to “What the monitor records.” The subsequent list concerns provenance and checks; it should not imply control satisfaction. “Audit-ready evidence pack” at `analytics/__init__.py:145` is also too strong for an excerpt bundle. The production guide's explicit separation of plan assertions and owner approval at `:179` is good and should govern all output.

Default assessment registrations (`assessments/__init__.py:66`) load synthetic active initiatives even when the caller supplies no registry; a missing registry path also falls back to them. That can make real reports appear to identify actual certification/audit exposure. Default to an empty registry, require explicit demo mode for samples, and fail clearly on a requested missing registry. Add `demo: true` and visible **Demo data** labels to sample assessments, Terraform, and downloadable viewer artifacts. “Examples”/“offline samples” in the gallery is helpful but does not travel with each downloaded JSON file.

## 5. UI

Source review and API tests establish the following; browser visual, responsive, contrast, and keyboard behavior were not fully validated.

| Kit rule | Local GUI | Pages viewer |
|---|---|---|
| Base `#0B0C0F`, accent `#1A8CFF`, sparing `#FF9900` | Fails: near-black/moss OKLCH tokens, `ui/static/app.css:2` | Fails: cream/green/brown palette, `docs/index.html:12` |
| No colored left-edge accent bars | None found | Fails: `.summary` left border, `docs/index.html:166` |
| Muted-red outline “Not verified” chip | Missing; confidence percent appears without review state, `app.js:87` | Missing; severity chip is not verification state, `docs/index.html:202` |
| Transform/opacity-only motion | Result animation complies, but color/filter transitions fail, `app.css:106`, `:157` | No animation found |
| Reduced-motion still | Present, `app.css:221` | Already still |
| No pulsing dots/three-dot loaders | No animated dot loader found; static parsing text only | Static loading text only |
| Simplified Technical English | Replace “Local policy parse · control map” (`index.html:18`) with “Upload a policy. Review suggested controls.” | Replace dense introduction (`docs/index.html:184`) with task-focused wording |

The local table omits `classification_status`; the API payload omits it too (`ui/app.py:175`). Carry that state and a separate human-verification state through the UI. Explain confidence as an uncalibrated heuristic score. Distinguish “no statements found” from incomplete extraction/OCR required. Display source mode and catalog date; do not call offline seed output “crosswalk API results” (`ui/static/index.html:102`). The footer's “Runs on this machine only” (`:123`) needs qualification because online mapping and remote fonts can make network requests.

Both views use text rendering/escaping for document content, which reduces straightforward HTML injection risk. Local tabs have roles but lack complete arrow-key/roving-tabindex behavior (`app.js:115`). Pages `loadFile()` lacks HTTP/error handling and request-order protection (`docs/index.html:263`): fast selection can show an earlier response beneath a newer filename. Add cancellation or a selection token. Make the same viewer fixes in `examples/viewer/index.html`, the regeneration source, so the sync script does not overwrite them. Update `DESIGN.md:5` to match the current kit.

## 6. Prioritized fixes

### Must-fix

| Location | One-line fix |
|---|---|
| `src/grc_pdf_mapper/lineage/__init__.py:64` | Validate all store identifiers and enforce resolved-root containment on reads and writes. |
| `src/grc_pdf_mapper/lineage/__init__.py:52` | Make repeated commits idempotent, preserve immutable snapshots, and reject history cycles. |
| `.github/workflows/doc-change-impact.yml:85`; `.github/workflows/policy-as-code-lockstep.yml:87` | Remove expression-to-shell interpolation and isolate trusted PR-comment permissions from untrusted analysis. |
| `src/grc_pdf_mapper/production_monitor.py:913` | Redact webhook URLs and credentials from exception/report fields. |
| `lab/fedramp/cr26_ksi_catalog.json:4`; `src/grc_pdf_mapper/fedramp/extract.py:53` | Migrate to current CR26 schema, refresh mappings, and fail on unsupported source changes. |
| `.github/workflows/doc-change-impact.yml:58` | Analyze every changed, renamed, and deleted controlled document. |
| `.github/workflows/policy-as-code-lockstep.yml:58` | Resolve all enrolled policy IDs/link manifests and compare explicit base/head revisions. |
| `src/grc_pdf_mapper/oscal/__init__.py:105`; `src/grc_pdf_mapper/terraform_classify/__init__.py:305` | Remove unsupported satisfaction/implementation claims and require independent review/evidence. |
| `src/grc_pdf_mapper/ui/app.py:120`; `src/grc_pdf_mapper/ingest/__init__.py:164` | Bound uploads before reading them and run hostile document conversion in resource-limited workers. |
| `src/grc_pdf_mapper/assessments/__init__.py:66` | Keep synthetic initiatives behind explicit demo mode and reject missing requested registries. |

### Should-fix

| Location | One-line fix |
|---|---|
| `src/grc_pdf_mapper/fedramp/__init__.py:218`; `pyproject.toml:34` | Ship the catalog as package data and verify installed-wheel mapping outside the repo. |
| `src/grc_pdf_mapper/fedramp/__init__.py:269`; `src/grc_pdf_mapper/analytics/__init__.py:153` | Use validated canonical IDs and explicit relationship types instead of broad/substring matches. |
| `src/grc_pdf_mapper/scf/__init__.py:290` | Record live/seed/fallback origin, catalog digest, fetch date, and full-chain confidence. |
| `src/grc_pdf_mapper/crosswalk/__init__.py:314` | Handle optional-provider failure explicitly and report incomplete mapping results. |
| `src/grc_pdf_mapper/oscal/__init__.py:33` | Retain every supporting statement, normalize catalog IDs, and schema-validate exports. |
| `src/grc_pdf_mapper/export/__init__.py:110` | Neutralize spreadsheet formulas in untrusted CSV fields. |
| `src/grc_pdf_mapper/watch/__init__.py:61`; `src/grc_pdf_mapper/alerts/__init__.py:85` | Alert on deletion and persist retryable per-destination delivery state. |
| `.github/workflows/ci.yml:11`; `requirements-production.lock:3` | Pin active actions and package artifacts, restrict permissions, and audit reproducible dependencies. |
| `lab/FEDRAMP-CR26-KSI.md:11`; `src/grc_pdf_mapper/fedramp/extract.py:86` | Use Classes A–D only and distinguish sourced applicability from local interpretation. |
| `src/grc_pdf_mapper/ui/static/app.css:2`; `docs/index.html:12` | Apply kit colors, remove the Pages accent bar, and add the required verification chip. |
| `src/grc_pdf_mapper/ui/static/app.css:106`; `src/grc_pdf_mapper/ui/static/app.js:87` | Restrict motion to transform/opacity and display review status with plain-language score context. |
| `lab/iac/access_control/main.tf:15`; `scripts/ci_pac_sync.py:297` | Label incomplete fixtures as demos and require control tests/owner review beyond editing both files. |

### Nice-to-have

| Location | One-line fix |
|---|---|
| `docs/index.html:263` | Cancel stale fetches, check response status, and show a recoverable load error. |
| `src/grc_pdf_mapper/ui/static/app.js:115` | Add complete keyboard tab navigation and test focus behavior. |
| `src/grc_pdf_mapper/ui/static/index.html:8` | Bundle fonts so offline mode does not contact a font service. |
| `src/grc_pdf_mapper/impact/__init__.py:229` | Add deterministic pairing tie-breakers and split/merge policy examples. |
| `tests/test_classifier_validation.py:13` | Add held-out documents and calibration measurements beyond the curated regression corpus. |
| `scripts/publish_github.sh:16` | Separate repository push from Pages configuration so publication is an explicit independent action. |

## 7. Integration ideas

**Control Current:** publish only approved synthetic examples. A vendor Policies card should show title, document date, source URL, source hash, parser/catalog versions, an exact excerpt, candidate frameworks, class applicability, and review date. Default to **Not verified**. Label sample values **Demo data**. Keep “policy exists,” “statement maps to a requirement,” and “operating evidence reviewed” as separate fields. A missing or unreadable document is “Unknown,” not a pass.

**Proofyard:** turn the existing risky-PR and lock-step labs into a sequence: establish a baseline; soften a duty; delete a policy; change a second policy in one PR; alter an unlinked Terraform resource; introduce a provider/variable change; compare output; have a human record an acceptance or rejection with reasons. Include the repeated-snapshot defect and stale-catalog case as regression exercises after fixes. Grade the student's reasoning and evidence, not merely the presence of two edited files.

**Jev/Clef and the bot fleet:** give agents read-only access to extracted statements and candidate mappings. Proposed triage thresholds: below 0.85 routes to manual classification; 0.85–0.94 requests a second classification; 0.95+ permits a suggested label only. These are pilot routing values, not validated probabilities or approval thresholds. Any negation, exception, class ambiguity, stale catalog, parser uncertainty, or classifier disagreement forces review regardless of score. Keep source documents as untrusted data, not agent instructions. Model output must never change approved policy, Terraform, verification status, or publication automatically.

**Evidence pipelines:** emit a versioned event containing source/snapshot IDs, old/new hashes, exact spans, parser and evaluator versions, mapping provenance, catalog digest, candidate relationship, change classification, scope/class, and reviewer state. Store original evidence separately from derived reports. Link operational tests to the control, environment, population, time window, expected result, and exceptions. Use event triggers plus scheduled reconciliation, durable delivery retries, and retention controls. An approved mapping can connect evidence to a requirement; it cannot itself establish that the requirement is met.
