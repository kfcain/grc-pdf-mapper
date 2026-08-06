"""Production monitor for documentation and Terraform repositories."""

from __future__ import annotations

import hashlib
import json
import os
import re
import subprocess
import tempfile
from collections.abc import Iterator
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Literal

import httpx
from pydantic import BaseModel, ConfigDict, Field, model_validator

from grc_pdf_mapper.assessments import AssessmentRegistry
from grc_pdf_mapper.classifier_validation import (
    ClassifierValidationReport,
    evaluate_classifier_corpus,
)
from grc_pdf_mapper.ingest import ingest_path
from grc_pdf_mapper.models import AlertSeverity, ObligationStrength, StatementKind
from grc_pdf_mapper.pac_models import (
    LifecycleAlert,
    PolicyCodeControlMapping,
    PolicyCodeLink,
    SyncGap,
    TerraformControlMapping,
    TerraformResourceRef,
)
from grc_pdf_mapper.sync import (
    analyze_doc_change_for_iac,
    analyze_iac_change,
    completeness_scan,
)
from grc_pdf_mapper.terraform_scan import (
    _RESOURCE_DECL_RE,
    _RESOURCE_TOKEN_RE,
    _find_block_end,
    _mask_hcl_non_code,
    diff_terraform_refs,
    scan_terraform_revision,
    scan_terraform_tree,
)


SEVERITY_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
_IAC_EXCLUDED_TREE_PARTS = {
    ".git",
    ".terraform",
    ".terragrunt-cache",
    ".venv",
    "node_modules",
}


class MonitorStatus(str, Enum):
    ALIGNED = "aligned"
    REVIEW_REQUIRED = "review_required"
    MISALIGNED = "misaligned"


class _StrictConfigModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class RepositoryConfig(_StrictConfigModel):
    name: str
    kind: Literal["documentation", "iac"]
    root: str
    repository_url: str = ""
    expected_revision: str | None = None
    expected_revision_env: str | None = None
    require_clean: bool = True


class TerraformRootConfig(_StrictConfigModel):
    repository: str
    path: str = "."


class MonitorTargetConfig(_StrictConfigModel):
    target_id: str
    doc_id: str
    policy_repository: str
    policy_path: str
    terraform_roots: list[TerraformRootConfig]
    link_ids: list[str] = Field(default_factory=list)


class ClassifierGateConfig(_StrictConfigModel):
    corpus_path: str
    minimum_score: float = Field(default=0.95, ge=0.0, le=1.0)
    review_below: float = Field(default=0.85, ge=0.0, le=1.0)
    require_expected_domains: bool = True
    require_exact_domains: bool = True


class NotificationConfig(_StrictConfigModel):
    webhook_envs: list[str] = Field(default_factory=list)
    minimum_severity: AlertSeverity = AlertSeverity.HIGH
    notify_on_recovery: bool = True
    require_destination: bool = True
    timeout_seconds: float = Field(default=10.0, gt=0.0, le=60.0)
    event_log_path: str = ".grc-monitor/notification-events.jsonl"


class ProductionMonitorConfig(_StrictConfigModel):
    schema_version: int = 1
    monitor_id: str
    tool_revision_env: str | None = None
    repositories: list[RepositoryConfig]
    links_path: str
    assessments_path: str | None = None
    state_path: str = ".grc-monitor/state.json"
    require_existing_state: Literal[True] = True
    targets: list[MonitorTargetConfig]
    classifier_gate: ClassifierGateConfig
    notifications: NotificationConfig = Field(default_factory=NotificationConfig)

    @model_validator(mode="after")
    def _validate_references(self) -> "ProductionMonitorConfig":
        if self.schema_version != 1:
            raise ValueError("Only production monitor schema_version 1 is supported")
        repository_index = {repo.name: repo for repo in self.repositories}
        if len(repository_index) != len(self.repositories):
            raise ValueError("Repository names must be unique")
        target_ids = {target.target_id for target in self.targets}
        if len(target_ids) != len(self.targets):
            raise ValueError("Target IDs must be unique")
        if not self.targets:
            raise ValueError("At least one monitor target is required")
        for target in self.targets:
            policy_repo = repository_index.get(target.policy_repository)
            if policy_repo is None or policy_repo.kind != "documentation":
                raise ValueError(
                    f"Target {target.target_id} needs a documentation repository"
                )
            if not target.terraform_roots:
                raise ValueError(
                    f"Target {target.target_id} needs at least one Terraform root"
                )
            for binding in target.terraform_roots:
                iac_repo = repository_index.get(binding.repository)
                if iac_repo is None or iac_repo.kind != "iac":
                    raise ValueError(
                        f"Target {target.target_id} references an unknown IaC repository: "
                        f"{binding.repository}"
                    )
        return self


class _StrictPolicyCodeLink(PolicyCodeLink):
    model_config = ConfigDict(extra="forbid")
    expected_statement_kind: StatementKind
    expected_strength: ObligationStrength
    expected_action_polarity: Literal["positive", "negative"]


class _ProductionLinkManifest(_StrictConfigModel):
    schema_version: Literal[1]
    links: list[_StrictPolicyCodeLink]

    @model_validator(mode="after")
    def _unique_link_ids(self) -> "_ProductionLinkManifest":
        link_ids = {link.link_id for link in self.links}
        if len(link_ids) != len(self.links):
            raise ValueError("Production policy-as-code link IDs must be unique")
        return self


class RepositorySnapshot(BaseModel):
    name: str
    kind: str
    root: str
    repository_url: str = ""
    revision: str
    clean: bool


class TargetMonitorResult(BaseModel):
    target_id: str
    doc_id: str
    status: MonitorStatus
    alert: LifecycleAlert


class NotificationOutcome(BaseModel):
    event: str = "none"
    attempted: bool = False
    sent_to: list[str] = Field(default_factory=list)
    suppressed: bool = False
    reason: str = ""
    errors: list[str] = Field(default_factory=list)


class ScannedFileEvidence(BaseModel):
    repository: str
    revision: str
    path: str
    sha256: str
    parsed_resource_count: int = 0


class ProductionMonitorReport(BaseModel):
    schema_version: int = 1
    monitor_id: str
    generated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    status: MonitorStatus
    severity: AlertSeverity
    summary: str
    tool_revision: str
    input_fingerprint: str
    finding_fingerprint: str
    state_transition: str = "unchanged"
    repositories: list[RepositorySnapshot]
    targets: list[TargetMonitorResult]
    classifier_validation: ClassifierValidationReport
    input_digests: dict[str, str] = Field(default_factory=dict)
    scanned_files: list[ScannedFileEvidence] = Field(default_factory=list)
    notification: NotificationOutcome = Field(default_factory=NotificationOutcome)
    decision_policy: dict[str, Any] = Field(default_factory=dict)


def load_production_monitor_config(
    path: str | Path,
) -> ProductionMonitorConfig:
    path = Path(path)
    return ProductionMonitorConfig.model_validate_json(path.read_text(encoding="utf-8"))


def run_production_monitor(
    config_path: str | Path,
    *,
    notify: bool = True,
    state_path_override: str | Path | None = None,
) -> ProductionMonitorReport:
    """Evaluate one exact documentation/IaC revision pair and route state changes."""
    config_path = Path(config_path).resolve()
    config_dir = config_path.parent
    config = load_production_monitor_config(config_path)
    repository_configs = {repo.name: repo for repo in config.repositories}
    repository_roots = {
        name: _resolve_path(config_dir, repo.root)
        for name, repo in repository_configs.items()
    }
    snapshots = [
        _snapshot_repository(repo, repository_roots[repo.name])
        for repo in config.repositories
    ]
    revision_index = {snapshot.name: snapshot.revision for snapshot in snapshots}

    links_path = _resolve_path(config_dir, config.links_path)
    links = _load_production_links(links_path)
    assessments = []
    assessments_path: Path | None = None
    if config.assessments_path:
        assessments_path = _resolve_path(config_dir, config.assessments_path)
        assessments = AssessmentRegistry(assessments_path).active()

    corpus_path = _resolve_path(config_dir, config.classifier_gate.corpus_path)
    classifier_validation = evaluate_classifier_corpus(
        corpus_path,
        minimum_score=config.classifier_gate.minimum_score,
    )
    tool_revision = _tool_revision(config)
    source_file_digests = _source_input_digests(
        config.targets,
        repository_roots,
    )
    input_fingerprint = _input_fingerprint(
        config=config,
        config_path=config_path,
        links_path=links_path,
        corpus_path=corpus_path,
        revisions=revision_index,
        tool_revision=tool_revision,
        source_file_digests=source_file_digests,
    )

    state_path = (
        Path(state_path_override).resolve()
        if state_path_override
        else _resolve_path(config_dir, config.state_path)
    )
    prior_state = _read_state(
        state_path,
        config.monitor_id,
        require_existing=config.require_existing_state,
        allow_bootstrap=(
            os.environ.get("GRC_MONITOR_ALLOW_STATE_BOOTSTRAP", "").lower()
            == "true"
        ),
    )
    prior_revisions = dict(
        prior_state.get("last_accepted_revisions", {})
        if "last_accepted_revisions" in prior_state
        else prior_state.get("last_observed_revisions", {})
    )

    current_cache: dict[tuple[str, str], list[TerraformResourceRef]] = {}
    revision_cache: dict[tuple[str, str, str], list[TerraformResourceRef]] = {}
    target_results: list[TargetMonitorResult] = []
    for target in config.targets:
        target_links = _links_for_target(links, target)
        integrity_gaps = _current_input_integrity_gaps(
            target,
            repository_roots,
            revision_index,
        )
        resources = _current_target_resources(
            target,
            repository_roots,
            revision_index,
            current_cache,
        )
        policy_root = repository_roots[target.policy_repository]
        policy_path = _safe_repo_path(policy_root, target.policy_path)
        completeness = completeness_scan(
            links=target_links,
            policy_path=policy_path,
            terraform_root=None,
            terraform_resources=resources,
            doc_id=target.doc_id,
            scf_offline=True,
            assessments=assessments,
            validate_classifier_alignment=True,
            classifier_review_below=config.classifier_gate.review_below,
            require_expected_domains=config.classifier_gate.require_expected_domains,
            require_exact_domains=config.classifier_gate.require_exact_domains,
        )
        extras: list[LifecycleAlert] = []
        history_gaps: list[SyncGap] = list(integrity_gaps)

        if prior_revisions:
            doc_previous = prior_revisions.get(target.policy_repository)
            doc_current = revision_index[target.policy_repository]
            if doc_previous and doc_previous != doc_current:
                try:
                    older_markdown = _ingest_git_document(
                        policy_root,
                        doc_previous,
                        target.policy_path,
                    )
                    newer_markdown = ingest_path(policy_path).markdown
                    extras.append(
                        analyze_doc_change_for_iac(
                            links=target_links,
                            doc_id=target.doc_id,
                            older_markdown=older_markdown,
                            newer_markdown=newer_markdown,
                            terraform_root=None,
                            terraform_resources=resources,
                            scf_offline=True,
                            assessments=assessments,
                        )
                    )
                except (OSError, subprocess.CalledProcessError, ValueError) as exc:
                    history_gaps.append(
                        _history_gap(target, target.policy_repository, doc_previous, exc)
                    )

            if any(
                prior_revisions.get(binding.repository)
                and prior_revisions[binding.repository]
                != revision_index[binding.repository]
                for binding in target.terraform_roots
            ):
                try:
                    previous_resources = _previous_target_resources(
                        target,
                        repository_roots,
                        revision_index,
                        prior_revisions,
                        current_cache,
                        revision_cache,
                    )
                    extras.append(
                        analyze_iac_change(
                            links=target_links,
                            base_tf_files=[],
                            head_tf_files=[],
                            base_tf_resources=previous_resources,
                            head_tf_resources=resources,
                            policy_path=policy_path,
                            doc_id=target.doc_id,
                            scf_offline=True,
                            assessments=assessments,
                        )
                    )
                    history_gaps.extend(
                        _unclassified_iac_change_gaps(
                            target=target,
                            repository_roots=repository_roots,
                            current_revisions=revision_index,
                            prior_revisions=prior_revisions,
                            previous_resources=previous_resources,
                            current_resources=resources,
                        )
                    )
                except (OSError, subprocess.CalledProcessError, ValueError) as exc:
                    changed_repo = next(
                        binding.repository
                        for binding in target.terraform_roots
                        if prior_revisions.get(binding.repository)
                        != revision_index[binding.repository]
                    )
                    history_gaps.append(
                        _history_gap(
                            target,
                            changed_repo,
                            prior_revisions.get(changed_repo, "unknown"),
                            exc,
                        )
                    )

        target_results.append(
            _merge_target_result(
                target=target,
                completeness_alert=(
                    completeness.alerts[0]
                    if completeness.alerts
                    else _aligned_alert(target, input_fingerprint)
                ),
                extra_alerts=extras,
                history_gaps=history_gaps,
                classifier_validation=classifier_validation,
                input_fingerprint=input_fingerprint,
                revisions=revision_index,
            )
        )

    severity = _max_severity(
        [result.alert.severity for result in target_results] or [AlertSeverity.INFO]
    )
    status = _status_for_severity(severity)
    finding_fingerprint = _finding_fingerprint(target_results, status)
    prior_status = str(prior_state.get("last_status", ""))
    prior_finding = str(prior_state.get("last_finding_fingerprint", ""))
    state_transition = (
        "recovered"
        if status == MonitorStatus.ALIGNED
        and prior_status in {
            MonitorStatus.MISALIGNED.value,
            MonitorStatus.REVIEW_REQUIRED.value,
        }
        else "opened"
        if status != MonitorStatus.ALIGNED
        and (
            not prior_finding
            or prior_status in {"", MonitorStatus.ALIGNED.value}
        )
        else "changed"
        if status != MonitorStatus.ALIGNED and prior_finding != finding_fingerprint
        else "repeated"
        if status != MonitorStatus.ALIGNED
        else "unchanged"
    )
    summary = (
        f"[{severity.value.upper()}] Production policy/IaC monitor '{config.monitor_id}': "
        f"{sum(result.status == MonitorStatus.MISALIGNED for result in target_results)} "
        f"misaligned target(s), "
        f"{sum(result.status == MonitorStatus.REVIEW_REQUIRED for result in target_results)} "
        f"target(s) need review, {len(target_results)} target(s) evaluated."
    )
    scanned_files = _scan_file_evidence(
        config.targets,
        repository_roots,
        revision_index,
        current_cache,
    )
    input_digests = {
        "config": _sha256_file(config_path),
        "links": _sha256_file(links_path),
        "classifier_corpus": _sha256_file(corpus_path),
        "classifier_taxonomy": _sha256_file(
            Path(__file__).resolve().parent / "classifier_taxonomy.py"
        ),
        "scf_offline_seed": _sha256_file(
            Path(__file__).resolve().parent / "scf" / "offline_seed.json"
        ),
        "source_file_set": hashlib.sha256(
            json.dumps(source_file_digests, sort_keys=True).encode("utf-8")
        ).hexdigest(),
    }
    if assessments_path is not None:
        input_digests["assessments"] = _sha256_file(assessments_path)
    dependency_manifest = next(
        (
            candidate
            for candidate in (
                config_dir.parent / "pyproject.toml",
                Path(__file__).resolve().parents[2] / "pyproject.toml",
            )
            if candidate.is_file()
        ),
        None,
    )
    if dependency_manifest is not None:
        input_digests["dependency_manifest"] = _sha256_file(dependency_manifest)
    report = ProductionMonitorReport(
        monitor_id=config.monitor_id,
        status=status,
        severity=severity,
        summary=summary,
        tool_revision=tool_revision,
        input_fingerprint=input_fingerprint,
        finding_fingerprint=finding_fingerprint,
        state_transition=state_transition,
        repositories=snapshots,
        targets=target_results,
        classifier_validation=classifier_validation,
        input_digests=input_digests,
        scanned_files=scanned_files,
        decision_policy={
            "classifier_minimum_score": config.classifier_gate.minimum_score,
            "classifier_review_below": config.classifier_gate.review_below,
            "require_expected_domains": config.classifier_gate.require_expected_domains,
            "require_exact_domains": config.classifier_gate.require_exact_domains,
            "notification_minimum_severity": config.notifications.minimum_severity.value,
            "required_notification_destination": config.notifications.require_destination,
            "require_existing_state": config.require_existing_state,
            "require_pinned_source_files": True,
            "require_exact_policy_semantics": True,
        },
    )

    notification = _route_notification(
        report,
        config.notifications,
        config_dir,
        prior_state,
        notify=notify,
    )
    report.notification = notification
    now = datetime.now(timezone.utc).isoformat()
    same_active_finding = (
        status != MonitorStatus.ALIGNED
        and prior_finding == finding_fingerprint
    )
    occurrence_count = (
        int(prior_state.get("occurrence_count", 0)) + 1
        if same_active_finding
        else 1
        if status != MonitorStatus.ALIGNED
        else 0
    )
    new_state = {
        "schema_version": 1,
        "monitor_id": config.monitor_id,
        "bootstrap_complete": (
            bool(prior_state.get("bootstrap_complete", not config.require_existing_state))
            or status == MonitorStatus.ALIGNED
        ),
        "updated_at": now,
        "last_observed_revisions": revision_index,
        "last_accepted_revisions": (
            revision_index
            if status == MonitorStatus.ALIGNED
            else prior_revisions
        ),
        "last_input_fingerprint": input_fingerprint,
        "last_finding_fingerprint": finding_fingerprint,
        "last_status": status.value,
        "finding_state": (
            "active" if status != MonitorStatus.ALIGNED else "resolved"
        ),
        "state_transition": state_transition,
        "occurrence_count": occurrence_count,
        "first_seen_at": (
            prior_state.get("first_seen_at", now)
            if same_active_finding
            else now
            if status != MonitorStatus.ALIGNED
            else ""
        ),
        "last_seen_at": now if status != MonitorStatus.ALIGNED else "",
        "last_notified_fingerprint": prior_state.get("last_notified_fingerprint", ""),
        "last_notified_finding_fingerprint": prior_state.get(
            "last_notified_finding_fingerprint",
            prior_state.get("last_notified_fingerprint", ""),
        ),
        "last_notified_input_fingerprint": prior_state.get(
            "last_notified_input_fingerprint", ""
        ),
    }
    if notification.sent_to and not notification.errors:
        new_state["last_notified_fingerprint"] = finding_fingerprint
        new_state["last_notified_finding_fingerprint"] = finding_fingerprint
        new_state["last_notified_input_fingerprint"] = input_fingerprint
    _write_state(state_path, new_state)
    return report


def _snapshot_repository(
    config: RepositoryConfig,
    root: Path,
) -> RepositorySnapshot:
    if not root.is_dir():
        raise ValueError(f"Repository root does not exist: {root}")
    revision = _git_revision(root, "HEAD")
    expected = config.expected_revision
    if config.expected_revision_env:
        expected = os.environ.get(config.expected_revision_env)
        if not expected:
            raise ValueError(
                f"Required revision variable is not set: {config.expected_revision_env}"
            )
    if expected:
        if not re.fullmatch(r"[0-9a-fA-F]{40}|[0-9a-fA-F]{64}", expected):
            raise ValueError(
                f"Repository {config.name} expected_revision must be a full commit SHA"
            )
        expected_revision = _git_revision(root, expected)
        if expected_revision != revision:
            raise ValueError(
                f"Repository {config.name} is at {revision}, not {expected_revision}"
            )
    clean = not _git(root, "status", "--porcelain", "--untracked-files=all")
    if config.require_clean and not clean:
        raise ValueError(f"Repository {config.name} has uncommitted input changes")
    return RepositorySnapshot(
        name=config.name,
        kind=config.kind,
        root=str(root),
        repository_url=config.repository_url,
        revision=revision,
        clean=clean,
    )


def _load_production_links(path: Path) -> list[PolicyCodeLink]:
    manifest = _ProductionLinkManifest.model_validate_json(
        path.read_text(encoding="utf-8")
    )
    return [PolicyCodeLink.model_validate(link.model_dump()) for link in manifest.links]


def _current_target_resources(
    target: MonitorTargetConfig,
    repository_roots: dict[str, Path],
    current_revisions: dict[str, str],
    cache: dict[tuple[str, str], list[TerraformResourceRef]],
) -> list[TerraformResourceRef]:
    resources: list[TerraformResourceRef] = []
    for binding in target.terraform_roots:
        clean_path = _clean_relative_path(binding.path)
        key = (binding.repository, clean_path)
        if key not in cache:
            repository_root = repository_roots[binding.repository]
            lexical_root = repository_root / clean_path
            if lexical_root.is_symlink():
                cache[key] = []
                continue
            root = _safe_repo_path(repository_root, clean_path)
            if not root.is_dir():
                raise ValueError(
                    f"Terraform root does not exist for {binding.repository}: {clean_path}"
                )
            cache[key] = scan_terraform_tree(
                root,
                repository=binding.repository,
                revision=current_revisions[binding.repository],
                root_path="" if clean_path == "." else clean_path,
                reject_symlinks=False,
            )
        resources.extend(cache[key])
    return _dedupe_resources(resources)


def _previous_target_resources(
    target: MonitorTargetConfig,
    repository_roots: dict[str, Path],
    current_revisions: dict[str, str],
    prior_revisions: dict[str, str],
    current_cache: dict[tuple[str, str], list[TerraformResourceRef]],
    revision_cache: dict[tuple[str, str, str], list[TerraformResourceRef]],
) -> list[TerraformResourceRef]:
    resources: list[TerraformResourceRef] = []
    for binding in target.terraform_roots:
        clean_path = _clean_relative_path(binding.path)
        revision = prior_revisions.get(binding.repository)
        if not revision or revision == current_revisions[binding.repository]:
            resources.extend(
                _current_target_resources(
                    target.model_copy(update={"terraform_roots": [binding]}),
                    repository_roots,
                    current_revisions,
                    current_cache,
                )
            )
            continue
        key = (binding.repository, revision, clean_path)
        if key not in revision_cache:
            revision_cache[key] = scan_terraform_revision(
                repository_roots[binding.repository],
                revision,
                [clean_path],
                repository=binding.repository,
            )
        resources.extend(revision_cache[key])
    return _dedupe_resources(resources)


def _links_for_target(
    links: list[PolicyCodeLink],
    target: MonitorTargetConfig,
) -> list[PolicyCodeLink]:
    selected = [link for link in links if link.doc_id == target.doc_id]
    if target.link_ids:
        requested = set(target.link_ids)
        selected = [link for link in selected if link.link_id in requested]
        missing = requested - {link.link_id for link in selected}
        if missing:
            raise ValueError(
                f"Target {target.target_id} references unknown link IDs: "
                + ", ".join(sorted(missing))
            )
    if not selected:
        raise ValueError(f"Target {target.target_id} has no policy-as-code links")
    return selected


def _merge_target_result(
    *,
    target: MonitorTargetConfig,
    completeness_alert: LifecycleAlert,
    extra_alerts: list[LifecycleAlert],
    history_gaps: list[SyncGap],
    classifier_validation: ClassifierValidationReport,
    input_fingerprint: str,
    revisions: dict[str, str],
) -> TargetMonitorResult:
    alerts = [completeness_alert, *extra_alerts]
    gaps = _dedupe_gaps(
        [gap for alert in alerts for gap in alert.gaps] + history_gaps
    )
    if not classifier_validation.passed:
        gaps.append(
            SyncGap(
                kind="classifier_validation_failed",
                severity=AlertSeverity.CRITICAL,
                detail=(
                    f"Classifier corpus gate failed: "
                    f"{classifier_validation.failed_case_count} case(s) failed."
                ),
                doc_id=target.doc_id,
                recommended_action=(
                    "Do not use automatic alignment decisions until the classifier gate passes."
                ),
            )
        )
    severity = _max_severity(
        [
            *(gap.severity for gap in gaps),
            *(alert.severity for alert in alerts),
        ]
        or [AlertSeverity.INFO]
    )
    controls = _dedupe_control_mappings(
        [mapping for alert in alerts for mapping in alert.control_mappings]
    )
    terraform = _dedupe_terraform_mappings(
        [mapping for alert in alerts for mapping in alert.terraform_mappings]
    )
    verbiage = [change for alert in alerts for change in alert.verbiage_changes]
    material = json.dumps(
        {
            "target": target.target_id,
            "input": input_fingerprint,
            "gaps": [gap.model_dump(mode="json") for gap in gaps],
        },
        sort_keys=True,
    ).encode("utf-8")
    alert = LifecycleAlert(
        alert_id=hashlib.sha256(material).hexdigest()[:20],
        trigger="production_cross_repo_monitor",
        severity=severity,
        summary=(
            f"[{severity.value.upper()}] Target '{target.target_id}' has "
            f"{len(gaps)} production policy/IaC finding(s)."
        ),
        gaps=gaps,
        verbiage_changes=verbiage,
        changed_paths=sorted(
            {path for alert_item in alerts for path in alert_item.changed_paths}
        ),
        linked_statements=sorted(
            {item for alert_item in alerts for item in alert_item.linked_statements}
        ),
        linked_iac=sorted(
            {item for alert_item in alerts for item in alert_item.linked_iac}
        ),
        frameworks=sorted(
            {item for alert_item in alerts for item in alert_item.frameworks}
        ),
        control_mappings=controls,
        terraform_mappings=terraform,
        assessments_impacted=[
            item for alert_item in alerts for item in alert_item.assessments_impacted
        ],
        recommended_actions=sorted(
            {
                action
                for alert_item in alerts
                for action in alert_item.recommended_actions
                if action
            }
            | {gap.recommended_action for gap in gaps if gap.recommended_action}
        ),
        metadata={
            "target_id": target.target_id,
            "input_fingerprint": input_fingerprint,
            "repository_revisions": revisions,
            "classifier_corpus_version": classifier_validation.corpus_version,
        },
    )
    return TargetMonitorResult(
        target_id=target.target_id,
        doc_id=target.doc_id,
        status=_status_for_severity(severity),
        alert=alert,
    )


def _route_notification(
    report: ProductionMonitorReport,
    config: NotificationConfig,
    config_dir: Path,
    prior_state: dict[str, Any],
    *,
    notify: bool,
) -> NotificationOutcome:
    prior_status = str(prior_state.get("last_status", ""))
    last_notified_finding = str(
        prior_state.get("last_notified_finding_fingerprint")
        or prior_state.get("last_notified_fingerprint", "")
    )
    last_notified_input = str(
        prior_state.get("last_notified_input_fingerprint", "")
    )
    recovery = (
        report.status == MonitorStatus.ALIGNED
        and prior_status in {MonitorStatus.MISALIGNED.value, MonitorStatus.REVIEW_REQUIRED.value}
        and config.notify_on_recovery
        and bool(last_notified_finding)
    )
    above_threshold = (
        SEVERITY_RANK[report.severity.value]
        >= SEVERITY_RANK[config.minimum_severity.value]
    )
    should_notify = recovery or (
        report.status != MonitorStatus.ALIGNED and above_threshold
    )
    event = "recovered" if recovery else "misaligned"
    if not notify:
        return NotificationOutcome(
            event=event if should_notify else "none",
            suppressed=should_notify,
            reason="Notification delivery was disabled for this run.",
        )
    if not should_notify:
        return NotificationOutcome(
            reason="The result does not meet the notification rule."
        )
    if (
        report.finding_fingerprint == last_notified_finding
        and report.input_fingerprint == last_notified_input
    ):
        return NotificationOutcome(
            event=event,
            suppressed=True,
            reason=(
                "This finding and source revision set was already delivered."
            ),
        )

    payload = _notification_payload(report, event)
    event_path = _resolve_path(config_dir, config.event_log_path)
    event_path.parent.mkdir(parents=True, exist_ok=True)
    with event_path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(payload, sort_keys=True) + "\n")

    urls: list[tuple[str, str]] = []
    missing: list[str] = []
    for variable in config.webhook_envs:
        value = os.environ.get(variable)
        if value:
            urls.append((variable, value))
        else:
            missing.append(variable)
    errors: list[str] = []
    if config.require_destination and not urls:
        errors.append(
            "No external notification destination is available; set one of: "
            + ", ".join(config.webhook_envs or ["webhook_envs"])
        )
    if missing:
        errors.append("Missing webhook variables: " + ", ".join(missing))

    sent: list[str] = []
    with httpx.Client(timeout=config.timeout_seconds) as client:
        for variable, url in urls:
            try:
                response = client.post(url, json=payload)
                response.raise_for_status()
                sent.append(variable)
            except httpx.HTTPError as exc:
                errors.append(f"{variable}: {type(exc).__name__}: {exc}")
    return NotificationOutcome(
        event=event,
        attempted=True,
        sent_to=sent,
        errors=errors,
        reason=(
            "Notification event was recorded and delivered."
            if sent and not errors
            else "Notification delivery needs attention."
        ),
    )


def _notification_payload(
    report: ProductionMonitorReport,
    event: str,
) -> dict[str, Any]:
    findings = [
        {
            "target_id": target.target_id,
            "severity": target.alert.severity.value,
            "kind": gap.kind,
            "link_id": gap.link_id,
            "detail": gap.detail,
        }
        for target in report.targets
        for gap in target.alert.gaps
    ][:30]
    return {
        "text": report.summary if event != "recovered" else f"[RECOVERED] {report.monitor_id} is aligned.",
        "event": f"grc.policy_iac.{event}",
        "monitor_id": report.monitor_id,
        "status": report.status.value,
        "severity": report.severity.value,
        "tool_revision": report.tool_revision,
        "input_fingerprint": report.input_fingerprint,
        "finding_fingerprint": report.finding_fingerprint,
        "state_transition": report.state_transition,
        "repository_revisions": {
            snapshot.name: snapshot.revision for snapshot in report.repositories
        },
        "findings": findings,
    }


def _history_gap(
    target: MonitorTargetConfig,
    repository: str,
    revision: str,
    error: Exception,
) -> SyncGap:
    return SyncGap(
        kind="history_revision_unavailable",
        severity=AlertSeverity.HIGH,
        detail=(
            f"Target {target.target_id} could not read prior revision {revision} "
            f"from repository {repository}: {type(error).__name__}."
        ),
        doc_id=target.doc_id,
        recommended_action=(
            "Fetch full Git history and run the monitor again. Do not accept a partial comparison."
        ),
    )


def _unclassified_iac_change_gaps(
    *,
    target: MonitorTargetConfig,
    repository_roots: dict[str, Path],
    current_revisions: dict[str, str],
    prior_revisions: dict[str, str],
    previous_resources: list[TerraformResourceRef],
    current_resources: list[TerraformResourceRef],
) -> list[SyncGap]:
    """Fail closed when an IaC input changed without a resource-block delta."""
    delta = diff_terraform_refs(previous_resources, current_resources)
    touched = {
        (resource.repository, resource.relative_path)
        for resource in [*delta["added"], *delta["removed"], *delta["changed"]]
    }
    gaps: list[SyncGap] = []
    by_repository: dict[str, list[str]] = {}
    for binding in target.terraform_roots:
        by_repository.setdefault(binding.repository, []).append(
            _clean_relative_path(binding.path)
        )
    for repository, paths in sorted(by_repository.items()):
        previous = prior_revisions.get(repository)
        current = current_revisions[repository]
        if not previous or previous == current:
            continue
        changed_files = _git_changed_files(
            repository_roots[repository], previous, current, paths
        )
        for path in changed_files:
            if not _is_iac_input(path):
                continue
            resource_delta = (repository, path) in touched
            non_resource_delta = resource_delta and path.lower().endswith(".tf") and (
                _non_resource_iac_fingerprint(
                    _git_file_at_revision(
                        repository_roots[repository], previous, path
                    )
                )
                != _non_resource_iac_fingerprint(
                    _git_file_at_revision(
                        repository_roots[repository], current, path
                    )
                )
            )
            if resource_delta and not non_resource_delta:
                continue
            gaps.append(
                SyncGap(
                    kind="unclassified_iac_file_change",
                    severity=AlertSeverity.HIGH,
                    detail=(
                        f"IaC input {repository}:{path} changed "
                        + (
                            "outside its parsed resource blocks while it also contained "
                            "a resource delta. "
                            if non_resource_delta
                            else "but the resource parser did not produce a resource delta. "
                        )
                        + "The change can be in a variable, local value, module source, "
                        "data block, provider setting, or policy file."
                    ),
                    doc_id=target.doc_id,
                    iac_ref=f"{repository}:{path}",
                    recommended_action=(
                        "Review the file change and attach Terraform plan or control-test evidence."
                    ),
                )
            )
    return gaps


def _git_file_at_revision(root: Path, revision: str, path: str) -> str:
    """Read one file at an exact revision, or return empty text if it is absent."""
    result = subprocess.run(
        ["git", "-C", str(root), "show", f"{revision}:{path}"],
        check=False,
        capture_output=True,
        text=True,
    )
    if result.returncode == 0:
        return result.stdout
    # A valid revision with no file is an expected side of an add/delete diff.
    subprocess.run(
        ["git", "-C", str(root), "rev-parse", "--verify", f"{revision}^{{commit}}"],
        check=True,
        capture_output=True,
        text=True,
    )
    return ""


def _non_resource_iac_fingerprint(text: str) -> str:
    """Hash Terraform text after parsed resource blocks are removed."""
    masked = _mask_hcl_non_code(text)
    spans: list[tuple[int, int]] = []
    for token in _RESOURCE_TOKEN_RE.finditer(masked):
        match = _RESOURCE_DECL_RE.match(text, token.start())
        if match is None:
            continue
        spans.append(
            (match.start(), _find_block_end(masked, match.end() - 1))
        )
    outside: list[str] = []
    cursor = 0
    for start, end in spans:
        outside.append(text[cursor:start])
        cursor = end
    outside.append(text[cursor:])
    normalized = re.sub(r"\s+", " ", "".join(outside)).strip()
    return hashlib.sha256(normalized.encode("utf-8")).hexdigest()


def _source_input_digests(
    targets: list[MonitorTargetConfig],
    repository_roots: dict[str, Path],
) -> dict[str, str]:
    """Hash every evaluated source file without following symbolic links."""
    digests: dict[str, str] = {}
    for target in targets:
        policy_relative = _clean_relative_path(target.policy_path)
        policy_path = repository_roots[target.policy_repository] / policy_relative
        policy_key = f"policy:{target.policy_repository}:{policy_relative}"
        digests[policy_key] = _safe_input_digest(policy_path)
        for repository, relative, path in _iter_iac_tree_entries(
            target,
            repository_roots,
        ):
            digests[f"iac:{repository}:{relative}"] = _safe_input_digest(path)
    return {key: digests[key] for key in sorted(digests)}


def _safe_input_digest(path: Path) -> str:
    if path.is_symlink():
        return hashlib.sha256(
            ("symlink:" + os.readlink(path)).encode("utf-8")
        ).hexdigest()
    if not path.is_file():
        return hashlib.sha256(b"missing").hexdigest()
    return _sha256_file(path)


def _current_input_integrity_gaps(
    target: MonitorTargetConfig,
    repository_roots: dict[str, Path],
    revisions: dict[str, str],
) -> list[SyncGap]:
    """Reject source inputs that do not come from the pinned Git objects."""
    gaps: list[SyncGap] = []
    policy_relative = _clean_relative_path(target.policy_path)
    policy_root = repository_roots[target.policy_repository]
    policy_path = policy_root / policy_relative
    policy_issue = _pinned_input_issue(
        policy_root,
        revisions[target.policy_repository],
        policy_relative,
        policy_path,
    )
    if policy_issue:
        gaps.append(
            SyncGap(
                kind="unpinned_source_input",
                severity=AlertSeverity.CRITICAL,
                detail=(
                    f"Policy input {target.policy_repository}:{policy_relative} "
                    f"is outside the pinned Git input boundary: {policy_issue}."
                ),
                doc_id=target.doc_id,
                recommended_action=(
                    "Use a regular Git-tracked file whose bytes match the selected commit."
                ),
            )
        )

    for repository, relative, path in _iter_iac_tree_entries(
        target,
        repository_roots,
    ):
        issue = _pinned_input_issue(
            repository_roots[repository],
            revisions[repository],
            relative,
            path,
        )
        if not issue:
            continue
        gaps.append(
            SyncGap(
                kind="unpinned_source_input",
                severity=AlertSeverity.CRITICAL,
                detail=(
                    f"IaC input {repository}:{relative} is outside the pinned Git "
                    f"input boundary: {issue}."
                ),
                doc_id=target.doc_id,
                iac_ref=f"{repository}:{relative}",
                recommended_action=(
                    "Replace symlinks and ignored inputs with regular Git-tracked files "
                    "whose bytes match the selected commit."
                ),
            )
        )
    return gaps


def _pinned_input_issue(
    repository_root: Path,
    revision: str,
    relative: str,
    path: Path,
) -> str:
    if path.is_symlink():
        return "symbolic links are not accepted"
    if not path.is_file():
        return "the file is missing or is not a regular file"
    blob = subprocess.run(
        ["git", "-C", str(repository_root), "cat-file", "-p", f"{revision}:{relative}"],
        check=False,
        capture_output=True,
    )
    if blob.returncode != 0:
        return "the file is not tracked at the selected commit"
    if path.read_bytes() != blob.stdout:
        return "working-tree bytes do not match the selected commit"
    return ""


def _iter_iac_tree_entries(
    target: MonitorTargetConfig,
    repository_roots: dict[str, Path],
) -> Iterator[tuple[str, str, Path]]:
    """Yield monitored IaC files and all symlinks without following links."""
    seen: set[tuple[str, str]] = set()
    for binding in target.terraform_roots:
        repository = binding.repository
        repository_root = repository_roots[repository]
        clean_path = _clean_relative_path(binding.path)
        lexical_root = repository_root / clean_path
        if lexical_root.is_symlink():
            relative = lexical_root.relative_to(repository_root).as_posix()
            key = (repository, relative)
            if key not in seen:
                seen.add(key)
                yield repository, relative, lexical_root
            continue
        root = _safe_repo_path(repository_root, clean_path)
        if not root.is_dir():
            raise ValueError(
                f"Terraform root does not exist for {repository}: {clean_path}"
            )
        for current, directories, files in os.walk(root, followlinks=False):
            current_path = Path(current)
            kept_directories: list[str] = []
            for name in sorted(directories):
                child = current_path / name
                if name in _IAC_EXCLUDED_TREE_PARTS:
                    continue
                if child.is_symlink():
                    relative = child.relative_to(repository_root).as_posix()
                    key = (repository, relative)
                    if key not in seen:
                        seen.add(key)
                        yield repository, relative, child
                    continue
                kept_directories.append(name)
            directories[:] = kept_directories
            for name in sorted(files):
                path = current_path / name
                relative = path.relative_to(repository_root).as_posix()
                key = (repository, relative)
                if key in seen:
                    continue
                if path.is_symlink() or _is_iac_input(relative):
                    seen.add(key)
                    yield repository, relative, path


def _scan_file_evidence(
    targets: list[MonitorTargetConfig],
    repository_roots: dict[str, Path],
    revisions: dict[str, str],
    current_cache: dict[tuple[str, str], list[TerraformResourceRef]],
) -> list[ScannedFileEvidence]:
    evidence: dict[tuple[str, str], ScannedFileEvidence] = {}
    resource_counts: dict[tuple[str, str], int] = {}
    for resources in current_cache.values():
        for resource in resources:
            key = (resource.repository, resource.relative_path)
            resource_counts[key] = resource_counts.get(key, 0) + 1
    for target in targets:
        for repository, relative, path in _iter_iac_tree_entries(
            target,
            repository_roots,
        ):
            if path.is_symlink() or not path.is_file() or not _is_iac_input(relative):
                continue
            key = (repository, relative)
            evidence[key] = ScannedFileEvidence(
                repository=repository,
                revision=revisions[repository],
                path=relative,
                sha256=_sha256_file(path),
                parsed_resource_count=resource_counts.get(key, 0),
            )
    return [evidence[key] for key in sorted(evidence)]


def _git_changed_files(
    root: Path,
    previous: str,
    current: str,
    paths: list[str],
) -> list[str]:
    output = _git(
        root,
        "diff",
        "--name-only",
        previous,
        current,
        "--",
        *sorted(set(paths)),
    )
    return sorted({line for line in output.splitlines() if line})


def _is_iac_input(path: str) -> bool:
    lowered = path.lower()
    return lowered.endswith(
        (
            ".tf",
            ".tfvars",
            ".tf.json",
            ".json",
            ".yaml",
            ".yml",
            ".tpl",
        )
    ) or lowered.endswith(".terraform.lock.hcl")


def _aligned_alert(
    target: MonitorTargetConfig,
    input_fingerprint: str,
) -> LifecycleAlert:
    return LifecycleAlert(
        alert_id=hashlib.sha256(
            f"{target.target_id}:{input_fingerprint}:aligned".encode("utf-8")
        ).hexdigest()[:20],
        trigger="completeness_scan",
        severity=AlertSeverity.INFO,
        summary=f"[INFO] Target '{target.target_id}' is complete.",
    )


def _ingest_git_document(root: Path, revision: str, path: str) -> str:
    clean_path = _clean_relative_path(path)
    blob = subprocess.run(
        ["git", "-C", str(root), "show", f"{revision}:{clean_path}"],
        check=True,
        capture_output=True,
    ).stdout
    with tempfile.TemporaryDirectory(prefix="grc-doc-history-") as temp_dir:
        temp_path = Path(temp_dir) / Path(clean_path).name
        temp_path.write_bytes(blob)
        return ingest_path(temp_path).markdown


def _input_fingerprint(
    *,
    config: ProductionMonitorConfig,
    config_path: Path,
    links_path: Path,
    corpus_path: Path,
    revisions: dict[str, str],
    tool_revision: str,
    source_file_digests: dict[str, str],
) -> str:
    payload = {
        "config": _sha256_file(config_path),
        "links": _sha256_file(links_path),
        "corpus": _sha256_file(corpus_path),
        "revisions": revisions,
        "tool_revision": tool_revision,
        "source_file_digests": source_file_digests,
        "targets": [target.model_dump(mode="json") for target in config.targets],
    }
    return hashlib.sha256(
        json.dumps(payload, sort_keys=True).encode("utf-8")
    ).hexdigest()


def _tool_revision(config: ProductionMonitorConfig) -> str:
    if config.tool_revision_env:
        revision = os.environ.get(config.tool_revision_env, "")
        if not re.fullmatch(r"[0-9a-fA-F]{40}|[0-9a-fA-F]{64}", revision):
            raise ValueError(
                f"{config.tool_revision_env} must contain the evaluator's full commit SHA"
            )
        return revision.lower()
    try:
        return _git_revision(Path(__file__).resolve().parents[2], "HEAD")
    except (OSError, subprocess.CalledProcessError):
        return "unavailable"


def _finding_fingerprint(
    targets: list[TargetMonitorResult],
    status: MonitorStatus,
) -> str:
    findings = sorted(
        (
            target.target_id,
            gap.kind,
            gap.severity.value,
            gap.link_id or "",
            gap.iac_ref or "",
            gap.detail,
        )
        for target in targets
        for gap in target.alert.gaps
    )
    wording_changes = sorted(
        (
            target.target_id,
            change.change_kind,
            change.before_text or "",
            change.after_text or "",
        )
        for target in targets
        for change in target.alert.verbiage_changes
    )
    return hashlib.sha256(
        json.dumps(
            {
                "status": status.value,
                "findings": findings,
                "wording_changes": wording_changes,
            },
            sort_keys=True,
        ).encode("utf-8")
    ).hexdigest()


def _dedupe_resources(
    resources: list[TerraformResourceRef],
) -> list[TerraformResourceRef]:
    index: dict[str, TerraformResourceRef] = {}
    for resource in resources:
        existing = index.get(resource.identity_key)
        if existing:
            raise ValueError(
                "Overlapping Terraform roots produced a duplicate resource identity: "
                + resource.identity_key
            )
        index[resource.identity_key] = resource
    return [index[key] for key in sorted(index)]


def _dedupe_gaps(gaps: list[SyncGap]) -> list[SyncGap]:
    index: dict[tuple[str, str, str, str], SyncGap] = {}
    for gap in gaps:
        key = (gap.kind, gap.link_id or "", gap.iac_ref or "", gap.detail)
        index[key] = gap
    return [index[key] for key in sorted(index)]


def _dedupe_control_mappings(
    mappings: list[PolicyCodeControlMapping],
) -> list[PolicyCodeControlMapping]:
    index = {mapping.link_id: mapping for mapping in mappings}
    return [index[key] for key in sorted(index)]


def _dedupe_terraform_mappings(
    mappings: list[TerraformControlMapping],
) -> list[TerraformControlMapping]:
    index = {
        (
            mapping.repository,
            mapping.revision,
            mapping.module_path,
            mapping.relative_path,
            mapping.address,
        ): mapping
        for mapping in mappings
    }
    return [index[key] for key in sorted(index)]


def _status_for_severity(severity: AlertSeverity) -> MonitorStatus:
    rank = SEVERITY_RANK[severity.value]
    if rank >= SEVERITY_RANK[AlertSeverity.HIGH.value]:
        return MonitorStatus.MISALIGNED
    if rank >= SEVERITY_RANK[AlertSeverity.LOW.value]:
        return MonitorStatus.REVIEW_REQUIRED
    return MonitorStatus.ALIGNED


def _max_severity(values: list[AlertSeverity]) -> AlertSeverity:
    return max(values, key=lambda value: SEVERITY_RANK[value.value])


def _read_state(
    path: Path,
    monitor_id: str,
    *,
    require_existing: bool = False,
    allow_bootstrap: bool = False,
) -> dict[str, Any]:
    if not path.exists():
        if require_existing and not allow_bootstrap:
            raise ValueError(
                "The production monitor state is missing. Restore the protected "
                "state or run one explicitly approved bootstrap."
            )
        return {}
    try:
        state = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError(f"The production monitor state is not readable: {path}") from exc
    if not isinstance(state, dict):
        raise ValueError("The production monitor state must be a JSON object")
    state_monitor = state.get("monitor_id")
    if state_monitor and state_monitor != monitor_id:
        raise ValueError(
            f"State belongs to monitor {state_monitor}, not {monitor_id}: {path}"
        )
    if require_existing:
        if state.get("schema_version") != 1:
            raise ValueError("The production monitor state schema is missing or unsupported")
        if state_monitor != monitor_id:
            raise ValueError("The production monitor state does not identify this monitor")
        if state.get("bootstrap_complete") is not True:
            raise ValueError(
                "The production monitor does not have an accepted aligned baseline. "
                "Run one explicitly approved bootstrap after alignment is restored."
            )
        accepted = state.get("last_accepted_revisions")
        if not isinstance(accepted, dict) or not accepted:
            raise ValueError(
                "The production monitor state has no accepted source revisions"
            )
        if any(
            not isinstance(name, str)
            or not name
            or not isinstance(revision, str)
            or not re.fullmatch(r"[0-9a-fA-F]{40}|[0-9a-fA-F]{64}", revision)
            for name, revision in accepted.items()
        ):
            raise ValueError(
                "The production monitor state has invalid accepted source revisions"
            )
        if state.get("last_status") not in {
            MonitorStatus.ALIGNED.value,
            MonitorStatus.REVIEW_REQUIRED.value,
            MonitorStatus.MISALIGNED.value,
        }:
            raise ValueError("The production monitor state has an invalid last status")
    return state


def _write_state(path: Path, state: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(
        mode="w",
        encoding="utf-8",
        dir=path.parent,
        prefix=path.name + ".",
        suffix=".tmp",
        delete=False,
    ) as handle:
        json.dump(state, handle, indent=2, sort_keys=True)
        handle.write("\n")
        temporary = Path(handle.name)
    temporary.replace(path)


def _resolve_path(base: Path, value: str) -> Path:
    path = Path(value)
    return path.resolve() if path.is_absolute() else (base / path).resolve()


def _safe_repo_path(root: Path, value: str) -> Path:
    clean = _clean_relative_path(value)
    candidate = (root / clean).resolve()
    try:
        candidate.relative_to(root.resolve())
    except ValueError as exc:
        raise ValueError(f"Path leaves repository root: {value}") from exc
    return candidate


def _clean_relative_path(value: str) -> str:
    normalized = Path(value).as_posix().strip("/")
    if normalized in {"", "."}:
        return "."
    if normalized == ".." or normalized.startswith("../"):
        raise ValueError(f"Repository path must not contain parent traversal: {value}")
    return normalized


def _git_revision(root: Path, ref: str) -> str:
    return _git(root, "rev-parse", "--verify", f"{ref}^{{commit}}")


def _git(root: Path, *args: str) -> str:
    return subprocess.run(
        ["git", "-C", str(root), *args],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()


def _sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()
