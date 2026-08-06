"""Keep policy documentation and policy-as-code / compliance-as-code in lock-step."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

from grc_pdf_mapper.extract import extract_control_statements
from grc_pdf_mapper.ingest import ingest_path
from grc_pdf_mapper.impact import detect_verbiage_changes, verbiage_change_severity
from grc_pdf_mapper.models import AlertSeverity, AssessmentRegistration, ControlStatement
from grc_pdf_mapper.classifier_taxonomy import normalize_domains
from grc_pdf_mapper.pac_mapping import (
    assessments_for_mappings,
    framework_labels,
    map_links_via_scf,
    map_terraform_resources_via_scf,
)
from grc_pdf_mapper.pac_models import (
    LifecycleAlert,
    PolicyCodeLink,
    SyncGap,
    SyncReport,
    TerraformResourceRef,
)
from grc_pdf_mapper.terraform_scan import diff_terraform_refs, parse_terraform_file, scan_terraform_tree


def load_links(path: str | Path) -> list[PolicyCodeLink]:
    path = Path(path)
    raw = json.loads(path.read_text(encoding="utf-8"))
    items = raw.get("links", raw) if isinstance(raw, dict) else raw
    return [PolicyCodeLink.model_validate(item) for item in items]


def save_links(links: list[PolicyCodeLink], path: str | Path) -> None:
    path = Path(path)
    payload = {"links": [link.model_dump() for link in links]}
    path.write_text(json.dumps(payload, indent=2), encoding="utf-8")


def completeness_scan(
    *,
    links: list[PolicyCodeLink],
    policy_path: str | Path,
    terraform_root: str | Path | None,
    doc_id: str,
    scf_offline: bool = True,
    assessments: list[AssessmentRegistration] | None = None,
    terraform_resources: list[TerraformResourceRef] | None = None,
    validate_classifier_alignment: bool = False,
    classifier_review_below: float = 0.85,
    require_expected_domains: bool = False,
    require_exact_domains: bool = False,
) -> SyncReport:
    """Check that linked statements and IaC resources still exist and connect."""
    ingest = ingest_path(policy_path)
    statements = extract_control_statements(ingest.markdown, doc_slug=doc_id)
    if terraform_resources is not None:
        resources = list(terraform_resources)
    elif terraform_root is not None:
        resources = scan_terraform_tree(terraform_root)
    else:
        raise ValueError("Provide terraform_root or terraform_resources")
    gaps: list[SyncGap] = []
    covered: list[str] = []

    for link in links:
        if link.doc_id != doc_id:
            continue
        stmt = _find_statement(statements, link)
        matched_resources = _match_resources(resources, link)

        ambiguous_address = _ambiguous_unqualified_address(link, matched_resources)
        if ambiguous_address:
            gaps.append(
                SyncGap(
                    kind="ambiguous_iac_selector",
                    severity=AlertSeverity.CRITICAL,
                    detail=(
                        f"Link {link.link_id} uses unqualified Terraform address "
                        f"{ambiguous_address}, which matches more than one resource."
                    ),
                    link_id=link.link_id,
                    doc_id=doc_id,
                    statement_anchor=link.statement_anchor,
                    iac_ref=", ".join(
                        resource.repository_qualified_address
                        for resource in matched_resources
                        if resource.address == ambiguous_address
                    ),
                    recommended_action=(
                        "Use repository and module-qualified Terraform addresses in the link."
                    ),
                )
            )
            continue

        if stmt is None:
            gaps.append(
                SyncGap(
                    kind="missing_policy_statement",
                    severity=AlertSeverity.HIGH,
                    detail=(
                        f"Link {link.link_id} expects policy language "
                        f"matching '{link.statement_anchor}', but it was not found."
                    ),
                    link_id=link.link_id,
                    doc_id=doc_id,
                    statement_anchor=link.statement_anchor,
                    recommended_action=(
                        "Restore the policy obligation or update the policy-as-code link."
                    ),
                )
            )
            continue

        if not matched_resources:
            gaps.append(
                SyncGap(
                    kind="missing_iac_implementation",
                    severity=AlertSeverity.CRITICAL,
                    detail=(
                        f"Policy statement exists for '{link.statement_anchor}', "
                        f"but no Terraform implementation matched link {link.link_id}."
                    ),
                    link_id=link.link_id,
                    doc_id=doc_id,
                    statement_anchor=link.statement_anchor,
                    recommended_action=(
                        "Add or restore Terraform that enforces this policy, "
                        "and annotate it with # grc: link_id=..."
                    ),
                )
            )
            continue

        covered.append(link.link_id)

    # Orphan IaC with GRC annotations but no manifest link.
    linked_ids = {link.link_id for link in links}
    for resource in resources:
        ann_link = resource.grc_annotations.get("link_id") or resource.tags.get("link_id")
        if ann_link and ann_link not in linked_ids:
            gaps.append(
                SyncGap(
                    kind="orphan_iac_annotation",
                    severity=AlertSeverity.MEDIUM,
                    detail=(
                        f"Terraform {resource.repository_qualified_address} declares "
                        f"link_id={ann_link}, "
                        "but that link is not in the manifest."
                    ),
                    iac_ref=resource.repository_qualified_address,
                    recommended_action="Add the link to the manifest or remove the stale annotation.",
                )
            )

    if validate_classifier_alignment:
        gaps.extend(
            classifier_alignment_gaps(
                links=links,
                statements=statements,
                resources=resources,
                doc_id=doc_id,
                review_below=classifier_review_below,
                require_expected_domains=require_expected_domains,
                require_exact_domains=require_exact_domains,
            )
        )

    doc_links = [link for link in links if link.doc_id == doc_id]
    control_mappings = map_links_via_scf(doc_links, offline=scf_offline)
    terraform_mappings = map_terraform_resources_via_scf(
        resources,
        offline=scf_offline,
    )
    alert = None
    if gaps:
        severity = max((g.severity for g in gaps), key=_sev_rank)
        assessment_impacts = assessments_for_mappings(
            [*control_mappings, *terraform_mappings],
            assessments or [],
            doc_id=doc_id,
            risk=severity,
        )
        alert = LifecycleAlert(
            alert_id=_alert_id("completeness", doc_id, severity.value),
            trigger="completeness_scan",
            severity=severity,
            summary=(
                f"[{severity.value.upper()}] Policy/IaC lock-step incomplete for '{doc_id}': "
                f"{len(gaps)} gap(s), {len(covered)} covered link(s)."
            ),
            gaps=gaps,
            linked_statements=[c.statement_anchor for c in links if c.link_id in covered],
            linked_iac=[r.repository_qualified_address for r in resources],
            frameworks=framework_labels([*control_mappings, *terraform_mappings]),
            control_mappings=control_mappings,
            terraform_mappings=terraform_mappings,
            assessments_impacted=assessment_impacts,
            recommended_actions=sorted({g.recommended_action for g in gaps if g.recommended_action}),
        )

    return SyncReport(
        link_count=len([link for link in links if link.doc_id == doc_id]),
        terraform_resource_count=len(resources),
        covered_links=covered,
        control_mappings=control_mappings,
        terraform_mappings=terraform_mappings,
        gaps=gaps,
        alerts=[alert] if alert else [],
        complete=not gaps,
    )


def classifier_alignment_gaps(
    *,
    links: list[PolicyCodeLink],
    statements: list[ControlStatement],
    resources: list[TerraformResourceRef],
    doc_id: str,
    review_below: float = 0.85,
    require_expected_domains: bool = True,
    require_exact_domains: bool = False,
) -> list[SyncGap]:
    """Compare policy and Terraform labels against human-reviewed ground truth."""
    gaps: list[SyncGap] = []
    for link in links:
        if link.doc_id != doc_id:
            continue
        statement = _find_statement(statements, link)
        matched_resources = _match_resources(resources, link)
        expected = set(normalize_domains(link.expected_domains, strict=True))

        if require_expected_domains and not expected:
            gaps.append(
                SyncGap(
                    kind="classifier_ground_truth_missing",
                    severity=AlertSeverity.MEDIUM,
                    detail=(
                        f"Link {link.link_id} has no expected_domains ground truth. "
                        "The policy and Terraform classifiers cannot be compared safely."
                    ),
                    link_id=link.link_id,
                    doc_id=doc_id,
                    statement_anchor=link.statement_anchor,
                    recommended_action=(
                        "Add human-reviewed expected_domains to the policy-as-code link."
                    ),
                )
            )
            continue

        if statement is not None and statement.classification_confidence < review_below:
            gaps.append(
                SyncGap(
                    kind="policy_classifier_review_required",
                    severity=AlertSeverity.MEDIUM,
                    detail=(
                        f"Policy classifier confidence for link {link.link_id} is "
                        f"{statement.classification_confidence:.2f}; the review threshold is "
                        f"{review_below:.2f}."
                    ),
                    link_id=link.link_id,
                    doc_id=doc_id,
                    statement_anchor=link.statement_anchor,
                    recommended_action=(
                        "Review the statement label and update the classifier corpus before approval."
                    ),
                )
            )

        if statement is not None and any(
            expected_value is not None
            for expected_value in (
                link.expected_statement_kind,
                link.expected_strength,
                link.expected_action_polarity,
            )
        ):
            actual_semantics = (
                statement.statement_kind,
                statement.strength,
                statement.action_polarity,
            )
            expected_semantics = (
                link.expected_statement_kind,
                link.expected_strength,
                link.expected_action_polarity,
            )
            mismatches = [
                f"{label} expected {getattr(expected, 'value', expected)}, "
                f"got {getattr(actual, 'value', actual)}"
                for label, expected, actual in zip(
                    ("kind", "strength", "polarity"),
                    expected_semantics,
                    actual_semantics,
                )
                if expected is not None and expected != actual
            ]
            if mismatches:
                gaps.append(
                    SyncGap(
                        kind="policy_statement_semantic_mismatch",
                        severity=AlertSeverity.CRITICAL,
                        detail=(
                            f"Policy statement semantics for link {link.link_id} do not "
                            "match reviewed ground truth: " + "; ".join(mismatches) + "."
                        ),
                        link_id=link.link_id,
                        doc_id=doc_id,
                        statement_anchor=link.statement_anchor,
                        recommended_action=(
                            "Restore the reviewed duty or approve and update the link semantics."
                        ),
                    )
                )

        policy_domains = set(statement.keywords) if statement is not None else set()
        if expected and statement is not None and not expected.issubset(policy_domains):
            missing = sorted(expected - policy_domains)
            gaps.append(
                SyncGap(
                    kind="policy_classifier_domain_mismatch",
                    severity=AlertSeverity.HIGH,
                    detail=(
                        f"Policy classifier labels for link {link.link_id} do not include "
                        f"the reviewed domain(s): {', '.join(missing)}."
                    ),
                    link_id=link.link_id,
                    doc_id=doc_id,
                    statement_anchor=link.statement_anchor,
                    recommended_action=(
                        "Correct the policy classifier or the reviewed link ground truth."
                    ),
                )
            )

        if require_exact_domains and expected and statement is not None:
            unexpected = sorted(policy_domains - expected)
            if unexpected:
                gaps.append(
                    SyncGap(
                        kind="policy_classifier_unexpected_domain",
                        severity=AlertSeverity.HIGH,
                        detail=(
                            f"Policy classifier labels for link {link.link_id} include "
                            f"domain(s) outside the reviewed set: {', '.join(unexpected)}."
                        ),
                        link_id=link.link_id,
                        doc_id=doc_id,
                        statement_anchor=link.statement_anchor,
                        recommended_action=(
                            "Correct the classifier or add the domain to reviewed ground truth."
                        ),
                    )
                )

        terraform_domains = {
            domain
            for resource in matched_resources
            for domain in resource.classification.domains
        }
        if expected and matched_resources and not expected.issubset(terraform_domains):
            missing = sorted(expected - terraform_domains)
            gaps.append(
                SyncGap(
                    kind="terraform_classifier_domain_mismatch",
                    severity=AlertSeverity.HIGH,
                    detail=(
                        f"Terraform classifier labels for link {link.link_id} do not include "
                        f"the reviewed domain(s): {', '.join(missing)}."
                    ),
                    link_id=link.link_id,
                    doc_id=doc_id,
                    statement_anchor=link.statement_anchor,
                    iac_ref=", ".join(
                        resource.repository_qualified_address
                        for resource in matched_resources
                    ),
                    recommended_action=(
                        "Add an explicit GRC domain annotation or correct the Terraform classifier."
                    ),
                )
            )


        if require_exact_domains and expected and matched_resources:
            unexpected = sorted(terraform_domains - expected)
            if unexpected:
                gaps.append(
                    SyncGap(
                        kind="terraform_classifier_unexpected_domain",
                        severity=AlertSeverity.HIGH,
                        detail=(
                            f"Terraform classifier labels for link {link.link_id} include "
                            f"domain(s) outside the reviewed set: {', '.join(unexpected)}."
                        ),
                        link_id=link.link_id,
                        doc_id=doc_id,
                        statement_anchor=link.statement_anchor,
                        iac_ref=", ".join(
                            resource.repository_qualified_address
                            for resource in matched_resources
                        ),
                        recommended_action=(
                            "Correct the classifier or add the domain to reviewed ground truth."
                        ),
                    )
                )

        for resource in matched_resources:
            if resource.classification.posture == "violated":
                gaps.append(
                    SyncGap(
                        kind="terraform_control_violation",
                        severity=AlertSeverity.CRITICAL,
                        detail=(
                            f"Terraform resource {resource.repository_qualified_address} "
                            "has a known-disabled security setting."
                        ),
                        link_id=link.link_id,
                        doc_id=doc_id,
                        statement_anchor=link.statement_anchor,
                        iac_ref=resource.repository_qualified_address,
                        recommended_action=(
                            "Enable the required setting or approve a documented exception."
                        ),
                    )
                )
            elif resource.classification.posture in {"unknown", "review_required"}:
                gaps.append(
                    SyncGap(
                        kind="terraform_posture_review_required",
                        severity=AlertSeverity.MEDIUM,
                        detail=(
                            f"Terraform resource {resource.repository_qualified_address} "
                            f"has posture {resource.classification.posture}."
                        ),
                        link_id=link.link_id,
                        doc_id=doc_id,
                        statement_anchor=link.statement_anchor,
                        iac_ref=resource.repository_qualified_address,
                        recommended_action=(
                            "Review the configuration and add an explicit approved annotation."
                        ),
                    )
                )
            if resource.classification.confidence >= review_below:
                continue
            gaps.append(
                SyncGap(
                    kind="terraform_classifier_review_required",
                    severity=AlertSeverity.MEDIUM,
                    detail=(
                        f"Terraform classifier confidence for "
                        f"{resource.repository_qualified_address} is "
                        f"{resource.classification.confidence:.2f}; the review threshold is "
                        f"{review_below:.2f}."
                    ),
                    link_id=link.link_id,
                    doc_id=doc_id,
                    statement_anchor=link.statement_anchor,
                    iac_ref=resource.repository_qualified_address,
                    recommended_action=(
                        "Add explicit GRC annotations or extend the reviewed classifier corpus."
                    ),
                )
            )
    for resource in resources:
        if not resource.classification.security_sensitive:
            continue
        if any(_resource_matches_link(resource, link) for link in links):
            continue
        severity = (
            AlertSeverity.HIGH
            if resource.classification.confidence >= review_below
            else AlertSeverity.MEDIUM
        )
        gaps.append(
            SyncGap(
                kind="unlinked_security_sensitive_resource",
                severity=severity,
                detail=(
                    f"Security-sensitive Terraform resource "
                    f"{resource.repository_qualified_address} has no policy-as-code link."
                ),
                doc_id=doc_id,
                iac_ref=resource.repository_qualified_address,
                recommended_action=(
                    "Add a repository-scoped policy-as-code link or document why the "
                    "resource is not a control implementation."
                ),
            )
        )
    return gaps


def analyze_iac_change(
    *,
    links: list[PolicyCodeLink],
    base_tf_files: list[Path],
    head_tf_files: list[Path],
    base_tf_roots: list[Path] | None = None,
    head_tf_roots: list[Path] | None = None,
    policy_path: str | Path | None = None,
    doc_id: str | None = None,
    scf_offline: bool = True,
    assessments: list[AssessmentRegistration] | None = None,
    base_tf_resources: list[TerraformResourceRef] | None = None,
    head_tf_resources: list[TerraformResourceRef] | None = None,
) -> LifecycleAlert:
    """
    When Terraform changes, prompt for documentation review on linked statements.
    """
    before: list[TerraformResourceRef] = list(base_tf_resources or [])
    after: list[TerraformResourceRef] = list(head_tf_resources or [])
    for path in base_tf_files:
        if path.exists():
            before.extend(parse_terraform_file(path))
    for path in head_tf_files:
        if path.exists():
            after.extend(parse_terraform_file(path))
    for root in base_tf_roots or []:
        if root.exists():
            before.extend(scan_terraform_tree(root))
    for root in head_tf_roots or []:
        if root.exists():
            after.extend(scan_terraform_tree(root))

    delta = diff_terraform_refs(before, after)
    touched = delta["added"] + delta["removed"] + delta["changed"]
    changed_paths = sorted({r.relative_path or r.file_path for r in touched})

    gaps: list[SyncGap] = []
    linked_statements: list[str] = []
    linked_iac: list[str] = []
    frameworks: set[str] = set()
    affected_link_ids: set[str] = set()

    for resource in touched:
        matched_links = [link for link in links if _resource_matches_link(resource, link)]
        if not matched_links:
            # Heuristic: IAM / MFA related resources without a link still need review.
            if _looks_security_sensitive(resource):
                gaps.append(
                    SyncGap(
                        kind="unlinked_sensitive_iac_change",
                        severity=AlertSeverity.HIGH,
                        detail=(
                            f"Sensitive Terraform resource "
                            f"{resource.repository_qualified_address} changed "
                            "but is not linked to a policy statement."
                        ),
                        iac_ref=resource.repository_qualified_address,
                        recommended_action=(
                            "Link this resource in the policy-as-code manifest and confirm "
                            "the controlling policy still describes the intended behavior."
                        ),
                    )
                )
            continue

        for link in matched_links:
            if doc_id and link.doc_id != doc_id:
                continue
            affected_link_ids.add(link.link_id)
            linked_statements.append(link.statement_anchor)
            linked_iac.append(resource.repository_qualified_address)
            frameworks.update(link.control_ids)
            change_kind = (
                "added"
                if resource in delta["added"]
                else "removed"
                if resource in delta["removed"]
                else "changed"
            )
            severity = (
                AlertSeverity.CRITICAL
                if change_kind == "removed"
                else AlertSeverity.HIGH
            )
            gaps.append(
                SyncGap(
                    kind=f"iac_{change_kind}_requires_doc_review",
                    severity=severity,
                    detail=(
                        f"Terraform {resource.address} was {change_kind}. "
                        f"Linked policy language: '{link.statement_anchor}'. "
                        "Update or re-validate the documentation in the same change set."
                    ),
                    link_id=link.link_id,
                    doc_id=link.doc_id,
                    statement_anchor=link.statement_anchor,
                    iac_ref=resource.address,
                    recommended_action=(
                        f"Open/update document '{link.doc_id}' so the obligation remains "
                        "accurate for this Terraform behavior, then re-run sync-check."
                    ),
                )
            )

    # Optional: if policy file provided, verify anchors still present.
    if policy_path and Path(policy_path).exists() and linked_statements:
        ingest = ingest_path(policy_path)
        current_statements = extract_control_statements(
            ingest.markdown,
            doc_slug=doc_id or "policy",
        )
        for link in links:
            if link.link_id not in affected_link_ids:
                continue
            if _find_statement(current_statements, link) is None:
                gaps.append(
                    SyncGap(
                        kind="doc_anchor_missing_after_iac_change",
                        severity=AlertSeverity.CRITICAL,
                        detail=(
                            f"IaC changed for anchor '{link.statement_anchor}', but that language "
                            "is missing from the current policy document."
                        ),
                        link_id=link.link_id,
                        doc_id=link.doc_id,
                        statement_anchor=link.statement_anchor,
                        recommended_action="Restore or rewrite the policy obligation to match the code.",
                    )
                )

    severity = (
        max((g.severity for g in gaps), key=_sev_rank) if gaps else AlertSeverity.INFO
    )
    control_mappings = map_links_via_scf(
        links,
        link_ids=affected_link_ids,
        offline=scf_offline,
    )
    terraform_mappings = map_terraform_resources_via_scf(
        touched,
        offline=scf_offline,
    )
    assessment_impacts = assessments_for_mappings(
        [*control_mappings, *terraform_mappings],
        assessments or [],
        doc_id=doc_id or (control_mappings[0].doc_id if control_mappings else ""),
        risk=severity,
    )
    summary = (
        f"[{severity.value.upper()}] Terraform change touches policy-as-code links: "
        f"{len(touched)} resource delta(s), {len(gaps)} lifecycle gap(s). "
        "Documentation review required to keep the control lifecycle complete."
    )
    return LifecycleAlert(
        alert_id=_alert_id("iac_changed", ",".join(changed_paths) or "tf", severity.value),
        trigger="iac_changed",
        severity=severity,
        summary=summary,
        gaps=gaps,
        changed_paths=changed_paths,
        linked_statements=sorted(set(linked_statements)),
        linked_iac=sorted(set(linked_iac)),
        frameworks=(
            framework_labels([*control_mappings, *terraform_mappings])
            or sorted(frameworks)
        ),
        control_mappings=control_mappings,
        terraform_mappings=terraform_mappings,
        assessments_impacted=assessment_impacts,
        recommended_actions=sorted({g.recommended_action for g in gaps if g.recommended_action}),
        metadata={"added": len(delta["added"]), "removed": len(delta["removed"]), "changed": len(delta["changed"])},
    )


def analyze_doc_change_for_iac(
    *,
    links: list[PolicyCodeLink],
    doc_id: str,
    older_markdown: str,
    newer_markdown: str,
    terraform_root: str | Path | None,
    scf_offline: bool = True,
    assessments: list[AssessmentRegistration] | None = None,
    terraform_resources: list[TerraformResourceRef] | None = None,
) -> LifecycleAlert:
    """
    When policy language changes, require verification of linked Terraform.
    """
    older_stmts = extract_control_statements(older_markdown, doc_slug=doc_id)
    newer_stmts = extract_control_statements(newer_markdown, doc_slug=doc_id)
    verbiage_changes = detect_verbiage_changes(older_stmts, newer_stmts)
    if terraform_resources is not None:
        resources = list(terraform_resources)
    elif terraform_root is not None:
        resources = scan_terraform_tree(terraform_root)
    else:
        raise ValueError("Provide terraform_root or terraform_resources")

    gaps: list[SyncGap] = []
    linked_iac: list[str] = []
    linked_statements: list[str] = []
    frameworks: set[str] = set()
    affected_link_ids: set[str] = set()

    for link in links:
        if link.doc_id != doc_id:
            continue
        old_hit = _find_statement(older_stmts, link)
        new_hit = _find_statement(newer_stmts, link)
        matched = _match_resources(resources, link)
        if matched:
            linked_iac.extend(r.repository_qualified_address for r in matched)
        frameworks.update(link.control_ids)

        if old_hit and not new_hit:
            affected_link_ids.add(link.link_id)
            linked_statements.append(link.statement_anchor)
            gaps.append(
                SyncGap(
                    kind="policy_obligation_removed_iac_still_present",
                    severity=AlertSeverity.CRITICAL,
                    detail=(
                        f"Policy language for '{link.statement_anchor}' was removed, "
                        f"but Terraform still implements: "
                        f"{', '.join(r.repository_qualified_address for r in matched) or 'none linked'}."
                    ),
                    link_id=link.link_id,
                    doc_id=doc_id,
                    statement_anchor=link.statement_anchor,
                    iac_ref=", ".join(r.repository_qualified_address for r in matched) or None,
                    recommended_action=(
                        "Either restore the policy obligation or change/retire the "
                        "Terraform implementation in the same release."
                    ),
                )
            )
        elif old_hit and new_hit and old_hit.content_hash != new_hit.content_hash:
            affected_link_ids.add(link.link_id)
            linked_statements.append(link.statement_anchor)
            gaps.append(
                SyncGap(
                    kind="policy_obligation_changed_verify_iac",
                    severity=AlertSeverity.HIGH,
                    detail=(
                        f"Policy language for '{link.statement_anchor}' changed. "
                        f"Verify Terraform still enforces the new wording: "
                        f"{', '.join(r.repository_qualified_address for r in matched) or 'NO IAC LINK'}."
                    ),
                    link_id=link.link_id,
                    doc_id=doc_id,
                    statement_anchor=link.statement_anchor,
                    iac_ref=", ".join(r.repository_qualified_address for r in matched) or None,
                    recommended_action=(
                        "Update Terraform (or confirm no code change is needed) and "
                        "record the verification in the PR."
                    ),
                )
            )
        elif new_hit and not matched:
            affected_link_ids.add(link.link_id)
            linked_statements.append(link.statement_anchor)
            gaps.append(
                SyncGap(
                    kind="policy_without_iac",
                    severity=AlertSeverity.HIGH,
                    detail=(
                        f"Policy obligation '{link.statement_anchor}' is present, "
                        "but no linked Terraform implementation was found."
                    ),
                    link_id=link.link_id,
                    doc_id=doc_id,
                    statement_anchor=link.statement_anchor,
                    recommended_action="Implement compliance-as-code for this obligation or mark it as manual.",
                )
            )

    severity = max(
        [
            *(gap.severity for gap in gaps),
            *(verbiage_change_severity(change) for change in verbiage_changes),
        ]
        or [AlertSeverity.INFO],
        key=_sev_rank,
    )
    control_mappings = map_links_via_scf(
        links,
        link_ids=affected_link_ids,
        offline=scf_offline,
    )
    affected_resources = [
        resource
        for resource in resources
        if any(
            link.link_id in affected_link_ids and _resource_matches_link(resource, link)
            for link in links
        )
    ]
    terraform_mappings = map_terraform_resources_via_scf(
        affected_resources,
        offline=scf_offline,
    )
    assessment_impacts = assessments_for_mappings(
        [*control_mappings, *terraform_mappings],
        assessments or [],
        doc_id=doc_id,
        risk=severity,
    )
    return LifecycleAlert(
        alert_id=_alert_id("doc_changed", doc_id, severity.value),
        trigger="doc_changed",
        severity=severity,
        summary=(
            f"[{severity.value.upper()}] Policy change for '{doc_id}' requires "
            f"policy-as-code verification ({len(gaps)} gap(s))."
        ),
        gaps=gaps,
        verbiage_changes=verbiage_changes,
        linked_statements=sorted(set(linked_statements)),
        linked_iac=sorted(set(linked_iac)),
        frameworks=(
            framework_labels([*control_mappings, *terraform_mappings])
            or sorted(frameworks)
        ),
        control_mappings=control_mappings,
        terraform_mappings=terraform_mappings,
        assessments_impacted=assessment_impacts,
        recommended_actions=sorted({g.recommended_action for g in gaps if g.recommended_action}),
    )


def evaluate_change_set(
    *,
    links: list[PolicyCodeLink],
    doc_id: str,
    base_policy_path: str | Path,
    head_policy_path: str | Path,
    base_tf_root: str | Path,
    head_tf_root: str | Path,
    scf_offline: bool = True,
    assessments: list[AssessmentRegistration] | None = None,
) -> LifecycleAlert:
    """Evaluate policy and all Terraform files as one coordinated change set."""
    base_policy_path = Path(base_policy_path)
    head_policy_path = Path(head_policy_path)
    base_tf_root = Path(base_tf_root)
    head_tf_root = Path(head_tf_root)

    older_markdown = ingest_path(base_policy_path).markdown
    newer_markdown = ingest_path(head_policy_path).markdown
    policy_changed = older_markdown != newer_markdown

    iac_alert = analyze_iac_change(
        links=links,
        base_tf_files=[],
        head_tf_files=[],
        base_tf_roots=[base_tf_root],
        head_tf_roots=[head_tf_root],
        policy_path=head_policy_path,
        doc_id=doc_id,
        scf_offline=scf_offline,
        assessments=assessments,
    )
    doc_alert = analyze_doc_change_for_iac(
        links=links,
        doc_id=doc_id,
        older_markdown=older_markdown,
        newer_markdown=newer_markdown,
        terraform_root=head_tf_root,
        scf_offline=scf_offline,
        assessments=assessments,
    )
    completeness = completeness_scan(
        links=links,
        policy_path=head_policy_path,
        terraform_root=head_tf_root,
        doc_id=doc_id,
        scf_offline=scf_offline,
        assessments=assessments,
        validate_classifier_alignment=True,
        classifier_review_below=0.8,
        require_expected_domains=False,
    )

    iac_by_link = _gaps_by_link(iac_alert.gaps)
    doc_by_link = _gaps_by_link(doc_alert.gaps)
    coordinated = set(iac_by_link).intersection(doc_by_link)
    gaps: list[SyncGap] = []

    # Coordination is evidence that both sides changed. It does not reduce the
    # inherent risk of either change. Keep the original findings until control
    # tests and owner approval verify the new behavior.
    gaps.extend([*iac_alert.gaps, *doc_alert.gaps])

    for link_id in sorted(coordinated):
        link = next((item for item in links if item.link_id == link_id), None)
        iac_gaps = iac_by_link[link_id]
        doc_gaps = doc_by_link[link_id]
        retirement = any("removed" in gap.kind for gap in [*iac_gaps, *doc_gaps])
        severity = max(
            (gap.severity for gap in [*iac_gaps, *doc_gaps]),
            key=_sev_rank,
        )
        kind = (
            "coordinated_control_retirement_review"
            if retirement
            else "coordinated_policy_iac_change"
        )
        resources = sorted(
            {
                ref
                for gap in [*iac_gaps, *doc_gaps]
                for ref in [gap.iac_ref]
                if ref
            }
        )
        gaps.append(
            SyncGap(
                kind=kind,
                severity=severity,
                detail=(
                    f"Policy and Terraform changed together for link {link_id}. "
                    f"Affected Terraform: {', '.join(resources) or 'linked tree resources'}. "
                    "Validate the new control behavior and record the result."
                ),
                link_id=link_id,
                doc_id=doc_id,
                statement_anchor=link.statement_anchor if link else None,
                iac_ref=", ".join(resources) or None,
                recommended_action=(
                    "Run the control-specific Terraform plan assertions and obtain "
                    "the control owner's approval."
                ),
            )
        )

    # Head-state completeness gaps remain valid even when both sides changed.
    existing = {(gap.kind, gap.link_id, gap.iac_ref) for gap in gaps}
    for gap in completeness.gaps:
        key = (gap.kind, gap.link_id, gap.iac_ref)
        if key not in existing:
            gaps.append(gap)
            existing.add(key)

    affected_link_ids = {gap.link_id for gap in gaps if gap.link_id}
    control_mappings = map_links_via_scf(
        links,
        link_ids=affected_link_ids,
        offline=scf_offline,
    )
    terraform_mapping_index = {
        (mapping.repository, mapping.relative_path, mapping.address): mapping
        for mapping in [*iac_alert.terraform_mappings, *doc_alert.terraform_mappings]
    }
    terraform_mappings = list(terraform_mapping_index.values())
    severity = (
        max((gap.severity for gap in gaps), key=_sev_rank)
        if gaps
        else AlertSeverity.INFO
    )
    assessment_impacts = assessments_for_mappings(
        [*control_mappings, *terraform_mappings],
        assessments or [],
        doc_id=doc_id,
        risk=severity,
    )
    changed_paths = list(iac_alert.changed_paths)
    if policy_changed:
        changed_paths.append(str(head_policy_path))
    actions = sorted({gap.recommended_action for gap in gaps if gap.recommended_action})
    summary = (
        f"[{severity.value.upper()}] Combined policy/Terraform evaluation for "
        f"'{doc_id}': {len(iac_alert.changed_paths)} Terraform file(s), "
        f"policy_changed={str(policy_changed).lower()}, {len(gaps)} lifecycle finding(s), "
        f"{len(control_mappings)} SCF-enriched link(s), "
        f"{len(terraform_mappings)} classified Terraform resource(s)."
    )
    return LifecycleAlert(
        alert_id=_alert_id(
            "change_set",
            doc_id,
            "|".join(changed_paths) or "unchanged",
            severity.value,
        ),
        trigger="change_set",
        severity=severity,
        summary=summary,
        gaps=gaps,
        changed_paths=sorted(set(changed_paths)),
        linked_statements=sorted(
            {mapping.statement for mapping in control_mappings}
        ),
        linked_iac=sorted(set(iac_alert.linked_iac + doc_alert.linked_iac)),
        frameworks=framework_labels([*control_mappings, *terraform_mappings]),
        control_mappings=control_mappings,
        terraform_mappings=terraform_mappings,
        assessments_impacted=assessment_impacts,
        recommended_actions=actions,
        metadata={
            "policy_changed": policy_changed,
            "terraform": iac_alert.metadata,
            "coordinated_link_count": len(coordinated),
            "completeness_gap_count": len(completeness.gaps),
            "terraform_resource_count": completeness.terraform_resource_count,
        },
    )


def _gaps_by_link(gaps: list[SyncGap]) -> dict[str, list[SyncGap]]:
    by_link: dict[str, list[SyncGap]] = {}
    for gap in gaps:
        if gap.link_id:
            by_link.setdefault(gap.link_id, []).append(gap)
    return by_link


def _find_statement(
    statements: list[ControlStatement],
    link: PolicyCodeLink,
) -> ControlStatement | None:
    anchor = link.statement_anchor.lower()
    for stmt in statements:
        hay = stmt.text.lower()
        if anchor in hay:
            return stmt
        if link.statement_keywords and all(k.lower() in hay for k in link.statement_keywords):
            return stmt
    return None


def _match_resources(
    resources: list[TerraformResourceRef],
    link: PolicyCodeLink,
) -> list[TerraformResourceRef]:
    return [r for r in resources if _resource_matches_link(r, link)]


def _ambiguous_unqualified_address(
    link: PolicyCodeLink,
    resources: list[TerraformResourceRef],
) -> str:
    for address in link.terraform_addresses:
        if "::" in address:
            continue
        identities = {
            resource.identity_key
            for resource in resources
            if resource.address == address
        }
        if len(identities) > 1:
            return address
    return ""


def _resource_matches_link(resource: TerraformResourceRef, link: PolicyCodeLink) -> bool:
    if link.iac_repositories and resource.repository not in link.iac_repositories:
        return False
    ann_link = resource.grc_annotations.get("link_id") or resource.tags.get("link_id")
    if ann_link and ann_link == link.link_id:
        return True
    address_hit = (
        resource.address in link.terraform_addresses
        or resource.qualified_address in link.terraform_addresses
    )
    if address_hit:
        return True

    path_hit = False
    normalized = (resource.relative_path or resource.file_path).replace("\\", "/")
    for path in link.iac_paths:
        if path in normalized or normalized.endswith(path) or path.endswith(normalized):
            path_hit = True
            break

    if path_hit and address_hit:
        return True
    if path_hit and not link.terraform_addresses and resource.resource_type in link.terraform_resource_types:
        return True
    if resource.resource_type in link.terraform_resource_types and not link.terraform_addresses and not ann_link:
        # Broad type match only when the link does not pin addresses and resource is in a linked path.
        return path_hit
    return False


def _looks_security_sensitive(resource: TerraformResourceRef) -> bool:
    if resource.classification.security_sensitive:
        return True
    t = resource.resource_type.lower()
    sensitive = (
        "iam",
        "mfa",
        "guardduty",
        "securityhub",
        "aws_s3_bucket_public",
        "aws_kms",
        "okta_",
        "azuread_",
    )
    return any(token in t for token in sensitive)


def _sev_rank(severity: AlertSeverity | str) -> int:
    value = severity.value if isinstance(severity, AlertSeverity) else severity
    return {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}.get(value, 0)


def _alert_id(*parts: str) -> str:
    material = "|".join(parts).encode("utf-8")
    return hashlib.sha256(material).hexdigest()[:16]
