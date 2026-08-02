"""Keep policy documentation and policy-as-code / compliance-as-code in lock-step."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

from grc_pdf_mapper.extract import extract_control_statements
from grc_pdf_mapper.ingest import ingest_path
from grc_pdf_mapper.models import AlertSeverity, ControlStatement
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
    terraform_root: str | Path,
    doc_id: str,
) -> SyncReport:
    """Check that linked statements and IaC resources still exist and connect."""
    ingest = ingest_path(policy_path)
    statements = extract_control_statements(ingest.markdown, doc_slug=doc_id)
    resources = scan_terraform_tree(terraform_root)
    gaps: list[SyncGap] = []
    covered: list[str] = []

    for link in links:
        if link.doc_id != doc_id:
            continue
        stmt = _find_statement(statements, link)
        matched_resources = _match_resources(resources, link)

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
                        f"Terraform {resource.address} declares link_id={ann_link}, "
                        "but that link is not in the manifest."
                    ),
                    iac_ref=resource.address,
                    recommended_action="Add the link to the manifest or remove the stale annotation.",
                )
            )

    alert = None
    if gaps:
        severity = max((g.severity for g in gaps), key=_sev_rank)
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
            linked_iac=[r.address for r in resources],
            frameworks=sorted({cid.split("-")[0] for link in links for cid in link.control_ids if "-" in cid}),
            recommended_actions=sorted({g.recommended_action for g in gaps if g.recommended_action}),
        )

    return SyncReport(
        link_count=len([link for link in links if link.doc_id == doc_id]),
        terraform_resource_count=len(resources),
        covered_links=covered,
        gaps=gaps,
        alerts=[alert] if alert else [],
        complete=not gaps,
    )


def analyze_iac_change(
    *,
    links: list[PolicyCodeLink],
    base_tf_files: list[Path],
    head_tf_files: list[Path],
    policy_path: str | Path | None = None,
    doc_id: str | None = None,
) -> LifecycleAlert:
    """
    When Terraform changes, prompt for documentation review on linked statements.
    """
    before: list[TerraformResourceRef] = []
    after: list[TerraformResourceRef] = []
    for path in base_tf_files:
        if path.exists():
            before.extend(parse_terraform_file(path))
    for path in head_tf_files:
        if path.exists():
            after.extend(parse_terraform_file(path))

    delta = diff_terraform_refs(before, after)
    touched = delta["added"] + delta["removed"] + delta["changed"]
    changed_paths = sorted({r.file_path for r in touched})

    gaps: list[SyncGap] = []
    linked_statements: list[str] = []
    linked_iac: list[str] = []
    frameworks: set[str] = set()

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
                            f"Sensitive Terraform resource {resource.address} changed "
                            "but is not linked to a policy statement."
                        ),
                        iac_ref=resource.address,
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
            linked_statements.append(link.statement_anchor)
            linked_iac.append(resource.address)
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
        text = ingest.markdown.lower()
        for anchor in sorted(set(linked_statements)):
            if anchor.lower() not in text:
                gaps.append(
                    SyncGap(
                        kind="doc_anchor_missing_after_iac_change",
                        severity=AlertSeverity.CRITICAL,
                        detail=(
                            f"IaC changed for anchor '{anchor}', but that language "
                            "is missing from the current policy document."
                        ),
                        statement_anchor=anchor,
                        recommended_action="Restore or rewrite the policy obligation to match the code.",
                    )
                )

    severity = (
        max((g.severity for g in gaps), key=_sev_rank) if gaps else AlertSeverity.INFO
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
        frameworks=sorted(frameworks),
        recommended_actions=sorted({g.recommended_action for g in gaps if g.recommended_action}),
        metadata={"added": len(delta["added"]), "removed": len(delta["removed"]), "changed": len(delta["changed"])},
    )


def analyze_doc_change_for_iac(
    *,
    links: list[PolicyCodeLink],
    doc_id: str,
    older_markdown: str,
    newer_markdown: str,
    terraform_root: str | Path,
) -> LifecycleAlert:
    """
    When policy language changes, require verification of linked Terraform.
    """
    older_stmts = extract_control_statements(older_markdown, doc_slug=doc_id)
    newer_stmts = extract_control_statements(newer_markdown, doc_slug=doc_id)
    resources = scan_terraform_tree(terraform_root)

    gaps: list[SyncGap] = []
    linked_iac: list[str] = []
    linked_statements: list[str] = []
    frameworks: set[str] = set()

    for link in links:
        if link.doc_id != doc_id:
            continue
        old_hit = _find_statement(older_stmts, link)
        new_hit = _find_statement(newer_stmts, link)
        matched = _match_resources(resources, link)
        if matched:
            linked_iac.extend(r.address for r in matched)
        frameworks.update(link.control_ids)

        if old_hit and not new_hit:
            linked_statements.append(link.statement_anchor)
            gaps.append(
                SyncGap(
                    kind="policy_obligation_removed_iac_still_present",
                    severity=AlertSeverity.CRITICAL,
                    detail=(
                        f"Policy language for '{link.statement_anchor}' was removed, "
                        f"but Terraform still implements: "
                        f"{', '.join(r.address for r in matched) or 'none linked'}."
                    ),
                    link_id=link.link_id,
                    doc_id=doc_id,
                    statement_anchor=link.statement_anchor,
                    iac_ref=", ".join(r.address for r in matched) or None,
                    recommended_action=(
                        "Either restore the policy obligation or change/retire the "
                        "Terraform implementation in the same release."
                    ),
                )
            )
        elif old_hit and new_hit and old_hit.content_hash != new_hit.content_hash:
            linked_statements.append(link.statement_anchor)
            gaps.append(
                SyncGap(
                    kind="policy_obligation_changed_verify_iac",
                    severity=AlertSeverity.HIGH,
                    detail=(
                        f"Policy language for '{link.statement_anchor}' changed. "
                        f"Verify Terraform still enforces the new wording: "
                        f"{', '.join(r.address for r in matched) or 'NO IAC LINK'}."
                    ),
                    link_id=link.link_id,
                    doc_id=doc_id,
                    statement_anchor=link.statement_anchor,
                    iac_ref=", ".join(r.address for r in matched) or None,
                    recommended_action=(
                        "Update Terraform (or confirm no code change is needed) and "
                        "record the verification in the PR."
                    ),
                )
            )
        elif new_hit and not matched:
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

    severity = (
        max((g.severity for g in gaps), key=_sev_rank) if gaps else AlertSeverity.INFO
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
        linked_statements=sorted(set(linked_statements)),
        linked_iac=sorted(set(linked_iac)),
        frameworks=sorted(frameworks),
        recommended_actions=sorted({g.recommended_action for g in gaps if g.recommended_action}),
    )


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


def _resource_matches_link(resource: TerraformResourceRef, link: PolicyCodeLink) -> bool:
    ann_link = resource.grc_annotations.get("link_id") or resource.tags.get("link_id")
    if ann_link and ann_link == link.link_id:
        return True
    if resource.address in link.terraform_addresses:
        return True

    path_hit = False
    normalized = resource.file_path.replace("\\", "/")
    for path in link.iac_paths:
        if path in normalized or normalized.endswith(path) or path.endswith(normalized):
            path_hit = True
            break

    if path_hit and resource.address in link.terraform_addresses:
        return True
    if path_hit and not link.terraform_addresses and resource.resource_type in link.terraform_resource_types:
        return True
    if resource.resource_type in link.terraform_resource_types and not link.terraform_addresses and not ann_link:
        # Broad type match only when the link does not pin addresses and resource is in a linked path.
        return path_hit
    return False


def _looks_security_sensitive(resource: TerraformResourceRef) -> bool:
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
