"""SCF enrichment for policy-to-code lifecycle evaluation."""

from __future__ import annotations

from collections.abc import Iterable

from grc_pdf_mapper.extract import extract_control_statements
from grc_pdf_mapper.models import (
    AlertSeverity,
    AssessmentImpact,
    AssessmentRegistration,
    ControlStatement,
)
from grc_pdf_mapper.pac_models import (
    PolicyCodeControlMapping,
    PolicyCodeLink,
    TerraformControlMapping,
    TerraformResourceRef,
)
from grc_pdf_mapper.scf import SCF_ATTRIBUTION, ScfClient


def map_links_via_scf(
    links: Iterable[PolicyCodeLink],
    *,
    link_ids: set[str] | None = None,
    offline: bool = True,
) -> list[PolicyCodeControlMapping]:
    """Map selected policy-to-code links through the SCF backbone."""
    selected = [link for link in links if link_ids is None or link.link_id in link_ids]
    mappings: list[PolicyCodeControlMapping] = []
    with ScfClient(offline=offline) as client:
        for link in selected:
            statement = _statement_for_link(link)
            hits = client.map_statement(statement)
            framework_controls: dict[str, list[str]] = {}
            for hit in hits:
                bucket = framework_controls.setdefault(hit.framework, [])
                if hit.control_id not in bucket:
                    bucket.append(hit.control_id)
            mappings.append(
                PolicyCodeControlMapping(
                    link_id=link.link_id,
                    doc_id=link.doc_id,
                    statement=link.statement_anchor,
                    source_control_ids=list(dict.fromkeys(link.control_ids)),
                    scf_control_ids=framework_controls.get("SCF", []),
                    framework_controls=framework_controls,
                    owner=link.owner,
                    attribution=SCF_ATTRIBUTION,
                )
            )
    return mappings


def assessments_for_mappings(
    mappings: Iterable[PolicyCodeControlMapping | TerraformControlMapping],
    assessments: Iterable[AssessmentRegistration],
    *,
    doc_id: str,
    risk: AlertSeverity,
) -> list[AssessmentImpact]:
    """Find active assessments that use frameworks in the SCF-enriched links."""
    framework_names = {
        framework
        for mapping in mappings
        for framework in mapping.framework_controls
        if framework != "SCF"
    }
    impacts: list[AssessmentImpact] = []
    for assessment in assessments:
        if assessment.status != "active":
            continue
        if assessment.doc_ids and doc_id not in assessment.doc_ids:
            continue
        affected = sorted(framework_names.intersection(assessment.frameworks))
        if not affected:
            continue
        impacts.append(
            AssessmentImpact(
                assessment_id=assessment.assessment_id,
                assessment_name=assessment.name,
                frameworks_at_risk=affected,
                risk=risk,
                reason=(
                    "A policy-to-code change affects SCF-mapped controls used by "
                    f"assessment '{assessment.name}'."
                ),
            )
        )
    return impacts


def map_terraform_resources_via_scf(
    resources: Iterable[TerraformResourceRef],
    *,
    offline: bool = True,
) -> list[TerraformControlMapping]:
    """Enrich changed Terraform classifier signals with SCF crosswalks."""
    selected = [resource for resource in resources if resource.classification.security_sensitive]
    mappings: list[TerraformControlMapping] = []
    with ScfClient(offline=offline) as client:
        for resource in selected:
            classification = resource.classification
            relationship = {
                "implemented": "implements",
                "violated": "is related to but violates",
                "review_required": "needs configuration review for",
            }.get(classification.posture, "is related to")
            statement = ControlStatement(
                statement_id=f"terraform:{resource.identity_key}",
                text=(
                    f"Terraform resource {resource.resource_type} {relationship} "
                    f"{', '.join(classification.domains) or 'security'} controls."
                ),
                keywords=classification.domains,
                candidate_framework_ids=classification.candidate_control_ids,
                classification_confidence=classification.confidence,
                classification_reasons=classification.reasons,
                content_hash=resource.identity_key,
            )
            framework_controls: dict[str, list[str]] = {}
            for hit in client.map_statement(statement):
                bucket = framework_controls.setdefault(hit.framework, [])
                if hit.control_id not in bucket:
                    bucket.append(hit.control_id)
            mappings.append(
                TerraformControlMapping(
                    address=resource.address,
                    resource_type=resource.resource_type,
                    relative_path=resource.relative_path,
                    module_path=resource.module_path,
                    root_path=resource.root_path,
                    qualified_address=resource.repository_qualified_address,
                    repository=resource.repository,
                    revision=resource.revision,
                    domains=classification.domains,
                    candidate_control_ids=classification.candidate_control_ids,
                    scf_control_ids=framework_controls.get("SCF", []),
                    framework_controls=framework_controls,
                    enforcement_roles=classification.enforcement_roles,
                    security_sensitive=classification.security_sensitive,
                    confidence=classification.confidence,
                    classification_status=classification.status,
                    posture=classification.posture,
                    reasons=classification.reasons,
                    attribution=SCF_ATTRIBUTION,
                )
            )
    return mappings


def framework_labels(
    mappings: Iterable[PolicyCodeControlMapping | TerraformControlMapping],
) -> list[str]:
    """Create stable framework:control labels for reports and alert indexes."""
    labels: set[str] = set()
    for mapping in mappings:
        for framework, control_ids in mapping.framework_controls.items():
            labels.update(f"{framework}:{control_id}" for control_id in control_ids)
    return sorted(labels)


def _statement_for_link(link: PolicyCodeLink) -> ControlStatement:
    extracted = extract_control_statements(link.statement_anchor, doc_slug=link.doc_id)
    if extracted:
        statement = extracted[0]
        candidates = list(
            dict.fromkeys([*statement.candidate_framework_ids, *link.control_ids])
        )
        return statement.model_copy(
            update={
                "statement_id": link.link_id,
                "candidate_framework_ids": candidates,
            }
        )
    return ControlStatement(
        statement_id=link.link_id,
        text=link.statement_anchor,
        keywords=[],
        candidate_framework_ids=list(dict.fromkeys(link.control_ids)),
        content_hash=link.link_id,
    )
