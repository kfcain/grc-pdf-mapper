"""Models for policy ↔ policy-as-code / compliance-as-code lock-step."""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Any, Literal

from pydantic import BaseModel, Field, field_validator

from grc_pdf_mapper.classifier_taxonomy import normalize_domains
from grc_pdf_mapper.models import (
    AlertSeverity,
    AssessmentImpact,
    ObligationStrength,
    StatementKind,
    VerbiageChange,
)


class LinkDirection(str, Enum):
    DOC_TO_CODE = "doc_to_code"
    CODE_TO_DOC = "code_to_doc"
    BIDIRECTIONAL = "bidirectional"


class PolicyCodeLink(BaseModel):
    """One explicit binding between policy language and executable controls."""

    link_id: str
    doc_id: str
    # Stable anchor into policy language (substring or obligation fingerprint hint).
    statement_anchor: str
    statement_keywords: list[str] = Field(default_factory=list)
    # Human-reviewed labels from the shared classifier taxonomy. Production
    # monitors use these labels as the ground truth for policy/IaC alignment.
    expected_domains: list[str] = Field(default_factory=list)
    expected_statement_kind: StatementKind | None = None
    expected_strength: ObligationStrength | None = None
    expected_action_polarity: Literal["positive", "negative"] | None = None
    control_ids: list[str] = Field(default_factory=list)
    # IaC / compliance-as-code selectors
    iac_repositories: list[str] = Field(default_factory=list)
    iac_paths: list[str] = Field(default_factory=list)
    terraform_addresses: list[str] = Field(default_factory=list)
    terraform_resource_types: list[str] = Field(default_factory=list)
    tags: dict[str, str] = Field(default_factory=dict)
    owner: str | None = None
    direction: LinkDirection = LinkDirection.BIDIRECTIONAL
    notes: str = ""

    @field_validator("expected_domains")
    @classmethod
    def _normalize_expected_domains(cls, values: list[str]) -> list[str]:
        return normalize_domains(values, strict=True)


class TerraformClassification(BaseModel):
    """Explainable security classification for one Terraform resource."""

    domains: list[str] = Field(default_factory=list)
    candidate_control_ids: list[str] = Field(default_factory=list)
    enforcement_roles: list[str] = Field(default_factory=list)
    security_sensitive: bool = False
    confidence: float = 0.0
    status: str = "unclassified"
    posture: str = "unknown"
    reasons: list[str] = Field(default_factory=list)

    @field_validator("domains")
    @classmethod
    def _normalize_domains(cls, values: list[str]) -> list[str]:
        return normalize_domains(values, strict=True)


class TerraformResourceRef(BaseModel):
    address: str
    resource_type: str
    name: str
    file_path: str
    relative_path: str = ""
    module_path: str = "."
    repository: str = ""
    revision: str = ""
    root_path: str = ""
    start_line: int = 0
    tags: dict[str, str] = Field(default_factory=dict)
    grc_annotations: dict[str, str] = Field(default_factory=dict)
    classification: TerraformClassification = Field(default_factory=TerraformClassification)
    content_hash: str = ""
    raw_snippet: str = ""

    @property
    def identity_key(self) -> str:
        """Stable identity across base/head trees and file moves in one module."""
        prefix = f"{self.repository}::" if self.repository else ""
        return f"{prefix}{self.module_path}::{self.address}"

    @property
    def qualified_address(self) -> str:
        if self.module_path in {"", "."}:
            return self.address
        return f"{self.module_path}::{self.address}"

    @property
    def repository_qualified_address(self) -> str:
        """Address that remains unique when the monitor scans many repositories."""
        if not self.repository:
            return self.address
        return f"{self.repository}::{self.qualified_address}"


class PolicyCodeControlMapping(BaseModel):
    """SCF-backed control context for one policy-to-code link."""

    link_id: str
    doc_id: str
    statement: str
    source_control_ids: list[str] = Field(default_factory=list)
    scf_control_ids: list[str] = Field(default_factory=list)
    framework_controls: dict[str, list[str]] = Field(default_factory=dict)
    owner: str | None = None
    source: str = "scf-api"
    attribution: str = ""


class TerraformControlMapping(BaseModel):
    """SCF-enriched classification for one changed Terraform resource."""

    address: str
    resource_type: str
    relative_path: str = ""
    module_path: str = "."
    root_path: str = ""
    qualified_address: str = ""
    repository: str = ""
    revision: str = ""
    domains: list[str] = Field(default_factory=list)
    candidate_control_ids: list[str] = Field(default_factory=list)
    scf_control_ids: list[str] = Field(default_factory=list)
    framework_controls: dict[str, list[str]] = Field(default_factory=dict)
    enforcement_roles: list[str] = Field(default_factory=list)
    security_sensitive: bool = False
    confidence: float = 0.0
    classification_status: str = "unclassified"
    posture: str = "unknown"
    reasons: list[str] = Field(default_factory=list)
    source: str = "terraform-classifier+scf-api"
    attribution: str = ""


class SyncGap(BaseModel):
    kind: str
    severity: AlertSeverity
    detail: str
    link_id: str | None = None
    doc_id: str | None = None
    statement_anchor: str | None = None
    iac_ref: str | None = None
    recommended_action: str = ""


class LifecycleAlert(BaseModel):
    """Alert when documentation and policy-as-code fall out of lock-step."""

    alert_id: str
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    trigger: str  # iac_changed | doc_changed | completeness_scan
    severity: AlertSeverity
    summary: str
    gaps: list[SyncGap] = Field(default_factory=list)
    verbiage_changes: list[VerbiageChange] = Field(default_factory=list)
    changed_paths: list[str] = Field(default_factory=list)
    linked_statements: list[str] = Field(default_factory=list)
    linked_iac: list[str] = Field(default_factory=list)
    frameworks: list[str] = Field(default_factory=list)
    control_mappings: list[PolicyCodeControlMapping] = Field(default_factory=list)
    terraform_mappings: list[TerraformControlMapping] = Field(default_factory=list)
    assessments_impacted: list[AssessmentImpact] = Field(default_factory=list)
    recommended_actions: list[str] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)


class SyncReport(BaseModel):
    """Full lock-step health report for docs + IaC."""

    generated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    link_count: int = 0
    terraform_resource_count: int = 0
    covered_links: list[str] = Field(default_factory=list)
    control_mappings: list[PolicyCodeControlMapping] = Field(default_factory=list)
    terraform_mappings: list[TerraformControlMapping] = Field(default_factory=list)
    gaps: list[SyncGap] = Field(default_factory=list)
    alerts: list[LifecycleAlert] = Field(default_factory=list)
    complete: bool = False
