"""Models for policy ↔ policy-as-code / compliance-as-code lock-step."""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field

from grc_pdf_mapper.models import AlertSeverity


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
    control_ids: list[str] = Field(default_factory=list)
    # IaC / compliance-as-code selectors
    iac_paths: list[str] = Field(default_factory=list)
    terraform_addresses: list[str] = Field(default_factory=list)
    terraform_resource_types: list[str] = Field(default_factory=list)
    tags: dict[str, str] = Field(default_factory=dict)
    owner: str | None = None
    direction: LinkDirection = LinkDirection.BIDIRECTIONAL
    notes: str = ""


class TerraformResourceRef(BaseModel):
    address: str
    resource_type: str
    name: str
    file_path: str
    start_line: int = 0
    tags: dict[str, str] = Field(default_factory=dict)
    grc_annotations: dict[str, str] = Field(default_factory=dict)
    raw_snippet: str = ""


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
    changed_paths: list[str] = Field(default_factory=list)
    linked_statements: list[str] = Field(default_factory=list)
    linked_iac: list[str] = Field(default_factory=list)
    frameworks: list[str] = Field(default_factory=list)
    recommended_actions: list[str] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)


class SyncReport(BaseModel):
    """Full lock-step health report for docs + IaC."""

    generated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    link_count: int = 0
    terraform_resource_count: int = 0
    covered_links: list[str] = Field(default_factory=list)
    gaps: list[SyncGap] = Field(default_factory=list)
    alerts: list[LifecycleAlert] = Field(default_factory=list)
    complete: bool = False
