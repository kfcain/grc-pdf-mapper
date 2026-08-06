"""Shared domain models for GRC PDF mapping."""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field


class ObligationStrength(str, Enum):
    MUST = "must"
    SHALL = "shall"
    SHOULD = "should"
    MAY = "may"
    PROHIBITED = "prohibited"
    DESCRIPTIVE = "descriptive"


class StatementKind(str, Enum):
    OBLIGATION = "obligation"
    PROHIBITION = "prohibition"
    RECOMMENDATION = "recommendation"
    PERMISSION = "permission"
    RESPONSIBILITY = "responsibility"
    CONTROL_DESCRIPTION = "control_description"
    CITATION = "citation"


class ControlStatement(BaseModel):
    """One control-related obligation extracted from policy text."""

    statement_id: str
    text: str
    heading_path: list[str] = Field(default_factory=list)
    page: int | None = None
    strength: ObligationStrength = ObligationStrength.DESCRIPTIVE
    statement_kind: StatementKind = StatementKind.CONTROL_DESCRIPTION
    action_polarity: str = "positive"
    keywords: list[str] = Field(default_factory=list)
    candidate_framework_ids: list[str] = Field(default_factory=list)
    classification_confidence: float = 0.0
    classification_status: str = "unclassified"
    classification_reasons: list[str] = Field(default_factory=list)
    source_span: tuple[int, int] | None = None
    content_hash: str = ""


class CrosswalkHit(BaseModel):
    """A mapped control from an external catalog or API."""

    source: str
    framework: str
    control_id: str
    title: str = ""
    relationship: str = "related"
    confidence: float = 0.5
    url: str | None = None
    cre_ids: list[str] = Field(default_factory=list)
    raw: dict[str, Any] = Field(default_factory=dict)


class IngestResult(BaseModel):
    """Output of document ingest (Markdown, PDF, or office via anydoc)."""

    source_path: str
    source_hash: str
    markdown: str
    pdf_type: str | None = None
    confidence: float | None = None
    page_count: int | None = None
    pages_needing_ocr: list[int] = Field(default_factory=list)
    title: str | None = None
    engine: str = "markdown"
    detected_format: str | None = None


class DocumentSnapshot(BaseModel):
    """Git-style immutable snapshot of a corporate document."""

    snapshot_id: str
    doc_id: str
    version_label: str
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    source_hash: str
    markdown_hash: str
    parent_snapshot_id: str | None = None
    title: str | None = None
    author: str | None = None
    approval_status: str = "draft"
    statement_ids: list[str] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)


class MappedStatement(BaseModel):
    statement: ControlStatement
    mappings: list[CrosswalkHit] = Field(default_factory=list)


class MappingReport(BaseModel):
    """Full pipeline report for one document version."""

    doc_id: str
    snapshot_id: str
    ingest: IngestResult
    statements: list[MappedStatement] = Field(default_factory=list)
    frameworks_covered: list[str] = Field(default_factory=list)
    gaps: list[str] = Field(default_factory=list)
    generated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class DriftFinding(BaseModel):
    kind: str
    detail: str
    statement_id: str | None = None
    severity: str = "info"


class BlastRadiusItem(BaseModel):
    framework: str
    control_id: str
    title: str = ""
    via_statement_id: str
    source: str


class AlertSeverity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class VerbiageChange(BaseModel):
    """One language change between document versions."""

    change_kind: str
    before_text: str | None = None
    after_text: str | None = None
    before_strength: str | None = None
    after_strength: str | None = None
    before_statement_id: str | None = None
    after_statement_id: str | None = None
    similarity: float = 0.0
    classification_confidence: float = 0.0
    classification_reasons: list[str] = Field(default_factory=list)
    risk_note: str = ""


class FrameworkImpact(BaseModel):
    framework: str
    control_ids: list[str] = Field(default_factory=list)
    risk: AlertSeverity = AlertSeverity.MEDIUM
    reason: str = ""


class AssessmentImpact(BaseModel):
    assessment_id: str
    assessment_name: str
    frameworks_at_risk: list[str] = Field(default_factory=list)
    risk: AlertSeverity = AlertSeverity.MEDIUM
    reason: str = ""


class ImpactAlert(BaseModel):
    """Real-time GRC alert when policy language may affect compliance."""

    alert_id: str
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    doc_id: str
    older_snapshot_id: str
    newer_snapshot_id: str
    version_from: str
    version_to: str
    severity: AlertSeverity
    summary: str
    verbiage_changes: list[VerbiageChange] = Field(default_factory=list)
    frameworks_impacted: list[FrameworkImpact] = Field(default_factory=list)
    assessments_impacted: list[AssessmentImpact] = Field(default_factory=list)
    recommended_actions: list[str] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)


class AssessmentRegistration(BaseModel):
    """Links an assessment/audit initiative to frameworks and documents."""

    assessment_id: str
    name: str
    frameworks: list[str] = Field(default_factory=list)
    doc_ids: list[str] = Field(default_factory=list)
    owner: str | None = None
    status: str = "active"
    due_date: str | None = None
    # FedRAMP CR26 certification class when this assessment is a FedRAMP package.
    fedramp_class: str | None = None
    certification_type: str | None = None  # e.g. 20x | rev5
