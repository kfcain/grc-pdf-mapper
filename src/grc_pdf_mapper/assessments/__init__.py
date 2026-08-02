"""Assessment registry: which audits depend on which frameworks/docs."""

from __future__ import annotations

import json
from pathlib import Path

from grc_pdf_mapper.models import AssessmentRegistration

DEFAULT_ASSESSMENTS: list[AssessmentRegistration] = [
    AssessmentRegistration(
        assessment_id="soc2-type2-2026",
        name="SOC 2 Type II 2026",
        frameworks=["SOC 2", "NIST 800-53", "NIST CSF 2.0"],
        doc_ids=["pol-ac-001"],
        owner="GRC Lead",
        status="active",
        due_date="2026-12-31",
    ),
    AssessmentRegistration(
        assessment_id="iso27001-surveillance-2026",
        name="ISO 27001 Surveillance 2026",
        frameworks=["ISO 27001", "NIST 800-53"],
        doc_ids=["pol-ac-001"],
        owner="ISMS Manager",
        status="active",
        due_date="2026-09-30",
    ),
    AssessmentRegistration(
        assessment_id="csf-internal-review",
        name="NIST CSF Internal Review",
        frameworks=["NIST CSF 2.0", "NIST 800-53"],
        doc_ids=[],
        owner="Security Governance",
        status="active",
    ),
    AssessmentRegistration(
        assessment_id="fedramp-20x-class-c",
        name="FedRAMP 20x Class C Certification",
        frameworks=["FedRAMP KSI", "NIST 800-53", "FedRAMP"],
        doc_ids=["pol-ac-001"],
        owner="FedRAMP Program Manager",
        status="active",
        due_date="2026-12-31",
        fedramp_class="c",
        certification_type="20x",
    ),
    AssessmentRegistration(
        assessment_id="fedramp-20x-class-b",
        name="FedRAMP 20x Class B Certification",
        frameworks=["FedRAMP KSI", "NIST 800-53", "FedRAMP"],
        doc_ids=["pol-ac-001"],
        owner="FedRAMP Program Manager",
        status="active",
        fedramp_class="b",
        certification_type="20x",
    ),
]


class AssessmentRegistry:
    """Load and persist assessment → framework/document bindings."""

    def __init__(self, path: str | Path | None = None) -> None:
        self.path = Path(path) if path else None
        self._items: list[AssessmentRegistration] = list(DEFAULT_ASSESSMENTS)
        if self.path and self.path.exists():
            self.load(self.path)

    def all(self) -> list[AssessmentRegistration]:
        return list(self._items)

    def active(self) -> list[AssessmentRegistration]:
        return [a for a in self._items if a.status == "active"]

    def upsert(self, assessment: AssessmentRegistration) -> None:
        self._items = [a for a in self._items if a.assessment_id != assessment.assessment_id]
        self._items.append(assessment)

    def load(self, path: str | Path) -> None:
        raw = json.loads(Path(path).read_text(encoding="utf-8"))
        items = raw.get("assessments", raw) if isinstance(raw, dict) else raw
        self._items = [AssessmentRegistration.model_validate(i) for i in items]

    def save(self, path: str | Path | None = None) -> Path:
        target = Path(path or self.path or "assessments.json")
        payload = {"assessments": [a.model_dump() for a in self._items]}
        target.write_text(json.dumps(payload, indent=2), encoding="utf-8")
        self.path = target
        return target
