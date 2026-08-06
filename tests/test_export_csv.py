"""Tests for framework / control CSV export from mapping results."""

from __future__ import annotations

import csv
import io
from pathlib import Path

from grc_pdf_mapper.export import framework_controls_csv, frameworks_csv, report_csv_exports
from grc_pdf_mapper.pipeline import analyze_document

FIXTURES = Path(__file__).parent / "fixtures"


def test_framework_and_control_csv_from_mappings():
    report = analyze_document(
        FIXTURES / "access_control_policy_v1.md",
        doc_id="pol-ac-001",
        offline=True,
        commit=False,
    )
    fw_csv = frameworks_csv(report.statements)
    ctrl_csv = framework_controls_csv(report.statements)

    fw_rows = list(csv.DictReader(io.StringIO(fw_csv)))
    assert fw_rows
    assert {"framework", "control_count", "statement_count", "control_ids"} <= set(
        fw_rows[0]
    )
    frameworks = {row["framework"] for row in fw_rows}
    assert "NIST 800-53" in frameworks or "SCF" in frameworks

    ctrl_rows = list(csv.DictReader(io.StringIO(ctrl_csv)))
    assert ctrl_rows
    assert {
        "framework",
        "control_id",
        "control_title",
        "sources",
        "max_confidence",
        "statement_count",
        "statement_ids",
        "strengths",
        "statement_kinds",
        "classifier_confidences",
        "classifier_reasons",
        "obligations",
    } <= set(ctrl_rows[0])
    assert any(row["control_id"] for row in ctrl_rows)

    bundle = report_csv_exports(report)
    assert bundle["frameworks"].startswith("framework,")
    assert bundle["controls"].startswith("framework,")
