from pathlib import Path

import pytest

from grc_pdf_mapper.analytics import (
    blast_radius,
    coverage_matrix,
    questionnaire_suggest,
    stale_framework_refs,
)
from grc_pdf_mapper.crosswalk import CrosswalkClient
from grc_pdf_mapper.extract import extract_control_statements
from grc_pdf_mapper.ingest import ingest_path
from grc_pdf_mapper.lineage import PolicyLineageStore
from grc_pdf_mapper.oscal import to_component_definition
from grc_pdf_mapper.pipeline import analyze_document

FIXTURES = Path(__file__).parent / "fixtures"


def test_ingest_markdown():
    result = ingest_path(FIXTURES / "access_control_policy_v1.md")
    assert result.engine == "markdown"
    assert result.title == "Access Control Policy"
    assert "AC-2" in result.markdown


def test_extract_obligations_and_citations():
    markdown = (FIXTURES / "access_control_policy_v1.md").read_text(encoding="utf-8")
    statements = extract_control_statements(markdown, doc_slug="pol-ac")
    assert len(statements) >= 8
    strengths = {s.strength.value for s in statements}
    assert "must" in strengths or "shall" in strengths
    assert "prohibited" in strengths
    cited = {cid for s in statements for cid in s.candidate_framework_ids}
    assert any(c.startswith("AC-") for c in cited)
    assert any("AU-2" in c or "AU-6" in c for c in cited)


def test_offline_crosswalk_seed():
    markdown = (FIXTURES / "access_control_policy_v1.md").read_text(encoding="utf-8")
    statements = extract_control_statements(markdown, doc_slug="pol-ac")
    with CrosswalkClient(offline=True) as client:
        hits = client.map_statement(statements[0])
    assert hits
    frameworks = {h.framework for h in hits}
    assert frameworks


def test_lineage_commit_diff_and_drift(tmp_path: Path):
    store = PolicyLineageStore(tmp_path / "lineage")
    r1 = analyze_document(
        FIXTURES / "access_control_policy_v1.md",
        doc_id="pol-ac-001",
        store=store,
        version_label="v2.1",
        offline=True,
    )
    r2 = analyze_document(
        FIXTURES / "access_control_policy_v2.md",
        doc_id="pol-ac-001",
        store=store,
        version_label="v2.2",
        offline=True,
    )
    history = store.history("pol-ac-001")
    assert len(history) == 2
    assert history[0].snapshot_id == r2.snapshot_id

    diff = store.diff_statements("pol-ac-001", r1.snapshot_id, r2.snapshot_id)
    assert diff["added"] or diff["removed"]

    findings = store.detect_drift("pol-ac-001", r1.snapshot_id, r2.snapshot_id)
    assert isinstance(findings, list)


def test_analytics_and_oscal():
    report = analyze_document(
        FIXTURES / "access_control_policy_v1.md",
        doc_id="pol-ac-001",
        offline=True,
        commit=False,
    )
    matrix = coverage_matrix(report.statements)
    assert "NIST 800-53" in matrix
    radius = blast_radius(report.statements)
    assert radius
    suggestions = questionnaire_suggest(
        "Do you require MFA for privileged access to production?",
        report.statements,
    )
    assert suggestions
    stale = stale_framework_refs(s.statement for s in report.statements)
    assert any("2013" in f["issue"] or "CSF 1.1" in f["issue"] for f in stale)

    oscal = to_component_definition(
        component_title="Access Control Policy",
        mapped=report.statements,
        doc_id="pol-ac-001",
    )
    impl = oscal["component-definition"]["components"][0]["control-implementations"][0]
    assert impl["implemented-requirements"]
