"""Tests for SCF API crosswalk integration."""

from __future__ import annotations

from pathlib import Path

from grc_pdf_mapper.crosswalk import CrosswalkClient
from grc_pdf_mapper.extract import extract_control_statements
from grc_pdf_mapper.models import ControlStatement, ObligationStrength
from grc_pdf_mapper.scf import (
    ScfClient,
    normalize_nist_id,
    is_scf_control_id,
)

FIXTURES = Path(__file__).parent / "fixtures"


def test_normalize_nist_id_zero_pads():
    assert normalize_nist_id("AC-2") == "AC-02"
    assert normalize_nist_id("ia-2") == "IA-02"
    assert normalize_nist_id("AC-02(1)") == "AC-02(1)"


def test_is_scf_control_id():
    assert is_scf_control_id("IAC-01")
    assert is_scf_control_id("CRY-05.3")
    assert not is_scf_control_id("AC-2")


def test_offline_scf_maps_nist_citation():
    stmt = ControlStatement(
        statement_id="t1",
        text="Privileged users must use MFA (AC-2).",
        strength=ObligationStrength.MUST,
        keywords=["access_control"],
        candidate_framework_ids=["AC-2"],
        content_hash="x",
    )
    with ScfClient(offline=True) as scf:
        hits = scf.map_statement(stmt)
    assert hits
    sources = {h.source for h in hits}
    assert "scf-api" in sources
    frameworks = {h.framework for h in hits}
    assert "SCF" in frameworks
    # Fan-out should include at least one non-SCF target.
    assert frameworks - {"SCF"}


def test_offline_scf_domain_fallback():
    stmt = ControlStatement(
        statement_id="t2",
        text="Encrypt data at rest.",
        strength=ObligationStrength.MUST,
        keywords=["encryption"],
        candidate_framework_ids=[],
        content_hash="y",
    )
    with ScfClient(offline=True) as scf:
        hits = scf.map_statement(stmt)
    assert any(h.framework == "SCF" and h.control_id.startswith("CRY") for h in hits)


def test_crosswalk_client_includes_scf_offline():
    markdown = (FIXTURES / "access_control_policy_v1.md").read_text(encoding="utf-8")
    statements = extract_control_statements(markdown, doc_slug="pol-ac")
    with CrosswalkClient(offline=True) as client:
        hits = client.map_statement(statements[0])
    assert any(h.source == "scf-api" for h in hits)
    assert any(h.framework == "SCF" for h in hits)


def test_extract_recognizes_scf_ids():
    markdown = "# Policy\n\nThe system shall enforce IAC-01 and CRY-05 for access and crypto.\n"
    statements = extract_control_statements(markdown, doc_slug="pol-scf")
    cited = {cid for s in statements for cid in s.candidate_framework_ids}
    assert "IAC-01" in cited or "IAC-1" in cited or any(c.startswith("IAC-") for c in cited)
    assert any(c.startswith("CRY-") for c in cited)
