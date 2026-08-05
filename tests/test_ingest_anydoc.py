"""Tests for Markdown, anydoc office, and PDF ingest routing."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock

import pytest

from grc_pdf_mapper.ingest import ingest_path, supported_suffixes
from grc_pdf_mapper.pipeline import analyze_document

FIXTURES = Path(__file__).parent / "fixtures"

anydoc = pytest.importorskip("anydoc")


def test_supported_suffixes_include_office_formats():
    suffixes = supported_suffixes()
    assert ".md" in suffixes
    assert ".docx" in suffixes
    assert ".xlsx" in suffixes
    assert ".csv" in suffixes
    assert ".rtf" in suffixes
    assert ".pdf" in suffixes


def test_ingest_csv_via_anydoc():
    result = ingest_path(FIXTURES / "control_matrix.csv")
    assert result.engine == "anydoc"
    assert result.detected_format == "csv"
    assert "AC-2" in result.markdown
    assert "MFA" in result.markdown


def test_ingest_rtf_via_anydoc():
    result = ingest_path(FIXTURES / "access_control_policy.rtf")
    assert result.engine == "anydoc"
    assert result.detected_format == "rtf"
    assert "MFA" in result.markdown
    assert "prohibited" in result.markdown.lower()


def test_ingest_docx_via_anydoc():
    result = ingest_path(FIXTURES / "access_control_policy.docx")
    assert result.engine == "anydoc"
    assert result.detected_format == "docx"
    assert "Access Control Policy" in result.markdown
    assert "MFA" in result.markdown


def test_analyze_docx_end_to_end(tmp_path: Path):
    report = analyze_document(
        FIXTURES / "access_control_policy.docx",
        doc_id="pol-ac-docx",
        store=None,
        offline=True,
        commit=False,
    )
    assert report.ingest.engine == "anydoc"
    assert len(report.statements) >= 2
    strengths = {row.statement.strength.value for row in report.statements}
    assert "must" in strengths or "shall" in strengths


def test_unsupported_suffix_lists_supported(tmp_path: Path):
    bad = tmp_path / "policy.png"
    bad.write_bytes(b"\x89PNG\r\n")
    with pytest.raises(ValueError, match="Unsupported file type"):
        ingest_path(bad)


def test_anydoc_missing_package_message(monkeypatch: pytest.MonkeyPatch, tmp_path: Path):
    import builtins

    real_import = builtins.__import__

    def fake_import(name, *args, **kwargs):
        if name == "anydoc" or name.startswith("anydoc."):
            raise ImportError("simulated missing anydoc")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", fake_import)
    docx = tmp_path / "sample.docx"
    docx.write_bytes((FIXTURES / "access_control_policy.docx").read_bytes())
    with pytest.raises(RuntimeError, match=r"\[anydoc\]"):
        ingest_path(docx)


def test_pdf_falls_back_to_anydoc_without_pdf_inspector(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
):
    """When pdf-inspector is absent, PDF ingest uses anydoc."""
    import builtins

    real_import = builtins.__import__

    def fake_import(name, *args, **kwargs):
        if name == "pdf_inspector" or name.startswith("pdf_inspector."):
            raise ImportError("simulated missing pdf-inspector")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", fake_import)

    # Minimal text PDF is hard; stub anydoc conversion for this unit path.
    fake = MagicMock()
    fake.format_from_bytes.return_value = "pdf"
    fake.format_from_extension.return_value = "pdf"
    fake.format_from_path.return_value = "pdf"
    fake.to_markdown_bytes.return_value = "# Policy\n\nMust enforce MFA.\n"
    fake.ConvertError = anydoc.ConvertError
    monkeypatch.setitem(__import__("sys").modules, "anydoc", fake)

    pdf = tmp_path / "policy.pdf"
    pdf.write_bytes(b"%PDF-1.4\n%\xe2\xe3\xcf\xd3\n1 0 obj<<>>endobj\ntrailer<<>>\n%%EOF\n")
    result = ingest_path(pdf)
    assert result.engine == "anydoc"
    assert result.detected_format == "pdf"
    assert "MFA" in result.markdown
