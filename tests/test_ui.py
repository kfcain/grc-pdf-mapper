"""Tests for the local upload GUI API."""

from __future__ import annotations

from pathlib import Path

import pytest

fastapi = pytest.importorskip("fastapi")
from fastapi.testclient import TestClient  # noqa: E402

from grc_pdf_mapper.ui.app import create_app

FIXTURES = Path(__file__).parent / "fixtures"


@pytest.fixture
def client() -> TestClient:
    return TestClient(create_app())


def test_health_and_formats(client: TestClient):
    health = client.get("/api/health")
    assert health.status_code == 200
    assert health.json()["status"] == "ok"

    formats = client.get("/api/formats")
    assert formats.status_code == 200
    suffixes = formats.json()["suffixes"]
    assert ".md" in suffixes
    assert ".docx" in suffixes


def test_index_served(client: TestClient):
    res = client.get("/")
    assert res.status_code == 200
    assert "GRC Mapper" in res.text
    assert "/assets/app.css" in res.text


def test_analyze_markdown_upload(client: TestClient):
    path = FIXTURES / "access_control_policy_v1.md"
    with path.open("rb") as handle:
        res = client.post(
            "/api/analyze",
            files={"file": (path.name, handle, "text/markdown")},
            data={"offline": "true"},
        )
    assert res.status_code == 200, res.text
    payload = res.json()
    assert payload["engine"] == "markdown"
    assert payload["statement_count"] >= 8
    assert payload["statements"]
    assert "must" in {row["strength"] for row in payload["statements"]} or "shall" in {
        row["strength"] for row in payload["statements"]
    }
    assert "AC-2" in payload["markdown"] or any(
        "AC-" in c["control_id"]
        for row in payload["statements"]
        for c in row["controls"]
    )


def test_analyze_rejects_bad_type(client: TestClient):
    res = client.post(
        "/api/analyze",
        files={"file": ("logo.png", b"\x89PNG\r\n", "image/png")},
        data={"offline": "true"},
    )
    assert res.status_code == 400
    assert "Unsupported" in res.json()["detail"]


def test_analyze_docx_upload(client: TestClient):
    pytest.importorskip("anydoc")
    path = FIXTURES / "access_control_policy.docx"
    with path.open("rb") as handle:
        res = client.post(
            "/api/analyze",
            files={
                "file": (
                    path.name,
                    handle,
                    "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
                )
            },
            data={"offline": "true"},
        )
    assert res.status_code == 200, res.text
    payload = res.json()
    assert payload["engine"] == "anydoc"
    assert payload["statement_count"] >= 2
