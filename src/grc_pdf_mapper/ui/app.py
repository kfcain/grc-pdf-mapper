"""FastAPI app: local upload → analyze → JSON results."""

from __future__ import annotations

import tempfile
from pathlib import Path
from typing import Any

from fastapi import FastAPI, File, Form, HTTPException, UploadFile
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from grc_pdf_mapper.ingest import supported_suffixes
from grc_pdf_mapper.pipeline import analyze_document

STATIC_DIR = Path(__file__).resolve().parent / "static"
MAX_UPLOAD_BYTES = 40 * 1024 * 1024


def create_app() -> FastAPI:
    app = FastAPI(title="GRC Mapper", docs_url=None, redoc_url=None)

    @app.get("/api/health")
    def health() -> dict[str, str]:
        return {"status": "ok"}

    @app.get("/api/formats")
    def formats() -> dict[str, list[str]]:
        return {"suffixes": sorted(supported_suffixes())}

    @app.post("/api/analyze")
    async def analyze(
        file: UploadFile = File(...),
        offline: bool = Form(True),
        doc_id: str | None = Form(None),
    ) -> dict[str, Any]:
        name = file.filename or "upload.bin"
        suffix = Path(name).suffix.lower()
        if suffix not in supported_suffixes():
            raise HTTPException(
                status_code=400,
                detail=(
                    f"Unsupported file type: {suffix or '(none)'}. "
                    f"Supported: {', '.join(sorted(supported_suffixes()))}"
                ),
            )

        raw = await file.read()
        if not raw:
            raise HTTPException(status_code=400, detail="The uploaded file is empty.")
        if len(raw) > MAX_UPLOAD_BYTES:
            raise HTTPException(
                status_code=400,
                detail=f"File exceeds the {MAX_UPLOAD_BYTES // (1024 * 1024)} MB limit.",
            )

        with tempfile.TemporaryDirectory(prefix="grc-ui-") as tmp:
            path = Path(tmp) / Path(name).name
            path.write_bytes(raw)
            try:
                report = analyze_document(
                    path,
                    doc_id=doc_id or None,
                    store=None,
                    offline=offline,
                    commit=False,
                    alert_on_change=False,
                )
            except RuntimeError as exc:
                raise HTTPException(status_code=422, detail=str(exc)) from exc
            except ValueError as exc:
                raise HTTPException(status_code=400, detail=str(exc)) from exc
            except Exception as exc:  # pragma: no cover - unexpected converter failure
                raise HTTPException(
                    status_code=500,
                    detail=f"Parse failed: {exc}",
                ) from exc

        return _ui_payload(report.model_dump(mode="json"), original_name=name)

    if STATIC_DIR.is_dir():
        app.mount("/assets", StaticFiles(directory=STATIC_DIR), name="assets")

        @app.get("/")
        def index() -> FileResponse:
            return FileResponse(STATIC_DIR / "index.html")

    return app


def _ui_payload(report: dict[str, Any], *, original_name: str) -> dict[str, Any]:
    """Shape the report for the GUI without dropping the full dump."""
    ingest = report.get("ingest") or {}
    statements = report.get("statements") or []
    rows = []
    for mapped in statements:
        stmt = mapped.get("statement") or {}
        hits = mapped.get("mappings") or []
        rows.append(
            {
                "statement_id": stmt.get("statement_id"),
                "strength": stmt.get("strength"),
                "text": stmt.get("text"),
                "heading_path": stmt.get("heading_path") or [],
                "keywords": stmt.get("keywords") or [],
                "controls": [
                    {
                        "framework": h.get("framework"),
                        "control_id": h.get("control_id"),
                        "title": h.get("title") or "",
                        "source": h.get("source"),
                        "confidence": h.get("confidence"),
                    }
                    for h in hits[:8]
                ],
            }
        )

    markdown = ingest.get("markdown") or ""
    return {
        "original_name": original_name,
        "doc_id": report.get("doc_id"),
        "engine": ingest.get("engine"),
        "detected_format": ingest.get("detected_format"),
        "title": ingest.get("title"),
        "statement_count": len(rows),
        "frameworks_covered": report.get("frameworks_covered") or [],
        "gaps": report.get("gaps") or [],
        "statements": rows,
        "markdown": markdown,
        "markdown_preview": markdown[:12_000],
        "report": report,
    }


def run_ui(*, host: str = "127.0.0.1", port: int = 8765, open_browser: bool = True) -> None:
    """Start the local UI server (blocking)."""
    try:
        import uvicorn
    except ImportError as exc:  # pragma: no cover
        raise RuntimeError(
            "The local UI needs uvicorn. From the repo root run: "
            "python3 -m pip install -e '.[ui]'"
        ) from exc

    if open_browser:
        import threading
        import webbrowser

        def _open() -> None:
            webbrowser.open(f"http://{host}:{port}/")

        threading.Timer(0.8, _open).start()

    uvicorn.run(create_app(), host=host, port=port, log_level="info")
