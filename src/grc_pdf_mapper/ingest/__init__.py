"""Document ingest via pdf-inspector (preferred) or Markdown files."""

from __future__ import annotations

import hashlib
from pathlib import Path

from grc_pdf_mapper.models import IngestResult


def _sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def ingest_path(path: str | Path) -> IngestResult:
    """Ingest a PDF or Markdown policy document into structured Markdown."""
    path = Path(path)
    if not path.exists():
        raise FileNotFoundError(path)

    suffix = path.suffix.lower()
    raw = path.read_bytes()
    source_hash = _sha256_bytes(raw)

    if suffix in {".md", ".markdown", ".txt"}:
        text = raw.decode("utf-8")
        return IngestResult(
            source_path=str(path),
            source_hash=source_hash,
            markdown=text,
            title=_first_heading(text),
            engine="markdown",
        )

    if suffix == ".pdf":
        return _ingest_pdf(path, raw, source_hash)

    raise ValueError(f"Unsupported file type: {suffix}")


def ingest_markdown(text: str, *, source_path: str = "<memory>") -> IngestResult:
    """Ingest Markdown already in memory (tests / git checkout)."""
    return IngestResult(
        source_path=source_path,
        source_hash=_sha256_text(text),
        markdown=text,
        title=_first_heading(text),
        engine="markdown",
    )


def _ingest_pdf(path: Path, raw: bytes, source_hash: str) -> IngestResult:
    try:
        import pdf_inspector  # type: ignore
    except ImportError as exc:  # pragma: no cover - optional dep
        raise RuntimeError(
            "PDF ingest needs the optional pdf-inspector package. "
            "From the repo root run: python3 -m pip install -e '.[pdf]'"
        ) from exc

    result = pdf_inspector.process_pdf_bytes(raw)
    markdown = result.markdown or ""
    if not markdown and result.pdf_type in {"scanned", "image_based", "mixed"}:
        markdown = (
            f"# OCR required\n\n"
            f"pdf-inspector classed this file as `{result.pdf_type}` "
            f"(confidence={result.confidence}). "
            f"Pages needing OCR: {result.pages_needing_ocr}.\n"
        )

    return IngestResult(
        source_path=str(path),
        source_hash=source_hash,
        markdown=markdown,
        pdf_type=result.pdf_type,
        confidence=result.confidence,
        page_count=result.page_count,
        pages_needing_ocr=list(result.pages_needing_ocr or []),
        title=result.title or _first_heading(markdown),
        engine="pdf-inspector",
    )


def _first_heading(text: str) -> str | None:
    for line in text.splitlines():
        stripped = line.strip()
        if stripped.startswith("#"):
            return stripped.lstrip("#").strip() or None
    return None
