"""Document ingest via Markdown, pdf-inspector, or Firecrawl anydoc."""

from __future__ import annotations

import hashlib
from pathlib import Path

from grc_pdf_mapper.models import IngestResult

# Plain-text formats handled without optional converters.
_MARKDOWN_SUFFIXES = {".md", ".markdown", ".txt"}

# Office and related formats converted by firecrawl-anydoc.
# PDF is listed here as a fallback when pdf-inspector is not installed.
_ANYDOC_SUFFIXES = {
    ".doc",
    ".docx",
    ".docm",
    ".ppt",
    ".pps",
    ".pot",
    ".pptx",
    ".pptm",
    ".ppsx",
    ".ppsm",
    ".xls",
    ".xlsx",
    ".xlsm",
    ".xlsb",
    ".odt",
    ".ods",
    ".odp",
    ".rtf",
    ".epub",
    ".csv",
    ".pdf",
}

# Formats that need an explicit anydoc format name (no byte signature).
_EXPLICIT_FORMAT_BY_SUFFIX = {
    ".csv": "csv",
}


def _sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def supported_suffixes() -> frozenset[str]:
    """Return every file suffix this ingest layer can accept."""
    return frozenset(_MARKDOWN_SUFFIXES | _ANYDOC_SUFFIXES)


def ingest_path(path: str | Path) -> IngestResult:
    """Ingest a policy document into structured Markdown.

    Route by suffix:
    - Markdown / plain text → native decode
    - PDF → pdf-inspector when installed (keeps class / OCR metadata),
      else anydoc
    - Word / PowerPoint / Excel / OpenDocument / RTF / EPUB / CSV → anydoc
    """
    path = Path(path)
    if not path.exists():
        raise FileNotFoundError(path)

    suffix = path.suffix.lower()
    raw = path.read_bytes()
    source_hash = _sha256_bytes(raw)

    if suffix in _MARKDOWN_SUFFIXES:
        text = raw.decode("utf-8")
        return IngestResult(
            source_path=str(path),
            source_hash=source_hash,
            markdown=text,
            title=_first_heading(text),
            engine="markdown",
            detected_format="markdown",
        )

    if suffix == ".pdf":
        return _ingest_pdf(path, raw, source_hash)

    if suffix in _ANYDOC_SUFFIXES:
        return _ingest_anydoc(path, raw, source_hash, suffix)

    raise ValueError(
        f"Unsupported file type: {suffix}. "
        f"Supported: {', '.join(sorted(supported_suffixes()))}"
    )


def ingest_markdown(text: str, *, source_path: str = "<memory>") -> IngestResult:
    """Ingest Markdown already in memory (tests / git checkout)."""
    return IngestResult(
        source_path=source_path,
        source_hash=_sha256_text(text),
        markdown=text,
        title=_first_heading(text),
        engine="markdown",
        detected_format="markdown",
    )


def _ingest_pdf(path: Path, raw: bytes, source_hash: str) -> IngestResult:
    try:
        import pdf_inspector  # type: ignore
    except ImportError:
        return _ingest_anydoc(path, raw, source_hash, ".pdf")

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
        detected_format="pdf",
    )


def _ingest_anydoc(
    path: Path,
    raw: bytes,
    source_hash: str,
    suffix: str,
) -> IngestResult:
    try:
        import anydoc
    except ImportError as exc:  # pragma: no cover - optional dep
        raise RuntimeError(
            "Office and PDF fallback ingest needs the optional firecrawl-anydoc "
            "package. From the repo root run: python3 -m pip install -e '.[anydoc]'"
        ) from exc

    format_hint = _EXPLICIT_FORMAT_BY_SUFFIX.get(suffix)
    detected = anydoc.format_from_bytes(raw)
    if detected is None:
        detected = anydoc.format_from_extension(suffix) or anydoc.format_from_path(
            str(path)
        )

    explicit = format_hint or detected
    try:
        if explicit:
            markdown = anydoc.to_markdown_bytes(raw, explicit)
        else:
            markdown = anydoc.to_markdown_bytes(raw)
    except anydoc.ConvertError as exc:
        raise RuntimeError(f"anydoc failed to convert {path}: {exc}") from exc

    return IngestResult(
        source_path=str(path),
        source_hash=source_hash,
        markdown=markdown,
        title=_first_heading(markdown),
        engine="anydoc",
        detected_format=str(explicit or suffix.lstrip(".")),
    )


def _first_heading(text: str) -> str | None:
    for line in text.splitlines():
        stripped = line.strip()
        if stripped.startswith("#"):
            return stripped.lstrip("#").strip() or None
    return None
