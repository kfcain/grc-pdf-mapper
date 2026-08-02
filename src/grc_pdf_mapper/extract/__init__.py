"""Extract control-related statements from policy Markdown."""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass

from grc_pdf_mapper.models import ControlStatement, ObligationStrength

# Modal verbs and prohibition patterns common in GRC prose.
_OBLIGATION_RE = re.compile(
    r"\b(?P<verb>must not|shall not|may not|must|shall|should|may|is required to|"
    r"are required to|is prohibited|are prohibited|will ensure|is responsible for)\b",
    re.IGNORECASE,
)

_PAGE_MARKER_RE = re.compile(r"<!--\s*Page\s+(\d+)\s*-->", re.IGNORECASE)
_HEADING_RE = re.compile(r"^(#{1,6})\s+(.*)$")
# Negative lookbehind avoids document ids like POL-AC-001 matching as AC-001.
_CONTROL_ID_RE = re.compile(
    r"(?<![A-Za-z-])("
    r"(?:AC|AT|AU|CA|CM|CP|IA|IR|MA|MP|PE|PL|PM|PS|PT|RA|SA|SC|SI|SR)"
    r"-\d+(?:\(\d+\))?|"
    r"A\.?\d+(?:\.\d+)+|"
    r"CC\d+\.\d+|"
    r"PR\.(?:AA|AT|CM|DS|IP|PT)-\d+|"
    r"GV\.(?:OC|RM|RR|PO|OV)-\d+|"
    r"ID\.(?:AM|RA|IM)-\d+|"
    r"DE\.(?:CM|AE)-\d+|"
    r"RS\.(?:MA|AN|CO|MI)-\d+|"
    r"RC\.(?:RP|CO)-\d+|"
    r"CIS\s*\d+(?:\.\d+)?|"
    r"Req\.?\s*\d+(?:\.\d+)*"
    r")\b",
    re.IGNORECASE,
)

_DOMAIN_KEYWORDS: dict[str, tuple[str, ...]] = {
    "access_control": ("access", "authentication", "authorization", "mfa", "privileged", "role"),
    "encryption": ("encrypt", "cryptograph", "tls", "key management", "certificate"),
    "logging": ("log", "audit trail", "monitoring", "siem"),
    "incident": ("incident", "breach", "response", "forensic"),
    "vendor": ("vendor", "third party", "supplier", "processor"),
    "privacy": ("personal data", "pii", "privacy", "gdpr", "data subject"),
    "backup": ("backup", "recovery", "continuity", "disaster"),
    "change": ("change management", "configuration", "baseline"),
}


@dataclass
class _Context:
    heading_path: list[str]
    page: int | None


def extract_control_statements(markdown: str, *, doc_slug: str = "doc") -> list[ControlStatement]:
    """Pull obligation sentences and explicit control ID citations from Markdown."""
    statements: list[ControlStatement] = []
    ctx = _Context(heading_path=[], page=None)
    offset = 0

    for raw_line in markdown.splitlines(keepends=True):
        line = raw_line.rstrip("\n")
        page_match = _PAGE_MARKER_RE.search(line)
        if page_match:
            ctx.page = int(page_match.group(1))
            offset += len(raw_line)
            continue

        heading_match = _HEADING_RE.match(line)
        if heading_match:
            level = len(heading_match.group(1))
            title = heading_match.group(2).strip()
            ctx.heading_path = ctx.heading_path[: level - 1] + [title]
            offset += len(raw_line)
            continue

        # Split on sentence boundaries while keeping control-dense lists intact.
        for sentence in _split_sentences(line):
            if not _is_control_candidate(sentence):
                continue
            start = offset + line.find(sentence)
            end = start + len(sentence)
            strength = _classify_strength(sentence)
            keywords = _match_keywords(sentence + " " + " ".join(ctx.heading_path))
            framework_ids = [
                m.group(1).upper().replace(" ", "") for m in _CONTROL_ID_RE.finditer(sentence)
            ]
            content_hash = hashlib.sha256(sentence.encode("utf-8")).hexdigest()[:16]
            statement_id = f"{doc_slug}:{content_hash}"
            statements.append(
                ControlStatement(
                    statement_id=statement_id,
                    text=sentence.strip(),
                    heading_path=list(ctx.heading_path),
                    page=ctx.page,
                    strength=strength,
                    keywords=keywords,
                    candidate_framework_ids=sorted(set(framework_ids)),
                    source_span=(start, end),
                    content_hash=content_hash,
                )
            )
        offset += len(raw_line)

    return _dedupe(statements)


def _split_sentences(line: str) -> list[str]:
    line = line.strip()
    if not line or line.startswith("|") or line.startswith("```"):
        return []
    # Keep bullet text.
    if line.startswith(("-", "*", "+")):
        line = line.lstrip("-*+ ").strip()
    parts = re.split(r"(?<=[.!?])\s+(?=[A-Z(\"'])", line)
    return [p.strip() for p in parts if len(p.strip()) > 20]


def _is_control_candidate(sentence: str) -> bool:
    if _OBLIGATION_RE.search(sentence):
        return True
    if _CONTROL_ID_RE.search(sentence):
        return True
    lowered = sentence.lower()
    # Skip metadata / document-id lines that are not obligations.
    if lowered.startswith("document id") or lowered.startswith("**document id"):
        return False
    controlish = ("control", "procedure", "standard", "requirement", "safeguard")
    return any(k in lowered for k in controlish) and any(
        any(token in lowered for token in tokens) for tokens in _DOMAIN_KEYWORDS.values()
    )


def _classify_strength(sentence: str) -> ObligationStrength:
    lowered = sentence.lower()
    if re.search(r"\b(must not|shall not|may not|is prohibited|are prohibited)\b", lowered):
        return ObligationStrength.PROHIBITED
    if re.search(r"\b(must|shall|is required to|are required to|will ensure)\b", lowered):
        return ObligationStrength.MUST
    if re.search(r"\bshould\b", lowered):
        return ObligationStrength.SHOULD
    if re.search(r"\bmay\b", lowered):
        return ObligationStrength.MAY
    return ObligationStrength.DESCRIPTIVE


def _match_keywords(sentence: str) -> list[str]:
    lowered = sentence.lower()
    hits: list[str] = []
    for domain, tokens in _DOMAIN_KEYWORDS.items():
        if any(token in lowered for token in tokens):
            hits.append(domain)
    return hits


def _dedupe(statements: list[ControlStatement]) -> list[ControlStatement]:
    seen: set[str] = set()
    out: list[ControlStatement] = []
    for stmt in statements:
        if stmt.content_hash in seen:
            continue
        seen.add(stmt.content_hash)
        out.append(stmt)
    return out
