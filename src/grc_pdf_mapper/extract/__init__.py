"""Extract control-related statements from policy Markdown."""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass

from grc_pdf_mapper.classifier_taxonomy import normalize_domains
from grc_pdf_mapper.models import ControlStatement, ObligationStrength, StatementKind

# Modal verbs and prohibition patterns common in GRC prose.
_OBLIGATION_RE = re.compile(
    r"\b(?P<verb>must never|shall never|should never|must not|shall not|should not|"
    r"may not|cannot|must|shall|"
    r"should|may|has to|have to|needs to|need to|is required(?: to)?|"
    r"are required(?: to)?|is prohibited|are prohibited|is not permitted|"
    r"are not permitted|will (?:ensure|maintain|review|monitor|perform|document|"
    r"retain|protect|implement|enforce)|is responsible for|are responsible for)\b",
    re.IGNORECASE,
)

_OBLIGATION_WAIVER_RE = re.compile(
    r"\b(?:do|does)\s+not\s+have\s+to\b|"
    r"\bneed\s+not\b|"
    r"\b(?:is|are)\s+(?:not\s+|no\s+longer\s+)required(?:\s+to)?\b",
    re.IGNORECASE,
)

_NON_NORMATIVE_MAY_RE = re.compile(
    r"\bmay\s+(?:result|cause|occur|indicate|include|also\s+include|be\s+caused|"
    r"be\s+due|vary|change|fail|expose|contain|become|lead\s+to)\b",
    re.IGNORECASE,
)

_NON_NORMATIVE_CANNOT_RE = re.compile(
    r"\bcannot\s+(?:support|determine|verify|connect|operate|function|"
    r"be\s+(?:available|supported|verified|determined|recovered))\b",
    re.IGNORECASE,
)

_NON_NORMATIVE_MAY_NOT_RE = re.compile(
    r"\bmay\s+not\s+(?:result|cause|occur|indicate|include|reflect|exist|"
    r"be\s+(?:available|possible|accurate|complete|applicable|supported|present|"
    r"reliable))\b",
    re.IGNORECASE,
)

_EPISTEMIC_SYSTEM_MAY_RE = re.compile(
    r"^\s*(?:the\s+)?(?:application|device|platform|service|software|system)\b"
    r"[^.!?]*\bmay\s+(?:generate|produce)\b",
    re.IGNORECASE,
)

_EPISTEMIC_SYSTEM_MAY_NOT_RE = re.compile(
    r"^\s*(?:the\s+)?(?:application|device|platform|service|software|system|vendor)\b"
    r"[^.!?]*\bmay\s+not\s+support\b",
    re.IGNORECASE,
)

_EPISTEMIC_SYSTEM_CANNOT_RE = re.compile(
    r"^\s*(?:the\s+)?(?:application|device|platform|service|software|system)\b"
    r"[^.!?]*\bcannot\s+encrypt\b",
    re.IGNORECASE,
)

_NEGATIVE_ACTIONS = {
    "block",
    "deny",
    "disable",
    "prevent",
    "prohibit",
    "reject",
    "revoke",
}

_ACTION_NORMALIZATION = {
    "allowed": "allow",
    "approved": "approve",
    "blocked": "block",
    "denied": "deny",
    "disabled": "disable",
    "enabled": "enable",
    "encrypted": "encrypt",
    "prevented": "prevent",
    "prohibited": "prohibit",
    "rejected": "reject",
    "retained": "retain",
    "revoked": "revoke",
}

_PAGE_MARKER_RE = re.compile(r"<!--\s*Page\s+(\d+)\s*-->", re.IGNORECASE)
_HEADING_RE = re.compile(r"^(#{1,6})\s+(.*)$")
# Negative lookbehind avoids document ids like POL-AC-001 matching as AC-001.
_CONTROL_ID_RE = re.compile(
    r"(?<![A-Za-z-])("
    r"(?:AC|AT|AU|CA|CM|CP|IA|IR|MA|MP|PE|PL|PM|PS|PT|RA|SA|SC|SI|SR)"
    r"-\d+(?:\(\d+\))?|"
    # SCF family-control ids (e.g. IAC-01, CRY-05.3, GOV-01)
    r"(?:AAT|AST|BCD|CAP|CFG|CHG|CLD|CPL|CRY|DCH|EMB|END|GOV|HRS|IAC|IAO|"
    r"IRO|MDM|MNT|MON|NET|OPS|PES|PRI|PRM|RSK|SAT|SEA|TDA|THR|TPM|VPM|WEB)"
    r"-\d+(?:\.\d+)?|"
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
    "access_control": (
        "access",
        "account",
        "authentication",
        "authorization",
        "identity",
        "mfa",
        "multi-factor",
        "password",
        "privileged",
        "role",
    ),
    "encryption": (
        "encrypt",
        "encryption",
        "cryptographic",
        "cryptography",
        "tls",
        "key management",
        "certificate",
        "secret",
    ),
    "logging": ("log", "logging", "audit trail", "monitoring", "siem", "telemetry"),
    "network_security": ("firewall", "network", "segmentation", "ingress", "egress", "boundary"),
    "vulnerability": ("vulnerability", "patch", "scan", "weakness", "remediation"),
    "asset": ("asset", "inventory", "device", "system component"),
    "data_protection": ("data protection", "data classification", "data retention", "data disposal"),
    "awareness": ("awareness", "training", "phishing exercise"),
    "physical": ("physical access", "facility", "visitor", "badge"),
    "secure_development": ("secure development", "code review", "software development", "sdlc"),
    "risk": ("risk assessment", "risk treatment", "risk register"),
    "governance": ("governance", "oversight", "policy approval", "management review"),
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


@dataclass
class _TextBlock:
    text: str
    start: int
    heading_path: list[str]
    page: int | None


def extract_control_statements(markdown: str, *, doc_slug: str = "doc") -> list[ControlStatement]:
    """Pull obligation sentences and explicit control ID citations from Markdown."""
    statements: list[ControlStatement] = []
    for block in _iter_text_blocks(markdown):
        for sentence in _split_sentences(block.text):
            for clause in _split_control_clauses(sentence):
                if not _is_control_candidate(clause):
                    continue
                local_start = max(0, block.text.find(clause))
                start = block.start + local_start
                end = start + len(clause)
                keywords = _match_keywords(clause + " " + " ".join(block.heading_path))
                framework_ids = [
                    m.group(1).upper().replace(" ", "")
                    for m in _CONTROL_ID_RE.finditer(clause)
                ]
                kind, strength, confidence, reasons = _classify_statement(
                    clause,
                    framework_ids=framework_ids,
                )
                if keywords:
                    reasons.append("security domains: " + ", ".join(keywords))
                    confidence = max(confidence, 0.78)
                hash_material = "\n".join([*block.heading_path, clause]).encode("utf-8")
                content_hash = hashlib.sha256(hash_material).hexdigest()[:16]
                statement_id = f"{doc_slug}:{content_hash}"
                statements.append(
                    ControlStatement(
                        statement_id=statement_id,
                        text=clause.strip(),
                        heading_path=list(block.heading_path),
                        page=block.page,
                        strength=strength,
                        statement_kind=kind,
                        action_polarity=_action_polarity(clause),
                        keywords=keywords,
                        candidate_framework_ids=sorted(set(framework_ids)),
                        classification_confidence=round(min(confidence, 0.99), 2),
                        classification_status=(
                            "classified" if confidence >= 0.85 else "review_required"
                        ),
                        classification_reasons=list(dict.fromkeys(reasons)),
                        source_span=(start, end),
                        content_hash=content_hash,
                    )
                )

    return _dedupe(statements)


def _iter_text_blocks(markdown: str) -> list[_TextBlock]:
    """Join wrapped prose and list items while preserving document context."""
    blocks: list[_TextBlock] = []
    ctx = _Context(heading_path=[], page=None)
    buffer: list[str] = []
    buffer_start = 0
    buffer_heading: list[str] = []
    buffer_page: int | None = None
    offset = 0
    in_fence = False
    table_body = False
    pending_table_header = False
    active_list_lead: tuple[str, int] | None = None

    def flush() -> None:
        nonlocal buffer
        text = " ".join(part.strip() for part in buffer if part.strip()).strip()
        if text:
            blocks.append(
                _TextBlock(
                    text=text,
                    start=buffer_start,
                    heading_path=list(buffer_heading),
                    page=buffer_page,
                )
            )
        buffer = []

    def start_buffer(text: str, start: int) -> None:
        nonlocal buffer_start, buffer_heading, buffer_page
        buffer_start = start
        buffer_heading = list(ctx.heading_path)
        buffer_page = ctx.page
        buffer.append(text)

    for raw_line in markdown.splitlines(keepends=True):
        line = raw_line.rstrip("\r\n")
        stripped = line.strip()

        if stripped.startswith("```"):
            flush()
            active_list_lead = None
            table_body = False
            pending_table_header = False
            in_fence = not in_fence
            offset += len(raw_line)
            continue
        if in_fence:
            offset += len(raw_line)
            continue

        page_match = _PAGE_MARKER_RE.search(line)
        if page_match:
            flush()
            active_list_lead = None
            table_body = False
            pending_table_header = False
            ctx.page = int(page_match.group(1))
            offset += len(raw_line)
            continue

        heading_match = _HEADING_RE.match(line)
        if heading_match:
            flush()
            active_list_lead = None
            table_body = False
            pending_table_header = False
            level = len(heading_match.group(1))
            title = heading_match.group(2).strip()
            ctx.heading_path = ctx.heading_path[: level - 1] + [title]
            offset += len(raw_line)
            continue

        if not stripped:
            current = " ".join(part.strip() for part in buffer if part.strip()).strip()
            if current.endswith(":") and _has_normative_modal(current):
                active_list_lead = (current[:-1].strip(), buffer_start)
                buffer = []
            elif buffer:
                flush()
                active_list_lead = None
            table_body = False
            pending_table_header = False
            offset += len(raw_line)
            continue

        if stripped.startswith("|") and stripped.endswith("|"):
            flush()
            active_list_lead = None
            cells = [
                re.sub(r"<br\s*/?>", "; ", cell.strip(), flags=re.IGNORECASE)
                for cell in stripped.strip("|").split("|")
            ]
            if cells and all(re.fullmatch(r":?-{3,}:?", cell) for cell in cells):
                table_body = True
                pending_table_header = False
                offset += len(raw_line)
                continue
            if not table_body:
                # A standard Markdown table puts its header before the separator.
                pending_table_header = True
                offset += len(raw_line)
                continue
            row_text = " | ".join(cell for cell in cells if cell).strip()
            if row_text:
                first_cell = next((cell for cell in cells if cell), "")
                cell_index = line.find(first_cell) if first_cell else 0
                blocks.append(
                    _TextBlock(
                        text=row_text,
                        start=offset + max(0, cell_index),
                        heading_path=list(ctx.heading_path),
                        page=ctx.page,
                    )
                )
            offset += len(raw_line)
            continue

        table_body = False
        pending_table_header = False

        bullet_match = re.match(r"^\s*(?:[-*+] |\d+[.)]\s+)(?P<text>.+)$", line)
        if bullet_match:
            current = " ".join(part.strip() for part in buffer if part.strip()).strip()
            if current.endswith(":") and _has_normative_modal(current):
                active_list_lead = (current[:-1].strip(), buffer_start)
                buffer = []
            else:
                flush()
            text = bullet_match.group("text").strip()
            if active_list_lead and not _has_normative_modal(text):
                lead, lead_start = active_list_lead
                start_buffer(f"{lead} {text}", lead_start)
            else:
                start_buffer(text, offset + line.find(text))
        elif not buffer:
            active_list_lead = None
            start_buffer(stripped, offset + line.find(stripped))
        else:
            buffer.append(stripped)
        offset += len(raw_line)

    flush()
    return blocks


def _split_sentences(text: str) -> list[str]:
    text = text.strip()
    if not text:
        return []
    parts = re.split(r"(?<=[.!?])\s+(?=[A-Z0-9(\"'])", text)
    return [part.strip() for part in parts if len(part.strip()) >= 12]


def _split_control_clauses(sentence: str) -> list[str]:
    """Split independent modal clauses without splitting shared-action lists."""
    sentence = re.sub(r"<br\s*/?>", "; ", sentence, flags=re.IGNORECASE)

    if " | " in sentence:
        table_cells = [cell.strip() for cell in sentence.split(" | ") if cell.strip()]
        normative_cells = [cell for cell in table_cells if _has_normative_modal(cell)]
        if len(normative_cells) > 1:
            return [
                clause
                for cell in normative_cells
                for clause in _split_control_clauses(cell)
            ]

    coarse = re.split(r"\s*;\s*|\s*,\s*(?:but|and)\s+", sentence)
    clauses: list[str] = []
    inherited_prefix = ""
    for part in coarse:
        part = part.strip()
        if not part:
            continue
        independent = _split_modal_conjunctions(part)
        for clause in independent:
            if not _has_normative_modal(clause) and inherited_prefix:
                clause = f"{inherited_prefix} {clause}".strip()
            prefix = _shared_modal_prefix(clause)
            if prefix:
                inherited_prefix = prefix
            clauses.append(clause)
    return clauses


def _split_modal_conjunctions(text: str) -> list[str]:
    """Recursively split conjunctions when each side has its own modal."""
    for conjunction in re.finditer(r"\s+(?:and|but)\s+", text, re.IGNORECASE):
        left = text[: conjunction.start()].strip()
        right = text[conjunction.end() :].strip()
        if _has_normative_modal(left) and _has_normative_modal(right):
            return _split_modal_conjunctions(left) + _split_modal_conjunctions(right)
    return [text.strip()]


def _shared_modal_prefix(text: str) -> str:
    """Return the subject and modal that a following action can inherit."""
    matches = _normative_obligation_matches(text)
    if not matches:
        return ""
    match = matches[0]
    prefix = text[: match.end()].strip()
    tail = text[match.end() :]
    if re.match(r"\s+be\b", tail, re.IGNORECASE):
        prefix += " be"
    return prefix


def _normative_obligation_matches(sentence: str) -> list[re.Match[str]]:
    matches: list[re.Match[str]] = []
    for match in _OBLIGATION_RE.finditer(sentence):
        verb = match.group("verb").lower()
        tail = sentence[match.start() :]
        if verb == "may" and (
            _NON_NORMATIVE_MAY_RE.match(tail)
            or _EPISTEMIC_SYSTEM_MAY_RE.search(sentence)
        ):
            continue
        if verb == "may not" and (
            _NON_NORMATIVE_MAY_NOT_RE.match(tail)
            or _EPISTEMIC_SYSTEM_MAY_NOT_RE.search(sentence)
        ):
            continue
        if verb == "cannot" and (
            _NON_NORMATIVE_CANNOT_RE.match(tail)
            or _EPISTEMIC_SYSTEM_CANNOT_RE.search(sentence)
        ):
            continue
        matches.append(match)
    return matches


def _has_normative_modal(sentence: str) -> bool:
    return bool(_OBLIGATION_WAIVER_RE.search(sentence) or _normative_obligation_matches(sentence))


def _is_control_candidate(sentence: str) -> bool:
    lowered = sentence.lower().strip()
    # Skip metadata / document-id lines that are not obligations.
    if lowered.startswith(("document id", "**document id", "version:", "approved by:")):
        return False
    if lowered.endswith("?"):
        return False
    if _OBLIGATION_WAIVER_RE.search(sentence):
        return True
    normative_matches = _normative_obligation_matches(sentence)
    if normative_matches:
        return True
    if _OBLIGATION_RE.search(sentence):
        # The sentence contains only an epistemic or ability modal that was
        # filtered above. Do not recover it as a descriptive control rule.
        return bool(_CONTROL_ID_RE.search(sentence))
    if _CONTROL_ID_RE.search(sentence):
        return True
    controlish = ("control", "procedure", "standard", "requirement", "safeguard")
    return any(k in lowered for k in controlish) and any(
        any(_contains_token(lowered, token) for token in tokens)
        for tokens in _DOMAIN_KEYWORDS.values()
    )


def _classify_strength(sentence: str) -> ObligationStrength:
    return _classify_statement(sentence, framework_ids=[])[1]


def _classify_statement(
    sentence: str,
    *,
    framework_ids: list[str],
) -> tuple[StatementKind, ObligationStrength, float, list[str]]:
    lowered = sentence.lower()
    if _OBLIGATION_WAIVER_RE.search(lowered):
        return (
            StatementKind.PERMISSION,
            ObligationStrength.MAY,
            0.96,
            ["explicit obligation waiver"],
        )
    verbs = {
        match.group("verb").lower()
        for match in _normative_obligation_matches(sentence)
    }
    if verbs.intersection(
        {
            "must never",
            "shall never",
            "must not",
            "shall not",
            "may not",
            "cannot",
            "is prohibited",
            "are prohibited",
            "is not permitted",
            "are not permitted",
        }
    ):
        return (
            StatementKind.PROHIBITION,
            ObligationStrength.PROHIBITED,
            0.98,
            ["explicit prohibition language"],
        )
    if "shall" in verbs:
        return (
            StatementKind.OBLIGATION,
            ObligationStrength.SHALL,
            0.97,
            ["explicit SHALL obligation"],
        )
    if verbs.intersection(
        {
            "must",
            "has to",
            "have to",
            "needs to",
            "need to",
            "is required",
            "is required to",
            "are required",
            "are required to",
            "will ensure",
            "will maintain",
            "will review",
            "will monitor",
            "will perform",
            "will document",
            "will retain",
            "will protect",
            "will implement",
            "will enforce",
        }
    ):
        return (
            StatementKind.OBLIGATION,
            ObligationStrength.MUST,
            0.96,
            ["explicit mandatory obligation"],
        )
    if verbs.intersection({"is responsible for", "are responsible for"}):
        return (
            StatementKind.RESPONSIBILITY,
            ObligationStrength.MUST,
            0.9,
            ["explicit responsibility assignment"],
        )
    if verbs.intersection({"should", "should not", "should never"}):
        return (
            StatementKind.RECOMMENDATION,
            ObligationStrength.SHOULD,
            0.9,
            [
                "explicit negative SHOULD recommendation"
                if verbs.intersection({"should not", "should never"})
                else "explicit SHOULD recommendation"
            ],
        )
    if "may" in verbs:
        return (
            StatementKind.PERMISSION,
            ObligationStrength.MAY,
            0.78,
            ["permission language; MAY can be context-sensitive"],
        )
    if framework_ids:
        return (
            StatementKind.CITATION,
            ObligationStrength.DESCRIPTIVE,
            0.84,
            ["explicit framework control citation"],
        )
    return (
        StatementKind.CONTROL_DESCRIPTION,
        ObligationStrength.DESCRIPTIVE,
        0.66,
        ["control-related descriptive language"],
    )


def _action_polarity(sentence: str) -> str:
    matches = _normative_obligation_matches(sentence)
    if not matches:
        return "positive"
    verb = matches[0].group("verb").lower()
    if (
        " not" in verb
        or "never" in verb
        or verb == "cannot"
        or "prohibited" in verb
        or "not permitted" in verb
    ):
        return "negative"
    action = _main_action_after_match(sentence, matches[0])
    if action in _NEGATIVE_ACTIONS:
        return "negative"
    return "positive"


def _main_action_after_match(sentence: str, match: re.Match[str]) -> str:
    tail = sentence[match.end() :]
    action_match = re.match(
        r"\s+(?:not\s+|never\s+)?(?:be\s+)?(?P<action>[a-z]+)",
        tail,
        re.IGNORECASE,
    )
    if not action_match:
        return ""
    return _normalize_action(action_match.group("action"))


def _normalize_action(action: str) -> str:
    return _ACTION_NORMALIZATION.get(action.lower(), action.lower())


def _match_keywords(sentence: str) -> list[str]:
    lowered = sentence.lower()
    hits: list[str] = []
    for domain, tokens in _DOMAIN_KEYWORDS.items():
        if any(_contains_token(lowered, token) for token in tokens):
            hits.append(domain)
    return normalize_domains(hits, strict=True)


def _contains_token(text: str, token: str) -> bool:
    if " " in token or "-" in token:
        return token in text
    return bool(re.search(rf"\b{re.escape(token)}(?:s|ed|ing)?\b", text))


def _dedupe(statements: list[ControlStatement]) -> list[ControlStatement]:
    seen: set[str] = set()
    out: list[ControlStatement] = []
    for stmt in statements:
        if stmt.content_hash in seen:
            continue
        seen.add(stmt.content_hash)
        out.append(stmt)
    return out
