"""Creative GRC analytics on top of extracted + mapped controls."""

from __future__ import annotations

from collections import defaultdict
from typing import Iterable

from grc_pdf_mapper.models import (
    BlastRadiusItem,
    ControlStatement,
    CrosswalkHit,
    MappedStatement,
)


def blast_radius(
    mapped: Iterable[MappedStatement],
    *,
    statement_ids: set[str] | None = None,
) -> list[BlastRadiusItem]:
    """
    When a policy clause changes, show every framework control that clause supports.

    Useful for change-impact analysis before a policy rewrite.
    """
    items: list[BlastRadiusItem] = []
    for row in mapped:
        if statement_ids and row.statement.statement_id not in statement_ids:
            continue
        for hit in row.mappings:
            items.append(
                BlastRadiusItem(
                    framework=hit.framework,
                    control_id=hit.control_id,
                    title=hit.title,
                    via_statement_id=row.statement.statement_id,
                    source=hit.source,
                )
            )
    # Prefer higher-confidence / explicit sources first by stable sort key.
    return sorted(items, key=lambda i: (i.framework, i.control_id, i.via_statement_id))


def coverage_matrix(mapped: Iterable[MappedStatement]) -> dict[str, list[str]]:
    """framework -> sorted unique control ids covered by this document."""
    matrix: dict[str, set[str]] = defaultdict(set)
    for row in mapped:
        for hit in row.mappings:
            matrix[hit.framework].add(hit.control_id)
    return {fw: sorted(ids) for fw, ids in sorted(matrix.items())}


def questionnaire_suggest(
    question: str,
    mapped: Iterable[MappedStatement],
    *,
    limit: int = 5,
) -> list[dict]:
    """
    Suggest policy excerpts that can answer a security questionnaire item.

    This is retrieval over obligation text + keywords — not generative answers.
    """
    tokens = {t.lower() for t in _tokenize(question) if len(t) > 2}
    scored: list[tuple[float, MappedStatement]] = []
    for row in mapped:
        hay = " ".join(
            [
                row.statement.text.lower(),
                " ".join(row.statement.keywords),
                " ".join(row.statement.heading_path).lower(),
                " ".join(h.control_id.lower() for h in row.mappings),
                " ".join(h.title.lower() for h in row.mappings),
            ]
        )
        overlap = sum(1 for t in tokens if t in hay)
        if overlap == 0:
            continue
        strength_bonus = {
            "must": 0.4,
            "shall": 0.4,
            "prohibited": 0.35,
            "should": 0.2,
            "may": 0.05,
            "descriptive": 0.0,
        }[row.statement.strength.value]
        score = overlap + strength_bonus + min(0.5, 0.05 * len(row.mappings))
        scored.append((score, row))
    scored.sort(key=lambda x: x[0], reverse=True)
    results: list[dict] = []
    for score, row in scored[:limit]:
        results.append(
            {
                "score": round(score, 2),
                "statement_id": row.statement.statement_id,
                "excerpt": row.statement.text,
                "heading_path": row.statement.heading_path,
                "page": row.statement.page,
                "controls": [
                    {"framework": h.framework, "control_id": h.control_id, "title": h.title}
                    for h in row.mappings[:6]
                ],
            }
        )
    return results


def stale_framework_refs(statements: Iterable[ControlStatement]) -> list[dict]:
    """
    Flag citations that look like outdated catalog versions.

    Heuristic only — review before acting.
    """
    findings: list[dict] = []
    for stmt in statements:
        text = stmt.text.lower()
        if "iso 27001:2013" in text or "iso/iec 27001:2013" in text:
            findings.append(
                {
                    "statement_id": stmt.statement_id,
                    "issue": "cites ISO 27001:2013",
                    "recommendation": "Update citation to ISO/IEC 27001:2022",
                }
            )
        if "nist csf 1.1" in text or "framework version 1.1" in text:
            findings.append(
                {
                    "statement_id": stmt.statement_id,
                    "issue": "cites NIST CSF 1.1",
                    "recommendation": "Update citation to NIST CSF 2.0",
                }
            )
        if "800-53 rev 4" in text or "800-53 revision 4" in text:
            findings.append(
                {
                    "statement_id": stmt.statement_id,
                    "issue": "cites NIST SP 800-53 Rev. 4",
                    "recommendation": "Update citation to Rev. 5",
                }
            )
    return findings


def evidence_packet(mapped: Iterable[MappedStatement], control_id: str) -> dict:
    """Build an audit-ready evidence pack for one control id."""
    control_id_norm = control_id.upper().replace(" ", "")
    excerpts: list[dict] = []
    for row in mapped:
        related = [
            h
            for h in row.mappings
            if h.control_id.upper().replace(" ", "") == control_id_norm
            or control_id_norm in h.control_id.upper().replace(" ", "")
        ]
        if not related and control_id_norm not in " ".join(row.statement.candidate_framework_ids):
            continue
        excerpts.append(
            {
                "statement_id": row.statement.statement_id,
                "text": row.statement.text,
                "page": row.statement.page,
                "heading_path": row.statement.heading_path,
                "strength": row.statement.strength.value,
                "mappings": [h.model_dump() for h in (related or row.mappings[:3])],
            }
        )
    return {
        "control_id": control_id,
        "excerpt_count": len(excerpts),
        "excerpts": excerpts,
    }


def control_graph(mapped: Iterable[MappedStatement]) -> dict:
    """
    Bipartite graph: policy statements <-> framework controls.

    Handy for visualization or GraphRAG seeding.
    """
    nodes: dict[str, dict] = {}
    edges: list[dict] = []
    for row in mapped:
        sid = row.statement.statement_id
        nodes[sid] = {
            "id": sid,
            "type": "statement",
            "label": row.statement.text[:80],
            "strength": row.statement.strength.value,
        }
        for hit in row.mappings:
            cid = f"{hit.framework}:{hit.control_id}"
            nodes[cid] = {
                "id": cid,
                "type": "control",
                "label": f"{hit.control_id} {hit.title}".strip(),
                "framework": hit.framework,
            }
            edges.append(
                {
                    "from": sid,
                    "to": cid,
                    "source": hit.source,
                    "confidence": hit.confidence,
                    "relationship": hit.relationship,
                }
            )
    return {"nodes": list(nodes.values()), "edges": edges}


def _tokenize(text: str) -> list[str]:
    import re

    return re.findall(r"[A-Za-z0-9][A-Za-z0-9\-./]*", text)
