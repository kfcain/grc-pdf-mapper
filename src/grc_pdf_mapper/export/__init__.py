"""CSV export of mapping results at framework and control grain."""

from __future__ import annotations

import csv
import io
from collections import defaultdict
from typing import Any, Iterable

from grc_pdf_mapper.models import MappedStatement, MappingReport


def frameworks_csv(mapped: Iterable[MappedStatement]) -> str:
    """One row per framework covered by the document mappings."""
    # framework -> {controls, statement_ids}
    by_fw: dict[str, dict[str, set[str]]] = defaultdict(
        lambda: {"controls": set(), "statements": set()}
    )
    for row in mapped:
        for hit in row.mappings:
            bucket = by_fw[hit.framework]
            bucket["controls"].add(hit.control_id)
            bucket["statements"].add(row.statement.statement_id)

    buffer = io.StringIO()
    writer = csv.writer(buffer)
    writer.writerow(
        [
            "framework",
            "control_count",
            "statement_count",
            "control_ids",
        ]
    )
    for framework in sorted(by_fw):
        controls = sorted(by_fw[framework]["controls"])
        statements = by_fw[framework]["statements"]
        writer.writerow(
            [
                framework,
                len(controls),
                len(statements),
                ";".join(controls),
            ]
        )
    return buffer.getvalue()


def framework_controls_csv(mapped: Iterable[MappedStatement]) -> str:
    """One row per framework control, with supporting statement ids and text."""
    # (framework, control_id) -> aggregate
    by_ctrl: dict[tuple[str, str], dict[str, Any]] = {}
    for row in mapped:
        for hit in row.mappings:
            key = (hit.framework, hit.control_id)
            entry = by_ctrl.get(key)
            if entry is None:
                entry = {
                    "framework": hit.framework,
                    "control_id": hit.control_id,
                    "title": hit.title or "",
                    "sources": set(),
                    "confidences": [],
                    "statement_ids": [],
                    "strengths": [],
                    "statement_kinds": [],
                    "classifier_confidences": [],
                    "classifier_reasons": [],
                    "obligations": [],
                }
                by_ctrl[key] = entry
            if hit.title and not entry["title"]:
                entry["title"] = hit.title
            entry["sources"].add(hit.source)
            entry["confidences"].append(float(hit.confidence))
            sid = row.statement.statement_id
            if sid not in entry["statement_ids"]:
                entry["statement_ids"].append(sid)
                entry["strengths"].append(row.statement.strength.value)
                entry["statement_kinds"].append(row.statement.statement_kind.value)
                entry["classifier_confidences"].append(
                    f"{row.statement.classification_confidence:.2f}"
                )
                entry["classifier_reasons"].append(
                    "; ".join(row.statement.classification_reasons)
                )
                entry["obligations"].append(row.statement.text)

    buffer = io.StringIO()
    writer = csv.writer(buffer)
    writer.writerow(
        [
            "framework",
            "control_id",
            "control_title",
            "sources",
            "max_confidence",
            "statement_count",
            "statement_ids",
            "strengths",
            "statement_kinds",
            "classifier_confidences",
            "classifier_reasons",
            "obligations",
        ]
    )
    for key in sorted(by_ctrl):
        entry = by_ctrl[key]
        confidences: list[float] = entry["confidences"]
        writer.writerow(
            [
                entry["framework"],
                entry["control_id"],
                entry["title"],
                ";".join(sorted(entry["sources"])),
                f"{max(confidences):.3f}" if confidences else "",
                len(entry["statement_ids"]),
                ";".join(entry["statement_ids"]),
                ";".join(entry["strengths"]),
                ";".join(entry["statement_kinds"]),
                ";".join(entry["classifier_confidences"]),
                " | ".join(entry["classifier_reasons"]),
                " | ".join(entry["obligations"]),
            ]
        )
    return buffer.getvalue()


def report_csv_exports(report: MappingReport) -> dict[str, str]:
    """Build both CSV grains from a MappingReport."""
    return {
        "frameworks": frameworks_csv(report.statements),
        "controls": framework_controls_csv(report.statements),
    }
