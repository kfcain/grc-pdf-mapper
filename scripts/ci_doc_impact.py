#!/usr/bin/env python3
"""CI helper: compare base vs head policy files and emit GitHub-friendly impact output."""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

from grc_pdf_mapper.alerts import default_router
from grc_pdf_mapper.assessments import AssessmentRegistry
from grc_pdf_mapper.impact import analyze_impact
from grc_pdf_mapper.lineage import PolicyLineageStore
from grc_pdf_mapper.pipeline import analyze_document

SEVERITY_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base-file", required=True, type=Path, help="Policy file at base ref")
    parser.add_argument("--head-file", required=True, type=Path, help="Policy file at PR head")
    parser.add_argument("--doc-id", required=True)
    parser.add_argument("--assessments", type=Path, default=Path("lab/assessments.json"))
    parser.add_argument("--store", type=Path, default=Path(".grc-lineage-ci"))
    parser.add_argument("--fail-on", default="high", help="Fail if severity >= this level")
    parser.add_argument("--comment-out", type=Path, default=Path("impact-comment.md"))
    parser.add_argument("--json-out", type=Path, default=Path("impact-alert.json"))
    parser.add_argument("--offline", action="store_true", default=True)
    parser.add_argument("--online", action="store_true", help="Allow live crosswalk APIs")
    args = parser.parse_args()

    offline = not args.online
    if not args.base_file.exists():
        print(f"Base file missing: {args.base_file}", file=sys.stderr)
        return 2
    if not args.head_file.exists():
        print(f"Head file missing: {args.head_file}", file=sys.stderr)
        return 2

    store = PolicyLineageStore(args.store)
    registry = AssessmentRegistry(args.assessments) if args.assessments.exists() else AssessmentRegistry()

    base_report = analyze_document(
        args.base_file,
        doc_id=args.doc_id,
        store=store,
        version_label="ci-base",
        author="github-actions",
        offline=offline,
        commit=True,
        alert_on_change=False,
        assessments=registry,
    )
    head_report = analyze_document(
        args.head_file,
        doc_id=args.doc_id,
        store=store,
        version_label="ci-head",
        author="github-actions",
        offline=offline,
        commit=True,
        alert_on_change=False,
        assessments=registry,
    )

    if base_report.ingest.source_hash == head_report.ingest.source_hash:
        comment = (
            "## Document change impact\n\n"
            "No content hash change detected for this policy file.\n"
        )
        args.comment_out.write_text(comment, encoding="utf-8")
        _set_output("severity", "info")
        _set_output("summary", "No content change")
        print("No content change.")
        return 0

    alert = analyze_impact(
        store,
        args.doc_id,
        base_report.snapshot_id,
        head_report.snapshot_id,
        assessments=registry.active(),
        offline=offline,
    )
    default_router(args.store).publish(alert)
    args.json_out.write_text(alert.model_dump_json(indent=2), encoding="utf-8")
    args.comment_out.write_text(_render_comment(alert, args.doc_id), encoding="utf-8")

    _set_output("severity", alert.severity.value)
    _set_output("summary", alert.summary)
    _set_output("alert_id", alert.alert_id)

    print(alert.summary)
    threshold = SEVERITY_RANK.get(args.fail_on, 3)
    if SEVERITY_RANK.get(alert.severity.value, 0) >= threshold:
        print(
            f"Failing check: severity '{alert.severity.value}' >= fail-on '{args.fail_on}'",
            file=sys.stderr,
        )
        return 1
    return 0


def _render_comment(alert, doc_id: str) -> str:
    lines = [
        "## Document change impact",
        "",
        f"**Severity:** `{alert.severity.value}`  ",
        f"**Document:** `{doc_id}` (`{alert.version_from}` → `{alert.version_to}`)  ",
        f"**Alert ID:** `{alert.alert_id}`",
        "",
        alert.summary,
        "",
    ]
    if alert.verbiage_changes:
        lines.extend(
            [
                "### Language changes",
                "",
                "| Kind | Before | After | Risk note |",
                "|---|---|---|---|",
            ]
        )
        for change in alert.verbiage_changes[:15]:
            before = _cell(change.before_text)
            after = _cell(change.after_text)
            note = _cell(change.risk_note)
            lines.append(f"| `{change.change_kind}` | {before} | {after} | {note} |")
        lines.append("")

    if alert.frameworks_impacted:
        lines.extend(["### Frameworks that may be affected", ""])
        for fw in alert.frameworks_impacted:
            controls = ", ".join(f"`{c}`" for c in fw.control_ids[:10]) or "_none_"
            lines.append(f"- **{fw.framework}** (`{fw.risk.value}`): {controls}")
        lines.append("")

    if alert.assessments_impacted:
        lines.extend(["### Assessments / initiatives that may be affected", ""])
        for item in alert.assessments_impacted:
            fws = ", ".join(item.frameworks_at_risk)
            lines.append(
                f"- **{item.assessment_name}** (`{item.risk.value}`) — frameworks: {fws}"
            )
        lines.append("")

    if alert.recommended_actions:
        lines.extend(["### Recommended actions", ""])
        for action in alert.recommended_actions:
            lines.append(f"- {action}")
        lines.append("")

    lines.extend(
        [
            "---",
            "_Generated by `grc-pdf-mapper` document change-impact CI._",
            "_Treat this as an assistive control signal. GRC / Document Control still decide merge._",
        ]
    )
    return "\n".join(lines) + "\n"


def _cell(value: str | None, limit: int = 90) -> str:
    if not value:
        return ""
    text = value.replace("|", "\\|").replace("\n", " ")
    if len(text) > limit:
        text = text[: limit - 1] + "…"
    return text


def _set_output(name: str, value: str) -> None:
    path = os.environ.get("GITHUB_OUTPUT")
    if not path:
        return
    with open(path, "a", encoding="utf-8") as fh:
        if "\n" in value:
            fh.write(f"{name}<<EOF\n{value}\nEOF\n")
        else:
            fh.write(f"{name}={value}\n")


if __name__ == "__main__":
    raise SystemExit(main())
