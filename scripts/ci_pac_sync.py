#!/usr/bin/env python3
"""CI helper: keep documentation and Terraform policy-as-code in lock-step."""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

from grc_pdf_mapper.alerts import default_router
from grc_pdf_mapper.models import AlertSeverity, ImpactAlert
from grc_pdf_mapper.sync import (
    analyze_doc_change_for_iac,
    analyze_iac_change,
    completeness_scan,
    load_links,
)

SEVERITY_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--mode",
        choices=["iac-changed", "doc-changed", "completeness"],
        required=True,
    )
    parser.add_argument("--links", type=Path, default=Path("lab/policy-as-code-links.json"))
    parser.add_argument("--doc-id", default="pol-ac-001")
    parser.add_argument("--policy", type=Path, default=Path("lab/policies/access-control.md"))
    parser.add_argument("--terraform-root", type=Path, default=Path("lab/iac"))
    parser.add_argument("--base-tf", type=Path, action="append", default=[])
    parser.add_argument("--head-tf", type=Path, action="append", default=[])
    parser.add_argument("--base-policy", type=Path)
    parser.add_argument("--head-policy", type=Path)
    parser.add_argument("--fail-on", default="high")
    parser.add_argument("--comment-out", type=Path, default=Path("pac-comment.md"))
    parser.add_argument("--json-out", type=Path, default=Path("pac-alert.json"))
    parser.add_argument("--store", type=Path, default=Path(".grc-lineage-ci"))
    args = parser.parse_args()

    links = load_links(args.links)

    if args.mode == "completeness":
        report = completeness_scan(
            links=links,
            policy_path=args.policy,
            terraform_root=args.terraform_root,
            doc_id=args.doc_id,
        )
        alert = report.alerts[0] if report.alerts else _ok_alert("completeness", args.doc_id)
        _write_outputs(alert, args.comment_out, args.json_out, args.store)
        return _exit_for(alert, args.fail_on)

    if args.mode == "iac-changed":
        if not args.head_tf:
            print("Provide --head-tf for iac-changed mode", file=sys.stderr)
            return 2
        alert = analyze_iac_change(
            links=links,
            base_tf_files=args.base_tf,
            head_tf_files=args.head_tf,
            policy_path=args.policy,
            doc_id=args.doc_id,
        )
        _write_outputs(alert, args.comment_out, args.json_out, args.store)
        return _exit_for(alert, args.fail_on)

    if args.mode == "doc-changed":
        base_policy = args.base_policy or args.policy
        head_policy = args.head_policy or args.policy
        older = base_policy.read_text(encoding="utf-8")
        newer = head_policy.read_text(encoding="utf-8")
        alert = analyze_doc_change_for_iac(
            links=links,
            doc_id=args.doc_id,
            older_markdown=older,
            newer_markdown=newer,
            terraform_root=args.terraform_root,
        )
        _write_outputs(alert, args.comment_out, args.json_out, args.store)
        return _exit_for(alert, args.fail_on)

    return 2


def _ok_alert(trigger: str, doc_id: str):
    from grc_pdf_mapper.pac_models import LifecycleAlert

    return LifecycleAlert(
        alert_id="ok",
        trigger=trigger,
        severity=AlertSeverity.INFO,
        summary=f"[INFO] Policy-as-code lock-step OK for '{doc_id}'.",
        recommended_actions=[],
    )


def _write_outputs(alert, comment_out: Path, json_out: Path, store: Path) -> None:
    json_out.write_text(alert.model_dump_json(indent=2), encoding="utf-8")
    comment_out.write_text(_render_comment(alert), encoding="utf-8")
    # Reuse alert router index for a unified feed.
    try:
        from grc_pdf_mapper.pac_models import LifecycleAlert

        # Adapt into ImpactAlert-shaped index via router metadata file.
        default_router(store)
        index = store / "alerts" / "pac-index.jsonl"
        index.parent.mkdir(parents=True, exist_ok=True)
        with index.open("a", encoding="utf-8") as fh:
            fh.write(
                alert.model_dump_json()
                + "\n"
            )
    except Exception:
        pass
    _set_output("severity", alert.severity.value)
    _set_output("summary", alert.summary)
    _set_output("trigger", alert.trigger)


def _render_comment(alert) -> str:
    lines = [
        "## Policy-as-code lock-step check",
        "",
        f"**Trigger:** `{alert.trigger}`  ",
        f"**Severity:** `{alert.severity.value}`  ",
        f"**Alert ID:** `{alert.alert_id}`",
        "",
        alert.summary,
        "",
    ]
    if alert.changed_paths:
        lines.append("### Changed IaC paths")
        lines.append("")
        for path in alert.changed_paths:
            lines.append(f"- `{path}`")
        lines.append("")
    if alert.linked_statements:
        lines.append("### Linked policy statements")
        lines.append("")
        for stmt in alert.linked_statements:
            lines.append(f"- {stmt}")
        lines.append("")
    if alert.linked_iac:
        lines.append("### Linked Terraform")
        lines.append("")
        for ref in alert.linked_iac:
            lines.append(f"- `{ref}`")
        lines.append("")
    if alert.gaps:
        lines.extend(
            [
                "### Lifecycle gaps",
                "",
                "| Kind | Severity | Detail | Action |",
                "|---|---|---|---|",
            ]
        )
        for gap in alert.gaps[:20]:
            lines.append(
                f"| `{gap.kind}` | `{gap.severity.value}` | {_cell(gap.detail)} | {_cell(gap.recommended_action)} |"
            )
        lines.append("")
    if alert.recommended_actions:
        lines.append("### Recommended actions")
        lines.append("")
        for action in alert.recommended_actions:
            lines.append(f"- {action}")
        lines.append("")
    lines.extend(
        [
            "---",
            "_Docs and compliance-as-code must move together. "
            "Do not merge only one side of a control change._",
        ]
    )
    return "\n".join(lines) + "\n"


def _cell(value: str | None, limit: int = 100) -> str:
    if not value:
        return ""
    text = value.replace("|", "\\|").replace("\n", " ")
    return text if len(text) <= limit else text[: limit - 1] + "…"


def _exit_for(alert, fail_on: str) -> int:
    print(alert.summary)
    if SEVERITY_RANK.get(alert.severity.value, 0) >= SEVERITY_RANK.get(fail_on, 3):
        print(
            f"Failing check: severity '{alert.severity.value}' >= fail-on '{fail_on}'",
            file=sys.stderr,
        )
        return 1
    return 0


def _set_output(name: str, value: str) -> None:
    path = os.environ.get("GITHUB_OUTPUT")
    if not path:
        return
    with open(path, "a", encoding="utf-8") as fh:
        fh.write(f"{name}={value}\n")


if __name__ == "__main__":
    raise SystemExit(main())
