#!/usr/bin/env python3
"""CI helper: keep documentation and Terraform policy-as-code in lock-step."""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

from grc_pdf_mapper.alerts import default_router
from grc_pdf_mapper.assessments import AssessmentRegistry
from grc_pdf_mapper.models import AlertSeverity
from grc_pdf_mapper.sync import (
    analyze_doc_change_for_iac,
    analyze_iac_change,
    completeness_scan,
    evaluate_change_set,
    load_links,
)

SEVERITY_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--mode",
        choices=["iac-changed", "doc-changed", "completeness", "change-set"],
        required=True,
    )
    parser.add_argument("--links", type=Path, default=Path("lab/policy-as-code-links.json"))
    parser.add_argument("--doc-id", default="pol-ac-001")
    parser.add_argument("--policy", type=Path, default=Path("lab/policies/access-control.md"))
    parser.add_argument("--terraform-root", type=Path, default=Path("lab/iac"))
    parser.add_argument("--base-tf", type=Path, action="append", default=[])
    parser.add_argument("--head-tf", type=Path, action="append", default=[])
    parser.add_argument("--base-tf-root", type=Path, action="append", default=[])
    parser.add_argument("--head-tf-root", type=Path, action="append", default=[])
    parser.add_argument("--base-policy", type=Path)
    parser.add_argument("--head-policy", type=Path)
    parser.add_argument("--assessments", type=Path, default=Path("lab/assessments.json"))
    parser.add_argument("--online-scf", action="store_true")
    parser.add_argument("--fail-on", default="high")
    parser.add_argument("--comment-out", type=Path, default=Path("pac-comment.md"))
    parser.add_argument("--json-out", type=Path, default=Path("pac-alert.json"))
    parser.add_argument("--store", type=Path, default=Path(".grc-lineage-ci"))
    args = parser.parse_args()

    links = load_links(args.links)
    registry = (
        AssessmentRegistry(args.assessments)
        if args.assessments.exists()
        else AssessmentRegistry()
    )
    active_assessments = registry.active()

    if args.mode == "completeness":
        report = completeness_scan(
            links=links,
            policy_path=args.policy,
            terraform_root=args.terraform_root,
            doc_id=args.doc_id,
            scf_offline=not args.online_scf,
            assessments=active_assessments,
        )
        alert = (
            report.alerts[0]
            if report.alerts
            else _ok_alert(
                "completeness",
                args.doc_id,
                control_mappings=report.control_mappings,
                terraform_mappings=report.terraform_mappings,
            )
        )
        _write_outputs(alert, args.comment_out, args.json_out, args.store)
        return _exit_for(alert, args.fail_on)

    if args.mode == "iac-changed":
        if not args.head_tf and not args.head_tf_root:
            print("Provide --head-tf or --head-tf-root for iac-changed mode", file=sys.stderr)
            return 2
        alert = analyze_iac_change(
            links=links,
            base_tf_files=args.base_tf,
            head_tf_files=args.head_tf,
            base_tf_roots=args.base_tf_root,
            head_tf_roots=args.head_tf_root,
            policy_path=args.policy,
            doc_id=args.doc_id,
            scf_offline=not args.online_scf,
            assessments=active_assessments,
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
            scf_offline=not args.online_scf,
            assessments=active_assessments,
        )
        _write_outputs(alert, args.comment_out, args.json_out, args.store)
        return _exit_for(alert, args.fail_on)

    if args.mode == "change-set":
        if not args.base_tf_root or not args.head_tf_root:
            print(
                "Provide --base-tf-root and --head-tf-root for change-set mode",
                file=sys.stderr,
            )
            return 2
        if len(args.base_tf_root) != 1 or len(args.head_tf_root) != 1:
            print(
                "change-set mode accepts one repository pair. Use production-monitor "
                "for multiple documentation or IaC repositories.",
                file=sys.stderr,
            )
            return 2
        base_policy = args.base_policy or args.policy
        head_policy = args.head_policy or args.policy
        alert = evaluate_change_set(
            links=links,
            doc_id=args.doc_id,
            base_policy_path=base_policy,
            head_policy_path=head_policy,
            base_tf_root=args.base_tf_root[0],
            head_tf_root=args.head_tf_root[0],
            scf_offline=not args.online_scf,
            assessments=active_assessments,
        )
        _write_outputs(alert, args.comment_out, args.json_out, args.store)
        return _exit_for(alert, args.fail_on)

    return 2


def _ok_alert(
    trigger: str,
    doc_id: str,
    *,
    control_mappings=None,
    terraform_mappings=None,
):
    from grc_pdf_mapper.pac_models import LifecycleAlert

    return LifecycleAlert(
        alert_id="ok",
        trigger=trigger,
        severity=AlertSeverity.INFO,
        summary=f"[INFO] Policy-as-code lock-step OK for '{doc_id}'.",
        control_mappings=control_mappings or [],
        terraform_mappings=terraform_mappings or [],
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
        lines.append("### Changed repository paths")
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
    if alert.control_mappings:
        lines.extend(
            [
                "### SCF control context",
                "",
                "| Link | SCF controls | Framework controls | Owner |",
                "|---|---|---|---|",
            ]
        )
        for mapping in alert.control_mappings:
            scf_ids = ", ".join(mapping.scf_control_ids) or "none"
            framework_items = [
                f"{framework}: {', '.join(control_ids[:6])}"
                for framework, control_ids in mapping.framework_controls.items()
                if framework != "SCF"
            ]
            lines.append(
                f"| `{mapping.link_id}` | {_cell(scf_ids)} | "
                f"{_cell('; '.join(framework_items), limit=220)} | "
                f"{_cell(mapping.owner or 'unassigned')} |"
            )
        lines.append("")
    if alert.terraform_mappings:
        lines.extend(
            [
                "### Terraform classifier and SCF context",
                "",
                "| Resource | Domains | Candidate controls | SCF | Roles | Confidence | Reasons |",
                "|---|---|---|---|---|---:|---|",
            ]
        )
        for mapping in alert.terraform_mappings[:40]:
            lines.append(
                f"| `{mapping.address}` | {_cell(', '.join(mapping.domains))} | "
                f"{_cell(', '.join(mapping.candidate_control_ids))} | "
                f"{_cell(', '.join(mapping.scf_control_ids))} | "
                f"{_cell(', '.join(mapping.enforcement_roles))} | "
                f"{mapping.confidence:.2f} | "
                f"{_cell('; '.join(mapping.reasons), limit=180)} |"
            )
        if len(alert.terraform_mappings) > 40:
            lines.append("")
            lines.append(
                f"_Showing 40 of {len(alert.terraform_mappings)} classified resources._"
            )
        lines.append("")
    if alert.assessments_impacted:
        lines.extend(["### Active assessments affected", ""])
        for assessment in alert.assessments_impacted:
            frameworks = ", ".join(assessment.frameworks_at_risk)
            lines.append(
                f"- **{assessment.assessment_name}** "
                f"(`{assessment.risk.value}`): {frameworks}"
            )
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
