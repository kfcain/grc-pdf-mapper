"""CLI for GRC PDF mapping workflows."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Optional

import typer
from rich.console import Console
from rich.table import Table

from grc_pdf_mapper.alerts import AlertRouter, default_router
from grc_pdf_mapper.analytics import (
    blast_radius,
    control_graph,
    coverage_matrix,
    evidence_packet,
    questionnaire_suggest,
    stale_framework_refs,
)
from grc_pdf_mapper.assessments import AssessmentRegistry
from grc_pdf_mapper.impact import analyze_impact
from grc_pdf_mapper.lineage import PolicyLineageStore
from grc_pdf_mapper.oscal import to_assessment_results, to_component_definition
from grc_pdf_mapper.pipeline import analyze_document
from grc_pdf_mapper.watch import PolicyWatcher

app = typer.Typer(
    name="grc-pdf",
    help=(
        "Extract control statements from policy documents "
        "(Markdown, PDF, Word, Excel, and other office formats) "
        "and map them to GRC frameworks."
    ),
    no_args_is_help=True,
)
console = Console()


@app.command("analyze")
def analyze_cmd(
    path: Path = typer.Argument(..., exists=True, readable=True),
    doc_id: Optional[str] = typer.Option(None, help="Stable document id"),
    store: Path = typer.Option(Path(".grc-lineage"), help="Lineage store directory"),
    version: str = typer.Option("v1", help="Version label for this commit"),
    author: Optional[str] = typer.Option(None),
    offline: bool = typer.Option(False, help="Use seed/local maps only"),
    no_commit: bool = typer.Option(False, help="Skip lineage commit"),
    no_alert: bool = typer.Option(False, help="Skip impact alerts on change"),
    assessments: Optional[Path] = typer.Option(None, help="Assessment registry JSON"),
    webhook: Optional[str] = typer.Option(None, help="Webhook URL for real-time alerts"),
    json_out: Optional[Path] = typer.Option(None, "--json", help="Write full report JSON"),
) -> None:
    """Ingest a policy document, extract obligations, and map controls."""
    lineage = PolicyLineageStore(store)
    registry = AssessmentRegistry(assessments) if assessments else AssessmentRegistry()
    report = analyze_document(
        path,
        doc_id=doc_id,
        store=lineage,
        version_label=version,
        author=author,
        offline=offline,
        commit=not no_commit,
        alert_on_change=not no_alert,
        assessments=registry,
        webhook_url=webhook,
    )

    console.print(f"[bold]Document[/bold]: {report.doc_id}")
    console.print(f"Snapshot: {report.snapshot_id}")
    fmt = report.ingest.detected_format or report.ingest.pdf_type or "-"
    console.print(f"Engine: {report.ingest.engine}  format={fmt}")
    console.print(f"Statements: {len(report.statements)}")
    console.print(f"Frameworks: {', '.join(report.frameworks_covered) or '(none)'}")
    if report.gaps:
        console.print(f"Coverage gaps vs core set: {', '.join(report.gaps)}")

    impact = getattr(report, "_impact_alert", None)
    if impact is not None:
        console.print(f"[bold red]Impact alert[/bold red]: {impact.severity.value} — {impact.summary}")

    table = Table(title="Sample mapped obligations")
    table.add_column("Strength")
    table.add_column("Excerpt")
    table.add_column("Controls")
    for row in report.statements[:12]:
        controls = ", ".join(f"{h.framework}:{h.control_id}" for h in row.mappings[:4])
        table.add_row(row.statement.strength.value, row.statement.text[:90], controls)
    console.print(table)

    if json_out:
        json_out.write_text(report.model_dump_json(indent=2), encoding="utf-8")
        console.print(f"Wrote {json_out}")


@app.command("history")
def history_cmd(
    doc_id: str,
    store: Path = typer.Option(Path(".grc-lineage")),
) -> None:
    """Show git-style snapshot history for a document."""
    lineage = PolicyLineageStore(store)
    snaps = lineage.history(doc_id)
    if not snaps:
        console.print("No history found.")
        raise typer.Exit(1)
    table = Table(title=f"History: {doc_id}")
    table.add_column("Snapshot")
    table.add_column("Version")
    table.add_column("Status")
    table.add_column("Statements")
    table.add_column("Created")
    for snap in snaps:
        table.add_row(
            snap.snapshot_id,
            snap.version_label,
            snap.approval_status,
            str(len(snap.statement_ids)),
            snap.created_at.isoformat(),
        )
    console.print(table)


@app.command("diff")
def diff_cmd(
    doc_id: str,
    older: str,
    newer: str,
    store: Path = typer.Option(Path(".grc-lineage")),
) -> None:
    """Diff control statements between two snapshots."""
    lineage = PolicyLineageStore(store)
    diff = lineage.diff_statements(doc_id, older, newer)
    console.print(f"[green]+{len(diff['added'])}[/green]  [red]-{len(diff['removed'])}[/red]")
    for stmt in diff["added"]:
        console.print(f"[green]+[/green] {stmt.text}")
    for stmt in diff["removed"]:
        console.print(f"[red]-[/red] {stmt.text}")


@app.command("drift")
def drift_cmd(
    doc_id: str,
    older: str,
    newer: str,
    store: Path = typer.Option(Path(".grc-lineage")),
) -> None:
    """Detect control-coverage drift between versions."""
    lineage = PolicyLineageStore(store)
    findings = lineage.detect_drift(doc_id, older, newer)
    if not findings:
        console.print("No drift findings.")
        return
    for f in findings:
        console.print(f"[{f.severity}] {f.kind}: {f.detail}")


@app.command("blast-radius")
def blast_radius_cmd(
    report_json: Path = typer.Argument(..., exists=True),
    statement_id: Optional[str] = typer.Option(None),
) -> None:
    """Show framework controls impacted by a statement (or all statements)."""
    from grc_pdf_mapper.models import MappingReport

    report = MappingReport.model_validate_json(report_json.read_text(encoding="utf-8"))
    ids = {statement_id} if statement_id else None
    items = blast_radius(report.statements, statement_ids=ids)
    table = Table(title="Blast radius")
    table.add_column("Framework")
    table.add_column("Control")
    table.add_column("Title")
    table.add_column("Via")
    for item in items[:50]:
        table.add_row(item.framework, item.control_id, item.title[:40], item.via_statement_id)
    console.print(table)


@app.command("ask")
def ask_cmd(
    report_json: Path = typer.Argument(..., exists=True),
    question: str = typer.Argument(...),
    limit: int = typer.Option(5),
) -> None:
    """Suggest policy excerpts for a questionnaire question."""
    from grc_pdf_mapper.models import MappingReport

    report = MappingReport.model_validate_json(report_json.read_text(encoding="utf-8"))
    suggestions = questionnaire_suggest(question, report.statements, limit=limit)
    console.print_json(json.dumps(suggestions))


@app.command("evidence")
def evidence_cmd(
    report_json: Path = typer.Argument(..., exists=True),
    control_id: str = typer.Argument(...),
) -> None:
    """Build an audit evidence packet for one control id."""
    from grc_pdf_mapper.models import MappingReport

    report = MappingReport.model_validate_json(report_json.read_text(encoding="utf-8"))
    packet = evidence_packet(report.statements, control_id)
    console.print_json(json.dumps(packet))


@app.command("coverage")
def coverage_cmd(report_json: Path = typer.Argument(..., exists=True)) -> None:
    """Print framework coverage matrix from a saved report."""
    from grc_pdf_mapper.models import MappingReport

    report = MappingReport.model_validate_json(report_json.read_text(encoding="utf-8"))
    matrix = coverage_matrix(report.statements)
    console.print_json(json.dumps(matrix))


@app.command("stale")
def stale_cmd(report_json: Path = typer.Argument(..., exists=True)) -> None:
    """Flag outdated framework version citations."""
    from grc_pdf_mapper.models import MappingReport

    report = MappingReport.model_validate_json(report_json.read_text(encoding="utf-8"))
    findings = stale_framework_refs(s.statement for s in report.statements)
    console.print_json(json.dumps(findings))


@app.command("graph")
def graph_cmd(
    report_json: Path = typer.Argument(..., exists=True),
    out: Path = typer.Option(Path("control-graph.json")),
) -> None:
    """Export statement↔control graph JSON for GraphRAG / viz tools."""
    from grc_pdf_mapper.models import MappingReport

    report = MappingReport.model_validate_json(report_json.read_text(encoding="utf-8"))
    graph = control_graph(report.statements)
    out.write_text(json.dumps(graph, indent=2), encoding="utf-8")
    console.print(f"Wrote {out} ({len(graph['nodes'])} nodes, {len(graph['edges'])} edges)")


@app.command("oscal")
def oscal_cmd(
    report_json: Path = typer.Argument(..., exists=True),
    out: Path = typer.Option(Path("component-definition.json")),
    kind: str = typer.Option("component", help="component|assessment"),
) -> None:
    """Export OSCAL-inspired JSON from a mapping report."""
    from grc_pdf_mapper.models import MappingReport

    report = MappingReport.model_validate_json(report_json.read_text(encoding="utf-8"))
    if kind == "assessment":
        payload = to_assessment_results(title=report.doc_id, mapped=report.statements)
    else:
        payload = to_component_definition(
            component_title=report.ingest.title or report.doc_id,
            mapped=report.statements,
            doc_id=report.doc_id,
        )
    out.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    console.print(f"Wrote {out}")


@app.command("impact")
def impact_cmd(
    doc_id: str,
    older: str,
    newer: str,
    store: Path = typer.Option(Path(".grc-lineage")),
    assessments: Optional[Path] = typer.Option(None, help="Assessment registry JSON"),
    offline: bool = typer.Option(True, help="Use offline maps for impact crosswalk"),
    publish: bool = typer.Option(False, help="Publish alert to configured sinks"),
    webhook: Optional[str] = typer.Option(None),
    json_out: Optional[Path] = typer.Option(None, "--json"),
) -> None:
    """Analyze whether language changes affect frameworks or assessments."""
    lineage = PolicyLineageStore(store)
    registry = AssessmentRegistry(assessments) if assessments else AssessmentRegistry()
    alert = analyze_impact(
        lineage,
        doc_id,
        older,
        newer,
        assessments=registry.active(),
        offline=offline,
    )
    if publish:
        default_router(store, webhook_url=webhook).publish(alert)

    console.print(f"[bold]{alert.severity.value.upper()}[/bold] {alert.summary}")
    if alert.verbiage_changes:
        table = Table(title="Verbiage changes")
        table.add_column("Kind")
        table.add_column("Before")
        table.add_column("After")
        table.add_column("Risk note")
        for change in alert.verbiage_changes[:20]:
            table.add_row(
                change.change_kind,
                (change.before_text or "")[:60],
                (change.after_text or "")[:60],
                change.risk_note[:80],
            )
        console.print(table)

    if alert.frameworks_impacted:
        fw_table = Table(title="Frameworks at risk")
        fw_table.add_column("Framework")
        fw_table.add_column("Risk")
        fw_table.add_column("Controls")
        for fw in alert.frameworks_impacted:
            fw_table.add_row(fw.framework, fw.risk.value, ", ".join(fw.control_ids[:8]))
        console.print(fw_table)

    if alert.assessments_impacted:
        a_table = Table(title="Assessments at risk")
        a_table.add_column("Assessment")
        a_table.add_column("Risk")
        a_table.add_column("Frameworks")
        for item in alert.assessments_impacted:
            a_table.add_row(
                item.assessment_name,
                item.risk.value,
                ", ".join(item.frameworks_at_risk),
            )
        console.print(a_table)

    if json_out:
        json_out.write_text(alert.model_dump_json(indent=2), encoding="utf-8")
        console.print(f"Wrote {json_out}")


@app.command("alerts")
def alerts_cmd(
    store: Path = typer.Option(Path(".grc-lineage")),
    min_severity: str = typer.Option("info", help="info|low|medium|high|critical"),
) -> None:
    """List published impact alerts from the lineage store."""
    index = store / "alerts" / "index.jsonl"
    rows = AlertRouter.read_alerts(index, min_severity=min_severity)
    if not rows:
        console.print("No alerts found.")
        return
    table = Table(title="GRC impact alerts")
    table.add_column("When")
    table.add_column("Severity")
    table.add_column("Doc")
    table.add_column("Summary")
    for row in rows[-50:]:
        table.add_row(
            str(row.get("created_at", ""))[:19],
            str(row.get("severity", "")),
            str(row.get("doc_id", "")),
            str(row.get("summary", ""))[:90],
        )
    console.print(table)


@app.command("watch")
def watch_cmd(
    paths: list[Path] = typer.Argument(..., exists=True, readable=True),
    store: Path = typer.Option(Path(".grc-lineage")),
    interval: float = typer.Option(2.0, help="Poll interval in seconds"),
    once: bool = typer.Option(False, help="Poll once and exit"),
    offline: bool = typer.Option(True),
    assessments: Optional[Path] = typer.Option(None),
    webhook: Optional[str] = typer.Option(None),
    doc_id: Optional[str] = typer.Option(None, help="Force one doc id when watching a single file"),
) -> None:
    """Watch policy files and alert in real time when language changes."""
    lineage = PolicyLineageStore(store)
    registry = AssessmentRegistry(assessments) if assessments else AssessmentRegistry()
    router = default_router(store, webhook_url=webhook)
    watcher = PolicyWatcher(
        lineage,
        router=router,
        assessments=registry,
        offline=offline,
    )
    if len(paths) == 1 and doc_id:
        watcher.add(paths[0], doc_id=doc_id)
    else:
        for path in paths:
            watcher.add(path)

    console.print(
        f"Watching {len(watcher.watched)} file(s). "
        f"Alerts → {store / 'alerts' / 'alerts.jsonl'}"
    )
    alerts = watcher.run(interval_seconds=interval, once=once)
    if once:
        console.print(f"Poll complete. Alerts emitted: {len(alerts)}")


@app.command("assessments-init")
def assessments_init_cmd(
    out: Path = typer.Option(Path("assessments.json")),
) -> None:
    """Write a starter assessment registry for framework/assessment alerting."""
    path = AssessmentRegistry().save(out)
    console.print(f"Wrote {path}")


@app.command("sync-check")
def sync_check_cmd(
    policy: Path = typer.Option(Path("lab/policies/access-control.md")),
    terraform_root: Path = typer.Option(Path("lab/iac")),
    links: Path = typer.Option(Path("lab/policy-as-code-links.json")),
    doc_id: str = typer.Option("pol-ac-001"),
    json_out: Optional[Path] = typer.Option(None, "--json"),
) -> None:
    """Check that policy statements and Terraform remain in lock-step."""
    from grc_pdf_mapper.sync import completeness_scan, load_links

    report = completeness_scan(
        links=load_links(links),
        policy_path=policy,
        terraform_root=terraform_root,
        doc_id=doc_id,
    )
    console.print(
        f"Links: {report.link_count}  Covered: {len(report.covered_links)}  "
        f"Gaps: {len(report.gaps)}  Complete: {report.complete}"
    )
    if report.gaps:
        table = Table(title="Lock-step gaps")
        table.add_column("Kind")
        table.add_column("Severity")
        table.add_column("Detail")
        for gap in report.gaps:
            table.add_row(gap.kind, gap.severity.value, gap.detail[:100])
        console.print(table)
    if json_out:
        json_out.write_text(report.model_dump_json(indent=2), encoding="utf-8")
        console.print(f"Wrote {json_out}")
    if not report.complete:
        raise typer.Exit(1)


@app.command("pac-impact")
def pac_impact_cmd(
    mode: str = typer.Argument(..., help="iac-changed|doc-changed"),
    links: Path = typer.Option(Path("lab/policy-as-code-links.json")),
    doc_id: str = typer.Option("pol-ac-001"),
    policy: Path = typer.Option(Path("lab/policies/access-control.md")),
    terraform_root: Path = typer.Option(Path("lab/iac")),
    base_tf: Optional[Path] = typer.Option(None, help="Base Terraform file"),
    head_tf: Optional[Path] = typer.Option(None, help="Head Terraform file"),
    base_policy: Optional[Path] = typer.Option(None),
    head_policy: Optional[Path] = typer.Option(None),
    json_out: Optional[Path] = typer.Option(None, "--json"),
) -> None:
    """Alert when IaC or docs change without the other side of the lifecycle."""
    from grc_pdf_mapper.sync import analyze_doc_change_for_iac, analyze_iac_change, load_links

    loaded = load_links(links)
    if mode == "iac-changed":
        if not head_tf:
            console.print("--head-tf is required for iac-changed")
            raise typer.Exit(2)
        alert = analyze_iac_change(
            links=loaded,
            base_tf_files=[base_tf] if base_tf else [],
            head_tf_files=[head_tf],
            policy_path=policy,
            doc_id=doc_id,
        )
    elif mode == "doc-changed":
        older = (base_policy or policy).read_text(encoding="utf-8")
        newer = (head_policy or policy).read_text(encoding="utf-8")
        alert = analyze_doc_change_for_iac(
            links=loaded,
            doc_id=doc_id,
            older_markdown=older,
            newer_markdown=newer,
            terraform_root=terraform_root,
        )
    else:
        console.print("mode must be iac-changed or doc-changed")
        raise typer.Exit(2)

    console.print(f"[bold]{alert.severity.value.upper()}[/bold] {alert.summary}")
    for gap in alert.gaps[:12]:
        console.print(f"- [{gap.severity.value}] {gap.kind}: {gap.detail}")
    if json_out:
        json_out.write_text(alert.model_dump_json(indent=2), encoding="utf-8")
    if alert.severity.value in {"high", "critical"}:
        raise typer.Exit(1)


@app.command("scf-map")
def scf_map_cmd(
    control_id: str = typer.Argument(..., help="Framework or SCF control id (e.g. AC-2, IAC-01, CC6.1)"),
    offline: bool = typer.Option(False, help="Use bundled SCF seed only"),
    json_out: Optional[Path] = typer.Option(None, "--json"),
) -> None:
    """Map a control id through the Secure Controls Framework (SCF) API."""
    from grc_pdf_mapper.models import ControlStatement, ObligationStrength
    from grc_pdf_mapper.scf import SCF_ATTRIBUTION, ScfClient, is_scf_control_id

    stmt = ControlStatement(
        statement_id="cli-scf-map",
        text=f"Map control {control_id}",
        strength=ObligationStrength.SHOULD,
        keywords=[],
        candidate_framework_ids=[control_id],
        content_hash="cli",
    )
    # If the user passes a topic-like token with no id shape, treat as keyword domain.
    if not is_scf_control_id(control_id) and "-" not in control_id and "." not in control_id:
        stmt.candidate_framework_ids = []
        stmt.keywords = [control_id.lower().replace(" ", "_")]

    with ScfClient(offline=offline) as scf:
        hits = scf.map_statement(stmt)

    console.print(f"[bold]SCF map[/bold]: {control_id}")
    console.print(f"Hits: {len(hits)}")
    console.print(SCF_ATTRIBUTION)
    table = Table(title="SCF crosswalk")
    table.add_column("Framework")
    table.add_column("Control")
    table.add_column("Title")
    table.add_column("Rel")
    table.add_column("Conf")
    for hit in hits[:40]:
        table.add_row(
            hit.framework,
            hit.control_id,
            (hit.title or "")[:48],
            hit.relationship,
            f"{hit.confidence:.2f}",
        )
    console.print(table)
    if json_out:
        json_out.write_text(
            json.dumps([h.model_dump() for h in hits], indent=2),
            encoding="utf-8",
        )


@app.command("fedramp-ksi")
def fedramp_ksi_cmd(
    class_id: str = typer.Option("c", "--class", help="FedRAMP class a|b|c|d"),
    control: Optional[str] = typer.Option(None, help="Optional NIST control filter, e.g. AC-2"),
    catalog: Path = typer.Option(Path("lab/fedramp/cr26_ksi_catalog.json")),
    json_out: Optional[Path] = typer.Option(None, "--json"),
) -> None:
    """List CR26 KSIs for a certification class (optionally filtered by NIST control)."""
    from grc_pdf_mapper.fedramp import FedRampKSICatalog

    cat = FedRampKSICatalog(catalog)
    console.print(f"CR26 catalog version: {cat.version}")
    if control:
        rows = cat.map_control(control, class_id=class_id)
        console.print(f"KSIs mapped from {control} for Class {class_id.upper()}: {len(rows)}")
    else:
        rows = cat.for_class(class_id)
        console.print(f"KSIs for Class {class_id.upper()}: {len(rows)}")
    table = Table(title=f"FedRAMP CR26 KSI — Class {class_id.upper()}")
    table.add_column("KSI")
    table.add_column("Name")
    table.add_column("Status")
    table.add_column("NIST controls")
    for row in rows[:40]:
        table.add_row(
            row["id"],
            row.get("name") or "",
            str(row.get("class_status") or row.get("class_applicability", {}).get(class_id, "")),
            ", ".join(row.get("controls_nist", [])[:5]),
        )
    console.print(table)
    if json_out:
        json_out.write_text(json.dumps(rows, indent=2), encoding="utf-8")


@app.command("fedramp-docs")
def fedramp_docs_cmd(
    class_id: str = typer.Option("c", "--class", help="FedRAMP class a|b|c|d"),
    catalog: Path = typer.Option(Path("lab/fedramp/cr26_ksi_catalog.json")),
    must_only: bool = typer.Option(False, help="Only show MUST documentation obligations"),
) -> None:
    """Show CR26 documentation / certification-package obligations by class."""
    from grc_pdf_mapper.fedramp import FedRampKSICatalog

    rows = FedRampKSICatalog(catalog).documentation_matrix(class_id)
    if must_only:
        rows = [r for r in rows if str(r.get("force", "")).upper() == "MUST"]
    table = Table(title=f"FedRAMP documentation obligations — Class {class_id.upper()}")
    table.add_column("ID")
    table.add_column("Force")
    table.add_column("Name")
    table.add_column("Cadence / note")
    for row in rows:
        cadence = ""
        if row.get("timeframe_num"):
            cadence = f"every {row['timeframe_num']} {row.get('timeframe_type')}"
        table.add_row(row["id"], str(row.get("force") or ""), row.get("name") or "", cadence)
    console.print(table)
    for row in rows:
        if row.get("statement"):
            console.print(f"\n[bold]{row['id']}[/bold]: {row['statement'][:240]}")


if __name__ == "__main__":
    app()
