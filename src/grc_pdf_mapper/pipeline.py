"""End-to-end GRC mapping pipeline."""

from __future__ import annotations

from pathlib import Path

from grc_pdf_mapper.alerts import AlertRouter, default_router
from grc_pdf_mapper.analytics import coverage_matrix
from grc_pdf_mapper.assessments import AssessmentRegistry
from grc_pdf_mapper.crosswalk import CrosswalkClient
from grc_pdf_mapper.extract import extract_control_statements
from grc_pdf_mapper.impact import analyze_impact
from grc_pdf_mapper.ingest import ingest_path
from grc_pdf_mapper.lineage import PolicyLineageStore
from grc_pdf_mapper.models import ImpactAlert, MappedStatement, MappingReport


def analyze_document(
    path: str | Path,
    *,
    doc_id: str | None = None,
    store: PolicyLineageStore | None = None,
    version_label: str = "v1",
    author: str | None = None,
    offline: bool = False,
    commit: bool = True,
    alert_on_change: bool = True,
    assessments: AssessmentRegistry | None = None,
    alert_router: AlertRouter | None = None,
    webhook_url: str | None = None,
) -> MappingReport:
    """Ingest → extract → crosswalk → optional lineage commit + impact alerts."""
    path = Path(path)
    ingest = ingest_path(path)
    slug = doc_id or path.stem.lower().replace(" ", "-")
    statements = extract_control_statements(ingest.markdown, doc_slug=slug)

    with CrosswalkClient(offline=offline) as client:
        mapped = [
            MappedStatement(statement=stmt, mappings=client.map_statement(stmt))
            for stmt in statements
        ]

    snapshot_id = "ephemeral"
    impact_alert: ImpactAlert | None = None
    if store and commit:
        previous = store.head(slug)
        snap = store.commit(
            doc_id=slug,
            ingest=ingest,
            statements=statements,
            version_label=version_label,
            author=author,
        )
        snapshot_id = snap.snapshot_id

        if alert_on_change and previous and previous.snapshot_id != snap.snapshot_id:
            registry = assessments or AssessmentRegistry()
            impact_alert = analyze_impact(
                store,
                slug,
                previous.snapshot_id,
                snap.snapshot_id,
                assessments=registry.active(),
                offline=offline,
            )
            router = alert_router or default_router(store.root, webhook_url=webhook_url)
            router.publish(impact_alert)

    matrix = coverage_matrix(mapped)
    expected = {"NIST 800-53", "ISO 27001", "SOC 2", "NIST CSF 2.0"}
    gaps = sorted(expected - set(matrix.keys()))

    report = MappingReport(
        doc_id=slug,
        snapshot_id=snapshot_id,
        ingest=ingest,
        statements=mapped,
        frameworks_covered=sorted(matrix.keys()),
        gaps=gaps,
    )
    if impact_alert is not None:
        # Attach without changing the MappingReport schema consumers rely on.
        report.__dict__["_impact_alert"] = impact_alert
    return report
