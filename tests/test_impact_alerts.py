from pathlib import Path

from grc_pdf_mapper.alerts import AlertRouter, JsonlAlertSink, default_router
from grc_pdf_mapper.assessments import AssessmentRegistry
from grc_pdf_mapper.impact import analyze_impact, detect_verbiage_changes
from grc_pdf_mapper.lineage import PolicyLineageStore
from grc_pdf_mapper.models import AlertSeverity, AssessmentRegistration, ControlStatement, ObligationStrength
from grc_pdf_mapper.pipeline import analyze_document
from grc_pdf_mapper.watch import PolicyWatcher

FIXTURES = Path(__file__).parent / "fixtures"


def test_verbiage_softening_and_sla_detection():
    older = [
        ControlStatement(
            statement_id="a:1",
            text="Privileged accounts must use multi-factor authentication within 24 hours.",
            strength=ObligationStrength.MUST,
            content_hash="old1",
            keywords=["access_control"],
        )
    ]
    newer = [
        ControlStatement(
            statement_id="a:2",
            text="Privileged accounts should use multi-factor authentication within 72 hours.",
            strength=ObligationStrength.SHOULD,
            content_hash="new1",
            keywords=["access_control"],
        )
    ]
    changes = detect_verbiage_changes(older, newer)
    assert len(changes) == 1
    assert changes[0].change_kind == "obligation_softened"
    assert "weakened" in changes[0].risk_note.lower() or "72" in changes[0].risk_note


def test_impact_alert_on_version_change(tmp_path: Path):
    store = PolicyLineageStore(tmp_path / "lineage")
    r1 = analyze_document(
        FIXTURES / "access_control_policy_v1.md",
        doc_id="pol-ac-001",
        store=store,
        version_label="v2.1",
        offline=True,
        alert_on_change=False,
    )
    r2 = analyze_document(
        FIXTURES / "access_control_policy_v2.md",
        doc_id="pol-ac-001",
        store=store,
        version_label="v2.2",
        offline=True,
        alert_on_change=True,
        assessments=AssessmentRegistry(),
        alert_router=default_router(store.root),
    )
    assert r1.snapshot_id != r2.snapshot_id

    alert = analyze_impact(
        store,
        "pol-ac-001",
        r1.snapshot_id,
        r2.snapshot_id,
        assessments=AssessmentRegistry().active(),
        offline=True,
    )
    assert alert.severity in {
        AlertSeverity.MEDIUM,
        AlertSeverity.HIGH,
        AlertSeverity.CRITICAL,
    }
    assert alert.verbiage_changes
    assert alert.frameworks_impacted
    assert any(a.assessment_id == "soc2-type2-2026" for a in alert.assessments_impacted)

    index = store.root / "alerts" / "index.jsonl"
    assert index.exists()
    rows = AlertRouter.read_alerts(index, min_severity="medium")
    assert rows


def test_watcher_emits_alert_on_file_change(tmp_path: Path):
    store = PolicyLineageStore(tmp_path / "lineage")
    watch_file = tmp_path / "policy.md"
    watch_file.write_text(
        (FIXTURES / "access_control_policy_v1.md").read_text(encoding="utf-8"),
        encoding="utf-8",
    )

    router = AlertRouter(
        [JsonlAlertSink(tmp_path / "out.jsonl")],
        index_path=tmp_path / "index.jsonl",
    )
    watcher = PolicyWatcher(
        store,
        router=router,
        assessments=AssessmentRegistry(),
        offline=True,
    )
    watcher.add(watch_file, doc_id="pol-ac-001")

    # Baseline ingest
    first = watcher.poll_once()
    assert first == []
    assert store.head("pol-ac-001") is not None

    # Mutate language: soften MFA requirement
    text = watch_file.read_text(encoding="utf-8")
    text = text.replace(
        "Privileged accounts must use multi-factor authentication.",
        "Privileged accounts should use multi-factor authentication.",
    )
    watch_file.write_text(text, encoding="utf-8")

    alerts = watcher.poll_once()
    assert len(alerts) == 1
    assert alerts[0].severity in {AlertSeverity.HIGH, AlertSeverity.CRITICAL, AlertSeverity.MEDIUM}
    assert alerts[0].assessments_impacted
    assert (tmp_path / "out.jsonl").exists()


def test_assessment_registry_roundtrip(tmp_path: Path):
    path = tmp_path / "assessments.json"
    registry = AssessmentRegistry()
    registry.upsert(
        AssessmentRegistration(
            assessment_id="custom-audit",
            name="Custom Audit",
            frameworks=["SOC 2"],
            doc_ids=["pol-ac-001"],
        )
    )
    registry.save(path)
    loaded = AssessmentRegistry(path)
    assert any(a.assessment_id == "custom-audit" for a in loaded.all())
