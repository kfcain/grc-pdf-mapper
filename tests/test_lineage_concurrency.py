"""Concurrent workers and interrupted commits retain one complete document chain."""
import hashlib
import json
import multiprocessing
import os
import time
from concurrent.futures import ProcessPoolExecutor
from pathlib import Path

import pytest

from grc_pdf_mapper.lineage import PolicyLineageStore
from grc_pdf_mapper.models import ControlStatement, IngestResult


def _commit(root, version="v1"):
    text = "Users must use MFA."
    digest = hashlib.sha256(text.encode()).hexdigest()
    return PolicyLineageStore(root).commit(
        doc_id="policy", version_label=version,
        ingest=IngestResult(source_path="policy.md", source_hash=digest, markdown=text),
        statements=[ControlStatement(statement_id="policy:one", text=text, content_hash=digest)])


def _start_workers(gate):
    global _START_GATE
    _START_GATE = gate


def _worker(args):
    root, version = args
    original = PolicyLineageStore._write_statement
    def slow_write(self, statement):
        time.sleep(0.05)  # Widen the old read-HEAD/write-snapshot race.
        return original(self, statement)
    _START_GATE.wait(timeout=10)
    PolicyLineageStore._write_statement = slow_write
    try:
        return _commit(root, version).snapshot_id
    finally:
        PolicyLineageStore._write_statement = original


@pytest.mark.parametrize("identical", [False, True])
def test_multiple_processes_preserve_all_revisions(tmp_path, identical):
    root = str(tmp_path / "store")
    baseline = _commit(root, "base")
    versions = ["next" if identical else f"v{i}" for i in range(12)]
    context = multiprocessing.get_context("spawn")
    with ProcessPoolExecutor(max_workers=4, mp_context=context, initializer=_start_workers,
                             initargs=(context.Barrier(4),)) as pool:
        ids = list(pool.map(_worker, [(root, v) for v in versions]))
    store = PolicyLineageStore(root)
    chain = store.history("policy")
    assert len(chain) == (2 if identical else 13)
    assert chain[-1] == baseline
    assert {s.snapshot_id for s in chain[:-1]} == set(ids)
    events = [json.loads(line) for line in (store.docs / "policy" / "log.jsonl").read_text().splitlines()]
    assert [event["snapshot_id"] for event in events] == [s.snapshot_id for s in reversed(chain)]


@pytest.mark.parametrize("point", ["journal", "log", "head"])
def test_interrupted_publish_recovers_exactly_once(tmp_path, monkeypatch, point):
    from grc_pdf_mapper import lineage
    root = tmp_path / "store"
    first = _commit(root, "base")
    original = lineage._atomic_text
    target = {"journal": ".pending-commit.json", "log": "log.jsonl", "head": "HEAD"}[point]
    def interrupt(path, content):
        original(path, content)
        if path.name == target:
            raise OSError("simulated process interruption")
    with monkeypatch.context() as patch:
        patch.setattr(lineage, "_atomic_text", interrupt)
        with pytest.raises(OSError):
            _commit(root, "next")
    restarted = PolicyLineageStore(root)
    recovered = restarted.recover("policy")
    assert recovered.version_label == "next" and recovered.parent_snapshot_id == first.snapshot_id
    assert restarted.recover("policy") == recovered
    assert _commit(root, "next") == recovered
    assert len(restarted.history("policy")) == 2
    assert len((restarted.docs / "policy" / "log.jsonl").read_text().splitlines()) == 2
    assert not (restarted.docs / "policy" / ".pending-commit.json").exists()


def _crash_after_journal(root):
    from grc_pdf_mapper import lineage
    original = lineage._atomic_text
    def crash(path, content):
        original(path, content)
        if path.name == ".pending-commit.json":
            os._exit(73)
    lineage._atomic_text = crash
    _commit(root, "next")


def test_process_death_releases_lock_and_head_read_recovers(tmp_path):
    first = _commit(tmp_path, "base")
    proc = multiprocessing.get_context("spawn").Process(target=_crash_after_journal, args=(str(tmp_path),))
    proc.start()
    proc.join(timeout=10)
    if proc.is_alive():
        proc.kill()
        proc.join()
        pytest.fail("commit process did not exit")
    assert proc.exitcode == 73
    recovered = PolicyLineageStore(tmp_path).head("policy")
    assert recovered.version_label == "next" and recovered.parent_snapshot_id == first.snapshot_id


def test_lock_timeout_does_not_write_objects(tmp_path):
    import fcntl
    store = PolicyLineageStore(tmp_path, lock_timeout=0.05)
    with (tmp_path / ".writer.lock").open("a") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        with pytest.raises(TimeoutError):
            store.commit(doc_id="policy", version_label="v1", statements=[],
                         ingest=IngestResult(source_path="x", source_hash="x", markdown="x"))
    assert not list(store.objects.iterdir())


def test_invalid_recovery_intent_does_not_change_head(tmp_path):
    first = _commit(tmp_path)
    directory = tmp_path / "docs" / "policy"
    (directory / ".pending-commit.json").write_text(json.dumps({"snapshot_id": "../../escape"}))
    with pytest.raises(ValueError):
        PolicyLineageStore(tmp_path).recover("policy")
    assert (directory / "HEAD").read_text() == first.snapshot_id


def test_retry_reuses_complete_orphan_before_intent(tmp_path, monkeypatch):
    from grc_pdf_mapper import lineage
    first = _commit(tmp_path, "base")
    original = lineage._atomic_text
    def fail_before_intent(path, content):
        if path.name == ".pending-commit.json":
            raise OSError("interrupted before intent")
        original(path, content)
    with monkeypatch.context() as patch:
        patch.setattr(lineage, "_atomic_text", fail_before_intent)
        with pytest.raises(OSError):
            _commit(tmp_path, "next")
    store = PolicyLineageStore(tmp_path)
    assert store.head("policy") == first
    orphan_path, = [p for p in (store.docs / "policy").glob("*.json") if p.stem != first.snapshot_id]
    orphan_bytes = orphan_path.read_bytes()
    retried = _commit(tmp_path, "next")
    assert retried.snapshot_id == orphan_path.stem
    assert orphan_path.read_bytes() == orphan_bytes
    assert len(store.history("policy")) == 2


def test_recovery_refuses_to_move_an_unexpected_head(tmp_path, monkeypatch):
    from grc_pdf_mapper import lineage
    first = _commit(tmp_path, "base")
    _commit(tmp_path, "middle")
    original = lineage._atomic_text
    def stop_after_intent(path, content):
        original(path, content)
        if path.name == ".pending-commit.json":
            raise OSError("interrupted")
    with monkeypatch.context() as patch:
        patch.setattr(lineage, "_atomic_text", stop_after_intent)
        with pytest.raises(OSError):
            _commit(tmp_path, "next")
    head_path = tmp_path / "docs" / "policy" / "HEAD"
    head_path.write_text(first.snapshot_id)
    with pytest.raises(ValueError, match="conflicts with HEAD"):
        PolicyLineageStore(tmp_path).recover("policy")
    assert head_path.read_text() == first.snapshot_id


def test_pipeline_compares_actual_parent_and_skips_duplicate_alerts(tmp_path, monkeypatch):
    from grc_pdf_mapper.pipeline import analyze_document
    store = PolicyLineageStore(tmp_path / "store")
    source = Path(__file__).parent / "fixtures" / "access_control_policy_v1.md"
    analyze_document(source, store=store, doc_id="policy", offline=True, version_label="base")
    original = store.commit_with_result
    intervening = []
    def commit_after_another_writer(**kwargs):
        if not intervening:
            intervening.append(original(**{**kwargs, "version_label": "intervening"}).snapshot)
        return original(**kwargs)
    monkeypatch.setattr(store, "commit_with_result", commit_after_another_writer)
    published = []
    class Router:
        def publish(self, alert):
            published.append(alert)
    report = analyze_document(source, store=store, doc_id="policy", offline=True,
                              version_label="next", alert_router=Router())
    assert len(published) == 1
    assert published[0].older_snapshot_id == intervening[0].snapshot_id
    assert published[0].newer_snapshot_id == report.snapshot_id
    analyze_document(source, store=store, doc_id="policy", offline=True,
                     version_label="next", alert_router=Router())
    assert len(published) == 1


def test_watcher_compares_actual_parent_after_another_writer(tmp_path, monkeypatch):
    from grc_pdf_mapper.watch import PolicyWatcher
    store = PolicyLineageStore(tmp_path / "store")
    source = tmp_path / "policy.md"
    source.write_text("Users must use MFA.")
    published = []
    class Router:
        def publish(self, alert):
            published.append(alert)
    watcher = PolicyWatcher(store, router=Router())
    watcher.add(source, doc_id="policy")
    assert watcher.poll_once() == []
    original = store.commit_with_result
    intervening = []
    def interleave(**kwargs):
        intervening.append(original(**{**kwargs, "version_label": "intervening"}).snapshot)
        return original(**kwargs)
    monkeypatch.setattr(store, "commit_with_result", interleave)
    source.write_text("Users should use MFA.")
    alerts = watcher.poll_once()
    assert len(alerts) == 1
    assert alerts[0].older_snapshot_id == intervening[0].snapshot_id
    assert alerts[0].metadata["trigger"] == "watch"
    assert alerts[0].metadata["content_hash"] == hashlib.sha256(source.read_bytes()).hexdigest()
