"""Document history must not change when a version is imported again."""
import hashlib
import json

import pytest

from grc_pdf_mapper.lineage import PolicyLineageStore
from grc_pdf_mapper.models import ControlStatement, IngestResult


def commit(store, text="Users must use MFA.", **kwargs):
    statement = ControlStatement(statement_id="policy:one", text=text,
                                 content_hash=hashlib.sha256(text.encode()).hexdigest())
    ingest = IngestResult(source_path="policy.md", source_hash=hashlib.sha256(text.encode()).hexdigest(),
                          markdown=text, title="Policy")
    options = dict(doc_id="policy", ingest=ingest, statements=[statement], version_label="v1")
    options.update(kwargs)
    return store.commit(**options)


def test_repeated_import_is_idempotent(tmp_path):
    store = PolicyLineageStore(tmp_path)
    first = commit(store)
    before = (store.docs / "policy" / f"{first.snapshot_id}.json").read_bytes()
    again = commit(store)
    assert again.parent_snapshot_id is None
    assert again == first
    assert (store.docs / "policy" / f"{first.snapshot_id}.json").read_bytes() == before
    assert len((store.docs / "policy" / "log.jsonl").read_text().splitlines()) == 1
    assert store.history("policy") == [first]


def test_reverting_content_creates_a_new_child_without_rewriting_history(tmp_path):
    store = PolicyLineageStore(tmp_path)
    first = commit(store)
    second = commit(store, "Users may use MFA.")
    restored = commit(store)
    assert restored.snapshot_id != first.snapshot_id
    assert restored.parent_snapshot_id == second.snapshot_id
    assert store.get_snapshot("policy", first.snapshot_id) == first
    assert store.history("policy") == [restored, second, first]


def test_metadata_and_statement_changes_have_distinct_snapshots(tmp_path):
    store = PolicyLineageStore(tmp_path)
    first = commit(store, author="Alice", metadata={"review": "pending"})
    second = commit(store, author="Bob", metadata={"review": "done"})
    refined = ControlStatement(statement_id="policy:one", text="Users must use MFA.",
                               content_hash="same-content", classification_confidence=0.9)
    third = commit(store, author="Bob", metadata={"review": "done"}, statements=[refined])
    assert len({first.snapshot_id, second.snapshot_id, third.snapshot_id}) == 3
    old = store.load_statements(first.statement_ids, statement_hashes=first.statement_hashes)
    new = store.load_statements(third.statement_ids, statement_hashes=third.statement_hashes)
    assert old[0].classification_confidence == 0
    assert new == [refined]


@pytest.mark.parametrize("broken", ["cycle", "missing_parent", "wrong_identity", "missing_head"])
def test_corrupt_history_fails_explicitly(tmp_path, broken, monkeypatch):
    store = PolicyLineageStore(tmp_path)
    first = commit(store)
    path = store.docs / "policy" / f"{first.snapshot_id}.json"
    content = json.loads(path.read_text())
    if broken == "missing_head":
        path.unlink()
    elif broken == "wrong_identity":
        content["doc_id"] = "other"
        path.write_text(json.dumps(content))
    else:
        content["parent_snapshot_id"] = first.snapshot_id if broken == "cycle" else "0" * 20
        path.write_text(json.dumps(content))
    # A guard also makes the regression fail promptly on the old infinite loop.
    original = store.get_snapshot
    calls = 0
    def bounded(*args):
        nonlocal calls
        calls += 1
        if calls > 5:
            pytest.fail("history did not detect the cycle")
        return original(*args)
    monkeypatch.setattr(store, "get_snapshot", bounded)
    with pytest.raises(ValueError):
        store.history("policy")


@pytest.mark.parametrize("doc_id", ["../escape", "/tmp/escape", "a/b", "a\\b", "..", "", "bad\x00id"])
def test_document_ids_cannot_escape_store(tmp_path, doc_id):
    store = PolicyLineageStore(tmp_path / "store")
    with pytest.raises(ValueError):
        commit(store, doc_id=doc_id)
    assert not list(store.objects.iterdir())


def test_object_reads_reject_invalid_identifiers_and_tampering(tmp_path):
    store = PolicyLineageStore(tmp_path)
    snap = commit(store)
    with pytest.raises(ValueError):
        store.get_snapshot("policy", "../../outside")
    with pytest.raises(ValueError):
        store.read_markdown("../outside")
    (store.objects / snap.markdown_hash).write_text("tampered")
    with pytest.raises(ValueError, match="hash"):
        store.read_markdown(snap.markdown_hash)
    with pytest.raises(ValueError, match="hash"):
        commit(store)


def test_missing_or_changed_statement_is_not_silently_omitted(tmp_path):
    store = PolicyLineageStore(tmp_path)
    snap = commit(store)
    digest = snap.statement_hashes["policy:one"]
    path = store.statements / "by-hash" / f"{digest}.json"
    path.write_text("{}")
    with pytest.raises(ValueError, match="hash"):
        store.load_statements(snap.statement_ids, statement_hashes=snap.statement_hashes)
    path.unlink()
    with pytest.raises(ValueError, match="Missing statement"):
        store.load_statements(snap.statement_ids, statement_hashes=snap.statement_hashes)


def test_legacy_snapshot_and_statement_files_remain_readable(tmp_path):
    store = PolicyLineageStore(tmp_path)
    statement = ControlStatement(statement_id="old:one", text="Users must use MFA.")
    (store.statements / "old__one.json").write_text(statement.model_dump_json())
    doc = store.docs / "legacy"
    doc.mkdir()
    legacy = {"snapshot_id": "a" * 20, "doc_id": "legacy", "version_label": "v0",
              "source_hash": "b" * 64, "markdown_hash": "c" * 64, "statement_ids": ["old:one"]}
    path = doc / ("a" * 20 + ".json")
    path.write_text(json.dumps(legacy))
    (doc / "HEAD").write_text("a" * 20)
    snapshot = store.head("legacy")
    assert store.load_statements(snapshot.statement_ids, statement_hashes=snapshot.statement_hashes) == [statement]
    commit(store, doc_id="legacy", statements=[statement.model_copy(update={"text": "New wording"})])
    assert json.loads(path.read_text()) == legacy
    assert store.load_statements(snapshot.statement_ids, statement_hashes=snapshot.statement_hashes) == [statement]


def test_new_snapshot_metadata_is_checked_against_its_hash(tmp_path):
    store = PolicyLineageStore(tmp_path)
    snap = commit(store)
    path = store.docs / "policy" / f"{snap.snapshot_id}.json"
    content = json.loads(path.read_text())
    content["approval_status"] = "approved"
    path.write_text(json.dumps(content))
    with pytest.raises(ValueError, match="Snapshot hash"):
        store.head("policy")


def test_legacy_cycle_is_detected(tmp_path):
    store = PolicyLineageStore(tmp_path)
    doc = store.docs / "legacy"
    doc.mkdir()
    for sid, parent in [("a" * 20, "b" * 20), ("b" * 20, "a" * 20)]:
        (doc / f"{sid}.json").write_text(json.dumps({
            "snapshot_id": sid, "doc_id": "legacy", "version_label": "v0",
            "source_hash": "c" * 64, "markdown_hash": "d" * 64, "parent_snapshot_id": parent}))
    (doc / "HEAD").write_text("a" * 20)
    # Check the already-tested cycle gate before traversing deliberately cyclic data.
    with pytest.raises(ValueError, match="Cycle"):
        store.history("legacy")


def test_document_directory_symlink_is_rejected_before_writes(tmp_path):
    store = PolicyLineageStore(tmp_path / "store")
    outside = tmp_path / "outside"
    outside.mkdir()
    (store.docs / "policy").symlink_to(outside, target_is_directory=True)
    with pytest.raises(ValueError, match="symlink"):
        commit(store)
    assert not list(outside.iterdir())
