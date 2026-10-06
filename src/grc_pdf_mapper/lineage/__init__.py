"""Git-style lineage store for policy / procedure documents."""

from __future__ import annotations

import hashlib
import json
import os
import re
import tempfile
from pathlib import Path
from typing import Any

from grc_pdf_mapper.models import ControlStatement, DocumentSnapshot, DriftFinding, IngestResult


class PolicyLineageStore:
    """
    Content-addressed document history.

    Layout:
      store/
        objects/<sha256>          # raw markdown blobs
        statements/<stmt_id>.json # legacy statement objects (read only)
        statements/by-hash/<sha256>.json # exact statement revisions
        docs/<doc_id>/HEAD        # current snapshot id
        docs/<doc_id>/<snap>.json # snapshot metadata
        docs/<doc_id>/log.jsonl   # append-only event log
    """

    def __init__(self, root: str | Path) -> None:
        self.root = Path(root)
        self.objects = self.root / "objects"
        self.statements = self.root / "statements"
        self.docs = self.root / "docs"
        for path in (self.objects, self.statements, self.docs):
            if path.is_symlink():
                raise ValueError("Store directories must not be symlinks")
            path.mkdir(parents=True, exist_ok=True)

    def commit(
        self,
        *,
        doc_id: str,
        ingest: IngestResult,
        statements: list[ControlStatement],
        version_label: str,
        author: str | None = None,
        approval_status: str = "draft",
        metadata: dict[str, Any] | None = None,
    ) -> DocumentSnapshot:
        doc_dir = self._doc_dir(doc_id)
        parent = self.head(doc_id)
        statement_hashes: dict[str, str] = {}
        for stmt in statements:
            if stmt.statement_id in statement_hashes:
                raise ValueError("Duplicate statement id")
            statement_hashes[stmt.statement_id] = self._write_statement(stmt)
        markdown_hash = self._write_blob(ingest.markdown)

        snapshot = DocumentSnapshot(
            snapshot_id="",
            doc_id=doc_id,
            version_label=version_label,
            format_version=2,
            source_hash=ingest.source_hash,
            markdown_hash=markdown_hash,
            parent_snapshot_id=parent.snapshot_id if parent else None,
            title=ingest.title,
            author=author,
            approval_status=approval_status,
            statement_ids=[s.statement_id for s in statements],
            statement_hashes=statement_hashes,
            metadata=metadata or {},
        )
        # Identical retries return the existing revision and do not append another event.
        ignored = {"snapshot_id", "created_at", "parent_snapshot_id"}
        if parent and parent.model_dump(mode="json", exclude=ignored) == snapshot.model_dump(mode="json", exclude=ignored):
            return parent
        snapshot.snapshot_id = _snapshot_digest(snapshot)
        doc_dir.mkdir(parents=True, exist_ok=True)
        snap_path = doc_dir / f"{snapshot.snapshot_id}.json"
        # Never overwrite an earlier revision, including after a content reversion.
        with snap_path.open("x", encoding="utf-8") as fh:
            fh.write(snapshot.model_dump_json(indent=2))
        _atomic_text(doc_dir / "HEAD", snapshot.snapshot_id)
        with (doc_dir / "log.jsonl").open("a", encoding="utf-8") as fh:
            fh.write(
                json.dumps(
                    {
                        "event": "commit",
                        "snapshot_id": snapshot.snapshot_id,
                        "version_label": version_label,
                        "author": author,
                        "approval_status": approval_status,
                        "statement_count": len(statements),
                    }
                )
                + "\n"
            )
        return snapshot

    def head(self, doc_id: str) -> DocumentSnapshot | None:
        head_path = self._doc_dir(doc_id) / "HEAD"
        _reject_symlink(head_path)
        if not head_path.exists():
            return None
        snapshot = self.get_snapshot(doc_id, head_path.read_text(encoding="utf-8").strip())
        if snapshot is None:
            raise ValueError("HEAD refers to a missing snapshot")
        return snapshot

    def get_snapshot(self, doc_id: str, snapshot_id: str) -> DocumentSnapshot | None:
        _validate_digest(snapshot_id, length=20)
        path = self._doc_dir(doc_id) / f"{snapshot_id}.json"
        _reject_symlink(path)
        if not path.exists():
            return None
        snapshot = DocumentSnapshot.model_validate_json(path.read_text(encoding="utf-8"))
        if snapshot.doc_id != doc_id or snapshot.snapshot_id != snapshot_id:
            raise ValueError("Snapshot identity does not match its path")
        if snapshot.format_version not in {1, 2}:
            raise ValueError("Unsupported snapshot format version")
        if snapshot.format_version == 2:
            if _snapshot_digest(snapshot) != snapshot_id:
                raise ValueError("Snapshot hash mismatch")
            if set(snapshot.statement_hashes) != set(snapshot.statement_ids):
                raise ValueError("Statement hash references do not match snapshot ids")
        return snapshot

    def history(self, doc_id: str) -> list[DocumentSnapshot]:
        chain: list[DocumentSnapshot] = []
        seen: set[str] = set()
        current = self.head(doc_id)
        while current:
            if current.snapshot_id in seen:
                raise ValueError("Cycle in snapshot history")
            seen.add(current.snapshot_id)
            chain.append(current)
            if not current.parent_snapshot_id:
                break
            current = self.get_snapshot(doc_id, current.parent_snapshot_id)
            if current is None:
                raise ValueError("Missing parent snapshot")
        return chain

    def read_markdown(self, markdown_hash: str) -> str:
        _validate_digest(markdown_hash)
        path = self.objects / markdown_hash
        return _read_hashed(path, markdown_hash).decode("utf-8")

    def load_statements(self, statement_ids: list[str], *,
                        statement_hashes: dict[str, str] | None = None) -> list[ControlStatement]:
        """Pass a snapshot's hashes for exact revisions; empty hashes read legacy objects."""
        out: list[ControlStatement] = []
        if statement_hashes and set(statement_hashes) != set(statement_ids):
            raise ValueError("Statement hash references do not match snapshot ids")
        for sid in statement_ids:
            if statement_hashes:
                digest = statement_hashes[sid]
                _validate_digest(digest)
                directory = self.statements / "by-hash"
                _reject_symlink(directory)
                path = directory / f"{digest}.json"
            else:
                path = self.statements / f"{_safe_name(sid)}.json"
            _reject_symlink(path)
            if not path.is_file():
                raise ValueError(f"Missing statement object: {sid}")
            raw = _read_hashed(path, digest) if statement_hashes else path.read_bytes()
            statement = ControlStatement.model_validate_json(raw)
            if statement.statement_id != sid:
                raise ValueError("Statement identity does not match its reference")
            out.append(statement)
        return out

    def diff_statements(
        self,
        doc_id: str,
        from_snapshot_id: str,
        to_snapshot_id: str,
    ) -> dict[str, list[ControlStatement]]:
        left = self.get_snapshot(doc_id, from_snapshot_id)
        right = self.get_snapshot(doc_id, to_snapshot_id)
        if not left or not right:
            raise ValueError("Unknown snapshot id")
        left_map = {s.content_hash: s for s in self.load_statements(left.statement_ids, statement_hashes=left.statement_hashes)}
        right_map = {s.content_hash: s for s in self.load_statements(right.statement_ids, statement_hashes=right.statement_hashes)}
        added = [right_map[h] for h in right_map.keys() - left_map.keys()]
        removed = [left_map[h] for h in left_map.keys() - right_map.keys()]
        return {"added": added, "removed": removed}

    def detect_drift(self, doc_id: str, older_id: str, newer_id: str) -> list[DriftFinding]:
        """Find control-coverage regressions between two snapshots."""
        diff = self.diff_statements(doc_id, older_id, newer_id)
        findings: list[DriftFinding] = []
        for stmt in diff["removed"]:
            severity = "high" if stmt.strength.value in {"must", "shall", "prohibited"} else "medium"
            findings.append(
                DriftFinding(
                    kind="obligation_removed",
                    detail=f"Removed obligation: {stmt.text[:160]}",
                    statement_id=stmt.statement_id,
                    severity=severity,
                )
            )
        for stmt in diff["added"]:
            findings.append(
                DriftFinding(
                    kind="obligation_added",
                    detail=f"Added obligation: {stmt.text[:160]}",
                    statement_id=stmt.statement_id,
                    severity="info",
                )
            )

        older = self.get_snapshot(doc_id, older_id)
        newer = self.get_snapshot(doc_id, newer_id)
        if older and newer:
            older_ids = set()
            newer_ids = set()
            for s in self.load_statements(older.statement_ids, statement_hashes=older.statement_hashes):
                older_ids.update(s.candidate_framework_ids)
            for s in self.load_statements(newer.statement_ids, statement_hashes=newer.statement_hashes):
                newer_ids.update(s.candidate_framework_ids)
            for lost in sorted(older_ids - newer_ids):
                findings.append(
                    DriftFinding(
                        kind="framework_citation_lost",
                        detail=f"Document no longer cites control {lost}",
                        severity="high",
                    )
                )
        return findings

    def _write_blob(self, markdown: str) -> str:
        digest = hashlib.sha256(markdown.encode("utf-8")).hexdigest()
        path = self.objects / digest
        _write_hashed(path, markdown.encode("utf-8"), digest)
        return digest

    def _write_statement(self, stmt: ControlStatement) -> str:
        raw = _canonical(stmt.model_dump(mode="json"))
        digest = hashlib.sha256(raw).hexdigest()
        directory = self.statements / "by-hash"
        _reject_symlink(directory)
        directory.mkdir(exist_ok=True)
        _write_hashed(directory / f"{digest}.json", raw, digest)
        return digest

    def _doc_dir(self, doc_id: str) -> Path:
        if (not isinstance(doc_id, str) or not doc_id.strip() or doc_id in {".", ".."}
                or len(doc_id) > 128 or any(c in doc_id for c in "/\\")
                or any(ord(c) < 32 or ord(c) == 127 for c in doc_id)):
            raise ValueError("Document id must be one nonempty path component (at most 128 characters)")
        path = self.docs / doc_id
        _reject_symlink(path)
        return path


def _safe_name(statement_id: str) -> str:
    if not isinstance(statement_id, str) or "\\" in statement_id or any(ord(c) < 32 for c in statement_id):
        raise ValueError("Invalid legacy statement id")
    return statement_id.replace("/", "_").replace(":", "__")


def _canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
                      allow_nan=False).encode("utf-8")


def _snapshot_digest(snapshot: DocumentSnapshot) -> str:
    material = snapshot.model_dump(mode="json", exclude={"snapshot_id", "created_at"})
    return hashlib.sha256(_canonical(material)).hexdigest()[:20]


def _validate_digest(value: str, *, length: int = 64) -> None:
    if not isinstance(value, str) or re.fullmatch(r"[0-9a-f]{%d}" % length, value) is None:
        raise ValueError("Invalid object hash identifier")


def _reject_symlink(path: Path) -> None:
    if path.is_symlink():
        raise ValueError("Lineage paths must not be symlinks")


def _read_hashed(path: Path, digest: str) -> bytes:
    _reject_symlink(path)
    raw = path.read_bytes()
    if hashlib.sha256(raw).hexdigest() != digest:
        raise ValueError("Stored object hash mismatch")
    return raw


def _write_hashed(path: Path, raw: bytes, digest: str) -> None:
    _reject_symlink(path)
    if path.exists():
        _read_hashed(path, digest)
        return
    with path.open("xb") as fh:
        fh.write(raw)


def _atomic_text(path: Path, content: str) -> None:
    _reject_symlink(path)
    fd, name = tempfile.mkstemp(dir=path.parent, prefix=".head-")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(content)
        os.replace(name, path)
    finally:
        Path(name).unlink(missing_ok=True)
