"""Git-style lineage store for policy / procedure documents."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

from grc_pdf_mapper.models import ControlStatement, DocumentSnapshot, DriftFinding, IngestResult


class PolicyLineageStore:
    """
    Content-addressed document history.

    Layout:
      store/
        objects/<sha256>          # raw markdown blobs
        statements/<stmt_id>.json # statement objects
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
        markdown_hash = self._write_blob(ingest.markdown)
        parent = self.head(doc_id)

        for stmt in statements:
            self._write_statement(stmt)

        snapshot = DocumentSnapshot(
            snapshot_id=self._snapshot_id(doc_id, markdown_hash, version_label),
            doc_id=doc_id,
            version_label=version_label,
            source_hash=ingest.source_hash,
            markdown_hash=markdown_hash,
            parent_snapshot_id=parent.snapshot_id if parent else None,
            title=ingest.title,
            author=author,
            approval_status=approval_status,
            statement_ids=[s.statement_id for s in statements],
            metadata=metadata or {},
        )
        doc_dir = self.docs / doc_id
        doc_dir.mkdir(parents=True, exist_ok=True)
        snap_path = doc_dir / f"{snapshot.snapshot_id}.json"
        snap_path.write_text(snapshot.model_dump_json(indent=2), encoding="utf-8")
        (doc_dir / "HEAD").write_text(snapshot.snapshot_id, encoding="utf-8")
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
        head_path = self.docs / doc_id / "HEAD"
        if not head_path.exists():
            return None
        return self.get_snapshot(doc_id, head_path.read_text(encoding="utf-8").strip())

    def get_snapshot(self, doc_id: str, snapshot_id: str) -> DocumentSnapshot | None:
        path = self.docs / doc_id / f"{snapshot_id}.json"
        if not path.exists():
            return None
        return DocumentSnapshot.model_validate_json(path.read_text(encoding="utf-8"))

    def history(self, doc_id: str) -> list[DocumentSnapshot]:
        chain: list[DocumentSnapshot] = []
        current = self.head(doc_id)
        while current:
            chain.append(current)
            if not current.parent_snapshot_id:
                break
            current = self.get_snapshot(doc_id, current.parent_snapshot_id)
        return chain

    def read_markdown(self, markdown_hash: str) -> str:
        path = self.objects / markdown_hash
        return path.read_text(encoding="utf-8")

    def load_statements(self, statement_ids: list[str]) -> list[ControlStatement]:
        out: list[ControlStatement] = []
        for sid in statement_ids:
            path = self.statements / f"{_safe_name(sid)}.json"
            if path.exists():
                out.append(ControlStatement.model_validate_json(path.read_text(encoding="utf-8")))
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
        left_map = {s.content_hash: s for s in self.load_statements(left.statement_ids)}
        right_map = {s.content_hash: s for s in self.load_statements(right.statement_ids)}
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
            for s in self.load_statements(older.statement_ids):
                older_ids.update(s.candidate_framework_ids)
            for s in self.load_statements(newer.statement_ids):
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
        if not path.exists():
            path.write_text(markdown, encoding="utf-8")
        return digest

    def _write_statement(self, stmt: ControlStatement) -> None:
        path = self.statements / f"{_safe_name(stmt.statement_id)}.json"
        path.write_text(stmt.model_dump_json(indent=2), encoding="utf-8")

    def _snapshot_id(self, doc_id: str, markdown_hash: str, version_label: str) -> str:
        material = f"{doc_id}:{markdown_hash}:{version_label}".encode("utf-8")
        return hashlib.sha256(material).hexdigest()[:20]


def _safe_name(statement_id: str) -> str:
    return statement_id.replace("/", "_").replace(":", "__")
