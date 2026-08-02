"""Watch policy files and emit real-time GRC impact alerts on change."""

from __future__ import annotations

import hashlib
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from grc_pdf_mapper.alerts import AlertRouter, default_router
from grc_pdf_mapper.assessments import AssessmentRegistry
from grc_pdf_mapper.impact import analyze_impact
from grc_pdf_mapper.lineage import PolicyLineageStore
from grc_pdf_mapper.models import ImpactAlert
from grc_pdf_mapper.pipeline import analyze_document


@dataclass
class WatchedDoc:
    path: Path
    doc_id: str
    last_hash: str | None = None


class PolicyWatcher:
    """
    Poll watched files. On content change:
      1) commit a new lineage version
      2) analyze framework/assessment impact
      3) publish alerts to configured sinks
    """

    def __init__(
        self,
        store: PolicyLineageStore,
        *,
        router: AlertRouter | None = None,
        assessments: AssessmentRegistry | None = None,
        offline: bool = True,
        author: str = "policy-watcher",
    ) -> None:
        self.store = store
        self.router = router or default_router(store.root)
        self.assessments = assessments or AssessmentRegistry()
        self.offline = offline
        self.author = author
        self.watched: list[WatchedDoc] = []

    def add(self, path: str | Path, *, doc_id: str | None = None) -> None:
        path = Path(path).resolve()
        if not path.exists():
            raise FileNotFoundError(path)
        slug = doc_id or path.stem.lower().replace(" ", "-")
        # last_hash starts unset so the first poll creates a baseline snapshot.
        self.watched.append(WatchedDoc(path=path, doc_id=slug, last_hash=None))

    def poll_once(self) -> list[ImpactAlert]:
        alerts: list[ImpactAlert] = []
        for item in self.watched:
            if not item.path.exists():
                continue
            digest = _file_hash(item.path)
            if digest == item.last_hash:
                continue
            alert = self._handle_change(item, digest)
            if alert:
                alerts.append(alert)
            item.last_hash = digest
        return alerts

    def run(self, *, interval_seconds: float = 2.0, once: bool = False) -> list[ImpactAlert]:
        collected: list[ImpactAlert] = []
        while True:
            collected.extend(self.poll_once())
            if once:
                return collected
            time.sleep(interval_seconds)

    def _handle_change(self, item: WatchedDoc, digest: str) -> ImpactAlert | None:
        previous = self.store.head(item.doc_id)
        version = datetime.now(timezone.utc).strftime("auto-%Y%m%dT%H%M%SZ")
        report = analyze_document(
            item.path,
            doc_id=item.doc_id,
            store=self.store,
            version_label=version,
            author=self.author,
            offline=self.offline,
            commit=True,
            alert_on_change=False,  # watcher publishes explicitly below
        )
        if not previous:
            # First seen: baseline only, no alert noise.
            return None
        if previous.snapshot_id == report.snapshot_id:
            return None

        alert = analyze_impact(
            self.store,
            item.doc_id,
            previous.snapshot_id,
            report.snapshot_id,
            assessments=self.assessments.active(),
            offline=self.offline,
        )
        alert.metadata.update(
            {
                "source_path": str(item.path),
                "content_hash": digest,
                "trigger": "watch",
            }
        )
        self.router.publish(alert)
        return alert


def _file_hash(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()
