"""Alert delivery for GRC impact events."""

from __future__ import annotations

import json
from abc import ABC, abstractmethod
from datetime import datetime, timezone
from pathlib import Path

import httpx

from grc_pdf_mapper.models import ImpactAlert


class AlertSink(ABC):
    @abstractmethod
    def emit(self, alert: ImpactAlert) -> None:
        raise NotImplementedError


class JsonlAlertSink(AlertSink):
    """Append alerts to a JSONL file for dashboards / SIEM shipping."""

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)

    def emit(self, alert: ImpactAlert) -> None:
        with self.path.open("a", encoding="utf-8") as fh:
            fh.write(alert.model_dump_json() + "\n")


class ConsoleAlertSink(AlertSink):
    def emit(self, alert: ImpactAlert) -> None:
        print(f"\n=== GRC IMPACT ALERT [{alert.severity.value.upper()}] ===")
        print(alert.summary)
        if alert.frameworks_impacted:
            print("Frameworks:")
            for fw in alert.frameworks_impacted:
                controls = ", ".join(fw.control_ids[:6])
                print(f"  - {fw.framework} [{fw.risk.value}]: {controls}")
        if alert.assessments_impacted:
            print("Assessments:")
            for a in alert.assessments_impacted:
                print(f"  - {a.assessment_name} [{a.risk.value}]: {a.reason}")
        if alert.recommended_actions:
            print("Actions:")
            for action in alert.recommended_actions:
                print(f"  * {action}")
        print("=== END ALERT ===\n")


class WebhookAlertSink(AlertSink):
    """POST alert JSON to Slack/Teams/Pager-compatible webhook URLs."""

    def __init__(self, url: str, *, timeout: float = 10.0) -> None:
        self.url = url
        self.timeout = timeout

    def emit(self, alert: ImpactAlert) -> None:
        payload = {
            "text": alert.summary,
            "alert": json.loads(alert.model_dump_json()),
        }
        # Slack-friendly top-level text; generic tools can read `alert`.
        with httpx.Client(timeout=self.timeout) as client:
            resp = client.post(self.url, json=payload)
            resp.raise_for_status()


class AlertRouter:
    """Fan-out alerts to one or more sinks and keep an in-store index."""

    def __init__(
        self,
        sinks: list[AlertSink] | None = None,
        *,
        index_path: str | Path | None = None,
    ) -> None:
        self.sinks = sinks or []
        self.index_path = Path(index_path) if index_path else None
        if self.index_path:
            self.index_path.parent.mkdir(parents=True, exist_ok=True)

    def publish(self, alert: ImpactAlert) -> ImpactAlert:
        for sink in self.sinks:
            sink.emit(alert)
        if self.index_path:
            with self.index_path.open("a", encoding="utf-8") as fh:
                fh.write(
                    json.dumps(
                        {
                            "alert_id": alert.alert_id,
                            "created_at": alert.created_at.isoformat(),
                            "doc_id": alert.doc_id,
                            "severity": alert.severity.value,
                            "summary": alert.summary,
                            "assessments": [a.assessment_id for a in alert.assessments_impacted],
                            "frameworks": [f.framework for f in alert.frameworks_impacted],
                        }
                    )
                    + "\n"
                )
        return alert

    @staticmethod
    def read_alerts(path: str | Path, *, min_severity: str | None = None) -> list[dict]:
        path = Path(path)
        if not path.exists():
            return []
        order = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
        min_rank = order.get(min_severity or "info", 0)
        alerts: list[dict] = []
        for line in path.read_text(encoding="utf-8").splitlines():
            if not line.strip():
                continue
            item = json.loads(line)
            if order.get(str(item.get("severity", "info")), 0) >= min_rank:
                alerts.append(item)
        return alerts


def default_router(store_root: str | Path, *, webhook_url: str | None = None) -> AlertRouter:
    root = Path(store_root)
    sinks: list[AlertSink] = [
        ConsoleAlertSink(),
        JsonlAlertSink(root / "alerts" / "alerts.jsonl"),
    ]
    if webhook_url:
        sinks.append(WebhookAlertSink(webhook_url))
    return AlertRouter(sinks, index_path=root / "alerts" / "index.jsonl")


def utc_now() -> datetime:
    return datetime.now(timezone.utc)
