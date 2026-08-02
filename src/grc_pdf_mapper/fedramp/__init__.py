"""FedRAMP CR26 Key Security Indicator (KSI) mappings across Classes A–D."""

from __future__ import annotations

import json
import re
from functools import lru_cache
from pathlib import Path

import httpx

from grc_pdf_mapper.models import AlertSeverity, ControlStatement, CrosswalkHit

DEFAULT_CATALOG = (
    Path(__file__).resolve().parents[3] / "lab" / "fedramp" / "cr26_ksi_catalog.json"
)
UPSTREAM_CR26 = (
    "https://raw.githubusercontent.com/FedRAMP/rules/main/fedramp-consolidated-rules.json"
)

_CONTROL_NORM_RE = re.compile(
    r"^(?P<fam>[A-Za-z]{2})-?(?P<num>\d+)(?:[\.(](?P<enh>\d+)\)?)?$"
)


class FedRampKSICatalog:
    """Load CR26 KSI catalog and answer class-aware mapping questions."""

    def __init__(self, catalog_path: str | Path | None = None) -> None:
        self.path = Path(catalog_path) if catalog_path else _default_catalog_path()
        self.data = json.loads(self.path.read_text(encoding="utf-8"))

    @property
    def version(self) -> str:
        return str(self.data.get("source", {}).get("version", "unknown"))

    def domains(self) -> list[dict]:
        return list(self.data.get("domains", {}).values())

    def indicators(self) -> list[dict]:
        out: list[dict] = []
        for domain in self.domains():
            for ind in domain.get("indicators", []):
                row = dict(ind)
                row["domain_id"] = domain.get("id")
                row["domain_name"] = domain.get("name")
                out.append(row)
        return out

    def documentation_requirements(self) -> list[dict]:
        return list(self.data.get("documentation_requirements", []))

    def for_class(self, class_id: str) -> list[dict]:
        """Return indicators applicable to a certification class (a/b/c/d)."""
        cls = class_id.lower().removeprefix("class ").strip()
        rows = []
        for ind in self.indicators():
            applicability = ind.get("class_applicability", {})
            status = applicability.get(cls)
            if status in {None, "not_applicable"}:
                continue
            row = dict(ind)
            row["class"] = cls
            row["class_status"] = status
            row["class_statement"] = (ind.get("class_statements") or {}).get(cls) or ind.get(
                "statement"
            )
            rows.append(row)
        return rows

    def map_control(self, control_id: str, *, class_id: str | None = None) -> list[dict]:
        """Map a NIST-style control id to KSIs (optionally filtered by class)."""
        needle = _normalize_control(control_id)
        hits = []
        for ind in self.indicators():
            nist = [_normalize_control(c) for c in ind.get("controls_nist", [])]
            raw = [_normalize_control(c) for c in ind.get("controls_raw", [])]
            if needle not in nist and needle not in raw and not _family_base_match(needle, nist + raw):
                continue
            if class_id:
                cls = class_id.lower().removeprefix("class ").strip()
                status = ind.get("class_applicability", {}).get(cls)
                if status in {None, "not_applicable"}:
                    continue
                ind = dict(ind)
                ind["class"] = cls
                ind["class_status"] = status
            hits.append(ind)
        return hits

    def map_statement(
        self,
        statement: ControlStatement,
        *,
        class_id: str | None = None,
    ) -> list[CrosswalkHit]:
        """Produce CrosswalkHit rows for FedRAMP KSIs related to a policy statement."""
        hits: list[CrosswalkHit] = []
        seen: set[str] = set()

        # Explicit control citations on the statement.
        for cid in statement.candidate_framework_ids:
            for ind in self.map_control(cid, class_id=class_id):
                if ind["id"] in seen:
                    continue
                seen.add(ind["id"])
                hits.append(_hit_from_indicator(ind, confidence=0.9, relationship="control-map"))

        # Keyword / domain heuristic for IAM-ish policy language.
        text = statement.text.lower()
        keyword_domains = {
            "IAM": ("account", "mfa", "privileged", "authentication", "identity", "least privilege"),
            "MLA": ("log", "audit", "siem", "monitor"),
            "CMT": ("change management", "configuration", "deploy"),
            "INR": ("incident", "breach", "response"),
            "SVC": ("encrypt", "secret", "configuration"),
            "PIY": ("inventory", "policy", "sdlc"),
            "RPL": ("backup", "recovery", "continuity"),
            "SCR": ("vendor", "supply chain", "third party"),
            "CED": ("training", "awareness"),
            "CNA": ("network", "segmentation", "cloud native"),
        }
        for domain, tokens in keyword_domains.items():
            if not any(t in text for t in tokens):
                continue
            for ind in self.indicators():
                if not str(ind.get("id", "")).startswith(f"KSI-{domain}-"):
                    continue
                if class_id:
                    cls = class_id.lower().removeprefix("class ").strip()
                    status = ind.get("class_applicability", {}).get(cls)
                    if status in {None, "not_applicable"}:
                        continue
                    ind = dict(ind)
                    ind["class"] = cls
                    ind["class_status"] = status
                if ind["id"] in seen:
                    continue
                seen.add(ind["id"])
                hits.append(_hit_from_indicator(ind, confidence=0.55, relationship="topic"))
        return hits

    def documentation_matrix(self, class_id: str) -> list[dict]:
        """Documentation / certification-package obligations for one class."""
        cls = class_id.lower().removeprefix("class ").strip()
        rows = []
        for req in self.documentation_requirements():
            by_class = req.get("by_class") or {}
            if cls in by_class:
                body = by_class[cls]
                rows.append(
                    {
                        "id": req["id"],
                        "name": req["name"],
                        "class": cls,
                        "force": body.get("force"),
                        "statement": body.get("statement"),
                        "timeframe_type": body.get("timeframe_type"),
                        "timeframe_num": body.get("timeframe_num"),
                        "following_information": body.get("following_information"),
                        "requires_documentation": True,
                    }
                )
            elif req.get("statement"):
                rows.append(
                    {
                        "id": req["id"],
                        "name": req["name"],
                        "class": cls,
                        "force": "APPLICABLE",
                        "statement": req.get("statement"),
                        "requires_documentation": True,
                    }
                )
        return rows

    def coverage_for_controls(
        self,
        control_ids: list[str],
        *,
        class_id: str,
    ) -> dict:
        """Summarize which KSIs are touched by a set of NIST controls for a class."""
        matched = []
        for cid in control_ids:
            matched.extend(self.map_control(cid, class_id=class_id))
        uniq = {m["id"]: m for m in matched}
        required = [m for m in uniq.values() if m.get("class_status") in {"required", "applicable"}]
        optional = [m for m in uniq.values() if m.get("class_status") == "optional"]
        return {
            "class": class_id.lower().removeprefix("class ").strip(),
            "control_ids": control_ids,
            "ksi_count": len(uniq),
            "required_or_applicable": sorted(required, key=lambda x: x["id"]),
            "optional": sorted(optional, key=lambda x: x["id"]),
            "documentation_requirements": self.documentation_matrix(class_id),
        }


def map_statement_to_ksi(
    statement: ControlStatement,
    *,
    class_id: str | None = None,
    catalog_path: str | Path | None = None,
) -> list[CrosswalkHit]:
    return FedRampKSICatalog(catalog_path).map_statement(statement, class_id=class_id)


def documentation_alerts_for_class(class_id: str, catalog_path: str | Path | None = None) -> list[dict]:
    """Return MUST documentation obligations that certifications require."""
    rows = FedRampKSICatalog(catalog_path).documentation_matrix(class_id)
    return [r for r in rows if str(r.get("force", "")).upper() == "MUST"]


@lru_cache(maxsize=1)
def _default_catalog_path() -> Path:
    candidates = [
        Path(__file__).resolve().parents[3] / "lab" / "fedramp" / "cr26_ksi_catalog.json",
        Path.cwd() / "lab" / "fedramp" / "cr26_ksi_catalog.json",
    ]
    for path in candidates:
        if path.exists():
            return path
    raise FileNotFoundError(
        "CR26 KSI catalog not found. Expected lab/fedramp/cr26_ksi_catalog.json"
    )


def _hit_from_indicator(ind: dict, *, confidence: float, relationship: str) -> CrosswalkHit:
    cls = ind.get("class")
    status = ind.get("class_status")
    title = ind.get("name") or ""
    if cls and status:
        title = f"{title} (Class {cls.upper()}: {status})"
    return CrosswalkHit(
        source="fedramp-cr26-ksi",
        framework="FedRAMP KSI",
        control_id=ind["id"],
        title=title,
        relationship=relationship,
        confidence=confidence,
        url="https://github.com/FedRAMP/rules",
        raw={
            "domain_id": ind.get("domain_id"),
            "domain_name": ind.get("domain_name"),
            "statement": ind.get("class_statement") or ind.get("statement"),
            "controls_nist": ind.get("controls_nist", []),
            "class": cls,
            "class_status": status,
            "documentation_sensitive": ind.get("documentation_sensitive", True),
        },
    )


def _normalize_control(control_id: str) -> str:
    cid = control_id.strip().upper().replace(" ", "")
    cid = cid.replace("_", "-")
    # AC-2(1) or AC-2.1 or ac-2.1
    cid = cid.replace(".", "-")
    m = re.match(r"^([A-Z]{2})-(\d+)(?:\((\d+)\)|-(\d+))?$", cid)
    if not m:
        # try ac-2-1 already
        return cid
    fam, num, enh_paren, enh_dash = m.group(1), m.group(2), m.group(3), m.group(4)
    enh = enh_paren or enh_dash
    return f"{fam}-{int(num)}" + (f"({int(enh)})" if enh else "")


def _family_base_match(needle: str, haystack: list[str]) -> bool:
    """AC-2 matches AC-2(1) family members when searching loosely."""
    base = needle.split("(")[0]
    return any(h == needle or h.startswith(base + "(") or h == base for h in haystack)


def refresh_catalog_from_upstream(
    out_path: str | Path,
    *,
    upstream_url: str = UPSTREAM_CR26,
    timeout: float = 60.0,
) -> Path:
    """Download CR26 JSON and rewrite the local extracted KSI catalog."""
    # Local extractor lives under scripts/; keep a minimal inline extract for runtime refresh.
    from grc_pdf_mapper.fedramp.extract import extract_catalog

    with httpx.Client(timeout=timeout, follow_redirects=True) as client:
        resp = client.get(upstream_url)
        resp.raise_for_status()
        raw = resp.json()
    catalog = extract_catalog(raw)
    out = Path(out_path)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(catalog, indent=2), encoding="utf-8")
    return out
