"""Secure Controls Framework (SCF) crosswalk client.

Uses the static JSON API originally published by ethanolivertroy /
GRC Engineering Club:

  https://grcengclub.github.io/scf-api/

SCF data is licensed CC BY-ND 4.0 by securecontrolsframework.com.
"""

from __future__ import annotations

import json
import re
from functools import lru_cache
from pathlib import Path
from typing import Any

import httpx

from grc_pdf_mapper.models import ControlStatement, CrosswalkHit

SCF_API_BASE = "https://grcengclub.github.io/scf-api"
SCF_ATTRIBUTION = (
    "Control mappings provided by the Secure Controls Framework "
    "(https://securecontrolsframework.com), licensed under CC BY-ND 4.0. "
    "API: https://grcengclub.github.io/scf-api/"
)

# Framework IDs in the SCF API → display names used in MappingReport.
DEFAULT_TARGET_FRAMEWORKS: dict[str, str] = {
    "general-nist-800-53-r5-2": "NIST 800-53",
    "general-iso-27001-2022": "ISO 27001",
    "general-aicpa-tsc-2017": "SOC 2",
    "general-nist-csf-2-0": "NIST CSF 2.0",
    "general-cis-csc-8-1": "CIS Controls",
    "general-pci-dss-4-0-1": "PCI DSS",
}

DOMAIN_TO_FAMILY: dict[str, str] = {
    "access_control": "IAC",
    "encryption": "CRY",
    "logging": "MON",
    "incident": "IRO",
    "vendor": "TPM",
    "privacy": "PRI",
    "backup": "BCD",
    "change": "CHG",
}

_NIST_ID_RE = re.compile(
    r"^(?P<fam>AC|AT|AU|CA|CM|CP|IA|IR|MA|MP|PE|PL|PM|PS|PT|RA|SA|SC|SI|SR)"
    r"-(?P<num>\d+)(?P<enh>\(\d+\))?$",
    re.IGNORECASE,
)
_SCF_FAMILIES = (
    "AAT|AST|BCD|CAP|CFG|CHG|CLD|CPL|CRY|DCH|EMB|END|GOV|HRS|IAC|IAO|"
    "IRO|MDM|MNT|MON|NET|OPS|PES|PRI|PRM|RSK|SAT|SEA|TDA|THR|TPM|VPM|WEB"
)
_SCF_ID_RE = re.compile(rf"^({_SCF_FAMILIES})-\d+(?:\.\d+)?$", re.IGNORECASE)


def is_scf_control_id(control_id: str) -> bool:
    return bool(_SCF_ID_RE.match(control_id.strip()))


@lru_cache(maxsize=1)
def load_offline_seed() -> dict[str, Any]:
    path = Path(__file__).with_name("offline_seed.json")
    return json.loads(path.read_text(encoding="utf-8"))


def normalize_nist_id(control_id: str) -> str:
    """Normalize AC-2 / ac-2 → AC-02 (SCF zero-pads NIST SP 800-53 IDs)."""
    match = _NIST_ID_RE.match(control_id.strip())
    if not match:
        return control_id.strip().upper()
    num = int(match.group("num"))
    enh = match.group("enh") or ""
    return f"{match.group('fam').upper()}-{num:02d}{enh}"


def guess_scf_framework_id(control_id: str) -> str | None:
    """Map a cited control id to the SCF API framework_id used for reverse lookup."""
    cid = control_id.strip()
    upper = cid.upper()
    if _NIST_ID_RE.match(cid):
        return "general-nist-800-53-r5-2"
    if upper.startswith("CC") or upper.startswith("P1") or upper.startswith("A1"):
        return "general-aicpa-tsc-2017"
    if re.match(r"^\d+\.\d+", cid) or upper.startswith("A."):
        return "general-iso-27001-2022"
    if upper.startswith(("PR.", "GV.", "ID.", "DE.", "RS.", "RC.")):
        return "general-nist-csf-2-0"
    if upper.startswith("CIS"):
        return "general-cis-csc-8-1"
    if upper.startswith("REQ"):
        return "general-pci-dss-4-0-1"
    if _SCF_ID_RE.match(cid):
        return None  # already an SCF id
    return None


def lookup_key_variants(control_id: str, framework_id: str | None) -> list[str]:
    """Generate plausible keys for framework_to_scf maps."""
    cid = control_id.strip()
    variants = [cid, cid.upper(), cid.lower()]
    if framework_id == "general-nist-800-53-r5-2" or _NIST_ID_RE.match(cid):
        padded = normalize_nist_id(cid)
        variants.extend([padded, padded.lower()])
        # Also try unpadded form.
        match = _NIST_ID_RE.match(cid)
        if match:
            bare = f"{match.group('fam').upper()}-{int(match.group('num'))}{match.group('enh') or ''}"
            variants.append(bare)
    if framework_id == "general-cis-csc-8-1":
        cleaned = re.sub(r"^CIS\s*", "", cid, flags=re.I).strip()
        variants.extend([cleaned, f"CIS {cleaned}", f"CIS{cleaned}"])
    if framework_id == "general-pci-dss-4-0-1":
        cleaned = re.sub(r"^Req\.?\s*", "", cid, flags=re.I).strip()
        variants.extend([cleaned, f"Req.{cleaned}", f"Req {cleaned}"])
    # Preserve order, drop empties/dupes.
    seen: set[str] = set()
    out: list[str] = []
    for item in variants:
        if item and item not in seen:
            seen.add(item)
            out.append(item)
    return out


class ScfClient:
    """Fetch SCF controls and expand them across framework crosswalks."""

    def __init__(
        self,
        *,
        base_url: str = SCF_API_BASE,
        offline: bool = False,
        client: httpx.Client | None = None,
        target_frameworks: dict[str, str] | None = None,
        expand_limit: int = 24,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.offline = offline
        self.target_frameworks = target_frameworks or dict(DEFAULT_TARGET_FRAMEWORKS)
        self.expand_limit = expand_limit
        self._owns_client = client is None
        self.client = client or httpx.Client(timeout=30.0, follow_redirects=True)
        self._seed = load_offline_seed()
        self._fw_cache: dict[str, dict[str, list[str]]] = {}
        self._control_cache: dict[str, dict[str, Any]] = {}
        self._family_cache: dict[str, list[dict[str, Any]]] = {}

    def close(self) -> None:
        if self._owns_client:
            self.client.close()

    def __enter__(self) -> ScfClient:
        return self

    def __exit__(self, *args: object) -> None:
        self.close()

    def map_statement(self, statement: ControlStatement) -> list[CrosswalkHit]:
        """Map one obligation onto SCF, then fan out to target frameworks."""
        hits: list[CrosswalkHit] = []
        scf_ids: list[str] = []

        for cid in statement.candidate_framework_ids:
            if is_scf_control_id(cid):
                scf_ids.append(cid.upper())
                continue
            fw_id = guess_scf_framework_id(cid)
            if not fw_id:
                continue
            scf_ids.extend(self.framework_to_scf(fw_id, cid))

        if not scf_ids:
            for domain in statement.keywords:
                scf_ids.extend(self.domain_scf_ids(domain))

        # Stable unique order.
        seen: set[str] = set()
        ordered: list[str] = []
        for sid in scf_ids:
            key = sid.upper()
            if key in seen:
                continue
            seen.add(key)
            ordered.append(key)

        for sid in ordered[:12]:
            hits.extend(self.hits_for_scf_control(sid, statement))
        return hits[: self.expand_limit + 12]

    def framework_to_scf(self, framework_id: str, control_id: str) -> list[str]:
        reverse = self._framework_reverse_map(framework_id)
        for key in lookup_key_variants(control_id, framework_id):
            found = reverse.get(key)
            if found:
                return list(found)
        return []

    def domain_scf_ids(self, domain: str) -> list[str]:
        family = DOMAIN_TO_FAMILY.get(domain) or self._seed.get("domain_families", {}).get(domain)
        if not family:
            return []
        controls = self._family_controls(family)
        # Prefer seeded domain-tagged controls when present.
        seeded = [
            cid
            for cid, row in self._seed.get("controls", {}).items()
            if domain in row.get("domains", [])
        ]
        if seeded:
            return seeded[:6]
        return [str(c.get("control_id")) for c in controls[:6] if c.get("control_id")]

    def hits_for_scf_control(self, scf_id: str, statement: ControlStatement | None = None) -> list[CrosswalkHit]:
        control = self.get_control(scf_id) or {
            "control_id": scf_id,
            "title": "",
            "family": scf_id.split("-", 1)[0],
            "crosswalks": {},
        }
        hits: list[CrosswalkHit] = [
            CrosswalkHit(
                source="scf-api",
                framework="SCF",
                control_id=str(control.get("control_id") or scf_id),
                title=str(control.get("title") or ""),
                relationship="backbone",
                confidence=0.9 if statement and statement.candidate_framework_ids else 0.72,
                url=f"{self.base_url}/api/controls/{scf_id}.json",
                raw={
                    "family": control.get("family"),
                    "family_name": control.get("family_name"),
                    "description": control.get("description"),
                    "attribution": SCF_ATTRIBUTION,
                },
            )
        ]
        crosswalks = control.get("crosswalks") or {}
        emitted = 0
        for fw_id, display in self.target_frameworks.items():
            mapped_ids = list(crosswalks.get(fw_id) or [])
            if not mapped_ids:
                mapped_ids = self._scf_to_framework(fw_id, scf_id)
            for mid in mapped_ids[:4]:
                hits.append(
                    CrosswalkHit(
                        source="scf-api",
                        framework=display,
                        control_id=str(mid),
                        title="",
                        relationship="scf-crosswalk",
                        confidence=0.88,
                        url=f"{self.base_url}/api/crosswalks/{fw_id}.json",
                        cre_ids=[scf_id],
                        raw={"scf_id": scf_id, "framework_id": fw_id, "attribution": SCF_ATTRIBUTION},
                    )
                )
                emitted += 1
                if emitted >= self.expand_limit:
                    return hits
        return hits

    def get_control(self, scf_id: str) -> dict[str, Any] | None:
        key = scf_id.upper()
        if key in self._control_cache:
            cached = self._control_cache[key]
            return cached or None
        seeded = self._seed.get("controls", {}).get(key)
        if self.offline:
            self._control_cache[key] = seeded or {}
            return seeded
        try:
            resp = self.client.get(f"{self.base_url}/api/controls/{key}.json")
            if resp.status_code == 404:
                self._control_cache[key] = seeded or {}
                return seeded
            resp.raise_for_status()
            data = resp.json()
            self._control_cache[key] = data
            return data
        except httpx.HTTPError:
            self._control_cache[key] = seeded or {}
            return seeded

    def list_frameworks(self) -> list[dict[str, Any]]:
        if self.offline:
            return [
                {"framework_id": fw_id, "display_name": name}
                for fw_id, name in self.target_frameworks.items()
            ]
        try:
            resp = self.client.get(f"{self.base_url}/api/crosswalks.json")
            resp.raise_for_status()
            return list(resp.json().get("frameworks", []))
        except httpx.HTTPError:
            return [
                {"framework_id": fw_id, "display_name": name}
                for fw_id, name in self.target_frameworks.items()
            ]

    def _framework_reverse_map(self, framework_id: str) -> dict[str, list[str]]:
        if framework_id in self._fw_cache:
            return self._fw_cache[framework_id]
        seeded = dict(self._seed.get("framework_to_scf", {}).get(framework_id, {}))
        if self.offline:
            self._fw_cache[framework_id] = seeded
            return seeded
        try:
            resp = self.client.get(f"{self.base_url}/api/crosswalks/{framework_id}.json")
            resp.raise_for_status()
            mappings = resp.json().get("framework_to_scf", {}).get("mappings", {})
            self._fw_cache[framework_id] = dict(mappings)
            return self._fw_cache[framework_id]
        except httpx.HTTPError:
            self._fw_cache[framework_id] = seeded
            return seeded

    def _scf_to_framework(self, framework_id: str, scf_id: str) -> list[str]:
        control = self._control_cache.get(scf_id.upper()) or self._seed.get("controls", {}).get(scf_id.upper())
        if control and control.get("crosswalks"):
            return list((control.get("crosswalks") or {}).get(framework_id, []))
        # Invert reverse map for offline / missing control metadata.
        reverse = self._framework_reverse_map(framework_id)
        needle = scf_id.upper()
        out: list[str] = []
        for fw_control, scf_list in reverse.items():
            if any(str(s).upper() == needle for s in scf_list):
                out.append(str(fw_control))
                if len(out) >= 8:
                    break
        return out

    def _family_controls(self, family: str) -> list[dict[str, Any]]:
        code = family.upper()
        if code in self._family_cache:
            return self._family_cache[code]
        if self.offline:
            rows = [
                row
                for row in self._seed.get("controls", {}).values()
                if str(row.get("family", "")).upper() == code
            ]
            self._family_cache[code] = rows
            return rows
        try:
            resp = self.client.get(f"{self.base_url}/api/families/{code}.json")
            resp.raise_for_status()
            rows = list(resp.json().get("controls", []))
            self._family_cache[code] = rows
            return rows
        except httpx.HTTPError:
            rows = [
                row
                for row in self._seed.get("controls", {}).values()
                if str(row.get("family", "")).upper() == code
            ]
            self._family_cache[code] = rows
            return rows


def map_statement_via_scf(
    statement: ControlStatement,
    *,
    offline: bool = False,
    client: httpx.Client | None = None,
    base_url: str = SCF_API_BASE,
) -> list[CrosswalkHit]:
    with ScfClient(offline=offline, client=client, base_url=base_url) as scf:
        return scf.map_statement(statement)
