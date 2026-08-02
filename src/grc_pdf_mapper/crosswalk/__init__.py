"""Framework crosswalk clients: SCF API, OpenCRE, OSA, NIST OSCAL, local seed map."""

from __future__ import annotations

import re
from typing import Iterable

import httpx

from grc_pdf_mapper.models import ControlStatement, CrosswalkHit
from grc_pdf_mapper.scf import SCF_API_BASE, ScfClient

OPENCRE_BASE = "https://opencre.org/rest/v1"
OSA_BASE = "https://opensecurityarchitecture.org/api/v1"
OSCAL_80053_URL = (
    "https://raw.githubusercontent.com/usnistgov/oscal-content/main/"
    "nist.gov/SP800-53/rev5/json/NIST_SP-800-53_rev5_catalog.json"
)

# Lightweight offline seed for demos / air-gapped runs.
SEED_CROSSWALK: dict[str, list[dict[str, str]]] = {
    "access_control": [
        {"framework": "NIST 800-53", "control_id": "AC-2", "title": "Account Management"},
        {"framework": "NIST 800-53", "control_id": "AC-3", "title": "Access Enforcement"},
        {"framework": "NIST 800-53", "control_id": "IA-2", "title": "Identification and Authentication"},
        {"framework": "ISO 27001", "control_id": "5.15", "title": "Access control"},
        {"framework": "ISO 27001", "control_id": "8.5", "title": "Secure authentication"},
        {"framework": "SOC 2", "control_id": "CC6.1", "title": "Logical access security"},
        {"framework": "NIST CSF 2.0", "control_id": "PR.AA-01", "title": "Identities and credentials"},
        {"framework": "CIS Controls", "control_id": "CIS 5.1", "title": "Establish account inventory"},
    ],
    "encryption": [
        {"framework": "NIST 800-53", "control_id": "SC-13", "title": "Cryptographic Protection"},
        {"framework": "NIST 800-53", "control_id": "SC-28", "title": "Protection of Information at Rest"},
        {"framework": "ISO 27001", "control_id": "8.24", "title": "Use of cryptography"},
        {"framework": "SOC 2", "control_id": "CC6.7", "title": "Transmission and disposal"},
        {"framework": "PCI DSS", "control_id": "Req.3", "title": "Protect stored account data"},
    ],
    "logging": [
        {"framework": "NIST 800-53", "control_id": "AU-2", "title": "Event Logging"},
        {"framework": "NIST 800-53", "control_id": "AU-6", "title": "Audit Record Review"},
        {"framework": "ISO 27001", "control_id": "8.15", "title": "Logging"},
        {"framework": "SOC 2", "control_id": "CC7.2", "title": "System monitoring"},
        {"framework": "NIST CSF 2.0", "control_id": "DE.CM-01", "title": "Networks and systems monitored"},
    ],
    "incident": [
        {"framework": "NIST 800-53", "control_id": "IR-4", "title": "Incident Handling"},
        {"framework": "ISO 27001", "control_id": "5.26", "title": "Response to information security incidents"},
        {"framework": "SOC 2", "control_id": "CC7.3", "title": "Incident evaluation"},
        {"framework": "NIST CSF 2.0", "control_id": "RS.MA-01", "title": "Incident management"},
    ],
    "vendor": [
        {"framework": "NIST 800-53", "control_id": "SR-3", "title": "Supply Chain Controls"},
        {"framework": "ISO 27001", "control_id": "5.19", "title": "Information security in supplier relationships"},
        {"framework": "SOC 2", "control_id": "CC9.2", "title": "Vendor risk management"},
    ],
    "privacy": [
        {"framework": "NIST 800-53", "control_id": "PT-2", "title": "Authority to Process Personally Identifiable Information"},
        {"framework": "ISO 27001", "control_id": "5.34", "title": "Privacy and protection of PII"},
        {"framework": "SOC 2", "control_id": "P1.0", "title": "Privacy criteria"},
    ],
    "backup": [
        {"framework": "NIST 800-53", "control_id": "CP-9", "title": "System Backup"},
        {"framework": "ISO 27001", "control_id": "8.13", "title": "Information backup"},
        {"framework": "NIST CSF 2.0", "control_id": "PR.DS-11", "title": "Backups"},
    ],
    "change": [
        {"framework": "NIST 800-53", "control_id": "CM-3", "title": "Configuration Change Control"},
        {"framework": "ISO 27001", "control_id": "8.32", "title": "Change management"},
        {"framework": "SOC 2", "control_id": "CC8.1", "title": "Change management"},
    ],
}

_OPENCRE_STANDARD_ALIASES = {
    "ISO 27001": "ISO 27001",
    "NIST 800-53": "NIST 800-53 v5",
    "PCI DSS": "PCI DSS",
    "ASVS": "ASVS",
}


class CrosswalkClient:
    """Aggregate SCF API maps with seed, FedRAMP, OpenCRE / OSA / OSCAL lookups."""

    def __init__(
        self,
        *,
        timeout: float = 20.0,
        offline: bool = False,
        client: httpx.Client | None = None,
        fedramp_class: str | None = None,
        fedramp_catalog_path: str | None = None,
        scf_base_url: str = SCF_API_BASE,
        use_scf: bool = True,
    ) -> None:
        self.offline = offline
        self.fedramp_class = fedramp_class
        self.fedramp_catalog_path = fedramp_catalog_path
        self.scf_base_url = scf_base_url
        self.use_scf = use_scf
        self._owns_client = client is None
        self.client = client or httpx.Client(timeout=timeout, follow_redirects=True)
        self._oscal_index: dict[str, str] | None = None
        self._scf: ScfClient | None = None

    def close(self) -> None:
        if self._scf is not None:
            self._scf.close()
            self._scf = None
        if self._owns_client:
            self.client.close()

    def __enter__(self) -> CrosswalkClient:
        return self

    def __exit__(self, *args: object) -> None:
        self.close()

    def map_statement(self, statement: ControlStatement) -> list[CrosswalkHit]:
        hits: list[CrosswalkHit] = []
        # SCF is the primary framework backbone (online API + offline seed).
        if self.use_scf:
            hits.extend(self._scf_hits(statement))
        hits.extend(self._seed_hits(statement))
        hits.extend(self._explicit_id_hits(statement))
        hits.extend(self._fedramp_ksi_hits(statement))
        if not self.offline:
            hits.extend(self._opencre_hits(statement))
            hits.extend(self._osa_hits(statement))
        return _unique_hits(hits)

    def map_statements(self, statements: Iterable[ControlStatement]) -> dict[str, list[CrosswalkHit]]:
        return {s.statement_id: self.map_statement(s) for s in statements}

    def list_opencre_standards(self) -> list[str]:
        if self.offline:
            return list(_OPENCRE_STANDARD_ALIASES.values())
        resp = self.client.get(f"{OPENCRE_BASE}/standards")
        resp.raise_for_status()
        data = resp.json()
        return list(data) if isinstance(data, list) else []

    def opencre_standard_sections(self, standard: str, *, pages: int = 1) -> list[dict]:
        if self.offline:
            return []
        name = _OPENCRE_STANDARD_ALIASES.get(standard, standard)
        resp = self.client.get(f"{OPENCRE_BASE}/standard/{name}", params={"page": pages})
        if resp.status_code == 404:
            return []
        resp.raise_for_status()
        payload = resp.json()
        return list(payload.get("standards", []))

    def osa_frameworks(self) -> list[dict]:
        if self.offline:
            return [{"id": "nist_csf_2", "name": "NIST CSF 2.0"}]
        resp = self.client.get(f"{OSA_BASE}/frameworks")
        resp.raise_for_status()
        payload = resp.json()
        return list(payload.get("data", []))

    def osa_control_mappings(self, framework_id: str, control_id: str) -> list[CrosswalkHit]:
        """Look up OSA bidirectional mappings for one control when online."""
        if self.offline:
            return []
        # OSA exposes framework documents; filter client-side for the control id.
        resp = self.client.get(
            f"{OSA_BASE}/frameworks/{framework_id}",
            params={"fields": "mappings", "limit": 200},
        )
        if resp.status_code == 404:
            return []
        resp.raise_for_status()
        payload = resp.json()
        data = payload.get("data", payload)
        mappings = data.get("mappings") or data.get("controls") or []
        hits: list[CrosswalkHit] = []
        needle = control_id.lower()
        for row in mappings:
            src = str(row.get("source_id") or row.get("control_id") or row.get("id") or "")
            if src.lower() != needle and needle not in str(row).lower():
                continue
            targets = row.get("targets") or row.get("maps_to") or [row]
            if isinstance(targets, dict):
                targets = [targets]
            for target in targets:
                hits.append(
                    CrosswalkHit(
                        source="osa",
                        framework=str(target.get("framework") or framework_id),
                        control_id=str(target.get("id") or target.get("control_id") or ""),
                        title=str(target.get("title") or target.get("name") or ""),
                        relationship=str(target.get("relationship") or "equivalent"),
                        confidence=0.85,
                        url=f"{OSA_BASE}/frameworks/{framework_id}",
                        raw=target if isinstance(target, dict) else {"value": target},
                    )
                )
        return hits

    def oscal_control_title(self, control_id: str) -> str | None:
        index = self._load_oscal_index()
        return index.get(control_id.upper())

    def _seed_hits(self, statement: ControlStatement) -> list[CrosswalkHit]:
        hits: list[CrosswalkHit] = []
        for domain in statement.keywords:
            for row in SEED_CROSSWALK.get(domain, []):
                hits.append(
                    CrosswalkHit(
                        source="seed",
                        framework=row["framework"],
                        control_id=row["control_id"],
                        title=row["title"],
                        relationship="topic",
                        confidence=0.55,
                    )
                )
        return hits

    def _fedramp_ksi_hits(self, statement: ControlStatement) -> list[CrosswalkHit]:
        try:
            from grc_pdf_mapper.fedramp import map_statement_to_ksi

            return map_statement_to_ksi(
                statement,
                class_id=self.fedramp_class,
                catalog_path=self.fedramp_catalog_path,
            )
        except FileNotFoundError:
            return []

    def _scf_client(self) -> ScfClient:
        if self._scf is None:
            # Share the httpx client; ScfClient must not close it on exit.
            self._scf = ScfClient(
                base_url=self.scf_base_url,
                offline=self.offline,
                client=self.client,
            )
        return self._scf

    def _scf_hits(self, statement: ControlStatement) -> list[CrosswalkHit]:
        try:
            return self._scf_client().map_statement(statement)
        except (httpx.HTTPError, OSError, ValueError, KeyError, TypeError):
            return []

    def _explicit_id_hits(self, statement: ControlStatement) -> list[CrosswalkHit]:
        hits: list[CrosswalkHit] = []
        for cid in statement.candidate_framework_ids:
            framework = _guess_framework(cid)
            title = ""
            if framework == "NIST 800-53" and not self.offline:
                title = self.oscal_control_title(cid) or ""
            hits.append(
                CrosswalkHit(
                    source="explicit-citation",
                    framework=framework,
                    control_id=cid,
                    title=title,
                    relationship="cited",
                    confidence=0.95,
                )
            )
        return hits

    def _opencre_hits(self, statement: ControlStatement) -> list[CrosswalkHit]:
        hits: list[CrosswalkHit] = []
        # Prefer explicit ISO / NIST citations; else search by keyword domain via ISO sections.
        query_terms = statement.candidate_framework_ids[:2]
        if not query_terms and statement.keywords:
            query_terms = [statement.keywords[0].replace("_", " ")]

        for term in query_terms:
            try:
                resp = self.client.get(f"{OPENCRE_BASE}/standard/ISO 27001", params={"page": 1})
                if resp.status_code != 200:
                    continue
                for section in resp.json().get("standards", []):
                    section_id = str(section.get("sectionID") or "")
                    section_name = str(section.get("section") or "")
                    blob = f"{section_id} {section_name}".lower()
                    if term.lower().replace("_", " ") not in blob and term.lower() not in blob:
                        # Soft match on statement keywords in section name.
                        if not any(k.replace("_", " ") in section_name.lower() for k in statement.keywords):
                            continue
                    cre_ids = [
                        link.get("document", {}).get("id", "")
                        for link in section.get("links", [])
                        if link.get("document", {}).get("doctype") == "CRE"
                    ]
                    hits.append(
                        CrosswalkHit(
                            source="opencre",
                            framework="ISO 27001",
                            control_id=section_id or section.get("id", ""),
                            title=section_name,
                            relationship="linked",
                            confidence=0.7,
                            url=f"https://opencre.org/standard/ISO%2027001",
                            cre_ids=[c for c in cre_ids if c],
                            raw=section,
                        )
                    )
            except httpx.HTTPError:
                continue
        return hits[:8]

    def _osa_hits(self, statement: ControlStatement) -> list[CrosswalkHit]:
        hits: list[CrosswalkHit] = []
        for cid in statement.candidate_framework_ids:
            if re.match(r"^AC-\d+", cid, re.I) or re.match(r"^IA-\d+", cid, re.I):
                hits.extend(self.osa_control_mappings("nist_800_53_rev5", cid))
            if re.match(r"^CC\d", cid, re.I):
                hits.extend(self.osa_control_mappings("soc2_tsc", cid))
        return hits[:10]

    def _load_oscal_index(self) -> dict[str, str]:
        if self._oscal_index is not None:
            return self._oscal_index
        if self.offline:
            self._oscal_index = {
                "AC-2": "Account Management",
                "AC-3": "Access Enforcement",
                "IA-2": "Identification and Authentication",
                "AU-2": "Event Logging",
                "SC-13": "Cryptographic Protection",
                "IR-4": "Incident Handling",
            }
            return self._oscal_index
        try:
            resp = self.client.get(OSCAL_80053_URL)
            resp.raise_for_status()
            catalog = resp.json().get("catalog", {})
            index: dict[str, str] = {}
            for group in catalog.get("groups", []):
                for control in group.get("controls", []):
                    cid = str(control.get("id", "")).upper()
                    title = str(control.get("title") or "")
                    if cid:
                        index[cid] = title
                    for child in control.get("controls", []):
                        child_id = str(child.get("id", "")).upper()
                        if child_id:
                            index[child_id] = str(child.get("title") or "")
            self._oscal_index = index
        except httpx.HTTPError:
            self._oscal_index = {}
        return self._oscal_index


def _guess_framework(control_id: str) -> str:
    cid = control_id.upper()
    if re.match(r"^(AC|AT|AU|CA|CM|CP|IA|IR|MA|MP|PE|PL|PM|PS|PT|RA|SA|SC|SI|SR)-\d+", cid):
        return "NIST 800-53"
    if re.match(
        r"^(AAT|AST|BCD|CAP|CFG|CHG|CLD|CPL|CRY|DCH|EMB|END|GOV|HRS|IAC|IAO|"
        r"IRO|MDM|MNT|MON|NET|OPS|PES|PRI|PRM|RSK|SAT|SEA|TDA|THR|TPM|VPM|WEB)"
        r"-\d+",
        cid,
    ):
        return "SCF"
    if cid.startswith("CC") or cid.startswith("P1") or cid.startswith("A1"):
        return "SOC 2"
    if re.match(r"^\d+\.\d+", cid) or cid.startswith("A."):
        return "ISO 27001"
    if cid.startswith("PR.") or cid.startswith("GV.") or cid.startswith("ID.") or cid.startswith("DE."):
        return "NIST CSF 2.0"
    if cid.startswith("CIS"):
        return "CIS Controls"
    if cid.startswith("REQ"):
        return "PCI DSS"
    return "Unknown"


def _unique_hits(hits: list[CrosswalkHit]) -> list[CrosswalkHit]:
    seen: set[tuple[str, str, str]] = set()
    out: list[CrosswalkHit] = []
    for hit in hits:
        key = (hit.source, hit.framework, hit.control_id)
        if key in seen or not hit.control_id:
            continue
        seen.add(key)
        out.append(hit)
    return out
