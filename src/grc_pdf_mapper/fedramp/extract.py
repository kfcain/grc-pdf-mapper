"""Extract a normalized CR26 KSI + documentation catalog from FedRAMP rules JSON."""

from __future__ import annotations

CLASS_ORDER = ["a", "b", "c", "d"]


def extract_catalog(raw: dict) -> dict:
    catalog = {
        "source": {
            "title": raw.get("info", {}).get("title"),
            "version": raw.get("info", {}).get("version"),
            "last_updated": raw.get("info", {}).get("last_updated"),
            "upstream": "https://github.com/FedRAMP/rules/blob/main/fedramp-consolidated-rules.json",
            "ruleset": "CR26 / FedRAMP Consolidated Rules for 2026",
        },
        "classes": {
            "a": {
                "name": "Class A",
                "legacy": None,
                "notes": "20x Pilot / minimal assurance; KSI automation MAY",
            },
            "b": {
                "name": "Class B",
                "legacy": "Low",
                "notes": "KSI automation SHOULD (min 1 method per KSI)",
            },
            "c": {
                "name": "Class C",
                "legacy": "Moderate",
                "notes": "KSI automation MUST (min 2 methods per KSI)",
            },
            "d": {
                "name": "Class D",
                "legacy": "High",
                "notes": "KSI automation MUST (min 4 methods per KSI)",
            },
        },
        "domains": {},
        "documentation_requirements": [],
    }

    doc_reqs = [
        ("FRC", "20x", "CSX", "FRC-CSX-VVK"),
        ("FRC", "20x", "CSX", "FRC-CSX-MOT"),
        ("SDR", "20x", "CSX", "SDR-CSX-KMT"),
        ("CPO", "all", "CSO", "CPO-CSO-OSA"),
        ("CPO", "20x", "CSX", "CPO-CSX-CPM"),
        ("CPO", "all", "CSO", "CPO-CSO-OVR"),
        ("CPO", "all", "CSO", "CPO-CSO-MTD"),
    ]
    for fam, section, group, rid in doc_reqs:
        req = raw["FRR"][fam]["data"][section][group][rid]
        by_class = {}
        for cls, body in (req.get("varies_by_class") or {}).items():
            by_class[cls] = {
                "force": (body.get("force") or "REQUIRED").upper(),
                "statement": body.get("statement"),
                "timeframe_type": body.get("timeframe_type"),
                "timeframe_num": body.get("timeframe_num"),
                "following_information": body.get("following_information"),
            }
        catalog["documentation_requirements"].append(
            {
                "id": rid,
                "name": req.get("name"),
                "family": fam,
                "requires_documentation": True,
                "statement": req.get("statement"),
                "by_class": by_class,
            }
        )

    for _dom_key, dom in raw.get("KSI", {}).items():
        indicators = []
        for iid, ind in dom.get("indicators", {}).items():
            nist = [_to_nist(c) for c in ind.get("controls", [])]
            applicability: dict[str, str] = {}
            class_statements: dict[str, str] = {}
            if "varies_by_class" in ind:
                vbc = ind["varies_by_class"]
                for cls in CLASS_ORDER:
                    if cls in vbc:
                        applicability[cls] = _force_for_vbc_entry(vbc[cls])
                        class_statements[cls] = vbc[cls].get("statement")
                    elif cls == "a":
                        applicability[cls] = "optional"
                        class_statements[cls] = (
                            "Class A: treat as optional unless adopted for pilot evidence."
                        )
                    elif cls == "d":
                        applicability[cls] = "required"
                        class_statements[cls] = vbc.get("c", {}).get("statement") or (
                            "Required for Class D (inherits Class C required posture)."
                        )
            else:
                applicability = {c: "applicable" for c in CLASS_ORDER}
                if ind.get("statement"):
                    for cls in CLASS_ORDER:
                        class_statements[cls] = ind["statement"]
            indicators.append(
                {
                    "id": iid,
                    "name": ind.get("name"),
                    "statement": ind.get("statement"),
                    "controls_raw": ind.get("controls", []),
                    "controls_nist": nist,
                    "class_applicability": applicability,
                    "class_statements": class_statements,
                    "varies_by_class": "varies_by_class" in ind,
                    "documentation_sensitive": True,
                }
            )
        catalog["domains"][dom.get("short_name") or _dom_key] = {
            "id": dom.get("id"),
            "name": dom.get("name"),
            "short_name": dom.get("short_name"),
            "status": dom.get("status"),
            "indicators": indicators,
        }
    return catalog


def _to_nist(control: str) -> str:
    parts = control.split("-", 1)
    if len(parts) != 2:
        return control.upper()
    fam, rest = parts[0].upper(), parts[1]
    if "." in rest:
        base, enh = rest.split(".", 1)
        return f"{fam}-{base}({enh})"
    return f"{fam}-{rest}"


def _force_for_vbc_entry(entry: dict) -> str:
    stmt = entry.get("statement") or ""
    if stmt.strip().lower().startswith("**optional:**"):
        return "optional"
    return (entry.get("force") or "required").lower()
