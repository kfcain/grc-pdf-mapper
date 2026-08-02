from pathlib import Path

from grc_pdf_mapper.crosswalk import CrosswalkClient
from grc_pdf_mapper.extract import extract_control_statements
from grc_pdf_mapper.fedramp import FedRampKSICatalog, documentation_alerts_for_class
from grc_pdf_mapper.fedramp.extract import extract_catalog
import json

ROOT = Path(__file__).resolve().parents[1]
CATALOG = ROOT / "lab" / "fedramp" / "cr26_ksi_catalog.json"
POLICY = ROOT / "lab" / "policies" / "access-control.md"


def test_catalog_has_all_domains_and_classes():
    cat = FedRampKSICatalog(CATALOG)
    assert cat.version.startswith("2026")
    domains = {d["short_name"] or d["id"] for d in cat.domains()}
    assert {"CED", "CMT", "CNA", "IAM", "INR", "MLA", "PIY", "RPL", "SCR", "SVC"} <= domains
    assert len(cat.indicators()) == 46
    for cls in ("a", "b", "c", "d"):
        rows = cat.for_class(cls)
        assert len(rows) >= 40


def test_varies_by_class_ksi_status():
    cat = FedRampKSICatalog(CATALOG)
    statuses = {}
    for cls in ("a", "b", "c", "d"):
        row = next(i for i in cat.for_class(cls) if i["id"] == "KSI-SVC-VCM")
        statuses[cls] = row["class_status"]
    assert statuses["a"] == "optional"
    assert statuses["b"] == "optional"
    assert statuses["c"] == "required"
    assert statuses["d"] == "required"


def test_control_to_ksi_mapping():
    cat = FedRampKSICatalog(CATALOG)
    iam = cat.map_control("IA-2", class_id="c")
    assert any(i["id"].startswith("KSI-IAM-") for i in iam)
    ac2 = cat.map_control("AC-2", class_id="b")
    assert ac2


def test_documentation_musts_rise_with_class():
    a_must = {r["id"] for r in documentation_alerts_for_class("a", CATALOG)}
    c_must = {r["id"] for r in documentation_alerts_for_class("c", CATALOG)}
    d_must = {r["id"] for r in documentation_alerts_for_class("d", CATALOG)}
    # Class A has fewer MUST doc obligations than C/D for KSI automation FRRs
    assert "FRC-CSX-VVK" not in a_must
    assert "CPO-CSX-CPM" in c_must
    assert "CPO-CSX-CPM" in d_must
    assert "FRC-CSX-VVK" in c_must
    assert "FRC-CSX-VVK" in d_must
    # Cadence tightens
    cat = FedRampKSICatalog(CATALOG)
    cpm_c = next(r for r in cat.documentation_matrix("c") if r["id"] == "CPO-CSX-CPM")
    cpm_d = next(r for r in cat.documentation_matrix("d") if r["id"] == "CPO-CSX-CPM")
    assert cpm_c["timeframe_num"] == 2 and cpm_c["timeframe_type"] == "weeks"
    assert cpm_d["timeframe_num"] == 1 and cpm_d["timeframe_type"] == "weeks"


def test_crosswalk_includes_fedramp_ksi():
    markdown = POLICY.read_text(encoding="utf-8")
    statements = extract_control_statements(markdown, doc_slug="pol-ac-001")
    with CrosswalkClient(offline=True, fedramp_class="c") as client:
        # Prefer an MFA / access statement
        target = next(
            s for s in statements if "multi-factor" in s.text.lower() or "mfa" in s.text.lower()
        )
        hits = client.map_statement(target)
    frameworks = {h.framework for h in hits}
    assert "FedRAMP KSI" in frameworks
    assert any(h.control_id.startswith("KSI-") for h in hits)


def test_extract_catalog_roundtrip(tmp_path: Path):
    raw = {
        "info": {"title": "t", "version": "test", "last_updated": "2026-01-01"},
        "FRR": {
            "FRC": {
                "data": {
                    "20x": {
                        "CSX": {
                            "FRC-CSX-VVK": {
                                "name": "VVK",
                                "varies_by_class": {
                                    "a": {"force": "MAY", "statement": "MAY"},
                                    "b": {"force": "SHOULD", "statement": "SHOULD"},
                                    "c": {"force": "MUST", "statement": "MUST"},
                                    "d": {"force": "MUST", "statement": "MUST"},
                                },
                            },
                            "FRC-CSX-MOT": {
                                "name": "MOT",
                                "varies_by_class": {
                                    "a": {"force": "MAY", "statement": "MAY"},
                                    "b": {"force": "SHOULD", "statement": "SHOULD"},
                                    "c": {"force": "MUST", "statement": "MUST"},
                                    "d": {"force": "MUST", "statement": "MUST"},
                                },
                            },
                        }
                    }
                }
            },
            "SDR": {
                "data": {
                    "20x": {
                        "CSX": {
                            "SDR-CSX-KMT": {
                                "name": "KMT",
                                "varies_by_class": {
                                    "a": {"force": "MAY", "statement": "MAY"},
                                    "b": {"force": "MUST", "statement": "MUST"},
                                    "c": {"force": "MUST", "statement": "MUST"},
                                    "d": {"force": "MUST", "statement": "MUST"},
                                },
                            }
                        }
                    }
                }
            },
            "CPO": {
                "data": {
                    "all": {
                        "CSO": {
                            "CPO-CSO-OSA": {
                                "name": "OSA",
                                "varies_by_class": {
                                    "a": {"force": "MAY", "statement": "MAY"},
                                    "b": {"force": "MUST", "statement": "MUST"},
                                    "c": {"force": "MUST", "statement": "MUST"},
                                    "d": {"force": "MUST", "statement": "MUST"},
                                },
                            },
                            "CPO-CSO-OVR": {"name": "OVR", "statement": "overview"},
                            "CPO-CSO-MTD": {"name": "MTD", "statement": "metadata"},
                        }
                    },
                    "20x": {
                        "CSX": {
                            "CPO-CSX-CPM": {
                                "name": "CPM",
                                "varies_by_class": {
                                    "a": {
                                        "force": "SHOULD",
                                        "statement": "3 months",
                                        "timeframe_type": "months",
                                        "timeframe_num": 3,
                                    },
                                    "b": {
                                        "force": "MUST",
                                        "statement": "1 month",
                                        "timeframe_type": "months",
                                        "timeframe_num": 1,
                                    },
                                    "c": {
                                        "force": "MUST",
                                        "statement": "2 weeks",
                                        "timeframe_type": "weeks",
                                        "timeframe_num": 2,
                                    },
                                    "d": {
                                        "force": "MUST",
                                        "statement": "1 week",
                                        "timeframe_type": "weeks",
                                        "timeframe_num": 1,
                                    },
                                },
                            }
                        }
                    },
                }
            },
        },
        "KSI": {
            "IAM": {
                "id": "KSI-IAM",
                "name": "Identity and Access Management",
                "short_name": "IAM",
                "status": "stable",
                "indicators": {
                    "KSI-IAM-AAM": {
                        "name": "Automating Account Management",
                        "statement": "Accounts are managed with automation.",
                        "controls": ["ac-2.2", "ia-2"],
                    }
                },
            }
        },
    }
    catalog = extract_catalog(raw)
    assert catalog["domains"]["IAM"]["indicators"][0]["controls_nist"] == ["AC-2(2)", "IA-2"]
    path = tmp_path / "c.json"
    path.write_text(json.dumps(catalog), encoding="utf-8")
    loaded = FedRampKSICatalog(path)
    assert loaded.map_control("IA-2", class_id="c")
