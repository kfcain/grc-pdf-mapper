"""Detect verbiage changes and map them to framework / assessment risk."""

from __future__ import annotations

import hashlib
import re
from difflib import SequenceMatcher

from grc_pdf_mapper.crosswalk import CrosswalkClient
from grc_pdf_mapper.lineage import PolicyLineageStore
from grc_pdf_mapper.models import (
    AlertSeverity,
    AssessmentImpact,
    AssessmentRegistration,
    ControlStatement,
    FrameworkImpact,
    ImpactAlert,
    ObligationStrength,
    VerbiageChange,
)

_STRENGTH_RANK = {
    ObligationStrength.PROHIBITED: 5,
    ObligationStrength.MUST: 5,
    ObligationStrength.SHALL: 5,
    ObligationStrength.SHOULD: 3,
    ObligationStrength.MAY: 1,
    ObligationStrength.DESCRIPTIVE: 0,
}

_DURATION_RE = re.compile(
    r"\bwithin\s+(\d+)\s+(hour|hours|day|days|business day|business days)\b",
    re.IGNORECASE,
)


def analyze_impact(
    store: PolicyLineageStore,
    doc_id: str,
    older_snapshot_id: str,
    newer_snapshot_id: str,
    *,
    assessments: list[AssessmentRegistration] | None = None,
    offline: bool = True,
) -> ImpactAlert:
    """Compare two versions and build a compliance-impact alert."""
    older = store.get_snapshot(doc_id, older_snapshot_id)
    newer = store.get_snapshot(doc_id, newer_snapshot_id)
    if not older or not newer:
        raise ValueError("Unknown snapshot id")

    left = store.load_statements(older.statement_ids)
    right = store.load_statements(newer.statement_ids)
    changes = detect_verbiage_changes(left, right)

    with CrosswalkClient(offline=offline) as client:
        # Prefer the highest FedRAMP class among active assessments for KSI mapping context.
        fed_classes = [
            a.fedramp_class
            for a in (assessments or [])
            if getattr(a, "fedramp_class", None)
        ]
        if fed_classes:
            # Use the strictest class present (d > c > b > a) for mapping context.
            order = {"a": 0, "b": 1, "c": 2, "d": 3}
            best = max(fed_classes, key=lambda c: order.get(str(c).lower(), -1))
            client.fedramp_class = str(best).lower()
        framework_impacts = _framework_impacts_from_changes(changes, left, right, client)

    assessment_impacts = map_assessments_at_risk(
        framework_impacts,
        assessments or [],
        doc_id=doc_id,
    )
    severity = _roll_up_severity(changes, framework_impacts, assessment_impacts)
    summary = _build_summary(doc_id, changes, framework_impacts, assessment_impacts, severity)
    actions = _recommended_actions(changes, framework_impacts, assessment_impacts)
    actions.extend(_fedramp_documentation_actions(assessment_impacts, assessments or []))

    material = f"{doc_id}:{older_snapshot_id}:{newer_snapshot_id}:{severity.value}".encode()
    return ImpactAlert(
        alert_id=hashlib.sha256(material).hexdigest()[:16],
        doc_id=doc_id,
        older_snapshot_id=older_snapshot_id,
        newer_snapshot_id=newer_snapshot_id,
        version_from=older.version_label,
        version_to=newer.version_label,
        severity=severity,
        summary=summary,
        verbiage_changes=changes,
        frameworks_impacted=framework_impacts,
        assessments_impacted=assessment_impacts,
        recommended_actions=actions,
    )


def detect_verbiage_changes(
    older: list[ControlStatement],
    newer: list[ControlStatement],
    *,
    match_threshold: float = 0.55,
) -> list[VerbiageChange]:
    """
    Classify language deltas: removed, added, softened, hardened, rewritten, sla_weakened.
    """
    older_by_hash = {s.content_hash: s for s in older}
    newer_by_hash = {s.content_hash: s for s in newer}
    removed = [older_by_hash[h] for h in older_by_hash.keys() - newer_by_hash.keys()]
    added = [newer_by_hash[h] for h in newer_by_hash.keys() - older_by_hash.keys()]

    changes: list[VerbiageChange] = []
    matched_added: set[str] = set()

    for old in removed:
        best: tuple[float, ControlStatement] | None = None
        for new in added:
            if new.content_hash in matched_added:
                continue
            score = _similarity(old.text, new.text)
            if best is None or score > best[0]:
                best = (score, new)
        if best and best[0] >= match_threshold:
            new = best[1]
            matched_added.add(new.content_hash)
            changes.append(_paired_change(old, new, best[0]))
        else:
            changes.append(
                VerbiageChange(
                    change_kind="obligation_removed",
                    before_text=old.text,
                    before_strength=old.strength.value,
                    before_statement_id=old.statement_id,
                    risk_note="Control language was removed. Evidence for mapped controls may fail.",
                )
            )

    for new in added:
        if new.content_hash in matched_added:
            continue
        changes.append(
            VerbiageChange(
                change_kind="obligation_added",
                after_text=new.text,
                after_strength=new.strength.value,
                after_statement_id=new.statement_id,
                risk_note="New obligation added. Confirm owners and evidence still align.",
            )
        )

    return changes


def map_assessments_at_risk(
    frameworks: list[FrameworkImpact],
    assessments: list[AssessmentRegistration],
    *,
    doc_id: str,
) -> list[AssessmentImpact]:
    impacted_frameworks = {f.framework for f in frameworks}
    # NIST control changes also threaten FedRAMP KSI-backed certifications.
    if "NIST 800-53" in impacted_frameworks:
        impacted_frameworks.add("FedRAMP KSI")
        impacted_frameworks.add("FedRAMP")
    framework_risk = {f.framework: f.risk for f in frameworks}
    if "FedRAMP KSI" not in framework_risk and "NIST 800-53" in framework_risk:
        framework_risk["FedRAMP KSI"] = framework_risk["NIST 800-53"]
        framework_risk["FedRAMP"] = framework_risk["NIST 800-53"]
    out: list[AssessmentImpact] = []
    for assessment in assessments:
        if assessment.status != "active":
            continue
        if assessment.doc_ids and doc_id not in assessment.doc_ids:
            continue
        at_risk = sorted(impacted_frameworks.intersection(assessment.frameworks))
        if not at_risk:
            continue
        risk = max((framework_risk.get(f, AlertSeverity.MEDIUM) for f in at_risk), key=_severity_rank)
        reason = (
            f"Policy language change may affect {', '.join(at_risk)} "
            f"evidence for assessment '{assessment.name}'."
        )
        if assessment.fedramp_class:
            reason += (
                f" FedRAMP Class {assessment.fedramp_class.upper()} certification "
                "documentation / KSI evidence may need update."
            )
        out.append(
            AssessmentImpact(
                assessment_id=assessment.assessment_id,
                assessment_name=assessment.name,
                frameworks_at_risk=at_risk,
                risk=risk,
                reason=reason,
            )
        )
    return out


def _paired_change(old: ControlStatement, new: ControlStatement, similarity: float) -> VerbiageChange:
    old_rank = _STRENGTH_RANK[old.strength]
    new_rank = _STRENGTH_RANK[new.strength]
    sla_note = _sla_delta(old.text, new.text)

    if new_rank < old_rank:
        kind = "obligation_softened"
        note = (
            f"Obligation strength weakened from {old.strength.value} "
            f"to {new.strength.value}. Auditors may reject this as weaker control language."
        )
    elif new_rank > old_rank:
        kind = "obligation_hardened"
        note = (
            f"Obligation strength increased from {old.strength.value} "
            f"to {new.strength.value}."
        )
    elif sla_note:
        kind = "sla_changed"
        note = sla_note
    else:
        kind = "obligation_rewritten"
        note = "Control language was rewritten. Re-validate mapped controls and evidence."

    if sla_note and kind != "sla_changed":
        note = f"{note} {sla_note}"

    return VerbiageChange(
        change_kind=kind,
        before_text=old.text,
        after_text=new.text,
        before_strength=old.strength.value,
        after_strength=new.strength.value,
        before_statement_id=old.statement_id,
        after_statement_id=new.statement_id,
        similarity=round(similarity, 3),
        risk_note=note,
    )


def _sla_delta(before: str, after: str) -> str:
    b = _DURATION_RE.search(before)
    a = _DURATION_RE.search(after)
    if not b or not a:
        return ""
    before_hours = _to_hours(int(b.group(1)), b.group(2))
    after_hours = _to_hours(int(a.group(1)), a.group(2))
    if after_hours > before_hours:
        return (
            f"Response window weakened from {b.group(0)} to {a.group(0)}. "
            "This can break assessment commitments and SLAs."
        )
    if after_hours < before_hours:
        return f"Response window tightened from {b.group(0)} to {a.group(0)}."
    return ""


def _to_hours(value: int, unit: str) -> int:
    unit = unit.lower()
    if "day" in unit:
        return value * 24
    return value


def _framework_impacts_from_changes(
    changes: list[VerbiageChange],
    older: list[ControlStatement],
    newer: list[ControlStatement],
    client: CrosswalkClient,
) -> list[FrameworkImpact]:
    older_map = {s.statement_id: s for s in older}
    newer_map = {s.statement_id: s for s in newer}
    by_framework: dict[str, dict[str, object]] = {}

    risky_kinds = {
        "obligation_removed",
        "obligation_softened",
        "sla_changed",
        "obligation_rewritten",
    }

    for change in changes:
        if change.change_kind not in risky_kinds and change.change_kind != "obligation_added":
            continue
        stmt = None
        if change.before_statement_id and change.before_statement_id in older_map:
            stmt = older_map[change.before_statement_id]
        elif change.after_statement_id and change.after_statement_id in newer_map:
            stmt = newer_map[change.after_statement_id]
        if not stmt:
            continue

        hits = client.map_statement(stmt)
        risk = _change_risk(change)
        reason = change.risk_note or change.change_kind
        for hit in hits:
            bucket = by_framework.setdefault(
                hit.framework,
                {"controls": set(), "risk": AlertSeverity.INFO, "reasons": []},
            )
            bucket["controls"].add(hit.control_id)  # type: ignore[index]
            if _severity_rank(risk) > _severity_rank(bucket["risk"]):  # type: ignore[arg-type]
                bucket["risk"] = risk
            reasons: list[str] = bucket["reasons"]  # type: ignore[assignment]
            if reason not in reasons:
                reasons.append(reason)

    # Citation loss across whole document.
    older_cites = {c for s in older for c in s.candidate_framework_ids}
    newer_cites = {c for s in newer for c in s.candidate_framework_ids}
    for lost in sorted(older_cites - newer_cites):
        framework = _framework_for_citation(lost)
        bucket = by_framework.setdefault(
            framework,
            {"controls": set(), "risk": AlertSeverity.INFO, "reasons": []},
        )
        bucket["controls"].add(lost)  # type: ignore[index]
        if _severity_rank(AlertSeverity.HIGH) > _severity_rank(bucket["risk"]):  # type: ignore[arg-type]
            bucket["risk"] = AlertSeverity.HIGH
        reasons = bucket["reasons"]  # type: ignore[assignment]
        note = f"Explicit citation {lost} was removed from the document."
        if note not in reasons:
            reasons.append(note)

    impacts: list[FrameworkImpact] = []
    for framework, data in sorted(by_framework.items()):
        impacts.append(
            FrameworkImpact(
                framework=framework,
                control_ids=sorted(data["controls"]),  # type: ignore[arg-type]
                risk=data["risk"],  # type: ignore[arg-type]
                reason="; ".join(data["reasons"][:3]),  # type: ignore[index]
            )
        )
    return impacts


def _change_risk(change: VerbiageChange) -> AlertSeverity:
    if change.change_kind == "obligation_removed":
        if change.before_strength in {"must", "shall", "prohibited"}:
            return AlertSeverity.CRITICAL
        return AlertSeverity.HIGH
    if change.change_kind == "obligation_softened":
        return AlertSeverity.CRITICAL
    if change.change_kind == "sla_changed" and "weakened" in change.risk_note.lower():
        return AlertSeverity.HIGH
    if change.change_kind == "obligation_rewritten":
        return AlertSeverity.MEDIUM
    if change.change_kind == "obligation_hardened":
        return AlertSeverity.LOW
    return AlertSeverity.INFO


def _roll_up_severity(
    changes: list[VerbiageChange],
    frameworks: list[FrameworkImpact],
    assessments: list[AssessmentImpact],
) -> AlertSeverity:
    ranks = [_change_risk(c) for c in changes if c.change_kind != "obligation_added"]
    ranks.extend(f.risk for f in frameworks)
    ranks.extend(a.risk for a in assessments)
    if not ranks:
        return AlertSeverity.INFO
    return max(ranks, key=_severity_rank)


def _severity_rank(severity: AlertSeverity | str) -> int:
    value = severity.value if isinstance(severity, AlertSeverity) else severity
    order = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
    return order.get(value, 0)


def _build_summary(
    doc_id: str,
    changes: list[VerbiageChange],
    frameworks: list[FrameworkImpact],
    assessments: list[AssessmentImpact],
    severity: AlertSeverity,
) -> str:
    risky = [c for c in changes if c.change_kind != "obligation_added"]
    fw = ", ".join(f.framework for f in frameworks[:4]) or "no mapped frameworks"
    assess = ", ".join(a.assessment_name for a in assessments[:3]) or "no registered assessments"
    return (
        f"[{severity.value.upper()}] Document '{doc_id}' language changed "
        f"({len(risky)} risked obligation deltas). "
        f"Frameworks possibly affected: {fw}. "
        f"Assessments possibly affected: {assess}."
    )


def _recommended_actions(
    changes: list[VerbiageChange],
    frameworks: list[FrameworkImpact],
    assessments: list[AssessmentImpact],
) -> list[str]:
    actions = [
        "Review the changed obligation language with the control owner.",
        "Update the control narrative and evidence links before the next assessment window.",
    ]
    if any(c.change_kind in {"obligation_softened", "obligation_removed"} for c in changes):
        actions.append(
            "Do not publish this version as approved until GRC confirms audit impact."
        )
    if frameworks:
        actions.append(
            "Re-run crosswalk coverage for: "
            + ", ".join(sorted({f.framework for f in frameworks}))
        )
    if assessments:
        actions.append(
            "Notify assessment owners: "
            + ", ".join(sorted({a.assessment_name for a in assessments}))
        )
    return actions


def _fedramp_documentation_actions(
    assessment_impacts: list[AssessmentImpact],
    assessments: list[AssessmentRegistration],
) -> list[str]:
    """Add CR26 documentation-maintenance actions for impacted FedRAMP certifications."""
    impacted_ids = {a.assessment_id for a in assessment_impacts}
    actions: list[str] = []
    try:
        from grc_pdf_mapper.fedramp import documentation_alerts_for_class
    except Exception:
        return actions

    for reg in assessments:
        if reg.assessment_id not in impacted_ids:
            continue
        if not reg.fedramp_class:
            continue
        musts = documentation_alerts_for_class(reg.fedramp_class)
        if not musts:
            continue
        names = ", ".join(f"{m['id']} ({m['name']})" for m in musts[:4])
        actions.append(
            f"FedRAMP Class {reg.fedramp_class.upper()} documentation must stay current: {names}. "
            "Update the Certification Package / Security Decision Record with the policy change."
        )
        # Highlight package maintenance cadence when present.
        for m in musts:
            if m["id"] == "CPO-CSX-CPM" and m.get("timeframe_num"):
                actions.append(
                    f"Certification Package maintenance cadence for Class {reg.fedramp_class.upper()}: "
                    f"every {m['timeframe_num']} {m.get('timeframe_type')}."
                )
    return actions


def _similarity(a: str, b: str) -> float:
    return SequenceMatcher(None, a.lower(), b.lower()).ratio()


def _framework_for_citation(control_id: str) -> str:
    cid = control_id.upper()
    if re.match(r"^(AC|AT|AU|CA|CM|CP|IA|IR|MA|MP|PE|PL|PM|PS|PT|RA|SA|SC|SI|SR)-\d+", cid):
        return "NIST 800-53"
    if cid.startswith("CC") or cid.startswith("P1"):
        return "SOC 2"
    if cid.startswith("PR.") or cid.startswith("GV.") or cid.startswith("DE."):
        return "NIST CSF 2.0"
    if cid.startswith("KSI-"):
        return "FedRAMP KSI"
    if re.match(r"^\d+\.\d+", cid):
        return "ISO 27001"
    return "Unknown"
