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
    r"\b(?:within|no later than)\s+"
    r"(\d+|one|two|three|four|five|six|seven|eight|nine|ten|twelve|twenty-four)\s+"
    r"(minute|minutes|hour|hours|day|days|business day|business days|week|weeks|month|months)\b",
    re.IGNORECASE,
)

_EVERY_DURATION_RE = re.compile(
    r"\bevery\s+(\d+|one|two|three|four|five|six|seven|eight|nine|ten|twelve)\s+"
    r"(minute|minutes|hour|hours|day|days|week|weeks|month|months)\b",
    re.IGNORECASE,
)

_CADENCE_HOURS = {
    "hourly": 1.0,
    "daily": 24.0,
    "weekly": 24.0 * 7,
    "monthly": 24.0 * 30,
    "quarterly": 24.0 * 90,
    "annually": 24.0 * 365,
    "yearly": 24.0 * 365,
}

_RETENTION_DURATION_RE = re.compile(
    r"\b(?:retain(?:ed|s|ing)?|retention(?:\s+period)?(?:\s+of)?|keep|kept)\b"
    r".{0,40}?\b(?:for\s+)?"
    r"(\d+|one|two|three|four|five|six|seven|eight|nine|ten|twelve|twenty-four)\s+"
    r"(minute|minutes|hour|hours|day|days|business day|business days|week|weeks|"
    r"month|months|year|years)\b",
    re.IGNORECASE,
)

_MINIMUM_THRESHOLD_RE = re.compile(
    r"\b(?:at\s+least|minimum(?:\s+(?:length|count))?(?:\s+of)?|"
    r"no\s+fewer\s+than)\s+(\d+)\s*"
    r"(characters?|factors?|approvals?|reviewers?|copies?|instances?|bits?)?\b",
    re.IGNORECASE,
)

_EXCEPTION_PHRASES = (
    "where feasible",
    "when feasible",
    "where practical",
    "when practical",
    "as appropriate",
    "if possible",
    "when convenient",
    "unless otherwise approved",
    "except as approved",
    "except for",
    "subject to approval",
    "with approval",
    "to the extent possible",
    "where technically possible",
    "unless",
)
_DYNAMIC_EXCEPTION_RE = re.compile(
    r"\bif\b[^.;]{0,60}\b(?:approve|approves|approved|authorize|authorizes|"
    r"authorized|permit|permits|permitted)\b|"
    r"\bexcept\s+(?:during|when|while|under|on)\b[^.;]*|"
    r"\bwith\b[^.;]{0,40}\bapproval\b",
    re.IGNORECASE,
)
_UNIVERSAL_SCOPE = ("all", "each", "any")
_LIMITED_SCOPE = (
    "some",
    "selected",
    "designated",
    "where applicable",
    "only selected",
    "only designated",
    "only for",
)
_MATCH_STOPWORDS = {
    "a",
    "an",
    "and",
    "are",
    "be",
    "for",
    "in",
    "is",
    "of",
    "on",
    "or",
    "the",
    "to",
}
_OPPOSITE_ACTIONS = {
    frozenset({"allow", "deny"}),
    frozenset({"approve", "reject"}),
    frozenset({"block", "permit"}),
    frozenset({"disable", "enable"}),
    frozenset({"grant", "revoke"}),
    frozenset({"grant", "deny"}),
}
_ACTION_NORMALIZATION = {
    "allowed": "allow",
    "approved": "approve",
    "blocked": "block",
    "denied": "deny",
    "disabled": "disable",
    "enabled": "enable",
    "encrypted": "encrypt",
    "prevented": "prevent",
    "prohibited": "prohibit",
    "rejected": "reject",
    "retained": "retain",
    "revoked": "revoke",
}
_HEADING_SCOPE_QUALIFIERS = {
    "all",
    "development",
    "designated",
    "nonproduction",
    "production",
    "selected",
    "some",
    "staging",
    "test",
}


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
    match_threshold: float = 0.5,
) -> list[VerbiageChange]:
    """
    Classify language deltas: removed, added, softened, hardened, rewritten, sla_weakened.
    """
    older_by_hash = {s.content_hash: s for s in older}
    newer_by_hash = {s.content_hash: s for s in newer}
    removed = [older_by_hash[h] for h in older_by_hash.keys() - newer_by_hash.keys()]
    added = [newer_by_hash[h] for h in newer_by_hash.keys() - older_by_hash.keys()]

    changes: list[VerbiageChange] = []
    candidates = sorted(
        (
            (_match_score(old, new), old, new)
            for old in removed
            for new in added
        ),
        key=lambda item: item[0],
        reverse=True,
    )
    matched_old: set[str] = set()
    matched_added: set[str] = set()
    pairs: dict[str, tuple[ControlStatement, float]] = {}
    for score, old, new in candidates:
        if score < match_threshold:
            break
        if old.content_hash in matched_old or new.content_hash in matched_added:
            continue
        matched_old.add(old.content_hash)
        matched_added.add(new.content_hash)
        pairs[old.content_hash] = (new, score)

    for old in removed:
        pair = pairs.get(old.content_hash)
        if pair:
            changes.append(_paired_change(old, pair[0], pair[1]))
        else:
            changes.append(
                VerbiageChange(
                    change_kind="obligation_removed",
                    before_text=old.text,
                    before_strength=old.strength.value,
                    before_statement_id=old.statement_id,
                    classification_confidence=max(0.85, old.classification_confidence),
                    classification_reasons=["no suitable replacement statement was found"],
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
                classification_confidence=max(0.8, new.classification_confidence),
                classification_reasons=["no prior statement matched the new obligation"],
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
    quantitative_delta = _quantitative_delta(old.text, new.text)
    added_exceptions = sorted(
        _exception_markers(new.text) - _exception_markers(old.text)
    )
    removed_exceptions = sorted(
        _exception_markers(old.text) - _exception_markers(new.text)
    )
    old_context = " ".join([*old.heading_path, old.text])
    new_context = " ".join([*new.heading_path, new.text])
    old_universal = _universal_scope_markers(old)
    new_universal = _universal_scope_markers(new)
    new_limited = _phrases(new_context, _LIMITED_SCOPE)
    old_action = _main_action(old.text)
    new_action = _main_action(new.text)
    reasons = [f"paired statement score={similarity:.3f}"]

    if old.action_polarity != new.action_polarity:
        kind = "obligation_reversed"
        note = "The action polarity changed. Confirm that the control direction is intended."
        reasons.append(
            f"action polarity changed from {old.action_polarity} to {new.action_polarity}"
        )
    elif (
        old_action
        and new_action
        and frozenset({old_action, new_action}) in _OPPOSITE_ACTIONS
    ):
        kind = "obligation_reversed"
        note = "The required action changed to its opposite. Confirm the control direction."
        reasons.append(f"main action changed from {old_action} to {new_action}")
    elif old.strength == ObligationStrength.PROHIBITED and new.strength in {
        ObligationStrength.MUST,
        ObligationStrength.SHALL,
    }:
        kind = "obligation_reversed"
        note = "A prohibited action became a mandatory action. Confirm the intended control direction."
        reasons.append("prohibition changed to a mandatory obligation")
    elif new.strength == ObligationStrength.PROHIBITED and old.strength in {
        ObligationStrength.MUST,
        ObligationStrength.SHALL,
    }:
        kind = "obligation_reversed"
        note = "A mandatory action became prohibited. Confirm the intended control direction."
        reasons.append("mandatory obligation changed to a prohibition")
    elif (
        old.strength == ObligationStrength.PROHIBITED
        and new.strength == ObligationStrength.SHOULD
        and old.action_polarity == "negative"
        and new.action_polarity == "negative"
    ):
        kind = "obligation_softened"
        note = "A binding prohibition became a negative recommendation."
        reasons.append("prohibition strength decreased to SHOULD")
    elif old.strength == ObligationStrength.PROHIBITED and new.strength != ObligationStrength.PROHIBITED:
        kind = "prohibition_removed"
        note = "Prohibition language was removed or replaced with weaker language."
        reasons.append("prohibition is not present in the replacement")
    elif new_rank < old_rank:
        kind = "obligation_softened"
        note = (
            f"Obligation strength weakened from {old.strength.value} "
            f"to {new.strength.value}. Auditors may reject this as weaker control language."
        )
        reasons.append("normative strength decreased")
    elif new_rank > old_rank:
        kind = "obligation_hardened"
        note = (
            f"Obligation strength increased from {old.strength.value} "
            f"to {new.strength.value}."
        )
        reasons.append("normative strength increased")
    elif added_exceptions:
        kind = "obligation_softened"
        note = "New exception language can reduce the control scope: " + ", ".join(added_exceptions) + "."
        reasons.append("exception qualifiers were added")
    elif (
        old_universal and (not new_universal or new_limited)
    ) or (
        new_limited
        and not _phrases(old_context, _LIMITED_SCOPE)
    ) or _subject_scope_narrowed(old.text, new.text):
        kind = "scope_reduced"
        note = "Universal control scope was reduced or replaced with limited scope language."
        reasons.append("universal scope language was removed or limited")
    elif (
        new_universal and not old_universal
    ) or _subject_scope_narrowed(new.text, old.text):
        kind = "scope_expanded"
        note = "The control now applies to a broader or universal scope."
        reasons.append("universal scope language was added")
    elif removed_exceptions:
        kind = "obligation_hardened"
        note = "Exception language was removed: " + ", ".join(removed_exceptions) + "."
        reasons.append("exception qualifiers were removed")
    elif quantitative_delta:
        kind, note, reason = quantitative_delta
        reasons.append(reason)
    elif sla_note:
        kind = "sla_changed"
        note = sla_note
        reasons.append("measurable response window changed")
    elif _modal_equivalent(old.text, new.text):
        kind = "non_material_rewording"
        note = "Mandatory modal wording changed without changing the control strength."
        reasons.append("MUST and SHALL are treated as mandatory equivalents")
    elif _cadence_equivalent(old.text, new.text):
        kind = "non_material_rewording"
        note = "Cadence wording changed without changing the measured interval."
        reasons.append("cadence intervals are quantitatively equivalent")
    elif _active_passive_equivalent(old.text, new.text):
        kind = "non_material_rewording"
        note = "Active and passive wording describe the same control obligation."
        reasons.append("active and passive semantic signatures match")
    elif _generic_any_equivalent(old.text, new.text):
        kind = "non_material_rewording"
        note = "Generic plural prohibition wording did not change the control scope."
        reasons.append("object determiner ANY was removed without changing the prohibition")
    elif old.text.strip().lower() == new.text.strip().lower() and _benign_heading_rename(
        old.heading_path, new.heading_path
    ):
        kind = "non_material_rewording"
        note = "The heading changed without changing the control text or its scope."
        reasons.append("heading taxonomy expanded without a scope qualifier")
    else:
        kind = "obligation_rewritten"
        note = "Control language was rewritten. Re-validate mapped controls and evidence."
        reasons.append("semantic wording changed without a strength or scope transition")

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
        classification_confidence=round(
            min(
                similarity,
                old.classification_confidence or similarity,
                new.classification_confidence or similarity,
            ),
            2,
        ),
        classification_reasons=reasons,
        risk_note=note,
    )


def _exception_markers(text: str) -> set[str]:
    markers = _phrases(text, _EXCEPTION_PHRASES)
    markers.update(
        match.group(0).lower().strip()
        for match in _DYNAMIC_EXCEPTION_RE.finditer(text)
    )
    return markers


def _universal_scope_markers(statement: ControlStatement) -> set[str]:
    """Find universal terms in headings or before the statement modal."""
    heading_text = " ".join(statement.heading_path)
    markers = _phrases(heading_text, _UNIVERSAL_SCOPE)
    modal = _modal_match(statement.text)
    subject = statement.text[: modal.start()] if modal else statement.text
    markers.update(_phrases(subject, _UNIVERSAL_SCOPE))
    return markers


def _modal_match(text: str) -> re.Match[str] | None:
    return re.search(
        r"\b(?:must\s+(?:not|never)|shall\s+(?:not|never)|"
        r"should\s+(?:not|never)|may\s+not|must|shall|should|may|"
        r"has\s+to|have\s+to|needs?\s+to|(?:is|are)\s+required(?:\s+to)?)\b",
        text,
        re.IGNORECASE,
    )


def _subject_scope_narrowed(before: str, after: str) -> bool:
    before_modal = _modal_match(before)
    after_modal = _modal_match(after)
    if not before_modal or not after_modal:
        return False
    before_predicate = _normalized_text(before[before_modal.start() :])
    after_predicate = _normalized_text(after[after_modal.start() :])
    if before_predicate != after_predicate:
        return False
    before_subject = _tokens(before[: before_modal.start()])
    after_subject = _tokens(after[: after_modal.start()])
    return bool(before_subject and before_subject < after_subject)


def _active_passive_equivalent(before: str, after: str) -> bool:
    passive_re = re.compile(
        r"\b(?:must|shall|should|may)\s+(?:not\s+|never\s+)?"
        r"be\s+[a-z]+(?:ed|en)\b",
        re.IGNORECASE,
    )
    if bool(passive_re.search(before)) == bool(passive_re.search(after)):
        return False
    return _semantic_signature(before) == _semantic_signature(after)


def _semantic_signature(text: str) -> list[str]:
    ignored = _MATCH_STOPWORDS | {
        "be",
        "by",
        "may",
        "must",
        "not",
        "shall",
        "should",
    }
    return sorted(
        _normalize_action(token)
        for token in re.findall(r"[a-z0-9]+", text.lower())
        if token not in ignored
    )


def _generic_any_equivalent(before: str, after: str) -> bool:
    negative_modal = re.compile(
        r"\b(?:must|shall|should|may)\s+(?:not|never)\b", re.IGNORECASE
    )
    if not negative_modal.search(before) or not negative_modal.search(after):
        return False
    normalize = lambda value: _normalized_text(  # noqa: E731
        re.sub(r"\bany\s+", "", value, flags=re.IGNORECASE)
    )
    return normalize(before) == normalize(after)


def _benign_heading_rename(before: list[str], after: list[str]) -> bool:
    before_tokens = _tokens(" ".join(before))
    after_tokens = _tokens(" ".join(after))
    if not before_tokens or not after_tokens:
        return False
    changed = before_tokens.symmetric_difference(after_tokens)
    return (
        bool(before_tokens <= after_tokens or after_tokens <= before_tokens)
        and not changed.intersection(_HEADING_SCOPE_QUALIFIERS)
    )


def _normalized_text(text: str) -> str:
    return " ".join(re.findall(r"[a-z0-9]+", text.lower()))


def _sla_delta(before: str, after: str) -> str:
    before_windows = list(_DURATION_RE.finditer(before))
    after_windows = list(_DURATION_RE.finditer(after))
    before_immediate = bool(re.search(r"\bimmediately\b", before, re.IGNORECASE))
    after_immediate = bool(re.search(r"\bimmediately\b", after, re.IGNORECASE))

    if before_windows and not after_windows and not after_immediate:
        return (
            f"Response deadline {before_windows[-1].group(0)} was removed. "
            "This can break assessment commitments and SLAs."
        )
    if before_immediate and after_windows:
        return (
            f"Response window weakened from immediately to {after_windows[0].group(0)}. "
            "This can break assessment commitments and SLAs."
        )
    if before_immediate and not after_immediate and not after_windows:
        return (
            "Response deadline immediately was removed and the response window weakened. "
            "This can break assessment commitments and SLAs."
        )
    if before_windows and after_immediate:
        return f"Response window tightened from {before_windows[0].group(0)} to immediately."
    if after_immediate and not before_immediate and not before_windows:
        return "Response window tightened from no measurable deadline to immediately."

    for before_match, after_match in zip(before_windows, after_windows):
        before_hours = _to_hours(
            _number_value(before_match.group(1)), before_match.group(2)
        )
        after_hours = _to_hours(
            _number_value(after_match.group(1)), after_match.group(2)
        )
        if after_hours > before_hours:
            return (
                f"Response window weakened from {before_match.group(0)} to "
                f"{after_match.group(0)}. This can break assessment commitments and SLAs."
            )
        if after_hours < before_hours:
            return (
                f"Response window tightened from {before_match.group(0)} to "
                f"{after_match.group(0)}."
            )
    if len(before_windows) > len(after_windows):
        return "A response deadline was removed. This can break assessment commitments and SLAs."

    before_cadence = _cadence_hours(before)
    after_cadence = _cadence_hours(after)
    if before_cadence is not None and after_cadence is not None:
        if after_cadence > before_cadence:
            return "Control cadence weakened to a less frequent interval."
        if after_cadence < before_cadence:
            return "Control cadence tightened to a more frequent interval."
    return ""


def _number_value(value: str) -> int:
    if value.isdigit():
        return int(value)
    return {
        "one": 1,
        "two": 2,
        "three": 3,
        "four": 4,
        "five": 5,
        "six": 6,
        "seven": 7,
        "eight": 8,
        "nine": 9,
        "ten": 10,
        "twelve": 12,
        "twenty-four": 24,
    }[value.lower()]


def _cadence_hours(text: str) -> float | None:
    every = _EVERY_DURATION_RE.search(text)
    if every:
        return _to_hours(_number_value(every.group(1)), every.group(2))
    lowered = text.lower()
    for label, hours in _CADENCE_HOURS.items():
        if re.search(rf"\b{label}\b", lowered):
            return hours
    return None


def _modal_equivalent(before: str, after: str) -> bool:
    if before.strip().lower() == after.strip().lower():
        return False
    normalize = lambda value: re.sub(  # noqa: E731
        r"\b(?:must|shall)\b", "mandatory", value.lower()
    )
    return normalize(before) == normalize(after)


def _cadence_equivalent(before: str, after: str) -> bool:
    if before.strip().lower() == after.strip().lower():
        return False
    before_hours = _cadence_hours(before)
    after_hours = _cadence_hours(after)
    return (
        before_hours is not None
        and after_hours is not None
        and before_hours == after_hours
    )


def _quantitative_delta(before: str, after: str) -> tuple[str, str, str] | None:
    """Classify reviewed retention and minimum-threshold changes."""
    retention_before = _RETENTION_DURATION_RE.search(before)
    retention_after = _RETENTION_DURATION_RE.search(after)
    if retention_before and not retention_after:
        return (
            "retention_weakened",
            f"Retention period {retention_before.group(0)} was removed. "
            "This can invalidate evidence and records commitments.",
            "measurable retention period was removed",
        )
    if retention_after and not retention_before:
        return (
            "retention_hardened",
            f"Retention period {retention_after.group(0)} was added.",
            "measurable retention period was added",
        )
    if retention_before and retention_after:
        before_hours = _to_hours(
            _number_value(retention_before.group(1)), retention_before.group(2)
        )
        after_hours = _to_hours(
            _number_value(retention_after.group(1)), retention_after.group(2)
        )
        if after_hours < before_hours:
            return (
                "retention_weakened",
                f"Retention decreased from {retention_before.group(0)} to "
                f"{retention_after.group(0)}. This can invalidate evidence and records commitments.",
                "measurable retention period decreased",
            )
        if after_hours > before_hours:
            return (
                "retention_hardened",
                f"Retention increased from {retention_before.group(0)} to "
                f"{retention_after.group(0)}.",
                "measurable retention period increased",
            )

    minimum_before = _MINIMUM_THRESHOLD_RE.search(before)
    minimum_after = _MINIMUM_THRESHOLD_RE.search(after)
    if minimum_before and minimum_after:
        before_value = int(minimum_before.group(1))
        after_value = int(minimum_after.group(1))
        before_unit = (minimum_before.group(2) or "units").lower()
        after_unit = (minimum_after.group(2) or "units").lower()
        if before_unit != after_unit:
            return None
        if after_value < before_value:
            return (
                "threshold_weakened",
                f"Minimum threshold decreased from {before_value} {before_unit} to "
                f"{after_value} {after_unit}.",
                "measurable minimum threshold decreased",
            )
        if after_value > before_value:
            return (
                "threshold_hardened",
                f"Minimum threshold increased from {before_value} {before_unit} to "
                f"{after_value} {after_unit}.",
                "measurable minimum threshold increased",
            )
    return None


def _to_hours(value: int, unit: str) -> float:
    unit = unit.lower()
    if "minute" in unit:
        return max(1, value) / 60
    if "day" in unit:
        return value * 24
    if "week" in unit:
        return value * 24 * 7
    if "month" in unit:
        return value * 24 * 30
    if "year" in unit:
        return value * 24 * 365
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
        "scope_reduced",
        "prohibition_removed",
        "obligation_reversed",
        "sla_changed",
        "retention_weakened",
        "threshold_weakened",
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
    if change.change_kind in {
        "obligation_softened",
        "scope_reduced",
        "prohibition_removed",
        "obligation_reversed",
        "retention_weakened",
        "threshold_weakened",
    }:
        return AlertSeverity.CRITICAL
    if change.change_kind == "sla_changed" and "weakened" in change.risk_note.lower():
        return AlertSeverity.HIGH
    if change.change_kind == "obligation_rewritten":
        return AlertSeverity.MEDIUM
    if change.change_kind in {
        "obligation_hardened",
        "scope_expanded",
        "retention_hardened",
        "threshold_hardened",
    }:
        return AlertSeverity.LOW
    return AlertSeverity.INFO


def verbiage_change_severity(change: VerbiageChange) -> AlertSeverity:
    """Return the gate severity for one classified wording change."""
    return _change_risk(change)


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
    if any(
        c.change_kind
        in {
            "obligation_softened",
            "obligation_removed",
            "scope_reduced",
            "prohibition_removed",
            "obligation_reversed",
        }
        for c in changes
    ):
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


def _match_score(old: ControlStatement, new: ControlStatement) -> float:
    """Score statement pairs with text, domain, citation, and heading evidence."""
    sequence = _similarity(old.text, new.text)
    old_tokens = _tokens(old.text)
    new_tokens = _tokens(new.text)
    token_union = old_tokens | new_tokens
    token_score = len(old_tokens & new_tokens) / len(token_union) if token_union else 0.0
    score = (0.65 * sequence) + (0.2 * token_score)
    if set(old.keywords).intersection(new.keywords):
        score += 0.08
    if set(old.candidate_framework_ids).intersection(new.candidate_framework_ids):
        score += 0.05
    if old.heading_path and new.heading_path and old.heading_path[-1] == new.heading_path[-1]:
        score += 0.02
    old_action = _main_action(old.text)
    new_action = _main_action(new.text)
    if old_action and new_action:
        if old_action == new_action:
            score += 0.05
        elif frozenset({old_action, new_action}) in _OPPOSITE_ACTIONS:
            score += 0.02
        else:
            score -= 0.22
    return round(max(0.0, min(score, 1.0)), 4)


def _main_action(text: str) -> str:
    match = re.search(
        r"\b(?:must|shall|should|may|has\s+to|have\s+to|needs?\s+to|"
        r"(?:is|are)\s+required\s+to|will)\s+(?:not\s+|never\s+)?"
        r"(?:be\s+)?(?P<action>[a-z]+)",
        text,
        re.IGNORECASE,
    )
    return _normalize_action(match.group("action")) if match else ""


def _normalize_action(action: str) -> str:
    return _ACTION_NORMALIZATION.get(action.lower(), action.lower())


def _similarity(a: str, b: str) -> float:
    return SequenceMatcher(None, a.lower(), b.lower()).ratio()


def _tokens(text: str) -> set[str]:
    return {
        token
        for token in re.findall(r"[a-z0-9]+", text.lower())
        if token not in _MATCH_STOPWORDS and len(token) > 1
    }


def _phrases(text: str, phrases: tuple[str, ...]) -> set[str]:
    lowered = text.lower()
    found: set[str] = set()
    for phrase in phrases:
        if " " in phrase:
            if phrase in lowered:
                found.add(phrase)
        elif re.search(rf"\b{re.escape(phrase)}\b", lowered):
            found.add(phrase)
    return found


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
