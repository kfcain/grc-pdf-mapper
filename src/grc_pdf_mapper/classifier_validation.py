"""Evaluate classifiers against a human-reviewed JSON corpus."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field

from grc_pdf_mapper.extract import extract_control_statements
from grc_pdf_mapper.impact import detect_verbiage_changes
from grc_pdf_mapper.models import ControlStatement
from grc_pdf_mapper.scf import ScfClient
from grc_pdf_mapper.terraform_classify import classify_terraform_resource


class ClassifierMetric(BaseModel):
    name: str
    cases: int
    correct: int = 0
    true_positive: int = 0
    false_positive: int = 0
    false_negative: int = 0
    accuracy: float = 0.0
    precision: float = 0.0
    recall: float = 0.0
    f1: float = 0.0


class ClassifierCaseResult(BaseModel):
    case_id: str
    classifier: str
    passed: bool
    expected: dict[str, Any] = Field(default_factory=dict)
    actual: dict[str, Any] = Field(default_factory=dict)
    reasons: list[str] = Field(default_factory=list)


class ClassifierValidationReport(BaseModel):
    corpus_path: str
    corpus_version: str = ""
    case_count: int
    passed_case_count: int
    failed_case_count: int
    minimum_score: float
    passed: bool
    metrics: dict[str, ClassifierMetric] = Field(default_factory=dict)
    cases: list[ClassifierCaseResult] = Field(default_factory=list)
    failures: list[str] = Field(default_factory=list)


def evaluate_classifier_corpus(
    path: str | Path,
    *,
    minimum_score: float = 0.95,
) -> ClassifierValidationReport:
    """Run policy, Terraform, and wording-change gold cases."""
    path = Path(path)
    corpus = json.loads(path.read_text(encoding="utf-8"))
    results: list[ClassifierCaseResult] = []

    for case in corpus.get("policy", []):
        results.append(_evaluate_policy_case(case))
    for case in corpus.get("terraform", []):
        results.append(_evaluate_terraform_case(case))
    for case in corpus.get("changes", []):
        results.append(_evaluate_change_case(case))
    for case in corpus.get("alignment", []):
        results.append(_evaluate_alignment_case(case))
    for case in corpus.get("scf", []):
        results.append(_evaluate_scf_case(case))

    metrics = _build_metrics(results)
    failures: list[str] = []
    for name, metric in metrics.items():
        if metric.accuracy < minimum_score:
            failures.append(
                f"{name} accuracy {metric.accuracy:.3f} is below {minimum_score:.3f}"
            )
        if (metric.true_positive or metric.false_positive or metric.false_negative) and (
            metric.precision < minimum_score
            or metric.recall < minimum_score
            or metric.f1 < minimum_score
        ):
            failures.append(
                f"{name} label score is below {minimum_score:.3f}: "
                f"precision={metric.precision:.3f}, recall={metric.recall:.3f}, "
                f"f1={metric.f1:.3f}"
            )

    failed_cases = [result for result in results if not result.passed]
    if failed_cases:
        failures.append(
            f"{len(failed_cases)} reviewed classifier case(s) did not match exactly"
        )
    return ClassifierValidationReport(
        corpus_path=str(path),
        corpus_version=str(corpus.get("version", "")),
        case_count=len(results),
        passed_case_count=len(results) - len(failed_cases),
        failed_case_count=len(failed_cases),
        minimum_score=minimum_score,
        passed=not failures and not failed_cases,
        metrics=metrics,
        cases=results,
        failures=failures,
    )


def _evaluate_policy_case(case: dict[str, Any]) -> ClassifierCaseResult:
    case_id = str(case["id"])
    statements = extract_control_statements(str(case["text"]), doc_slug=f"gold-{case_id}")
    expected_statements = list(case.get("statements", []))
    if expected_statements:
        expected_domains = sorted(
            {
                domain
                for item in expected_statements
                for domain in item.get("domains", [])
            }
        )
        actual_rows = [
            {
                "text": statement.text,
                "kind": statement.statement_kind.value,
                "strength": statement.strength.value,
                "action_polarity": statement.action_polarity,
                "domains": sorted(statement.keywords),
                "status": statement.classification_status,
            }
            for statement in statements
        ]
        reasons: list[str] = []
        for expected_row in expected_statements:
            text_contains = str(expected_row.get("text_contains", "")).lower()
            candidates = [
                row
                for row in actual_rows
                if not text_contains or text_contains in row["text"].lower()
            ]
            if not candidates:
                reasons.append(f"statement containing {text_contains!r} was not extracted")
                continue
            row = candidates[0]
            for key in (
                "kind",
                "strength",
                "action_polarity",
                "domains",
                "status",
            ):
                if key not in expected_row:
                    continue
                expected_value = (
                    sorted(expected_row[key])
                    if key == "domains"
                    else expected_row[key]
                )
                if row[key] != expected_value:
                    reasons.append(f"{text_contains!r} {key} did not match")
        if len(statements) != len(expected_statements):
            reasons.append(
                f"expected {len(expected_statements)} statements, got {len(statements)}"
            )
        return ClassifierCaseResult(
            case_id=case_id,
            classifier="policy",
            passed=not reasons,
            expected={
                "extract": True,
                "domains": expected_domains,
                "statements": expected_statements,
            },
            actual={
                "extract": bool(statements),
                "domains": sorted(
                    {domain for statement in statements for domain in statement.keywords}
                ),
                "statements": actual_rows,
            },
            reasons=reasons,
        )
    expected_extract = bool(case.get("extract", True))
    actual_extract = bool(statements)
    expected = {
        "extract": expected_extract,
        "kind": case.get("kind"),
        "strength": case.get("strength"),
        "action_polarity": case.get("action_polarity"),
        "domains": sorted(case.get("domains", [])),
        "status": case.get("status"),
    }
    actual: dict[str, Any] = {"extract": actual_extract}
    reasons: list[str] = []
    passed = expected_extract == actual_extract
    if expected_extract and statements:
        statement = statements[0]
        actual.update(
            {
                "kind": statement.statement_kind.value,
                "strength": statement.strength.value,
                "action_polarity": statement.action_polarity,
                "domains": sorted(statement.keywords),
                "status": statement.classification_status,
                "confidence": statement.classification_confidence,
            }
        )
        for key in ("kind", "strength", "action_polarity", "domains", "status"):
            if expected.get(key) is not None and actual.get(key) != expected.get(key):
                passed = False
                reasons.append(f"{key} did not match")
    elif expected_extract:
        reasons.append("expected one extracted statement")
    elif statements:
        reasons.append("non-control text was extracted")
    return ClassifierCaseResult(
        case_id=case_id,
        classifier="policy",
        passed=passed,
        expected=expected,
        actual=actual,
        reasons=reasons,
    )


def _evaluate_terraform_case(case: dict[str, Any]) -> ClassifierCaseResult:
    case_id = str(case["id"])
    classification = classify_terraform_resource(
        str(case["resource_type"]),
        str(case.get("block", "")),
        tags=case.get("tags", {}),
        annotations=case.get("annotations", {}),
    )
    expected = {
        "security_sensitive": bool(case.get("security_sensitive", True)),
        "domains": sorted(case.get("domains", [])),
        "control_ids": sorted(case.get("control_ids", [])),
    }
    if "status" in case:
        expected["status"] = str(case["status"])
    if "posture" in case:
        expected["posture"] = str(case["posture"])
    actual = {
        "security_sensitive": classification.security_sensitive,
        "domains": sorted(classification.domains),
        "control_ids": sorted(classification.candidate_control_ids),
        "confidence": classification.confidence,
        "status": classification.status,
        "posture": classification.posture,
    }
    compared_keys = ["security_sensitive", "domains", "control_ids"]
    if "status" in expected:
        compared_keys.append("status")
    if "posture" in expected:
        compared_keys.append("posture")
    reasons = [
        f"{key} did not match"
        for key in compared_keys
        if actual[key] != expected[key]
    ]
    return ClassifierCaseResult(
        case_id=case_id,
        classifier="terraform",
        passed=not reasons,
        expected=expected,
        actual=actual,
        reasons=reasons,
    )


def _evaluate_change_case(case: dict[str, Any]) -> ClassifierCaseResult:
    case_id = str(case["id"])
    older = extract_control_statements(
        str(case.get("before", "")), doc_slug=f"gold-{case_id}-before"
    )
    newer = extract_control_statements(
        str(case.get("after", "")), doc_slug=f"gold-{case_id}-after"
    )
    changes = detect_verbiage_changes(older, newer)
    actual_kinds = [change.change_kind for change in changes]
    expected_kinds = list(case.get("kinds", [case.get("kind")]))
    expected_kinds = [str(value) for value in expected_kinds if value]
    passed = sorted(actual_kinds) == sorted(expected_kinds)
    return ClassifierCaseResult(
        case_id=case_id,
        classifier="change",
        passed=passed,
        expected={"kinds": expected_kinds},
        actual={"kinds": actual_kinds},
        reasons=[] if passed else ["change kind did not match"],
    )


def _evaluate_alignment_case(case: dict[str, Any]) -> ClassifierCaseResult:
    """Check that both classifiers produce the same reviewed domain set."""
    case_id = str(case["id"])
    statements = extract_control_statements(
        str(case["policy_text"]), doc_slug=f"gold-{case_id}-policy"
    )
    terraform = classify_terraform_resource(
        str(case["resource_type"]),
        str(case.get("block", "")),
        tags=case.get("tags", {}),
        annotations=case.get("annotations", {}),
    )
    expected_domains = sorted(case.get("domains", []))
    policy_domains = sorted(statements[0].keywords) if statements else []
    terraform_domains = sorted(terraform.domains)
    expected = {
        "policy_domains": expected_domains,
        "terraform_domains": expected_domains,
    }
    actual = {
        "policy_domains": policy_domains,
        "terraform_domains": terraform_domains,
        "aligned": policy_domains == terraform_domains,
    }
    reasons: list[str] = []
    if not statements:
        reasons.append("policy statement was not extracted")
    if policy_domains != expected_domains:
        reasons.append("policy domains did not match reviewed domains")
    if terraform_domains != expected_domains:
        reasons.append("Terraform domains did not match reviewed domains")
    if policy_domains != terraform_domains:
        reasons.append("policy and Terraform domains did not align")
    return ClassifierCaseResult(
        case_id=case_id,
        classifier="alignment",
        passed=not reasons,
        expected=expected,
        actual=actual,
        reasons=reasons,
    )


def _evaluate_scf_case(case: dict[str, Any]) -> ClassifierCaseResult:
    """Check deterministic offline SCF mapping and confidence provenance."""
    case_id = str(case["id"])
    source_confidence = float(case.get("source_confidence", 0.9))
    statement = ControlStatement(
        statement_id=f"gold-{case_id}",
        text=str(case.get("text", "")),
        keywords=list(case.get("domains", [])),
        candidate_framework_ids=list(case.get("control_ids", [])),
        classification_confidence=source_confidence,
        content_hash=case_id,
    )
    with ScfClient(offline=True) as client:
        hits = client.map_statement(statement)
    expected_ids = sorted(case.get("scf_control_ids", []))
    actual_ids = sorted(
        {hit.control_id for hit in hits if hit.framework == "SCF"}
    )
    confidence_capped = all(hit.confidence <= source_confidence for hit in hits)
    expected = {
        "scf_control_ids": expected_ids,
        "confidence_capped": bool(case.get("confidence_capped", True)),
    }
    actual = {
        "scf_control_ids": actual_ids,
        "confidence_capped": confidence_capped,
        "hit_count": len(hits),
    }
    reasons: list[str] = []
    if actual_ids != expected_ids:
        reasons.append("SCF control IDs did not match")
    if actual["confidence_capped"] != expected["confidence_capped"]:
        reasons.append("SCF confidence exceeded source-classifier confidence")
    return ClassifierCaseResult(
        case_id=case_id,
        classifier="scf",
        passed=not reasons,
        expected=expected,
        actual=actual,
        reasons=reasons,
    )


def _build_metrics(
    results: list[ClassifierCaseResult],
) -> dict[str, ClassifierMetric]:
    metrics: dict[str, ClassifierMetric] = {}
    for classifier in ("policy", "terraform", "change", "alignment", "scf"):
        selected = [result for result in results if result.classifier == classifier]
        if not selected:
            continue
        metrics[f"{classifier}_cases"] = _exact_metric(
            f"{classifier}_cases", selected
        )

    policy = [result for result in results if result.classifier == "policy"]
    if policy:
        metrics["policy_domains"] = _label_metric(
            "policy_domains", policy, "domains"
        )
    terraform = [result for result in results if result.classifier == "terraform"]
    if terraform:
        metrics["terraform_domains"] = _label_metric(
            "terraform_domains", terraform, "domains"
        )
        metrics["terraform_controls"] = _label_metric(
            "terraform_controls", terraform, "control_ids"
        )
    alignment = [result for result in results if result.classifier == "alignment"]
    if alignment:
        metrics["alignment_policy_domains"] = _label_metric(
            "alignment_policy_domains", alignment, "policy_domains"
        )
        metrics["alignment_terraform_domains"] = _label_metric(
            "alignment_terraform_domains", alignment, "terraform_domains"
        )
    scf = [result for result in results if result.classifier == "scf"]
    if scf:
        metrics["scf_controls"] = _label_metric(
            "scf_controls", scf, "scf_control_ids"
        )
    return metrics


def _exact_metric(
    name: str, results: list[ClassifierCaseResult]
) -> ClassifierMetric:
    correct = sum(result.passed for result in results)
    accuracy = correct / len(results) if results else 1.0
    return ClassifierMetric(
        name=name,
        cases=len(results),
        correct=correct,
        accuracy=round(accuracy, 4),
        precision=round(accuracy, 4),
        recall=round(accuracy, 4),
        f1=round(accuracy, 4),
    )


def _label_metric(
    name: str,
    results: list[ClassifierCaseResult],
    key: str,
) -> ClassifierMetric:
    true_positive = false_positive = false_negative = exact = 0
    for result in results:
        expected = set(result.expected.get(key, []))
        actual = set(result.actual.get(key, []))
        true_positive += len(expected & actual)
        false_positive += len(actual - expected)
        false_negative += len(expected - actual)
        exact += expected == actual
    precision = _ratio(true_positive, true_positive + false_positive)
    recall = _ratio(true_positive, true_positive + false_negative)
    f1 = _ratio(2 * precision * recall, precision + recall)
    return ClassifierMetric(
        name=name,
        cases=len(results),
        correct=exact,
        true_positive=true_positive,
        false_positive=false_positive,
        false_negative=false_negative,
        accuracy=round(_ratio(exact, len(results)), 4),
        precision=round(precision, 4),
        recall=round(recall, 4),
        f1=round(f1, 4),
    )


def _ratio(numerator: float, denominator: float) -> float:
    if denominator == 0:
        return 1.0
    return numerator / denominator
