import json
from pathlib import Path

from grc_pdf_mapper.classifier_validation import evaluate_classifier_corpus


ROOT = Path(__file__).resolve().parents[1]
CORPUS = ROOT / "tests" / "fixtures" / "classifier_corpus.json"


def test_reviewed_classifier_corpus_passes_all_gates():
    report = evaluate_classifier_corpus(CORPUS, minimum_score=0.95)

    assert report.passed, report.failures
    assert report.case_count >= 30
    assert report.failed_case_count == 0
    assert all(metric.accuracy >= 0.95 for metric in report.metrics.values())
    assert all(metric.f1 >= 0.95 for metric in report.metrics.values())


def test_classifier_gate_fails_on_wrong_human_label(tmp_path: Path):
    payload = json.loads(CORPUS.read_text(encoding="utf-8"))
    payload["policy"][0]["kind"] = "permission"
    bad_corpus = tmp_path / "bad-corpus.json"
    bad_corpus.write_text(json.dumps(payload), encoding="utf-8")

    report = evaluate_classifier_corpus(bad_corpus, minimum_score=0.95)

    assert not report.passed
    assert report.failed_case_count == 1
    assert report.failures
