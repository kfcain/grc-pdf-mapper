from pathlib import Path
import subprocess
import sys

from grc_pdf_mapper.sync import (
    analyze_doc_change_for_iac,
    analyze_iac_change,
    completeness_scan,
    load_links,
)
from grc_pdf_mapper.terraform_scan import parse_terraform_file, scan_terraform_tree

ROOT = Path(__file__).resolve().parents[1]
LINKS = ROOT / "lab" / "policy-as-code-links.json"
POLICY = ROOT / "lab" / "policies" / "access-control.md"
TF = ROOT / "lab" / "iac" / "access_control" / "main.tf"
TF_ROOT = ROOT / "lab" / "iac"


def test_terraform_annotations_parsed():
    refs = parse_terraform_file(TF)
    addresses = {r.address for r in refs}
    assert "aws_iam_policy.require_mfa" in addresses
    mfa = next(r for r in refs if r.address == "aws_iam_policy.require_mfa")
    assert mfa.grc_annotations.get("link_id") == "lnk-mfa-privileged"
    assert mfa.tags.get("doc_id") == "pol-ac-001"


def test_completeness_scan_passes_on_lab_baseline():
    report = completeness_scan(
        links=load_links(LINKS),
        policy_path=POLICY,
        terraform_root=TF_ROOT,
        doc_id="pol-ac-001",
    )
    assert report.complete, [g.detail for g in report.gaps]
    assert len(report.covered_links) >= 4


def test_iac_change_prompts_documentation_update(tmp_path: Path):
    base = tmp_path / "base.tf"
    head = tmp_path / "head.tf"
    original = TF.read_text(encoding="utf-8")
    base.write_text(original, encoding="utf-8")
    # Weaken MFA implementation and drop annotation integrity.
    weakened = original.replace(
        '"aws:MultiFactorAuthPresent" = "false"',
        '"aws:MultiFactorAuthPresent" = "true"',
    )
    head.write_text(weakened, encoding="utf-8")

    alert = analyze_iac_change(
        links=load_links(LINKS),
        base_tf_files=[base],
        head_tf_files=[head],
        policy_path=POLICY,
        doc_id="pol-ac-001",
    )
    assert alert.trigger == "iac_changed"
    assert alert.gaps
    assert any("require_mfa" in (g.iac_ref or "") or "documentation" in g.detail.lower() for g in alert.gaps)
    assert alert.severity.value in {"high", "critical"}


def test_doc_change_requires_iac_verification():
    older = POLICY.read_text(encoding="utf-8")
    newer = older.replace(
        "Privileged accounts must use multi-factor authentication.",
        "Privileged accounts should use multi-factor authentication when convenient.",
    )
    alert = analyze_doc_change_for_iac(
        links=load_links(LINKS),
        doc_id="pol-ac-001",
        older_markdown=older,
        newer_markdown=newer,
        terraform_root=TF_ROOT,
    )
    assert alert.trigger == "doc_changed"
    assert any(
        g.kind in {
            "policy_obligation_changed_verify_iac",
            "policy_obligation_removed_iac_still_present",
        }
        for g in alert.gaps
    )
    assert "aws_iam_policy.require_mfa" in alert.linked_iac


def test_ci_pac_sync_completeness(tmp_path: Path):
    comment = tmp_path / "c.md"
    alert = tmp_path / "a.json"
    proc = subprocess.run(
        [
            sys.executable,
            str(ROOT / "scripts" / "ci_pac_sync.py"),
            "--mode",
            "completeness",
            "--links",
            str(LINKS),
            "--policy",
            str(POLICY),
            "--terraform-root",
            str(TF_ROOT),
            "--doc-id",
            "pol-ac-001",
            "--fail-on",
            "critical",
            "--comment-out",
            str(comment),
            "--json-out",
            str(alert),
            "--store",
            str(tmp_path / "store"),
        ],
        cwd=str(ROOT),
        capture_output=True,
        text=True,
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "lock-step" in comment.read_text(encoding="utf-8").lower() or "OK" in proc.stdout
