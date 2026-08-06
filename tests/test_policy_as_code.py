from pathlib import Path
import shutil
import subprocess
import sys

from grc_pdf_mapper.assessments import AssessmentRegistry
from grc_pdf_mapper.pac_models import PolicyCodeLink
from grc_pdf_mapper.sync import (
    analyze_doc_change_for_iac,
    analyze_iac_change,
    completeness_scan,
    evaluate_change_set,
    load_links,
)
from grc_pdf_mapper.terraform_scan import (
    diff_terraform_refs,
    parse_terraform_file,
    scan_terraform_tree,
)

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
    assert report.control_mappings
    assert any(mapping.scf_control_ids for mapping in report.control_mappings)


def test_tree_diff_distinguishes_same_address_in_separate_modules(tmp_path: Path):
    base = tmp_path / "base"
    head = tmp_path / "head"
    for root in (base, head):
        (root / "modules" / "alpha").mkdir(parents=True)
        (root / "modules" / "beta").mkdir(parents=True)
        for module in ("alpha", "beta"):
            (root / "modules" / module / "main.tf").write_text(
                'resource "aws_iam_role" "worker" { name = "worker" }\n',
                encoding="utf-8",
            )
    (head / "modules" / "beta" / "main.tf").write_text(
        'resource "aws_iam_role" "worker" { name = "changed-worker" }\n',
        encoding="utf-8",
    )

    delta = diff_terraform_refs(
        scan_terraform_tree(base),
        scan_terraform_tree(head),
    )

    assert len(delta["changed"]) == 1
    assert delta["changed"][0].module_path == "modules/beta"


def test_completeness_rejects_ambiguous_unqualified_address(tmp_path: Path):
    policy = tmp_path / "policy.md"
    policy.write_text(
        "Privileged accounts must use multi-factor authentication.\n",
        encoding="utf-8",
    )
    terraform = tmp_path / "terraform"
    for module in ("alpha", "beta"):
        directory = terraform / "modules" / module
        directory.mkdir(parents=True)
        (directory / "main.tf").write_text(
            'resource "aws_iam_role" "worker" { name = "worker" }\n',
            encoding="utf-8",
        )
    link = PolicyCodeLink(
        link_id="lnk-mfa",
        doc_id="pol-ac",
        statement_anchor="Privileged accounts must use multi-factor authentication.",
        terraform_addresses=["aws_iam_role.worker"],
    )

    report = completeness_scan(
        links=[link],
        policy_path=policy,
        terraform_root=terraform,
        doc_id="pol-ac",
    )

    assert any(gap.kind == "ambiguous_iac_selector" for gap in report.gaps)


def test_tree_diff_detects_change_after_display_snippet_limit(tmp_path: Path):
    base = tmp_path / "base"
    head = tmp_path / "head"
    base.mkdir()
    head.mkdir()
    padding = "x" * 650
    before = (
        'resource "aws_iam_role" "worker" {\n'
        f'  description = "{padding}"\n'
        '  name = "before"\n'
        '}\n'
    )
    after = before.replace('name = "before"', 'name = "after"')
    (base / "main.tf").write_text(before, encoding="utf-8")
    (head / "main.tf").write_text(after, encoding="utf-8")

    delta = diff_terraform_refs(
        scan_terraform_tree(base),
        scan_terraform_tree(head),
    )

    assert len(delta["changed"]) == 1
    assert delta["changed"][0].raw_snippet == before[before.index("{") :][:500]


def test_multi_file_tree_change_has_scf_and_assessment_context(tmp_path: Path):
    base = tmp_path / "base"
    head = tmp_path / "head"
    shutil.copytree(TF_ROOT, base)
    shutil.copytree(TF_ROOT, head)

    main = head / "access_control" / "main.tf"
    main.write_text(
        main.read_text(encoding="utf-8").replace(
            '"aws:MultiFactorAuthPresent" = "false"',
            '"aws:MultiFactorAuthPresent" = "true"',
        ),
        encoding="utf-8",
    )
    logging = head / "logging" / "extra.tf"
    logging.parent.mkdir(parents=True)
    logging.write_text(
        """# grc: link_id=lnk-auth-logging; doc_id=pol-ac-001; control_id=AU-2
resource "aws_cloudwatch_log_group" "auth_events" {
  name = "/security/auth-events"
}
""",
        encoding="utf-8",
    )

    alert = analyze_iac_change(
        links=load_links(LINKS),
        base_tf_files=[],
        head_tf_files=[],
        base_tf_roots=[base],
        head_tf_roots=[head],
        policy_path=POLICY,
        doc_id="pol-ac-001",
        assessments=AssessmentRegistry().active(),
    )

    assert len(alert.changed_paths) == 2
    assert alert.metadata == {"added": 1, "removed": 0, "changed": 1}
    assert {mapping.link_id for mapping in alert.control_mappings} == {
        "lnk-auth-logging",
        "lnk-mfa-privileged",
    }
    assert all(mapping.scf_control_ids for mapping in alert.control_mappings)
    assert len(alert.terraform_mappings) == 2
    assert all(mapping.reasons for mapping in alert.terraform_mappings)
    assert all(mapping.scf_control_ids for mapping in alert.terraform_mappings)
    assert alert.assessments_impacted


def test_combined_change_set_reconciles_policy_and_iac_change(tmp_path: Path):
    base_tf = tmp_path / "base-tf"
    head_tf = tmp_path / "head-tf"
    shutil.copytree(TF_ROOT, base_tf)
    shutil.copytree(TF_ROOT, head_tf)
    main = head_tf / "access_control" / "main.tf"
    main.write_text(
        main.read_text(encoding="utf-8").replace(
            '"aws:MultiFactorAuthPresent" = "false"',
            '"aws:MultiFactorAuthPresent" = "true"',
        ),
        encoding="utf-8",
    )
    base_policy = tmp_path / "base-policy.md"
    head_policy = tmp_path / "head-policy.md"
    base_policy.write_text(POLICY.read_text(encoding="utf-8"), encoding="utf-8")
    head_policy.write_text(
        POLICY.read_text(encoding="utf-8").replace(
            "Privileged accounts must use multi-factor authentication.",
            "Privileged accounts should use multi-factor authentication.",
        ),
        encoding="utf-8",
    )

    alert = evaluate_change_set(
        links=load_links(LINKS),
        doc_id="pol-ac-001",
        base_policy_path=base_policy,
        head_policy_path=head_policy,
        base_tf_root=base_tf,
        head_tf_root=head_tf,
        assessments=AssessmentRegistry().active(),
    )

    assert alert.trigger == "change_set"
    assert any(gap.kind == "coordinated_policy_iac_change" for gap in alert.gaps)
    assert alert.severity.value == "high", [
        (gap.kind, gap.severity.value) for gap in alert.gaps
    ]
    assert alert.control_mappings
    assert alert.assessments_impacted


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
