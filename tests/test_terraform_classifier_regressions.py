from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

from grc_pdf_mapper.models import ControlStatement
from grc_pdf_mapper.scf import ScfClient, guess_scf_framework_id
from grc_pdf_mapper.terraform_classify import classify_terraform_resource
from grc_pdf_mapper.terraform_scan import (
    parse_terraform_text,
    scan_terraform_revision,
    scan_terraform_tree,
)


def test_scanner_ignores_security_terms_and_metadata_in_dead_text() -> None:
    resources = parse_terraform_text(
        '''resource "null_resource" "comment_only" {
  # encrypted = false
  # tags = { link_id = "ghost-tag" }
  triggers = { value = "safe" }
}

resource "null_resource" "script" {
  provisioner "local-exec" {
    command = <<EOF
# grc: link_id=ghost; domains=access_control; control_ids=AC-2
encrypted = false
EOF
  }
}
''',
        file_path="main.tf",
        relative_path="main.tf",
        module_path=".",
    )

    assert len(resources) == 2
    for resource in resources:
        assert resource.tags == {}
        assert resource.grc_annotations == {}
        assert not resource.classification.security_sensitive
        assert resource.classification.posture == "unknown"


def test_direct_classifier_ignores_security_terms_in_dead_text() -> None:
    classification = classify_terraform_resource(
        "null_resource",
        '''{
  # encrypted = false
  provisioner "local-exec" {
    command = <<EOF
encrypted = false
0.0.0.0/0
EOF
  }
}''',
    )

    assert not classification.security_sensitive
    assert classification.candidate_control_ids == []
    assert classification.status == "not_security_relevant"
    assert classification.posture == "unknown"


def test_invalid_explicit_control_id_requires_review() -> None:
    classification = classify_terraform_resource(
        "null_resource",
        "{ triggers = {} }",
        annotations={"control_id": "NOT-A-CONTROL"},
    )

    assert classification.security_sensitive
    assert classification.candidate_control_ids == []
    assert classification.status == "review_required"
    assert classification.posture == "review_required"
    assert classification.confidence < 0.85
    assert any("unrecognized" in reason for reason in classification.reasons)


@pytest.mark.parametrize(
    "control_id",
    [
        "IA-2",
        "IAC-01",
        "KSI-IAM-APM",
        "CC6.1",
        "5.15",
        "PR.AA-01",
        "CIS 5.1",
        "Req.1.2.2",
    ],
)
def test_supported_explicit_control_id_formats_remain_valid(control_id: str) -> None:
    classification = classify_terraform_resource(
        "null_resource",
        "{ triggers = {} }",
        annotations={"control_id": control_id},
    )

    assert classification.candidate_control_ids == [control_id.upper()]
    assert classification.posture == "implemented"
    assert not any("unrecognized" in reason for reason in classification.reasons)


@pytest.mark.parametrize(
    ("resource_type", "domain"),
    [
        ("google_service_account", "access_control"),
        ("azurerm_network_security_rule", "network_security"),
        ("azurerm_storage_container", "data_protection"),
    ],
)
def test_provider_security_resources_are_not_silent(
    resource_type: str,
    domain: str,
) -> None:
    classification = classify_terraform_resource(
        resource_type,
        '{ name = "security" }',
    )

    assert classification.security_sensitive
    assert domain in classification.domains
    assert classification.candidate_control_ids


def test_unknown_explicit_scf_citation_does_not_use_domain_fallback() -> None:
    statement = ControlStatement(
        statement_id="unknown-scf",
        text="Access controls must implement IAC-999.",
        keywords=["access_control"],
        candidate_framework_ids=["IAC-999"],
        classification_confidence=0.9,
        content_hash="unknown-scf",
    )

    with ScfClient(offline=True) as client:
        hits = client.map_statement(statement)

    assert hits == []


def test_scf_keeps_each_backbone_before_limiting_crosswalk_expansion() -> None:
    candidates = ["AC-2", "AC-3", "IA-2"]
    statement = ControlStatement(
        statement_id="access-controls",
        text="Access controls must enforce account and identity requirements.",
        candidate_framework_ids=candidates,
        classification_confidence=0.9,
        content_hash="access-controls",
    )

    with ScfClient(offline=True) as client:
        expected: list[str] = []
        for control_id in candidates:
            framework_id = guess_scf_framework_id(control_id)
            assert framework_id is not None
            for scf_id in client.framework_to_scf(framework_id, control_id):
                if scf_id not in expected:
                    expected.append(scf_id)
        hits = client.map_statement(statement)

    actual = [hit.control_id for hit in hits if hit.framework == "SCF"]
    assert actual == expected
    assert "IAC-02" in actual


def test_local_and_revision_scans_exclude_only_nested_cache_paths(
    tmp_path: Path,
) -> None:
    repository = tmp_path / "vendor" / "production-iac"
    repository.mkdir(parents=True)
    subprocess.run(["git", "init", "-q", str(repository)], check=True)

    (repository / "main.tf").write_text(
        'resource "random_pet" "live" {}\n',
        encoding="utf-8",
    )
    cached = repository / ".terraform" / "modules" / "cached" / "main.tf"
    cached.parent.mkdir(parents=True)
    cached.write_text(
        'resource "aws_iam_role" "generated" {}\n',
        encoding="utf-8",
    )
    subprocess.run(
        ["git", "-C", str(repository), "add", "-f", "main.tf", str(cached)],
        check=True,
    )
    subprocess.run(
        [
            "git",
            "-C",
            str(repository),
            "-c",
            "user.name=GRC Test",
            "-c",
            "user.email=grc-test@example.com",
            "commit",
            "-q",
            "-m",
            "baseline",
        ],
        check=True,
    )
    revision = subprocess.run(
        ["git", "-C", str(repository), "rev-parse", "HEAD"],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()

    local = scan_terraform_tree(repository, repository="production-iac")
    historical = scan_terraform_revision(
        repository,
        revision,
        ["."],
        repository="production-iac",
    )

    assert [resource.relative_path for resource in local] == ["main.tf"]
    assert [resource.relative_path for resource in historical] == ["main.tf"]


def test_local_scan_rejects_terraform_symlink(tmp_path: Path) -> None:
    external = tmp_path / "external.tf"
    external.write_text('resource "aws_iam_role" "external" {}\n', encoding="utf-8")
    root = tmp_path / "iac"
    root.mkdir()
    (root / "linked.tf").symlink_to(external)

    with pytest.raises(ValueError, match="must not be a symlink"):
        scan_terraform_tree(root)


def test_local_scan_does_not_follow_symlink_directory(tmp_path: Path) -> None:
    external = tmp_path / "external-module"
    external.mkdir()
    (external / "main.tf").write_text(
        'resource "aws_iam_role" "external" {}\n',
        encoding="utf-8",
    )
    root = tmp_path / "iac"
    root.mkdir()
    (root / "linked-module").symlink_to(external, target_is_directory=True)

    with pytest.raises(ValueError, match="directory must not be a symlink"):
        scan_terraform_tree(root)


def test_tracked_vendor_directory_is_not_silently_excluded(tmp_path: Path) -> None:
    root = tmp_path / "iac"
    vendor = root / "vendor" / "security"
    vendor.mkdir(parents=True)
    (vendor / "main.tf").write_text(
        'resource "aws_iam_role" "vendored" {}\n',
        encoding="utf-8",
    )

    resources = scan_terraform_tree(root)

    assert [resource.relative_path for resource in resources] == [
        "vendor/security/main.tf"
    ]
