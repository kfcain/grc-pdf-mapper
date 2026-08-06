from pathlib import Path

from grc_pdf_mapper.extract import extract_control_statements
from grc_pdf_mapper.impact import detect_verbiage_changes
from grc_pdf_mapper.models import ControlStatement, ObligationStrength, StatementKind
from grc_pdf_mapper.pac_mapping import map_terraform_resources_via_scf
from grc_pdf_mapper.pac_models import (
    PolicyCodeLink,
    TerraformClassification,
    TerraformResourceRef,
)
from grc_pdf_mapper.sync import classifier_alignment_gaps
from grc_pdf_mapper.terraform_scan import (
    parse_terraform_file,
    parse_terraform_text,
    scan_terraform_tree,
)


def test_policy_classifier_handles_wrapped_lists_and_tables():
    markdown = """# Access and Logging

- All privileged accounts
  shall use multi-factor authentication.

| Requirement | Owner |
|---|---|
| Authentication logs are required to be retained within 30 days. | Security Operations |
"""

    statements = extract_control_statements(markdown, doc_slug="pol-test")

    mfa = next(statement for statement in statements if "multi-factor" in statement.text)
    logging = next(statement for statement in statements if "logs" in statement.text)
    assert mfa.strength == ObligationStrength.SHALL
    assert mfa.statement_kind == StatementKind.OBLIGATION
    assert "access_control" in mfa.keywords
    assert mfa.classification_confidence >= 0.9
    assert mfa.classification_reasons
    assert logging.strength == ObligationStrength.MUST
    assert "logging" in logging.keywords


def test_policy_classifier_rejects_non_normative_may_but_keeps_permission():
    markdown = """System outages may result in delayed access.

Administrators may request temporary access through the approved workflow.
"""

    statements = extract_control_statements(markdown, doc_slug="pol-test")

    assert len(statements) == 1
    assert statements[0].statement_kind == StatementKind.PERMISSION
    assert statements[0].strength == ObligationStrength.MAY


def test_policy_classifier_distinguishes_waiver_and_uncertain_may_not():
    markdown = """Administrators do not have to use multi-factor authentication.

The service may not be available during maintenance.

Users may not share credentials.
"""

    statements = extract_control_statements(markdown, doc_slug="pol-test")

    assert len(statements) == 2
    waiver = next(statement for statement in statements if "do not have to" in statement.text)
    prohibition = next(statement for statement in statements if "may not share" in statement.text)
    assert waiver.statement_kind == StatementKind.PERMISSION
    assert waiver.strength == ObligationStrength.MAY
    assert prohibition.statement_kind == StatementKind.PROHIBITION
    assert prohibition.strength == ObligationStrength.PROHIBITED


def test_terraform_annotation_parser_preserves_multi_value_labels():
    refs = parse_terraform_text(
        """# grc: control_ids=AC-2, IA-2; domains=access_control, logging; roles=preventive, detective
resource "custom_guard" "example" {
  enabled = true
}
""",
        file_path="guard.tf",
        relative_path="guard.tf",
        module_path=".",
    )

    assert refs[0].grc_annotations == {
        "control_ids": "AC-2, IA-2",
        "domains": "access_control, logging",
        "roles": "preventive, detective",
    }
    assert refs[0].classification.candidate_control_ids == ["AC-2", "IA-2"]
    assert refs[0].classification.domains == ["access_control", "logging"]


def test_terraform_scanner_ignores_dead_resource_text_and_quoted_braces():
    refs = parse_terraform_text(
        '''# resource "aws_security_group" "commented" {}
/* resource "aws_kms_key" "blocked" {} */
locals {
  example = <<-EOT
resource "aws_cloudtrail" "heredoc" {}
EOT
}
resource "aws_iam_role" "live" {
  description = "a quoted closing brace } does not end this block"
  name        = "live"
}
''',
        file_path="main.tf",
        relative_path="main.tf",
        module_path=".",
    )

    assert [resource.address for resource in refs] == ["aws_iam_role.live"]
    assert 'name        = "live"' in refs[0].raw_snippet


def test_terraform_annotations_do_not_leak_to_the_next_resource():
    refs = parse_terraform_text(
        '''# grc: link_id=first-link; control_ids=AC-2, IA-2
resource "custom_guard" "first" { enabled = true }
resource "random_pet" "second" { length = 2 }
''',
        file_path="main.tf",
        relative_path="main.tf",
        module_path=".",
    )

    assert refs[0].grc_annotations["link_id"] == "first-link"
    assert refs[1].grc_annotations == {}


def test_terraform_parser_normalizes_annotation_and_quoted_tag_keys():
    refs = parse_terraform_text(
        '''# GRC: Control_IDs=AC-2, IA-2; Domains=access_control, logging
resource "custom_guard" "mixed_case" {
  tags = merge(local.common_tags, {
    "grc_roles"  = "preventive, detective"
    "link_id"    = "lnk-mixed"
    "control_ids" = "AC-2, IA-2"
  })
}
''',
        file_path="main.tf",
        relative_path="main.tf",
        module_path=".",
    )

    assert refs[0].grc_annotations["control_ids"] == "AC-2, IA-2"
    assert refs[0].classification.candidate_control_ids == ["AC-2", "IA-2"]
    assert refs[0].classification.domains == ["access_control", "logging"]
    assert refs[0].tags["link_id"] == "lnk-mixed"


def test_terraform_tree_excludes_generated_cache_directories(tmp_path: Path):
    generated = [
        tmp_path / ".terraform" / "modules" / "cached",
        tmp_path / ".terragrunt-cache" / "cached",
    ]
    for directory in generated:
        directory.mkdir(parents=True)
        (directory / "main.tf").write_text(
            'resource "aws_iam_role" "generated" {}\n', encoding="utf-8"
        )

    assert scan_terraform_tree(tmp_path) == []


def test_exact_classifier_alignment_rejects_unexpected_domains():
    link = PolicyCodeLink(
        link_id="lnk-mfa",
        doc_id="pol-ac",
        statement_anchor="Privileged accounts must use multi-factor authentication.",
        expected_domains=["access_control"],
        iac_repositories=["prod-iac"],
        terraform_addresses=["aws_iam_policy.require_mfa"],
    )
    statement = ControlStatement(
        statement_id="statement",
        text=link.statement_anchor,
        strength=ObligationStrength.MUST,
        keywords=["access_control", "logging"],
        content_hash="statement",
        classification_confidence=0.96,
    )
    resource = TerraformResourceRef(
        address="aws_iam_policy.require_mfa",
        resource_type="aws_iam_policy",
        name="require_mfa",
        file_path="main.tf",
        relative_path="main.tf",
        repository="prod-iac",
        classification=TerraformClassification(
            domains=["access_control"],
            security_sensitive=True,
            confidence=0.9,
            status="classified",
            posture="implemented",
        ),
    )

    gaps = classifier_alignment_gaps(
        links=[link],
        statements=[statement],
        resources=[resource],
        doc_id="pol-ac",
        require_exact_domains=True,
    )

    assert [gap.kind for gap in gaps] == ["policy_classifier_unexpected_domain"]


def test_change_classifier_detects_scope_exception_and_reversal():
    old_scope = _statement(
        "old-scope",
        "All privileged accounts must use multi-factor authentication.",
        ObligationStrength.MUST,
    )
    new_scope = _statement(
        "new-scope",
        "Selected privileged accounts must use multi-factor authentication.",
        ObligationStrength.MUST,
    )
    scope_change = detect_verbiage_changes([old_scope], [new_scope])[0]
    assert scope_change.change_kind == "scope_reduced"
    assert scope_change.classification_reasons

    old_exception = _statement(
        "old-exception",
        "Privileged accounts must use multi-factor authentication.",
        ObligationStrength.MUST,
    )
    new_exception = _statement(
        "new-exception",
        "Privileged accounts must use multi-factor authentication where feasible.",
        ObligationStrength.MUST,
    )
    exception_change = detect_verbiage_changes([old_exception], [new_exception])[0]
    assert exception_change.change_kind == "obligation_softened"
    assert "exception" in " ".join(exception_change.classification_reasons)

    old_reversal = _statement(
        "old-reversal",
        "Administrators must not export production credentials.",
        ObligationStrength.PROHIBITED,
    )
    new_reversal = _statement(
        "new-reversal",
        "Administrators must export production credentials.",
        ObligationStrength.MUST,
    )
    reversal = detect_verbiage_changes([old_reversal], [new_reversal])[0]
    assert reversal.change_kind == "obligation_reversed"


def test_terraform_classifier_is_explainable_and_scf_enriched(tmp_path: Path):
    path = tmp_path / "network.tf"
    path.write_text(
        """# grc: domain=network_security; control_id=SC-7
resource "aws_security_group" "public_admin" {
  ingress {
    cidr_blocks = ["0.0.0.0/0"]
  }
}
""",
        encoding="utf-8",
    )

    resource = parse_terraform_file(path)[0]
    classification = resource.classification
    assert classification.security_sensitive
    assert "network_security" in classification.domains
    assert "SC-7" in classification.candidate_control_ids
    assert "preventive" in classification.enforcement_roles
    assert classification.confidence >= 0.9
    assert any("unrestricted" in reason for reason in classification.reasons)

    mappings = map_terraform_resources_via_scf([resource], offline=True)
    assert len(mappings) == 1
    assert mappings[0].scf_control_ids
    assert mappings[0].framework_controls.get("NIST 800-53")


def _statement(
    content_hash: str,
    text: str,
    strength: ObligationStrength,
) -> ControlStatement:
    return ControlStatement(
        statement_id=content_hash,
        text=text,
        strength=strength,
        keywords=["access_control"],
        content_hash=content_hash,
        classification_confidence=0.95,
    )
