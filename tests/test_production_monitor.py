import json
import os
import re
import subprocess
from pathlib import Path

import pytest

from grc_pdf_mapper.production_monitor import (
    load_production_monitor_config,
    run_production_monitor,
)
from grc_pdf_mapper.terraform_scan import scan_terraform_tree


ROOT = Path(__file__).resolve().parents[1]
CORPUS = ROOT / "tests" / "fixtures" / "classifier_corpus.json"


@pytest.fixture(autouse=True)
def _approved_test_bootstrap(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("GRC_MONITOR_ALLOW_STATE_BOOTSTRAP", "true")


def test_cross_repo_monitor_detects_second_iac_repo_and_deduplicates_alerts(
    tmp_path: Path,
    monkeypatch,
):
    config, docs, primary, secondary = _production_fixture(tmp_path)
    state = tmp_path / "monitor-state.json"

    baseline = run_production_monitor(
        config,
        notify=False,
        state_path_override=state,
    )
    assert baseline.status.value == "aligned", baseline.model_dump()
    assert {item.repository for item in baseline.scanned_files} == {
        "iac-primary",
        "iac-secondary",
    }
    assert all(len(item.revision) == 40 for item in baseline.repositories)

    secondary_file = secondary / "security" / "main.tf"
    secondary_file.write_text(
        secondary_file.read_text(encoding="utf-8")
        + """
resource "aws_security_group" "unlinked_admin" {
  ingress { cidr_blocks = ["0.0.0.0/0"] }
}
""",
        encoding="utf-8",
    )
    _commit(secondary, "add unlinked production firewall")

    requests: list[tuple[str, dict]] = []

    class _Response:
        def raise_for_status(self) -> None:
            return None

    def _post(_client, url, *, json):
        requests.append((url, json))
        return _Response()

    monkeypatch.setenv("GRC_TEST_WEBHOOK", "https://alerts.invalid/grc")
    monkeypatch.setattr(
        "grc_pdf_mapper.production_monitor.httpx.Client.post",
        _post,
    )
    first = run_production_monitor(config, state_path_override=state)

    assert first.status.value == "misaligned"
    assert first.notification.sent_to == ["GRC_TEST_WEBHOOK"]
    assert any(
        gap.kind == "unlinked_security_sensitive_resource"
        and "iac-secondary" in (gap.iac_ref or "")
        for target in first.targets
        for gap in target.alert.gaps
    )

    second = run_production_monitor(config, state_path_override=state)
    assert second.status.value == "misaligned"
    assert second.notification.suppressed
    assert len(requests) == 1
    saved_state = json.loads(state.read_text(encoding="utf-8"))
    assert saved_state["occurrence_count"] == 2
    assert saved_state["finding_state"] == "active"


def test_repository_selector_separates_equal_terraform_addresses(tmp_path: Path):
    first = tmp_path / "first"
    second = tmp_path / "second"
    for root in (first, second):
        root.mkdir()
        (root / "main.tf").write_text(
            'resource "aws_iam_role" "worker" { name = "worker" }\n',
            encoding="utf-8",
        )

    resources = [
        *scan_terraform_tree(first, repository="repo-a"),
        *scan_terraform_tree(second, repository="repo-b"),
    ]

    assert len({resource.identity_key for resource in resources}) == 2
    assert {resource.repository_qualified_address for resource in resources} == {
        "repo-a::aws_iam_role.worker",
        "repo-b::aws_iam_role.worker",
    }


def test_known_disabled_security_setting_is_a_critical_violation(tmp_path: Path):
    config, _docs, primary, _secondary = _production_fixture(tmp_path)
    state = tmp_path / "monitor-state.json"
    run_production_monitor(config, notify=False, state_path_override=state)

    main = primary / "security" / "main.tf"
    main.write_text(
        """# grc: link_id=lnk-mfa; domain=access_control; control_id=IA-2
resource "aws_iam_policy" "require_mfa" {
  name       = "require-mfa"
  encrypted  = false
}
""",
        encoding="utf-8",
    )
    _commit(primary, "disable a security-relevant setting")

    report = run_production_monitor(config, notify=False, state_path_override=state)

    assert report.severity.value == "critical"
    assert any(
        gap.kind == "terraform_control_violation"
        for target in report.targets
        for gap in target.alert.gaps
    )


def test_production_policy_softening_alerts_when_iac_does_not_change(tmp_path: Path):
    config, docs, _primary, _secondary = _production_fixture(tmp_path)
    state = tmp_path / "monitor-state.json"
    run_production_monitor(config, notify=False, state_path_override=state)

    policy = docs / "policies" / "access.md"
    policy.write_text(
        "# Access Control\n\n"
        "Privileged accounts should use multi-factor authentication.\n",
        encoding="utf-8",
    )
    _commit(docs, "soften the production policy")

    report = run_production_monitor(config, notify=False, state_path_override=state)

    assert report.status.value == "misaligned"
    assert report.severity.value == "critical"
    assert any(
        change.change_kind == "obligation_softened"
        for target in report.targets
        for change in target.alert.verbiage_changes
    )


@pytest.mark.parametrize(
    ("relative_path", "content"),
    [
        ("security/variables.tf", 'variable "admin_cidr" { default = "0.0.0.0/0" }\n'),
        (
            "security/module.tf",
            'module "security" { source = "example/security/aws" version = "2.0.0" }\n',
        ),
        ("security/production.tfvars", 'admin_cidr = "0.0.0.0/0"\n'),
    ],
)
def test_non_resource_iac_change_fails_closed(
    tmp_path: Path,
    relative_path: str,
    content: str,
):
    config, _docs, _primary, secondary = _production_fixture(tmp_path)
    state = tmp_path / "monitor-state.json"
    run_production_monitor(config, notify=False, state_path_override=state)

    changed_file = secondary / relative_path
    changed_file.write_text(content, encoding="utf-8")
    _commit(secondary, "change an IaC input outside a resource block")

    report = run_production_monitor(config, notify=False, state_path_override=state)

    assert report.status.value == "misaligned"
    assert any(
        gap.kind == "unclassified_iac_file_change"
        for target in report.targets
        for gap in target.alert.gaps
    )


def test_production_config_rejects_unknown_fields_and_moving_revision(tmp_path: Path):
    config, _docs, _primary, _secondary = _production_fixture(tmp_path)
    payload = json.loads(config.read_text(encoding="utf-8"))
    payload["unexpected"] = True
    config.write_text(json.dumps(payload), encoding="utf-8")
    with pytest.raises(ValueError, match="unexpected"):
        load_production_monitor_config(config)

    payload.pop("unexpected")
    payload["repositories"][0]["expected_revision"] = "main"
    config.write_text(json.dumps(payload), encoding="utf-8")
    with pytest.raises(ValueError, match="full commit SHA"):
        run_production_monitor(config, notify=False)


def test_production_workflow_pins_actions_and_keeps_analysis_read_only():
    workflow = (
        ROOT / "examples" / "github" / "production-cross-repo-lockstep.yml"
    ).read_text(encoding="utf-8")
    action_refs = re.findall(r"uses:\s+[^\s@]+@([^\s#]+)", workflow)

    assert action_refs
    assert all(re.fullmatch(r"[0-9a-f]{40}", ref) for ref in action_refs)
    assert "pull-requests: write" not in workflow
    assert workflow.count("persist-credentials: false") >= 4
    assert "if-no-files-found: error" in workflow
    assert "40-character commit IDs" in workflow
    assert "requirements-production.lock" in workflow


def _production_fixture(tmp_path: Path) -> tuple[Path, Path, Path, Path]:
    docs = tmp_path / "prod-docs"
    primary = tmp_path / "prod-iac-primary"
    secondary = tmp_path / "prod-iac-secondary"
    _init_repo(
        docs,
        {
            "policies/access.md": (
                "# Access Control\n\n"
                "Privileged accounts must use multi-factor authentication.\n"
            )
        },
    )
    _init_repo(
        primary,
        {
            "security/main.tf": """# grc: link_id=lnk-mfa; domain=access_control; control_id=IA-2
resource "aws_iam_policy" "require_mfa" {
  name = "require-mfa"
}
"""
        },
    )
    _init_repo(
        secondary,
        {
            "security/main.tf": (
                'resource "random_pet" "deployment_name" { length = 2 }\n'
            )
        },
    )

    links = tmp_path / "production-links.json"
    links.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "links": [
                    {
                        "link_id": "lnk-mfa",
                        "doc_id": "pol-ac-prod",
                        "statement_anchor": (
                            "Privileged accounts must use multi-factor authentication."
                        ),
                        "statement_keywords": [
                            "privileged",
                            "multi-factor",
                            "authentication",
                        ],
                        "expected_domains": ["access_control"],
                        "expected_statement_kind": "obligation",
                        "expected_strength": "must",
                        "expected_action_polarity": "positive",
                        "control_ids": ["IA-2"],
                        "iac_repositories": ["iac-primary"],
                        "iac_paths": ["security/main.tf"],
                        "terraform_resource_types": ["aws_iam_policy"],
                    }
                ]
            },
            indent=2,
        ),
        encoding="utf-8",
    )
    config = tmp_path / "production-monitor.json"
    config.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "monitor_id": "test-production",
                "repositories": [
                    {
                        "name": "production-docs",
                        "kind": "documentation",
                        "root": str(docs),
                    },
                    {
                        "name": "iac-primary",
                        "kind": "iac",
                        "root": str(primary),
                    },
                    {
                        "name": "iac-secondary",
                        "kind": "iac",
                        "root": str(secondary),
                    },
                ],
                "links_path": str(links),
                "state_path": str(tmp_path / "default-state.json"),
                "require_existing_state": True,
                "targets": [
                    {
                        "target_id": "production-access",
                        "doc_id": "pol-ac-prod",
                        "policy_repository": "production-docs",
                        "policy_path": "policies/access.md",
                        "terraform_roots": [
                            {"repository": "iac-primary", "path": "security"},
                            {"repository": "iac-secondary", "path": "security"},
                        ],
                    }
                ],
                "classifier_gate": {
                    "corpus_path": str(CORPUS),
                    "minimum_score": 0.95,
                    "review_below": 0.85,
                    "require_expected_domains": True,
                    "require_exact_domains": True,
                },
                "notifications": {
                    "webhook_envs": ["GRC_TEST_WEBHOOK"],
                    "minimum_severity": "high",
                    "notify_on_recovery": True,
                    "require_destination": True,
                    "event_log_path": str(tmp_path / "events.jsonl"),
                },
            },
            indent=2,
        ),
        encoding="utf-8",
    )
    return config, docs, primary, secondary


def _init_repo(root: Path, files: dict[str, str]) -> None:
    root.mkdir()
    subprocess.run(["git", "init", "-q", str(root)], check=True)
    subprocess.run(
        ["git", "-C", str(root), "config", "user.email", "grc-test@example.com"],
        check=True,
    )
    subprocess.run(
        ["git", "-C", str(root), "config", "user.name", "GRC Test"],
        check=True,
    )
    for relative, content in files.items():
        path = root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
    _commit(root, "baseline")


def _commit(root: Path, message: str) -> None:
    subprocess.run(["git", "-C", str(root), "add", "."], check=True)
    environment = os.environ.copy()
    environment.update(
        {
            "GIT_AUTHOR_DATE": "2026-08-05T12:00:00Z",
            "GIT_COMMITTER_DATE": "2026-08-05T12:00:00Z",
        }
    )
    subprocess.run(
        ["git", "-C", str(root), "commit", "-q", "-m", message],
        check=True,
        env=environment,
    )
