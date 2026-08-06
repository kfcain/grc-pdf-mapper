import json
import os
import subprocess
from pathlib import Path

import pytest

from grc_pdf_mapper.production_monitor import (
    load_production_monitor_config,
    run_production_monitor,
)


ROOT = Path(__file__).resolve().parents[1]
CORPUS = ROOT / "tests" / "fixtures" / "classifier_corpus.json"


@pytest.fixture(autouse=True)
def _approved_test_bootstrap(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("GRC_MONITOR_ALLOW_STATE_BOOTSTRAP", "true")


def test_missing_required_state_cannot_become_a_new_baseline(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
):
    config, docs, _iac = _production_fixture(
        tmp_path,
        require_existing_state=True,
    )
    state = tmp_path / "monitor-state.json"

    monkeypatch.setenv("GRC_MONITOR_ALLOW_STATE_BOOTSTRAP", "true")
    baseline = run_production_monitor(
        config,
        notify=False,
        state_path_override=state,
    )
    monkeypatch.delenv("GRC_MONITOR_ALLOW_STATE_BOOTSTRAP")
    assert baseline.status.value == "aligned"

    policy = docs / "policies" / "access.md"
    policy.write_text(
        "# Access Control\n\n"
        "Privileged accounts should use multi-factor authentication.\n",
        encoding="utf-8",
    )
    _commit(docs, "soften policy")
    state.unlink()

    with pytest.raises(ValueError, match="state is missing"):
        run_production_monitor(
            config,
            notify=False,
            state_path_override=state,
        )


@pytest.mark.parametrize(
    "payload",
    [
        {},
        {"schema_version": 1},
        {
            "schema_version": 1,
            "monitor_id": "production-regression-test",
            "bootstrap_complete": True,
            "last_accepted_revisions": {},
            "last_status": "aligned",
        },
        {
            "schema_version": 1,
            "monitor_id": "production-regression-test",
            "bootstrap_complete": True,
            "last_accepted_revisions": {"production-docs": "not-a-commit"},
            "last_status": "aligned",
        },
    ],
)
def test_incomplete_required_state_fails_closed(
    tmp_path: Path,
    payload: dict,
):
    config, _docs, _iac = _production_fixture(
        tmp_path,
        require_existing_state=True,
    )
    state = tmp_path / "monitor-state.json"
    state.write_text(json.dumps(payload), encoding="utf-8")

    with pytest.raises(ValueError, match="production monitor state"):
        run_production_monitor(
            config,
            notify=False,
            state_path_override=state,
        )


def test_production_config_cannot_disable_required_state(tmp_path: Path):
    config, _docs, _iac = _production_fixture(tmp_path)
    payload = json.loads(config.read_text(encoding="utf-8"))
    payload["require_existing_state"] = False
    config.write_text(json.dumps(payload), encoding="utf-8")

    with pytest.raises(ValueError, match="require_existing_state"):
        load_production_monitor_config(config)


def test_mixed_resource_and_non_resource_change_fails_closed(tmp_path: Path):
    config, _docs, iac = _production_fixture(tmp_path)
    state = tmp_path / "monitor-state.json"
    baseline = run_production_monitor(
        config,
        notify=False,
        state_path_override=state,
    )
    assert baseline.status.value == "aligned", baseline.model_dump()

    main = iac / "security" / "main.tf"
    main.write_text(
        _terraform_text(variable_default="permissive", random_length=3),
        encoding="utf-8",
    )
    _commit(iac, "change a variable and a resource in one file")

    report = run_production_monitor(
        config,
        notify=False,
        state_path_override=state,
    )

    assert report.status.value == "misaligned"
    assert any(
        gap.kind == "unclassified_iac_file_change"
        and "outside its parsed resource blocks" in gap.detail
        for target in report.targets
        for gap in target.alert.gaps
    )


def test_removed_policy_duty_cannot_bootstrap_as_aligned(tmp_path: Path):
    config, docs, _iac = _production_fixture(tmp_path)
    policy = docs / "policies" / "access.md"
    policy.write_text(
        "# Access Control\n\n"
        "The requirement that privileged accounts must use multi-factor "
        "authentication is no longer required.\n",
        encoding="utf-8",
    )
    _commit(docs, "remove the production duty")

    report = run_production_monitor(
        config,
        notify=False,
        state_path_override=tmp_path / "monitor-state.json",
    )

    assert report.status.value == "misaligned"
    assert report.severity.value == "critical"
    assert any(
        gap.kind == "policy_statement_semantic_mismatch"
        for target in report.targets
        for gap in target.alert.gaps
    )


def test_tracked_iac_symlink_is_rejected_without_reading_external_bytes(
    tmp_path: Path,
):
    config, _docs, iac = _production_fixture(tmp_path)
    state = tmp_path / "monitor-state.json"
    baseline = run_production_monitor(
        config,
        notify=False,
        state_path_override=state,
    )
    assert baseline.status.value == "aligned"

    external = tmp_path / "external-production.tfvars"
    external.write_text("mfa_enabled = true\n", encoding="utf-8")
    linked = iac / "security" / "production.tfvars"
    linked.symlink_to(external)
    _commit(iac, "add tracked IaC symlink")

    first = run_production_monitor(
        config,
        notify=False,
        state_path_override=state,
    )
    external.write_text("mfa_enabled = false\n", encoding="utf-8")
    second = run_production_monitor(
        config,
        notify=False,
        state_path_override=state,
    )

    assert first.status.value == "misaligned"
    assert first.severity.value == "critical"
    assert any(
        gap.kind == "unpinned_source_input" and "symbolic links" in gap.detail
        for target in first.targets
        for gap in target.alert.gaps
    )
    assert first.input_fingerprint == second.input_fingerprint
    assert all(item.path != "security/production.tfvars" for item in first.scanned_files)


def test_ignored_untracked_iac_input_is_rejected(tmp_path: Path):
    config, _docs, iac = _production_fixture(tmp_path)
    state = tmp_path / "monitor-state.json"
    run_production_monitor(config, notify=False, state_path_override=state)

    (iac / ".gitignore").write_text("*.tfvars\n", encoding="utf-8")
    _commit(iac, "ignore local variable files")
    ignored = iac / "security" / "production.tfvars"
    ignored.write_text('admin_cidr = "0.0.0.0/0"\n', encoding="utf-8")

    report = run_production_monitor(
        config,
        notify=False,
        state_path_override=state,
    )

    assert report.status.value == "misaligned"
    assert any(
        gap.kind == "unpinned_source_input" and "not tracked" in gap.detail
        for target in report.targets
        for gap in target.alert.gaps
    )


def test_same_finding_at_new_source_revision_sends_a_new_notification(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
):
    config, _docs, iac = _production_fixture(tmp_path)
    state = tmp_path / "monitor-state.json"
    run_production_monitor(config, notify=False, state_path_override=state)

    requests: list[dict] = []

    class _Response:
        def raise_for_status(self) -> None:
            return None

    def _post(_client, _url, *, json):
        requests.append(json)
        return _Response()

    monkeypatch.setenv("GRC_TEST_WEBHOOK", "https://alerts.invalid/grc")
    monkeypatch.setattr(
        "grc_pdf_mapper.production_monitor.httpx.Client.post",
        _post,
    )
    main = iac / "security" / "main.tf"
    main.write_text(
        main.read_text(encoding="utf-8")
        + _unlinked_security_group("0.0.0.0/0"),
        encoding="utf-8",
    )
    _commit(iac, "add an unlinked security group")
    first = run_production_monitor(config, state_path_override=state)

    main.write_text(
        main.read_text(encoding="utf-8").replace(
            'cidr_blocks = ["0.0.0.0/0"]',
            'cidr_blocks = ["10.0.0.0/8"]',
        ),
        encoding="utf-8",
    )
    _commit(iac, "change the same unlinked security group")
    second = run_production_monitor(config, state_path_override=state)
    repeated = run_production_monitor(config, state_path_override=state)

    assert first.finding_fingerprint == second.finding_fingerprint
    assert first.input_fingerprint != second.input_fingerprint
    assert first.notification.sent_to == ["GRC_TEST_WEBHOOK"]
    assert second.notification.sent_to == ["GRC_TEST_WEBHOOK"]
    assert repeated.notification.suppressed
    assert len(requests) == 2


def test_workflow_discovers_only_enrolled_sources_and_fails_closed_on_state_loss():
    workflow = (
        ROOT / "examples" / "github" / "production-cross-repo-lockstep.yml"
    ).read_text(encoding="utf-8")

    assert "source_alias" in workflow
    assert "source_sha" in workflow
    assert "client_payload.repository" not in workflow
    assert "client_payload.path" not in workflow
    assert "GRC_DOCS_REF" in workflow
    assert "GRC_PLATFORM_IAC_REF" in workflow
    assert "GRC_SECURITY_IAC_REF" in workflow
    assert 'EVENT_NAME" == "workflow_dispatch"' in workflow
    assert 'EVENT_NAME" == "repository_dispatch"' in workflow
    assert "schedule or repository_dispatch event cannot create a baseline" in workflow


def _production_fixture(
    tmp_path: Path,
    *,
    require_existing_state: bool = True,
) -> tuple[Path, Path, Path]:
    docs = tmp_path / "prod-docs"
    iac = tmp_path / "prod-iac"
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
        iac,
        {"security/main.tf": _terraform_text()},
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
                        "iac_repositories": ["production-iac"],
                        "iac_paths": ["security/main.tf"],
                        "terraform_resource_types": ["aws_iam_policy"],
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    config = tmp_path / "production-monitor.json"
    config.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "monitor_id": "production-regression-test",
                "repositories": [
                    {
                        "name": "production-docs",
                        "kind": "documentation",
                        "root": str(docs),
                    },
                    {
                        "name": "production-iac",
                        "kind": "iac",
                        "root": str(iac),
                    },
                ],
                "links_path": str(links),
                "state_path": str(tmp_path / "default-state.json"),
                "require_existing_state": require_existing_state,
                "targets": [
                    {
                        "target_id": "production-access",
                        "doc_id": "pol-ac-prod",
                        "policy_repository": "production-docs",
                        "policy_path": "policies/access.md",
                        "terraform_roots": [
                            {"repository": "production-iac", "path": "security"}
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
            }
        ),
        encoding="utf-8",
    )
    return config, docs, iac


def _terraform_text(
    *,
    variable_default: str = "safe",
    random_length: int = 2,
) -> str:
    return f'''variable "mode" {{
  default = "{variable_default}"
}}

# grc: link_id=lnk-mfa; domain=access_control; control_id=IA-2
resource "aws_iam_policy" "require_mfa" {{
  name = var.mode
}}

resource "random_pet" "deployment_name" {{
  length = {random_length}
}}
'''


def _unlinked_security_group(cidr: str) -> str:
    return f'''
resource "aws_security_group" "unlinked_admin" {{
  ingress {{
    cidr_blocks = ["{cidr}"]
  }}
}}
'''


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
