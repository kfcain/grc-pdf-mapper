import pytest

from grc_pdf_mapper.extract import extract_control_statements
from grc_pdf_mapper.impact import detect_verbiage_changes
from grc_pdf_mapper.models import ObligationStrength, StatementKind


def _extract(text: str):
    return extract_control_statements(text, doc_slug="regression")


def _changes(before: str, after: str):
    older = extract_control_statements(before, doc_slug="regression-before")
    newer = extract_control_statements(after, doc_slug="regression-after")
    return detect_verbiage_changes(older, newer)


def _single_change(before: str, after: str):
    changes = _changes(before, after)
    assert len(changes) == 1
    return changes[0]


def test_should_not_stays_a_negative_recommendation_and_can_be_softened():
    statement = _extract(
        "Administrators should not export access credentials."
    )[0]

    assert statement.statement_kind == StatementKind.RECOMMENDATION
    assert statement.strength == ObligationStrength.SHOULD
    assert statement.action_polarity == "negative"

    change = _single_change(
        "Administrators must not export access credentials.",
        "Administrators should not export access credentials.",
    )
    assert change.change_kind == "obligation_softened"


@pytest.mark.parametrize(
    "text",
    [
        "The vendor may not support TLS 1.3.",
        "The system may generate duplicate audit logs.",
        "The device cannot encrypt archived records.",
    ],
)
def test_clear_epistemic_modals_are_not_policy_statements(text: str):
    assert _extract(text) == []


def test_epistemic_filter_keeps_actor_permissions_and_prohibitions():
    permission = _extract("Administrators may generate access reports.")[0]
    prohibition = _extract(
        "Administrators cannot encrypt records with unapproved keys."
    )[0]

    assert permission.statement_kind == StatementKind.PERMISSION
    assert permission.strength == ObligationStrength.MAY
    assert prohibition.statement_kind == StatementKind.PROHIBITION
    assert prohibition.strength == ObligationStrength.PROHIBITED


def test_not_required_without_to_is_an_explicit_waiver():
    statement = _extract("Multi-factor authentication is not required.")[0]

    assert statement.statement_kind == StatementKind.PERMISSION
    assert statement.strength == ObligationStrength.MAY


def test_shared_modal_list_survives_a_blank_line_after_the_lead():
    statements = _extract(
        """Administrators must:

- use multi-factor authentication.
- retain audit logs.
"""
    )

    assert [statement.strength for statement in statements] == [
        ObligationStrength.MUST,
        ObligationStrength.MUST,
    ]
    assert "use multi-factor" in statements[0].text
    assert "retain audit logs" in statements[1].text


def test_shared_modal_is_inherited_after_comma_and():
    statements = _extract(
        "Administrators must encrypt backups, and retain audit logs."
    )

    assert len(statements) == 2
    assert all(statement.strength == ObligationStrength.MUST for statement in statements)
    assert "encrypt backups" in statements[0].text
    assert "retain audit logs" in statements[1].text


def test_three_independent_modal_clauses_are_split_recursively():
    statements = _extract(
        "Administrators must use MFA and should review audit logs weekly "
        "and may request exceptions."
    )

    assert [statement.strength for statement in statements] == [
        ObligationStrength.MUST,
        ObligationStrength.SHOULD,
        ObligationStrength.MAY,
    ]


def test_table_row_with_two_rules_produces_two_statements():
    statements = _extract(
        """| Mandatory rule | Optional rule |
|---|---|
| Accounts must use MFA. | Contractors may use passwords. |
"""
    )

    assert len(statements) == 2
    assert [statement.strength for statement in statements] == [
        ObligationStrength.MUST,
        ObligationStrength.MAY,
    ]


def test_interrogative_modal_is_not_a_policy_statement():
    assert _extract("Must administrators use multi-factor authentication?") == []


def test_subordinate_negative_verb_does_not_reverse_the_main_action():
    change = _single_change(
        "Administrators must allow access after they revoke stale credentials.",
        "Administrators must allow access after they remove stale credentials.",
    )

    assert change.change_kind == "obligation_rewritten"


def test_active_to_passive_voice_is_a_non_material_rewording():
    change = _single_change(
        "Security must retain audit logs for 365 days.",
        "Audit logs must be retained for 365 days by Security.",
    )

    assert change.change_kind == "non_material_rewording"


@pytest.mark.parametrize(
    "exception",
    [
        "if the owner approves",
        "except during emergencies",
    ],
)
def test_dynamic_exception_softens_an_obligation(exception: str):
    change = _single_change(
        "Privileged accounts must use multi-factor authentication.",
        "Privileged accounts must use multi-factor authentication "
        f"{exception}.",
    )

    assert change.change_kind == "obligation_softened"


def test_retention_period_removal_is_a_weakening():
    change = _single_change(
        "Audit logs must be retained for 365 days.",
        "Audit logs must be retained.",
    )

    assert change.change_kind == "retention_weakened"


def test_word_based_retention_reduction_is_a_weakening():
    change = _single_change(
        "Audit logs must be retained for one year.",
        "Audit logs must be retained for six months.",
    )

    assert change.change_kind == "retention_weakened"


def test_immediate_deadline_removal_is_an_sla_change():
    change = _single_change(
        "Compromised credentials must be revoked immediately.",
        "Compromised credentials must be revoked.",
    )

    assert change.change_kind == "sla_changed"
    assert "weakened" in change.risk_note.lower()


@pytest.mark.parametrize(
    ("before", "after"),
    [
        ("User accounts must be enabled.", "User accounts must be disabled."),
        (
            "Administrators must approve access requests.",
            "Administrators must reject access requests.",
        ),
    ],
)
def test_lexical_opposites_reverse_the_obligation(before: str, after: str):
    assert _single_change(before, after).change_kind == "obligation_reversed"


def test_generic_any_removal_is_not_a_scope_reduction():
    change = _single_change(
        "Administrators must not share any passwords.",
        "Administrators must not share passwords.",
    )

    assert change.change_kind == "non_material_rewording"


def test_added_subject_modifier_reduces_scope():
    change = _single_change(
        "Privileged accounts must use multi-factor authentication.",
        "Production privileged accounts must use multi-factor authentication.",
    )

    assert change.change_kind == "scope_reduced"


def test_benign_heading_rename_is_non_material():
    change = _single_change(
        "# Access Control\n\nAccounts must use MFA.",
        "# Identity and Access Control\n\nAccounts must use MFA.",
    )

    assert change.change_kind == "non_material_rewording"
