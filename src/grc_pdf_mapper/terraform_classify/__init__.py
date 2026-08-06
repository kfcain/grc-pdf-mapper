"""Explainable Terraform resource classification for GRC processing."""

from __future__ import annotations

import re
from dataclasses import dataclass

from grc_pdf_mapper.classifier_taxonomy import normalize_domains
from grc_pdf_mapper.pac_models import TerraformClassification
from grc_pdf_mapper.terraform_syntax import mask_hcl_non_code


_SUPPORTED_EXPLICIT_CONTROL_ID_RES = (
    re.compile(
        r"^(?:AC|AT|AU|CA|CM|CP|IA|IR|MA|MP|PE|PL|PM|PS|PT|RA|SA|SC|SI|SR)"
        r"-\d+(?:\(\d+\))?$",
        re.IGNORECASE,
    ),
    re.compile(
        r"^(?:AAT|AST|BCD|CAP|CFG|CHG|CLD|CPL|CRY|DCH|EMB|END|GOV|HRS|IAC|IAO|"
        r"IRO|MDM|MNT|MON|NET|OPS|PES|PRI|PRM|RSK|SAT|SEA|TDA|THR|TPM|VPM|WEB)"
        r"-\d+(?:\.\d+)?$",
        re.IGNORECASE,
    ),
    re.compile(r"^KSI-[A-Z0-9]+-[A-Z0-9]+$", re.IGNORECASE),
    re.compile(
        r"^(?:CC|A1|C1|PI1|P1)\d*(?:\.\d+)+(?:-POF\d+)?$",
        re.IGNORECASE,
    ),
    re.compile(r"^(?:A\.)?\d+(?:\.\d+)+$", re.IGNORECASE),
    re.compile(r"^(?:GV|ID|PR|DE|RS|RC)\.[A-Z]{2}(?:-\d+)?$", re.IGNORECASE),
    re.compile(r"^CIS\s*\d+(?:\.\d+)*$", re.IGNORECASE),
    re.compile(r"^REQ\.?\s*\d+(?:\.\d+)*$", re.IGNORECASE),
)


@dataclass(frozen=True)
class _Rule:
    domain: str
    type_terms: tuple[str, ...]
    content_terms: tuple[str, ...]
    control_ids: tuple[str, ...]
    roles: tuple[str, ...]


_RULES = (
    _Rule(
        "access_control",
        (
            "_iam_",
            "azuread_",
            "okta_",
            "identity",
            "sso",
            "access_policy",
            "service_account_key",
            "google_service_account",
            "role_definition",
        ),
        ("multifactorauth", "multi-factor", "mfa", "assume_role", "principal"),
        ("AC-2", "AC-3", "IA-2"),
        ("preventive",),
    ),
    _Rule(
        "logging",
        (
            "cloudtrail",
            "log_group",
            "diagnostic_setting",
            "audit",
            "securityhub",
            "guardduty",
            "sentinel",
            "logging_project_sink",
            "log_analytics_workspace",
            "config_configuration_recorder",
        ),
        ("enable_logging", "audit_log", "log_destination", "event_selector"),
        ("AU-2", "AU-6", "SI-4"),
        ("detective",),
    ),
    _Rule(
        "encryption",
        (
            "_kms_",
            "key_vault",
            "key_ring",
            "crypt",
            "certificate",
            "secretsmanager",
            "secret_manager_secret",
        ),
        ("encrypted", "encryption", "kms_key", "customer_managed_key", "tls"),
        ("SC-12", "SC-13", "SC-28"),
        ("preventive",),
    ),
    _Rule(
        "network_security",
        (
            "security_group",
            "network_acl",
            "firewall",
            "_waf",
            "cloud_armor",
            "compute_security_policy",
            "azurerm_network_security_rule",
        ),
        ("cidr_blocks", "source_ranges", "0.0.0.0/0", "::/0", "ingress", "egress"),
        ("SC-7", "AC-4"),
        ("preventive",),
    ),
    _Rule(
        "backup",
        ("backup", "recovery", "snapshot"),
        ("retention_days", "recovery_point", "backup_vault", "point_in_time_recovery"),
        ("CP-9", "CP-10"),
        ("recovery",),
    ),
    _Rule(
        "vulnerability",
        ("inspector", "vulnerability", "patch", "defender"),
        ("scan", "patch_baseline", "vulnerability"),
        ("RA-5", "SI-2"),
        ("detective", "corrective"),
    ),
    _Rule(
        "change",
        (
            "config_rule",
            "policy_assignment",
            "organization_policy",
            "organizations_policy",
            "config_configuration_recorder",
        ),
        ("compliance_rule", "configuration_policy", "policy_type"),
        ("CM-2", "CM-3", "CM-6"),
        ("governance", "preventive"),
    ),
    _Rule(
        "incident",
        ("incident", "event_rule", "eventbridge_rule", "response"),
        ("incident_response", "remediation", "response_plan"),
        ("IR-4", "IR-5"),
        ("detective", "corrective"),
    ),
    _Rule(
        "data_protection",
        (
            "s3_bucket",
            "storage_account",
            "storage_bucket",
            "azurerm_storage_container",
            "_rds_",
            "sql_database",
            "bigquery_dataset",
        ),
        ("public_access", "versioning", "data_classification", "retention_policy"),
        ("AC-3", "SC-28", "MP-4"),
        ("preventive",),
    ),
    _Rule(
        "access_control",
        ("accessanalyzer_analyzer",),
        (),
        ("AC-2", "AC-6", "CA-7"),
        ("detective",),
    ),
)


def classify_terraform_resource(
    resource_type: str,
    block: str,
    *,
    tags: dict[str, str] | None = None,
    annotations: dict[str, str] | None = None,
) -> TerraformClassification:
    """Classify one resource with deterministic rules and evidence strings."""
    tags = tags or {}
    annotations = annotations or {}
    block = mask_hcl_non_code(block, mask_strings=False)
    type_text = resource_type.lower()
    content_text = block.lower().replace(" ", "")
    domains: set[str] = set()
    controls: set[str] = set()
    roles: set[str] = set()
    reasons: list[str] = []
    confidence = 0.0

    for rule in _RULES:
        type_hits = [term for term in rule.type_terms if term in type_text]
        content_hits = [term for term in rule.content_terms if term.replace(" ", "") in content_text]
        if not type_hits and not content_hits:
            continue
        domains.add(rule.domain)
        controls.update(rule.control_ids)
        roles.update(rule.roles)
        if type_hits:
            reasons.append(
                f"resource type matched {rule.domain}: {', '.join(type_hits)}"
            )
            confidence = max(confidence, 0.82)
        if content_hits:
            reasons.append(
                f"resource content matched {rule.domain}: {', '.join(content_hits[:4])}"
            )
            confidence = max(confidence, 0.74)
        if type_hits and content_hits:
            confidence = max(confidence, 0.9)

    declared_controls = _split_values(
        annotations.get("control_ids")
        or annotations.get("control_id")
        or tags.get("control_ids")
        or tags.get("control_id")
        or ""
    )
    explicit_controls = [
        value for value in declared_controls if _is_supported_explicit_control_id(value)
    ]
    invalid_controls = [
        value for value in declared_controls if not _is_supported_explicit_control_id(value)
    ]
    if explicit_controls:
        controls.update(value.upper() for value in explicit_controls)
        reasons.append("explicit GRC control annotation")
        confidence = max(confidence, 0.99)
    if invalid_controls:
        reasons.append(
            "unrecognized GRC control annotation: "
            + ", ".join(value.upper() for value in invalid_controls)
        )
        confidence = max(confidence, 0.5)

    explicit_domains = _split_values(
        annotations.get("domains")
        or annotations.get("domain")
        or tags.get("grc_domains")
        or tags.get("grc_domain")
        or ""
    )
    if explicit_domains:
        domains.update(normalize_domains(explicit_domains, strict=True))
        reasons.append("explicit GRC domain annotation")
        confidence = max(confidence, 0.98)

    explicit_roles = _split_values(
        annotations.get("roles")
        or annotations.get("role")
        or tags.get("grc_roles")
        or tags.get("grc_role")
        or ""
    )
    if explicit_roles:
        roles.update(value.lower() for value in explicit_roles)
        reasons.append("explicit GRC enforcement-role annotation")
        confidence = max(confidence, 0.98)

    if annotations.get("link_id") or tags.get("link_id"):
        reasons.append("resource has a policy-to-code link identifier")
        confidence = max(confidence, 0.97)

    unrestricted_network = "0.0.0.0/0" in block or "::/0" in block
    if unrestricted_network:
        domains.add("network_security")
        controls.update(("SC-7", "AC-4"))
        roles.add("preventive")
        roles.add("exposure")
        reasons.append("resource contains an unrestricted network scope marker")
        confidence = max(confidence, 0.92)

    disabled = re.findall(
        r"\b(encrypted|enable_logging|logging_enabled|public_access_block|"
        r"block_public_acls|block_public_policy|restrict_public_buckets|"
        r"ignore_public_acls|mfa_delete|enable_key_rotation|"
        r"point_in_time_recovery_enabled)\s*=\s*false\b",
        block,
        flags=re.IGNORECASE,
    )
    if disabled:
        reasons.append(
            "security-relevant settings are disabled: " + ", ".join(sorted(set(disabled)))
        )
        confidence = max(confidence, 0.92)
        roles.clear()
        roles.add("configuration_risk")

    security_sensitive = bool(
        domains
        or declared_controls
        or annotations.get("link_id")
        or tags.get("link_id")
    )
    explicit_review = bool(explicit_controls or explicit_domains or explicit_roles)
    approved_posture = (
        annotations.get("posture", "").lower() in {"approved", "implemented"}
        or tags.get("grc_posture", "").lower() in {"approved", "implemented"}
        or bool(annotations.get("exception_id") or tags.get("grc_exception_id"))
    )
    posture = (
        "violated"
        if disabled
        else "review_required"
        if invalid_controls or (unrestricted_network and not approved_posture)
        else "implemented"
        if security_sensitive and (explicit_review or confidence >= 0.85)
        else "unknown"
    )
    status = (
        "misconfigured"
        if posture == "violated"
        else "review_required"
        if posture == "review_required"
        else "reviewed_annotation"
        if explicit_review
        else "classified"
        if security_sensitive and confidence >= 0.85
        else "review_required"
        if security_sensitive
        else "not_security_relevant"
    )
    return TerraformClassification(
        domains=normalize_domains(domains, strict=True),
        candidate_control_ids=sorted(controls),
        enforcement_roles=sorted(roles),
        security_sensitive=security_sensitive,
        confidence=round(min(confidence, 0.99), 2),
        status=status,
        posture=posture,
        reasons=list(dict.fromkeys(reasons)),
    )


def _split_values(value: str) -> list[str]:
    return [item.strip() for item in re.split(r"[,|]", value) if item.strip()]


def _is_supported_explicit_control_id(value: str) -> bool:
    control_id = value.strip()
    return any(pattern.fullmatch(control_id) for pattern in _SUPPORTED_EXPLICIT_CONTROL_ID_RES)
