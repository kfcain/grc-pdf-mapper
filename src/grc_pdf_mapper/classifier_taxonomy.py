"""Shared labels for policy and Terraform security classifiers."""

from __future__ import annotations

import re
from collections.abc import Iterable


CANONICAL_DOMAINS = frozenset(
    {
        "access_control",
        "asset",
        "awareness",
        "backup",
        "change",
        "data_protection",
        "encryption",
        "governance",
        "incident",
        "logging",
        "network_security",
        "physical",
        "privacy",
        "risk",
        "secure_development",
        "vendor",
        "vulnerability",
    }
)

DOMAIN_ALIASES = {
    "access": "access_control",
    "access_management": "access_control",
    "identity": "access_control",
    "identity_and_access_management": "access_control",
    "audit": "logging",
    "audit_logging": "logging",
    "business_continuity": "backup",
    "configuration": "change",
    "configuration_management": "change",
    "cryptography": "encryption",
    "data_security": "data_protection",
    "iam": "access_control",
    "incident_response": "incident",
    "network": "network_security",
    "security_awareness": "awareness",
    "supplier": "vendor",
    "third_party": "vendor",
    "vulnerability_management": "vulnerability",
}


def normalize_domain(value: str) -> str:
    """Return one stable snake-case classifier label."""
    normalized = re.sub(r"[^a-z0-9]+", "_", value.strip().lower()).strip("_")
    return DOMAIN_ALIASES.get(normalized, normalized)


def normalize_domains(values: Iterable[str], *, strict: bool = False) -> list[str]:
    """Normalize and deduplicate domain labels.

    With ``strict=True``, reject a label that is not in the shared taxonomy.
    """
    normalized = sorted({normalize_domain(value) for value in values if value.strip()})
    if strict:
        unknown = [value for value in normalized if value not in CANONICAL_DOMAINS]
        if unknown:
            raise ValueError("Unknown classifier domain(s): " + ", ".join(unknown))
    return normalized
