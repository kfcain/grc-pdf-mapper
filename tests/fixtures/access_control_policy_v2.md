# Access Control Policy

**Document ID:** POL-AC-001  
**Version:** 2.2  
**Owner:** Security Governance  
**Framework alignment:** NIST SP 800-53 Rev. 5, ISO/IEC 27001:2022, SOC 2 TSC, NIST CSF 2.0

<!-- Page 1 -->

## 1. Purpose

This policy defines how the organization manages logical access to systems and data. It supports AC-2, AC-3, and IA-2 from NIST SP 800-53, and ISO 27001 control 5.15.

## 2. Scope

This policy applies to all workforce members, contractors, and system accounts that access corporate systems.

## 3. Account Management

User accounts must be uniquely assigned to an individual. Shared accounts are prohibited for interactive administrative access.

The identity team shall provision accounts only after manager approval is recorded in the ITSM system.

Privileged accounts must use multi-factor authentication. Temporary elevated access should expire within 8 hours.

Account reviews must occur at least monthly. Orphaned accounts shall be disabled within 4 hours of detection.

Joiner-mover-leaver workflows must update access within one business day of an HR status change.

## 4. Authentication

Workforce members must authenticate with MFA before they access production systems.

Password reuse across corporate and personal accounts is prohibited.

Service accounts should use managed identities or short-lived credentials where available.

## 5. Encryption of Credentials and Secrets

Secrets must be stored in an approved vault. Credentials shall not be committed to source control.

Data in transit must use TLS 1.2 or higher. Cryptographic modules should align with ISO 27001 control 8.24.

## 6. Logging and Monitoring

Authentication events must be logged centrally. Security operations shall review privileged access anomalies daily.

Audit logs must be retained for at least 12 months to support AU-2 and AU-6 requirements.

## 7. Incident Response Linkage

Access-related security incidents must be escalated under the incident response plan within one hour.

The response team shall revoke compromised credentials immediately after confirmation.

## 8. Third-Party Access

Vendor accounts must be time-bound and scoped to least privilege. Third-party access reviews should occur every 90 days.

## 9. Framework Currency

All external framework citations must reference ISO/IEC 27001:2022 and NIST CSF 2.0.

## 10. Enforcement

Violations of this policy may result in disciplinary action up to termination of access and employment.
