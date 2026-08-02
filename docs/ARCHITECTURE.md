# Architecture

## Problem

Organizations keep policies as PDFs and Markdown. Auditors and certification
programs need:

- Control language tied to NIST / ISO / SOC 2 / CSF / FedRAMP KSI
- Version history and change impact
- Evidence excerpts that cite a specific control
- Lock-step between written policy and policy-as-code

## Approach

Use [Firecrawl pdf-inspector](https://github.com/firecrawl/pdf-inspector) as the
local PDF classification and Markdown extraction engine, then apply a GRC
semantics layer on top.

```
Corporate PDF / Markdown
        │
        ▼
 pdf-inspector (classify + extract)
        │
        ▼
 Control statement miner
        │
        ▼
 Crosswalk (OpenCRE · OSA · OSCAL · FedRAMP CR26 KSI · seed)
        │
        ├─ Lineage store
        ├─ Impact / assessment alerts
        ├─ Policy-as-code sync
        └─ OSCAL-shaped export
```

## Control statement model

Each statement carries a stable content hash, obligation strength
(`must` / `shall` / `should` / `prohibited`), heading path, optional page
marker, explicit framework citations, and topic keywords.

## Crosswalk strategy

1. Explicit citations win.
2. FedRAMP CR26 KSIs map from NIST controls and topic language, with class A–D status.
3. OpenCRE / OSA enrich when online.
4. NIST OSCAL supplies 800-53 titles.
5. Seed maps keep offline workflows useful.

Every mapping records its `source`.

## Document lineage

The lineage store versions Markdown by hash, diffs obligation hashes between
snapshots, and flags removed high-strength obligations as drift.

## Policy-as-code lock-step

Links bind policy language to annotated Terraform. IaC-only or doc-only changes
raise lifecycle alerts so both sides stay complete.

## FedRAMP documentation

For certified offerings, CR26 documentation FRRs (for example certification
package maintenance) are included in impact actions when FedRAMP assessments
are registered for a class.
