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
 Crosswalk (SCF API · FedRAMP CR26 KSI · OpenCRE · OSA · OSCAL · seed)
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
2. **SCF API** (Secure Controls Framework) is the primary backbone: cited
   controls resolve to SCF ids, then fan out across NIST / ISO / SOC 2 /
   CSF / CIS / PCI (live API online; bundled seed offline).
3. FedRAMP CR26 KSIs map from NIST controls and topic language, with class A–D status.
4. OpenCRE / OSA enrich when online.
5. NIST OSCAL supplies 800-53 titles.
6. Seed maps keep offline workflows useful.

Every mapping records its `source` (`scf-api`, `seed`, `fedramp-cr26-ksi`, …).

SCF data is CC BY-ND 4.0 from [securecontrolsframework.com](https://securecontrolsframework.com).
API: [GRCEngClub/scf-api](https://github.com/GRCEngClub/scf-api) (ethanolivertroy).

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
