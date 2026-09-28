# Native Prisma Compute export adapter — design

Date: 2026-09-28. Status: owner-approved delivery scope; input and output contracts remain proposed under [ADR-0020](../adr/ADR-0020-prisma-acquisition-and-vulnerability-data.md).

## Goal and scope

Allow Ariadne to ingest original Prisma Cloud Compute **deployed-image CSV exports and JSON reports offline**, without asking users to translate them into Ariadne's `prisma-v1` CSV. Add API acquisition after offline adaptation. Treat registry-image reports as a later, separately validated profile; their order relative to the API connector remains open. Keep the existing `prisma-v1` input for compatibility.

This targets reported image findings and deployment context. An image report alone does not establish the identity of a Kubernetes pod or a complete technical decision. The first delivery must make unlinked findings and losses visible; it must not invent pod UIDs or evaluation results.

## Why this scope

| Option | Benefit | Cost or limit |
| --- | --- | --- |
| Keep manual conversion to `prisma-v1` | Smallest implementation | Human mapping can lose fields, cardinality, timestamps and provenance. |
| Accept native JSON only | Richer structure and one initial parser | Does not accept the familiar CSV export directly. |
| Accept deployed-image CSV and JSON offline first **(selected)** | Removes manual conversion and lets shared facts be compared | Requires two validated profiles and explicit representation-specific losses. |
| Include registry images immediately | Broader scan coverage | Adds another report contract; a registry scan does not prove deployment. |

Palo Alto Networks documents separate [deployed-image CSV downloads](https://pan.dev/prisma-cloud/api/cwpp/get-images-download/), [deployed-image JSON reports](https://pan.dev/prisma-cloud/api/cwpp/get-images/) and [registry-image CSV downloads](https://pan.dev/prisma-cloud/api/cwpp/get-registry-download/). These pages do not define an exhaustive CSV header or establish compatibility with a particular installed release. No universal Prisma export format is assumed.

## Data flow

1. The caller supplies an original file and explicit source context: Compute edition/release, report kind, scope, filters and acquisition information as required by the reviewed contract. A filename extension or a few matching columns cannot establish compatibility.
2. A bounded CSV or JSON profile validates the admitted shape. Each profile classifies fields as retained, transformed, excluded or uninterpretable. Unknown or malformed data produces bounded diagnostics without copying excluded values into output or errors.
3. Sanitization produces a traceable source and manifest whose hashes cover retained bytes, not the full provider response. The contract must define ordering, duplicates, provenance, timestamps and losses before implementation.
4. Both profiles map only evidenced common facts into a versioned intermediate representation. Format-specific fields and omissions remain explicit. A missing CSV column is not filled from a separate JSON report.
5. A bundle and evaluation are produced only when separate evidence establishes the required pod UID, container and image relationship. Otherwise, the image finding remains visibly unlinked under a contract still to be ratified.
6. A later API connector acquires existing JSON reports and feeds the same admission path. It has separate credentials, network limits, pagination and failure rules. The evaluator remains offline.

`clusters`, `namespaces` and image distribution fields are candidate context when present in an admitted source. Aggregated lists cannot establish cluster/namespace pairs or pod membership. An image's distribution does not identify the node OS or prove a fix. Pod names and container IDs do not substitute for Kubernetes pod UIDs.

## Assisted field recognition — design preference, 2026-09-28

The owner favors documented profiles supplemented by explainable mapping suggestions based on names, value patterns, types and document structure. Exact names alone are brittle across variants; regex alone can confuse a finding with a CVE mentioned in an exclusion or reference. Candidates would remain outside effective adaptation until confirmed under a reviewed contract, with ambiguous relationships visible. Confirmed mappings would be versioned and reproducible, without implying provider authenticity or real Prisma compatibility. Exact rules, confirmation, resource limits, diagnostic redaction and negative tests remain to be specified under ADR-0020. This preference does not change delivery gates or authorize implementation.

## Failure and compatibility rules

Unsupported release or report shape fails visibly. A valid file may still be filtered, partial, old or only one page; file validity must not be reported as complete inventory coverage. CSV flattening, absent columns, JSON-only structure and scanner disagreements are recorded as losses or conflicts rather than silently reconciled. Existing `prisma-v1` behavior, historical evidence hashes and decision states remain unchanged. Registry images require their own profile; no registry finding is promoted to a deployed finding merely because names match.

## Verification and delivery gates

The contract phase must verify an exact deployed-image CSV header/dialect and JSON shape against a specific Compute edition/release using synthetic workloads. It must document field disposition, size limits, identity joins, unlinked findings, sanitized provenance, errors and report exposure in both internal and public ADRs. Synthetic fixtures then test quoted CSV cells, lists, duplicate and optional columns, hostile JSON, omitted fields, stale scans, conflicting image identities, ambiguous clusters, sensitive values, replay and shared-fact comparison across formats. Such fixtures do not prove behavior of a real release.

Implementation remains gated on the reviewed and ratified contract, observed version-specific baseline, executable handoff and owner authorization. API acquisition and registry profiles have separate follow-on reviews. See [ADR-0020](../adr/ADR-0020-prisma-acquisition-and-vulnerability-data.md) for the current decision status and limits.
