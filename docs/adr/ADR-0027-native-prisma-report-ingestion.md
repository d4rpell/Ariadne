# ADR-0027: Native ingestion of Prisma deployed-image reports (offline)

- **Status:** ratified by the owner (2026-10-02); independently reviewed with no open finding; implementation complete and independently reviewed (`apto`, 0 P0/P1/P2/P3), published 2026-10-03.
- **Origin:** task A2-07-F1; the underlying contract was independently reviewed and closed with no open finding.
- **Relationships:** develops the offline scope of [ADR-0020](ADR-0020-prisma-acquisition-and-vulnerability-data.md) (see its proposed-revision section). Preserves the evidence bundle wire `0.2`, the `prisma-v1` input contract, and the accepted records on identity, provenance, decision layers and the evaluator boundary. Supersedes no accepted record.

## Proposed decision

Add two explicitly selected offline input profiles for **native deployed-image reports** of Prisma Cloud Compute, with no autodetection and no fallback:

- `prisma-native-images-json-v1/1.0` — a JSON array of image objects, structured against the publicly documented Compute self-hosted OpenAPI reference `34.04.145` (pinned commit), with a closed disposition for all 89 documented image properties (27 retained, 62 excluded with a loss witness).
- `prisma-native-images-csv-v1/1.0` — a CSV with an exact 39-column header and an Ariadne-defined dialect. This profile is an explicit **candidate**: the header comes from a transcription of an unavailable spreadsheet, and its correspondence with any real Prisma release is **not verified**.

Both produce, in memory: a derived sanitized source (`prisma-native-source-v1`) that retains only allow-listed declarations with explicit presence, numeric-token wrappers and redaction witnesses; a verifiable manifest (`prisma-native-manifest-v1`) with derived counts, aggregated losses and a closed set of 22 limitation codes; and a hash sidecar. A strict replay reconstructs the inventory, all interpretation diagnostics and the manifest from the artifacts alone, trusting no counters, losses or offsets supplied by a caller.

## Context and evidence

External validation against a real Prisma Compute installation was closed as unattainable (2026-10-02): the owner has no tenant access, and public search found no recent verifiable CSV+JSON export pair. P-01 is therefore closed on public documentation plus synthetic loads, with the limit declared in the contract. The JSON profile has documentary structural backing (a pinned catalog of 71 schemas / 392 properties); the CSV candidate has none beyond the transcription.

## Options considered

| Option | Assessment |
| --- | --- |
| Keep only the Ariadne-defined `prisma-v1` CSV | Lowest new surface, but keeps manual conversion and loses native structure and provenance. |
| JSON only | Best documentary backing, but contradicts the confirmed dual offline scope. |
| CSV + JSON with explicit limits (chosen) | Direct conservation and replayable interpretation; costs two profiles and declares unverified CSV semantics. |
| Present the CSV header as an official format | Rejected: the evidence does not support that claim. |
| Infer field mappings by name/value patterns | Deferred: useful as future assistance, insufficient as admission semantics. |
| Persist full originals or fabricate workload subjects | Rejected on privacy and identity grounds. |

## Consequences and limits

Buys: a reproducible, offline, deterministic import record with visible losses, bounded resources and fail-closed admission, without manual conversion. CVSS is retained with exact decimal interpretation and no recalculation; CSV dates stay literal; associations are structural only (no joins by CVE/package name, no cluster×namespace pairing, no runtime binding). The projection to the evidence bundle `0.2` is **empty by contract** for this scope: findings without a proven pod UID + container remain in an intermediate representation, never attributed by invention.

Does not guarantee: compatibility with any Prisma installation, full CSV/JSON equivalence, field presence, authenticity, inventory completeness, scan freshness, absence of vulnerabilities or secrets, security, SLA or compliance. The three decision layers are untouched; scanner metadata never produces technical statuses or risk decisions.

## Revisit if

Primary evidence contradicts the candidate CSV header or its interpretation; a real release becomes available for synthetic validation; another edition/release/report class is needed; an excluded field family becomes necessary; assisted mapping is to be made effective; runtime attribution or a positive bundle projection is required; or leak/unbounded-resource evidence appears.

## Delivery status

Registered in both layers on 2026-10-02 as a proposal and ratified the same day. The offline adapters (task A2-08-F1) are **implemented** and were independently reviewed with `apto` (0 P0/P1/P2/P3); they reproduce the contract's byte-exact vectors. The CSV profile remains an explicit candidate with no verified correspondence to any real Prisma release, and compatibility with a real installation is not verified. The API connector (A2-08-F2) is not implemented. Ariadne is pre-alpha; no distribution of bundles or reports and no release is authorized.
