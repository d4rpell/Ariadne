# ADR-0029: Offline Prisma Cloud Compute registry-image profile

- **Status:** ratified by the owner (2026-10-03). The **registry JSON profile** is implemented, independently reviewed (`apto tras corregir`, 0 P0/0 P1) and published (2026-10-03). The **registry CSV profile is reserved indefinitely**: its literal header (ES-R1) cannot be closed by evidence because the owner has **no access** to a registry CSV export. Real Prisma compatibility is **not verified**.
- **Origin:** task A2-07/A2-08 — "Extend profiles to registry images".
- **Relationships:** develops the registry scope of [ADR-0020](ADR-0020-prisma-acquisition-and-vulnerability-data.md) ("registry images are a later, separately validated profile"). It is a **new contract, not an extension** of [ADR-0027](ADR-0027-native-prisma-report-ingestion.md), which fixes `report_kind` to `deployed_images` and rejects any other value. It is **offline**: it does not touch the network scope of [ADR-0028](ADR-0028-prisma-api-acquisition-connector.md). It preserves the evidence bundle wire `0.2`, `prisma-v1`, the evaluator, the three decision layers and the identity rules. Supersedes no accepted record.

## Decision

Add a **third** offline native-ingestion profile for **registry-image reports** (registry scans) of Prisma Cloud Compute, separate from the deployed-image profiles of ADR-0027:

- A dedicated artifact family: `report_kind = registry_images` (new literal), artifact version `2.0`, selectors `prisma-native-registry-json-v1` / `prisma-native-registry-csv-v1`, profiles `compute-sh-34.04.145-registry-json` and `compute-sh-34.04.145-registry-csv-candidate`.
- Central rule: **a registry scan does not prove deployment**. `runtime_binding = not_attempted`; an explicit prohibition on promoting a registry finding to a deployed finding; the projection to the evidence bundle `0.2` is **empty by contract**; and mandatory global limitation codes `registry_profile` and `registry_not_deployment`.
- Full reuse of ADR-0027's ratified rigor (private reader, fail-closed budgets with no relaxation, strict admission, field disposition, sanitized-source/manifest/hash-sidecar artifacts and strict replay), with declared registry deltas and **no expansion of what is retained** (`labels`, `hosts` and free metadata stay excluded).
- The **native report class is a caller declaration, not a property provable from bytes**: a `shared.ImageScanResult` is byte-indistinguishable between a registry and a deployed scan. The separation is of contract and artifacts, not of authenticated provenance.
- **One input precision remains open and deferred**: the **literal CSV header of the registry export** (ES-R1). No registry export is available for review (owner-confirmed, 2026-10-03), so ES-R1 cannot be closed by evidence and the CSV profile stays reserved. The earlier precision about the JSON schema **is resolved at the documentary level** by new evidence: `/registry` shares the `shared.ImageScanResult` schema with `/images`.
- The **relative order** between this profile and the API connector (ADR-0028) remains **open**; only the question is recorded.

## Context and evidence

ADR-0027 (ratified and implemented) admits **only** deployed images; the code rejects any `report_kind` other than `deployed_images`. ADR-0020 and the public plan fix registry images as a later profile with its own contract, and state that a registry scan does not prove deployment. External validation against a real Prisma installation was closed as unattainable (A2-10, 2026-10-02): compatibility per edition/release **cannot be attested**, so support rests on public documentation plus synthetic loads.

Documentary authority (public sources only; no tenant, no credentials, no customer data): the pinned Compute self-hosted OpenAPI `34.04.145` (commit `e5b16d8e…`), whose SHA-256 was recomputed and matches the reference fixed by ADR-0027.

- `GET /api/v34.04/registry` → `200 application/json` of schema `-_shared.ImageScanResult` (an array of `shared.ImageScanResult`), **the same schema as `/api/v34.04/images`**. Documented parameters include `offset`, `limit`, `sort`, `reverse`, `id`, `imageID`, `repository`, `registry`, `name`, `compact`, `normalizedSeverity`, `layers`, `issueType`, `filterBaseImage` and CAAS/uai filters.
- `GET /api/v34.04/registry/download` → the registry report **as CSV**, with **no documented header, columns or dialect**.

No registry header transcription exists. The 39-column transcription of ADR-0027 is a **deployed-image** header and is not reused.

## Options considered

| Option | Assessment |
| --- | --- |
| Do not admit registry images | Smallest surface, but leaves out a report class the owner asked to consider. |
| Reuse the deployed-image profile behind a flag | Rejected: it would make a registry finding indistinguishable from a deployed one — the exact error to prevent. |
| Extend ADR-0027 instead of a new record | Rejected: a contract change needs its own record, and ADR-0027 fixes `report_kind` to `deployed_images`. |
| Separate profile with its own record (chosen) | Preserves the registry/deployed semantic separation and allows separate review and ratification. |
| JSON only | Backed by a documented schema, but drops the usual CSV representation. |
| CSV only | Inverts the priority, and its header is not verifiable today. |
| Both representations, CSV as candidate (chosen) | Full coverage while declaring what is unverified, without inventing facts. |
| Invent a candidate registry header | Rejected: it would fabricate columns without evidence. |
| Require an authorized header transcription (ES-R1) | Recommended: it fixes the literal from owner evidence, as was done for deployed images. |
| Expand retention to `labels`/`hosts`/free metadata | Rejected here: it could retain secrets previously discarded; it is an owner decision needing its own policy. |

## Why this was the best at the time

Separating the profile is the only way to guarantee that "registry" is never confused with "deployed" in any layer: context, artifacts, replay, limitations and projection. Reusing ADR-0027's rigor — including its documented JSON schema, shared by `/registry` — minimizes new surface and keeps the evaluator offline. Declaring the CSV header open, instead of inventing it, avoids turning a hypothesis into a compatibility claim. The cost is registry coverage limited to repository/image context without deployment attribution, plus one owner-dependent implementation blocker.

## Consequences and limits

Buys: a reproducible, offline, deterministic registry profile with visible losses, bounded resources and fail-closed admission, without manual conversion, and an explicit semantic boundary that prevents registry-to-deployed promotion.

Does not guarantee: compatibility with any real Prisma release; the registry CSV header (ES-R1); which properties a registry scan populates (the schema is documented, per-class presence is not); that the declared class is authentic (it is a caller declaration, not provable from bytes); deployment attribution, pod/namespace/cluster linkage or a pod UID; the existence, absence or resolution of vulnerabilities; scan freshness; authenticity or inventory completeness; security, SLA or compliance. The three decision layers are untouched; scanner metadata never produces technical statuses or risk decisions. The projection to the evidence bundle is **empty by contract**.

## Revisit if

A verifiable registry CSV header or a `/registry` JSON response appears that contradicts the field disposition; another edition/release must be supported; a positive bundle projection, runtime binding or registry-to-deployed promotion is required; retention is to be expanded to `labels`/`hosts`/free metadata; the offline boundary is found permeable; or the pinned `/registry` schema or parameters change.

## Delivery status

Registered in both layers on 2026-10-03 and **ratified by the owner the same day**. The **registry JSON profile** is implemented, independently reviewed with no open P0/P1 and published on 2026-10-03. The **registry CSV profile stays reserved**: it cannot start until ES-R1 is closed with verifiable evidence of the literal registry CSV header, and the owner has no access to a registry export, so no such evidence is expected. Ariadne is pre-alpha; no distribution of bundles or reports and no release is authorized.
