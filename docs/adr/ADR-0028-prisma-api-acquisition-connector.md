# ADR-0028: Optional Prisma API acquisition connector

- **Status:** proposed (2026-10-02); an authorized fallback independent review (repository `code-reviewer`) closed with no open finding in three passes; the primary Astra review remains re-openable when external quota returns; pending owner ratification; not implemented.
- **Origin:** task A2-07-F2; the contract builds on the ratified offline ingestion scope of [ADR-0027](ADR-0027-native-prisma-report-ingestion.md).
- **Relationships:** develops the network scope of [ADR-0020](ADR-0020-prisma-acquisition-and-vulnerability-data.md) (see its connector precision section). Follows the read-only network precedent of [ADR-0026](ADR-0026-optional-pod-collector.md) as a separate privilege root. Does not change the evidence bundle wire `0.2`, the `prisma-v1` input contract, the decision layers or the Kubernetes collector.

## Proposed decision

An optional connector in a new package (`internal/prismaacquire`, a distinct network-privileged root, independent of the Kubernetes collector in both directions) that acquires only **existing** JSON deployed-image reports from Prisma Cloud Compute **Self-Hosted**, documentary reference `34.04.145`:

- Closed operation allowlist: `GET /api/v34.04/images` plus, only in password-exchange mode, a single `POST /api/v34.04/authenticate`. One explicit HTTPS destination with an in-memory CA, TLS ≥ 1.2, no redirects, proxy, compression, HTTP/2, keep-alive or retries.
- Authentication: a supplied bearer token or one user/password exchange; credentials resolved in memory behind an opaque reference; no Basic, mTLS, platform tokens, automatic renewal or re-authentication after 401; no reading of Kubernetes Secrets, environment values or files.
- Pagination: `offset` advances by the number of received records with `limit=50`; the sequence closes **only** on an admitted empty page (a short page does not terminate, and HTTP 429 is never treated as end of data). Fixed budgets (300 s total, 129 attempts, 5,000 images, 64 MiB accumulated, zero retries) and two conservative guards — repeated sanitized page and suspected drift — abort the run while keeping the pages already admitted. Termination (`finished`/`aborted`/`unknown`) stays separate from inventory coverage, which is always `unknown`, and from consistency, which is always `not_atomic`.
- Delivery: each page is admitted under the exact ratified offline rules (no second parser) and leaves the package as its own sanitized source, manifest and hash sidecar, plus a typed in-memory run result. A new provenance value (`compute_api`) is carried by an explicit `1.1` version of the import artifacts with its own replay selector; the ratified `1.0` artifacts remain unchanged and reject the new value.
- Real-service compatibility per edition/release remains **not verified**: external validation was closed as unattainable, so support rests on public documentation and synthetic tests with the limit declared in the contract itself.

## Options considered

A generic Prisma client (rejected: unbounded surface and authentication combinations before any real evidence); extending the Kubernetes collector package (rejected: mixes privileges and domain contracts); network inside the offline admission (rejected: breaks the acquisition/replay separation); labeling API pages as operator exports or silently extending the ratified artifacts (rejected: false provenance / broken contract); ending on a short page, retrying 429, or deduplicating by digest (rejected: false completion or provenance loss).

## Consequences and limits

Buys a narrow, testable acquisition path with minimal network surface, explicit provenance and full reuse of the offline redaction and replay. Does not guarantee complete inventory, atomic snapshots, freshness, a read-only credential on the server (the documented permission name does not prove it), remote authenticity of the offline artifact, unexercised compatibility, universal anonymization, secure memory erasure or an exact RSS bound. Replaying a page does not reconstruct the whole network run. The three decision layers are untouched; network failures never produce technical statuses or risk decisions.

## Revisit if

Another edition or release must be supported, a documented stable snapshot/cursor mechanism appears, effective server permissions differ, new authentication flows are needed, measured limits block legitimate cases, the repetition/drift guards produce relevant false positives, a persistent run manifest or runtime integration becomes necessary, standard-library changes affect retry behavior, or the import gate is found permeable. Schema, security or privilege changes require a new recorded decision.

## Delivery status

Registered in both layers on 2026-10-02 as a proposal after a no-open-finding fallback review. Implementation (task A2-08-F2) requires a separate executable handoff and explicit authorization. Ariadne is pre-alpha; nothing described here is implemented, and no distribution or release is authorized.
