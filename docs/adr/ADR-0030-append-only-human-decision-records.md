# ADR-0030: Offline append-only records of human risk decisions

- **Status:** ratified and accepted by the owner (2026-10-04). The design contract was independently reviewed and closed with no open findings (0 P0/P1/P2/P3); the implementation was independently reviewed with the same result (`apto`, 0 P0/0 P1, 2 P2 deferred to backlog), with 22/22 mutation tests red and all local gates green, and published to `origin/main` the same day with the owner's authorization.
- **Scope:** task A3-01; the first layer-3 library, `internal/casefile`.
- **Relationships:** develops [ADR-0004](ADR-0004-no-exec-human-decision.md) (no AI in the decision path; an exception is a human act) and the append-only timeline of [ADR-0017](ADR-0017-optional-governance-platform-and-timeline.md); preserves the evidence bundle wire `0.2`, the CLI contract, and the accepted records on identity, provenance and the evaluator boundary. Supersedes no accepted record. Provides the base expected by exception lifecycle (A3-02) and VEX/SARIF exports (A3-03).

## Proposed decision

Add a pure, offline Go library that keeps explicit human risk decisions as append-only records.

- Record vocabulary is exactly `accepted`, `deferred`, `rejected`. Absence of a human assessment produces no record at all; the internal `not_assessed` notion never becomes a record.
- Every record requires an owner, an approver, a rationale, a scope and a `decided_at` timestamp. Optional fields — compensating controls, `expires_at`, a result fingerprint and a `supersedes` reference — are carried as declared data.
- The scope links the decision to a bundle hash (`sha256:` + 64 hex), a workload UID, a container name, a container class and a vulnerability identifier. Identity is never inferred or normalized.
- The library offers immutable append, read-back, deterministic canonical JSON, a SHA-256 hash per record and full verification of a hash chain (each record embeds the previous record's hash). It never computes technical states or human decisions, never emits an `exception-candidate` label, and never derives a "currently valid" decision.
- The API takes bytes in and returns bytes or writes to an explicit `io.Writer`. It opens no paths and uses no network, shell, clock, environment or implicit input. The format is independent of the evidence bundle wire.

Expiry and invalidation semantics (reopening after `expires_at`, the effect of `supersedes`) are out of scope here; they belong to the exception-lifecycle record.

## Context

Ariadne separates product status, exploitability and human risk decision; the first two never constitute risk acceptance. The architecture names the case/decision record as designed but unimplemented debt, and the ratified governance-platform record requires an append-only timeline where corrections create new events instead of rewriting history. The evidence bundle already establishes the house pattern — canonical bytes, content hashes, IO through explicit capabilities — and its hash proves integrity of a representation, never authenticity of an origin; a decision ledger needs that distinction stated even more explicitly, because a hash chain without an external anchor has limits that must be declared, not hidden.

## Options considered

| Option | Assessment |
| --- | --- |
| Put the decision inside the evidence bundle `0.2` | Rejected: mixes lifecycles and forces a change to an out-of-scope contract. |
| Keep only the latest decision | Rejected: loses owners, rationale and prior history. |
| Editable records with optional audit trail | Rejected: permits rewriting and makes history a conditional guarantee. |
| Independent hashed records, no chaining | Insufficient: no verifiable relation between successive appends. |
| Canonical immutable book with a hash chain (chosen) | Separates governance from evidence; the whole presented sequence is verifiable. |
| Database, signatures and authorization service from the start | Deferred: persistence, identity, key management and operation decisions are still open. |
| Flexible JSON normalized on read | Rejected: enlarges accepted variants and hides representational differences. |
| Automatic expiry/invalidation inside append | Rejected for this task: pre-empts the exception-lifecycle record. |

## Why this was the best option at the time

The standalone library fills a missing piece without introducing acquisition or storage privileges. The immutable book makes historical conservation checkable by direct comparison of records and hashes; typed references keep the exact subject visible without attributing authenticity to caller-supplied values. A single canonical representation enables reproducible byte-for-byte vectors, and conservative budgets bound processing without truncating declarations. A stdlib-only import boundary avoids accidentally connecting governance code to evaluators or network clients. The accepted cost is a new internal format with a strict reader and full-chain re-verification on append, bounded by the budgets; no efficiency is promised for unbounded durable histories.

## Consequences and limits

Corrections are expressed as new records; earlier ones stay available. `expires_at` and `supersedes` are preserved from the first format but implement no expiry, invalidation, reopening or precedence. The chain detects internal inconsistency; it does not authenticate the declarer and does not prevent a full reconstruction, a truncated suffix, a fork or a wholesale substitution by another coherent book. The caller remains responsible for authorized human decisions, correct references, external head comparisons, destinations and persistence. The library does not verify that a referenced bundle exists or contains the subject; an accepted record never implies a currently valid risk acceptance, product safety or compliance. No CLI, web platform, signatures, encryption, durable storage, VEX or SARIF is delivered; the existing reporter is unchanged.

## Review conditions

Contract revision is required to extend fields, enums, formats, timestamp precision or budgets; to verify bundles or results; to add cross-book references, case identity, deduplication or branch merging. Changing the meaning of `supersedes`, computing validity or deriving governance views belongs to the exception-lifecycle record or an explicit later decision. Persistence, retention, deletion, authentication and operation get their own records — they will not slip in as implementation details. Artifacts admitted under a ratified version keep their bytes and interpretation; an incompatible need means a new version with explicit admission.
