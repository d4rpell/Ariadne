# ADR-0034: Governance platform — closure of Q-01..Q-08 and operating contract

**Status: Ratified on 2026-10-06 by the owner** (drafted as Proposed the same day; independent review closed with `apto` — 0 P0/0 P1; the owner accepted the closure of task A3-07 and authorized commit/push). Task A3-07; basis for the A3-06 platform contract. **No implementation**: this decision adds no code, wire fields or states; implementation requires its own handoff and authorization.

Relations: **supersedes** ADR-0019 (proposal, whose Q-01..Q-08 it closes). Depends on ADR-0003 (offline, deterministic, single binary), ADR-0004 (no `pods/exec`, no AI in the decision path), ADR-0017 (governance platform), ADR-0016 (wire `0.2`), ADR-0030/ADR-0031 (append-only case record and validity view), ADR-0026 (collector). It does **not** authorize distribution or release.

## Decision

The recommended option for each of the eight open questions of ADR-0019 is adopted. Guiding principle: **the platform is a derived projection over canonical append-only artifacts; it is not an alternative source of truth, does not edit technical states, does not rewrite history, and exposes no network beyond loopback.** The UI consumes an **immutable, reconstructible read model**; every mutation goes through typed, authorized and auditable backend commands.

- **Q-08 — Authorization and isolation.** Platform **loopback only (`127.0.0.1`)**, no telemetry, no CDN, no remote fonts, no LAN access. Strict separation of UI / backend / collector / evaluator. Collector holds credentials **in memory only**, least-privilege per namespace, and reads no Secrets/logs/env or `ConfigMap.data`. The UI never mutates storage directly. **Until the local caller-authorization model is decided (a deferred sub-decision), the platform is implemented read-only over the read model and NO mutations are implemented**: loopback limits the network, it does not authorize a local process/user, so accepting mutations without verifiable identity and permissions is prohibited.
- **Q-05 — Source of truth and storage.** Canonical **append-only, immutable** artifacts are the source of truth. The (hot) read model is **reconstructible** from verified artifacts. `hot/warm/cold` are **access tiers**, not semantic states or alternative sources. A3-06 implements **a single verifiable local store**; indexes/caches never change states.
- **Q-02 — Event identity.** Each event is identified by a **canonical envelope hash** linked explicitly to its inputs. Byte-equivalent duplicates are **idempotent**; a change, re-evaluation or historical import produces a **new related event**, never an overwrite. Four times stay separate (`observed_at`/`ingested_at`/`evaluated_at`/`decided_at`). Ordering is by **declared semantic time + deterministic tie-break**; arrival order is not temporal truth.
- **Q-01 — Orchestration.** Point `Job` (manual) and periodic `CronJob` (tracking) in a configurable dedicated namespace. **No bespoke scheduler.** Concurrency **1 per scope**; **bounded** retries for recoverable failures only; frequency declared in configuration. Partial results and failure events are **persisted before exit**; resumption is per idempotent unit. The evaluator stays pure, offline and network-free.
- **Q-04 — Views, coverage and staleness.** Views and graphs derive from the read model and **declare** scope, last observation/ingestion/evaluation, freshness and provenance. Stale data stays **visible as stale**; it never becomes absence, `not_affected` or a current state. Graphs show **only changes explained by events**; an unobserved cause is **unknown**. The three decision layers stay separate.
- **Q-03 — Asset continuity.** Primary identity is `metadata.uid` + container. History is **not** transferred between UIDs automatically; continuity requires an **explicit, verifiable relation** (`supersedes`/`replaces` or equivalent) with actor, evidence, date and scope. Deadlines transfer **only** if policy authorizes it; affectedness is **never** transferred automatically (`product_status` does not follow asset presence).
- **Q-06 — Retention and suppression.** The append-only history is the audit source. Normal suppression **appends an event** of concealment/invalidation and updates the read model; it does **not** silently erase evidence. `legal hold` blocks suppression until explicit release. Physical deletion, key-destruction encryption and legal retention periods are **not** decided yet.
- **Q-07 — Export.** **Versioned canonical JSON** for reproducible interchange; **CSV** only as a limited tabular projection with closed columns and diagnostic rows; **XML deferred** outside A3-06. Unknowns are represented **explicitly** (never empty/zero/`false`). Export **≠** distribution and does not attest origin authenticity.

## Context

ADR-0019 (proposal, 2026-09-27) deliberately left Q-01..Q-08 undecided; ADR-0017 (ratified) defines the governance projection but **explicitly reserves** DB, API, framework, deployment, auth/RBAC/SSO, multi-tenancy and retention/deletion. Neither is implemented. Existing code: `internal/casefile` (append-only decision record + `Assess` view), `internal/collector`, `internal/evaluator`, `internal/report`, `internal/interop`; no UI, server or durable platform store. Owner choices: in-cluster, configurable dedicated namespace, point `Job`, periodic `CronJob`, durable storage outside the pod lifecycle (2026-09-27); and a **local** UI (loopback, no telemetry/CDN, embedded assets) consuming an immutable read model (2026-10-06).

## Options

For each question the realistic options and the rejected ones are recorded in the internal option analysis (brief, 2026-10-06). In summary, the chosen options are loopback+local user (Q-08), canonical append-only + reconstructible read model (Q-05), content-hash identity (Q-02), `Job`/`CronJob` without a bespoke scheduler (Q-01), non-authoritative derived indexes with explicit staleness (Q-04), continuity only via explicit relation (Q-03), event-based suppression with legal hold (Q-06), and canonical JSON with derived CSV and XML deferred (Q-07).

## Why this is best now

It preserves the offline/deterministic/append-only invariants and the separation of the three decision layers; it is fully reversible (remote exposure, physical engine and physical deletion are explicitly deferred and would require a new ADR); and it avoids pulling into A3-06 the three largest sources of complexity (physical engine, multi-user auth, bespoke scheduler) before real volume and requirements exist.

## Consequences and limits (what it does NOT guarantee)

- The platform remains a **projection**, not a source of truth; a read model rebuilt from the same artifacts must be **identical**.
- It does **not** authorize remote network, multi-tenancy, SSO or multi-user RBAC; loopback is the only decided mode.
- It does **not** authorize **mutations** from local users/processes until the caller-authorization boundary (identity, permissions, rejection, auditing) is fixed; until then the platform is **read-only**.
- It does **not** decide physical deletion, key-destruction encryption or retention periods (Q-06 remains open on those points).
- It does **not** decide the physical engine or hot/warm/cold as an implementation (only their logical semantics).
- It changes no wire, states or `casefile` contract; any decision requiring new wire fields (event identity, continuity relations, tombstones) requires a **new ADR**.
- It attests no origin authenticity, no Kubernetes/OpenShift per-release compatibility, and no technical correctness of any conclusion.

## Deferred sub-decisions (owner input required)

Depend on data or judgement that does not exist today and is not invented: number of installations/local users and the **local caller-authorization model** (mutation identity, permissions, rejection, auditing), and need for login (Q-08); physical engine, volume/latency/space, encryption/backup/disaster recovery, whether warm/cold is in A3-06 (Q-05); min/max frequency, operational budget, retry and cluster-load policy, target Kubernetes versions (Q-01); freshness thresholds and per-view "active" meaning (Q-04); who may declare continuity and with what evidence, deadline-transfer policy (Q-03); retention periods, data subject to suppression, legal hold, legal/contractual requirements — a **mandatory** owner decision (Q-06); target consumers and format compatibility, whether import is allowed (Q-07); exact canonical identity fields and external-clock trust (Q-02).

## Review conditions

Reopen if: (a) remote/LAN exposure or multi-user becomes a requirement; (b) the platform becomes a source of truth or edits states; (c) physical deletion or key destruction is required; (d) the read model stops being reconstructible from verified artifacts; (e) format compatibility with a concrete external consumer is needed; (f) the wire or event identity changes.

## Status and date

- **2026-10-06:** Ratified by the owner; independent review closed with `apto` (0 P0/0 P1). Closes Q-01..Q-08 of ADR-0019 and unblocks the design and handoff of the A3-06 contract (F2), without authorizing implementation until its own handoff and authorization.
- **Depends on**: ADR-0003, ADR-0004, ADR-0016, ADR-0017, ADR-0026, ADR-0030, ADR-0031.
- **Supersedes**: ADR-0019. **Superseded by**: nothing.
