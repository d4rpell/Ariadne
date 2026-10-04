# ADR-0031: Case-record validity, invalidation and `supersedes` relations

- **Status:** ratified by the owner and accepted (2026-10-04). The design contract and the implementation were independently reviewed with no open finding (`apto`); the derived view is implemented (task A3-02) and published the same day.
- **Scope:** task A3-02; `internal/casefile`.
- **Relationships:** develops [ADR-0030](ADR-0030-append-only-human-decision-records.md) (append-only decision records) and the append-only timeline of [ADR-0017](ADR-0017-optional-governance-platform-and-timeline.md); applies the two-layer record policy of [ADR-0011](ADR-0011-decision-record-policy.md); preserves the evidence bundle wire `0.2` and the three separate decision layers. Supersedes no accepted record. Does not close the open questions of [ADR-0019](ADR-0019-operating-modes-and-persistent-tracking.md).

## Proposed decision

Add to `internal/casefile` a **pure derived view** —`Assess(book, asOf)`— over an already-admitted record book:

- At a caller-supplied instant (`as_of`), each record gets one closed `standing`: `effective`, `pending`, `expired` or `superseded`. These are derived governance states, never technical states or risk decisions.
- `superseded` is resolved through an explicit `supersedes` relation, using a **continuity key** — the decision subject: the decision scope without the bundle-dependent fields (`bundle_hash`, `result_fingerprint`). The key is what allows a digest change to invalidate an earlier exception through a declared `supersedes` without the library reading the bundle. It is **not** a scope of application: each derived entry keeps the full scope, and a query by subject returns **candidates within the book**, not "the applicable decision". Applying a decision to another bundle or fingerprint requires a new declaration or an explicit correspondence contract; the caller must match the full scope against the evidence it holds.
- Expiry is inclusive: a record with `expires_at <= as_of` is `expired`. Reopening is not performed by the library: the consumer maps the absence of a candidate decision to the layer-3 absence (`not_assessed`), never to a technical state. An `expired` record means that record provides no current decision — not that the subject lacks one.
- A query for the effective candidates of a subject **does not collapse conflicts**: zero, one or several effective records are returned as-is, with structural or instant-dependent anomalies (`supersedes_subject_mismatch`, `ambiguous_supersession`) surfaced instead of a silent choice.

The view changes neither the format, the version, the hash preimage, the budgets nor the closed error catalogue. It preserves the bytes, admission and behaviour of ADR-0030's operations; the new operation **adds** an explicit validity interpretation under this record.

## Context

ADR-0030 deliberately left expiry, invalidation, reopening and semantic precedence out of scope: the record carries `expires_at` and `supersedes` as data but does not interpret them. The architecture requires that, after `expires_at`, a conclusion is no longer treated as current (reopened as `unknown`/`under_investigation`) without rewriting history, and that invalidation use explicit `supersedes` relations (digest change, base image, package release, configuration, advisory). What was missing is the contract that makes this semantics operational without turning the record into a state machine.

## Options considered

| Option | Assessment |
| --- | --- |
| Add a per-record validity field to the wire | Rejected: mixes declared data with derived state and breaks byte compatibility. |
| Automatic digest-change invalidation inside `casefile` | Rejected: requires reading the bundle/Result, forbidden by ADR-0030 (the library does not resolve bundles). |
| Pure derived view over the book, no format change | **Recommended:** deterministic, offline, backward compatible, no new authority. |
| Collapse to "one current decision per subject" | Rejected: would choose silently on conflict (silent invalidation). |
| Supersession over the whole scope (including the bundle) | Rejected: a digest change would change `bundle_hash` and would not invalidate, emptying the use case. |
| Require subject match as fail-closed validation | Rejected: would refuse books already admitted by ADR-0030; it is surfaced as an anomaly instead. |

## Why this was the best option at the time

The derived view introduces no privileges, network or clock, and rests on data that already exists: minimal contract cost, high reversibility, zero migration. Defining the subject without the bundle is what lets a digest change invalidate a prior exception through an explicit `supersedes` while keeping `casefile`'s boundary intact. Not collapsing conflicts keeps ambiguity visible, consistent with the product corollary of traceable evidence and declared uncertainty. Surfacing anomalies instead of rejecting preserves the byte compatibility required by ADR-0030.

## Consequences and limits

History is conserved; validity is **derived**, never rewritten. `expired`/`superseded`/`pending` are not technical states: the consumer maps the absence of a candidate decision to layer 3 (`not_assessed`) without touching `product_status`/`exploitability`, and an `expired` record only means that record provides no current decision. The view does not authenticate references (a `superseded_by` hash is syntactic) and does not detect a truncated suffix, forks or substitution by another coherent book. Invalidations are declared, not inferred: the library never reads the referenced evidence to detect a digest, package or advisory change. A query by subject returns candidates that keep the full scope; the caller decides applicability, and an image change that yields a new UID stays outside the continuity edges. No persistence, retention, CLI or exports are delivered, and no exception-candidate label is emitted. Books admitted under ADR-0030 keep their bytes, admission and operation behaviour; the derived validity view is added by this record.

## Review conditions

Contract revision is required to infer invalidation from evidence (reading the bundle), add cross-book references, enterprise actor identity or automatic conflict resolution, or change the `standing`/`anomaly` vocabulary. Persistence, retention, authorization and operation get their own records (ADR-0019 / A3-06 / A3-07). Any change altering the bytes of already-admitted books requires a new version with explicit admission.
