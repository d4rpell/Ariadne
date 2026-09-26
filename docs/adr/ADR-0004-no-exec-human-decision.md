# ADR-0004 — No `pods/exec`, no AI in the decision path, exceptions are human

- **Status**: accepted (2026-09-23)
- **Decision owner**: project owner

## Decision

1. **No `pods/exec`.** Evidence comes from sanitized exports. The **planned** optional read-only collector is designed to use only `get`/`list` on explicit resources within an allowlist of namespaces; it does not exist yet, and no read-only guarantee is claimed for it here. Any future runtime probing requires its own decision record, an exact allowlist of reviewed checks and treatment as a mutating operation.
2. **No AI in the decision path.** Language models may at most assist in drafting report prose offline; they never compute statuses, never decide exceptions and never generate commands to run against a cluster.
3. **The exception is a human decision.** `risk_decision` (owner, approver, rationale, compensating controls, expiry) is a layer separate from technical status. The legacy `EXCEPCIONABLE` label survives only as a derived governance view, never as a technical state and never as automatic approval.

## Context

The original manual flow this project replaces used per-CVE scripts that executed phases inside pods through a jump host and returned single operational labels. Two problems followed from it:

- `pods/exec` is not a read-only operation: it allows file modification, package installation, network access and data exposure, and it normally requires a `create` permission rather than a read permission.
- A single label collapses three different questions — is the artifact affected? are the exploitation conditions met here? who accepts the residual risk? — and mixing them makes the result neither technically accurate nor auditable.

## Options considered

1. Keep in-pod probing for richer evidence. Discarded: mutating operations in production, an unacceptable permission footprint, and a false sense of certainty.
2. Use a model to classify findings or draft decisions. Discarded: not reproducible, not auditable, and not architecturally authorised on a critical path.
3. Outside-only evidence with an explicit human decision layer — chosen.

## Why this was the best at the time

- It is what makes the tool defensible in front of a security committee: the design requires every conclusion to be reproducible and every acceptance to carry a responsible person and an expiry date.
- It removes an entire class of risk — executing code in production pods — at the cost of coverage that is declared as `unknown` instead of being faked.
- Separating the three layers is what allows the same technical evidence to be re-evaluated when the risk appetite or the exposure changes, without rewriting the technical assessment.

## Consequences and limits

- Less automatic coverage at first: the interior of a container is not observed, so the technical status is limited to what is demonstrable from outside.
- A failed step, a missing binary or an unobserved import is **insufficient evidence** → `unknown`/`under investigation`, never `not affected`.
- The design makes validity a system property rather than a manual task: a changed digest, UID, package, advisory or scope is intended to invalidate the previous decision, with re-opening handled by the record itself and not left to an analyst remembering to re-check. **This invalidation logic is not implemented yet.**

## Revisit if

A requirement appears that genuinely needs in-pod observation; it would need its own record with an exact check allowlist, prior approval and explicit treatment as a mutating operation.
