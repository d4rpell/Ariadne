# ADR-0032: OpenVEX and SARIF exports where the semantics fit

- **Status:** ratified by the owner and accepted (2026-10-05). Implemented as `internal/interop` and independently reviewed the same day (contract, handoff and delta each closed with no open P0/P1). Contract and implementation files are published as of 2026-10-05 with owner authorization.

> **Distribution clause superseded (2026-10-08):** the statement that distribution of the reports, bundles or exported documents is “not authorized” was withdrawn from the product presentation and from the current-state documentation by [ADR-0039](ADR-0039-state-label-and-distribution-scope.md). The rationale and dated text below are retained as history; the security and accuracy limits of this record still stand.
- **Scope:** task A3-03; new package `internal/interop` (twelfth root of the import gate).
- **Relationships:** applies [ADR-0004](ADR-0004-no-exec-human-decision.md) (no hidden clock), [ADR-0011](ADR-0011-decision-record-policy.md) (two-layer record policy) and the deterministic-presentation model of [ADR-0022](ADR-0022-json-and-html-report-contract.md), including its **no-authorized-distribution** rule. Reuses the rigor of evidence-bundle wire `0.2` without changing it. Coexists with [ADR-0017](ADR-0017-optional-governance-platform-and-timeline.md) and the still-open export question of [ADR-0019](ADR-0019-operating-modes-and-persistent-tracking.md). Supersedes no accepted record.

## Proposed decision

Add an **offline, deterministic, byte-for-byte** generation of two interoperability documents from an already-computed evaluation result and the canonical bundle whose projection hash the result carries:

- **OpenVEX v0.2.0:** a document with a **single** statement (the result is scoped to one target). `status` is an **identity mapping** of the closed product vocabulary (`affected`/`not_affected`/`fixed`/`under_investigation`), where `unknown` is already reopened as `under_investigation`. `justification` is **never** emitted — Ariadne cannot attribute a machine-readable justification it does not carry. `not_affected` is satisfied with an inert `impact_statement` and `affected` with an inert `action_statement`. The product identity is a **local, opaque URN** (never a purl or CPE). `@id`, `author` and `timestamp` are supplied by the caller, because the evaluation instant is a replay parameter, **not** an issuance date; the canonical-UTC form of that timestamp is an Ariadne policy, not an OpenVEX requirement.
- **SARIF v2.1.0:** a log with one run; `driver.name = "Ariadne"`, `driver.version` = engine version; `rules` are the rules referenced by sustained candidates (unique, ASCII order); one result **per candidate**; `level` is the constant `note` (**not** severity); the local extensions (`product_status`, `exploitability`, profile, bundle hash) go into the **namespaced property bag** `properties.ariadne`; no timestamps and no `locations`.

Neither export re-evaluates, reads the bundle beyond the hash contrast, opens a path, reaches the network or executes a process.

## Context

The architecture fixes the VEX semantics and its limits: `unknown`→`under_investigation` is an internal mapping; `not_affected` requires bounded affirmative evidence; and `exploitability`, `risk_decision`, `valid_until`, `invalidated_at` and `supersedes` are **local Ariadne extensions**, not fields of the standard. ADR-0022 scoped the report to JSON/HTML, deferred VEX/SARIF, and declared report **distribution not authorized**. The evaluation result exists and is deterministic; what was missing is the contract for the interoperability surface, with the explicit risk of "attributing to the standard fields it does not have".

## Options considered

| Option | Assessment |
| --- | --- |
| Emit VEX/SARIF from the existing report package | Rejected: ADR-0022 scopes that surface to JSON/HTML; mixing contracts complicates review and versioning. |
| A dedicated package with its own import-gate root | **Recommended:** independent contract and boundary; offline and network-free. |
| Map the internal `not_affected` reason to a `justification` label | Rejected: the result does not carry the reason, so it would assert a fact Ariadne does not prove. An inert `impact_statement` is used instead. |
| Place `exploitability`/`risk_decision` as VEX fields | Rejected: they are not standard fields. Omitted in VEX; placed in the `ariadne` property bag in SARIF. |
| Product identity by purl/CPE | Rejected: Ariadne holds no product purl in the result and does not fabricate one; an opaque local URN avoids leaking cluster identifiers. |
| SARIF `level` derived from product status | Rejected: it would assert severity the result does not carry. Constant `note`; real state in the property bag. |
| SARIF results per checked rule | Rejected: SARIF reports sustained findings; one result per candidate. |
| VEX `timestamp` fixed to the evaluation instant | Rejected: that instant is a replay parameter, not an issuance date; the caller supplies it. |

## Why this was the best option at the time

The export introduces no privileges, network or clock, and rests on data that already exists: minimal contract cost, high reversibility, zero migration. Keeping the standard fields pure and moving local data into the standard extension mechanism — or omitting it — is the only way to avoid the overstatement the architecture forbids. An explicit caller-supplied issuer respects the no-hidden-clock rule. A dedicated boundary mirroring the report package preserves the offline guarantee verified in CI.

## Consequences and limits

Generation is defined; **distribution of the exported documents is not authorized**. Neither VEX nor SARIF proves the correctness of a conclusion — they present it in a standard format. The OpenVEX product identifier is local and opaque (not a purl/CPE, not mappable without Ariadne); the human-readable view stays in the JSON report under its own access policy. `not_affected` is exported without a machine-readable justification; mapping the internal reason to one requires a future domain contract. The SARIF `level` is not severity; the real state travels in `properties.ariadne`. Byte-for-byte conformance against official OpenVEX/SARIF validators is not accredited by this record. No CLI, no persistence, no lifecycle; verification is single-platform (windows/amd64).

## Review conditions

Contract revision is required if the domain contract starts carrying the VEX justification, a public product identifier is required, a SARIF consumer requires per-rule results, official-validator conformance is decided, or distribution is authorized (ADR-0022 / ADR-0019 open question).
