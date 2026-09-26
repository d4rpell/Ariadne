# Decision records

This directory is the **public decision record of Ariadne**. Every decision that shapes the product — scope, architecture, contracts, security limits, data semantics and process — is written down here, with the alternatives that were considered and the reasons the chosen option was the best available at that moment.

It exists for three audiences:

- **Users and reviewers** who need to know why the tool behaves the way it does, not only what it does.
- **Technical due diligence**: a decision without its alternatives and its trade-offs is an opinion, not a decision.
- **Future maintainers** who need to judge whether the conditions that justified a decision still hold.

**Ariadne is pre-alpha.** These records document the decisions taken; they are not a description of shipped functionality. Where a decision concerns something that does not exist yet, the record says so explicitly, and a decision that *reduces* what the tool claims is recorded here just like any other.

## How to read a record

Each record follows the same template:

| Section | Content |
|---|---|
| Status | `accepted`, `superseded` or `withdrawn`, and the date |
| Decision | What was decided, in one or two sentences |
| Context | The problem, the constraints and the evidence available at the time |
| Options considered | Every realistic option, including the discarded ones |
| Why this was the best at the time | The reasoning: cost, risk, reversibility, fit with the constraints |
| Consequences and limits | What the decision buys, what it costs, and what it deliberately does *not* guarantee |
| Revisit if | The facts that would justify revisiting the decision |
| Normative detail | Where the full contract lives, when there is one beyond this summary |

Two rules apply to every record:

1. **A decision is never edited in silence.** If something changes, a new record supersedes the old one and says so; the previous record keeps its date and its original reasoning.
2. **Limits are stated, not hidden.** If a decision means the tool cannot claim something, the record says so explicitly.

## Index

| Record | Decision | Status |
|---|---|---|
| [ADR-0001](ADR-0001-project-name.md) | Project name: Ariadne | accepted (2026-09-23) |
| [ADR-0002](ADR-0002-evidence-first.md) | Evidence-first: post-processor, not scanner or exploiter | accepted (2026-09-23) |
| [ADR-0003](ADR-0003-go-offline-deterministic.md) | Go, offline, deterministic, single binary | accepted (2026-09-23) |
| [ADR-0004](ADR-0004-no-exec-human-decision.md) | No `pods/exec`, no AI in the decision path, exceptions are human | accepted (2026-09-23) |
| [ADR-0005](ADR-0005-apache-2-license.md) | License: Apache-2.0 | accepted (2026-09-23) |
| [ADR-0006](ADR-0006-evidence-bundle-wire-contract.md) | Evidence bundle wire contract, canonical form and hash | accepted (2026-09-24) |
| [ADR-0007](ADR-0007-prisma-v1-schema-and-limits.md) | `prisma-v1` input schema and hard limits | accepted (2026-09-25) |
| [ADR-0008](ADR-0008-prisma-v1-lexical-precisions.md) | `prisma-v1` lexical and accounting precisions | accepted (2026-09-25) |
| [ADR-0009](ADR-0009-requested-image-and-platform.md) | Requested image composition and platform carrier | accepted (2026-09-25) |
| [ADR-0010](ADR-0010-provenance-scope-and-digest-class.md) | Provenance boundary, container scope collision, digest class | accepted (2026-09-25) |
| [ADR-0011](ADR-0011-decision-record-policy.md) | Two-layer decision record: what, alternatives, why, limits, revisit conditions | accepted (2026-09-25) |

## Adding a record

1. Copy the template above into `ADR-NNNN-short-slug.md`, continuing the numbering.
2. Fill every section. "Options considered" and "Why this was the best at the time" are mandatory: a record without them is not accepted.
3. Add the row to the index.
4. If the record changes a contract (evidence schema, decision states, security limits, privilege boundaries), the change needs its own record — it is never folded into an existing one.
