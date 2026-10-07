# ADR-0036: CLI `import` — the CSV-to-case pipeline, end to end

- **Status**: proposed (2026-10-07). Pending independent review (task A3-09) and owner ratification.
- **Task**: A3-09.
- **Relation**: refines ADR-0023 (the deferred `import`/`normalize` subset becomes "`import` implemented; `normalize` still deferred"); builds on the ratified evidence bundle, `prisma-v1` ingestion, image identity, bundle integration and CLI contracts (ADR-0006..0012, ADR-0023) and on the case-record records (ADR-0030/0031). No change to the `0.2` evidence bundle wire.

## Decision

The CLI gains an **`import` subcommand**: a complete offline pipeline —
findings CSV (`prisma-v1`, the only admitted schema) plus an explicit bindings
document plus a caller-declared observation instant — that produces a canonical
`0.2` evidence bundle (the three artifacts written to disk with exclusive
0600 creation) and a stdout receipt. The normalization step runs inside
`import`; **`normalize` remains a known, rejected keyword** (deferred), and
`diff` stays deferred (task A3-10). Findings only: the observation sources
(sanitized PodList, collector, native Prisma adapters) remain library-only.
`import` never writes casefile books; the correspondence between a produced
bundle and a future decision record is documented, not automated.

## Context

ADR-0023 deferred `import`/`normalize` until an entry/binding/persistence
contract existed, and A1-09 recorded the resulting limit: the full pipeline
(fixture → bundle → evaluate → report) was not demonstrable with the binary
alone. Every library piece already exists and is reviewed: the strict
`prisma-v1` parser, conservative normalization whose finding-to-container
link is always an explicit caller binding (findings carry no workload
identity), the canonical bundle projection with per-item provenance, and the
evaluator and reports. What is missing is exactly the piece that builds a
bundle from a terminal: the input surface, the operator-declared binding, and
artifact persistence under the ratified filesystem policy. The residual DoD
criterion (an end-to-end demo a third party can run) requires it.

## Options considered

1. **Full pipeline in `import` (chosen)**: CSV + bindings → bundle in one
   command, no persistent intermediate formats.
2. **Two commands chained by a persistent intermediate format**: rejected —
   ADR-0023 already ruled it out ("no persistent intermediate formats"), and a
   new intermediate document would be wire without value.
3. **`import` that only validates CSV**: rejected — "validating CSV without
   producing a case would be a different utility from the promised pipeline"
   (ADR-0023).
4. **Inline flag bindings** (one observation per flag group): rejected — does
   not scale to several containers or per-finding indices and bloats the
   grammar.
5. **Binding documents for every source family**: rejected for now — each
   admission profile has its own context shape; generalizing would be a new
   ingestion contract (reversible cut).

## Why the chosen option was the best at the time

- **Closes the residual DoD criterion with the minimum**: one new command,
  zero new persistence formats (the artifacts are the already-published `0.2`
  bundle), zero new wire fields, zero new exit codes.
- **Preserves every layer's purity**: the binding stays an explicit caller
  instruction (never inferred), identity stays uid + class + name, provenance
  stays mandatory per fact, and the human decision layer is untouched
  (`import` writes no books).
- **Reuses the ratified rigor**: the ADR-0023 grammar and filesystem policy
  (single path resolution, exclusive 0600 creation, no overwrite), fail-closed
  budgets, a closed error table extended with new stages but no new exit codes.
- **Reversible**: the cut (findings only; `normalize` deferred) can be reopened
  by a later precision without touching the wire.

## Consequences and limits

**Buys**: the fixture → bundle → evaluate → report pipeline is demonstrable
end to end with the binary alone (residual DoD criterion); third parties can
build canonical bundles without writing Go.

**Does not guarantee / declared limits**:

- Bundle quality is the quality of its declared inputs: the bindings document
  is an operator declaration; its provenance labels do not authenticate origin.
- A `partial` bundle with visible diagnostics is a valid result, not a
  failure; an observed negative is not a universal absence.
- No new conformance claim against any external validator; bundle distribution
  remains unauthorized (ADR-0022).
- Findings `prisma-v1` only; other sources remain library-only.
- `normalize` and `diff` stay deferred; no scheduler, no persistent tracking
  (ADR-0034).
- No atomicity across the three artifact writes (a partial delivery is
  possible, never announced as complete, and the stdout receipt is only
  emitted after all three writes succeed); windows/amd64 only; the aggregate
  `make check` gate is not executable on the maintainer's PC (no `make`
  installed) — local verification is executed step by step with the same
  commands.

## Review conditions

- If an observation source needs CLI bindings, reopen with a precision or an
  ingestion ADR.
- If the receipt or the frozen run metadata need new fields, that is a
  contract change (precision of this record or a new one).
- If casefile persistence (A3-11) needs binding fields on the casefile wire,
  that is A3-11's record, not this one.
