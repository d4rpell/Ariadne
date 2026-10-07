# ADR-0038: Validity diff over a casefile book (exception lifecycle)

- **Status:** ratified by the owner (2026-10-07; proposed 2026-10-07). Task A3-10. Implemented and independently reviewed (`apto`, 0 P0/0 P1).
- **Relation:** extends the ADR-0023 CLI surface with one new subcommand (`diff`); no wire, state, budget or exit-code changes to existing commands. Reuses the ADR-0031 derived validity view (`casefile.Assess`, task A3-02) without reimplementing it; follows the ADR-0037 command pattern (`book`/`append`) and ADR-0034 (`serve`) for reading one verified book and a declared instant. Supersedes no accepted record.

## Decision

A new offline subcommand:

- `ariadne diff --casebook PATH --since TIMESTAMP --as-of TIMESTAMP --out PATH` reads and verifies **one** casefile book, evaluates it at **two declared instants**, and writes to a new exclusive file (0600) a **deterministic JSON document** that makes each subject's validity change visible between `--since` and `--as-of`. A stdout receipt `{"subjects":N,"changed":M}` follows only after the document is fully written.

The comparison is a new **pure library function** `internal/casefile.Diff(book, since, asOf)` that reuses `Assess` at both instants and reads no clock, opens no path and uses no network or shell. The compared unit is each subject's **set of decisions in force** (all hashes with `Standing == effective` at that instant), not a representative: with ≥2 records in force no transition is lost. The change vocabulary is closed: `granted` (no decision in force → some), `reopened` (some decision in force → none), `revised` (a decision in force on both sides but with a **different set**; covers re-issuance and a digest change that alters the in-force set) and `unchanged` (same set, or both empty). `Diff` validates the book and both instants as `Assess` does and additionally requires `since <= as-of` (violation ⇒ `invalid_timestamp`, a branch unreachable from the CLI, whose grammar rejects it first). Validity is a **derived view**: `granted`/`reopened`/`revised` describe only the change of the in-force set, never a `product_status`, `exploitability`, `risk_decision` or an exception recommendation.

## Context

ADR-0023 deferred `diff` to phase 0.3. DoD criterion (7) was **partial** in the A1-09 audit: detection against a *declared* hash/fingerprint exists, but **no persistent exception lifecycle visible to a third party**. The validity semantics are already implemented and ratified in `internal/casefile.Assess` (ADR-0031, task A3-02): expiry via `expires_at`, invalidation via a `supersedes` local to one `Subject`, `Candidates` that does not collapse conflicts. What is missing is a surface that **shows the temporal transition**: which decision stops being in force, and when.

Reality of artifacts today: an evaluation `Result` is **not persisted** (ADR-0023: `evaluate` prints a receipt, `report` prints a presentation). The only durable decision state is the `casefile` book (`book`/`append`, ADR-0037), servable by `serve` (ADR-0034). The book is therefore the natural and sufficient material for a lifecycle `diff`.

## Options considered

1. **One book, two instants (chosen).** `Assess` applied to the same book at `since` and `asOf`. The only variant that makes the **temporal** transition visible (`expires_at` reached ⇒ `reopened`), which is the task's stated goal. Minimum new machinery: one read, two `Assess` calls, no second input format. Re-issuance is covered by the `declarations` list (records decided within `(since, as-of]`).
2. **Two books, one instant** (`case-prev/ case/`). Considered: the classic state diff, but with a single `--as-of` it does **not** show expiry by itself (time passing is not part of the comparison); it shows structural changes only. Deferred: comparing against the empty book is expressible by setting `--since` before any decision.
3. **Diff between two `Result`s (evaluation runs).** Rejected for the light version: it would require persisting or re-evaluating twice (bundle+context+pack per side) and a `Result` format that does not exist today; that is a separate persistence contract.
4. **Presentation-level diff (two JSON reports).** Rejected: reintroduces a report parser and compares presentation, not validity; couples the lifecycle to the report contract (ADR-0022).
5. **Applying/rewriting decisions from the diff.** Rejected: breaks append-only and collapses layers; `diff` only observes.

## Why the chosen option was best

Smallest real cost: one thin command and one pure function over already-reviewed primitives (`Assess`, `Verify`, R-02 `readInput`/`writeOutput`); no dependencies, no wire, no new exit codes (the error table does not grow). Goal coverage: `reopened` makes visible that a subject **loses every decision in force** (for example, `expires_at` reached) without asserting any technical state, and `revised` makes visible that the in-force set changed (re-issuance or digest change) without collapsing layers. Risk: `diff` is **read-only** on the book and output-only; it cannot corrupt the record. Reversible: the recorte is revocable; the same primitive admits the "two books" variant later without breaking the document (that would be a new contract).

## Consequences and limits

Buys: a **derived, pure and deterministic** view of the exception lifecycle (what was granted, what expired, what was replaced) between two instants, with the same fail-closed profile as the rest of the CLI (grammar before reading files; all-or-nothing `Verify`; receipt only after the write completes; exclusive creation 0600).

**Does not guarantee or provide**: the comparison is **retrospective over one history** — it does not reconstruct two runs or the knowledge available at each (a record added later with `decided_at <= since` appears in force at `since` too), and it does not detect bundle/`result_fingerprint` changes between runs; `granted`/`reopened`/`revised` describe only the change of the in-force set, never a `product_status`/`exploitability`/`risk_decision`; it does not distinguish the cause of `reopened` (expiry versus supersession with no effective successor); it compares the validity of **one** book at two instants (not two books, not two `Result`s); the decision↔bundle binding is documentary (`BundleHash`/`ResultFingerprint` are declared references; `diff` does not open the bundle); actors are operator declarations; no atomicity (a failure may leave a partial document **without a receipt**; the input book stays intact by construction); no scheduler, retention or decision rewriting (ADR-0034); `EXCEPCIONABLE` and any exception recommendation remain prohibited; subject order is first-appearance in the book (not lexicographic), because `casefile`'s stdlib-only allowlist forbids `sort`; pre-alpha, verified on windows/amd64 only.

## Review conditions

Reopen if comparing **two books** (or two evaluation runs with a persisted `Result`) becomes necessary — that needs a new contract (second input or `Result` format), never a silent edit. Any new output field that depends on the wire or on decision states requires a new record. If ADR-0034 fixes a timeline surface in the platform, `diff` is re-evaluated as a redundant or complementary CLI view. Ratification of the recorte is an owner act, not delegable.

## State

Ratified by the owner on 2026-10-07 (proposed the same day); implemented under task A3-10, independently reviewed (`apto`, 0 P0/0 P1) and published the same day.
