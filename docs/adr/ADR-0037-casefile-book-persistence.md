# ADR-0037: Casefile book persistence on disk (`book` and `append`)

- **Status**: proposed (2026-10-07). Task A3-11. Independent review and owner ratification pending.
- **Relation**: extends the ADR-0023 CLI surface with two commands and one error stage; no wire, state, budget or exit-code changes. Builds on ADR-0030 (casefile library), ADR-0031 (validity view), ADR-0034 (governance platform) and ADR-0036 (precedent for declared surface extensions).

## Decision

Two new offline subcommands persist a casefile book as exactly the canonical `casefile.Encode` bytes — no new fields, no second on-disk format:

- `ariadne book --out PATH` writes the canonical empty book (exclusive creation 0600) and prints `{"records":0}` on stdout.
- `ariadne append --casebook PATH --decision accepted|deferred|rejected --owner … --approver … --rationale … --bundle-hash H --subject-uid … --container-name … --container-class regular|init|ephemeral --vulnerability-id … --decided-at TS [--expires-at TS] [--supersedes H] [--result-fingerprint H] [--controls LIST] --out PATH` reads and verifies an existing book, appends exactly one declared decision, and writes the resulting book to a **new** file, printing `{"records":N,"head_hash":"sha256:…"}` only after the write completes.

**No file is ever overwritten**: every write creates a new file under the ratified filesystem policy (single route resolution, exclusive creation 0600, symlink/reparse/special rejection). Chaining appends means passing the previous append's output as the next `--casebook`.

## Context

`internal/casefile` (ADR-0030) is a pure library: until now nothing created or grew a book on disk, while the read-only dashboard (`serve`) requires one. The project is personal and non-commercial (2026-10-06 decision), so storage sub-decisions resolve to the simplest thing that use requires.

## Options considered

1. **Two commands, new file per write (chosen)** — reuses the reviewed read/write frontiers and the library's all-or-nothing `Verify`; keeps the append-only history out of the file being written.
2. **In-place rewrite** — rejected: breaks exclusive creation and, without atomic rename+fsync (out of ratified scope), a partial write would destroy the append-only history.
3. **One command with implicit create-or-append** — rejected: implicit filesystem behavior contradicts the closed argument grammar.
4. **Mutations through the platform server** — rejected: ADR-0034 keeps the platform read-only until a local authorization model exists.
5. **A second container format (JSONL, book directories)** — rejected: reintroduces exactly the format variety this task avoids.

## Why the chosen option was best

Smallest real cost: thin runners over primitives that already have goldens and contract tests; no dependencies, no wire change, no new exit codes. Risk posture: the append-only ledger is protected by construction. Reversible: if the platform later gains mutations, these commands remain compatible file-level producers.

## Consequences and limits

Buys: offline creation and growth of a hash-chained decision record servable by `serve`, with the same fail-closed profile as the rest of the CLI.

**Does not guarantee or provide**: authenticated actors (owners/approvers are operator declarations); existence or freshness of the referenced bundle (`--bundle-hash` is grammar-checked, not verified); atomicity across writes; in-place updates (never); retention, backup, encryption or multi-user (not applicable, 2026-10-06 decision); any clock (every instant is declared). A failed write may leave a partial file without a receipt; the previous file stays intact. Pre-alpha, verified on windows/amd64 only.

## Review conditions

Reopen if the platform gains a local authorization model with mutations; if in-place updates become necessary, a new ADR must specify an atomic replacement; any new on-disk field requires a new record.

## State

Proposed 2026-10-07; implementation under task A3-11.
