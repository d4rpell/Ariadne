# Synthetic case

Runnable inputs for the offline CLI, built entirely from the synthetic fixtures
shipped in this repository. No cluster, scanner account, credential or network
access is involved, and every identifier, hash, timestamp, package and digest is
fabricated.

The walkthrough that uses these files is [`docs/quickstart.md`](../../docs/quickstart.md).

## Contents

| File | What it is |
|---|---|
| `f09.context.json` | The composed CLI context (`target` + `admission` + `domain`, ADR-0023 §4.2) for fixture `F09-unmapped-redhat-package` |
| `f10.context.json` | The composed context for fixture `F10-redhat-backport` |
| `f13.context.json` | The composed context for fixture `F13-contradictory-evidence` |
| `f09.receipt.json` | The exact stdout of `ariadne evaluate` for F09 |
| `f10.receipt.json` | The exact stdout of `ariadne evaluate` for F10 |
| `f13.receipt.json` | The exact stdout of `ariadne evaluate` for F13 |

The three fixtures carry their own bundles, packs and expected wire artifacts
under `fixtures/<name>/0.2/`; this directory does not duplicate them.

## Provenance and integrity

- Each `*.context.json` is the composition of the fixture’s `target.json`,
  `admission-context.json` and `domain-context.json`, with the optional members
  the fixture files omit (`previous`, `advisory_id`, `advisory_revision`)
  materialized as explicit `null` — the CLI context requires every field,
  nullable ones included — plus one final LF. The fixture files themselves are
  never modified.
- Each `*.receipt.json` is the byte-exact stdout of a real `evaluate`
  invocation over the corresponding fixture, produced by the built binary — not
  hand-written.
- `TestExampleContextsMatchFixtureComposition`, `TestExampleReceiptsAndReplay`
  and `TestExampleReportMatchesReviewedGolden` in `cmd/ariadne/example_test.go`
  anchor both properties: they recompose every context from the fixture inputs
  and compare it byte for byte with the files here, re-run `evaluate`, compare
  stdout byte for byte with the published receipt, re-run `verify` with the
  receipt’s fingerprint, and check that the F09 HTML report still matches the
  reviewed presentation golden.

## Limits

- The receipts bind the exact bytes of this bundle and this pack, and the
  context that produced them; the context file itself is not hash-bound. They do
  not authenticate origin, prove freshness or carry any signature.
- These files demonstrate the CLI over synthetic data; they do not demonstrate
  support for any real scanner export, vendor advisory or customer
  environment.
- Report and bundle distribution is not authorized in pre-alpha.
