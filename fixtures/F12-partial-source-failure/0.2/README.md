# F12 — partial-source-failure

Fixture F12 of the synthetic fixture matrix, materialized for A1-08 F3 as four
committed bundle-artifact triplets (`run-start-only`, `run-end-only`,
`run-neither`, `run-both`) of the N1–N4 null-variant series. The
partial-source-failure behaviour of F12 itself is accredited programmatically:
a failed reader, `unavailable` evidence, missing provenance, static
diagnostics and presentation omissions.

## Content

Each case directory holds only the three wire artifacts of ADR-0006 §5
(`expected/bundle.json`, `expected/bundle.hash-input.json`,
`expected/bundle.sha256`). There is no `input/` directory: the bundles are
produced by an explicit Go constructor, not captured from any source.

- Constructor: `a108NullVariant` in `internal/bundle/a1_08_test.go`, case name
  equal to the directory name, over the one-row synthetic findings import
  (`CVE-2024-1234`, package `openssl`, `registry.example/payments/api:release`).
- Method and scope: `findings_import`, one synthetic subject
  (`cluster-a` / `payments` / `Pod` / `payments-api-7f4d`, uid `pod-uid-1`),
  container `api` (class `regular`), full observation provenance, platform
  `linux/amd64`.
- N4, the four run-timestamp combinations with fixed instants
  (`2026-09-26T10:00:00Z` start, `2026-09-26T11:00:00Z` end when present):
  only start, only end, neither and both. Run timestamps are always explicit
  `null` in the envelope when absent, and both fields are excluded from the
  hash-input projection; the four committed projections are therefore
  byte-identical while the four envelopes differ.
- `observed_at` stays mandatory on every evidence item, including
  `unavailable` ones; that obligation is accredited in the evaluator tests,
  not by these artifacts.
- Expectation: `TestA108GoldenNullVariants` in `internal/bundle/a1_08_golden_test.go`
  rebuilds the projection from each committed envelope, recomputes the digest
  independently, pins each case's timestamp combination and fixes the shared
  projection of the four variants.

## Limits

No universal secret sanitizer exists and no redaction-before-persist
guarantee is demonstrated here; redaction markers are only proven where the
contract requires omitting them. Every identifier, hash and timestamp is
fabricated; this fixture represents no real source failure of any real system.
