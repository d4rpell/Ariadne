# F11 — malformed-csv

Fixture F11 of the synthetic fixture matrix, materialized for A1-08 F3 as one
committed bundle-artifact triplet (`ruleset-null`) of the N1–N4 null-variant
series. The malformed-CSV behaviour of F11 is accredited by the real parser in
the ingestion tests: headers, text encoding, structure, lexical values, inert
content, accounting and size limits.

## Content

The case directory holds only the three wire artifacts of ADR-0006 §5
(`expected/bundle.json`, `expected/bundle.hash-input.json`,
`expected/bundle.sha256`). There is no `input/` directory: the bundle is
produced by an explicit Go constructor, not captured from any source.

- Constructor: `a108NullVariant` in `internal/bundle/a1_08_test.go`, case
  `ruleset-null`, over the one-row synthetic findings import
  (`CVE-2024-1234`, package `openssl`, `registry.example/payments/api:release`).
- Method and scope: `findings_import`, one synthetic subject
  (`cluster-a` / `payments` / `Pod` / `payments-api-7f4d`, uid `pod-uid-1`),
  container `api` (class `regular`), full observation provenance, platform
  `linux/amd64`.
- N2: `ruleset` is explicit `null` in the envelope, and the hash-input
  projection reduces it to `null` as well. A valid bundle is used: canonical
  null handling is never tested with an invalid CSV.
- Expectation: `TestA108GoldenNullVariants` in `internal/bundle/a1_08_golden_test.go`
  rebuilds the projection from the committed envelope, recomputes the digest
  independently and pins the `ruleset:null` of this case.

## Limits

The malformed CSV and limit cases of this fixture live exclusively in the
ingestion tests (`internal/ingest/a1_08_*_test.go`); they are not re-frozen
here. There is no `import` command, no CSV/XLSX export and no claim that this
schema matches any native scanner CSV. Every identifier, hash and timestamp is
fabricated.
