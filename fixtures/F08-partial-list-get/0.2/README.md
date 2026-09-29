# F08 — partial-list-get

Fixture F08 of the synthetic fixture matrix, materialized for A1-08 F3 as two
committed bundle-artifact triplets (`owner-null`, `image-optionals-null`) of
the N1–N4 null-variant series. The partial/unknown completeness behaviour of
F08 itself is accredited programmatically (a synthetic container-observation
bundle with progress, abort and error becomes `partial`; unknown coverage stays
valid as `unknown`; neither ever publishes an affirmative state).

## Content

Each case directory holds only the three wire artifacts of ADR-0006 §5
(`expected/bundle.json`, `expected/bundle.hash-input.json`,
`expected/bundle.sha256`). There is no `input/` directory: the bundles are
produced by explicit Go constructors, not captured from any source.

- Constructor: `a108NullVariant` in `internal/bundle/a1_08_test.go`, case name
  equal to the directory name, over the one-row synthetic findings import
  (`CVE-2024-1234`, package `openssl`, `registry.example/payments/api:release`).
- Method and scope: `findings_import`, one synthetic subject
  (`cluster-a` / `payments` / `Pod` / `payments-api-7f4d`, uid `pod-uid-1`),
  container `api` (class `regular`), observation source `sanitized-pods.json`
  with locator `items[3].status.containerStatuses[0].imageID`, proven platform
  digest, platform `linux/amd64`, observed at `2026-09-26T09:00:00Z`.
- `owner-null` (N1): `owner_chain` is explicit `null` in envelope and
  projection; the subject uid stays valid; no owner resolution is invented.
- `image-optionals-null` (N3): `requested_image`, `raw_image_id` and
  `normalized_digest` are simultaneously `null` and the platform is
  `unknown` with empty `os`/`architecture`, while the container identity
  (key, name, class, observation) is conserved.
- Expectation: `TestA108GoldenNullVariants` in `internal/bundle/a1_08_golden_test.go`
  rebuilds the hash-input projection from the committed envelope, recomputes
  the SHA-256 digest independently and pins the committed null of each case.

## Limits

The completeness values of these triplets are `complete`: the two unbound CSV
rows are omitted by the ratified partition without degrading completeness.
Nothing here performs a real `list`/`get`, and no fake collector output is
presented as production evidence. The F08 residual (real acquisition limits,
lifecycle) remains deferred. Every identifier, hash and timestamp is
fabricated; this fixture represents no real cluster or customer environment.
