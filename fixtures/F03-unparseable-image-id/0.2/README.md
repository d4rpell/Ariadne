# F03 — unparseable-image-id

Fixture F03 of the synthetic fixture matrix, materialized for AX-04 as one
committed bundle-artifact triplet (`opaque-raw`) of a findings import.

## Content

The case directory holds the three wire artifacts of ADR-0006 §5, produced by
the real import path.

- Constructor: `ax04BuildFI` in
  `internal/bundle/ax_04_fi_fixture_golden_test.go`, case `opaque-raw`.
- The record declares tag `release`; the caller binding declares a raw image id
  that is **not** a digest (`ref:opaque-identifier`) and **no** guaranteed
  digest.

## Expected outcome

The opaque raw identifier is preserved **verbatim** as `raw_image_id`; no
digest is promoted and the platform stays `unknown`. The null
`normalized_digest` is produced by production, not pre-set by the test.

## Limits

The test accredits conservation of an opaque identifier; it does not
accredit any universal image-ID parser and no registry resolution. The
observable predicate is limited to this method and these input conditions.
Every identifier, hash and timestamp is fabricated.
