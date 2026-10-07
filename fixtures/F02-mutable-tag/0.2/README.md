# F02 — mutable-tag

Fixture F02 of the synthetic fixture matrix, materialized for AX-04 as two
committed bundle-artifact triplets (`tag-vs-digest`, `tag-without-digest`) of a
findings import.

## Content

Each case directory holds the three wire artifacts of ADR-0006 §5. The bundles
are produced by the real import path (`ParsePrismaV1` → `Normalize` →
`Build` → `Encode`); the requested reference is composed from the CSV record
(ADR-0009), never from the binding.

- Constructors: `ax04BuildFI` in
  `internal/bundle/ax_04_fi_fixture_golden_test.go`, cases
  `tag-vs-digest` and `tag-without-digest`.
- `tag-vs-digest`: the record declares tag `release`; the caller binding
  declares a raw image id and a guaranteed digest. `requested_image`,
  `raw_image_id` and `normalized_digest` are three distinct, non-null fields.
- `tag-without-digest`: the record declares tag `latest`; the binding declares
  **no** raw and **no** digest. `requested_image` is present; `raw_image_id`
  and `normalized_digest` are **null as produced by production**, and the
  platform is `unknown`.

## Expected outcome

A requested tag alone is never content identity: the nulls are produced by the
projection, not pre-set by the test. A tag is never promoted to a verified
digest.

## Limits

No registry resolution and no proof of the deployed manifest digest. Every
identifier, hash and timestamp is fabricated.
