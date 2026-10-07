# F04 — multiarch

Fixture F04 of the synthetic fixture matrix, materialized for AX-04 as one
committed bundle-artifact triplet (`no-accredited-manifest`) of a findings
import.

## Content

The case directory holds the three wire artifacts of ADR-0006 §5, produced by
the real import path.

- Constructor: `ax04BuildFI` in
  `internal/bundle/ax_04_fi_fixture_golden_test.go`, case
  `no-accredited-manifest`.
- The record declares tag `release`; the caller binding declares a raw image id
  whose reference the available method does **not** accredit as a manifest of
  the observed platform, and **no** guaranteed digest.

## Expected outcome

The reference is preserved as `raw_image_id` and **never** promoted:
`normalized_digest` is null and the platform is `unknown`. The predicate is
observable — a reference without an accredited manifest of the observed
platform is not promoted — and is **not** a claim about the digest class: the
syntax of a digest does not prove that it identifies an index.

## Limits

No OCI query and no digest-class attestation. The test does not distinguish an
index from a manifest; it accredits only the non-promotion under this method
and these input conditions. Every identifier, hash and timestamp is
fabricated.
