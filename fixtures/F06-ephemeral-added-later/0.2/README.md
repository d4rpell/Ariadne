# F06 — ephemeral-added-later

Fixture F06 of the synthetic fixture matrix, materialized for AX-04 as two
committed bundle-artifact triplets (`first-empty`, `second-added`) of container
observations.

## Content

Each case directory holds the three wire artifacts of ADR-0006 §5, produced by
the real pipeline.

- Constructors: the `ax04COCases` list in
  `internal/bundle/ax_04_co_fixture_golden_test.go`.
- `first-empty`: one capture whose `ephemeralContainers` is **explicitly
  empty**. The ephemeral category is observed as an empty array.
- `second-added`: a later capture (observed at `2026-09-30T14:00:00Z`) that
  adds an ephemeral container `debug` with its status. Its `source_hash` and
  `observed_at` are its own, distinct from the first capture.

## Expected outcome

The first capture accredits an observed, empty ephemeral category — **not** the
absence of ephemeral containers in the future. The second capture incorporates
the ephemeral container with its observed image id.

## Limits

This is the **observable slice** of F06 only. There is no monitor, no diff and
no persisted timeline; the first capture proves nothing about the future. Every
identifier, hash and timestamp is fabricated.
