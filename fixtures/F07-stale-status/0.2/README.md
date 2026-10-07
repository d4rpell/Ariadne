# F07 — stale-status

Fixture F07 of the synthetic fixture matrix, materialized for AX-04 as one
committed bundle-artifact triplet (`reread-uid-changed`) of a container
observation.

## Content

The case directory holds the three wire artifacts of ADR-0006 §5, produced by
the real pipeline.

- Constructor: the `ax04COCases` list in
  `internal/bundle/ax_04_co_fixture_golden_test.go`, case `reread-uid-changed`.
- One capture at `2026-09-30T11:00:00Z` of a Pod whose UID is `uid-0002` and
  whose `resourceVersion` is `rv-8` (the re-read, distinct from a previous
  capture with another UID).

## Expected outcome

The capture keeps its own UID, its own `resourceVersion` and its own
`observed_at`; no evidence is mixed with a previous capture of another UID.

## Limits

This is the **observable slice** of F07. Real stale-status detection (the
bounded status-tuple pattern) is accredited by `TestA202F07` in
`internal/collector`, not by this artifact; there is no re-read monitor and no
temporal diff here. Every identifier, hash and timestamp is fabricated.
