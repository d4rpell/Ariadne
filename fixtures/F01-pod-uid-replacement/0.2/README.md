# F01 — pod-uid-replacement

Fixture F01 of the synthetic fixture matrix, materialized for AX-04 as two
committed bundle-artifact triplets (`uid-a`, `uid-b`) of one document that
carries **two Pods sharing namespace/name with different UIDs**.

## Content

Each case directory holds the three wire artifacts of ADR-0006 §5
(`expected/bundle.json`, `expected/bundle.hash-input.json`,
`expected/bundle.sha256`). There is no `input/` directory: the bundles are
produced by the real pipeline (parse → normalize → build → Encode) over a
document built by the test.

- Constructor: `ax04F01Document` in
  `internal/bundle/ax_04_co_fixture_golden_test.go`; cases `uid-a` (subject
  index 0, uid `uid-0001`, container `api`) and `uid-b` (subject index 1, uid
  `uid-0002`, container `worker`).
- Scope: `container_observation`, one PodList with two Pods, terminated
  `finished`, namespace `payments`, both named `payments-api`.
- The conflict is declared because the document carries **two conflicting Pod
  identities**, not because a UID changed over time: both bundles raise
  `source_conflict` (class `contradictory`) and the
  `source contains conflicting Pod identity context` diagnostic.

## Expected outcome

Two separate bundles, each with its own UID, its own container and its own
evidence scope. Neither is merged and no order is read as chronology.

## Limits

Identity is by uid+container; there is no cluster re-read and no replacement
detection over time. Every identifier, hash and timestamp is fabricated; no
real cluster, customer or scanner data is involved.
