# F05 — init-and-sidecar

Fixture F05 of the synthetic fixture matrix, materialized for AX-04 as three
committed bundle-artifact triplets (`three-classes`, `sidecar-is-regular`,
`collision-refused`) of container observations.

## Content

Each case directory holds the three wire artifacts of ADR-0006 §5, produced by
the real pipeline (parse → normalize → build → Encode).

- Constructors: the `ax04COCases` list in
  `internal/bundle/ax_04_co_fixture_golden_test.go`.
- `three-classes`: one regular container `api`, one init container `init-setup`
  and an ephemeral category observed **explicitly empty**.
  `observed_container_classes` lists the three categories and the init
  container is bound to its own status.
- `sidecar-is-regular`: two **regular** containers with distinct names (`api`,
  `sidecar`). There is no `sidecar` class in the vocabulary: both are regular.
- `collision-refused`: the same container name in two classes cannot be
  distinguished by the wire scope, so the collided key is omitted visibly
  (`bundle: scope collision omitted`), completeness drops to `partial`, and the
  healthy container of the subject survives.

## Expected outcome

Regular, init and ephemeral are separate scopes; an explicitly empty category is
an observed category, not an absent one; a name colliding across classes is
refused without merging.

## Limits

No `sidecar` enum and no merging of classes. Every identifier, hash and
timestamp is fabricated.
