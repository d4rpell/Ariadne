# F15 — digest-invalidates-exception

Fixture F15 of the synthetic fixture matrix, materialized for AX-04 as two
committed bundle-artifact triplets (`digest-a`, `digest-b`) of a findings
import plus one committed casefile book (`exception-book`).

## Content

- Bundle half: `digest-a` and `digest-b` hold the three wire artifacts of
  ADR-0006 §5 for the **same** subject and container, differing only in the
  observed digest (`sha256:aaaa…` vs `sha256:bbbb…`). Constructor:
  `ax04F15Build` in `internal/bundle/ax_04_f15_fixture_golden_test.go`.
- Casefile half: `exception-book/book.json` is a `casefile` book with one
  `accepted` decision scoped to `bundle_hash` = the digest of `digest-a` and a
  future `expires_at`. Its bytes were produced by an independent Python oracle
  that recomputed the record preimage and its SHA-256 from the canonical format
  of ADR-0030 §4, not by the Go package.
- `exception-book/expected.json` pins the two bundle digests, the `as_of`
  instant, the effective candidate count and the record hash. The two halves
  meet through these committed literals.

## Expected outcome

The two bundles carry different digests. The decision's `Scope.BundleHash`
equals A's digest and differs from B's, so the decision **does not apply** to
the new bundle. `Assess` returns exactly one effective candidate, scoped to A.

## Limits

- The decision is **scoped** to A and does not apply to B; this is not a
  consumer-side rejection.
- `SubjectOf` excludes the bundle hash, so `Assess` does **not** return zero
  candidates for B — asserting that would be false.
- Automatic invalidation by digest does **not** exist in `casefile`; the
  declared invalidation via `supersedes` is accredited by the
  `casefile-supersedes` vector (A3-02) and is cited, not duplicated.
- The bundle↔book link is documentary (`bundle_hash`): the book does not open
  the bundle and does not verify that it exists. Every identifier, hash and
  timestamp is fabricated.
