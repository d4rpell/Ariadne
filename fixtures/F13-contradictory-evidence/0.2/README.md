# F13 — contradictory-evidence

Fixture F13 of the synthetic fixture matrix: two valid, applicable vendor proofs
that sustain incompatible states block every affirmative publication. Contradictory
and uninterpretable warnings block as well; a known informational warning alone
does not. Duplicated records and permuted evidence order never change the
semantic result.

## Content

- `input/bundle.json`: canonical Bundle `0.2` envelope of a complete findings
  import for one synthetic subject (`uid-F13`, container `app`), with the
  complete declared finding row (the fifteen columns of the canonical record
  plus the composed `requested_image`), the container observation, the mapping
  group, the artifact inspection group and two applicable vendor proofs of the
  same exact build: one `vulnerable_build` and one `fixed_build`. The
  `proof_kind` item of each proof carries one warning: a known contradictory one
  (`source_conflict`) and one with an unknown code, which is uninterpretable
  for this schema version.
- `input/findings.csv`, `input/pods.json`, `input/mapping.json`,
  `input/inspection.json`, `input/advisory.json`: complete synthetic
  transcriptions of the referenced sources. Every item is contrasted with the
  exact field of the record its locator names, and the sibling proof records show
  why the contradiction is real: `records/proof/0` states a `vulnerable_build`
  and `records/proof/1` a `fixed_build` for the same subject.
  `TestProductFixtures` fails if a source is replaced, if a fact is attributed to
  a record that does not state it or if a `value_hash` does not cover the value
  the record states: the digest of the file, the item `source_hash`, the resolved
  field and the hash preimage are checked.
- `input/pack.json`: declarative pack, schema `0.1`, profile
  `product-evidence-v1`, with three rules: `rule.affected` (terminal
  `redhat_build_affected`, emits `affected`), `rule.fixed` (terminal
  `redhat_build_fixed`, emits `fixed`) and `rule.shortcut`, a branch without a
  terminal that emits `under_investigation` and therefore can never publish.
- `input/target.json`, `input/admission-context.json`,
  `input/domain-context.json`: the evaluation target, the admission policy and
  the domain policy pinning exactly the three sources.
- `expected/bundle.json`, `expected/bundle.hash-input.json`,
  `expected/bundle.sha256`: the three wire artifacts of ADR-0006 §5, recomputed
  for Bundle `0.2`.
- `expected/expectations.json`: semantic test expectations consumed only by
  `TestProductFixtures`.

## Expected outcome

The evaluation returns `under_investigation` with the reasons
`affirmative_conflict`, `blocking_warning` and `conflicting_evidence`. Both
terminal rules run and pass, but their candidates sustain incompatible states,
so nothing is published; a rule is never resolved by order, majority or
recency. The branch without a terminal appears as `checked` but produces no
candidate. Two warning references are reported.

The harness derives three variants in memory: with a single `fixed_build`
proof, no warnings and only `rule.fixed`, the result is `fixed` with no
reasons; adding a known informational warning (`redaction_applied`) does not
block; duplicating the fixed proof byte for byte and reversing the evidence
order conserves the same semantic result while changing the canonical bytes and
therefore the bundle hash. These variants are not stored as files: the
committed hashes always match the committed inputs.

## Limits

Every identifier, hash, timestamp, package, advisory and warning is
fabricated. This fixture does not represent any real vendor advisory or customer
environment, and passing it does not demonstrate support for any real vendor
feed.
