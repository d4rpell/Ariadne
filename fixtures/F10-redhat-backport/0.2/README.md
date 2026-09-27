# F10 — redhat-backport

Fixture F10 of the synthetic fixture matrix: an installed version that looks old
against the upstream fix does not prove affectedness. A backported fix ships an
old upstream version with the vulnerability already removed, so only an exact
vendor proof bound to the observed build may conclude `fixed`.

## Content

- `input/bundle.json`: canonical Bundle `0.2` envelope of a complete findings
  import for one synthetic subject (`uid-F10`, container `app`), with the
  complete declared finding row (the fifteen columns of the canonical record —
  installed version `1.2.3-1`, severity `low` — plus the composed
  `requested_image`), the container observation, the mapping group, the artifact
  inspection group (version `1.2.3`) and one exact `fixed_build` vendor proof
  bound to the observed digest.
- `input/findings.csv`, `input/pods.json`, `input/mapping.json`,
  `input/inspection.json`, `input/advisory.json`: complete synthetic
  transcriptions of the referenced sources; their SHA-256 hashes are the ones
  the bundle, the target and the domain pins carry. Every fact the bundle
  attributes to a source is present in that source under its locator: the CSV
  is one canonical prisma-v1 record, `pods.json` carries the observed image id
  and platform, and the mapping, inspection and advisory documents carry the
  records the domain items cite. Every item is contrasted with the exact field
  of the record its locator resolves to: a CSV locator is the absolute byte
  interval of the record in the stream (ADR-0008), and the support definition a
  proof's `basis_locator` names must exist and agree on the basis and the
  vulnerability. `TestProductFixtures` fails if a source is replaced, if a fact
  is attributed to a record that does not state it, if the locator does not name
  the carrier the item type declares, or if the collection does not match the
  item family: the digest of the file, the item `source_hash`, the resolved
  field and the hash preimage of the value are checked.
- `input/pack.json`: declarative pack, schema `0.1`, profile
  `product-evidence-v1`, one affirmative rule `rule.fixed` with the eleven
  minimum requirements and the `redhat_build_fixed` terminal.
- `input/target.json`, `input/admission-context.json`,
  `input/domain-context.json`: the evaluation target, the admission policy and
  the domain policy pinning exactly the three sources.
- `expected/bundle.json`, `expected/bundle.hash-input.json`,
  `expected/bundle.sha256`: the three wire artifacts of ADR-0006 §5, recomputed
  for Bundle `0.2`.
- `expected/expectations.json`: semantic test expectations consumed only by
  `TestProductFixtures`.

## Expected outcome

The evaluation returns `fixed` with one candidate (`rule.fixed`) and no global
reasons: the proof is applicable, complete, current and inside the pins. The
severity column of the finding is never consulted; `exploitability` stays
`not_assessed`, and `fixed` is never transformed into `not_affected`.

The harness derives, in memory and per identity link, four negatives: changing
the artifact digest, the mapping product release, the mapping package name or
the vendor proof version drops the result back to `under_investigation` with no
candidates. Each mutation recomputes the value hash and the bundle hash, so the
rejection is semantic and not a wire integrity error. These negatives are not
stored as files: the committed hashes always match the committed inputs.

## Limits

Every identifier, hash, timestamp, package and advisory is fabricated. This
fixture does not represent any real Red Hat advisory, backport or customer
environment, and passing it does not demonstrate support for any real vendor
feed.
