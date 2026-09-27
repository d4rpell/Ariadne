# F09 — unmapped-redhat-package

Fixture F09 of the synthetic fixture matrix: the presence of a package in a
findings import never demonstrates `affected`, `fixed` or `not_affected` while
the product-to-component mapping is missing. No product, release or architecture
may be inferred from the package name or from a version string.

## Content

- `input/bundle.json`: canonical Bundle `0.2` envelope of a complete findings
  import for one synthetic subject (`uid-F09`, container `app`), with the
  declared finding row, the container observation (image id, normalized digest,
  platform) and an artifact inspection group. There is no `domain.mapping`
  group and no vendor proof.
- `input/findings.csv`, `input/pods.json`, `input/inspection.json`: complete
  synthetic transcriptions of the sources the bundle references by SHA-256.
  Each transcription carries the facts attributed to it: the CSV is one
  canonical prisma-v1 record (the `requested_image` is its ADR-0009 composition
  from the declared image columns), `pods.json` is a sanitized list whose
  `items[0].status.containerStatuses[0]` carries the observed image id and
  platform, and `inspection.json` is the package inspection record. Every
  evidence item is contrasted with the exact field of the record its locator
  resolves to: a CSV locator is the absolute byte interval of the record in the
  stream (ADR-0008) and a JSON locator resolves to the record that must state
  the value. `TestProductFixtures` fails if a source is replaced or if a fact is
  attributed to a record that does not state it: the file digest, the item
  `source_hash` and the resolved field are all checked. The bundle is
  the only machine-consumed authority; the transcriptions exist so the hashes
  are reproducible and the facts auditable.
- `input/pack.json`: declarative pack, schema `0.1`, profile
  `product-evidence-v1`, one affirmative rule `rule.affected` with the eleven
  minimum requirements and the `redhat_build_affected` terminal.
- `input/target.json`, `input/admission-context.json`,
  `input/domain-context.json`: the evaluation target, the admission policy and
  the domain policy (age limit and the source pins of the sources that exist).
- `expected/bundle.json`, `expected/bundle.hash-input.json`,
  `expected/bundle.sha256`: the three wire artifacts of ADR-0006 §5, recomputed
  for Bundle `0.2`. They must match the input envelope byte for byte.
- `expected/expectations.json`: semantic test expectations consumed only by
  `TestProductFixtures`. They are not a public serialization of the result.

## Expected outcome

The evaluation returns `under_investigation`. The rule stops at
`missing_evidence` with `domain.mapping`, `domain.artifact` and
`domain.vendor_proof` missing, and no candidate is published. The pinned
artifact source has no pertinent candidate while the mapping is absent, which is
reported as `domain_source_unapproved`: per ADR-0015 §7.1 a pin without a
candidate is a gap, never a silent satisfaction. `exploitability` stays
`not_assessed`; no severity or risk conclusion is drawn.

## Limits

Every identifier, hash, timestamp, package and digest is fabricated. The
`advisory`-shaped artifacts of this matrix describe synthetic vendor behavior
only: this fixture does not represent any real Red Hat advisory, product or
customer environment, and passing it does not demonstrate support for any real
vendor feed.
