# F14 — expired-or-tampered-rule

Fixture F14 of the synthetic fixture matrix, materialized for AX-04 as five
committed pack vectors: one admitted control (`base`) and four rejections
(`expired`, `wrong-hash`, `downgrade`, `forbidden-field`).

## Content

Each case directory holds `pack.json` (the frozen pack bytes) and
`expected.json` (the frozen admission context and the expected typed error
code). This is a **golden of rejection**: A0-04 §2 defines a bundle golden and
F14 has no bundle, so the format is adapted explicitly.

- Consumer: `TestAX04F14FixtureVectors` in
  `internal/rulepack/ax_04_f14_fixture_golden_test.go`.
- `expected.json` freezes the entry point (`Admit`), the evaluation instant, the
  pinned pack id, the minimum version, the SHA-256 of the pack bytes and the
  expected `rulepack.ErrorCode`.
- Each rejection vector differs from `base` **only** in the condition under
  test; the pack hash in the context is recomputed independently with
  `crypto/sha256`, so it always matches the committed bytes except in
  `wrong-hash`, where the mismatch is the subject.

| Vector | Varied condition | Expected code |
|---|---|---|
| `base` | none | admitted (positive control) |
| `expired` | `expires_at` before the evaluation instant | `pack_expired` |
| `wrong-hash` | the pinned digest disagrees with the bytes | `pack_hash_mismatch` |
| `downgrade` | the context demands a higher minimum version | `pack_downgrade` |
| `forbidden-field` | a key outside the declared grammar (`executable`) | `invalid_pack` |

## Expected outcome

The base pack is admitted. Every rejection carries its **exact typed code**, and
repairing the single varied condition admits a pack again, so the rejection is
attributed to that condition and not to an earlier phase.

## Limits

The forbidden field is an inert datum refused by the closed grammar: this does
**not** demonstrate isolation (that is the import contract test) and no general
detection of executable code. Every identifier and timestamp is fabricated.
