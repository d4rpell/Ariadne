# A1-08 fixture coverage index

Where each fixture of the synthetic matrix (F01–F15) and each null variant
(N1–N4) is accredited in the A1-08 suites: the tests that pin it, the data it
uses, and the effective limit of that accreditation. Fixtures are synthetic
throughout; no real cluster, vendor feed or customer environment is involved.

AX-04 (2026-10-07) materialized the invariants that previously had only
programmatic coverage as committed golden artifacts: F01–F07 (group A, under
`fixtures/F0X-*/0.2/<case>/expected/`), F14 (group B, pack vectors under
`fixtures/F14-expired-or-tampered-rule/0.2/`) and F15 (group C, bundle pair plus
a `casefile` book under `fixtures/F15-digest-invalidates-exception/0.2/`). The
AX-04 suites are `TestAX04COFixtureGoldens` and `TestAX04COFixtureInventory`
(`internal/bundle/ax_04_co_fixture_golden_test.go`), `TestAX04FIFixtureGoldens`
(`internal/bundle/ax_04_fi_fixture_golden_test.go`), `TestAX04F15DigestPair`
(`internal/bundle/ax_04_f15_fixture_golden_test.go`), `TestAX04F14FixtureVectors`
(`internal/rulepack/ax_04_f14_fixture_golden_test.go`) and
`TestAX04F15ExceptionBook` (`internal/casefile/ax_04_f15_fixture_golden_test.go`).
Each fixture README documents its own input, expected outcome and limits.

| Fixture | Accredited by | Data | Effective limit |
|---|---|---|---|
| F01 `pod-uid-replacement` | `TestA108IdentityMatrix`, `TestA108Bindings`, `TestA108ProvenanceIsolation`; `TestAX04COFixtureGoldens/uid-a`,`uid-b` | Programmatic synthetic bundles + 2 committed triplets (`F01-pod-uid-replacement/0.2/`) | Identity by uid+container; no cluster re-read or replacement detection. The conflict is declared because one document carries two conflicting Pod identities, not by UID change over time |
| F02 `mutable-tag` | `TestA108IdentityMatrix`, `TestA108DigestReplay`; `TestAX04FIFixtureGoldens/tag-vs-digest`,`tag-without-digest` | Programmatic synthetic bundles + 2 committed triplets (`F02-mutable-tag/0.2/`) | requested/raw/digest kept separate; the nulls are produced by production; no registry resolution |
| F03 `unparseable-image-id` | `TestA108IdentityMatrix`; `TestAX04FIFixtureGoldens/opaque-raw` | Programmatic synthetic bundles + 1 committed triplet (`F03-unparseable-image-id/0.2/`) | Opaque raw conserved verbatim, digest null produced by production; no universal image-ID parser; predicate limited to this method and these inputs |
| F04 `multiarch` | `TestA108IdentityMatrix`; `TestAX04FIFixtureGoldens/no-accredited-manifest` | Programmatic synthetic bundles + 1 committed triplet (`F04-multiarch/0.2/`) | A reference without an accredited manifest of the observed platform is never promoted; **not** a claim about digest class (an index is not distinguished from a manifest); no OCI query |
| F05 `init-and-sidecar` | `TestA108BundlePartition`, `TestBuildThreeClassCollision`, `TestBuildScopeCollisionKeepsOtherContainers`, `TestScopeCollisionsReportsThreeClassesOnce`, `TestResolveContainerClassesDoNotMerge`, `TestNormalizeSeparatesContainerClasses`; `TestAX04COFixtureGoldens/three-classes`,`sidecar-is-regular`,`collision-refused` | Programmatic synthetic bundles + 3 committed triplets (`F05-init-and-sidecar/0.2/`) | Regular, init and ephemeral are separate scopes; a name colliding across classes is refused visibly in all six permutations, keeps the healthy container of the subject and degrades completeness to `partial`; no `sidecar` enum |
| F06 `ephemeral-added-later` | Partial: container classes are separate scopes and a collision across them is refused (`TestResolveContainerClassesDoNotMerge`, `TestNormalizeSeparatesContainerClasses`, `TestBuildThreeClassCollision`); an import accredits no observed class (`TestBuildImportIsNotInventory`); `TestAX04COFixtureGoldens/first-empty`,`second-added` | Programmatic synthetic bundles + 2 committed triplets (`F06-ephemeral-added-later/0.2/`) | **The observable slice only:** the first capture accredits an explicitly empty ephemeral category and the second incorporates the ephemeral container with its status; a first observation never accredits future absence; no monitor, no diff and no persisted timeline |
| F07 `stale-status` | `TestDomainEvidenceAge`, `TestProductExpirySeparation`; `TestA202F07` (bounded status-tuple pattern, `internal/collector`); `TestAX04COFixtureGoldens/reread-uid-changed` | Programmatic synthetic contexts + 1 committed triplet (`F07-stale-status/0.2/`) | The committed artifact accredits only the observable slice (own UID, own `resourceVersion`, own `observed_at`, no crossed evidence); real stale detection is `TestA202F07`, not this artifact; no TTL inference from text and no re-read monitor |
| F08 `partial-list-get` | `TestA108IncompleteEvidence`, `TestA108BundlePartition`; artifacts in `F08-partial-list-get/0.2/` (N1 `owner-null`, N3 `image-optionals-null`) | Programmatic constructor `a108NullVariant` + two committed triplets | Completeness `partial`/`unknown` never affirmative; no real list/get |
| F09 `unmapped-redhat-package` | `TestProductFixtures` | `F09-unmapped-redhat-package/` (full input + expected + expectations) | Missing mapping stays `under_investigation`; no product inference |
| F10 `redhat-backport` | `TestProductFixtures` | `F10-redhat-backport/` (full input + expected + expectations) | Exact-build proof required for `fixed`; no general EVR/OVAL comparator |
| F11 `malformed-csv` | `TestA108ParserHeaders`, `TestA108ParserText`, `TestA108ParserStructure`, `TestA108ParserLexicalValues`, `TestA108ParserInertValues`, `TestA108ParserAccounting`, `TestA108CSVLimits`; artifacts in `F11-malformed-csv/0.2/` (N2 `ruleset-null`) | Real parser on programmatic cases + one committed triplet | Parser fail-closed and bounded; no `import` command or native-CSV claim |
| F12 `partial-source-failure` | `TestA108IncompleteEvidence`, `TestA108RequiredLinks`, `TestA108PresentationOmissions`; artifacts in `F12-partial-source-failure/0.2/` (N4 `run-start-only`, `run-end-only`, `run-neither`, `run-both`) | Programmatic tests + four committed triplets | Static diagnostics and omissions; no universal secret sanitizer |
| F13 `contradictory-evidence` | `TestProductFixtures` | `F13-contradictory-evidence/` (full input + expected + expectations) | Conflicts block every affirmative publication; never resolved by order/majority |
| F14 `expired-or-tampered-rule` | `TestA108DomainAdmissionMatrix`, `TestA108AdmissionFailures`, `TestA108PackValidity`, `TestA108PackLimits`, `TestA108AllDiagnosticBytes`; `TestAX04F14FixtureVectors` | Programmatic packs and CLI diagnostics + 5 committed pack vectors (`F14-expired-or-tampered-rule/0.2/`: `base` admitted control, `expired`, `wrong-hash`, `downgrade`, `forbidden-field`) | Expiry, pin, downgrade and vocabulary refusal fail-closed with their exact typed code; the golden is a **rejection** golden (adapted format); no payload execution, no isolation and no general detection of executable code |
| F15 `digest-invalidates-exception` | `TestA108DigestReplay`, binary replay harness (`cmd/ariadne/binary_test.go`); `TestAX04F15DigestPair` (bundle half) + `TestAX04F15ExceptionBook` (casefile half) | Programmatic bundle pairs + 2 committed bundle triplets and 1 committed `casefile` book (`F15-digest-invalidates-exception/0.2/`) | Replay-transfer substitute only; the decision is **scoped** to A's digest and does not apply to B — not a consumer-side rejection; `Assess` does not return zero candidates for B (`SubjectOf` excludes the bundle hash); automatic invalidation by digest does not exist (`supersedes` is A3-02, cited); lifecycle/append-only record excluded |
| N1 owner null | `TestA108CanonicalNullVariants`, `TestA108GoldenNullVariants` | `F08-partial-list-get/0.2/owner-null/` | `owner_chain:null` pinned in envelope and projection |
| N2 ruleset null | `TestA108CanonicalNullVariants`, `TestA108GoldenNullVariants` | `F11-malformed-csv/0.2/ruleset-null/` | Valid bundle; canonicalization never tested with an invalid CSV |
| N3 image optionals null | `TestA108CanonicalNullVariants`, `TestA108GoldenNullVariants` | `F08-partial-list-get/0.2/image-optionals-null/` | Optionals null and platform `unknown` with container identity conserved |
| N4 run timestamps | `TestA108CanonicalNullVariants`, `TestA108GoldenNullVariants` | `F12-partial-source-failure/0.2/run-*/` | Four combinations; timestamps excluded from the projection; `observed_at` stays mandatory |

Numerical limits of every layer (CSV ADR-0007/0008, packs ADR-0013, evaluator
model, CLI transport R-01 of ADR-0023) are pinned by `TestA108CSVLimits`,
`TestA108PackLimits`, `TestA108EvaluatorLimits` and
`TestA108TransportLimits` with N−1/N/N+1 per budget; they are not re-declared
by any fixture README.

The committed artifact triplets are consumed by
`TestA108GoldenNullVariants` (`internal/bundle/a1_08_golden_test.go`), which
rebuilds each hash-input projection from the committed envelope and recomputes
the SHA-256 digest independently. Golden regeneration is never automatic; the
committed bytes are the contract.
