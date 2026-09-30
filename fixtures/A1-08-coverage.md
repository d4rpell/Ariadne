# A1-08 fixture coverage index

Where each fixture of the synthetic matrix (F01–F15) and each null variant
(N1–N4) is accredited in the A1-08 suites: the tests that pin it, the data it
uses, and the effective limit of that accreditation. Fixtures are synthetic
throughout; no real cluster, vendor feed or customer environment is involved.

| Fixture | Accredited by | Data | Effective limit |
|---|---|---|---|
| F01 `pod-uid-replacement` | `TestA108IdentityMatrix`, `TestA108Bindings`, `TestA108ProvenanceIsolation` | Programmatic synthetic bundles | Identity by uid+container; no cluster re-read or replacement detection |
| F02 `mutable-tag` | `TestA108IdentityMatrix`, `TestA108DigestReplay` | Programmatic synthetic bundles | requested/raw/digest kept separate; no registry resolution |
| F03 `unparseable-image-id` | `TestA108IdentityMatrix` | Programmatic synthetic bundles | Opaque raw conserved; no universal image-ID parser |
| F04 `multiarch` | `TestA108IdentityMatrix` | Programmatic synthetic bundles | Index stays raw; no OCI query or digest-class attestation |
| F05 `init-and-sidecar` | `TestA108BundlePartition`, `TestBuildThreeClassCollision`, `TestBuildScopeCollisionKeepsOtherContainers`, `TestScopeCollisionsReportsThreeClassesOnce`, `TestResolveContainerClassesDoNotMerge`, `TestNormalizeSeparatesContainerClasses` | Programmatic synthetic bundles | Regular, init and ephemeral are separate scopes; a name colliding across classes is refused visibly in all six permutations, keeps the healthy container of the subject and degrades completeness to `partial`; no `sidecar` enum |
| F06 `ephemeral-added-later` | Partial: container classes are separate scopes and a collision across them is refused (`TestResolveContainerClassesDoNotMerge`, `TestNormalizeSeparatesContainerClasses`, `TestBuildThreeClassCollision`); an import accredits no observed class (`TestBuildImportIsNotInventory`) | Programmatic synthetic bundles | **The declared scenario — a later observation adding an ephemeral container — is not constructed by any committed test**; a first observation never accredits future absence; no monitor and no temporal diff |
| F07 `stale-status` | `TestDomainEvidenceAge`, `TestProductExpirySeparation` | Programmatic synthetic contexts | Future and expired observations stay inconclusive, including the exact boundaries; no TTL inference from text and no re-read detection; an old observation is not a genuinely delayed status |
| F08 `partial-list-get` | `TestA108IncompleteEvidence`, `TestA108BundlePartition`; artifacts in `F08-partial-list-get/0.2/` (N1 `owner-null`, N3 `image-optionals-null`) | Programmatic constructor `a108NullVariant` + two committed triplets | Completeness `partial`/`unknown` never affirmative; no real list/get |
| F09 `unmapped-redhat-package` | `TestProductFixtures` | `F09-unmapped-redhat-package/` (full input + expected + expectations) | Missing mapping stays `under_investigation`; no product inference |
| F10 `redhat-backport` | `TestProductFixtures` | `F10-redhat-backport/` (full input + expected + expectations) | Exact-build proof required for `fixed`; no general EVR/OVAL comparator |
| F11 `malformed-csv` | `TestA108ParserHeaders`, `TestA108ParserText`, `TestA108ParserStructure`, `TestA108ParserLexicalValues`, `TestA108ParserInertValues`, `TestA108ParserAccounting`, `TestA108CSVLimits`; artifacts in `F11-malformed-csv/0.2/` (N2 `ruleset-null`) | Real parser on programmatic cases + one committed triplet | Parser fail-closed and bounded; no `import` command or native-CSV claim |
| F12 `partial-source-failure` | `TestA108IncompleteEvidence`, `TestA108RequiredLinks`, `TestA108PresentationOmissions`; artifacts in `F12-partial-source-failure/0.2/` (N4 `run-start-only`, `run-end-only`, `run-neither`, `run-both`) | Programmatic tests + four committed triplets | Static diagnostics and omissions; no universal secret sanitizer |
| F13 `contradictory-evidence` | `TestProductFixtures` | `F13-contradictory-evidence/` (full input + expected + expectations) | Conflicts block every affirmative publication; never resolved by order/majority |
| F14 `expired-or-tampered-rule` | `TestA108DomainAdmissionMatrix`, `TestA108AdmissionFailures`, `TestA108PackValidity`, `TestA108PackLimits`, `TestA108AllDiagnosticBytes` | Programmatic packs and CLI diagnostics | Expiry, pin, downgrade and vocabulary refusal fail-closed; no payload execution |
| F15 `digest-invalidates-exception` | `TestA108DigestReplay`, binary replay harness (`cmd/ariadne/binary_test.go`) | Programmatic bundle pairs | Replay-transfer substitute only; lifecycle/append-only record excluded |
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
