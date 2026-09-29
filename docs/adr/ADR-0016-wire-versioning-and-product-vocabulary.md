# ADR-0016 — Wire versioning and product vocabulary

- **Status**: **ratified by the owner on 2026-09-26; implemented and accepted by the owner on 2026-09-27**. `0.2` is emitted and accepted by the repository (`pkg/evidence`, `internal/bundle`, `internal/rulepack`, `internal/evaluator`); the frozen `0.1` vectors stay frozen. Nothing is activated, distributed or released, and Ariadne remains pre-alpha. This record alone does not authorize activation, distribution, commits or pushes.
- **Decision owner**: project owner.
- **Independent review**: the record was reviewed before ratification; the review found no blocking findings and the corrections it requested are applied.
- **Emission policy**: general `0.2` emission, selected by the owner on 2026-09-26 and ratified with this record.

**Ariadne is pre-alpha.** This record fixes a contract; it does not describe shipped functionality or authorize implementation, activation of `0.2`, distribution, commits or pushes. It does not ratify the affirmative domain contract, which requires a separate decision. The sections below were written while the decision was a proposal; a sentence in the proposal tense states what was decided, not pending work.

## Decision

Introduce the exact `product_v1.*` evidence vocabulary through a **MINOR bundle schema increment from `0.1` to `0.2`**, preserving the existing scalar representation and wire rules. The updated reader would accept `0.1` and `0.2`, and the updated producer would emit all new bundles as `0.2`, including ordinary imports, without downgrade or automatic migration.

### Vocabulary and digest class

The catalogue contains 59 names in three families. Each name is the prefix in the table followed by one listed suffix; matching a prefix does not register additional names.

The exact grammar is `product_v1.<family>.<field>`, where `family` is exactly `mapping`, `artifact` or `vendor`, and `field` matches `[a-z][a-z0-9_]{0,31}` — lowercase ASCII, one to 32 bytes, starting with a letter. The full name is ASCII and at most 52 bytes. There is no wildcard: a name is registered only by appearing in the table below, and no prefix match, longer name or variant spelling extends the catalogue.

| Prefix and use | Exact suffixes |
|---|---|
| `product_v1.mapping.` (14) | `method`, `coverage`, `vulnerability_id`, `scanner_package_type`, `scanner_package_name`, `scanner_package_id`, `vendor`, `product_id`, `product_release`, `os`, `architecture`, `component_id`, `package_name`, `package_arch` |
| `product_v1.artifact.` (15) | `method`, `coverage`, `artifact_digest`, `digest_kind`, `vendor`, `product_id`, `product_release`, `os`, `architecture`, `component_id`, `package_name`, `package_arch`, `epoch`, `version`, `package_release` |
| `product_v1.vendor.` common fields (21) | `method`, `coverage`, `vulnerability_id`, `advisory_id`, `advisory_revision`, `vendor`, `product_id`, `product_release`, `os`, `architecture`, `component_id`, `package_name`, `package_arch`, `epoch`, `version`, `package_release`, `source_status_vocabulary`, `source_status_value`, `proof_kind`, `basis_id`, `basis_locator` |
| `product_v1.vendor.` additions for `vulnerable_build` (2) | `vulnerable_code_id`, `applicability` |
| `product_v1.vendor.` additions for `fixed_build` (3) | `fixed_code_id`, `fix_id`, `fix_membership` |
| `product_v1.vendor.` additions for `code_excluded_build` (4) | `excluded_code_id`, `build_id`, `exclusion`, `exclusion_coverage` |

Mapping records express an explicit scanner-to-product/component correspondence; artifact records express inspection of the exact build; vendor records express support for the exact build and vulnerability. Their complete source, joining, validity and evaluation requirements belong to the separate domain contract. This catalogue does not approve those requirements or deliver producers for them.

`product_v1.artifact.digest_kind=platform_manifest` is a **scalar digest-class claim with per-item provenance**, not a new JSON member. It requires producer support: the class cannot be inferred from SHA-256, OS or architecture. The artifact digest must match an independently established `normalized_digest`; this claim neither fills nor changes that field. An index digest or an ambiguous class does not satisfy the claim, and an index is never promoted to a platform manifest.

### Preserved contract

The proposal changes no structure, keys, wire enums, projection function or exclusions, canonicalization, `value_hash` preimage, completeness rule or wire warning policy. Value hashes remain hashes of the exact UTF-8 value bytes. Auxiliary evidence does not turn a complete findings import into a complete inventory. Product status, exploitability and human risk decisions remain separate.

The existing import vocabulary keeps its meaning. The bundle increment does not change the `prisma-v1` input schema, its evidence values or the rule-pack schema. The evidence-item type remains an open string at the transport layer; this proposal does not impose a universal product-catalogue allowlist or silently tighten validation of historical bundles. The separate product profile must recognize its evidence explicitly; transport acceptance alone grants no affirmative authority.

### Readers and emission

| Reader | Valid `0.1` bundle | Valid `0.2` bundle |
|---|---|---|
| Reader supporting `0.1` | Accepts under the original contract | Rejects by version, fail-closed |
| Updated reader supporting `0.1` and `0.2` | Accepts under the original contract | Accepts under the new contract |

Rejection of a future minor version is expected under ADR-0006; it does not by itself require a MAJOR increment. Unknown versions, future minors and other majors remain rejected. Version incompatibility is not a technical `not_affected` result. Existing acceptance of `0.0` is preserved as historical behavior; this record creates no new `0.0` contract and does not authorize removing that acceptance.

The owner's selected emission policy is **general `0.2` emission**, including imports with no product evidence. Since `schema_version` belongs to the hashed projection, rebuilding a bundle from the same import data after the transition changes its bundle hash. Individual `value_hash` values remain unchanged when their values do not change. The hash algorithm and projection function stay the same; their input bytes change.

Historical bundles remain unchanged and verifiable under their original version. There is no automatic migration, negotiated downgrade or affirmative reinterpretation of `0.1` by the proposed product profile. Rebuilding evidence explicitly produces a new bundle, not a revision of the old artifact or permission to copy its conclusions.

## Context

The proposed product vocabulary needs to express mapping, artifact inspection and vendor evidence, including digest class. An open string carrier can transport new names, but that does not exempt their contractual meaning from versioning. ADR-0012 requires a new record and schema increment for new evidence types or vocabulary; ADR-0010 requires the same for digest-class representation. ADR-0006 assigns MINOR increments to compatible additions.

The addition preserves existing representations and meanings, so the versioning obligations can be met without structural changes. Available evidence is limited to the proposed contract and synthetic cases; no real producer or deployment compatibility is established. External consumers and their update costs have not been inventoried.

## Options considered

| Option | Outcome and trade-off |
|---|---|
| MINOR `0.2` with scalar evidence, including digest class | Proposed choice. Makes the vocabulary version explicit while preserving existing semantics; requires updated readers and versioned vectors. |
| Add a structural digest-class field | Discarded. Adds keys, projection and validation changes without a demonstrated need, with a risk of duplicate representations. |
| Remove `digest_kind` | Not chosen. Loses explicit class evidence while the remaining vocabulary still requires a schema increment. |
| Keep `0.1` and version the catalogue separately | Discarded under the current contracts. Would require an explicit exception, its own integrity and admission rules, and replacement of existing versioning obligations. |
| Keep `0.1` and suspend affirmative scope | Valid but not selected. Reduces immediate technical cost at the cost of delaying the capability. |
| Use a separate, linked evidence contract | Discarded. Adds versioning, hashing, admission and replay obligations; an external document is not an integrity shortcut. |
| MAJOR increment without a structural or semantic break | Discarded. No incompatible change has been identified that justifies the additional coordination. |
| Negotiate capabilities or projection per bundle | Discarded. Introduces selectors and multiple interpretations instead of one projection per version. |
| Dual emission: ordinary imports as `0.1`, product bundles as `0.2` | Discarded in favor of general `0.2` emission. Preserves older import consumers but requires two emission paths and a version choice for each construction. |

## Why this was the best at the time

The MINOR increment meets the existing versioning obligations while retaining scalar evidence, the canonical form and the projection. It avoids both an unsupported no-bump exception and the cost of structural redesign. Historical `0.1` artifacts remain usable without rewriting their hashes.

General emission provides one output path and avoids accidentally labelling product evidence as `0.1`. In pre-alpha, no external consumers have been inventoried; their population and measured upgrade costs remain unknown. The choice is justified under that uncertainty, not by a claim that consumers do not exist. It can be reconsidered before activation; after emission, reversing course cannot silently renumber artifacts or rewrite their hashes.

## Consequences and limits

- Consumers receiving new bundles must support `0.2`, even for ordinary imports. Bundle hashes are not preserved across the version change.
- Historical `0.1` vectors must remain, with separate `0.2` vectors. Activation and distribution require reconciliation, independent review and ratification of the catalogue and domain contract, verified implementation, and published specifications and vectors for each version.
- Digest-class evidence satisfies ADR-0010's requirement for a new record and schema increment only within the proposed `0.2` representation, once ratified. It does not establish the real-source use case or support that remains to be demonstrated.
- A bundle hash supports integrity against trusted expected inputs; it does not authenticate an origin or prove that sources are sufficient, exhaustive or current. An open carrier cannot retroactively prevent a nonconforming producer from mislabelling new evidence as `0.1`.
- **Not guaranteed:** authenticity of origin, material sufficiency of sources, support for real sources or adapters, EVR range or OVAL coverage, real Red Hat/OpenShift compatibility, immutability of the runtime filesystem, migrations, performance or interoperability with uninspected consumers. Synthetic cases do not establish real deployment support.
- This versioning proposal does not ratify affirmative predicates, source producers, validity periods, conflict rules or resource budgets. Incomplete or contradictory evidence remains uncertainty, never a favorable conclusion by default.

## Revisit if

Revisit the proposal if a structural field, projection, canonical rule, enum or wire warning policy must change; the catalogue or a type's meaning changes; affirmative interpretation under `0.1` becomes a requirement; historical version acceptance or canonical bytes regress; identified consumers cannot update at an acceptable cost; or validators, vectors and specifications disagree.

A first real producer or accredited corpus, insufficient digest-class support, or a requirement for migration, signatures, external evidence, mixed methods or a public evaluation wire contract also requires reconsideration. Before ratification, changes remain explicit amendments to the proposal. After acceptance, contract changes require a new record with an explicit supersession relationship.

## Relationships and normative detail

This proposal depends on [ADR-0006](ADR-0006-evidence-bundle-wire-contract.md), [ADR-0010](ADR-0010-provenance-scope-and-digest-class.md) and [ADR-0012](ADR-0012-evidence-bundle-integration-precisions.md). Once ratified, it would supersede only the supported-minor ceiling for the updated reader in ADR-0006 and the absence of a digest-class representation in ADR-0010 for `0.2`. Their general rules and historical `0.1` contracts remain intact; no supersession takes effect while this record is proposed.

[ADR-0013](ADR-0013-offline-evaluator-contract.md) remains unchanged: the `evidence-readiness-v1` profile retains its inconclusive results and gains no affirmative authority from product items. Bundle schema `0.2` does not imply rule-pack schema `0.2`.

This public record states the proposed versioning scope and exact catalogue. A complete public specification and versioned vectors remain prerequisites to distribution; this summary does not claim that they have been delivered. The separate affirmative domain decision still requires its own ratification.
