# Decision records

This directory is the **public decision record of Ariadne**. Every decision that shapes the product — scope, architecture, contracts, security limits, data semantics and process — is written down here, with the alternatives that were considered and the reasons the chosen option was the best available at that moment.

It exists for three audiences:

- **Users and reviewers** who need to know why the tool behaves the way it does, not only what it does.
- **Technical due diligence**: a decision without its alternatives and its trade-offs is an opinion, not a decision.
- **Future maintainers** who need to judge whether the conditions that justified a decision still hold.

**Ariadne is pre-alpha.** These records document the decisions taken; they are not a description of shipped functionality. Where a decision concerns something that does not exist yet, the record says so explicitly, and a decision that *reduces* what the tool claims is recorded here just like any other.

Records retain dated rationale and implementation snapshots. A historical statement that a capability was absent or acceptance was pending (including older records such as ADR-0002 and ADR-0003) describes that record's stage unless a later dated status line supersedes it. The root README states the current shipped scope.

## How to read a record

Each record follows the same template:

| Section | Content |
|---|---|
| Status | `accepted`, `superseded` or `withdrawn`, and the date. A record may also appear as `proposed`: a written proposal pending review and ratification, not yet a decision |
| Decision | What was decided, in one or two sentences |
| Context | The problem, the constraints and the evidence available at the time |
| Options considered | Every realistic option, including the discarded ones |
| Why this was the best at the time | The reasoning: cost, risk, reversibility, fit with the constraints |
| Consequences and limits | What the decision buys, what it costs, and what it deliberately does *not* guarantee |
| Revisit if | The facts that would justify revisiting the decision |
| Normative detail | Where the full contract lives, when there is one beyond this summary |

Two rules apply to every record:

1. **A decision is never edited in silence.** If something changes, a new record supersedes the old one and says so; the previous record keeps its date and its original reasoning.
2. **Limits are stated, not hidden.** If a decision means the tool cannot claim something, the record says so explicitly.

## Index

| Record | Decision | Status |
|---|---|---|
| [ADR-0001](ADR-0001-project-name.md) | Project name: Ariadne | accepted (2026-09-23) |
| [ADR-0002](ADR-0002-evidence-first.md) | Evidence-first: post-processor, not scanner or exploiter | accepted (2026-09-23) |
| [ADR-0003](ADR-0003-go-offline-deterministic.md) | Go, offline, deterministic, single binary | accepted (2026-09-23) |
| [ADR-0004](ADR-0004-no-exec-human-decision.md) | No `pods/exec`, no AI in the decision path, exceptions are human | accepted (2026-09-23) |
| [ADR-0005](ADR-0005-apache-2-license.md) | License: Apache-2.0 | accepted (2026-09-23) |
| [ADR-0006](ADR-0006-evidence-bundle-wire-contract.md) | Evidence bundle wire contract, canonical form and hash | accepted (2026-09-24) |
| [ADR-0007](ADR-0007-prisma-v1-schema-and-limits.md) | `prisma-v1` input schema and hard limits | accepted (2026-09-25) |
| [ADR-0008](ADR-0008-prisma-v1-lexical-precisions.md) | `prisma-v1` lexical and accounting precisions | accepted (2026-09-25) |
| [ADR-0009](ADR-0009-requested-image-and-platform.md) | Requested image composition and platform carrier | accepted (2026-09-25) |
| [ADR-0010](ADR-0010-provenance-scope-and-digest-class.md) | Provenance boundary, container scope collision, digest class | accepted (2026-09-25) |
| [ADR-0011](ADR-0011-decision-record-policy.md) | Two-layer decision record: what, alternatives, why, limits, revisit conditions | accepted (2026-09-25) |
| [ADR-0012](ADR-0012-evidence-bundle-integration-precisions.md) | Evidence item mapping, value-hash preimage, source hash and omission semantics | accepted (2026-09-26) |
| [ADR-0013](ADR-0013-offline-evaluator-contract.md) | Conservative evaluator profile, pack admission and reproducibility | ratified (2026-09-26); implemented and accepted by owner (2026-09-27) |
| [ADR-0014](ADR-0014-static-import-closure.md) | Static closure of local production imports | ratified (2026-09-26); implemented and accepted by owner (2026-09-27) |
| [ADR-0015](ADR-0015-domain-contract-and-affirmative-evaluation.md) | Domain contract and affirmative product evaluation: profile, evidence families, conflict policy | ratified (2026-09-26); implemented and accepted by owner (2026-09-27) |
| [ADR-0016](ADR-0016-wire-versioning-and-product-vocabulary.md) | Wire versioning to `0.2` for the product vocabulary, digest-class claim and emission policy | ratified (2026-09-26); implemented and accepted by owner (2026-09-27) |
| [ADR-0017](ADR-0017-optional-governance-platform-and-timeline.md) | Optional governance platform, private-image evidence and append-only timeline | ratified (2026-09-26); not implemented |
| [ADR-0018](ADR-0018-domain-context-and-profile-recognition.md) | Domain context combinations and bounded profile recognition | accepted under delegated authority (2026-09-26); implemented and accepted by owner (2026-09-27) |
| [ADR-0019](ADR-0019-operating-modes-and-persistent-tracking.md) | Operating modes (occasional vs. tracking), temporal semantics, chart meaning, hot/warm/cold storage and external-policy export | proposed (2026-09-27); not implemented |
| [ADR-0020](ADR-0020-prisma-acquisition-and-vulnerability-data.md) | Optional Prisma Compute acquisition, richer vulnerability data and CVSS provenance, with the evaluator kept offline | proposed (2026-09-27); native deployed-image CSV and JSON offline before API selected (2026-09-28); not implemented |
| [ADR-0021](ADR-0021-lab-and-integration-validation.md) | Synthetic Kubernetes lab and evidence levels for integration validation | lab scope confirmed; technical design proposed (2026-09-27); not deployed |
| [ADR-0022](ADR-0022-json-and-html-report-contract.md) | JSON and HTML report contract: result-derived core plus bundle-verified evidence and warning catalogues | ratified by delegated authority (2026-09-28); implemented and accepted (2026-09-28); distribution of reports not authorized |
| [ADR-0023](ADR-0023-offline-cli-and-replay-contract.md) | Offline CLI subset, explicit IO, deterministic replay and test contract | ratified and accepted by the owner (2026-09-28); transport bounds and filesystem policy resolved; implemented and independently reviewed with no open finding (2026-09-28); task accepted by the owner (2026-09-28); distribution of reports and release not authorized |
| [ADR-0024](ADR-0024-public-repository-visibility.md) | Public repository visibility | accepted (2026-09-29); visibility verified separately |
| [ADR-0025](ADR-0025-sanitized-podlist-ingestion.md) | Offline ingestion of sanitized PodList exports: closed `sanitized-podlist-v1/1.0` profile, allowlist rejection, explicit coverage and termination | ratified and implemented (2026-09-30); independent review of the implementation closed with no open finding; distribution and release remain unauthorized |
| [ADR-0026](ADR-0026-optional-pod-collector.md) | Optional read-only Pod collector: closed Pod allowlist, standard-library REST client, fixed budgets and explicit provenance | ratified (2026-10-01); recommended decisions accepted; implemented and accepted (A2-02 F2, 2026-10-01); no compatibility claim |
| [ADR-0027](ADR-0027-native-prisma-report-ingestion.md) | Native offline ingestion of Prisma deployed-image reports (JSON documentary profile and candidate 39-column CSV): derived sanitized source, verifiable manifest and strict replay; bundle projection empty by contract | ratified (2026-10-02); contract independently reviewed with no open finding; offline adapters implemented and independently reviewed (`apto`, 2026-10-03); API connector implemented under [ADR-0028](ADR-0028-prisma-api-acquisition-connector.md) (2026-10-03) |
| [ADR-0028](ADR-0028-prisma-api-acquisition-connector.md) | Optional API acquisition connector for existing Prisma deployed-image reports: closed operation allowlist, in-memory credentials, offset pagination closing only on an empty page, fixed budgets, per-page delivery into the ratified offline admission with explicit `compute_api` provenance | ratified (2026-10-02, NE-N01..N07); implemented (A2-08-F2), independently reviewed (`apto`, 0 P0/P1/P2/P3) and published (2026-10-03); accepted by the owner (2026-10-03); real-service compatibility not verified |
| [ADR-0029](ADR-0029-prisma-registry-image-profile.md) | Offline Prisma Cloud Compute registry-image profile: separate `report_kind`, dedicated artifact family, a registry scan never proves deployment, empty bundle projection by contract, and one deferred input precision (the literal CSV header) | ratified (2026-10-03); registry JSON profile implemented, independently reviewed (`apto tras corregir`, 0 P0/0 P1) and published; registry CSV profile reserved indefinitely (ES-R1: no registry export available to the owner); compatibility not verified |
| [ADR-0030](ADR-0030-append-only-human-decision-records.md) | Offline append-only records of human risk decisions (`accepted`/`deferred`/`rejected`): canonical JSON with a per-record SHA-256 hash chain, full fail-closed verification, caller-supplied time, no technical states or derived verdicts, and declared limits of an unanchored chain | ratified and accepted by the owner (2026-10-04); implemented (A3-01), independently reviewed (`apto`, 0 P0/0 P1, 2 P2 to backlog) and published the same day |
| [ADR-0031](ADR-0031-case-record-validity-and-supersession.md) | Derived validity/invalidation view over the append-only decision records: a closed per-record `standing` (`effective`/`pending`/`expired`/`superseded`) at a caller-supplied instant, `supersedes` invalidation local to a decision subject (scope without bundle fields), inclusive expiry, visible conflicts as structural anomalies, and no format or byte change | ratified and accepted by the owner (2026-10-04); task A3-02; contract and implementation independently reviewed (`apto`), implemented and published the same day |
| [ADR-0032](ADR-0032-vex-and-sarif-exports.md) | OpenVEX and SARIF exports where the semantics fit: offline deterministic generation from an evaluation result, identity `status` mapping, no synthesized VEX justification, opaque local product identifier, constant SARIF `level` with local extensions in a namespaced property bag, and distribution not authorized | ratified and accepted by the owner (2026-10-05); task A3-03; implemented (`internal/interop`), independently reviewed (`apto`, 0 P0/0 P1) and published the same day (2026-10-05) |
| [ADR-0033](ADR-0033-bundle-signing-separate-evolution.md) | Bundle signing evaluated as a separate evolution: recommended direction is a detached signature over the exact hashable projection bytes, offline fail-closed verification with a caller-supplied trust anchor, no wire or state change in this decision, and implementation gated behind a future ADR; a signature attests key control, not origin authenticity, and does not authorize distribution | proposed (2026-10-05); task A3-05; independently reviewed (`apto`, 0 P0/0 P1) and published the same day; owner ratification pending; no implementation |

## Adding a record

1. Copy the template above into `ADR-NNNN-short-slug.md`, continuing the numbering.
2. Fill every section. "Options considered" and "Why this was the best at the time" are mandatory: a record without them is not accepted.
3. Add the row to the index.
4. If the record changes a contract (evidence schema, decision states, security limits, privilege boundaries), the change needs its own record — it is never folded into an existing one.
