# ADR-0026: Optional read-only Pod collector

- **Status:** ratified under delegated authority on 2026-10-01, after an independent review closed with no open finding (0 P0, 0 P1, 0 P2, 0 P3). **Implemented and accepted on 2026-10-01** (A2-02 F2: the `k8s-pod-read-v1/1.0` profile in `internal/collector` and the `BuildCollectedObservation` projection in `internal/bundle`, covered by synthetic contract, limit, golden and import-boundary tests; the implementation delta closed an independent review with `apto` — 0 P0, 0 P1, 0 P2, 0 P3 — and CI is green on `c9ad8f9`). The implementation has **not** been verified against a real cluster and carries no Kubernetes/OpenShift compatibility matrix (A2-09/A2-10); F07 remains the bounded pattern. This record authorizes no cluster access, no distribution and no release.
- **Related records:** develops ADR-0004 (no runtime probing), ADR-0006 (coverage by method), ADR-0009 (requested image and platform carrier), ADR-0010 (provenance, scope collision and digest class), ADR-0011 (two-layer decision records), ADR-0012 (bundle projection and value-hash preimage), ADR-0014 (static import closure) and ADR-0025 (sanitized PodList ingestion). No accepted record is superseded. Coordinates with ADR-0021 (validation lab) without authorizing its execution.

## Decision

Add an optional collector that acquires Pods exclusively through `get` and `list` inside an explicit namespace allowlist (one to sixteen namespaces, no wildcards, no default namespace), using a minimal REST client built on the Go standard library instead of a Kubernetes client library, with endpoint, TLS trust and credentials received explicitly in memory. Acquisition applies fixed budgets, keeps failures as incomplete observations, and projects API responses onto the sanitized PodList grammar through a parallel acquisition profile, `k8s-pod-read-v1/1.0`, feeding the existing admission, normalization, identity and bundle machinery through a dedicated collected-observation entry point. Wire version, decision states and evidence vocabulary do not change.

## Context

ADR-0025 covered operator-produced sanitized exports. The 0.2 milestone adds the optional in-cluster read path, the first network boundary in the project. It must not leak network privileges into the offline core (which is enforced by a static import-closure gate), must not treat an API response as complete evidence, and must not present an operator export as a live capture.

During the contract phase, an examination of `k8s.io/client-go` showed that its REST transport statically pulls in the `exec` authentication provider, which imports `os/exec`. Disabling that provider in configuration does not remove the import. The project's closure gate forbids `os/exec` in the relevant boundaries and its module profile currently rejects external module dependencies (`require`, `vendor`). Adopting the library would therefore require a new toolchain, module and gate decision before implementation. The independent review of this contract did not fetch the external sources of the cited library versions, so that transitive-import claim is documented, not independently verified by the reviewer.

## Options considered

1. **Kubernetes client library (`k8s.io/client-go`).** Rejected for this profile: its transitive `os/exec` import conflicts with the closure policy, and it would add the project's first external dependency and change the module and gate profile.
2. **Shelling out to `kubectl` or `oc`.** Rejected: process execution is outside the project boundary.
3. **Minimal standard-library REST client with scripted in-memory HTTP doubles for tests.** Chosen: keeps the closure free of process execution and the module without external dependencies; its cost is a self-maintained transport and response projector.
4. **Reusing the sanitized-export profile unchanged.** Rejected in favor of a parallel acquisition profile sharing the sanitized document grammar: live acquisition, pagination and provenance differ from an operator export, and the export profile stays intact.
5. **Automatic kubeconfig loading or in-cluster autodetection.** Rejected: credentials are received explicitly in memory only; file loading and environment detection remain outside this contract.
6. **Unlimited or caller-raised limits; automatic retries.** Rejected: fixed budgets and zero automatic retries in this profile.
7. **Watch-based observation.** Rejected: only `list` plus two read-back `get` rounds on the inventoried names; watch, mutation and subresources remain prohibited.

## Why this was the best choice now

The decision adds the first network boundary while preserving every property the project already relies on: the offline evaluator keeps no network client; identity stays tied to pod UID and container; requested and observed image fields stay apart; no digest or platform is promoted; incomplete acquisition never produces a favorable conclusion; and the accepted input profile is not weakened. It adds no wire vocabulary, no decision state and no external module dependency. Its costs are explicit: a self-maintained REST transport and response projector, a conservative profile that can yield partial bundles from ordinary API responses when container categories are omitted, and a deliberately narrow credential model.

## Consequences and limits

- Budgets bound the client. They do not guarantee that a remote operation stops when the client stops, nor the absence of remote effects.
- `get`/`list` without Secrets is not privacy by itself: pod responses can contain sensitive material in process memory. The collector's guarantee is limited to what it semantically uses and what it persists; no secure-erasure or universal secret-detection guarantee is offered.
- Hashes prove bundle integrity, not authenticity of origin or of the cluster.
- Completeness is relative to the method: omitted container categories remain unobserved, and a finished acquisition can still yield a partial bundle; the projection never fills the gap.
- A simulated transport proves program behavior, not Kubernetes RBAC enforcement or interoperability. A real-release compatibility matrix is a separate prerequisite owned by its own task, coordinated with the validation lab; this record establishes **no** Kubernetes or OpenShift compatibility claim.
- No watch, no mutation verbs, no subresources, no discovery and no runtime probing of any kind are authorized; any extension requires its own decision.
- No cluster access, no distribution of bundles or reports and no release are authorized by this record.

Conditions that would justify revisiting this record: needing another resource or verb; adopting a Kubernetes client library or any external dependency; adding file-loaded credentials, authentication plugins or further modalities; requiring HTTP/2, proxies, redirects or retries; measurements justifying different budgets; treating omitted categories as empty; independently proving digest or platform; persisting the acquisition plan or adding wire types; or an observed incompatibility with a real release.

## Revision conditions and history

The contract was independently reviewed before ratification: first pass `apto tras corregir` with three P2 findings — an ambiguous `Content-Encoding` acceptance rule, an undecided tie-break between the per-response and global byte budgets, and a mutation oracle that could not discriminate a specific defect — all corrected; a second directed pass returned `apto` with no open finding. Ratified under delegated authority on 2026-10-01. No implementation has been authorized.
