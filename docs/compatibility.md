# Compatibility — what has actually been verified

> **Ariadne has been verified against exactly one environment: a single-node synthetic Kubernetes 1.37.0 lab. No OpenShift release — and no other Kubernetes distribution, version or managed cloud — has been verified. "Not verified" below means exactly that: it is neither a claim of compatibility nor a claim of incompatibility.**

**Status:** MVP complete, offline. This page reports first-party experimental evidence gathered with the real Ariadne collector binary against a real API server, with synthetic fixtures only (no customer or production data). Every claim below is scoped to that exercise; the [README](../README.md) states what Ariadne is and deliberately is not, and [ADR-0026](adr/ADR-0026-optional-pod-collector.md) defines the collector contract these results exercised.

## How this was verified

- **Method:** the read-only pod collector (`k8s-pod-read-v1/1.0`, stdlib REST, bearer authentication, namespace allowlist, fixed budgets, no retries) executed a scripted procedure against the API server: positive acquisition over an allowed namespace, negative acquisition against a namespace the service account cannot read, RBAC probes, a pod recreation, budget consumption and a server-side pagination sweep.
- **Identity of the exercise** (all values observed, not assumed):

| Dimension | Observed value |
|---|---|
| Distribution | kind v0.33.0 (rootless Podman), single control-plane node |
| API server | Kubernetes v1.37.0 (`f54c212e…`), linux/arm64 |
| Node image | `kindest/node:v1.37.0`, multi-arch **index** digest; Debian 13, containerd 2.3.4 |
| Transport | HTTPS on loopback with an explicit CA; bearer token of a dedicated service account |
| Acquisition identity | `ServiceAccount` with a namespace-scoped `Role` (`get`/`list` pods, plus deployments/replicasets — broader than the collector's minimum) |
| Code under test | `main` at commit `7a1bf11`; collector profile unchanged |

- **Fixtures were synthetic** (dedicated namespaces, disposable deployments). The pod fixture was deleted and recreated once, with the deletion bound to a name+UID check; this is a documented deviation from a server-side UID precondition and does not eliminate the race between check and delete.

## Result matrix

| # | Dimension | Result | Notes and limits |
|---|---|---|---|
| 1 | Release identity | **Verified** | Server v1.37.0, node v1.37.0, kind v0.33.0. One version only; no other release is accredited. |
| 2 | Core API and transport | **Verified** | 9/9 pod read operations returned HTTP 200 over HTTPS with an explicit CA. Loopback only; **mTLS not exercised** (bearer was used). |
| 3 | Authentication | **Verified** | Dedicated service account, short-lived bearer token held in memory by the collector. |
| 4 | RBAC — allowed scope | **Verified** | `get`/`list` pods succeeded through the collector: 4 pods listed, 9 operations HTTP 200 in total. |
| 5 | RBAC — denied scope | **Verified** | A namespaced `list` against the denied namespace returned 403 `forbidden` and 0 bundles with a visible error (`partial`); a namespaced `get` of a specific pod there was denied by a separate probe. In total the exercise recorded **4 allowed and 13 denied authorization checks** (the 11 surface probes of row 6, plus this denied-namespace list and get); the nine successful collector HTTP reads of row 2 are separate from these probe counts. |
| 6 | Denied surface | **Verified** | Authorization probes returned **no** for 11 combinations: secrets, configmaps and nodes reads, pod create/delete, watch, `pods/log`, `pods/exec`, all-namespaces and default-namespace pod reads. Probes are authorization checks, not acquisitions. |
| 7 | Container categories | **Verified (finding)** | The live API **omits empty `initContainers`/`ephemeralContainers`**. The collector treats a missing applicable category as "not observed": **all 12 bundles from the four initial pod UIDs came out `completeness: partial`**. Within this profile, any response that omits the empty categories yields `partial`; this is conservative behavior per the evidence contract, not a defect. A change would require a new decision record. |
| 8 | Projection and redaction | **Verified** | Captured payloads contained only the allowlisted fields; single emitted evidence type (`container_status.image_id`); requested image and observed `imageID` kept separate; no digest promotion; platform `unknown`. **Env redaction was not exercised** — fixtures carried no `env`/`envFrom`. |
| 9 | Pod identity on recreation | **Verified** | After deletion and recreation of the same named deployment, the collector observed a **new pod UID** and kept the subjects separate. |
| 10 | Server-side pagination | **Verified (per page)** | With `limit=1` the server returned four pages of one item, with `continue` on pages 1–3 and absent on page 4, and `resourceVersion` on all. **Multi-page traversal by the collector itself was not exercised** (fixture count below the page limit). |
| 11 | `resourceVersion` | **Verified** | Present on list responses; treated as an opaque string. No ordering or age comparison was tested. |
| 12 | HTTP error classes | **Partially verified** | 403 and 404 observed and classified. **401/410/429/5xx not exercised.** |
| 13 | Budgets | **Verified (consumption only)** | Time ≈1.6 s of 300 s; 9 of 1,024 requests; 72,939 of 67,108,864 B (64 MiB). The guards were not driven to their edges. |
| 14 | Sequencing | **Verified (as declared)** | Concurrency 1; one list plus two read rounds. `MaxConcurrency` is an implementation-declared value. |
| 15 | Caller cancellation | **Not verified** | Pre-start and mid-flight cancellation were not exercised against a live cluster (covered programmatically in unit tests). |
| 16 | Snapshot / consistency | **Verified (as declared)** | `list`+`get` is **not** an atomic snapshot; observations are recorded as `not-atomic`. |
| 17 | Status evolution (stale status) | **Not observed** | No delayed status transition was induced; the corresponding failure-mode fixture remains a limited pattern. |
| 18 | Determinism amd64/arm64 | **Verified elsewhere** | Byte-identical golden outputs across windows/amd64 and linux/arm64 were established in a separate exercise; it did not involve a live cluster. |

## OpenShift

**Not verified.** No OpenShift cluster was available and none was used. Until a real OpenShift matrix is executed, Ariadne makes **no OpenShift compatibility claim** of any kind.

## What this page does not claim

- It does not claim compatibility with any Kubernetes release other than the one tested, nor with multi-node clusters, managed Kubernetes (GKE/EKS/AKS/OpenShift), or production workloads.
- It does not claim security, isolation, performance or fitness for any purpose; a green test run does not prove security.
- It does not claim that budgets, timeouts or read-only verbs prevent any effect on the API server; they bound the client only.
- A bundle hash proves bundle integrity, not authenticity of the origin cluster; nothing here attests authenticity.
- Results were produced against synthetic fixtures; no real customer or production data was involved.

## Conditions for revisiting this page

This page must be re-executed and updated when any of the following happens: a new Kubernetes release is tested; an OpenShift cluster becomes available; the collector's transport, authentication or RBAC surface changes; or the empty-category completeness behavior is changed by a new decision record.
