# Ariadne

> **The thread through the CVE labyrinth.**
>
> Turns a container vulnerability finding into a reproducible, auditable evidence record — without executing code inside the pod.

**Status: PRE-ALPHA (design phase).** This repository currently contains the project specification. There is no code yet. Interfaces, schemas and command names described below are design targets, not shipped features.

## The problem

A vulnerability scanner does not produce an exception. It produces a finding. Between the finding and the decision sits the real work:

```text
CVE
  -> advisory / product mapping (Red Hat backporting, RHSA, OVAL)
  -> package / version / EVR
  -> artifact digest / platform
  -> deployed workload UID
  -> container scope (regular / init / sidecar / ephemeral)
  -> applicability preconditions
  -> technical status
  -> exploitability assessment
  -> human risk decision
```

In regulated environments (banking, VDI, jump hosts, air-gapped clusters) every link is verified by hand: export the CSV, locate the pod in the right cluster, check whether the deployed digest is the scanned one, distinguish the requested tag from the real `imageID`, prepare the justification, and re-validate whenever the digest changes.

Ariadne automates the **evidence preparation and evaluation** of that chain. The decision stays human.

## What it is

- An offline CLI that ingests findings (CSV from Prisma Cloud or any other scanner) and sanitized `kubectl`/`oc` exports.
- A conservative identity resolver: CVE → package → digest → workload UID → container.
- A deterministic evaluator: same evidence bundle + same rules = same result, byte for byte.
- An exception record with owner, scope, validity window, and automatic invalidation when the evidence changes.
- Report export (HTML/JSON) and, where the semantics hold, OpenVEX declarations and SARIF output.

## What it is not

- **Not another scanner.** It does not compete with Prisma/Sysdig/RHACS/Kubescape — it consumes them.
- **No exploitation.** It never runs exploits, kill chains or code inside pods.
- **No `pods/exec`.** Remote command execution is not read-only (it allows mutation, network access and data exposure), so it is out of scope.
- **No AI in the decision path.** Conclusions are produced by deterministic, declarative rules.
- **No false negatives by default.** A failed check, a missing binary or an unobserved import is *insufficient evidence* → `unknown`, never `not_affected`.
- **No automatic risk acceptance.** Exceptions require a named human decision.

## Architecture (summary)

```text
scanner CSV ──┐
oc export   ──┤-> input adapters -> normalized facts -> evidence bundle (hashable)
SBOM/RHSA   ──┘                                            |
                                                           v
                                        offline evaluator (deterministic rules)
                                                           |
                                 |-------------------------+------------------------|
                                 v                         v                        v
                        technical status          exception view          interoperability
                        + evidence chain          + human workflow        JSON/HTML/VEX/SARIF
```

Three components with separated trust and privilege:

| Component | Responsibility | Privilege |
|---|---|---|
| Collector | Observe and record facts | Read-only (`get`/`list` on allowlisted resources) |
| Evaluator | Apply declarative rules offline | None: no network, no shell, no cluster client |
| Case record | Record human decisions and validity | None: append-only local store |

## Evidence model

Three questions, never collapsed into a single label:

1. **Product status** (technical): `affected` · `not_affected` · `fixed` · `under_investigation`
2. **Exploitability** (contextual, project-specific): `not_assessed` · `unknown` · `conditions_met` · `conditions_not_met`
3. **Risk decision** (governance, human): `not_assessed` · `accepted` · `deferred` · `rejected`

Core rules:

- `fixed` ≠ `not_affected`. A vendor advisory proves a fix exists for a product; it does not prove *this* deployed workload runs the fixed build.
- Severity ≠ exploitability ≠ affected. CVSS and vendor ratings do not establish that a finding is exploitable.
- Evidence is always bound to a pod **UID** and container — never to `namespace/name` alone, because a replacement pod can reuse the name.
- The requested image (`spec.containers[].image`) and the observed image (`status...imageID`) are separate fields; a mutable tag is never treated as a verified digest.
- Every conclusion links to source, locator, hash and timestamp, and declares its validity window.

## Security posture

- Offline and air-gap friendly: no telemetry, no callbacks, no external feeds required.
- No Secrets, logs, env values or ConfigMap data are read or persisted.
- Redaction happens before anything is written to disk.
- Rule packs are declarative and content-hashed; the evaluator cannot execute code or reach the network, enforced by a CI import check.
- No cost, performance or security guarantee is claimed without reproducible evidence.

## Roadmap

| Phase | Scope |
|---|---|
| 0.1 | Offline core: strict CSV parser, sanitized export ingestion, normalized identity resolution, hashable evidence bundle, deterministic rule evaluation, HTML/JSON reports, synthetic fixtures with golden outputs |
| 0.2 | Optional read-only collector (namespace allowlist, scoped RBAC), fake API server tests, verified compatibility matrix per Kubernetes/OpenShift release |
| 0.3 | Exception lifecycle: expiry, diff between runs, re-validation, OpenVEX/SARIF export |

The public demo runs entirely on synthetic fixtures and requires no access to private infrastructure.

## Documentation

User and contributor documentation lives in [`docs/`](docs/). It will grow as the implementation lands: architecture, evidence schema, rule pack format, compatibility matrix and decision model.

## Confidentiality

This project was designed from experience in regulated environments, but it contains **no client or employer data**: no real CSVs, no namespace/cluster/pod names, no internal scripts or procedures. All examples are synthetic.

## License

[Apache-2.0](LICENSE).

## Contributing

Not open for contributions yet — the interfaces are still moving. Issue reports and design feedback are welcome.
