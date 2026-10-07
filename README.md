# Ariadne

> **The thread through the CVE labyrinth.**
>
> Turns a container vulnerability finding into a reproducible, auditable evidence record — without executing code inside the pod.

**Status: PRE-ALPHA.** The repository contains the project specification and a working offline core, covered by tests: the evidence bundle contract (`pkg/evidence`, `internal/evidence`) with fail-closed validation, canonical JSON and SHA-256 hashing; the strict `prisma-v1` CSV parser (`internal/ingest`, `internal/schema`); conservative normalization and identity resolution (`internal/normalize`, `internal/identity`); the canonical bundle projection (`internal/bundle`); the declarative offline evaluator with fail-closed pack admission (`internal/rulepack`, `internal/evaluator`); the deterministic JSON and HTML report renderer over an evaluation result (`internal/report`); the public wire specification `0.2` with synthetic vectors (`docs/spec/evidence-bundle/`); synthetic fixtures with golden outputs; and a runnable walkthrough (`docs/quickstart.md`, `examples/synthetic-case/`). The offline CLI (`cmd/ariadne`) is implemented and covered by tests — `evaluate`, `report` and `verify` over a canonical evidence bundle, with report files written through an explicit local-filesystem boundary ([ADR-0023](docs/adr/ADR-0023-offline-cli-and-replay-contract.md)). The read-only Kubernetes collector ([ADR-0026](docs/adr/ADR-0026-optional-pod-collector.md)) is implemented and has been exercised against a single-node synthetic Kubernetes 1.37.0 lab — see [compatibility](docs/compatibility.md); OpenShift and other releases not verified. It has no CLI acquisition command. The offline CLI also implements `import` (CSV-to-case pipeline, [ADR-0036](docs/adr/ADR-0036-cli-import-pipeline.md)), `book`/`append` (casefile book persistence, [ADR-0037](docs/adr/ADR-0037-casefile-book-persistence.md)), `serve` (read-only local dashboard over a casefile book, [ADR-0034](docs/adr/ADR-0034-governance-platform-operating-contract.md)) and `diff` (validity diff over one casefile book at two declared instants, [ADR-0038](docs/adr/ADR-0038-validity-diff-lifecycle.md)). The only deferred subcommand is `normalize`; the remaining interfaces and command names described below are design targets, not shipped features, and no release is available.

**Input compatibility today:** `prisma-v1` is an [Ariadne-defined CSV contract](docs/adr/ADR-0007-prisma-v1-schema-and-limits.md), not the header of a verified Prisma Cloud export. The parser rejects headers outside that contract. Direct import of native Prisma CSV or JSON is [planned](docs/adr/ADR-0020-prisma-acquisition-and-vulnerability-data.md), not implemented.

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

- An offline CLI that evaluates a prepared evidence bundle and renders deterministic JSON/HTML reports; ingestion of supported scanner findings and sanitized `kubectl`/`oc` exports is planned. Try it with the [quickstart](docs/quickstart.md).
- A conservative identity resolver: CVE → package → digest → workload UID → container.
- A deterministic evaluator: the same evidence bundle, the same rules and the same explicit evaluation context (target, admission policy, domain policy, engine version) produce the same result, byte for byte; replay validity is limited to those same engine, profile and presentation semantics ([ADR-0023](docs/adr/ADR-0023-offline-cli-and-replay-contract.md)).
- An exception record with owner, scope, validity window, and automatic invalidation when the evidence changes.
- Report export (HTML/JSON), available today through the offline CLI; OpenVEX, SARIF ([ADR-0032](docs/adr/ADR-0032-vex-and-sarif-exports.md)) and CSAF 2.0 VEX ([ADR-0035](docs/adr/ADR-0035-csaf-vex-export.md)) exports are implemented in the `internal/interop` library (not yet wired to a CLI subcommand); document distribution is not authorized.

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
| Collector ([ADR-0026](docs/adr/ADR-0026-optional-pod-collector.md); implemented read-only, accepted 2026-10-01; exercised against a single-node synthetic Kubernetes 1.37.0 lab — see [compatibility](docs/compatibility.md); OpenShift and other releases not verified) | Observe and record facts | Read-only (`get`/`list` on an allowlisted namespace set); allowlist projection before persistence — no Secrets, logs, environment values or ConfigMap data are retained |
| Evaluator | Apply declarative rules offline | None: no network, no shell, no cluster client |
| Case record ([ADR-0030](docs/adr/ADR-0030-append-only-human-decision-records.md)/[ADR-0031](docs/adr/ADR-0031-case-record-validity-and-supersession.md); implemented) | Record human decisions and validity | Append-only, hash-chained local record of human decisions, with a derived validity view (expiry, supersession) and a validity diff between two declared instants ([ADR-0038](docs/adr/ADR-0038-validity-diff-lifecycle.md)) |

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

- The current CLI consumes caller-provided, prepared canonical evidence bundles; it does not acquire scanner or cluster sources.
- The collector contract excludes Secrets, logs, environment values and ConfigMap data from **persistence**: it reads Pods through the Kubernetes API and projects only allowlisted fields before anything is retained, so such values are never persisted. Ariadne is not a general sanitizer or secret detector. (In the lab exercise of [compatibility](docs/compatibility.md), the fixtures carried no `env`/`envFrom`, so env redaction was not exercised live.)
- Rule packs are declarative and content-hashed; the evaluator cannot execute code or reach the network, enforced by a CI import check.
- No cost, performance or security guarantee is claimed without reproducible evidence.

## Roadmap

| Phase | Scope |
|---|---|
| 0.1 | Offline core: strict CSV parser, sanitized export ingestion, normalized identity resolution, hashable evidence bundle, deterministic rule evaluation, HTML/JSON reports, synthetic fixtures with golden outputs |
| 0.2 | Optional read-only collector (namespace allowlist, scoped RBAC): **implemented and accepted 2026-10-01** with synthetic (fake API server) coverage; **one Kubernetes release verified** against a single-node lab (see [compatibility](docs/compatibility.md)); OpenShift and other releases still unverified |
| 0.3 | Exception lifecycle: expiry and validity view (implemented), **diff between declared instants** (implemented), VEX/SARIF and CSAF VEX export (implemented); automatic re-validation and diff between two independent runs still open |

The public demo runs entirely on synthetic fixtures and needs no access to private infrastructure. The repository now ships a runnable walkthrough — [`docs/quickstart.md`](docs/quickstart.md) builds the CLI and runs `evaluate`, `report` and `verify` over the fixtures, with precomposed contexts and byte-exact receipts under [`examples/synthetic-case/`](examples/synthetic-case/). It demonstrates the offline CLI path, not the full CSV-to-case pipeline: `import` now exists ([ADR-0036](docs/adr/ADR-0036-cli-import-pipeline.md)), while `normalize` does not.

## Documentation

User and contributor documentation lives in [`docs/`](docs/). Start with the [quickstart](docs/quickstart.md) to build the CLI and run it over the synthetic fixtures, and see [compatibility](docs/compatibility.md) for what has actually been verified against a cluster. The rest will grow as the implementation lands: architecture, evidence schema, rule pack format and decision model.

Decision records live in [`docs/adr/`](docs/adr/README.md): every decision that shapes the product is written down with the alternatives that were considered, the reasons the chosen option was the best available at the time, the limits it introduces and the conditions that would justify revisiting it. That is where the answer to “why does it work this way?” belongs — including the decisions that deliberately *reduce* what the tool claims.

## Confidentiality

This project was designed from experience in regulated environments, but it contains **no client or employer data**: no real CSVs, no namespace/cluster/pod names, no internal scripts or procedures. All examples are synthetic.

## License

[Apache-2.0](LICENSE).

## Contributing

Not open for contributions yet — the interfaces are still moving. Issue reports and design feedback are welcome.
