# ADR-0019: Operating modes and persistent tracking

- **Status:** **proposed (2026-09-27); pending review and ratification; not implemented.** This record is a proposal: nothing in it is decided until the owner ratifies it through a separate, explicit decision.
- **Date:** 2026-09-27.
- **Scope:** propose two ways of using the same product (occasional runs and continuous tracking), the transition between them, the temporal meaning of observations, what charts may honestly show, a hot/warm/cold storage evolution and exports for external corporate policies. It complements the optional governance platform record (ADR-0017); it supersedes nothing.
- **Related records:** depends on ADR-0002, ADR-0003, ADR-0004, ADR-0006, ADR-0007, ADR-0008, ADR-0010, ADR-0012, ADR-0013, ADR-0015, ADR-0016 and ADR-0018; complements ADR-0017. No accepted record is superseded.
- **Delivery status:** a proposal of scope and direction. Ratification authorizes no implementation. Every open question Q-01..Q-08 requires a later owner decision, with architecture/contract review, before any code, wire, state or security boundary changes.

## Proposed decision

**Related proposal added on 2026-09-27:** [ADR-0020](ADR-0020-prisma-acquisition-and-vulnerability-data.md) proposes optional Prisma Compute acquisition and richer vulnerability data as a potential evidence source. It does not close this record's Q-01..Q-08, select a scheduler or storage system, or change its proposed status. One-shot acquisition does not require a platform; persistent integration retains this record's design dependencies.

Ariadne would offer **two usage modes of the same product** sharing one core of rules and evidence:

1. **Occasional:** a manual or pipeline-embedded run takes a bounded set of evidence, produces keepable, exportable artifacts (canonical bundle, hash, evaluation) and finishes. Nothing needs to stay alive; the artifacts persist even if the run does not.
2. **Continuous tracking:** new observations arrive periodically; each delivery is evaluated and incorporated into durable storage with a queryable history and evolution views. Tracking does not require any collection process to stay alive: a run may be ephemeral while its artifacts persist.

The CLI and the platform use the same rules and the same evidence; dashboards derive from traceable artifacts (ADR-0017). Neither mode turns the evaluator into a network client or Ariadne into a scanner or exploiter: recurrence orchestrates reviewed producers/collectors and evaluations of what those producers deliver.

Tracking a deployment needs **new observations**. Re-running the evaluator over the same bundle proves nothing about re-observing the cluster: re-evaluating an artifact yields another evaluation, not a new observation.

## Context

The optional governance platform record (ADR-0017) ratified an append-only timeline, but did not decide how evidence reaches it over time or what a series of evaluations means temporally. Real usage starts occasional (a one-off CSV review with kept artifacts) and evolves toward tracking (periodic collection, trends, expiries). The evidence contract already separates `observed_at` from run time and keeps `published_date` and `discovery_date` as optional `prisma-v1` columns; the evaluator already treats observation age and future observations conservatively. No collector, durable storage, history or views exist; everything here is future design.

## Options considered

| Option | Proposed outcome |
| --- | --- |
| Only manual runs | Not selected as the final scope. It leaves recurring reviews, trends and expiries without product support; it is the occasional mode, not the destination. |
| Periodic runs with durable history | **Recommended starting point for tracking.** Each run is ephemeral, leaves verifiable artifacts, and a later step ingests them into history. Reversible, auditable, compatible with the offline core. |
| Permanent event-reactive service | Not selected as the starting point; kept as a conditional evolution. It adds availability, concurrency and operational surface that are not designed yet. |
| Persist only current state, discard the past | Rejected. It breaks decision traceability (ADR-0017) and makes it impossible to explain what was known when a decision was made. |
| Editable history for corrections | Rejected. Corrections create new events, invalidations or `supersedes`; history is never rewritten. |
| Derive history from re-evaluating the same bundle | Rejected. Re-evaluation is not observation; it would build a time series with no new observational content. |
| A universal risk-percentage chart | Rejected. It would blend CVE counts, affected-asset counts and severity into a number with no stable meaning or traceability. |

## Why the recommendation was the best at the time

- **Cost:** periodic runs reuse the offline binary with no permanent service; durable storage can start as files with derived indexes.
- **Risk:** no new privileges (no network in the evaluator, no `pods/exec`), no wire or state changes, three decision layers kept separate.
- **Reversibility:** the occasional mode is the degenerate case of tracking (a history of size one); a user can stop tracking and still keep and verify artifacts.
- **Fit:** matches the append-only timeline of ADR-0017 and the rule that every conclusion links to evidence with its timestamps.

## Mode transition

A user can start occasionally, keep the bundles and evaluations, and later incorporate them into an installation with history. Historical import must respect the original version, integrity, provenance, scope and times under the applicable admission contracts. **Importing today does not make an old observation recent**: the original `observed_at` is kept and the import time is a different time. Re-delivering the same data must never be presented as a new observation (open question Q-02).

History exists only as far as kept and admitted artifacts exist; periods without evidence are not reconstructed — a gap is a gap. A new evaluation preserves the previous one and keeps its inputs, rules and context identifiable; it never rewrites what was known. The occasional user keeps getting verifiable, exportable artifacts after joining tracking.

## Time, detection and identity

The proposal requires distinguishing, without adding wire fields in this record:

| Time | Meaning | Current state |
| --- | --- | --- |
| CVE publication (`published_date`) | When the source published the advisory | Optional `prisma-v1` column, preserved (ADR-0007/0008); no derived use implemented |
| Source-declared discovery (`discovery_date`) | When the source says it discovered the vulnerability | Optional column, preserved; its presence and format do not prove when an asset started being affected |
| Observation (`observed_at`) | When the source observed the fact on the asset | Mandatory in the evidence contract (ADR-0006/0012) |
| Ingestion | When Ariadne received the artifact | Separate per ADR-0017; not implemented |
| Evaluation | When the evaluator processed the evidence set | Separate per ADR-0017; not implemented |
| Human decision | When a person decided | Decision layer; not implemented |

First recorded detection, first accredited affectation and the real start of a vulnerability are different concepts; the real start may remain unknown, and no formula over the other times proves it. `observed_at` is never replaced by publication, discovery or run time. How to derive each date against late imports, duplicates, reappearances, source corrections and out-of-order observations is an open question (Q-03).

Evidence keeps the existing strict identity: UID plus container, container class where applicable, observed digest and accredited platform (ADR-0009/0010). Replacing a pod creates a new identity. **Business-asset continuity across replacements** needs an explicit relationship and a later contract; it is never inferred from namespace/name or a label. Corporate deadlines do not automatically reset when a UID changes, and affectation is not automatically transferred to the new UID: both need explicit semantics and adequate evidence (Q-03).

## Coverage and the meaning of charts

Views must distinguish current, stale, incomplete and absent observation, with the last observation and its scope visible; no new technical enums are introduced. A drop in findings between two reviews can mean accredited remediation, retired assets, a scope change, a revised source or lost observation; these causes must be distinguishable (Q-04). **Disappearing from the last inventory or a failed collection proves neither `fixed` nor `not_affected`**: a negative observation is "not observed in this method/scope", not universal absence.

Charts must keep their relationship to the observed asset set and its coverage. No universal risk percentage is promised, and no formula blends CVE counts, affected-asset counts and risk. Frequency, retries, concurrency, recovery from interruptions, advisory revisions and gap handling are designed later (Q-01, Q-04).

## Persistence and hot/warm/cold

A proposed evolution in three **access and storage** tiers — not trust tiers, not technical states:

- **Hot:** frequent queries, recent state, indexes, dashboard.
- **Warm:** queryable history for trends and routine investigation.
- **Cold:** archived artifacts and history with less immediate retrieval.

An old event in an active case may need frequent access: **no migration is imposed by age alone**. Moving artifacts between tiers never changes their canonical bytes, hashes, provenance or relationships; any physical container or compression must allow recovering the verified bytes. Indexes and summaries are derived and rebuildable. Links must locate an artifact or request its retrieval, and express that it is archived, pending retrieval or unavailable.

The three tiers are **not a requirement of the first implementation**: durable storage and a correct history come first (Q-05). This record chooses no database, provider, physical format, retention periods, availability guarantees or RPO/RTO.

**Archive is not backup is not deletion.** The append-only model of ADR-0017 is not replaced by a deletion authorization. Retention, erasure, audit preservation, the fate of indexes and references, and their effect on queries are open decisions that must be resolved before any destructive implementation (Q-06); if they require changing a current contract, they need a separate later decision. Complete history is not promised after its storage is lost or destroyed.

## Corporate deadlines and export

Proposed scope: an organization can compute grace periods, remediation deadlines and their indicators **externally**, using traceable data exported by Ariadne. This proposal does not require an internal SLA or corporate-policy engine (Q-07).

Evidence validity, pack validity, exception expiry, grace period and remediation deadline are distinct concepts. Being inside a grace period or having an exception does not change `product_status`; the risk decision remains human.

The bundle JSON exists; **CSV and XML are not presented as implemented exporters or ratified formats**. CSV is a possible tabular output to be studied; XML is only an example of a possible format. The export contract must fix scope, identity, dates, provenance, coverage and the representation of unknowns before any implementation. Exported data must allow interpreting periods and scope changes without inventing data: gaps, coverages and unknowns stay declared, never filled in.

## Product and security limits

The offline core and the collector/evaluator/platform separation are preserved. No Secrets, logs, env values, ConfigMap data or `pods/exec` (ADR-0004). New integrations, API operations, privileges or data storage require contracts and review before implementation. `product_status`, `exploitability` and `risk_decision` stay separate; **no new technical state** is declared for being in grace, archived or pending collection — those conditions live in views and governance, not in the technical enum. No real customer data, no total-coverage promises, no automatic legal compliance, no unverified compatibility.

## Consequences and limits

If ratified and implemented, this buys a transition between occasional and tracked use with no second semantics, time series with explicit observational meaning, degradable views that stay interpretable, and a storage growth path that never moves trust. It does **not** define orchestration, frequency or concrete mechanisms (a `CronJob` is an example mechanism, not a proven compatibility or an implemented resource); it does not decide event identity, idempotency or deduplication; it does not formula dates or guarantee knowing when a vulnerability started; it does not authorize retention or erasure; it does not define export formats or an SLA engine; it adds no wire fields, changes no states or enums, and introduces no network in the evaluator. It guarantees neither complete history after storage loss, nor complete charts, nor that a time series proves remediation.

## Traceability matrix

| Requirement | Section | Related record | Open question | Future acceptance evidence |
| --- | --- | --- | --- | --- |
| A. Two modes, shared core | Proposed decision, Options, Why | ADR-0003, ADR-0017 | Q-01 | Ratified orchestration contract; occasional mode yields the same artifacts as tracking for the same evidence |
| B. Mode transition | Mode transition | ADR-0012, ADR-0017 | Q-02 | Historical import keeps `observed_at` and provenance; repeated delivery never presented as a new observation (by test) |
| C. Time, detection, identity | Time, detection and identity | ADR-0006, ADR-0007/0008, ADR-0009, ADR-0010, ADR-0017 | Q-03 | Ratified semantics for first detection/affectation and asset continuity; no derived date without a contract; strict identity preserved |
| D. Coverage and charts | Coverage and the meaning of charts | ADR-0006, ADR-0017 | Q-01, Q-04 | Views distinguish current/stale/incomplete/absent; each drop cause distinguishable; no chart without a path to evidence |
| E. Persistence hot/warm/cold | Persistence and hot/warm/cold | ADR-0017 | Q-05, Q-06 | Durable storage with correct history first; bytes and hashes identical after a tier move (by test); retention policy ratified before any deletion |
| F. Corporate deadlines and export | Corporate deadlines and export | ADR-0006, ADR-0017 | Q-07 | Export contract with scope, identity, dates, provenance, coverage and unknowns; external deadline computation possible without an internal engine |
| G. Product and security limits | Product and security limits | ADR-0003, ADR-0004, ADR-0013 | — (invariant) | Existing gates stay green; no network in the evaluator; no new states; import-boundary and redaction tests intact |

## Open questions

Each question closes with an owner decision (with architecture/contract review) and a documented deliverable.

- **Q-01 — Orchestration and frequency.** How producers/collectors and evaluations are orchestrated: mechanism, frequency, new sources, retries, concurrency, recovery. Alternatives: external cron (smallest surface), own scheduler, reactive service (conditional evolution). Recommendation given: start with periodic runs external to the binary; the rest is undecided. Closes with: an orchestration precision record and design.
- **Q-02 — Event identity, historical imports, duplicates.** Event identity, idempotency, deduplication, temporal ordering, re-evaluations and historical imports. Alternatives: content-derived (hash) identity, producer-assigned identity, hybrid. Undecided. Closes with: a ratified event and import contract extending the platform timeline record.
- **Q-03 — Derived dates and asset continuity.** Definition and scope of first detection/affectation, reappearance, and business-asset continuity across UIDs (explicit relationship, deadline-transfer and affectation-transfer semantics). Alternatives: operator-declared relationship, deployment-derived relationship, no continuity support. Undecided. Closes with: a continuity and derived-dates record.
- **Q-04 — History contract and chart semantics.** Indexes, coverage in views, stale data and the causes behind chart changes. Alternatives: rebuildable indexes vs. persistent materializations; taxonomized causes vs. generic warnings. Undecided. Closes with: a history and views contract.
- **Q-05 — Durable storage and tiers.** Hot/warm/cold evolution: engine, physical format, integrity and retrieval. Alternatives: files plus derived indexes (likely first implementation), a database, external object/archive storage. No technology chosen. Closes with: a storage record.
- **Q-06 — Retention, erasure and append-only.** Retention, erasure, audit preservation and their relation to the append-only model. **No deletion authorization in this proposal.** Alternatives: indefinite retention, policy-based retention with legal preservation, erasure with markers. Undecided. Closes with: a retention record prior to any destructive implementation.
- **Q-07 — Export and external policies.** Formats (CSV as a candidate to study, XML as a possible example), scope, identity, dates, provenance, coverage and unknowns. No format chosen. Closes with: a ratified export contract.
- **Q-08 — Authorization and operation.** Authorization, installation isolation, collector permissions and platform operation. Inherits what the platform record leaves open (no API, authentication or RBAC defined). Undecided. Closes with: an authorization/operation record before any platform implementation.

### Requirements refinement — 2026-09-27: bounded tracking and deployment

**Owner-confirmed partial choice (2026-09-27):** for an in-cluster Kubernetes/OpenShift installation, use a **dedicated, configurable namespace**, a `Job` for a one-shot run and a `CronJob` for periodic collection, with durable storage independent of pods and separate identities, permissions, network rules and resource limits. The owner approved this specific recommendation. An installation outside the cluster remains possible without a Kubernetes namespace or Job. This combination separates operations and permits ephemeral collectors with persistent history, at the cost of deployment and administration. A namespace alone proves neither sufficient isolation nor authorization to read other namespaces.

This partial choice **does not ratify all of ADR-0019 or close Q-01/Q-05/Q-08**. Exact frequency, window expiry, idempotency, storage technology, RBAC, network policy and verified OpenShift compatibility still require their contracts. An organization that requires an existing namespace or external scheduler must record and assess that variant against these controls. This choice authorizes no deployment or code change.

The proposal now explicitly includes one-shot acquisition and scheduled tracking with an optional end date. A week or one/three months of tracking uses the same engine, permissions and durable history as indefinite tracking: it is an operating window, not a separate product mode or licensing trial. Extending or removing the end date is an explicit recorded change; it must not reset findings or fabricate observations.

Configuration should separate sources, scope, frequency, time zone, start, optional end and durable destination. Calendar durations resolve to visible dates; a month must not silently mean 30 days. Q-01 must settle interval/calendar/DST semantics, first execution and changes. Restarting a pod cannot restart the window. Credentials alone do not enable a schedule, and offline inputs remain available.

At expiry, the recommended default prevents new cycles while allowing a started run to finish within its budget. A strict activity cutoff needs a separately defined cancellation and in-flight-request policy. Stopping tracking does not delete artifacts, credentials, namespaces or storage; retention remains separate. A proposed closing report should show actual coverage, expected/completed runs and gaps. Resumption cannot fabricate missing observations or create unbounded catch-up runs.

For an in-cluster installation, recommend a dedicated configurable namespace, with a Job for a one-shot run and CronJob as the leading recurring option. External scheduling remains valid. A permanent service needs its own justification, such as a future query UI/API. Neither a namespace nor a long-lived pod provides durable history: storage must survive collection pods, with technology still open under Q-05.

The [CronJob API](https://kubernetes.io/docs/reference/kubernetes-api/batch/cron-job-v1/) has no campaign end-date field, and suspension does not stop active Jobs. Design must combine a pre-acquisition window check with reconcilable schedule deactivation, avoiding indefinitely scheduled empty runs. `Forbid` is a candidate concurrency policy, not cross-instance deduplication. The orchestration identity that manages Ariadne resources must be separate from evidence readers.

[Namespace isolation](https://kubernetes.io/docs/concepts/security/multi-tenancy/) also needs authorization, network controls and resource limits. Installation in one namespace grants no access to others. Prisma-only acquisition needs no Kubernetes read permissions. An existing organizational namespace is an alternative if it meets isolation requirements; a particular namespace name is not mandated.

Q-01/Q-08 remain open and now require explicit tests for start/end, restart, extension, expiry, active runs, suspension, bounded recovery and least privilege. Q-02 preserves identity; Q-04/Q-07 cover closure reporting; Q-05/Q-06 cover retention. ADR-0020 P-02/P-07/P-08 covers credentials, acquisition and handoff. These are proposed requirements, not implemented functionality or verified OpenShift compatibility.

## Revisit if

Reopen or revise this proposal if the platform record's event or timeline contract evolves incompatibly; if the owner chooses an orchestration mechanism that requires network or a permanent service in components that must stay offline; if a real observation producer arrives whose temporal model does not fit the distinction above; if retention or erasure contradicting the append-only model is needed (new record required); or if a real implementation shows the tier distinction is insufficient or is de facto used as trust levels.

## Status

Proposed on 2026-09-27; pending contractual independent review and owner ratification; not implemented. This record authorizes no code, implementation or contract change. If accepted, the acceptance will be recorded through the project's decision-record policy; until then this is decision material, not a normative contract.
