# ADR-0017: Optional governance platform and timeline

- **Status:** **ratified by the owner on 2026-09-26**; not implemented.
- **Date:** 2026-09-26.
- **Scope:** extend Ariadne with an optional query and governance layer without replacing the offline CLI core or the evidence contract.
- **Related records:** depends on ADR-0002, ADR-0003, ADR-0004, ADR-0006, ADR-0012, ADR-0013, ADR-0015 and ADR-0016. No accepted record is superseded.
- **Delivery status:** this is a scope decision. The API, storage, authentication, web interface and operational retention require later tasks and contracts.

## Decision

Ariadne's product architecture will retain an offline CLI core for building and verifying evidence bundles, and may add an optional centralized platform for querying evidence, evaluations, exploitability conditions and human decisions. The platform is not a second source of truth: once implemented, its views, charts, filters and exports must derive from traceable bundles, evidence items and decision records.

The platform will preserve an append-only timeline of relevant facts, evaluations and decisions. A later change may create a new event, invalidate an earlier conclusion or supersede a decision under the applicable rules, but it must not rewrite history to hide what was known, when it was observed or why a decision was made.

The platform must be able to represent company-owned images. Reviewed producers or importers may provide SBOMs, build metadata, digest relationships, internal or external advisories and evidence about exploitability conditions. Source provenance and limitations remain visible; a private registry name is not sufficient proof.

## Context

In large enterprise environments, the number of assets associated with a CVE can change between reviews: new workloads appear, new digests are deployed, an advisory receives a new revision or an exception expires. A current-state view alone cannot explain what changed between meetings or what information was available when a decision was made.

The project must also cover images built by the customer. A private image may contain Red Hat packages, proprietary software or components from another vendor. Assessing its exact build requires linking the deployed digest to an SBOM, build metadata or equivalent evidence and to a source describing the vulnerability. That need cannot be solved by assuming that every image comes from Red Hat.

The CLI remains necessary for offline work, CI/CD and environments that do not want a central service. A web platform can make reviews, expiry tracking and trends easier, but it introduces authentication, authorization, retention, isolation, invalidation and availability requirements that are not implemented yet.

## Options considered

| Option | Outcome |
| --- | --- |
| Keep only the CLI | Not selected as the final scope. It keeps the core small, but leaves centralized review, recurring meetings and historical evolution without a product surface for large installations. |
| Replace the CLI with a web application | Rejected. It would break offline and CI/CD use, expand the operational surface and make the interface necessary to produce or verify evidence. |
| Optional platform derived from bundles and decisions, with the CLI retained | Selected. It adds query and governance capabilities without duplicating technical semantics and permits local or internal deployment, or no server at all. |
| Store only current state and recompute the past | Rejected. It would lose what changed, what evidence was available and which decision was valid at a particular time. |
| Allow administrators to edit history | Rejected. Corrections must create new events, invalidations or `supersedes` relationships rather than hide prior records. |
| Build charts independently of bundles | Rejected. It would create numbers without traceability and could make the dashboard and CLI count different things. |
| Accept any private-image source without a contract | Rejected. A registry, tag or scanner label does not prove the content of a digest or the applicability of an advisory. |

## Why this was the best option at the time

- It preserves the existing offline, deterministic and no-`pods/exec` core boundary.
- It addresses an operational need: reviewing changes, expirations and increases in affected assets without losing historical context.
- It makes the interface a navigable projection of the same evidence that the CLI can verify instead of creating a second semantic system.
- It permits a local or internal deployment without claiming a SaaS architecture, general cluster compatibility or a retention policy that has not been designed.
- It accommodates private images through explicit evidence without granting extra trust merely because a source is internal or uses a private registry.
- It is reversible at the presentation layer: a customer may continue using only the CLI and bundles while the evidence and decision contracts remain independent of presentation.

## Scope contract

### Source of truth

Normalized evidence, canonical bundles, versioned evaluations and decision records are authoritative. The API and web interface index and present those artifacts; they must not invent facts or silently modify technical states.

Important views must lead, directly or indirectly, to the CVE, subject and container, digest, evidence item, source, hash, locator and relevant timestamps. A chart without a path to its supporting data is not sufficient for audit use.

### Timeline

The timeline must distinguish at least:

- when a source observed a fact (`observed_at`);
- when Ariadne received or recorded the artifact (`ingested_at`);
- when the evidence set was evaluated (`evaluated_at`);
- when a person created, approved, changed, expired or superseded a decision (`decided_at` or the event's equivalent).

Each timeline event must have a stable event identifier, an event kind, its source or actor, the relevant timestamp, and references to the bundle, subject, finding or decision it describes. An invalidation must be a new event that identifies the prior conclusion or decision, records the reason and actor or source, and links to the replacement evaluation or decision when one exists. `supersedes` and invalidation relationships must preserve both sides; they must not overwrite the referenced event.

An observation time must not be replaced with ingestion time. If a required time is missing, in the future or outside the validity policy, the applicable contract must preserve uncertainty.

Domain history is append-only. An implementation may use indexes, projections or materialized views for queries, but rebuilding current state must not delete original events.

### Private images

A private-image integration should preserve, when applicable:

- declared reference and observed digest;
- platform and relationship to the exact build;
- SBOM, build metadata or equivalent evidence;
- component, package, version and architecture;
- external or internal advisory, revision and provenance;
- observation scope and date;
- coverage limitations and missing evidence.

Producers may be internal or external, but their assertions remain supplied evidence and must meet the provenance, integrity, scope and validity obligations of the applicable contract. Support for a new source family or technical state requires its own contract and review; this ADR does not treat private sources as equivalent to Red Hat and does not implement an adapter.

### Decision separation

The platform must display separately:

1. `product_status`: the technical status of the product or build within the tested scope;
2. `exploitability`: the evaluated conditions and their limits;
3. `risk_decision`: the human decision, owner, validity, rationale and controls.

A chart may summarize these layers, but it must not collapse them into one label. `EXCEPCIONABLE` remains a derived governance view and never a technical state.

## Initial views

The first visual scope may include:

- a dashboard of CVEs and changes since a reference date;
- a CVE detail view with affected, under-investigation, fixed and exception states separated;
- an image and digest detail view with SBOM and missing evidence;
- exceptions, owners and expiry dates;
- a navigable timeline;
- access to the raw evidence bundle, hashes and provenance;
- meeting and audit exports that preserve data scope.

Historical charts should be added after temporal retention and invalidation semantics are fixed. A chart decrease must not be interpreted as remediation if it represents lost evidence, a scope change or an inconclusive reevaluation.

## Consequences and limits

This decision buys a centralized experience for large teams, navigation from trends to raw evidence and explicit preservation of change. It also introduces substantial costs: storage, indexing, access control, installation isolation, retention, backups, availability, migrations and protection of infrastructure information.

This ADR does not define:

- a database, API, web framework or deployment provider;
- authentication, RBAC, SSO, multi-tenancy or secret management;
- a legal retention or deletion policy;
- bundle signing or source authenticity;
- a real adapter for Red Hat, other vendors or internal advisories;
- general Kubernetes or OpenShift compatibility;
- automatic change detection without new observations;
- exploitation, executed kill chains, `pods/exec` or runtime probing;
- a guarantee that a chart is complete or that an exception is safe.

A hash protects artifact integrity against expected inputs, but does not by itself prove source authenticity, sufficiency, exhaustiveness or freshness. An append-only Ariadne record also does not prove that the original producer was correct.

## Revisit if

Reopen this decision with a new ADR if the source of truth must differ from bundles and decisions, technical states can be changed from the interface, history can be rewritten, data is shared between customers, signatures are needed for authenticity, an external service is introduced, new cluster operations are accepted, sensitive data is read, or validity and invalidation semantics change.

Revisit it as well if real data shows that observed, ingested, evaluated and decided times are insufficient, or if private images require an evidence contract that cannot be represented by the ratified families and versions.

## Status

Ratified by the owner on 2026-09-26. The platform, API, storage, views and private-image importers are not implemented. Implementation tasks must preserve this boundary and record new contracts before changing the wire, states, permissions or security rules.
