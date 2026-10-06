# ADR-0035: CSAF 2.0 VEX export from an evaluation result

- **Status:** proposed (2026-10-06). Not ratified and not implemented. Task A3-08.
- **Scope:** contract for a new output surface in the `internal/interop` package (twelfth root of the import gate, ADR-0032). Adds no gate root.
- **Relationships:** applies [ADR-0004](ADR-0004-no-exec-human-decision.md) (no hidden clock), [ADR-0011](ADR-0011-decision-record-policy.md) (two-layer record policy) and the deterministic-presentation model of [ADR-0022](ADR-0022-json-and-html-report-contract.md), including its **no-authorized-distribution** rule. Reuses the rigor of [ADR-0032](ADR-0032-vex-and-sarif-exports.md) without changing the wire. Closes restriction D3 of A3-04 and escalation ES-1. Supersedes no accepted record.

## Decision

Add an **offline, deterministic, byte-for-byte** export of a **CSAF 2.0 VEX** document (OASIS Standard, 18 Nov 2022, `csaf-v2.0-os`) from an already-computed evaluation result and the canonical bundle whose projection hash the result carries:

- **Identity mapping** of the closed product vocabulary to CSAF `product_status`: `affected`→`known_affected`, `not_affected`→`known_not_affected`, `fixed`→`fixed`, `under_investigation`→`under_investigation`. `unknown` is not a CSAF state (it arrives already reopened as `under_investigation`).
- A **compact** document with the mandatory minimum of the official schema: `document` (`category:"csaf_vex"`, `csaf_version:"2.0"`, `publisher{category:"other",name,namespace}`, `title`, `tracking`), `product_tree.full_product_names` and one `vulnerabilities[]` entry with `product_status` and the VEX-required statements.
- **Restriction D3 resolved in two parts:** the **impact statement** of `known_not_affected` is emitted as **inert, constant, frozen text** in `threats`/`impact` (human-readable; Ariadne carries no machine-readable justification label), worded as a **non-probative descriptive claim** that asserts no universal absence and does not re-project the sufficiency of the evidence. The **action statement** of `known_affected` is **supplied by the caller** (`CSAFRemediation{Category,Details}`): Ariadne models no remediation and the five CSAF categories are factual claims it cannot substantiate. The adapter **does not invent** the category; it **fails closed** when it is missing or invalid. The adapter **validates the CVE format** of `VulnerabilityID` and fails closed otherwise, so it never presents a non-CVE advisory identifier as a CVE.
- Product identity is a **local opaque URN** (`urn:ariadne:subject:sha256:…`, the ADR-0032 one), never a purl/CPE, and leaks no cluster identifier.
- `CSAFIssuer` (`DocumentID`, `PublisherName`, `PublisherNamespace`, `IssuedAt`) is supplied by the caller, because the evaluation instant is a replay parameter, not an issuance date.

## Context

Ariadne exports OpenVEX and SARIF (ADR-0032) and lacks the CSAF piece. A3-04 validated the CSAF 2.0 normative text and left restriction **D3**: VEX conformance (`MUST`, §6.1.27.5/9/10) requires an impact statement for `known_not_affected` and an action statement for `known_affected`; the adapter **cannot** reuse the inert decision of A3-03 about `impact_statement`/`action_statement`. The mandatory fields were confirmed against the official schema. The product rule applies: the tool does not assert facts it cannot substantiate, and the `remediations[].category` enum is machine-readable.

## Options considered

| Option | Assessment |
| --- | --- |
| Implement **reading** of CSAF advisories as an evidence source | Discarded for this scope: it is an **ingestion** surface (profile, allowlist, budgets, replay), a different task with its own ADR. |
| **Generation** of CSAF VEX documents from the `Result` | **Recommended:** the interoperability piece missing beside OpenVEX/SARIF; fits `internal/interop` and centers on D3. |
| Reuse the inert A3-03 decision for the action statement | Rejected: in CSAF the statement carries a closed `category` the consumer reads as a fact; inert text with an invented category overstates. |
| Emit the action statement with a **constant** category chosen by Ariadne | Rejected: all five categories assert a real remediation Ariadne does not know. |
| Emit the action statement **supplied by the caller**, fail-closed if missing | **Recommended:** the `Issuer` pattern; Ariadne invents nothing it cannot substantiate. |
| Emit the impact statement as a machine-readable `flags` entry | Rejected: Ariadne carries no justification label (consistent with ADR-0032); `threats`/`impact` human-readable is used. |
| Product identity by purl/CPE | Rejected: Ariadne holds none and fabricates none; an opaque URN avoids leaking. |
| Do not emit CSAF until remediation is modeled | Rejected: it would leave `fixed`/`under_investigation`/`not_affected` — which can be presented honestly — uncovered. |

## Why this was the best option at the time

The export introduces no privilege, network or clock and rests on data that already exists, on the already-reviewed `internal/interop` surface. Keeping the machine-readable fields free of unsupported claims is the only way to respect the no-overstatement rule. Delegating to the caller what Ariadne cannot invent follows an accepted pattern in the project (`Issuer`, the `casefile` instant, `HashSource`). Minimal contract cost, high reversibility, zero migration.

## Consequences and limits

Generation is defined; **distribution of the exported documents is not authorized** (ADR-0022; ADR-0034). The document **does not prove the correctness** of the conclusion — it presents it in a standard format. **No conformance** with official CSAF validators is accredited (same limit as ADR-0032). The `product_id` is local and opaque; there is no automatic CSAF↔OpenVEX mapping of IDs/states/justifications. The `known_affected` action statement is caller data emitted verbatim: this package does not accredit its truth. Single-platform (windows/amd64); no CLI, persistence or lifecycle.

## Revisit if

Contract revision is required if the domain contract starts carrying a remediation or a machine-readable justification; official-validator conformance is decided; distribution is authorized; **reading** of CSAF is required (a new ingestion ADR); or the F1 scope choice (generation) is revoked towards reading.

## Normative detail

Full contract: `.internal/design-A3-08-adaptador-csaf.md`. Normative base: `.internal/report-A3-04-csaf-normative-validation.md`.
