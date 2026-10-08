# ADR-0022 — JSON and HTML report contract

- **Status**: **ratified by delegated authority of the owner (2026-09-28); implemented as F2 (2026-09-28) and accepted by the owner on 2026-09-28; distribution of reports not authorized.** The delegation covered the review reservations of the report design and their registration in the two-layer decision record; implementation required and received a separate authorization from the owner the same day. The implementation lives in `internal/report` (`Build`, `JSON`, `HTML`) and closed four independent review passes with no open finding (0 P0, 0 P1, 0 P2, 0 P3). The owner accepted the implementation on 2026-09-28 after the gates were green, the three commits were pushed to `origin/main` and CI was green, closing A1-06. This record does not authorize distribution of reports — that requires a designated responsible owner and an access policy — or a release.

> **Distribution clause superseded (2026-10-08):** the statement that distribution of the reports, bundles or exported documents is “not authorized” was withdrawn from the product presentation and from the current-state documentation by [ADR-0039](ADR-0039-state-label-and-distribution-scope.md). The rationale and dated text below are retained as history; the security and accuracy limits of this record still stand.
- **Decision owner**: project owner (delegated to the design model for the reservations below).
- **Independent review**: the report design was reviewed before ratification; the review found no open finding in the final delta (0 P0/P1/P2/P3 after corrections).
- **Relationships**: depends on ADR-0003, ADR-0004, ADR-0006 §9/D3, ADR-0011, ADR-0012, ADR-0013, ADR-0015, ADR-0016 and ADR-0018. Supersedes no accepted record. It changes neither the evidence wire, nor `schema_version`, nor the evaluator result.

**Ariadne is pre-alpha.** This record fixes a presentation contract; it does not describe shipped functionality. Goldens for evaluation results and for the decision record remain deferred to Phase 3 (A0-04 D3); this record only authorizes presentation goldens.

## Decision

The report is a **deterministic presentation of an already-computed evaluation result**. The complete report is the `Result`-derived core (`ResultDTO`) plus an evidence catalogue and a warning catalogue resolved **exclusively** from the canonical bundle projection validated against `Result.BundleHash`. The evaluator result, the bundle and the wire stay unchanged; the report does not re-evaluate rules, does not compute exploitability and does not take human decisions. No `schema_version`, hash or public compatibility promise is attached to the report in this pre-alpha phase.

Ratified reservations:

| Reservation | Content | Decision |
|---|---|---|
| P1 | Input and traceability: `Result` core + bundle-verified catalogue | The bundle is an explicit auxiliary input, not implicit disk access; only hash-covered fields are used |
| P2 | Format nature: closed grammar, `risk_decision:null`, no `issued_at`, no compatibility promise | Closed ordered grammar; absence of a human decision is represented as `null`, never as `not_assessed` |
| P3 | Presentation goldens and D3 reconciliation | Presentation-only goldens; evaluation-record goldens remain in Phase 3 |
| P4 | T3 criterion: inert text and the Excel limit | Formula prefixes treated as inert text; no protection claim when importing into a spreadsheet |
| P5 | API, validation and resources | `Build`, `JSON` and `HTML` with closed static diagnostics and no partial bytes |
| P6 | Redaction, authorization and distribution | Values and messages excluded; no secret detector; distribution not authorized |
| P7 | Two-layer registration | This public record with its internal normative counterpart and index row |

## Context

After the offline evaluator was accepted, reports were the next phase of the MVP. No record or specification fixed the report format: the design example in the architecture document is historical, and the evaluator result is internal and does not contain the warnings or the evidence items it references — it contains indices into the bundle. Presentation therefore cannot be written by an executor without first deciding how citations and warning codes are resolved, and the delegation pattern requires a closed contract before mechanical implementation.

The design phase documented the applicable discrepancies honestly: `unknown` is not a technical product status (it exists for checks and exploitability), the result carries no issuance date, warnings arrive only as references, T3 mentions spreadsheet exports while this phase delivers HTML/JSON only, and the historical memories contain superseded task states.

## Options considered

| Option | Outcome and trade-off |
|---|---|
| Result core + bundle catalogue verified against the bundle hash | Chosen. Keeps result and wire intact, resolves codes and citations with provenance, requires the intact bundle as an explicit auxiliary input. Reversible through a new record. |
| Result-only core | Cheaper and self-contained, but cannot resolve warning codes or citation details; does not meet the requested deliverable. |
| Extend the evaluator result with citation and warning snapshots | Meets result-only access at the cost of changing the evaluator contract, its sensitive surface and its budgets; exceeds this phase. |
| Represent the absence of a risk decision by omitting the key or by emitting `not_assessed` | Omitting loses a uniform serialized representation; `not_assessed` attributes to the result a governance evaluation it does not contain. |
| Cover CSV/XLSX instead of, or in addition to, HTML/JSON | Changes the export and T3 scope; requires its own contract. |
| Copy sanitized warning messages | Improves readability; adds a free-text surface the result does not control and a sanitization step that cannot be verified. |

## Why this was the best at the time

A deterministic presentation of a computed result cannot invent fields the result does not carry, and it cannot turn index references into text that lives in the bundle. The chosen option is the only one that resolves that tension without touching the evaluator contract or the wire: an explicit auxiliary input bound by hash, with scope validation and fail-closed rejection. It keeps the three decision layers separate, preserves the evaluator's authority over states and affirmative links, and keeps the renderer as an unprivileged surface with no IO, network or file access. The maintenance cost (field coverage against result changes) is bounded and testable. Omitting free-text messages and blocking distribution are declared costs, not hidden ones. With synthetic evidence and in pre-alpha, this was the lowest-risk reversible option; any extension — report versioning, a redacted view, CSV/XLSX/VEX export — has its own gate and does not break what is ratified here.

## Consequences and limits

- Consumers of the report must supply the intact bundle that produced the evaluated result; the report alone is not self-sufficient for citation resolution.
- The report excludes evidence values, free-text warning messages, raw JSON, secrets, logs, environment values, ConfigMap data, argv and source errors; it preserves codes, classes, references and previously sanitized citations.
- **Not guaranteed:** authenticity of origin or authorship (an equal hash proves integrity, not provenance, and a fabricated result can pass structural validation), evaluation semantics (the renderer is not a second evaluator), universal redaction (there is no secret detector; authorization belongs to the producer and the caller), spreadsheet-import safety, public interoperability or a versioned report wire, issuance date or validity of a report, distribution of reports. The report is not the evidence bundle, not a decision record and not a risk acceptance.
- Operation of the report contract requires a successful evaluation result and its bundle, with the existing evaluator limits; widening the input boundary requires its own decision with its own limits.

## Revisit if

Revisit this record if the evaluator result or the bundle wire changes; a consumer needs a persistent report wire or public interoperability; identifiers or citations must be hidden (redacted view); CSV/XLSX/VEX/SARIF export is requested; issuance, validity or invalidation requirements appear; real volume requires its own limits; distribution of reports is requested — which will require a designated responsible owner and an access policy; or implementation finds contradictions with this contract. None of these conditions authorizes silently changing states, the wire or the evaluator.

## Normative detail

The full normative contract — the exact closed grammar, key orders, vocabulary lists, catalogue construction rules, validation preconditions, diagnostics and the execution instructions with their invariants and mutation list — lives in the internal two-layer record of the same number. This public summary is faithful and self-contained; it states the decision, its alternatives, its reasons and its limits, and it does not reference private material.
