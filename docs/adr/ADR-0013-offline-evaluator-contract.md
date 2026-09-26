# ADR-0013: Initial offline evaluator contract

- **Status:** **ratified by the owner on 2026-09-26** and **implemented** as the initial conservative profile of the offline evaluator. The independent review of that implementation is still in progress, so the decision is ratified while its acceptance is pending.
- **Related records:** depends on ADR-0003, ADR-0004, ADR-0006, ADR-0010, ADR-0011 and ADR-0012; paired with the ratified ADR-0014. No accepted record is superseded.
- **Reading this record:** the sections below are the text that was ratified, written while the decision was still a proposal; a sentence in the proposal tense describes what was decided, not pending work. The superseded state lines were: "the earlier state line said the record was proposed and awaiting ratification, and that the evaluator and pack admission were not implemented. Both statements described the proposal stage and are superseded by the status line above. The sections below keep their original wording as the record of what was decided."

## Decision

Introduce a conservative evidence-checking profile with strict JSON rule packs, explicit admission policy and reproducible internal results. This initial profile would return only `product_status=under_investigation` and `exploitability=not_assessed`; it would neither make risk decisions nor infer affirmative product conclusions from scanner fields.

This is a reduction of the first evaluator delivery, not completion of the full evaluator. Supporting `affected`, `fixed` or `not_affected` requires a separate contract for domain evidence and predicates. Those states remain distinct in the product model.

## Context

The existing bundle records scanner facts, image identity, provenance and method-specific coverage. Importing a complete file does not establish complete runtime inventory, advisory applicability or a deployed fix. A scanner's fix label and the presence of a package are insufficient to establish the product's technical status.

ADR-0006 separates evaluation from the evidence bundle and defers its public record format. The proposed initial result would remain internal; it would not be a VEX statement, exception record or public evaluation wire format.

## Contract

Packs would use a closed JSON schema and predicate vocabulary, with typed parameters and no executable expressions, callbacks, includes or external resolution. The initial predicates would check exact finding values and substantiated image digest/platform identity. Missing, redacted, unavailable or conflicting evidence would remain unknown. No predicate would turn an unobserved value into proof of absence.

The proposed pack schema is `0.1`, with profile `evidence-readiness-v1`. Packs would include an ID, a positive integer version, a validity interval and rules with explicit prerequisites. Every rule would fix both its output and `on_missing_evidence` to `under_investigation`. Other output states would be rejected, rather than resolved through an implicit rule priority.

Admission would verify SHA-256 over the exact pack bytes against an independently supplied pin. It would reject malformed packs, unsupported schema or predicates, hash mismatches, expired or not-yet-valid packs, version rollback and same-version content changes relative to supplied policy. Rejection would produce no evaluation result. A valid pack with missing evidence or no applicable rule would instead produce an inconclusive result with reasons.

Time, the minimum permitted version and any previously accepted version/hash would be explicit inputs. Reproducibility means the same canonical bundle, pack bytes, target, admission context and engine/profile version produce the same result. There would be no hidden clock or persistent state in the evaluator. Protection against rollback is limited to the supplied policy; durable protection of that policy is a later integration responsibility.

Evidence references would remain tied to the bundle hash and exact subject/container and finding provenance. Fields from different source rows would not be combined to manufacture evidence. Existing contradictory warnings and unknown warning codes would remain visible and could not justify `not_affected`. The evaluator would not modify the original bundle to attach its result or ruleset.

The proposal includes bounded parsing and evaluation: 1 MiB per pack, 128 rules, 32 checks per rule, bounded strings and JSON depth, and explicit bundle and evaluation-work budgets. Exceeding a budget would reject evaluation without discarding the original evidence. These proposed budgets have not been benchmarked and do not guarantee a fixed memory footprint.

Pack admission and evaluation would have separate pure components under the same network, shell and cluster-access restrictions. File acquisition and trusted policy storage would remain outside the evaluator.

## Options considered

| Option | Trade-off |
|---|---|
| Conservative initial profile — recommended | Establishes admission, evidence checks and reproducibility now; delays affirmative product assessment |
| Full evaluator plus a new domain-evidence contract | More immediate functionality, but requires adequate advisory/product/version evidence and a larger security review |
| Generic field comparisons allowed to emit any product status | Small implementation, but permits unsupported conclusions from scanner labels or missing data; rejected |
| Delay all evaluator work | Avoids an intermediate profile, but also delays pack integrity and isolation controls |

Strict JSON is proposed instead of the earlier illustrative YAML format to avoid adding a parser dependency and extra language constructs. A strictly constrained YAML format remains an alternative requiring explicit selection and review; there would be no handwritten YAML parser.

## Why this was recommended then

The proposal followed the evidence available at the time. It makes integrity failures distinguishable from valid but inconclusive assessments without inventing proofs of applicability, remediation or absence. The smaller initial contract is easier to review and can be extended through a new version and decision record.

The cost is material: a successful check is not a completed vulnerability assessment. The full evaluator must not be presented as delivered when only this profile exists.

## Consequences and limits

The initial profile does not establish source authenticity, scanner correctness, workload freshness, exploitability, durable anti-rollback protection or acceptance of risk. Hashes bind bytes; they do not authenticate the cluster or the author of a pack. Existing redaction remains the responsibility of evidence producers; the evaluator would add static reasons and references rather than echo untrusted values in diagnostics.

No public evaluation format, lifecycle, evaluation golden files or CLI verification command is frozen by this record. Internal reproducibility checks are not a public compatibility promise.

## Revisit if

Adequate domain evidence becomes available; affirmative conclusions are needed; measured budgets prove unsuitable; YAML authoring or multiple packs become necessary; trusted policy storage is integrated; or a public evaluation format is ready for a separate decision.

## Normative detail

This record fixes the contract of the initial profile; the normative detail of the admitted surface is the ratified decision, not this summary. Verification of the implementation and its acceptance are separate steps. ADR-0006 continues to govern the evidence bundle; its bytes and version are unchanged by this decision.
