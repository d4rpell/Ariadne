# ADR-0018: Domain context and profile recognition

- **Status**: **accepted under authority delegated by the project owner, 2026-09-26**. The domain context limits and the bounded profile recognition exist in the repository since 2026-09-27 (`internal/evaluator`, `internal/rulepack`), pending the closing independent review and the owner's acceptance of the task. Nothing is distributed or released; Ariadne remains pre-alpha. This decision alone does not authorize implementation or distribution.
- **Decision owner**: project owner (delegated decision on this point).
- **Related records**: extends the previously unspecified context combinations of ADR-0015 and replaces its pending proposal on those combinations; preserves ADR-0013 error meanings and admission order, ADR-0016, and the corrected rule that pack hash verification precedes schema admission. Recorded under ADR-0011. No successor is recorded.
- **Independent review**: pending. The proposal and the design review of the execution plan come from the same session, so this record is not yet independently reviewed.

## Decision

**`DomainContext` is required for the `product-evidence-v1` profile and rejected when supplied to `evidence-readiness-v1`.** Rejection uses `invalid_context`. The legacy profile keeps its contract and does not retain domain context in its result.

To apply that rule, a **strict, bounded, non-admitting profile recognition** is fixed. It reuses the pack scanner over the complete document, serves only to determine which context contract applies, and never authenticates bytes, checks bundle/profile compatibility, executes rules or produces an admissible pack.

## Context

The profile only appears in the pack bytes, but context validation precedes bundle and pack admission. The `Request` has no separate profile selector. A profile that cannot be determined does not allow inferring an obligation of presence. A malformed syntax is not the same as unknown vocabulary, and the error codes remain closed.

## Recognition

After input limits, reuse the bounded strict scanner on the complete document, with its existing limits (1 MiB, depth 8, 20,000 tokens, 256-byte strings). Recognize only an object root with exact string schema `0.1` and an exact known profile string (`evidence-readiness-v1` or `product-evidence-v1`). Compare decoded keys. Duplicate keys at any depth, malformed or incomplete JSON, exceeded scanner limits, missing or incorrectly typed header fields, or unknown schema/profile prevent recognition.

Other schema validation is not required merely to identify the header. Do not use substrings, regular expressions or a permissive parser. Recognition returns only a classification, never an admitted pack, and performs no bundle/profile compatibility check. Recognition errors remain deferred to their existing admission phase: a scanner limit is not advanced ahead of the pack hash.

A recognizable header may cause `invalid_context` before the pack hash is checked, as the context phase requires. It can **never** cause the profile/version compatibility error before the hash is checked.

## Order and diagnostics

1. Input limits, counting all supplied context regardless of profile: more than 128 pins or more than 4,096 joint bytes is `input_limit` with a zero result.
2. Context and target: admission context, supplied domain context form, profile-dependent presence, and target. Invalid form, required absence or forbidden presence is `invalid_context`; target errors keep `invalid_target`. Within domain context, maximum age is validated before source pins, and nothing is ordered or copied before limits are checked.
3. Bundle validity and integrity: `invalid_bundle`, `bundle_hash_mismatch`, `value_hash_mismatch`.
4. Pack presence and hash: `missing_pack` for no bytes, `pack_hash_mismatch` for different bytes.
5. Pack syntax, schema and profile, then bundle compatibility: `invalid_pack` for syntax, types, fields, parameters and illegal combinations; `unsupported_pack` for unknown schema, profile, predicate, requirement or emission. Once known vocabulary is resolved, a product profile with a bundle other than `0.2` yields `invalid_pack`.
6. Identity and version policy, validity, ruleset linkage, evaluation budgets and result.

The joint 4,096-byte and 128-pin limits remain unchanged. No error code is added. Every rejection returns a zero result: no partial result, no candidates, no evaluation bytes or hash.

## Alternatives and rationale

Silently ignoring context hides caller errors and would let a supplied time-to-live be mistaken for effective validity. Accepting unrelated context would require additional legacy replay behavior and budget rules for a datum outside its contract. A `Request` selector creates two profile authorities. Substring recognition is ambiguous. Requiring context for every request changes legacy behavior; checking only after full admission changes error precedence and would let expiry win over an invalid context.

Strict classification with explicit rejection preserves the existing boundaries at bounded cost, and distinguishes the internal order of a bounded inspection from the contractual order of errors and admission. A new record is used because these are observable admission rules, not an editorial correction.

## Consequences and limits

- Recognition may require an additional bounded pass over the pack. No performance, memory or benchmark is promised, and no caching or external token path is introduced.
- **Not guaranteed**: authenticity of the header or of any source, material sufficiency, signatures, revocation, or that preliminary classification equals admission. Recognizing a header does not authenticate its bytes.
- No wire format, state, enum, resource limit, trusted source, evidence-verification duty, privilege, network access or public evaluation format changes. No real producer is introduced.
- Changing these rules after implementation requires a successor decision. The options are reversible before implementation.

## Review conditions

Additional schema/profile pairs, a need to accept legacy context or a separate selector, different error priorities, or inability to share strict recognition within existing bounds. Changes to states, wire, security limits or evidence-verification obligations require an owner decision before implementation.

## Normative detail

This record fixes the context-combination rules and the bounded recognition needed to apply them. The full admission contract remains ADR-0013; the domain contract remains ADR-0015; the wire versioning remains ADR-0016. Implementation, its tests and the synthetic corpus are separate work.
