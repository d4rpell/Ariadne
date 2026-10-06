# ADR-0033: Bundle signing as a separate evolution

**Status: Ratified on 2026-10-06 by the owner** (proposed 2026-10-05). Independently reviewed (`apto`, 0 P0/0 P1) and published on 2026-10-05; owner ratification granted on 2026-10-06 and recorded locally (no further commit/push). Task A3-05. **No implementation is part of this decision**: it adds no wire fields, states, CLI commands or dependencies; any future implementation requires a new ADR with its own authorization.

## Proposed decision

1. Bundle signing is treated as a **separate evolution**, outside the MVP and outside the phases ratified so far. It is not implemented in this task.
2. Recommended direction: a **detached signature over the exact bytes of the hashable projection** — the same bytes covered by the `sha256:` digest of ADR-0006 — with **offline, fail-closed verification**.
3. The **trust anchor is supplied by the caller**: a public key (or key identifier) with its explicit policy. Ariadne never discovers, contacts or rates keys over the network, and does not become a trust authority.
4. **What signature verification attests** (once it exists): only that "these bytes were signed with key K at the instant T declared by the signature itself". It does **not** attest the authenticity of the cluster or of the origin of the observations, does **not** replace per-item provenance (ADR-0010/ADR-0012), does **not** change digest semantics, and does **not** authorize distribution of bundles.
5. **Fail-closed**: without a declared trust anchor, or with a missing/invalid signature, the consumer treats the bundle as **not authenticated** — never "verified by default". The base guarantee remains bundle integrity via the digest; signing is an opt-in addition that may only be claimed after verification.
6. **Implementation requires a new ADR**: key and trust-anchor model, signature format and anchoring mechanism (sidecar or envelope field), expiry/revocation handling, interaction with `verify`/replay (ADR-0023), budgets and a test plan. Any wire change requires a `schema_version` bump (ADR-0016) and a recorded contract change.

## Context

- Threat T10 records the known gap: "false authenticity by trusting a local hash". The current control states that the bundle hash proves bundle integrity, not the origin or the cluster, and defers signing as an evolution.
- ADR-0006: input hashes and provenance provide traceability, not authenticity. The public wire specification 0.2 states the digest proves integrity of the projection bytes and does not authenticate an origin.
- ADR-0023 (`verify`): the hashes do not authenticate origin, author or policy; detecting a coordinated substitution of bundle and digest requires a previously trusted digest or another authenticity mechanism. Within Ariadne, a coordinated substitution of bundle, digest and declared fingerprint is indetectable by design today.
- ADR-0017 explicitly reserved reopening authenticity claims through signatures for a new ADR; this is that evaluation.
- Current reality: offline product (ADR-0003), single binary, no network in evaluator/report/interop (import gates verified in CI), stable wire 0.2, and **distribution of reports and bundles is not authorized**. Ariadne operates no PKI and no transparency services.

## Options considered

- **O1 — Keep the hash only** (status quo with the documented limit). Rejected as an end state: it leaves the T10 attack class (coordinated bundle+digest substitution by whoever controls the delivery channel) with no defensive direction, and the requested evaluation requires a decision.
- **O2 — Detached signature over the hashable projection**, offline verification with a caller-supplied trust anchor, as a separate evolution behind a future implementation ADR. **Recommended.**
- **O3 — Integration with external signing frameworks** (Sigstore/cosign, Notary v2): introduces dependencies on transparency/network services and a third-party trust root; conflicts with the offline and deterministic posture of ADR-0003 and adds its own supply-chain surface. Not as a base; may be re-evaluated as an optional future layer if the use case appears.
- **O4 — Embedded envelope signature (PKI/X.509) with new wire fields now**: an immediate contract change with no authorized use case (distribution is not authorized), high cost, and risk of premature design over a stable wire.
- **O5 — Do not decide** (leave the debt directionless): violates the project's decision-record policy for a question already opened by T10 and ADR-0017 with a named owner.

## Why this was the best option at the time

- **Reversibility**: O2 changes no wire, states, errors or gates; it fixes direction and conditions. Any reversal is documentary.
- **Fit**: offline, deterministic verification is compatible with ADR-0003; the caller-supplied anchor keeps Ariadne a verifier, not an authority; the signature covers the same bytes as the digest, so digest meaning is neither duplicated nor weakened.
- **Cost**: zero implementation now; the detailed design (signature format, sidecar vs envelope, revocation) is decided in the implementation ADR, with a real use case in front.
- **Risk**: it addresses the T10 class without overclaiming — it attests key control over the bytes, not the truth of the content nor the origin of the observations; the risk decision remains human (layer 3).

## Consequences and limits

**What it buys:** a recorded direction; stable vocabulary separating integrity (digest) from authentication (signature); explicit conditions for the future implementation ADR and its gates.

**What it does not guarantee** (nor will future signing):

- Authenticity of the cluster, of the observation origin, or of the truth of the signed content: a signer only attests key control at the declared instant.
- Non-repudiation beyond key control (without key policy/HSM, attribution is weak).
- Confidentiality: a signature neither encrypts nor protects content.
- Authorization to distribute bundles/reports; that authorization remains separate.
- This decision does not change `evaluate`/`report`: today `verify` measures integrity and authentication stays separate and declared; whether authentication becomes a consumer requirement will be fixed by the implementation ADR's contract.

**Limits of this ADR:** no implementation, no wire fields, no changes to the CLI, errors, budgets or existing tests. All concrete design belongs to the implementation ADR.

## Review conditions

Reopen this decision if:

1. Distribution of bundles/reports to third parties is authorized (a delivery channel outside the producer's control appears).
2. A real multi-actor flow appears where the bundle producer and consumer are different parties.
3. A customer requires a signed chain of custody as a contractual requirement.
4. A reference standard whose adoption makes sense appears (O3 will be re-evaluated with its real cost).

The implementation ADR must define, at minimum: key and trust-anchor model; signature format and anchoring mechanism (sidecar or envelope); expiry and revocation; interaction with `verify`/replay of ADR-0023; budgets and fail-closed behavior; and its own test and mutation plan.

## Relations and acceptance

- **Depends on**: ADR-0003, ADR-0006, ADR-0016, ADR-0023.
- **Completes** the evaluation opened by threat T10 and ADR-0017.
- **Respects**: ADR-0024, ADR-0022 and ADR-0019 Q-07 (distribution not authorized); ADR-0010 (signing covers projection bytes and does not change content digest-class semantics).
- **Supersedes**: nothing. **Superseded by**: nothing.
- **Acceptance**: ratified by the owner on 2026-10-06 after independent review.
