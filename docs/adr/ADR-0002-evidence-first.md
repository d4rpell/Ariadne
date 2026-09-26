# ADR-0002 — Evidence-first: post-processor, not scanner or exploiter

- **Status**: accepted (2026-09-23)
- **Decision owner**: project owner

## Decision

Ariadne is an **evidence post-processor** by design. It consumes findings (scanner CSV, sanitized cluster exports, advisories) and is intended to produce reproducible records: technical status, exploitability conditions and a human exception decision with validity. It does **not** scan images, does **not** run exploits or kill chains, does **not** generate attack scripts and does **not** compete with scanners — it consumes them.

## Context

Scanning, prioritisation and runtime security are already covered by established products. The observed pain sits *after* the scanner: turning a finding into a decision that can be defended and that stays valid in a regulated environment. In those environments the chain is verified by hand — export the CSV, find the pod, check whether the running digest is the scanned one, separate the requested tag from the real `imageID`, write the justification, and re-validate when the digest changes.

One alternative was considered seriously: automating exploitation attempts per CVE to “prove” exploitability.

## Options considered

1. **Automated exploitation / kill chains** to demonstrate exploitability. Discarded: a failed step proves nothing about absence of exposure, so it produces false negatives while running offensive code in production — an unacceptable risk.
2. **Another scanner** (image or runtime). Discarded: crowded market, and it would not address the evidence gap.
3. **Evidence post-processor with a human decision layer** — chosen.

## Why this was the best at the time

- It targets the part of the chain that is still manual, repetitive and auditable — the part a regulated environment actually pays for.
- It avoids the two structural problems of the discarded alternative: false negatives from failed checks, and the reputational and contractual risk of executing offensive code in production.
- It composes with what customers already own, so adoption does not require replacing a scanner.

## Consequences and limits

- The honest guarantee is *traceable evidence and declared uncertainty* (`unknown`), never “zero false positives”.
- Technical status is limited to what can be demonstrated from outside the container; the missing introspection is compensated with declared `unknown`, not with assumptions.
- The commercial differentiation (reproducible record, air-gapped operation, Red Hat semantics) is a **hypothesis**, not a measured fact; it is to be validated with real cases.
- **Implementation status**: the pipeline described here is a design target. What exists today is the evidence contract and its canonical form, the input parser for one format, and the normalization and identity layer; the evaluator, the reports and the CLI do not exist yet.

## Revisit if

Interviews or adoption data show that the evidence gap is not the actual pain, or that a capability explicitly excluded here turns out to be the deciding purchase criterion.
