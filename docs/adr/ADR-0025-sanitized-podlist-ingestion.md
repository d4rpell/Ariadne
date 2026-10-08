# ADR-0025: Offline ingestion of sanitized PodList exports

- **Status:** ratified by the owner on 2026-09-30 after an independent review closed with no open finding (0 P0, 0 P1, 0 P2, 0 P3). **Implemented and accepted by the owner on 2026-09-30** (F2): the profile, the strict reader, the observation projection and the import-boundary gate exist in `internal/schema`, `internal/ingest`, `internal/identity`, `internal/normalize` and `internal/bundle`, with the first-class test plan of this record, nine golden triplets verified by an independent projection oracle and a mutation corpus of 29 red instances with byte-identical restoration. The independent review of the implementation closed with `apto` (0 P0, 0 P1, 0 P2, 0 P3) on the corrected delta; the published tree passed the offline CI gates (run `36763660870`, job `offline gates (linux/amd64)`, `completed`/`success`). This record changes no evidence wire version, no decision state and no accepted contract. Distribution of bundles or reports and any release remain unauthorized.

> **Distribution clause superseded (2026-10-08):** the statement that distribution of the reports, bundles or exported documents is “not authorized” was withdrawn from the product presentation and from the current-state documentation by [ADR-0039](ADR-0039-state-label-and-distribution-scope.md). The rationale and dated text below are retained as history; the security and accuracy limits of this record still stand.
- **Related records:** develops ADR-0011 (two-layer decision records), ADR-0006/0007/0008 (input schema and ingestion limits precedent), ADR-0009 (requested image and platform carrier), ADR-0010 (provenance, scope collision, digest class) and ADR-0023 (deferred CLI surface). No accepted record is superseded.

## Decision

Admit a single, explicitly selected input profile, `sanitized-podlist-v1/1.0`, over a JSON document `apiVersion: "v1"`, `kind: "PodList"` that an operator has already sanitized. The library produces typed observations, sanitized diagnostics and a conservative projection to the existing bundle wire `0.2`.

The profile keeps identity by pod UID, container class and container name; keeps requested image, status image and `imageID` separate; rejects any field outside a closed per-path allowlist; keeps capture termination and container-category coverage explicit; and never derives a guaranteed digest or a known platform from a PodList alone.

## Context

The current input contract covers a versioned CSV findings format. A Kubernetes export is a different input family with its own trust questions: JSON validity does not prove redaction, identity, capture completeness, freshness or digest class. Adding it required its own decision record instead of an extension of the existing one.

The available wire already represents observed images, coverage and failures, but it has no ratified catalogue for every pod field. The decision therefore projects only into the existing vocabulary and leaves the rest as internal context.

## Options considered

1. **Read the general Kubernetes JSON with an open field set.** Rejected: it would let a successful parse legitimize a document containing data outside the authorized scope.
2. **Heuristically clean unknown fields inside the parser.** Rejected: redaction is an operator obligation performed before persistence; the parser cannot verify how a file was produced.
3. **Declare a closed profile over an already-sanitized PodList, with a closed allowlist and a private strict JSON reader.** Chosen: it makes the accepted input auditable, keeps the existing wire and states unchanged, and keeps offline and deterministic behavior.

A separate envelope format was also rejected to avoid introducing a new persistent document type.

## Why this was the best choice now

The profile keeps every guarantee the project already relies on: strict, versioned, fail-closed input handling; evidence tied to a pod UID and container; requested and observed image fields kept apart; no promotion of an ambiguous digest; and incomplete capture never producing a favorable conclusion. It adds no new wire vocabulary, no new decision state and no new dependency, and it enables a set of already approved synthetic fixtures without inventing identity or fabricating a subject.

Its costs are explicit: a strict pre-transformation step is required; exports containing extra fields are rejected rather than filtered; part of the observed context stays outside bundle evidence items; and a platform manifest cannot be established from a PodList alone.

## Consequences and limits

- The profile does not certify Kubernetes or OpenShift compatibility, and its acceptance is not a compatibility matrix.
- It does not detect secrets hidden inside fields the allowlist does permit; that redaction remains an operator obligation.
- It does not prove that a local, complete file reflects a complete remote capture, and its source hash covers the sanitized artifact, not a remote response.
- It does not guarantee memory bounds: limits are budgets, and a blocking reader remains the caller's responsibility.
- Persisting the fields kept as internal context as new evidence types, or making them necessary for a conclusion, requires a new decision record and a wire version change.
- Tests written against this profile do not by themselves prove a real collector, a real cluster or cross-platform replay.

Conditions that would justify reopening this record: needing another resource, version, field or input shape; accepting omissions as explicit empty categories; requiring pagination or multi-capture composition; using readiness, state, owner references or resource version as evidence items; obtaining a producer able to prove manifest and platform; or any relaxation of redaction, import or error handling.

## Revision conditions and history

The record was independently reviewed before ratification: first pass `no apto` (one finding where scope-collision completeness could contradict the existing wire rule that an unknown capture termination implies unknown completeness), then `apto tras corregir`, then `apto` with no open finding. The corrections kept the wire, limits and the existing evaluator and rule-pack import policies unchanged.
