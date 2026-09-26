# ADR-0012 — Evidence bundle integration precisions

- **Status**: accepted (2026-09-26)
- **Decision owner**: project owner

## Decision

Three precisions about how normalised `prisma-v1` facts become an evidence bundle. None of them changes the wire, the schema version or the golden vectors.

1. **Evidence items and value hashes have a fixed mapping.** Each non-empty CSV column becomes one evidence item whose type is the format selector plus the canonical column name (`prisma_v1.vulnerability_id`, `prisma_v1.package_name`, and so on, one per column), marked `observed`; the composed requested reference becomes an item marked `derived`. An observation contributes items only for the facts it carries: the raw image id (`observed`), the guaranteed digest (`derived`) and, when the platform is known, its OS and architecture (`observed`). `value` carries the exact bytes when they satisfy the wire rules; when they do not — only possible for optional text kept verbatim, such as surrounding whitespace — the item is emitted with a null value and the hash of those exact bytes, so the fact stays auditable without exposing it. An empty optional means "not informed" and produces no item. The `value_hash` preimage is fixed: `sha256:` plus the SHA-256 digest of the exact UTF-8 bytes of the value, with no normalisation.
2. **The source hash covers the complete source, and says so as far as it can.** The hash helper covers all bytes it is given, and the caller must hand over the complete source and parse exactly those bytes; the source path, its hash and an observation timestamp are required before any bundle is emitted. What the code cannot prove is that the hash belongs to the whole file: that proof belongs to the reviewed adapter that reads the source, exactly as with the provenance boundary of ADR-0010.
3. **Omissions are either partition or defect.** Findings with no attributable workload identity, or belonging to another subject, are simply outside a subject bundle: the run accounting stays intact and completeness does not change, and both classes are recorded in the builder's local diagnostics with a static reason. A defect inside the subject — an unrepresentable requested reference, an observation whose provenance is incomplete, or a scope collision already decided in ADR-0010 — is visible: the affected identity is left out, a static error is recorded and completeness becomes `partial`, so a bundle never looks complete while evidence was dropped.

## Refinement (2026-09-26)

Two precisions were added after the first implementation, without changing the wire or the schema version. First, the builder refuses any internal state that no normalisation run can produce: the state must be exactly the one derived from the import completeness and the resolution, the resolution state is validated on both paths — complete and incomplete, so an invented value is refused even when the bundle is emitted incomplete — and the finding's observation must be the same observation its resolution carries, so a hand-made inconsistent value is refused instead of being projected as facts. Second, the exclusion of a finding that belongs to another subject is not silent: it is recorded locally with a static reason, while coverage, completeness, warnings and errors stay untouched. A nil writer is likewise refused before any bytes are transported.

## Context

The wire contract (ADR-0006) fixed the shape of evidence items but left the meaning of `type`, `value` and `value_hash` open for imported findings, and ADR-0008 recorded explicitly that the parser's wire would need its own contract. Three questions were therefore open and each had a tempting shortcut: copy free-text columns verbatim into `value` (which the wire rejects for some values), hash whatever was read (a truncated file would look whole), or drop unprojectable findings silently (a `complete` bundle missing evidence).

## Options considered

| Question | Options | Choice |
|---|---|---|
| Finding mapping | One item per field / one aggregated item per record with an explicit payload / defer the mapping | One item per field |
| Source hash | Complete bytes held in memory and parsed from the same bytes / streaming with the hash confirmed before parsing / external proof by the producer | Complete bytes in memory |
| Omission erasure | Same visible pattern as the scope collision / fail the whole build / diagnostics only, nothing on the wire | Visible pattern, separating partition from defect |

An aggregated item would have introduced a nested payload contract the wire does not have; deferring the mapping would have left the task unfinished. Requiring an external proof of origin is not available before the observation adapter exists. Failing the whole build would lose a valid bundle over one identity, and keeping omissions only in local diagnostics would make a dropped finding invisible to anyone holding the bundle.

## Why this was the best at the time

- It closes the gap where it lives, without touching the frozen wire, the canonical form or the hash vectors, so no published hash changes.
- Every choice fails closed in the direction that matters: no fabricated source, no fabricated timestamp, no claim that a truncated read is a complete file, and no silent loss of evidence.
- It reuses already-ratified mechanisms instead of adding vocabulary: the warning code, the error list and the `partial` completeness are those of ADR-0006 and ADR-0010, and no new warning code is introduced for schema version 0.1.
- The mapping is mechanical and testable: one column, one type, one preimage rule.

## Consequences and limits

- A bundle carries more evidence items (one per informed column) and its hash changes whenever any declared fact changes — intended, since the hash covers the claims.
- **Not guaranteed**: that a source hash corresponds to a complete file, that an observation was verified against a live cluster, that every optional column appears as an item, or that the public specification has been published — the last one is deferred to its own task.
- A bundle with any projection defect inside its subject is emitted `partial` and carries visible errors; findings outside the subject never change completeness.
- The full representation of a collision or of a digest class in the wire is still deferred: it would require a schema version change and its own record.

## Revisit if

A real case needs an omission represented with typed vocabulary — a new warning code or field, a source proof stronger than the adapter's assertion, or a different completeness rule — any of which is a wire or contract change and needs its own record and schema version decision.
