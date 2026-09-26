# ADR-0006 — Evidence bundle wire contract, canonical form and hash

- **Status**: accepted (2026-09-24)
- **Decision owner**: project owner

## Decision

The evidence bundle has a **canonical JSON wire form** and a **SHA-256 hash over a defined projection**. Concretely: field names in `snake_case` with a fixed key order, a `schema_version` of the form `MAJOR.MINOR` interpreted fail-closed, a canonical serialization with no HTML escaping, no BOM, no added whitespace and no trailing newline, and a hash computed over a projection that covers the provenance claims while excluding operational metadata.

Warnings are typed objects (`code`, `class`, `message`) rather than free strings, and completeness is defined **relative to the method that produced the evidence**.

## Context

The type model of the contract existed, but eight questions were still open, and each of them changed the bytes on the wire: the scope of the hash, how absent optional fields are represented, the grammar of the scope object, the order of collections, the hashing algorithm, the schema version grammar, how an unobserved container category is represented, and how warnings are classified.

Without those answers there can be no canonical serialization, no stable hash, no byte-for-byte golden fixtures and no way to re-run an evaluation and compare results — which is the product's core determinism promise.

## Options considered

1. **Multiple wire forms** (per-consumer serializers). Discarded: several ways to say the same thing make the hash ambiguous and the audit worthless.
2. **Hash the whole document including operational metadata** (timestamps of the run, budgets, sanitized argv). Discarded: those fields change between identical evaluations and would break reproducibility; they are operational metadata, not claims about the subject.
3. **Free-text warnings**. Discarded: a warning that cannot be classified cannot be guaranteed to block a favourable conclusion.
4. **Canonical form plus a claimed-projection hash, with typed warnings and method-relative completeness** — chosen.

## Why this was the best at the time

- Hashing exactly the claims (and not the operational noise) is what makes “same bundle plus same rules equals the same result” testable rather than aspirational.
- Fixed key order and strict escaping rules remove any dependency on the serializer implementation, so a third party can reproduce the bytes with a different tool.
- A closed, typed warning vocabulary with an explicit blocking rule converts “there is something odd here” into a machine-checkable condition: a contradiction or an unknown warning code cannot silently coexist with a favourable conclusion.
- Method-relative completeness prevents the most dangerous misreading: a complete findings import is not a complete inventory of a cluster.

## Consequences and limits

- Any change to the canonical bytes requires a schema version decision and new golden vectors; it can never be a silent edit.
- The hash proves **integrity of the bundle**, not authenticity of its origin nor of the cluster it describes. Provenance is carried by the evidence items themselves.
- Golden vectors pin the canonical serialization and hash behaviour, so a change in either is visible as a change in the vectors.
- Optional run timestamps are emitted as `null` when absent and are excluded from the hash projection, so the envelope can change while the digest does not.

## Revisit if

A consumer fundamentally requires a different wire form (for example a binary format), or a field must move between the claimed projection and the operational metadata — both need a new record and a schema version decision.
