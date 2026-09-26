# ADR-0010 — Provenance boundary, container scope collision, digest class

- **Status**: accepted (2026-09-25)
- **Decision owner**: project owner

## Decision

Three integration rules, none of which changes the wire:

1. **Provenance is established by evidence items, not by an internal type.** The internal observation structure validates *form and combination*, never *origin*. What proves where a value came from is the evidence item's `source`, `source_hash`, `locator` and `observed_at`, plus the bundle's provenance hash. Presenting an internal resolution as proof of origin is forbidden.
2. **A container scope collision is omitted visibly, not merged.** If the same workload UID carries the same container name in more than one container class (regular, init, ephemeral), the wire scope cannot tell them apart. The affected identity and its evidence are left out of the emitted bundle, the rest of the subject is projected normally, and the omission is reported: completeness becomes `partial`, and a warning `scope_mismatch` of class `contradictory` is recorded with a static message plus the affected classes in canonical order — never the UID or the container name. A `contradictory` warning blocks any favourable conclusion. Three or more classes produce one omission and one warning for that key.
3. **An index digest is never a guaranteed digest.** `normalized_digest` means “the source proved this digest references the artifact content for the observed platform”. A multi-arch index digest does not satisfy that, so it is preserved as the observed raw image id with an unknown platform, and no conclusion is transferred between platforms.

## Context

Three questions remained open about how the internal, normalised facts become bundle claims. Each has a tempting shortcut and each shortcut would silently weaken the evidence model:

- If provenance is assumed from the type, the tool implicitly claims “this came from the cluster” when it only knows “this value is well formed”.
- If two containers share a name across classes, a single name-based scope makes some evidence ambiguous; merging them would attribute evidence to the wrong container.
- If an index digest is treated as a per-platform digest, a CVE conclusion can be carried across platforms that were never observed.

## Options considered

| Question | Options | Choice |
|---|---|---|
| Provenance | Document the boundary / encapsulate the internal type / build a public observation API | Document the boundary |
| Scope collision | Omit visibly / add a class field to the wire / encode the class inside the container name | Omit visibly |
| Digest class | Rule “index never guaranteed” / internal metadata only / add a field to the wire | Rule “index never guaranteed” |

Encapsulating the internal type, or exposing a constructor-based observation API, does **not** create a provenance guarantee: a constructor taking plain values is just as forgeable by its caller. The guarantee has to come from the layer that reads the source.

## Why this was the best at the time

- It fixes each gap where it actually lives instead of enlarging the wire: no schema change, no golden vectors regenerated, no compatibility surface.
- All three rules fail closed in the direction that matters — no claim is made that cannot be supported — **retaining the observation internally and omitting the colliding identity and its evidence from the emitted bundle**, rather than merging it into a plausible-looking scope.
- Omission with a visible, typed warning follows the pattern already used for partial results elsewhere in the contract, so no new vocabulary was needed.
- Adding a class field to the scope, or a digest-class field to the wire, remains available as a complete fix if a real case appears; it is deferred rather than rejected, and it would require its own record.

## Consequences and limits

- The tool cannot claim, anywhere, that an observation was verified against a live cluster until the adapter that reads a source defines how it is proven.
- A bundle whose subject has a colliding container scope is emitted incomplete and carries a warning that blocks a favourable conclusion. This is visible, not silent.
- Multi-arch conclusions are conservative: without a proven per-platform manifest, the platform stays `unknown` and the digest stays raw.
- The rule applies from the moment bundles exist: an emitted bundle is never rewritten — it keeps its hash and its history — and validity is re-opened through the normal invalidation rules rather than by editing the record.

## Revisit if

A real workload hits a scope collision that must be represented rather than omitted, or a consumer must distinguish an index digest from a per-platform manifest — both require a wire change, a schema version decision and a new record.
