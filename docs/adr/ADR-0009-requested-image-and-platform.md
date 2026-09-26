# ADR-0009 — Requested image composition and platform carrier

- **Status**: accepted (2026-09-25)
- **Decision owner**: project owner

## Decision

**Requested image.** The declared reference from an import is composed into the wire string with a single lexical rule:

```text
requested_image = registry + "/" + repository + (":" + tag if present)
```

- Nothing is normalised: no trimming, no lower-casing, no Unicode normalisation, no escaping, no percent-encoding.
- No implicit default is added; an absent tag means no tag, never `:latest`.
- Registry: a host, `host:port` (port 1–65535, leading zeros preserved) or a bracketed IPv6 literal validated strictly. Hosts must start and end with an alphanumeric character.
- Repository: one or more non-empty segments from an explicit ASCII allowlist (letters, digits, `.`, `-`, `_`); the relative segments `.` and `..` are rejected.
- Tag: `[A-Za-z_][A-Za-z0-9_.-]{0,127}`.
- An embedded digest (`@sha256:…`) is rejected: these columns describe a *requested* reference and never prove content identity.
- A declaration the grammar cannot represent is **refused, not repaired**: the components are preserved verbatim for diagnosis and the reference stays unrepresented, which blocks that image identity downstream instead of producing a plausible-looking string.

**Platform.** An observed platform is carried by two internal fields (`os` and `architecture`) alongside the status. A `known` platform requires both fields, observed and valid, **and** a digest proven by the source. An `unknown` platform may not carry an observed value. Nothing is ever inferred from the host, the build, the process architecture, a tag or a digest.

## Context

Two gaps blocked the layer that builds the bundle:

- The import gives the image as three separate declared columns, while the wire has one string. Any composition would be a grammar decision, and there was no ratified grammar: registry normalisation, default tags, ports, digests inside the name.
- The wire requires `os` and `architecture` when the platform status is `known`, but the internal observation only carried the status, so a genuinely observed platform could not be represented at all.

## Options considered

| Option | Why it was discarded |
|---|---|
| Do not compose the reference, defer to the consumer | Keeps the ambiguity alive and forces someone else to invent the grammar later |
| Permissive composition (join the parts, accept anything) | Produces plausible-looking references from ambiguous input — exactly the failure mode the evidence model exists to prevent |
| Change the wire to a structured object | More faithful to the input, but it is a schema change with new canonical bytes, new golden vectors and a compatibility surface, for no gain in verifiability |
| Keep `known` platforms blocked forever | Safe but needlessly lossy: an observed platform is the strongest evidence available |
| **Strict lexical composition plus an explicit internal platform carrier** | Chosen |

## Why this was the best at the time

- A single lexical rule is decidable and testable byte by byte; every accepted input has exactly one output, and everything else fails visibly.
- Refusing rather than repairing preserves the property that matters: the tool never manufactures a reference that looks authoritative but is a guess.
- Carrying the platform internally, and projecting it to the existing wire fields, fixes the gap **without touching the wire**, the schema version or any existing golden vector.
- Requiring a proven digest for a `known` platform keeps the two facts tied together: a platform claim without content proof is not usable.

## Consequences and limits

- Some real declarations will be rejected if they use characters outside the allowlist. That is a deliberate trade in favour of unambiguity, and the components remain available for diagnosis.
- The grammar bounds *shape*, not *size*: the size bound comes from the input format's per-field limit. A serialized-reference limit imposed by a remote registry is out of scope here.
- An index digest (a multi-arch manifest list) is never a per-platform manifest, so it never becomes a normalised digest; it is preserved as the observed raw image id with an unknown platform.
- The internal carrier validates *form and combination*, not *provenance*: the type cannot prove that the observation came from a real cluster. That boundary is the subject of ADR-0010.

## Revisit if

A real declaration is rejected that cannot be safely represented, or a consumer needs the requested reference as structured data — either would justify a new record, and a wire change would require a schema version decision.
