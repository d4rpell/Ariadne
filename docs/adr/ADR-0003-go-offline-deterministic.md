# ADR-0003 — Go, offline, deterministic, single binary

- **Status**: accepted (2026-09-23)
- **Decision owner**: project owner

## Decision

Ariadne is **designed as** a Go CLI distributed as a single binary, with a core that is **fully offline**: the first milestone does not connect to any cluster, it consumes sanitized exports. The evaluator is **deterministic by design** — same evidence bundle plus same rules equals the same result, byte for byte and verifiable by re-running it — and rule packs are declarative, versioned, hashed and fail-closed. **The CLI and evaluator are not implemented yet**: this record fixes the choice of language, distribution model and execution model, not shipped capabilities.

## Context

The product must run in regulated environments: virtual desktops, jump hosts, air-gapped clusters. It must be distributable by a platform engineering team that cannot install runtimes or resolve dependencies on those hosts, and its output must be auditable months later.

## Options considered

| Option | Why it was discarded |
|---|---|
| Python | Distribution is fragile exactly where the tool must run: interpreter, dependency resolution and packaging on hosts without internet |
| Rust | Technically viable; the Kubernetes CLI ecosystem and the expected contributor profile favour Go |
| A web service | Larger operational and security surface, and the tool would depend on infrastructure the target environments try to minimise |

## Why this was the best at the time

- A single static binary is trivially distributable to a jump host with no internet and no package manager.
- Determinism is what makes an audit possible: a reviewer can re-run the same bundle and get the identical result.
- Declarative rules are meant to let security teams review *what* is asserted without reading source code, which is also what should make the evaluator auditable by a security committee.

## Consequences and limits

- Determinism becomes a product feature **and** a test requirement: golden fixtures, a re-execution check, and a canonical, hashable serialization of the bundle.
- The cost of the decision is commitment: the canonical serialization must stay stable across versions, with explicit migration rules tied to a versioned schema.
- The evaluator is designed to have no network and no shell access, so a rule pack cannot become a way to reach data or execute anything.
- “Deterministic” refers to the evaluation, not to the inputs: garbage in still produces garbage out with a valid hash. The hash proves integrity of the bundle, not authenticity of its origin.

## Revisit if

The tool must run inside a platform where binaries cannot be installed (for example a managed pipeline that only accepts containers), or a hosted offering becomes a requirement.
