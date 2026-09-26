# ADR-0005 — License: Apache-2.0

- **Status**: accepted (2026-09-23)
- **Decision owner**: project owner

## Decision

Ariadne is licensed under **Apache-2.0**. The license was chosen and recorded before the first public commit and before any external contribution.

## Context

The project targets enterprise adoption in security and platform teams of regulated environments. The owner also envisages an open-core model: the core stays open source, with paid support, integrations and private rule packs around it.

The license had to be fixed early because changing it later requires the consent of every contributor, which in practice makes the change impossible.

## Options considered

| Option | Why it was discarded |
|---|---|
| MIT | Simple and permissive, but it grants no explicit patent license — an avoidable friction point with corporate legal departments |
| AGPL-3.0 / GPL-3.0 | Strong copyleft would block competing hosted services, but many banking policies forbid or discourage the GPL family — the exact opposite of the target customer |
| Proprietary or source-available | Would prevent the adoption path the project depends on, and would foreclose community contribution |
| **Apache-2.0** | Chosen |

## Why this was the best at the time

1. **Maximum enterprise adoption**: it is the de facto standard in cloud-native projects (Kubernetes, Falco and others), and legal departments in regulated sectors are already familiar with it.
2. **Explicit patent grant**: removes a category of legal objection that MIT leaves open.
3. **Compatible with the intended business model**: support, integrations and private rule packs can be sold around an Apache-2.0 core without ambiguity about what may be commercialised.
4. **Clear trademark and contribution clauses** for a project that expects contributions.

## Consequences and limits

- The license is permissive: a third party could offer a service built on the core. That is accepted; the defence is specialisation and brand, not the license.
- Operational requirements follow: keep a `NOTICE` file if third-party attributed code is incorporated, and preserve Apache license headers when source files carry them.
- A future license change would require a new record and re-permission from every contributor.

## Revisit if

The business model changes in a way that requires a different licensing posture — which would need a new record, not an edit of this one.
