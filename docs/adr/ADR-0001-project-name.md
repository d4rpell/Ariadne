# ADR-0001 — Project name: Ariadne

- **Status**: accepted (2026-09-23)
- **Decision owner**: project owner

## Decision

The project is named **Ariadne**, with the tagline *“The thread through the CVE labyrinth”*.

## Context

The project needed a name for the repository, the Go module and the binary. The requirements were specific: a single-word name in the style of research-lab tooling (constellations, allusion, literary weight), connected to computer-science history, and tied to what the product actually does — carry a thread of evidence through a maze of findings.

The product's core metaphor was already fixed by the problem it solves: hundreds of vulnerability findings (the labyrinth) and a traceable chain from CVE to advisory, digest, workload UID and decision (the thread).

## Options considered

Verdandi, Aletheia, Memex, Aleph, Hopper, Perseus — all discarded in favour of a name that is explicitly about the thread and the maze rather than about a person, a promise or a generic computing reference.

## Why this was the best at the time

| Dimension | Connection |
|---|---|
| Mythology | Ariadne's thread: the guide that lets you enter the labyrinth and come out of it |
| Literature | The labyrinth as a central figure (Borges, Eco, Strauss/Hofmannsthal) |
| Computer history | The *thread* as the fundamental unit of execution |
| Naming | Corona Borealis, Ariadne's crown: a natural visual mark (seven stars joined by one thread) |

The name is short, no naming conflict is currently known in the Kubernetes/OpenShift security niche, and it carries the product promise without claiming a capability the tool does not have.

## Consequences and limits

- Stable name for the repository, the binary (`ariadne`) and the module path.
- Public documentation is written in English for international reach; internal notes stay in Spanish.
- Homonymous tools exist (a GraphQL library, academic projects) with no known conflict in this niche. If the project grew commercially, trademark checks in the software class should be repeated before registering a domain.
- The name is a metaphor, not a claim: it invites the “thread of evidence” reading and nothing more.

## Revisit if

A commercial launch makes trademark clearance necessary, or a naming conflict appears in the container-security market.
