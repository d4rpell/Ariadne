# ADR-0011 — Two-layer decision record

- **Status**: accepted (2026-09-25)
- **Decision owner**: project owner

## Decision

Every decision about the project is recorded **on the day it is taken**, in two layers sharing one number:

1. **Normative record** (mandatory, full detail): the project's internal record. Where a document contradicts it, the record wins.
2. **Public record** (mandatory, this directory): `ADR-NNNN-<slug>.md` plus its row in the [index](README.md), written for clients, reviewers and technical due diligence, with no private material.

Every record contains, at minimum: what was decided; the context and the real constraints; **the options that were considered**, including the discarded ones; **why the chosen option was the best available at that moment** (cost, risk, reversibility, fit); consequences and **limits** (what it does *not* guarantee); the objective facts that would justify revisiting it; and its status, date and relationships (`supersedes`, dependencies).

Rules: an accepted decision is never edited in silence — it is superseded by a new record that says so, keeping the original reasoning and date; a contract change requires its own record; a task that involved a decision is not marked done without its record; the public record never cites private material and never overstates what the tool does.

## Context

The project accumulates contract, security and scope decisions, and their justification was being lost between changelogs, working notes and session memory. Internal records existed from the start, but two things were missing:

- They are **not readable by a client or an auditor**, so the reasoning was not available when the question was actually asked.
- There was **no template forcing the discarded options and the reason** — precisely what turns a decision into something defensible instead of an opinion.

The practical symptom: every time a topic was reopened (how the requested image is composed, whether an observation proves its origin) the “why” had to be reconstructed from scratch.

## Options considered

| Option | Why it was discarded |
|---|---|
| Keep records internal only | Not usable for clients or due diligence: that material is outside the public surface by design |
| Keep only the public record | Would force operational and security detail into public view, or lose it |
| Record decisions in the changelog | Chronological, not topical: it cannot answer “why does it work this way?”, nor supersede one specific decision |
| An external wiki | Leaves the repository, drifts from the code, and does not travel with the audited version |
| **Two layers, shared numbering, mandatory template** | Chosen |

## Why this was the best at the time

- The repository is the artefact that gets audited and handed over: if the justification does not travel with it, it does not exist at the moment someone asks.
- The public/private split was already a project rule; applying it to decisions too means nobody has to re-decide “can this be told?” each time.
- The mandatory template targets the observed failure: what was missing was not “what was decided”, it was **what was rejected and why**. Without that section a future reader cannot judge whether the decision still holds.
- The cost is low: the reasoning is already made when the decision is taken; writing it down takes minutes and avoids full reconstructions (which have already happened several times during design).

## Consequences and limits

- It adds work per decision and a discipline requirement: a decision without a record counts as not taken.
- The public record is a **faithful summary**, not a copy: operational detail (for example how something is verified internally) stays in the normative layer. That is deliberate and stated.
- It does not guarantee the record is up to date if someone decides something informally and does not write it down; the mitigation is the “no `done` without a record” rule, not an automatic mechanism.
- Numbers are shared across layers: one `ADR-NNNN` identifies the decision in both, so a client citing an internal number finds the equivalent public record.

## Revisit if

The number of decisions makes the index hard to navigate, or a publishing requirement (for example generated public documentation) demands another format.
