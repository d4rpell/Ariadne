# Ariadne documentation

Documentation for users and contributors.

Content will grow alongside the implementation:

- `architecture.md` — components, data flow, trust boundaries
- `evidence-schema.md` — the evidence bundle contract
- `decision-model.md` — product status, exploitability and risk decision
- `rule-packs.md` — writing and validating declarative evaluation rules
- `compatibility.md` — verified Kubernetes and OpenShift releases
- `quickstart.md` — installation and first run

Already available:

- [`adr/`](adr/README.md) — the **decision records**: what was decided, the alternatives considered, why the chosen option was the best available at the time, and the conditions that would justify revisiting it. This is the place to look when the question is “why does it work this way?” rather than “how do I run it?”.
- [`spec/evidence-bundle/0.2.md`](spec/evidence-bundle/0.2.md) — the **wire specification of the evidence bundle** (`0.2`): canonical serialization, hash projection and a third-party verification procedure, with [published synthetic vectors](spec/evidence-bundle/0.2/). Pre-alpha: publication does not authorize distribution.

Until the first release, the [project README](../README.md) is the source of truth for what Ariadne is and what it deliberately is not.
