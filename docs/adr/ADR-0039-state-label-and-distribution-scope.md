# ADR-0039: Current state label and scope of the distribution clause

- **Status:** **ratified by the owner on 2026-10-08** (proposed 2026-10-08). Task AX-10. Independent review closed with no open P0/P1 (`apto`, Astra High, 2026-10-08). Presentation only.
- **Date:** 2026-10-08.
- **Scope:** fix the **current state text the product prints** (CLI help, HTML report banner and `serve` dashboard banner) and the scope of the "report distribution is not authorized" clause that accompanies it today; update the current-state documentation accordingly.
- **Related records:** **partially supersedes** the distribution clause ("distribution of reports / of the exported documents is not authorized") of ADR-0022 (P6), ADR-0023, ADR-0025, ADR-0026, ADR-0027, ADR-0028, ADR-0029, ADR-0032, ADR-0033 and ADR-0035 — their historical records are kept with a dated note. **Keeps** ADR-0023 (CLI surface; help texts are test-frozen constants), ADR-0022 (deterministic presentation contract), ADR-0034 (loopback platform), ADR-0036/0037/0038 (commands). **Does not touch** wire, decision states, budgets, exit codes, paths or privilege boundaries.

## Decision

The **current state text** of the product (the one the binary prints) is fixed, and the **distribution clause is withdrawn** from the presentation:

- **CLI help** (`cmd/ariadne/arguments.go`, constants `helpRoot`/`helpLastLine`): the last line changes from
  `Pre-alpha. Offline. Report distribution is not authorized.`
  to
  `MVP complete. Offline.`
  for the eight subcommands (`evaluate`/`report`/`verify`/`import`/`book`/`append`/`serve`/`diff`) and the root.
- **HTML report banner** (`internal/report/html.go`): the opening sentence changes from
  `Pre-alpha presentation of one evaluation result.`
  to
  `MVP complete presentation of one evaluation result.`
  The rest of the paragraph ("It is not a risk acceptance, not an approval and not a security statement. This document reproduces what the evaluator computed; it adds no conclusion.") is **kept in full**: it remains true and is part of the product's honest guarantee.
- **`serve` dashboard banner** (`internal/platform/render.go`): the text **does not change** (it contains neither the label nor the clause). Only the package comment describing it as "of the pre-alpha platform" is updated.
- **Residual distribution clause in the product output** (`internal/report/html.go`, the "Limits of this report" bullet): the sentence "…and distribution of reports is not authorized by this contract." is **removed** from the bullet (the bullet keeps the rest: no universal secret detector, identifiers and citations are the responsibility of the producer and the caller). It is a **user-visible** surface of the report. It is also removed from the package comment in `internal/interop/doc.go`.
- **Supersession of the distribution clause:** the statement "distribution is not authorized" is no longer emitted as presentation text and no longer appears as a current limit in the state documentation. The cited records are kept with their rationale and date, plus a one-line note pointing to this record.
- **Current-state documentation** (`README.md`, `docs/README.md`, `docs/adr/README.md`, `docs/quickstart.md`, `docs/compatibility.md`, `docs/comparison.md`, `docs/spec/evidence-bundle/0.2.md`, `docs/assets/README.md`, `examples/synthetic-case/README.md`): the **current** label becomes **"MVP complete"** and the distribution clause is withdrawn as a current limit. **Dated historical statements are not rewritten.**
- **AX-08 presentation artifacts** (`docs/assets/ariadne-flow.{gif,png}`): the flow GIF/PNG **print** `Ariadne | pre-alpha | …` (footer) and `report and bundle distribution is not authorized` (frame 4). They are **regenerated** with the footer and frame aligned to the new text, keeping the verified deterministic chain. The dashboard artifacts (`ariadne-serve.{gif,png}`) show neither the label nor the clause and are **not** regenerated.

## Context

The repository has carried the `PRE-ALPHA` label since its first state (2026-09-24), when the core was mostly unwritten. Since then the project has closed roadmap 0.1–0.3: a complete offline core; a CLI with `import`/`evaluate`/`report`/`verify`/`book`/`append`/`serve`/`diff`; a read-only collector; OpenVEX/SARIF/CSAF exports; validity lifecycle; a T1–T12 threat model with verified controls; and lint+`gosec` gates in CI. The A1-09 audit left the DoD at 8/2/2 and the residuals were closed afterwards (criterion (10) with A1-12; (12) with A2-06; (7) with A3-10). `TODO.md` has no open tasks.

Observed fact that motivates the review: the label does not live only in the documentation. **It is printed in the product's output** — CLI help, HTML report banner and dashboard banner — and **frozen byte for byte in 13 golden files** plus 9 cases in `arguments_test.go`. Separately, the "distribution not authorized" clause became a **ratified policy** in ADR-0022 (P6) and was restated in the ADR-0023/0025/0032/0033/0035 indices.

The owner's decision (2026-10-08) is that the project is **personal, not commercial, with no clients, release or planned distribution** (recorded in ADR-0034 §8). Under that reality, "PRE-ALPHA" as a current state **undersells** what was delivered, and the owner withdraws the distribution clause from the presentation: it was introduced as a governance hedge during the design phase, and the owner no longer considers it applicable to a personal project. This record documents that decision; it does not argue that the clause was wrong or that it never applied.

## Options considered

1. **Change only the documentation, leaving the binary output as is** (rejected). Cheapest, but leaves the binary printing `Pre-alpha` while the README says "MVP complete": it reproduces the ambiguity **exactly where the user sees it**. Does not fix the detected problem.
2. **Change the state label only, keeping the distribution clause** (rejected). Removing "pre-alpha" while keeping "distribution is not authorized" yields incoherent text — a finished label with a live distribution restriction — and retains a policy that does not apply to the personal case.
3. **Change the label and withdraw the clause, in both layers, regenerating the presentation artifacts** (chosen). Leaves the current state coherent end to end: what the README declares is what the binary prints. Requires an ADR (presentation contract change), regeneration of 13 goldens and 2 presentation artifacts, and a current-state documentation update without rewriting history.
4. **Relabel to `alpha`/`beta`** (rejected). Would imply external users testing it and verified real compatibility, neither of which exists (and Prisma compatibility is permanently unverifiable). That would be overclaiming, against rule 9 and the project's honest-guarantee doctrine.
5. **Drop the label entirely and print no state** (rejected). The state label is useful information and the project keeps real limits (offline, no release).
6. **Also regenerate the dashboard artifacts for aesthetic consistency** (rejected). They show neither the label nor the clause; regenerating them would add cost and byte-drift risk with no visible change.

## Why the chosen option was best

Bounded, verifiable cost: the text change is mechanical and covered by byte-exact goldens, so any deviation is caught in CI; the AX-08 generation chain reproduces **byte for byte** today (verified: recomputed `ariadne-flow.gif` hash `48f0978b…` identical to the published one), so regenerating the flow artifact is safe and deterministic. It fixes the real problem (coherence between what is declared and what is printed) without widening scope to wire, states or boundaries. Highly reversible: it is presentation; a later ADR can revert the text. Fit: it respects history (it does not silently edit ADRs, it annotates them) and sets no precedent of relaxing a security guarantee — the withdrawn clause was about **distribution**, not security or technical accuracy, and the limits that matter (`unknown`, integrity ≠ authenticity, no release) **remain**.

## Consequences and limits

Buys: a **coherent and honest** current state — "MVP complete, offline" — describing what exists (a closed, gated MVP) without promising what does not (release, users, compatibility), and removes the distribution clause from the presentation so the printed state matches what the documentation declares.

**Does not guarantee or provide:** it does not change product behavior (wire, states, budgets, exit codes, paths, privilege boundaries unchanged); it does not create a release or publish a tag; it does **not by itself authorize** commercial distribution or use with real data, which remain owner decisions not taken; it does not turn the project into a commercial product; "MVP complete" describes **closed planned scope**, not absence of limits — the declared limits (Prisma/OpenShift compatibility not verified, no conformance with official validators, windows/amd64 only, `make check` not literally runnable) **remain in force**; the honest guarantee is not relaxed: the report still says it is not a risk acceptance, not an approval and not a security statement, `unknown` remains a valid result, and the hash still proves integrity and not authenticity; historical entries are not rewritten.

## Review conditions

- If the owner decides to publish a **release** or authorize distribution (to third parties or with real data), reopen with a new record: the state label and distribution conditions are then fixed by explicit decision, not inherited from this one.
- If an **external consumer** (user, contributor or auditor) appears whose policy depends on distribution or access, reopen to fix it in writing.
- Any text change that touches wire, decision states, exit codes or security limits requires a new record, not an edit of this one.
- Ratification of this record is an owner act, not delegable.

## State

Ratified by the owner on 2026-10-08 (proposed the same day). Task AX-10. Independent review closed with no open P0/P1 (`apto`, Astra High, 2026-10-08).
