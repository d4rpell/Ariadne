# ADR-0014: Static closure of local imports

- **Status:** **ratified by the owner on 2026-09-26; implemented and accepted by the owner on 2026-09-27** as the import-boundary closure of the reviewed test suite. Ariadne remains pre-alpha; this status does not authorize distribution or release.
- **Related records:** develops the offline isolation requirements of ADR-0003 and ADR-0004, follows ADR-0011, and supports the ratified ADR-0013. No accepted record is superseded.
- **Reading this record:** the sections below are the text that was ratified, written while the decision was still a proposal; a sentence in the proposal tense describes what was decided, not pending work. The superseded state lines were: "the earlier state line said the record was proposed and that the closure was not implemented. Both statements described the proposal stage and are superseded by the status line above. The sections below keep their original wording as the record of what was decided."

## Decision

Check the transitive union of imports from all local production Go sources reachable from protected packages, including sources excluded by the active operating system, architecture or build tags. Reject forbidden imports and ambiguous analysis, while retaining the active build's dependency check as a complementary control.

## Context

A dependency check for one compiled build sees only that build's sources. Reading all direct imports of a protected package adds coverage, but still misses a forbidden import reached through a local intermediate package from an excluded source file.

The isolation requirement needs to address this local transitive gap. An execution matrix alone cannot establish coverage of arbitrary build-tag combinations.

## Options considered

| Option | Trade-off |
|---|---|
| Conservative union of local source imports — recommended | Covers excluded local sources; may reject paths that cannot coexist in an actual build |
| Operating-system, architecture and tag matrix | Exercises chosen configurations but leaves unenumerated combinations uncovered |
| Constraint satisfiability analysis | Could avoid some false positives, at the cost of substantially more analysis complexity |
| Keep direct-source and active-build checks alone | Retains the known local transitive gap |

## Why this was chosen

A conservative union fits a small, single-module repository and makes uncertain cases fail visibly. False positives can be reviewed without silently weakening the boundary. It avoids claiming that a finite build matrix proves all possible variants.

## Scope

The evaluator and pack-admission component would share a restricted set of standard-library imports and prohibit network clients, shell execution, cluster clients, native extensions and dynamic loading. Their reachable local production packages would be subject to the same policy. The report component would retain its separate, narrower shell-execution prohibition.

The initial analyzer would support a single module without external module dependencies, replacements or vendored sources. Unsupported dependency arrangements, unresolved paths, malformed source, unsafe path resolution or unsupported native/linking mechanisms would fail closed. Expanding this profile would require review and a recorded decision.

The source union would include local generated and build-excluded production Go files without running generators. Test-only code would remain outside the production import boundary. Analysis policy would not be configurable by rule packs.

## Consequences and limits

The closure addresses the identified gap in local source traversal. It intentionally accepts false positives where mutually exclusive build constraints make a path impossible in a real binary.

“All variants” describes conservative inspection of local production sources. It does not claim execution or successful compilation on every platform, exhaustive inspection of all variants of the standard library or third-party dependencies, or a general proof of program purity.

Import analysis is not a sandbox. An allowed library can still expose APIs inappropriate for deterministic evaluation. Code review and behavioral verification remain necessary, and a passing check does not prove security or toolchain integrity.

## Revisit if

A required dependency, replacement, workspace, native source, generated-source arrangement or standard-library import falls outside the supported profile; or a concrete false positive justifies the additional cost of constraint-aware analysis.

## Normative detail

This record fixes the boundary and its limits. It does not claim that related security work such as pack signing or a general purity proof is complete, and it does not close the broader threat item on its own. Verification of the implementation and its acceptance are separate steps.
