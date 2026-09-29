# ADR-0024 — Public repository visibility

- **Status:** accepted by the owner on 2026-09-29. The visibility change is verified separately as an execution result.
- **Relationship:** develops ADR-0005 (Apache-2.0) and ADR-0011 (two-layer decision records). Supersedes no decision and changes no evidence, evaluation, CLI, or report contract.

## Decision

Make the existing Ariadne GitHub repository public after correcting the two documentation issues found in its publication review. The public surface includes its Git history, source, tests, documentation, and synthetic fixtures. This decision does not create a release or authorize distribution of evidence bundles or reports.

## Context

Ariadne remains pre-alpha. At the time of review, the remote had one branch with 41 commits and no tags. The README describes both implemented and deferred functionality. The owner wanted the work to be available for external review. Changing visibility also exposes Git history and GitHub Actions logs, so the current tree alone was not a sufficient publication check.

The prepublication review examined the reachable history and available GitHub surfaces. It found no confirmed credential or customer or employer data in that scope. It identified two public wording issues: an overbroad reading of the README's redaction claim and ADR status lines that had not caught up with accepted work. These are corrected before changing visibility. The review was not a source-code security audit, legal review, or proof that all sensitive data is absent.

## Options considered

1. **Stay private until an MVP or release.** This limits exposure now but delays review of the existing code and records without resolving the documentation issues.
2. **Publish a new repository with shortened history.** This allows another content selection but fragments provenance and traceability. No confirmed finding justified removing the reviewed history.
3. **Publish the existing repository after targeted corrections and a final check of the published commit.** Chosen. It preserves the links among code, tests, decisions, and CI while making the pre-alpha limits clear.

## Why this was the best choice now

The existing Apache-2.0 decision supports public review. The available history, documentation, and Actions logs were examined before exposure. Fixing the two inaccurate statements is small work with a direct benefit for readers. Keeping the same repository preserves reviewable provenance. Although visibility can later be changed again, anyone may retain a copy of material published in the meantime; the prepublication checks therefore matter.

## Consequences and limits

- The repository history, authorship, public design records, synthetic fixtures, and accessible Actions logs become visible. Local private notes and agent instructions remain outside the published branch.
- Repository visibility does not certify production readiness, external product compatibility, absence of unknown secrets, or availability of a release. It does not authorize distribution of reports or bundles of any kind, or customer evidence. Synthetic specification vectors retain their previously authorized publication scope.
- The final commit must be checked before the visibility change. Branch protection must be inspected after the change according to the GitHub features available then; no unobserved protection is claimed here.
- A subsequently discovered historical secret would require revocation or rotation and evaluation of the published history and copies. Making the repository private again would not recall copies already made.

## Revisit if

Revisit if a published ref or log is found to contain credentials, real customer or employer data, or private planning; a final publication check reveals a new blocker; publication expands to releases or real evidence; or legal or third-party obligations require a different visibility choice. Record a new decision that cites this one rather than silently changing this accepted record.
