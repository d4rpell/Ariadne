// Package evaluator implements the offline, deterministic evidence evaluator of
// ADR-0013, profile evidence-readiness-v1. It validates one request against the
// canonical evidence bundle contract, admits exactly one rule pack and composes
// an internal, reproducible result.
//
// The initial profile is deliberately inconclusive: every evaluated outcome is
// under_investigation with exploitability not_assessed. Checking requirements
// does not prove product impact, absence of impact or remediation, and no rule of
// this profile may emit any other state. The result is internal: it is not a VEX
// statement, an exception record or a public evaluation format.
//
// The package has no network client, no shell, no cluster client and no clock:
// the evaluation instant, the pack pin and the version policy are explicit
// caller inputs, and the same canonical bundle, pack bytes, target, admission
// context and engine/profile version always produce the same result.
package evaluator
