// Package rulepack implements the admitted rule-pack contract of ADR-0013
// (profile evidence-readiness-v1): byte-exact JSON decoding, closed-vocabulary
// validation, content hash and pure admission.
//
// A pack is data, never code: the predicate and requirement vocabularies are
// closed, unknown members are rejected instead of interpreted, and no pack field
// can request execution, network access, includes, templates or expressions.
//
// The package performs no I/O, opens no path and reads no clock: admission
// context (instant, minimum version, pinned id/hash and previous version) is
// supplied by the caller, and every hash is computed over the exact bytes it
// receives (ADR-0013 §5.2). Pin, instant and history are caller claims: this
// package detects downgrade relative to the supplied policy, never rollback of a
// store or of a clock.
package rulepack
