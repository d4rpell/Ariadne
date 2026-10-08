// Package report renders a deterministic JSON and HTML presentation of an
// already-computed evaluation result (ADR-0022). It re-evaluates nothing, opens
// no path, reaches no network and executes no process: Build projects the
// evaluator Result and resolves its evidence and warning references against the
// canonical bundle whose projection hash the Result carries, and the encoders
// return bytes the caller decides where to write.
//
// The report is not the evidence bundle, not a decision record and not a risk
// acceptance. Values and free-text warning messages are excluded by
// presentation policy; authorization of the identifiers and citations it does
// carry belongs to the producer and the caller (ADR-0039).
package report
