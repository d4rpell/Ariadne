// Package interop renders deterministic OpenVEX, SARIF and CSAF 2.0 VEX
// interoperability documents from an already-computed evaluation result and the
// canonical bundle whose projection hash the result carries (ADR-0032,
// ADR-0035). It re-evaluates nothing, opens no path, reaches no network and
// executes no process: it re-validates the form it needs, contrasts the bundle
// hash and returns the bytes the caller decides where to write.
//
// The standard fields carry only what Ariadne can substantiate from the result;
// local extensions are omitted (OpenVEX), placed in the standard extension
// mechanism under a namespaced key (SARIF), or demanded from the caller (the
// CSAF action statement, because Ariadne models no remediation). These documents
// are not the evidence bundle, not a decision record and not a risk acceptance,
// and none of them proves the correctness of the conclusion it presents.
package interop
