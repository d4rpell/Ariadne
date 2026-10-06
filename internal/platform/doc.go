// Package platform serves a read-only, loopback dashboard and timeline over one
// verified casefile book (ADR-0034, task A3-06). It projects the book and the
// derived validity view of ADR-0031 into an ordered in-memory model, renders it
// as static HTML with html/template and serves it over a loopback-only HTTP
// listener.
//
// The package is read-only. It opens no path, reads no clock (the as-of instant
// is supplied by the caller), performs no network egress, executes nothing and
// mutates no artifact. Only layer 3 of the decision model (risk_decision) is
// present here: product status and exploitability do not exist in the book and
// are never invented. Absence is rendered as an explicit null or none, never as
// an ambiguous empty cell. There is no JavaScript and no external resource.
package platform
