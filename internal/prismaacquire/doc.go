// Package prismaacquire implements the optional Prisma Cloud Compute API
// acquisition connector of ADR-0028. It is a network-privileged root, separate
// from internal/collector in both directions, that reads only existing deployed
// image reports and delivers each admitted page to the ratified offline
// ingestion of ADR-0027, tagging it with explicit `compute_api` provenance.
//
// The package never decides vulnerability states: it produces a native
// inventory and acquisition provenance, never an evidence bundle, a
// product_status, an exploitability or a risk_decision. It performs no retries,
// follows no redirects, uses no proxy, HTTP/2, keep-alive or compression, and
// exposes no caller-supplied client, transport, TLS config or callback.
package prismaacquire
