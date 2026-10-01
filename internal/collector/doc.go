// Package collector implements the optional, read-only Pod acquisition of
// ADR-0026 (profile k8s-pod-read-v1/1.0).
//
// Scope: one run lists and reads Pods of an explicit namespace allowlist
// through the standard-library REST client, projects each admitted response
// onto the sanitized-podlist-v1 grammar of ADR-0025, and hands every subject to
// the collected-observation builder. The result is a typed acquisition record
// plus one bundle per subject and capture. It never evaluates, never decides
// vulnerability status and never writes a file.
//
// Limits, all program constants that no caller can raise:
//
//   - HTTPS only, one authority, explicit in-memory CA, bearer or mTLS, no
//     kubeconfig, no service-account autodetection, no proxy, redirects,
//     cookies, compression, HTTP/2 or connection reuse;
//   - get and list over namespaced pods only; watch, subresources, other
//     resources and discovery are refused before the transport;
//   - 300 s global, 10 s per request, 1024 requests, 1024 Pod occurrences,
//     256 initial UIDs, 64 MiB of accumulated bodies, 4 MiB per response,
//     32 KiB of response headers, 1 MiB per raw Pod, 32 MiB of retained
//     sources, one in-flight request, 200 ms between request starts, two get
//     rounds, zero retries, 8 KiB continuation token, raw JSON depth 64,
//     1,000,000 tokens and 2,048 members per object;
//   - an aborted run returns its partial result together with a static error;
//     every affected bundle keeps the concrete global error and the coverage
//     never ascends because a subject was selected.
//
// Limits of this package, declared rather than hidden: it proves behaviour of
// its own code under synthetic input; it does not prove remote cancellation,
// RBAC effectiveness, cluster compatibility, absence of secrets in memory,
// atomicity across namespaces or real detection of a delayed status.
package collector
