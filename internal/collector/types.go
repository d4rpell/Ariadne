package collector

import (
	"context"

	"github.com/d4rpell/Ariadne/internal/bundle"
	contract "github.com/d4rpell/Ariadne/pkg/evidence"
)

// Public surface of the optional read-only Pod collector (ADR-0026).
//
// The collector acquires Pods through get/list only, inside an explicit
// namespace allowlist, with credentials supplied in memory. It projects each
// admitted response to the sanitized PodList grammar and feeds the existing
// admission, normalization and bundle machinery through the collected
// observation entry point. It never decides vulnerability status, never
// persists and never opens files.

// Config is the complete input of one acquisition run. The zero value is
// invalid: every field is validated before any network operation.
type Config struct {
	Selector        string
	Version         string
	RedactionPolicy string
	ClusterAlias    string
	Namespaces      []string

	Endpoint             string
	CAPEM                []byte
	BearerToken          string
	ClientCertificatePEM []byte
	ClientKeyPEM         []byte
}

// String renders static text: the configuration carries credentials and an
// endpoint, and neither may appear in a formatted value.
func (Config) String() string { return "collector.Config{REDACTED}" }

// GoString keeps the same guarantee for %#v formatting.
func (Config) GoString() string { return "collector.Config{REDACTED}" }

// CollectedBundle is one bundle built from one subject of one admitted
// capture, with the omissions of its projection.
type CollectedBundle struct {
	CaptureOrdinal uint64
	ItemIndex      int
	Bundle         contract.Bundle
	Diagnostics    bundle.ObservationDiagnostics
}

// Result is the outcome of one acquisition run. Acquisition carries only
// publishable facts; it never includes the configuration, credentials, the
// client, requests, responses or underlying errors.
type Result struct {
	Acquisition bundle.CollectedAcquisition
	Bundles     []CollectedBundle
	// Incomplete reports that some observation of the run is not complete. It
	// never replaces the coverage termination of a bundle.
	Incomplete bool
}

// Collect runs one acquisition and returns its publishable result. A run that
// aborted returns the partial result together with a static error; a finished
// run may still carry incomplete observations, reported by Incomplete and by
// the coverage of every bundle.
func Collect(ctx context.Context, config Config) (Result, error) {
	return collectWithDependencies(ctx, config, nil, nil)
}
