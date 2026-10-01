package collector

import (
	"bytes"
	"time"

	"github.com/d4rpell/Ariadne/internal/bundle"
	"github.com/d4rpell/Ariadne/internal/ingest"
	"github.com/d4rpell/Ariadne/internal/normalize"
	"github.com/d4rpell/Ariadne/internal/schema"
	contract "github.com/d4rpell/Ariadne/pkg/evidence"
)

// Admission of one projected source (ADR-0026 A.7.3, A.9). Every admitted
// response is parsed and normalized with the real A2-01 machinery: the
// collector never fabricates findings, never weakens the sanitized grammar and
// never publishes a prefix.

// admissionContext describes the operational facts of one capture. The
// termination is only final once the whole run is known; the collector admits
// each response with the termination it can prove at that moment and rebuilds
// the observation later from the same bytes when the global termination
// differs.
type admissionContext struct {
	sourceName         string
	clusterAlias       string
	namespace          string
	observedAt         time.Time
	captureTermination contract.CoverageTermination
}

// admitSource parses and normalizes one complete sanitized source.
func admitSource(source []byte, context admissionContext) (normalize.ObservationResult, error) {
	parsed, err := ingest.ParseSanitizedPodList(bytes.NewReader(source), ingest.PodListContext{
		Selector:           schema.SanitizedPodListSelector,
		Version:            schema.SanitizedPodListVersion,
		RedactionPolicy:    schema.SanitizedPodListRedactionPolicy,
		SourceName:         context.sourceName,
		ClusterAlias:       context.clusterAlias,
		Namespace:          context.namespace,
		ObservedAt:         context.observedAt,
		CaptureTermination: context.captureTermination,
	})
	if err != nil {
		return normalize.ObservationResult{}, err
	}
	if !parsed.PodListAccepted() {
		// Without an admitted source there is no publicable observation.
		return normalize.ObservationResult{}, staticError(bundle.CodeRedactionFailed)
	}
	normalized, err := normalize.NormalizePodList(parsed)
	if err != nil {
		return normalize.ObservationResult{}, err
	}
	return normalized, nil
}

// captureAlias renders the stable logical alias of one capture. The ordinal is
// the request ordinal: the alias never contains an endpoint, a namespace or a
// Pod name.
func captureAlias(requestOrdinal uint64) string {
	const digits = 6
	value := requestOrdinal
	rendered := make([]byte, digits)
	for index := digits - 1; index >= 0; index-- {
		rendered[index] = byte('0' + value%10)
		value /= 10
	}
	return "capture-" + string(rendered) + ".json"
}
