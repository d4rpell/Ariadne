package ingest

import (
	"time"

	"github.com/d4rpell/Ariadne/internal/schema"
)

// Context validation of ADR-0025 A.6 and A.10.3 row 1. The context is checked
// in the declared field order and the reader is not consumed while any field is
// rejected: selector, version and policy first, then the aliases, the namespace,
// the explicit timestamp and the capture termination. Nothing here reads a
// clock, an mtime or a resourceVersion.

// validatePodListContext returns the sanitized failure of one context check or
// nil when the whole context is admissible.
func validatePodListContext(context PodListContext) *PodListError {
	if context.Selector != schema.SanitizedPodListSelector {
		return failure(PodListCodeUnsupportedSelector, 0)
	}
	if context.Version != schema.SanitizedPodListVersion {
		return failure(PodListCodeUnsupportedVersion, 0)
	}
	if context.RedactionPolicy != schema.SanitizedPodListRedactionPolicy {
		return failure(PodListCodeRedactionPolicyRequired, 0)
	}
	if !validPodListAlias(context.SourceName) {
		return failure(PodListCodeInvalidContext, 0)
	}
	if !validPodListAlias(context.ClusterAlias) {
		return failure(PodListCodeInvalidContext, 0)
	}
	if !validPodListNamespace(context.Namespace) {
		return failure(PodListCodeInvalidContext, 0)
	}
	if !validPodListObservedAt(context.ObservedAt) {
		return failure(PodListCodeInvalidContext, 0)
	}
	if !context.CaptureTermination.Valid() {
		return failure(PodListCodeInvalidContext, 0)
	}
	return nil
}

// validPodListAlias enforces the logical alias grammar of A.6: ASCII
// [A-Za-z0-9][A-Za-z0-9._-]{0,127}, never "." or "..". An alias is a logical
// name, not a path: it is never opened or resolved.
func validPodListAlias(value string) bool {
	if value == "." || value == ".." {
		return false
	}
	if len(value) < 1 || len(value) > 128 {
		return false
	}
	for index := 0; index < len(value); index++ {
		c := value[index]
		switch {
		case c >= 'A' && c <= 'Z', c >= 'a' && c <= 'z', c >= '0' && c <= '9':
		case c == '.' || c == '_' || c == '-':
			if index == 0 {
				return false
			}
		default:
			return false
		}
	}
	return true
}

// validPodListNamespace enforces the sanitized textual identifier of A.6: it is
// required, must be valid UTF-8, must not carry forbidden text characters and
// must not be surrounded by whitespace. The value is kept exactly as given.
func validPodListNamespace(value string) bool {
	if value == "" || len(value) > schema.SanitizedPodListMaxIdentifierBytes {
		return false
	}
	problem := podListTextProblem([]byte(value))
	if problem != nil {
		return false
	}
	return !podListWhitespaceSurrounded(value)
}

// validPodListObservedAt enforces the explicit timestamp of A.6: a valid,
// non-zero instant expressed in UTC. No other source of time is consulted.
func validPodListObservedAt(value time.Time) bool {
	if value.IsZero() {
		return false
	}
	return value.Location() == time.UTC
}
