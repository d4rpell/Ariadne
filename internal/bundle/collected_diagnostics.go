package bundle

// Live-collection diagnostics (ADR-0026 A.10). The codes of this producer are a
// closed catalog of this package: a code outside it is never printed and the
// integration fails closed. The rendered message is always exactly
// "collector: <code>".

// CollectionCode is one closed diagnostic code of the live collector.
type CollectionCode string

const (
	CodeInvalidConfig        CollectionCode = "invalid_config"
	CodeUnsupportedAuth      CollectionCode = "unsupported_auth"
	CodeRequestNotAllowed    CollectionCode = "request_not_allowed"
	CodeAuthFailed           CollectionCode = "auth_failed"
	CodeForbidden            CollectionCode = "forbidden"
	CodeNotFound             CollectionCode = "not_found"
	CodePaginationExpired    CollectionCode = "pagination_expired"
	CodeRateLimited          CollectionCode = "rate_limited"
	CodeServerError          CollectionCode = "server_error"
	CodeUnexpectedStatus     CollectionCode = "unexpected_status"
	CodeRedirectRefused      CollectionCode = "redirect_refused"
	CodeTLSFailed            CollectionCode = "tls_failed"
	CodeTransportFailed      CollectionCode = "transport_failed"
	CodeRequestTimeout       CollectionCode = "request_timeout"
	CodeBodyReadFailed       CollectionCode = "body_read_failed"
	CodeResponseInvalid      CollectionCode = "response_invalid"
	CodePaginationInvalid    CollectionCode = "pagination_invalid"
	CodeScopeMismatch        CollectionCode = "scope_mismatch"
	CodeIdentityConflict     CollectionCode = "identity_conflict"
	CodeUIDChanged           CollectionCode = "uid_changed"
	CodeObservationChanged   CollectionCode = "observation_changed"
	CodeStaleStatusSuspected CollectionCode = "stale_status_suspected"
	CodeResourceVersionMiss  CollectionCode = "resource_version_missing"
	CodePodRejected          CollectionCode = "pod_rejected"
	CodeRedactionFailed      CollectionCode = "redaction_failed"
	CodeRequestLimit         CollectionCode = "request_limit"
	CodeObjectLimit          CollectionCode = "object_limit"
	CodeByteLimit            CollectionCode = "byte_limit"
	CodeResponseLimit        CollectionCode = "response_limit"
	CodeOutputLimit          CollectionCode = "output_limit"
	CodeTimeLimit            CollectionCode = "time_limit"
	CodeCancelled            CollectionCode = "cancelled"
	CodeClockInvalid         CollectionCode = "clock_invalid"
	CodeProjectionFailed     CollectionCode = "projection_failed"
)

// collectionCodes is the closed catalog. Order is not significant; membership is.
var collectionCodes = []CollectionCode{
	CodeInvalidConfig, CodeUnsupportedAuth, CodeRequestNotAllowed,
	CodeAuthFailed, CodeForbidden, CodeNotFound, CodePaginationExpired,
	CodeRateLimited, CodeServerError, CodeUnexpectedStatus, CodeRedirectRefused,
	CodeTLSFailed, CodeTransportFailed, CodeRequestTimeout, CodeBodyReadFailed,
	CodeResponseInvalid, CodePaginationInvalid, CodeScopeMismatch,
	CodeIdentityConflict, CodeUIDChanged, CodeObservationChanged,
	CodeStaleStatusSuspected, CodeResourceVersionMiss, CodePodRejected,
	CodeRedactionFailed, CodeRequestLimit, CodeObjectLimit, CodeByteLimit,
	CodeResponseLimit, CodeOutputLimit, CodeTimeLimit, CodeCancelled,
	CodeClockInvalid, CodeProjectionFailed,
}

// Codes returns the closed catalog so callers can resolve a rendered message
// back to its code without duplicating the list.
func Codes() []CollectionCode {
	return append([]CollectionCode{}, collectionCodes...)
}

// CollectionCodeKnown reports whether a code belongs to the closed catalog.
func CollectionCodeKnown(code CollectionCode) bool {
	for _, known := range collectionCodes {
		if code == known {
			return true
		}
	}
	return false
}

// CollectionMessage renders the exact message of one code. An unknown code has
// no message: the caller must treat it as projection_failed instead.
func CollectionMessage(code CollectionCode) string {
	if !CollectionCodeKnown(code) {
		return ""
	}
	return "collector: " + string(code)
}

// CollectionDiagnostic is one sanitized diagnostic of the live producer. It
// carries closed codes and bounded positions only: never an endpoint, token,
// URL, error body or foreign name.
type CollectionDiagnostic struct {
	Code           CollectionCode
	RequestOrdinal *uint64
	CaptureOrdinal *uint64
	ItemIndex      *int
	FieldLocator   string
}
