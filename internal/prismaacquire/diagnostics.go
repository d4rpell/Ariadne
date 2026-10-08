package prismaacquire

// Acquisition diagnostic structure of ADR-0028 §11.1. Diagnostics carry only
// typed, bounded fields: never provider messages, URLs, hostnames, project,
// user, token or remote body fragments.

// Acquisition phases (§11.1).
const (
	PhaseConfig       = "config"
	PhaseAuth         = "auth"
	PhaseRequest      = "request"
	PhaseBody         = "body"
	PhaseAdmission    = "admission"
	PhasePagination   = "pagination"
	PhaseFinalization = "finalization"
)

// Closed diagnostic catalogue (§11.2).
const (
	CodeInvalidConfig               = "invalid_config"
	CodeUnsupportedProfile          = "unsupported_profile"
	CodeUnsupportedAuth             = "unsupported_auth"
	CodeCredentialUnavailable       = "credential_unavailable"        //nolint:gosec // diagnostic code string, not a credential
	CodeCredentialReferenceMismatch = "credential_reference_mismatch" //nolint:gosec // diagnostic code string, not a credential
	CodeCredentialExpired           = "credential_expired"            //nolint:gosec // diagnostic code string, not a credential
	CodeTLSConfigInvalid            = "tls_config_invalid"
	CodeRequestNotAllowed           = "request_not_allowed"
	CodeAuthFailed                  = "auth_failed"
	CodeForbidden                   = "forbidden"
	CodeNotFound                    = "not_found"
	CodeGone                        = "gone"
	CodeRateLimited                 = "rate_limited"
	CodeServerError                 = "server_error"
	CodeRedirectRefused             = "redirect_refused"
	CodeUnexpectedStatus            = "unexpected_status"
	CodeTLSFailed                   = "tls_failed"
	CodeTransportFailed             = "transport_failed"
	CodeRequestTimeout              = "request_timeout"
	CodeBodyReadFailed              = "body_read_failed"
	CodeResponseInvalid             = "response_invalid"
	CodeAuthResponseInvalid         = "auth_response_invalid"
	CodeNativeAdmissionFailed       = "native_admission_failed"
	CodePageSizeExceeded            = "page_size_exceeded"
	CodePageRepeated                = "page_repeated"
	CodePageDriftSuspected          = "page_drift_suspected"
	CodeRequestLimit                = "request_limit"
	CodePageLimit                   = "page_limit"
	CodeResponseLimit               = "response_limit"
	CodeByteLimit                   = "byte_limit"
	CodeObjectLimit                 = "object_limit"
	CodeTokenLimit                  = "token_limit"
	CodeOutputLimit                 = "output_limit"
	CodeTimeLimit                   = "time_limit"
	CodeCancelled                   = "cancelled"
	CodeClockInvalid                = "clock_invalid"
	CodeFinalizationFailed          = "finalization_failed"
	CodeInternalInvariantFailed     = "internal_invariant_failed"
)

// AcquisitionCodes is the closed catalogue of §11.2, in contract order.
func AcquisitionCodes() []string {
	return []string{
		CodeInvalidConfig, CodeUnsupportedProfile, CodeUnsupportedAuth,
		CodeCredentialUnavailable, CodeCredentialReferenceMismatch,
		CodeCredentialExpired, CodeTLSConfigInvalid, CodeRequestNotAllowed,
		CodeAuthFailed, CodeForbidden, CodeNotFound, CodeGone,
		CodeRateLimited, CodeServerError, CodeRedirectRefused,
		CodeUnexpectedStatus, CodeTLSFailed, CodeTransportFailed,
		CodeRequestTimeout, CodeBodyReadFailed, CodeResponseInvalid,
		CodeAuthResponseInvalid, CodeNativeAdmissionFailed, CodePageSizeExceeded,
		CodePageRepeated, CodePageDriftSuspected, CodeRequestLimit, CodePageLimit,
		CodeResponseLimit, CodeByteLimit, CodeObjectLimit, CodeTokenLimit,
		CodeOutputLimit, CodeTimeLimit, CodeCancelled, CodeClockInvalid,
		CodeFinalizationFailed, CodeInternalInvariantFailed,
	}
}

// AcquisitionError is the typed acquisition diagnostic of §11.1. It carries no
// free-text field and never wraps the underlying error, so a caller cannot
// recover provider URLs, hostnames, project, user, token or body fragments.
type AcquisitionError struct {
	Code           string
	Phase          string
	RequestOrdinal int    // request ordinal, when applicable
	PageOrdinal    int    // page ordinal, when applicable
	PreviousPage   int    // previous page ordinal for cross-page anomalies
	HTTPStatus     int    // numeric HTTP code, when present
	FirstRecord    int    // first record index, when applicable
	SecondRecord   int    // second record index, when applicable
	Count          uint64 // relevant numeric counter
	NativeCode     string // F1 native admission code, when applicable
}

// Error renders the closed textual form of §11.1: "prismaacquire: <code>". A
// code that is not in the catalogue is reduced to internal_invariant_failed.
func (e *AcquisitionError) Error() string {
	code := e.Code
	if !validAcquisitionCode(code) {
		code = CodeInternalInvariantFailed
	}
	return "prismaacquire: " + code
}

func validAcquisitionCode(code string) bool {
	for _, known := range AcquisitionCodes() {
		if code == known {
			return true
		}
	}
	return false
}

// acquireErr builds a typed acquisition error with a catalogue code.
func acquireErr(code, phase string) *AcquisitionError {
	if !validAcquisitionCode(code) {
		code = CodeInternalInvariantFailed
	}
	return &AcquisitionError{Code: code, Phase: phase}
}

// httpStatusError maps a non-200 HTTP status to its catalogue code (§11.3). A
// 200 is a candidate rather than an error and is not handled here.
func httpStatusError(status int) string {
	switch {
	case status >= 300 && status < 400:
		return CodeRedirectRefused
	case status == 401:
		return CodeAuthFailed
	case status == 403:
		return CodeForbidden
	case status == 404:
		return CodeNotFound
	case status == 410:
		return CodeGone
	case status == 429:
		return CodeRateLimited
	case status >= 500:
		return CodeServerError
	default:
		return CodeUnexpectedStatus
	}
}
