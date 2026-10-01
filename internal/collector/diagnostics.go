package collector

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net"
	"net/http"
	"net/url"

	"github.com/d4rpell/Ariadne/internal/bundle"
)

// Diagnostic classification (ADR-0026 A.10). Every classification uses a known
// type or condition of the standard library: free-text matching of an error
// message is never the criterion, and the original error never reaches a
// publishable value.

var (
	errRedirectRefused = errors.New("collector: redirect_refused")
)

// classifyTransportError maps one failed round trip to its closed code. A
// redirect refused by the client keeps its own cause: the guard that fired is
// never replaced by the generic transport failure its cancellation produces.
func classifyTransportError(err error) bundle.CollectionCode {
	if err == nil {
		return ""
	}
	if errors.Is(err, errRedirectRefused) {
		return bundle.CodeRedirectRefused
	}
	var urlError *url.Error
	if errors.As(err, &urlError) {
		if urlError.Timeout() {
			return bundle.CodeRequestTimeout
		}
		return classifyTransportError(urlError.Err)
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return bundle.CodeRequestTimeout
	}
	if errors.Is(err, context.Canceled) {
		return bundle.CodeCancelled
	}
	var hostnameError x509.HostnameError
	if errors.As(err, &hostnameError) {
		return bundle.CodeTLSFailed
	}
	var certificateError x509.CertificateInvalidError
	if errors.As(err, &certificateError) {
		return bundle.CodeTLSFailed
	}
	var unknownAuthority x509.UnknownAuthorityError
	if errors.As(err, &unknownAuthority) {
		return bundle.CodeTLSFailed
	}
	var recordHeaderError tls.RecordHeaderError
	if errors.As(err, &recordHeaderError) {
		return bundle.CodeTLSFailed
	}
	var netError net.Error
	if errors.As(err, &netError) {
		if netError.Timeout() {
			return bundle.CodeRequestTimeout
		}
		return bundle.CodeTransportFailed
	}
	return bundle.CodeTransportFailed
}

// classifyStatus maps one HTTP status to its closed code. Only 200 is
// admitted; every other status is classified here.
func classifyStatus(status int) bundle.CollectionCode {
	switch {
	case status == http.StatusOK:
		return ""
	case status == http.StatusUnauthorized:
		return bundle.CodeAuthFailed
	case status == http.StatusForbidden:
		return bundle.CodeForbidden
	case status == http.StatusNotFound:
		return bundle.CodeNotFound
	case status == http.StatusGone:
		return bundle.CodePaginationExpired
	case status == http.StatusTooManyRequests:
		return bundle.CodeRateLimited
	case status >= 300 && status < 400:
		return bundle.CodeRedirectRefused
	case status >= 500 && status < 600:
		return bundle.CodeServerError
	default:
		return bundle.CodeUnexpectedStatus
	}
}

// contentEncodingProblem checks the single admitted values of Content-Encoding:
// an absent header or exactly "identity". Everything else is refused.
func contentEncodingProblem(values []string) bool {
	switch len(values) {
	case 0:
		return false
	case 1:
		return values[0] != "identity"
	default:
		return true
	}
}
