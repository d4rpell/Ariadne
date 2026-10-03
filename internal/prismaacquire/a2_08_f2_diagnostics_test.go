package prismaacquire

import (
	"net/http"
	"strings"
	"testing"
)

// Incremento 10 de A2-08-F2: catálogo y precedencia de diagnósticos
// (ADR-0028 §11). El catálogo es cerrado y el texto se reduce a
// "prismaacquire: <code>"; ningún error envuelve un error subyacente.

func TestA208F2DiagnosticCatalogue(t *testing.T) {
	codes := AcquisitionCodes()
	if len(codes) != 38 {
		t.Fatalf("catalogue has %d codes, want 38", len(codes))
	}
	seen := map[string]bool{}
	for _, code := range codes {
		if code == "" || seen[code] {
			t.Fatalf("empty or duplicated catalogue code %q", code)
		}
		seen[code] = true
		failure := acquireErr(code, PhasePagination)
		if got, want := failure.Error(), "prismaacquire: "+code; got != want {
			t.Fatalf("Error() = %q, want %q", got, want)
		}
	}
	for _, required := range []string{
		CodeInvalidConfig, CodeRedirectRefused, CodeRateLimited, CodePageRepeated,
		CodePageDriftSuspected, CodeObjectLimit, CodeTokenLimit, CodeTimeLimit,
		CodeClockInvalid, CodeFinalizationFailed,
	} {
		if !seen[required] {
			t.Fatalf("catalogue is missing %q", required)
		}
	}
	// An unknown code never leaks a free text: it is reduced.
	unknown := &AcquisitionError{Code: "not_a_real_code"}
	if got := unknown.Error(); got != "prismaacquire: "+CodeInternalInvariantFailed {
		t.Fatalf("unknown code = %q, want the internal invariant fallback", got)
	}
}

func TestA208F2HTTPStatusMatrix(t *testing.T) {
	cases := []struct {
		status int
		code   string
	}{
		{http.StatusFound, CodeRedirectRefused},
		{http.StatusNotModified, CodeRedirectRefused},
		{http.StatusUnauthorized, CodeAuthFailed},
		{http.StatusForbidden, CodeForbidden},
		{http.StatusNotFound, CodeNotFound},
		{http.StatusGone, CodeGone},
		{http.StatusTooManyRequests, CodeRateLimited},
		{http.StatusInternalServerError, CodeServerError},
		{http.StatusServiceUnavailable, CodeServerError},
		{http.StatusNoContent, CodeUnexpectedStatus},
		{http.StatusPartialContent, CodeUnexpectedStatus},
	}
	for _, tc := range cases {
		if got := httpStatusError(tc.status); got != tc.code {
			t.Fatalf("status %d -> %s, want %s", tc.status, got, tc.code)
		}
	}
}

func TestA208F2ErrorDoesNotUnwrapSecrets(t *testing.T) {
	failure := acquireErr(CodeTransportFailed, PhaseRequest)
	failure.NativeCode = "read_failed"
	if _, ok := interface{}(failure).(interface{ Unwrap() error }); ok {
		t.Fatal("AcquisitionError exposes an Unwrap that could reveal an underlying error")
	}
	if strings.Contains(failure.Error(), "http") || strings.Contains(failure.Error(), "://") {
		t.Fatalf("diagnostic text carries transport detail: %q", failure.Error())
	}
}
