package collector

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/d4rpell/Ariadne/internal/bundle"
	"github.com/d4rpell/Ariadne/internal/ingest"
	contract "github.com/d4rpell/Ariadne/pkg/evidence"
)

// Diagnostic cases of the A2-02 plan (handoff §4.2 row "Diagnósticos"): the
// closed catalog, the precedence of simultaneous conditions and the redaction
// of every underlying failure.

func TestA202DiagnosticCatalog(t *testing.T) {
	for _, code := range bundle.Codes() {
		t.Run(string(code), func(t *testing.T) {
			message := bundle.CollectionMessage(code)
			if message != "collector: "+string(code) {
				t.Fatalf("message = %q, want %q", message, "collector: "+string(code))
			}
			if !bundle.CollectionCodeKnown(code) {
				t.Fatalf("%q is not known", code)
			}
		})
	}
	t.Run("unknown_code_has_no_message", func(t *testing.T) {
		unknown := bundle.CollectionCode("synthetic_unknown")
		if bundle.CollectionMessage(unknown) != "" {
			t.Fatal("an unknown code produced a message")
		}
		if bundle.CollectionCodeKnown(unknown) {
			t.Fatal("an unknown code is reported as known")
		}
	})
	t.Run("codes_are_unique_and_closed", func(t *testing.T) {
		codes := bundle.Codes()
		seen := map[bundle.CollectionCode]bool{}
		for _, code := range codes {
			if seen[code] {
				t.Fatalf("duplicated code %q", code)
			}
			seen[code] = true
		}
		if len(codes) != 34 {
			t.Fatalf("catalog has %d codes, want the closed 34", len(codes))
		}
	})
}

func TestA202DiagnosticPrecedence(t *testing.T) {
	t.Run("config_before_network", func(t *testing.T) {
		config := a202Config(t)
		config.Selector = "wrong"
		transport := newA202ScriptedTransport(a202RoundTrip{err: errors.New("must not be reached")})
		_, err := collectWithDependencies(context.Background(), config, transport, newA202Clock(t, a202StartMoment))
		if err == nil || err.Error() != "collector: invalid_config" {
			t.Fatalf("err = %v, want collector: invalid_config", err)
		}
		if transport.callCount() != 0 {
			t.Fatalf("transport calls = %d, want 0", transport.callCount())
		}
	})
	t.Run("global_deadline_and_request_timeout", func(t *testing.T) {
		// With the run deadline already expired, the run reports time_limit and
		// never attributes the stop to a per-request timeout.
		config := a202Config(t)
		transport := newA202ScriptedTransport(a202JSONResponse(a202CompleteDocument("u1", "n1")))
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		clock := &a202DeadlineClock{start: a202StartMoment, expired: true}
		result, err := collectWithDependencies(ctx, config, transport, clock)
		if err == nil {
			t.Fatal("an expired deadline produced a successful run")
		}
		if err.Error() != "collector: cancelled" && err.Error() != "collector: time_limit" {
			t.Fatalf("err = %v, want cancelled or time_limit", err)
		}
		if len(result.Acquisition.GlobalErrors) == 0 {
			t.Fatal("the stop is not visible as a global error")
		}
	})
	t.Run("response_and_total_bytes_same_probe", func(t *testing.T) {
		// One probe byte exceeds both the per-response and the global budget:
		// exactly one diagnostic, and it is response_limit.
		// The global budget has exactly the room of the per-response limit: the
		// first chunk fills it without exceeding, and the single probe byte
		// trips both counters at once.
		budget := &budgetState{totalBodyBytes: maxTotalBodyBytes - maxResponseBodyBytes}
		payload := strings.Repeat("a", maxResponseBodyBytes+8)
		response, body := a202Response(t, 200, payload)
		body.limit = maxResponseBodyBytes
		body.maxChunk = maxResponseBodyBytes
		_, err := readResponse(context.Background(), response, budget)
		if err == nil || err.Error() != "collector: response_limit" {
			t.Fatalf("err = %v, want collector: response_limit", err)
		}
		// The probe byte was really read, so the counter records it: the global
		// accounting stays exact (L+1) and the more specific guard owns the code.
		if budget.totalBodyBytes != maxTotalBodyBytes+1 {
			t.Fatalf("global counter = %d, want the really read bytes %d", budget.totalBodyBytes, maxTotalBodyBytes+1)
		}
		if body.afterLimit != 0 {
			t.Fatalf("reads after the probe = %d, want 0", body.afterLimit)
		}
		if body.closes != 1 {
			t.Fatalf("closes = %d, want 1", body.closes)
		}
	})
	t.Run("budget_then_context_cancel", func(t *testing.T) {
		// A budget guard fires and the wait it triggers returns a cancellation:
		// the cause that fired is preserved.
		budget := &budgetState{}
		for index := 0; index < 1024; index++ {
			if _, ok := checkedAdd(budget.requests, 1, 1024); !ok {
				t.Fatal("the request budget refused an admitted attempt")
			}
			budget.requests++
		}
		clock := newA202Clock(t, a202StartMoment)
		clock.failWait = context.Canceled
		err := budget.beforeRequest(context.Background(), clock)
		if err == nil || err.Error() != "collector: request_limit" {
			t.Fatalf("err = %v, want collector: request_limit", err)
		}
		if budget.abortCode != bundle.CodeRequestLimit {
			t.Fatalf("abort code = %q, want request_limit", budget.abortCode)
		}
	})
	t.Run("scope_mismatch_with_sensitive_content", func(t *testing.T) {
		config := a202Config(t)
		foreign := `{"apiVersion":"v1","kind":"PodList","metadata":{"resourceVersion":"7"},"items":[` +
			`{"apiVersion":"v1","kind":"Pod","metadata":{"uid":"u1","namespace":"other","name":"` + a202MarkerForeign + `"},` +
			`"spec":{"containers":[{"name":"api","image":"` + a202MarkerToken + `"}]}}]}`
		result, err, _ := a202Collect(t, config, []a202RoundTrip{a202JSONResponse(foreign)})
		if err == nil || err.Error() != "collector: scope_mismatch" {
			t.Fatalf("err = %v, want collector: scope_mismatch", err)
		}
		for _, marker := range []string{a202MarkerForeign, a202MarkerToken} {
			if a202Anywhere(result, marker) {
				t.Fatalf("marker %q reached a publishable artefact", marker)
			}
		}
	})
	t.Run("repeated_token_before_next_request_limit", func(t *testing.T) {
		config := a202Config(t)
		page := `{"apiVersion":"v1","kind":"PodList","metadata":{"resourceVersion":"7","continue":"token-x"},"items":[]}`
		_, err, transport := a202Collect(t, config, []a202RoundTrip{a202JSONResponse(page), a202JSONResponse(page)})
		if err == nil || err.Error() != "collector: pagination_invalid" {
			t.Fatalf("err = %v, want collector: pagination_invalid", err)
		}
		if transport.callCount() != 2 {
			t.Fatalf("requests = %d: the repeated token must be detected without a further request", transport.callCount())
		}
	})
	t.Run("http_status_before_body_semantics", func(t *testing.T) {
		config := a202Config(t)
		body := `{"apiVersion":"v1","kind":"PodList","metadata":{"resourceVersion":"7"},"items":[` + a202CompletePod("u1", "n1") + `]}`
		result, err, _ := a202Collect(t, config, []a202RoundTrip{a202RoundTrip{status: 500, body: body}})
		if err == nil || err.Error() != "collector: server_error" {
			t.Fatalf("err = %v, want collector: server_error", err)
		}
		if len(result.Acquisition.Captures) != 0 {
			t.Fatal("the body of a failed status was published as a source")
		}
	})
	t.Run("failure_after_three_categories", func(t *testing.T) {
		// A complete observation preceded the failure: the previous bundle does
		// not keep "complete" after the run aborts.
		config := a202Config(t)
		steps := []a202RoundTrip{
			a202JSONResponse(a202CompleteDocument("u1", "n1")),
			a202RoundTrip{status: 403, body: "{}"},
		}
		result, err, _ := a202Collect(t, config, steps)
		if err == nil || err.Error() != "collector: forbidden" {
			t.Fatalf("err = %v, want collector: forbidden", err)
		}
		for _, candidate := range result.Bundles {
			if candidate.Bundle.Provenance.Completeness == "complete" {
				t.Fatalf("a bundle kept complete after the failure: %+v", candidate.Bundle.Provenance)
			}
			if candidate.Bundle.Provenance.Coverage.Termination != contractTerminationAborted() {
				t.Fatalf("coverage termination = %q", candidate.Bundle.Provenance.Coverage.Termination)
			}
		}
	})
}

// a202DeadlineClock reports an expired deadline for every WithTimeout call.
type a202DeadlineClock struct {
	start   string
	expired bool
}

func (c *a202DeadlineClock) Now() clockSample {
	moment, err := timeParse(c.start)
	if err != nil {
		panic(err)
	}
	return clockSample{UTC: moment}
}

func (c *a202DeadlineClock) Wait(parent context.Context, delay time.Duration) error {
	return parent.Err()
}

func (c *a202DeadlineClock) WithTimeout(parent context.Context, timeout time.Duration) (context.Context, context.CancelFunc) {
	ctx, cancel := context.WithCancel(parent)
	if c.expired {
		cancel()
	}
	return ctx, cancel
}

// a202Anywhere scans every publishable field of one result for a marker.
func a202Anywhere(result Result, marker string) bool {
	if marker == "" {
		return false
	}
	for _, capture := range result.Acquisition.Captures {
		if strings.Contains(string(capture.Bytes), marker) || strings.Contains(capture.Alias, marker) {
			return true
		}
	}
	for _, operation := range result.Acquisition.Operations {
		if strings.Contains(operation.Name, marker) {
			return true
		}
	}
	for _, failure := range result.Acquisition.GlobalErrors {
		if strings.Contains(failure, marker) {
			return true
		}
	}
	for _, diagnostic := range result.Acquisition.Diagnostics {
		if strings.Contains(string(diagnostic.Code), marker) || strings.Contains(diagnostic.FieldLocator, marker) {
			return true
		}
	}
	for _, candidate := range result.Bundles {
		if strings.Contains(string(candidate.Bundle.Subject.Name), marker) {
			return true
		}
		for _, failure := range candidate.Bundle.Provenance.Errors {
			if strings.Contains(failure, marker) {
				return true
			}
		}
		for _, warning := range candidate.Bundle.Provenance.Warnings {
			if strings.Contains(warning.Message, marker) || strings.Contains(warning.Code, marker) {
				return true
			}
		}
		for _, item := range candidate.Bundle.Evidence {
			if strings.Contains(string(item.Locator), marker) || strings.Contains(item.Source, marker) {
				return true
			}
			if item.Value != nil && strings.Contains(*item.Value, marker) {
				return true
			}
		}
	}
	return false
}

func contractTerminationAborted() contract.CoverageTermination {
	return contract.TerminationAborted
}

// timeParse parses one RFC3339 instant for the deadline clock.
func timeParse(value string) (time.Time, error) { return time.Parse(time.RFC3339, value) }

// TestA202ErrorRedaction proves that no underlying failure reaches a
// publishable value: every case introduces distinct markers in the token, the
// endpoint and a foreign name, and the scan covers the error, the diagnostics,
// the record, the provenance and the artifacts.
func TestA202ErrorRedaction(t *testing.T) {
	markers := []string{a202MarkerToken, a202MarkerEndpoint, a202MarkerForeign}
	scan := func(t *testing.T, result Result, err error, extra ...string) {
		t.Helper()
		if err != nil {
			for _, marker := range markers {
				if strings.Contains(err.Error(), marker) {
					t.Fatalf("the returned error exposes %q: %v", marker, err)
				}
			}
		}
		for _, marker := range markers {
			if a202Anywhere(result, marker) {
				t.Fatalf("marker %q reached a publishable artefact", marker)
			}
			for _, artefact := range extra {
				if strings.Contains(artefact, marker) {
					t.Fatalf("marker %q reached an encoded artefact", marker)
				}
			}
		}
	}
	encodeArtifacts := func(t *testing.T, result Result) []string {
		t.Helper()
		artefacts := []string{}
		for _, candidate := range result.Bundles {
			encoded, err := bundle.Encode(candidate.Bundle)
			if err != nil {
				continue
			}
			artefacts = append(artefacts, string(encoded.Envelope), string(encoded.HashInput), encoded.Hash)
		}
		return artefacts
	}
	t.Run("http_error_body", func(t *testing.T) {
		config := a202Config(t)
		body := `{"kind":"Status","message":"token ` + a202MarkerToken + ` endpoint ` + a202MarkerEndpoint + ` pod ` + a202MarkerForeign + `"}`
		result, err, _ := a202Collect(t, config, []a202RoundTrip{a202RoundTrip{status: 403, body: body}})
		scan(t, result, err, encodeArtifacts(t, result)...)
		if err == nil || err.Error() != "collector: forbidden" {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("tls_error", func(t *testing.T) {
		config := a202Config(t)
		transport := newA202ScriptedTransport(a202RoundTrip{err: errors.New("tls failure for " + a202MarkerEndpoint + " with " + a202MarkerToken)})
		clock := newA202Clock(t, a202StartMoment)
		result, err := collectWithDependencies(context.Background(), config, transport, clock)
		scan(t, result, err, encodeArtifacts(t, result)...)
	})
	t.Run("transport_error", func(t *testing.T) {
		config := a202Config(t)
		transport := newA202ScriptedTransport(a202RoundTrip{err: errors.New("dial " + a202MarkerEndpoint + " rejected " + a202MarkerForeign)})
		clock := newA202Clock(t, a202StartMoment)
		result, err := collectWithDependencies(context.Background(), config, transport, clock)
		scan(t, result, err, encodeArtifacts(t, result)...)
	})
	t.Run("reader_error", func(t *testing.T) {
		config := a202Config(t)
		transport := newA202ScriptedTransport(a202RoundTrip{status: 200, handler: func(request *http.Request) (*http.Response, error) {
			return &http.Response{StatusCode: 200, Header: http.Header{}, Body: &a202MarkerBody{marker: a202MarkerForeign}}, nil
		}})
		clock := newA202Clock(t, a202StartMoment)
		result, err := collectWithDependencies(context.Background(), config, transport, clock)
		scan(t, result, err, encodeArtifacts(t, result)...)
	})
	t.Run("close_error", func(t *testing.T) {
		config := a202Config(t)
		transport := newA202ScriptedTransport(a202RoundTrip{status: 200, handler: func(request *http.Request) (*http.Response, error) {
			return &http.Response{StatusCode: 200, Header: http.Header{}, Body: &a202MarkerBody{marker: a202MarkerToken, failClose: true}}, nil
		}})
		clock := newA202Clock(t, a202StartMoment)
		result, err := collectWithDependencies(context.Background(), config, transport, clock)
		scan(t, result, err, encodeArtifacts(t, result)...)
	})
	t.Run("unknown_diagnostic_code", func(t *testing.T) {
		// A code outside the closed catalog is never rendered: the renderer
		// returns no message and the integration fails with projection_failed.
		if bundle.CollectionMessage(bundle.CollectionCode(a202MarkerForeign)) != "" {
			t.Fatal("an unknown code produced a message")
		}
	})
	t.Run("invalid_locator", func(t *testing.T) {
		// A locator outside the closed grammar is refused by the validator, so
		// free text never reaches the record.
		if ingestLocatorValid("free text " + a202MarkerForeign) {
			t.Fatal("a free-text locator was admitted")
		}
	})
}

// a202MarkerBody delivers one marker in its reader failure.
type a202MarkerBody struct {
	marker    string
	failClose bool
}

func (b *a202MarkerBody) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	copy(p, `{"apiVersion":"v1"`)
	return 17, errors.New("read failed with marker " + b.marker)
}

func (b *a202MarkerBody) Close() error {
	if b.failClose {
		return errors.New("close failed with marker " + b.marker)
	}
	return nil
}

// ingestLocatorValid is the closed locator validator used by the redaction
// control.
func ingestLocatorValid(locator string) bool { return ingest.PodListLocatorValid(locator) }
