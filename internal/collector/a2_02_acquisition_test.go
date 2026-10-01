package collector

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/d4rpell/Ariadne/internal/bundle"
	contract "github.com/d4rpell/Ariadne/pkg/evidence"
)

// Acquisition cases of the A2-02 plan (handoff §4.2 rows "Retries",
// "Ritmo/concurrencia" and "Vacío/fallo inicial"): one attempt per operation,
// no implicit retry, one in-flight request at a time and a closed plan that is
// never silently reduced.

func TestA202NoRetries(t *testing.T) {
	statusCases := map[string]struct {
		status int
		code   bundle.CollectionCode
	}{
		"401":             {401, bundle.CodeAuthFailed},
		"403":             {403, bundle.CodeForbidden},
		"404":             {404, bundle.CodeNotFound},
		"429_retry_after": {429, bundle.CodeRateLimited},
		"500":             {500, bundle.CodeServerError},
	}
	for name, testCase := range statusCases {
		t.Run(name, func(t *testing.T) {
			config := a202Config(t)
			header := http.Header{}
			if name == "429_retry_after" {
				header.Set("Retry-After", "1")
			}
			result, err, transport := a202Collect(t, config, []a202RoundTrip{
				{status: testCase.status, body: `{"kind":"Status"}`, header: header},
				// The control answers a second attempt: if the collector retried,
				// it would consume this step and the count below would differ.
				a202JSONResponse(a202CompleteDocument("u1", "n1")),
			})
			if err == nil || err.Error() != "collector: "+string(testCase.code) {
				t.Fatalf("err = %v, want collector: %s", err, testCase.code)
			}
			if transport.callCount() != 1 {
				t.Fatalf("attempts = %d, want exactly 1", transport.callCount())
			}
			if len(result.Acquisition.Operations) != 1 {
				t.Fatalf("operations = %d, want 1", len(result.Acquisition.Operations))
			}
			operation := result.Acquisition.Operations[0]
			if operation.State != bundle.OperationFailed || operation.Diagnostic != testCase.code {
				t.Fatalf("operation = %+v", operation)
			}
			if operation.StatusCode != testCase.status {
				t.Fatalf("status = %d, want %d", operation.StatusCode, testCase.status)
			}
		})
	}
	t.Run("timeout", func(t *testing.T) {
		config := a202Config(t)
		_, err, transport := a202Collect(t, config, []a202RoundTrip{
			a202RoundTrip{err: &net.DNSError{IsTimeout: true, Err: "synthetic timeout"}},
			a202JSONResponse(a202CompleteDocument("u1", "n1")),
		})
		if err == nil || err.Error() != "collector: request_timeout" {
			t.Fatalf("err = %v, want collector: request_timeout", err)
		}
		if transport.callCount() != 1 {
			t.Fatalf("attempts = %d, want exactly 1", transport.callCount())
		}
	})
	t.Run("connection_failure", func(t *testing.T) {
		config := a202Config(t)
		_, err, transport := a202Collect(t, config, []a202RoundTrip{
			a202RoundTrip{err: errors.New("synthetic connection failure " + a202MarkerToken)},
			a202JSONResponse(a202CompleteDocument("u1", "n1")),
		})
		if err == nil || err.Error() != "collector: transport_failed" {
			t.Fatalf("err = %v, want collector: transport_failed", err)
		}
		if transport.callCount() != 1 {
			t.Fatalf("attempts = %d, want exactly 1", transport.callCount())
		}
	})
	t.Run("body_eof", func(t *testing.T) {
		config := a202Config(t)
		_, err, transport := a202Collect(t, config, []a202RoundTrip{
			a202RoundTrip{status: 200, handler: func(request *http.Request) (*http.Response, error) {
				return &http.Response{
					StatusCode: 200,
					Header:     http.Header{},
					Body:       &a202EofMidBody{},
					Request:    request,
				}, nil
			}},
			a202JSONResponse(a202CompleteDocument("u1", "n1")),
		})
		if err == nil || err.Error() != "collector: body_read_failed" {
			t.Fatalf("err = %v, want collector: body_read_failed", err)
		}
		if transport.callCount() != 1 {
			t.Fatalf("attempts = %d, want exactly 1", transport.callCount())
		}
	})
	t.Run("redirect", func(t *testing.T) {
		config := a202Config(t)
		_, err, transport := a202Collect(t, config, []a202RoundTrip{
			a202RoundTrip{status: 302, header: http.Header{"Location": []string{"https://synthetic.example:6443/api/v1/namespaces/payments/pods"}}},
			a202JSONResponse(a202CompleteDocument("u1", "n1")),
		})
		if err == nil || err.Error() != "collector: redirect_refused" {
			t.Fatalf("err = %v, want collector: redirect_refused", err)
		}
		if transport.callCount() != 1 {
			t.Fatalf("attempts = %d, want exactly 1", transport.callCount())
		}
	})
}

// a202EofMidBody delivers a prefix and then fails: the response is truncated
// and can never become a source.
type a202EofMidBody struct{ delivered bool }

func (b *a202EofMidBody) Read(p []byte) (int, error) {
	if !b.delivered {
		b.delivered = true
		return copy(p, `{"apiVersion":"v1","kind":"PodList","items":[`), nil
	}
	return 0, io.ErrUnexpectedEOF
}

func (b *a202EofMidBody) Close() error { return nil }

func TestA202RateAndConcurrency(t *testing.T) {
	t.Run("fast_responses", func(t *testing.T) {
		config := a202Config(t)
		transport := newA202ScriptedTransport(
			a202JSONResponse(a202Document(a202CompletePod("u1", "n1"))),
			a202JSONResponse(a202Pod("u1", "n1")),
			a202JSONResponse(a202Pod("u1", "n1")),
		)
		clock := newA202Clock(t, a202StartMoment)
		if _, err := collectWithDependencies(context.Background(), config, transport, clock); err != nil {
			t.Fatalf("collect: %v", err)
		}
		// Every start after the first waits the fixed separation: two waits for
		// three requests.
		waits := clock.recordedWaits()
		if len(waits) != 2 {
			t.Fatalf("waits = %v, want one separation before each of the two following starts", waits)
		}
		for _, wait := range waits {
			if wait != requestSpacing {
				t.Fatalf("separation = %v, want %v", wait, requestSpacing)
			}
		}
	})
	t.Run("pagination", func(t *testing.T) {
		config := a202Config(t)
		page1 := `{"apiVersion":"v1","kind":"PodList","metadata":{"resourceVersion":"7","continue":"token-2"},"items":[]}`
		page2 := `{"apiVersion":"v1","kind":"PodList","metadata":{"resourceVersion":"7"},"items":[]}`
		transport := newA202ScriptedTransport(a202JSONResponse(page1), a202JSONResponse(page2))
		clock := newA202Clock(t, a202StartMoment)
		if _, err := collectWithDependencies(context.Background(), config, transport, clock); err != nil {
			t.Fatalf("collect: %v", err)
		}
		if len(clock.recordedWaits()) != 1 {
			t.Fatalf("waits = %v, want the pagination request to be separated too", clock.recordedWaits())
		}
	})
	t.Run("two_rounds", func(t *testing.T) {
		config := a202Config(t)
		transport := newA202ScriptedTransport(
			a202JSONResponse(a202Document(a202CompletePod("u1", "n1"))),
			a202JSONResponse(a202Pod("u1", "n1")),
			a202JSONResponse(a202Pod("u1", "n1")),
		)
		clock := newA202Clock(t, a202StartMoment)
		result, err := collectWithDependencies(context.Background(), config, transport, clock)
		if err != nil {
			t.Fatalf("collect: %v", err)
		}
		rounds := map[uint8]int{}
		for _, operation := range result.Acquisition.Operations {
			if operation.Verb == "get" {
				rounds[operation.Round]++
			}
		}
		if rounds[1] != 1 || rounds[2] != 1 {
			t.Fatalf("rounds = %v, want exactly one get per round", rounds)
		}
		if result.Acquisition.Plan.PlannedReReadsPerTarget != 2 {
			t.Fatalf("planned re-reads = %d, want 2", result.Acquisition.Plan.PlannedReReadsPerTarget)
		}
	})
	t.Run("cancel_wait", func(t *testing.T) {
		config := a202Config(t)
		transport := newA202ScriptedTransport(
			a202JSONResponse(a202Document(a202CompletePod("u1", "n1"))),
			a202JSONResponse(a202Pod("u1", "n1")),
			a202JSONResponse(a202Pod("u1", "n1")),
		)
		clock := newA202Clock(t, a202StartMoment)
		clock.failWait = context.Canceled
		_, err := collectWithDependencies(context.Background(), config, transport, clock)
		if err == nil || err.Error() != "collector: cancelled" {
			t.Fatalf("err = %v, want collector: cancelled", err)
		}
		if transport.callCount() != 1 {
			t.Fatalf("attempts = %d, want the cancelled wait to stop the run after the first request", transport.callCount())
		}
	})
	t.Run("single_inflight", func(t *testing.T) {
		// The scripted transport registers the number of overlapping calls: the
		// profile allows exactly one.
		transport := &a202ConcurrencyTransport{}
		config := a202Config(t)
		clock := newA202Clock(t, a202StartMoment)
		if _, err := collectWithDependencies(context.Background(), config, transport, clock); err != nil {
			t.Fatalf("collect: %v", err)
		}
		if transport.maximum != 1 {
			t.Fatalf("maximum concurrency = %d, want 1", transport.maximum)
		}
	})
}

// a202ConcurrencyTransport answers valid documents and records the maximum
// number of overlapping calls.
type a202ConcurrencyTransport struct {
	inflight int
	maximum  int
	calls    int
}

func (t *a202ConcurrencyTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	t.inflight++
	if t.inflight > t.maximum {
		t.maximum = t.inflight
	}
	t.calls++
	document := a202Document(a202CompletePod("u1", "n1"))
	if t.calls > 1 {
		document = a202Pod("u1", "n1")
	}
	t.inflight--
	body := newA202Body(document)
	return &http.Response{StatusCode: 200, Header: http.Header{}, Body: body, Request: request}, nil
}

func TestA202EmptyAndEarlyAbort(t *testing.T) {
	t.Run("empty_list", func(t *testing.T) {
		config := a202Config(t)
		result, err, transport := a202Collect(t, config, []a202RoundTrip{
			a202JSONResponse(`{"apiVersion":"v1","kind":"PodList","metadata":{"resourceVersion":"7"},"items":[]}`),
		})
		if err != nil {
			t.Fatalf("collect: %v", err)
		}
		if transport.callCount() != 1 {
			t.Fatalf("requests = %d, want only the empty list", transport.callCount())
		}
		if len(result.Acquisition.Captures) != 1 {
			t.Fatalf("captures = %d, want the admitted empty source", len(result.Acquisition.Captures))
		}
		if len(result.Bundles) != 0 {
			t.Fatalf("bundles = %d, want zero: no subject may be invented", len(result.Bundles))
		}
		if result.Acquisition.Termination != contract.TerminationUnknown {
			t.Fatalf("termination = %q, want unknown without verifiable progress", result.Acquisition.Termination)
		}
		if result.Incomplete == false {
			t.Fatal("an empty observation must report itself incomplete")
		}
	})
	t.Run("config_failure", func(t *testing.T) {
		config := a202Config(t)
		config.ClusterAlias = "."
		result, err, transport := a202Collect(t, config, []a202RoundTrip{
			a202JSONResponse(a202CompleteDocument("u1", "n1")),
		})
		if err == nil || err.Error() != "collector: invalid_config" {
			t.Fatalf("err = %v, want collector: invalid_config", err)
		}
		if transport.callCount() != 0 {
			t.Fatalf("requests = %d, want 0", transport.callCount())
		}
		if len(result.Bundles) != 0 {
			t.Fatal("a rejected configuration produced a bundle")
		}
	})
	t.Run("first_request_forbidden", func(t *testing.T) {
		config := a202Config(t)
		result, err, _ := a202Collect(t, config, []a202RoundTrip{{status: 403, body: "{}"}})
		if err == nil || err.Error() != "collector: forbidden" {
			t.Fatalf("err = %v, want collector: forbidden", err)
		}
		if len(result.Bundles) != 0 {
			t.Fatal("a failure without identity produced a bundle")
		}
		if result.Acquisition.Termination != contract.TerminationUnknown {
			t.Fatalf("termination = %q, want unknown without progress", result.Acquisition.Termination)
		}
		if result.Incomplete == false {
			t.Fatal("an aborted run without bundles must report itself incomplete")
		}
	})
	t.Run("first_body_invalid", func(t *testing.T) {
		config := a202Config(t)
		result, err, _ := a202Collect(t, config, []a202RoundTrip{
			a202JSONResponse("not json at all"),
		})
		if err == nil || err.Error() != "collector: response_invalid" {
			t.Fatalf("err = %v, want collector: response_invalid", err)
		}
		if len(result.Acquisition.Captures) != 0 {
			t.Fatalf("captures = %d, want 0", len(result.Acquisition.Captures))
		}
		if len(result.Bundles) != 0 {
			t.Fatal("an invalid body produced a bundle")
		}
	})
	t.Run("namespace_order_and_partial_plan", func(t *testing.T) {
		// Two namespaces are requested; the first completes and the second is
		// forbidden. The pending namespace stays visible and the first bundle
		// keeps the concrete global error.
		config := a202Config(t)
		config.Namespaces = []string{a202NamespaceAlt, a202Namespace}
		// The admitted page of the first namespace belongs to "orders"? No: the
		// listed document must address the namespace being listed, so the first
		// response carries the identity of the first namespace.
		transport := newA202ScriptedTransport(
			a202JSONResponse(a202DocumentFor(a202NamespaceAlt, a202CompletePodFor(a202NamespaceAlt, "u1", "n1"))),
			a202RoundTrip{status: 403, body: "{}"},
		)
		clock := newA202Clock(t, a202StartMoment)
		result, err := collectWithDependencies(context.Background(), config, transport, clock)
		if err == nil || err.Error() != "collector: forbidden" {
			t.Fatalf("err = %v, want collector: forbidden", err)
		}
		// Namespaces are addressed in lexical order: orders before payments.
		paths := transport.requestURLs()
		if !strings.Contains(paths[0], "/namespaces/orders/pods") {
			t.Fatalf("first request = %q, want the lexical first namespace", paths[0])
		}
		if len(result.Acquisition.Plan.PendingNamespaces) != 1 || result.Acquisition.Plan.PendingNamespaces[0] != a202Namespace {
			t.Fatalf("pending = %v, want the unvisited namespace", result.Acquisition.Plan.PendingNamespaces)
		}
		if len(result.Acquisition.Termination) == 0 || result.Acquisition.Termination != contract.TerminationAborted {
			t.Fatalf("termination = %q, want aborted", result.Acquisition.Termination)
		}
		if len(result.Bundles) == 0 {
			t.Fatal("the admitted namespace produced no bundle")
		}
		for _, candidate := range result.Bundles {
			if !a202HasWarning(candidate.Bundle.Provenance.Warnings, "tool_failure", contract.WarningContradictory, "collector acquisition did not complete") {
				t.Fatalf("bundle without the acquisition warning: %+v", candidate.Bundle.Provenance.Warnings)
			}
			if !a202HasError(candidate.Bundle.Provenance.Errors, "collector: forbidden") {
				t.Fatalf("bundle without the concrete global error: %v", candidate.Bundle.Provenance.Errors)
			}
			if candidate.Bundle.Provenance.Coverage.Termination != contract.TerminationAborted {
				t.Fatalf("coverage termination = %q", candidate.Bundle.Provenance.Coverage.Termination)
			}
		}
	})
}

var _ = time.Second
