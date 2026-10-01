package collector

import (
	"context"
	"testing"
	"time"

	"github.com/d4rpell/Ariadne/internal/bundle"
	contract "github.com/d4rpell/Ariadne/pkg/evidence"
)

// Clock cases of the A2-02 plan (handoff §4.2 row "Reloj"): the capture instant
// is the end of each response, budgets use the monotonic reading, and an
// unusable civil clock aborts without clamping.

func TestA202Clock(t *testing.T) {
	t.Run("capture_end_time", func(t *testing.T) {
		config := a202Config(t)
		transport := newA202ScriptedTransport(a202JSONResponse(`{"apiVersion":"v1","kind":"PodList","metadata":{"resourceVersion":"7"},"items":[]}`))
		clock := newA202Clock(t, a202StartMoment)
		clock.advance(2 * time.Second)
		result, err := collectWithDependencies(context.Background(), config, transport, clock)
		if err != nil {
			t.Fatalf("collect: %v", err)
		}
		capture := result.Acquisition.Captures[0]
		want := time.Date(2026, 10, 1, 10, 0, 2, 0, time.UTC)
		if capture.Observation.ObservedAt == nil || !capture.Observation.ObservedAt.Time.Equal(want) {
			t.Fatalf("observed_at = %v, want %v", capture.Observation.ObservedAt, want)
		}
	})
	t.Run("monotonic_budget", func(t *testing.T) {
		config := a202Config(t)
		transport := newA202ScriptedTransport(
			a202JSONResponse(`{"apiVersion":"v1","kind":"PodList","metadata":{"resourceVersion":"7"},"items":[]}`),
		)
		clock := newA202Clock(t, a202StartMoment)
		clock.advance(3 * time.Second)
		result, err := collectWithDependencies(context.Background(), config, transport, clock)
		if err != nil {
			t.Fatalf("collect: %v", err)
		}
		if result.Acquisition.Stats.Elapsed < 3*time.Second {
			t.Fatalf("elapsed = %v, want the monotonic reading", result.Acquisition.Stats.Elapsed)
		}
	})
	t.Run("civil_regression", func(t *testing.T) {
		config := a202Config(t)
		transport := newA202ScriptedTransport(
			a202JSONResponse(`{"apiVersion":"v1","kind":"PodList","metadata":{"resourceVersion":"7"},"items":[]}`),
			a202JSONResponse(`{"apiVersion":"v1","kind":"PodList","metadata":{"resourceVersion":"8"},"items":[]}`),
		)
		clock := &a202RegressingClock{start: time.Date(2026, 10, 1, 10, 0, 0, 0, time.UTC)}
		result, err := collectWithDependencies(context.Background(), config, transport, clock)
		if err == nil || err.Error() != "collector: clock_invalid" {
			t.Fatalf("err = %v, want collector: clock_invalid", err)
		}
		if !a202HasError(result.Acquisition.GlobalErrors, "collector: clock_invalid") {
			t.Fatalf("global errors = %v", result.Acquisition.GlobalErrors)
		}
		// The invalid reading is never clamped: ended_at stays absent while the
		// final instant cannot be validated.
		if result.Acquisition.EndedAt != nil {
			t.Fatal("an invalid final reading was published")
		}
	})
	t.Run("invalid_start", func(t *testing.T) {
		config := a202Config(t)
		transport := newA202ScriptedTransport(a202JSONResponse(`{"apiVersion":"v1","kind":"PodList","items":[]}`))
		clock := newA202Clock(t, a202StartMoment)
		clock.setCivil(time.Time{})
		result, err := collectWithDependencies(context.Background(), config, transport, clock)
		if err == nil || err.Error() != "collector: clock_invalid" {
			t.Fatalf("err = %v, want collector: clock_invalid", err)
		}
		if transport.callCount() != 0 {
			t.Fatalf("requests = %d, want none after an invalid start", transport.callCount())
		}
		if result.Acquisition.StartedAt != nil {
			t.Fatal("an invalid start was published")
		}
	})
	t.Run("invalid_end", func(t *testing.T) {
		config := a202Config(t)
		transport := newA202ScriptedTransport(a202JSONResponse(`{"apiVersion":"v1","kind":"PodList","metadata":{"resourceVersion":"7"},"items":[]}`))
		clock := &a202ZeroAfterStartClock{start: time.Date(2026, 10, 1, 10, 0, 0, 0, time.UTC)}
		result, err := collectWithDependencies(context.Background(), config, transport, clock)
		if err == nil || err.Error() != "collector: clock_invalid" {
			t.Fatalf("err = %v, want collector: clock_invalid", err)
		}
		if result.Acquisition.EndedAt != nil {
			t.Fatal("a zero final reading was published as a timestamp")
		}
	})
	t.Run("no_clamp", func(t *testing.T) {
		// The civil clock moves backwards between captures while the monotonic
		// reading advances: the run is aborted and no earlier instant is
		// published for the later capture.
		config := a202Config(t)
		transport := newA202ScriptedTransport(
			a202JSONResponse(`{"apiVersion":"v1","kind":"PodList","metadata":{"resourceVersion":"7"},"items":[]}`),
			a202JSONResponse(`{"apiVersion":"v1","kind":"PodList","metadata":{"resourceVersion":"8"},"items":[]}`),
		)
		clock := &a202RegressingClock{start: time.Date(2026, 10, 1, 10, 0, 0, 0, time.UTC)}
		result, err := collectWithDependencies(context.Background(), config, transport, clock)
		if err == nil || err.Error() != "collector: clock_invalid" {
			t.Fatalf("err = %v, want collector: clock_invalid", err)
		}
		for index, capture := range result.Acquisition.Captures {
			if capture.Observation.ObservedAt != nil && capture.Observation.ObservedAt.Time.Before(clock.start) {
				t.Fatalf("capture %d carries a clamped instant %v", index, capture.Observation.ObservedAt)
			}
		}
	})
	t.Run("clock_failure_after_response_keeps_previous_captures", func(t *testing.T) {
		// The civil clock dies exactly when the second response body has been
		// consumed, at the sampling that closes that response — never at the start
		// of the attempt. The whole body was really read, the attempt was already
		// counted, and leaving without a record would corrupt the accounting and
		// turn the acquisition failure into a projection failure; the failed
		// attempt must be recorded with clock_invalid and the first capture must
		// still reach its bundles as an incomplete abort.
		config := a202Config(t)
		clock := newA202ArmedClock(t, a202StartMoment)
		second := a202JSONResponse(`{"apiVersion":"v1","kind":"PodList","metadata":{"resourceVersion":"7"},"items":[]}`)
		second.onExhaust = clock.arm()
		transport := newA202ScriptedTransport(
			// First page: a Pod with an image, so the run has real progress and
			// a retained capture before the clock dies.
			a202JSONResponse(`{"apiVersion":"v1","kind":"PodList","metadata":{"resourceVersion":"7","continue":"token-2"},"items":[`+a202CompletePod("u1", "n1")+`]}`),
			// Second page: the whole body is consumed and only then the clock dies.
			second,
		)
		result, err := collectWithDependencies(context.Background(), config, transport, clock)
		if err == nil || err.Error() != "collector: clock_invalid" {
			t.Fatalf("err = %v, want collector: clock_invalid", err)
		}
		// The second request really reached the transport and its whole body was
		// consumed before the clock died: the scenario is the closing sampling,
		// not the start of the attempt.
		if transport.callCount() != 2 {
			t.Fatalf("requests = %d, want 2 real calls", transport.callCount())
		}
		bodies := transport.recordedBodies()
		if len(bodies) != 2 {
			t.Fatalf("recorded bodies = %d, want 2", len(bodies))
		}
		if bodies[1].reads == 0 || bodies[1].pos != len(bodies[1].data) {
			t.Fatalf("the second body was not consumed before the clock died: %d of %d bytes read", bodies[1].pos, len(bodies[1].data))
		}
		if !a202HasError(result.Acquisition.GlobalErrors, "collector: clock_invalid") {
			t.Fatalf("global errors = %v", result.Acquisition.GlobalErrors)
		}
		if result.Acquisition.Termination != contract.TerminationAborted {
			t.Fatalf("termination = %q, want aborted", result.Acquisition.Termination)
		}
		if len(result.Acquisition.Captures) != 1 {
			t.Fatalf("captures = %d, want the first page retained", len(result.Acquisition.Captures))
		}
		if len(result.Bundles) != 1 {
			t.Fatalf("bundles = %d, want the previous capture delivered as incomplete", len(result.Bundles))
		}
		// The request really reached the transport twice and both attempts are
		// visible in the record: the accounting stays coherent.
		if result.Acquisition.Stats.RequestsAttempted != 2 {
			t.Fatalf("requests attempted = %d, want 2", result.Acquisition.Stats.RequestsAttempted)
		}
		// The failed attempt keeps the start it really sampled: the gap is the
		// closing reading of the second response, not the whole window.
		failed := false
		for _, operation := range result.Acquisition.Operations {
			if operation.State == bundle.OperationFailed && operation.Diagnostic == bundle.CodeClockInvalid {
				failed = true
				if operation.StartedAt == nil || operation.EndedAt != nil || operation.Elapsed != 0 {
					t.Fatalf("the failed attempt is not the closing gap: %+v", operation)
				}
			}
		}
		if !failed {
			t.Fatalf("the failed attempt was not recorded: %+v", result.Acquisition.Operations)
		}
	})
	t.Run("acquisition_failure_and_clock_failure_coincide", func(t *testing.T) {
		// The API answers the second page with 403 and the civil clock dies in the
		// sampling that would have closed that operation. Both failures coincide:
		// the acquisition cause (forbidden) stays visible in the operation record
		// while the clock failure is the run-wide cause, and the capture already
		// admitted still reaches its bundle as an incomplete abort instead of the
		// whole result being lost behind a projection failure.
		config := a202Config(t)
		clock := newA202ArmedClock(t, a202StartMoment)
		forbidden := a202RoundTrip{status: 403}
		forbidden.onDeliver = clock.arm()
		transport := newA202ScriptedTransport(
			a202JSONResponse(`{"apiVersion":"v1","kind":"PodList","metadata":{"resourceVersion":"7","continue":"token-2"},"items":[`+a202CompletePod("u1", "n1")+`]}`),
			forbidden,
		)
		result, err := collectWithDependencies(context.Background(), config, transport, clock)
		if err == nil || err.Error() != "collector: clock_invalid" {
			t.Fatalf("err = %v, want collector: clock_invalid", err)
		}
		if !a202HasError(result.Acquisition.GlobalErrors, "collector: clock_invalid") {
			t.Fatalf("global errors = %v", result.Acquisition.GlobalErrors)
		}
		if result.Acquisition.Termination != contract.TerminationAborted {
			t.Fatalf("termination = %q, want aborted", result.Acquisition.Termination)
		}
		// The acquisition cause is preserved in its own record: the rejected
		// response stays visible as a failed operation whose closing reading never
		// arrived.
		failed := 0
		for _, operation := range result.Acquisition.Operations {
			if operation.Diagnostic == bundle.CodeForbidden {
				failed++
				if operation.State != bundle.OperationFailed || operation.StartedAt == nil || operation.EndedAt != nil {
					t.Fatalf("the forbidden operation is not coherent: %+v", operation)
				}
			}
		}
		if failed != 1 {
			t.Fatalf("forbidden operations = %d, want 1: %+v", failed, result.Acquisition.Operations)
		}
		// The previously admitted capture is still delivered, with the causes of
		// its incompleteness visible in the bundle.
		if len(result.Acquisition.Captures) != 1 {
			t.Fatalf("captures = %d, want the first page retained", len(result.Acquisition.Captures))
		}
		if len(result.Bundles) != 1 {
			t.Fatalf("bundles = %d, want the previous capture delivered as incomplete", len(result.Bundles))
		}
		provenance := result.Bundles[0].Bundle.Provenance
		if !a202HasError(provenance.Errors, "collector: clock_invalid") {
			t.Fatalf("bundle errors = %v, want the visible clock failure", provenance.Errors)
		}
		if !a202HasWarning(provenance.Warnings, "tool_failure", contract.WarningContradictory, "collector acquisition did not complete") {
			t.Fatalf("bundle warnings = %+v, want the run-wide failure", provenance.Warnings)
		}
		if result.Acquisition.Stats.RequestsAttempted != 2 || result.Acquisition.Stats.ResponsesFailed != 1 {
			t.Fatalf("stats = %+v, want two attempts and one failed response", result.Acquisition.Stats)
		}
	})
}

// a202ZeroAfterStartClock returns one valid civil reading and a zero one for
// every later read: the final instant can never be validated.
type a202ZeroAfterStartClock struct {
	start   time.Time
	elapsed time.Duration
	reads   int
}

func (c *a202ZeroAfterStartClock) Now() clockSample {
	c.reads++
	c.elapsed += time.Millisecond
	if c.reads == 1 {
		return clockSample{UTC: c.start, Elapsed: c.elapsed}
	}
	return clockSample{UTC: time.Time{}, Elapsed: c.elapsed}
}

func (c *a202ZeroAfterStartClock) Wait(parent context.Context, delay time.Duration) error { return nil }

func (c *a202ZeroAfterStartClock) WithTimeout(parent context.Context, timeout time.Duration) (context.Context, context.CancelFunc) {
	return context.WithCancel(parent)
}

// a202RegressingClock moves its civil reading backwards after the first capture
// while the monotonic reading keeps growing.
type a202RegressingClock struct {
	start   time.Time
	elapsed time.Duration
	reads   int
}

func (c *a202RegressingClock) Now() clockSample {
	c.reads++
	c.elapsed += time.Millisecond
	civil := c.start.Add(time.Duration(c.reads) * time.Second)
	if c.reads > 4 {
		civil = c.start.Add(-time.Hour)
	}
	return clockSample{UTC: civil, Elapsed: c.elapsed}
}

func (c *a202RegressingClock) Wait(ctx context.Context, delay time.Duration) error { return nil }

func (c *a202RegressingClock) WithTimeout(parent context.Context, timeout time.Duration) (context.Context, context.CancelFunc) {
	return context.WithCancel(parent)
}

var _ = bundle.CodeClockInvalid
var _ = contract.TerminationFinished
