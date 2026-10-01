package collector

import (
	"context"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/d4rpell/Ariadne/internal/bundle"
	contract "github.com/d4rpell/Ariadne/pkg/evidence"
)

// Raw-JSON cases of the A2-02 plan (handoff §4.2 rows "JSON crudo" y
// "Números descartados"): the scanner admits exactly one unambiguous document,
// refuses ambiguity without repairing it, and walks discarded values without
// decoding them.

// a202TripwireContext is the context of the cancellation cases: it reports no
// error until its Nth read of Err, then the scripted cause, so the cancellation
// is initiated by the walk itself — the only caller of Err during a discard.
// The reads are synchronized: a child context watcher may read it concurrently
// with the walk that drives it.
type a202TripwireContext struct {
	mu      sync.Mutex
	checks  int
	after   int
	cause   error
	done    chan struct{}
	flipped bool
}

func newA202TripwireContext(after int, cause error) *a202TripwireContext {
	return &a202TripwireContext{after: after, cause: cause, done: make(chan struct{})}
}

func (c *a202TripwireContext) Deadline() (time.Time, bool) { return time.Time{}, false }

func (c *a202TripwireContext) Done() <-chan struct{} { return c.done }

func (c *a202TripwireContext) Err() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.checks++
	if c.checks < c.after {
		return nil
	}
	if !c.flipped {
		c.flipped = true
		close(c.done)
	}
	return c.cause
}

func (c *a202TripwireContext) Value(any) any { return nil }

// TestA202RawJSONCancellation is the T04 correction: the discarding walks
// consult the run context at every consumed token, so a large discarded value
// stops on the first token after the caller gave up instead of being walked to
// its end. The tripwire is driven by those checks: without them the walk would
// complete and the response would be admitted.
func TestA202RawJSONCancellation(t *testing.T) {
	// A large discarded value: a long array of long numbers.
	document := "[" + strings.Repeat("123456789,", 20000) + "0]"
	t.Run("discard_stops_mid_walk", func(t *testing.T) {
		scanner := newRawScanner([]byte(document))
		scanner.ctx = newA202TripwireContext(2, context.Canceled)
		if scanner.skipValue(0) {
			t.Fatal("the discarded value was walked to its end after the cancellation")
		}
		if !scanner.cancelledHit {
			t.Fatal("the stop was not attributed to the expired context")
		}
		if scanner.limitHit {
			t.Fatal("the stop was attributed to a raw limit")
		}
		if scanner.pos >= len(document) {
			t.Fatalf("the walk consumed the whole document (%d of %d bytes)", scanner.pos, len(document))
		}
		if err := scanner.failure(); err == nil || err.Error() != "collector: cancelled" {
			t.Fatalf("failure = %v, want collector: cancelled", err)
		}
	})
	t.Run("control_positive", func(t *testing.T) {
		// The same value with a live context is walked to its end: the early stop
		// above is caused by the cancellation, not by the document.
		scanner := newRawScanner([]byte(document))
		scanner.ctx = context.Background()
		if !scanner.skipValue(0) {
			t.Fatal("the discarded value was refused with a live context")
		}
		if !scanner.atEnd() {
			t.Fatalf("the walk did not consume the whole document: %d of %d bytes", scanner.pos, len(document))
		}
	})
	t.Run("projection_reports_cancelled_not_malformed", func(t *testing.T) {
		// The closed code of a walk stopped by the run context is cancelled: the
		// same document with a live context is admitted, so the refusal is caused
		// by the cancellation and not by the representation.
		response := `{"discarded":` + document + `,"apiVersion":"v1","kind":"PodList","items":[]}`
		tripwire := newA202TripwireContext(4, context.Canceled)
		if _, err := projectResponse(tripwire, []byte(response), operationSpec{verb: "list", namespace: a202Namespace}, &budgetState{}); err == nil || err.Error() != "collector: cancelled" {
			t.Fatalf("err = %v, want collector: cancelled", err)
		}
		if _, err := projectResponse(context.Background(), []byte(response), operationSpec{verb: "list", namespace: a202Namespace}, &budgetState{}); err != nil {
			t.Fatalf("the same document with a live context was refused: %v", err)
		}
	})
}

// a202TripwireRunClock hands the run-level deadline a tripwire context that
// expires itself on its Nth read: the cancellation is initiated by the walk
// under test (a whitespace tail), never by an event of the response flow.
type a202TripwireRunClock struct {
	base *a202Clock
	trip *a202TripwireContext
}

func newA202TripwireRunClock(t *testing.T, start string, after int, cause error) *a202TripwireRunClock {
	t.Helper()
	return &a202TripwireRunClock{base: newA202Clock(t, start), trip: newA202TripwireContext(after, cause)}
}

func (c *a202TripwireRunClock) Now() clockSample { return c.base.Now() }

func (c *a202TripwireRunClock) Wait(parent context.Context, delay time.Duration) error { return nil }

func (c *a202TripwireRunClock) WithTimeout(parent context.Context, timeout time.Duration) (context.Context, context.CancelFunc) {
	if timeout == acquisitionDeadline {
		return c.trip, func() {}
	}
	return context.WithCancel(parent)
}

// a202ProjectionTokens counts the tokens one document really spends, so a test
// can arm its tripwire with a structural count instead of a magic number.
func a202ProjectionTokens(t *testing.T, document string) int {
	t.Helper()
	probe := newRawScanner([]byte(document))
	if !probe.skipValue(0) || !probe.atEnd() {
		t.Fatalf("the probe could not walk the document")
	}
	return int(probe.tokens)
}

// a202CountingContext counts every read of Err without ever failing, so a test
// can measure how many context reads the whole projection performs.
type a202CountingContext struct {
	checks int
}

func (c *a202CountingContext) Deadline() (time.Time, bool) { return time.Time{}, false }
func (c *a202CountingContext) Done() <-chan struct{}       { return nil }
func (c *a202CountingContext) Err() error                  { c.checks++; return nil }
func (c *a202CountingContext) Value(any) any               { return nil }

// a202ProjectionChecks measures the context reads of one complete projection.
func a202ProjectionChecks(t *testing.T, document string) int {
	t.Helper()
	counting := &a202CountingContext{}
	if _, err := projectResponse(counting, []byte(document), operationSpec{verb: "list", namespace: a202Namespace}, &budgetState{}); err != nil {
		t.Fatalf("the live probe was refused: %v", err)
	}
	return counting.checks
}

// TestA202WhitespaceTailCancellation is the Q01 correction: the whitespace
// traversal consults the run context at every byte and the projection re-checks
// the context after the whole document, trailing whitespace included, was
// consumed, so a long tail never becomes an admitted source after the caller
// gave up.
func TestA202WhitespaceTailCancellation(t *testing.T) {
	t.Run("scanner_tail_stops", func(t *testing.T) {
		// The tripwire flips on the first whitespace byte of the tail: the number
		// itself only spends three token checks.
		document := "123" + strings.Repeat(" ", 4096)
		scanner := newRawScanner([]byte(document))
		scanner.ctx = newA202TripwireContext(4, context.Canceled)
		if !scanner.skipValue(0) {
			t.Fatal("the number was refused with a live context")
		}
		if scanner.atEnd() {
			t.Fatal("the whitespace tail was consumed after the cancellation")
		}
		if !scanner.cancelledHit {
			t.Fatal("the stop was not attributed to the expired context")
		}
		if scanner.pos >= len(document) {
			t.Fatalf("the scanner consumed the whole document (%d of %d bytes)", scanner.pos, len(document))
		}
		if err := scanner.failure(); err == nil || err.Error() != "collector: cancelled" {
			t.Fatalf("failure = %v, want collector: cancelled", err)
		}
	})
	t.Run("control_positive", func(t *testing.T) {
		document := "123" + strings.Repeat(" ", 4096)
		scanner := newRawScanner([]byte(document))
		scanner.ctx = context.Background()
		if !scanner.skipValue(0) {
			t.Fatal("the number was refused with a live context")
		}
		if !scanner.atEnd() {
			t.Fatalf("the walk did not consume the whole document: %d of %d bytes", scanner.pos, len(document))
		}
	})
	t.Run("projection_stops_inside_the_tail", func(t *testing.T) {
		// The tripwire flips a few bytes into the whitespace tail: the projection
		// is refused with the closed code instead of being admitted. The threshold
		// is structural for this document (one context read per token, plus the
		// entry, the item and the pre-tail checks) so the flip is placed inside the
		// tail by construction, and the live count proves the structure holds.
		body := a202Document(a202CompletePod("u1", "n1"))
		document := body + strings.Repeat(" ", 4096)
		threshold := a202ProjectionTokens(t, body) + 4 + 2
		if measured := a202ProjectionChecks(t, body); measured != threshold-2 {
			t.Fatalf("the projection reads the context %d times, want the structural %d", measured, threshold-2)
		}
		tripwire := newA202TripwireContext(threshold, context.Canceled)
		if _, err := projectResponse(tripwire, []byte(document), operationSpec{verb: "list", namespace: a202Namespace}, &budgetState{}); err == nil || err.Error() != "collector: cancelled" {
			t.Fatalf("err = %v, want collector: cancelled", err)
		}
		if _, err := projectResponse(context.Background(), []byte(document), operationSpec{verb: "list", namespace: a202Namespace}, &budgetState{}); err != nil {
			t.Fatalf("the same document with a live context was refused: %v", err)
		}
	})
	t.Run("projection_rechecks_after_the_document", func(t *testing.T) {
		// A document without any tail: the tripwire is armed on the last context
		// read of the whole projection — the closing check that runs after the
		// document was consumed — so only that check can observe the cancellation
		// and the projection never becomes an admitted source. The live count
		// proves the structural formula holds, which is what keeps the flip on the
		// closing check.
		document := a202Document(a202CompletePod("u1", "n1"))
		threshold := a202ProjectionTokens(t, document) + 4
		if measured := a202ProjectionChecks(t, document); measured != threshold {
			t.Fatalf("the projection reads the context %d times, want the structural %d", measured, threshold)
		}
		tripwire := newA202TripwireContext(threshold, context.Canceled)
		if _, err := projectResponse(tripwire, []byte(document), operationSpec{verb: "list", namespace: a202Namespace}, &budgetState{}); err == nil || err.Error() != "collector: cancelled" {
			t.Fatalf("err = %v, want collector: cancelled", err)
		}
		if _, err := projectResponse(context.Background(), []byte(document), operationSpec{verb: "list", namespace: a202Namespace}, &budgetState{}); err != nil {
			t.Fatalf("the same document with a live context was refused: %v", err)
		}
	})
	t.Run("run_admits_no_source", func(t *testing.T) {
		// The same cancellation inside a long whitespace tail, at the run level:
		// the source is never admitted (no capture and no bundle), the attempt is
		// recorded with the closed cause and the body was really consumed.
		document := a202Document(a202CompletePod("u1", "n1")) + strings.Repeat(" ", 512*1024)
		config := a202Config(t)
		clock := newA202TripwireRunClock(t, a202StartMoment, 4096, context.Canceled)
		transport := newA202ScriptedTransport(a202JSONResponse(document))
		result, err := collectWithDependencies(context.Background(), config, transport, clock)
		if len(result.Acquisition.Captures) != 0 || len(result.Bundles) != 0 {
			t.Fatalf("captures = %d, bundles = %d, want none", len(result.Acquisition.Captures), len(result.Bundles))
		}
		if err == nil || err.Error() != "collector: cancelled" {
			t.Fatalf("err = %v, want collector: cancelled", err)
		}
		if result.Acquisition.Termination != contract.TerminationUnknown {
			t.Fatalf("termination = %q, want unknown", result.Acquisition.Termination)
		}
		if transport.callCount() != 1 {
			t.Fatalf("requests = %d, want 1", transport.callCount())
		}
		bodies := transport.recordedBodies()
		if len(bodies) != 1 || bodies[0].pos != len(bodies[0].data) {
			t.Fatal("the response body was not consumed")
		}
		failed := false
		for _, operation := range result.Acquisition.Operations {
			if operation.State == bundle.OperationFailed && operation.Diagnostic == bundle.CodeCancelled {
				failed = true
			}
		}
		if !failed {
			t.Fatalf("the failed attempt was not recorded: %+v", result.Acquisition.Operations)
		}
	})
}

func TestA202RawJSON(t *testing.T) {
	t.Run("single_document", func(t *testing.T) {
		scanner := newRawScanner([]byte(`{"a":1,"b":[true,null,"x"]}`))
		if err := scanner.scanDocument(); err != nil {
			t.Fatalf("a valid document was refused: %v", err)
		}
		if !scanner.atEnd() {
			t.Fatal("the scanner did not consume the document")
		}
	})
	t.Run("trailing_data", func(t *testing.T) {
		// scanDocument refuses concatenated documents as a whole: neither one
		// becomes a source and no fragment survives.
		if err := newRawScanner([]byte(`{"a":1}{"b":2}`)).scanDocument(); err == nil {
			t.Fatal("concatenated documents were admitted")
		}
		if err := newRawScanner([]byte(`{"a":1} `)).scanDocument(); err != nil {
			t.Fatalf("trailing JSON whitespace must be admitted: %v", err)
		}
	})
	t.Run("truncated", func(t *testing.T) {
		for _, document := range []string{`{"a":`, `{"a":1`, `[1,`, `"unterminated`, `tru`} {
			if err := newRawScanner([]byte(document)).scanDocument(); err == nil {
				t.Fatalf("truncated %q was admitted", document)
			}
		}
	})
	t.Run("duplicate_escaped_key", func(t *testing.T) {
		// The two keys decode to the same text: the duplicate is detected after
		// resolving the escape, not by comparing raw bytes.
		if err := newRawScanner([]byte(`{"a":1,"\u0061":2}`)).scanDocument(); err == nil {
			t.Fatal("a duplicate key after escape resolution was admitted")
		}
	})
	t.Run("duplicate_in_discarded_object", func(t *testing.T) {
		// The duplicate lives inside an object this profile discards: it is
		// still ambiguous input, and the discarded object is walked structurally.
		document := `{"apiVersion":"v1","kind":"PodList","items":[],"discarded":{"x":1,"x":2}}`
		if err := newRawScanner([]byte(document)).scanDocument(); err == nil {
			t.Fatal("a duplicate inside a discarded object was admitted")
		}
	})
	t.Run("invalid_utf8", func(t *testing.T) {
		if err := newRawScanner([]byte("{\"a\":\"\xff\xfe\"}")).scanDocument(); err == nil {
			t.Fatal("invalid UTF-8 was admitted")
		}
	})
	t.Run("isolated_surrogate", func(t *testing.T) {
		if err := newRawScanner([]byte(`{"a":"\ud800"}`)).scanDocument(); err == nil {
			t.Fatal("an isolated high surrogate was admitted")
		}
		if err := newRawScanner([]byte(`{"a":"\udc00"}`)).scanDocument(); err == nil {
			t.Fatal("an isolated low surrogate was admitted")
		}
	})
	t.Run("valid_surrogate_pair", func(t *testing.T) {
		if err := newRawScanner([]byte(`{"a":"\ud83d\ude00"}`)).scanDocument(); err != nil {
			t.Fatalf("a valid surrogate pair was refused: %v", err)
		}
	})
	t.Run("legitimate_replacement_character", func(t *testing.T) {
		// U+FFFD is legitimate text and is not mistaken for a decoding failure.
		if err := newRawScanner([]byte("{\"a\":\"\uFFFD\"}")).scanDocument(); err != nil {
			t.Fatalf("a legitimate replacement character was refused: %v", err)
		}
	})
	t.Run("raw_control_character", func(t *testing.T) {
		if err := newRawScanner([]byte("{\"a\":\"x\x01y\"}")).scanDocument(); err == nil {
			t.Fatal("a raw control character was admitted")
		}
	})
	t.Run("empty_and_nested", func(t *testing.T) {
		for _, document := range []string{`{}`, `[]`, `{"a":{}}`, `{"a":[]}`, `{"a":[{}]}`, `null`, `true`, `123`} {
			if err := newRawScanner([]byte(document)).scanDocument(); err != nil {
				t.Fatalf("%q was refused: %v", document, err)
			}
		}
	})
}

func TestA202DiscardedJSONNumbers(t *testing.T) {
	t.Run("negative", func(t *testing.T) {
		if err := newRawScanner([]byte(`{"a":-5}`)).scanDocument(); err != nil {
			t.Fatalf("a negative number was refused: %v", err)
		}
	})
	t.Run("fraction", func(t *testing.T) {
		if err := newRawScanner([]byte(`{"a":1.5}`)).scanDocument(); err != nil {
			t.Fatalf("a fractional number was refused: %v", err)
		}
	})
	t.Run("exponent", func(t *testing.T) {
		if err := newRawScanner([]byte(`{"a":1e10}`)).scanDocument(); err != nil {
			t.Fatalf("an exponent number was refused: %v", err)
		}
		if err := newRawScanner([]byte(`{"a":-1.5E-3}`)).scanDocument(); err != nil {
			t.Fatalf("a signed exponent number was refused: %v", err)
		}
	})
	t.Run("invalid_number", func(t *testing.T) {
		for _, document := range []string{`{"a":01}`, `{"a":1.}`, `{"a":.5}`, `{"a":1e}`, `{"a":-}`, `{"a":1..2}`} {
			if err := newRawScanner([]byte(document)).scanDocument(); err == nil {
				t.Fatalf("invalid number %q was admitted", document)
			}
		}
	})
	t.Run("selected_restart_count_remains_strict", func(t *testing.T) {
		// A number outside the strict semantic grammar of a selected field is
		// refused by the profile, even though the same number passes the general
		// JSON grammar: the strictness belongs to the field, not to the scanner.
		document := `{"apiVersion":"v1","kind":"PodList","items":[` +
			`{"apiVersion":"v1","kind":"Pod","metadata":{"uid":"u1","namespace":"payments","name":"n1"},` +
			`"spec":{"containers":[{"name":"api","image":"registry.example/app:release"}]},` +
			`"status":{"containerStatuses":[{"name":"api","imageID":"sha256:aa","restartCount":-1}]}}]}`
		if _, err := projectResponse(context.Background(), []byte(document), operationSpec{verb: "list", namespace: a202Namespace}, &budgetState{}); err != nil {
			t.Fatalf("the general grammar admits a negative number: %v", err)
		}
		// The selected field accepts the general JSON number at projection; its
		// strictness is applied by the admission stage of A2-01, which is the
		// layer that owns the semantic grammar of the field.
		if err := newRawScanner([]byte(`{"restartCount":-1}`)).scanDocument(); err != nil {
			t.Fatalf("the scanner applied a field grammar: %v", err)
		}
	})
}
