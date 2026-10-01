package collector

import (
	"context"
	"errors"
	"math"
	"time"

	"github.com/d4rpell/Ariadne/internal/bundle"
)

// Budget accounting (ADR-0026 A.5.1, A.5.2). Every counter is checked before
// the growth, send or incorporation that would exceed a limit; an abort never
// returns budget and never hides its cause behind a later cancellation.

// budgetState is the mutable accounting of one run. It is not shared between
// runs and is never exposed: the publishable numbers live in the result.
type budgetState struct {
	requests          uint64
	podOccurrences    uint64
	initialUIDs       uint64
	totalBodyBytes    uint64
	retainedSource    uint64
	responsesFinished uint64
	responsesFailed   uint64
	lastStart         time.Duration
	started           bool
	abortCode         bundle.CollectionCode
}

// checkedAdd adds increment to current, refusing overflow past limit. It
// reports the new value and whether the addition is admissible.
func checkedAdd(current, increment, limit uint64) (uint64, bool) {
	if current > limit {
		return current, false
	}
	if increment > limit-current {
		return current, false
	}
	return current + increment, true
}

// abort records the first cause of the run. A cause already recorded is never
// replaced: the guard that fired owns the diagnosis.
func (b *budgetState) abort(code bundle.CollectionCode) error {
	if b.abortCode == "" {
		b.abortCode = code
	}
	return errors.New(bundle.CollectionMessage(b.abortCode))
}

// beforeRequest applies the run deadline, the request budget and the minimum
// spacing between request starts. It consumes one request attempt and the
// spacing wait, in that order.
func (b *budgetState) beforeRequest(ctx context.Context, clock collectionClock) error {
	if b.abortCode != "" {
		return errors.New(bundle.CollectionMessage(b.abortCode))
	}
	if ctx.Err() != nil {
		// A deadline that the run set for itself is time_limit; a cancellation
		// that came from the caller is cancelled. The closed code is chosen by
		// the condition, never by the text of the error.
		b.abortCode = bundle.CodeCancelled
		if errors.Is(ctx.Err(), context.DeadlineExceeded) {
			b.abortCode = bundle.CodeTimeLimit
		}
		return errors.New(bundle.CollectionMessage(b.abortCode))
	}
	next, ok := checkedAdd(b.requests, 1, maxRequests)
	if !ok {
		return b.abort(bundle.CodeRequestLimit)
	}
	sample := clock.Now()
	if b.started {
		elapsed := sample.Elapsed - b.lastStart
		if elapsed < requestSpacing {
			if err := clock.Wait(ctx, requestSpacing-elapsed); err != nil {
				// The cause of the guard that fired is never replaced by the
				// cancellation it triggered.
				if b.abortCode == "" {
					b.abortCode = bundle.CodeCancelled
					if errors.Is(err, context.DeadlineExceeded) {
						b.abortCode = bundle.CodeTimeLimit
					}
				}
				return errors.New(bundle.CollectionMessage(b.abortCode))
			}
			sample = clock.Now()
		}
	}
	b.requests = next
	b.lastStart = sample.Elapsed
	b.started = true
	return nil
}

// addBodyBytes counts really read body bytes, including rejected responses and
// the authorized probe byte. It reports whether the addition exceeded the global
// budget; the caller decides the diagnosis, because a per-response overflow of
// the same byte takes precedence over the global one.
//
// The counter is exact: the bytes were read from the wire, so they are recorded
// even when they pass the limit. Saturating instead would under-report what the
// run really consumed and hide the probe from the accounting.
func (b *budgetState) addBodyBytes(n uint64) bool {
	next, ok := checkedAdd(b.totalBodyBytes, n, maxTotalBodyBytes)
	if !ok {
		b.totalBodyBytes += n
		return true
	}
	b.totalBodyBytes = next
	return false
}

// addPodOccurrence counts one examined Pod occurrence, re-reads included.
func (b *budgetState) addPodOccurrence() error {
	next, ok := checkedAdd(b.podOccurrences, 1, maxPodOccurrences)
	if !ok {
		return b.abort(bundle.CodeObjectLimit)
	}
	b.podOccurrences = next
	return nil
}

// addInitialUID counts one UID of the initial inventory.
func (b *budgetState) addInitialUID() error {
	next, ok := checkedAdd(b.initialUIDs, 1, maxInitialUIDs)
	if !ok {
		return b.abort(bundle.CodeObjectLimit)
	}
	b.initialUIDs = next
	return nil
}

// retainSource counts one sanitized source retained for the result.
func (b *budgetState) retainSource(n uint64) error {
	next, ok := checkedAdd(b.retainedSource, n, maxRetainedSourceBytes)
	if !ok {
		return b.abort(bundle.CodeOutputLimit)
	}
	b.retainedSource = next
	return nil
}

// noteResponse records the completion of one admitted or rejected response.
func (b *budgetState) noteResponse(finished bool) {
	if finished {
		b.responsesFinished++
	} else {
		b.responsesFailed++
	}
}

// exhausted reports whether a guard already fired.
func (b *budgetState) exhausted() bool { return b.abortCode != "" }

// abortDiagnostic returns the recorded cause as a publishable diagnostic.
func (b *budgetState) abortDiagnostic() *bundle.CollectionDiagnostic {
	if b.abortCode == "" {
		return nil
	}
	return &bundle.CollectionDiagnostic{Code: b.abortCode}
}

// maxUint64 is a helper for overflow tests of this package.
const maxUint64 = uint64(math.MaxUint64)
