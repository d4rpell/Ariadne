package collector

import (
	"context"
	"time"
)

// Clock seam of the collector (ADR-0026 A.5.5, A.8.2). The real clock derives
// durations from a monotonic reference; the test clock controls civil time,
// monotonic time and cancellations independently. There is no mutable global.

// clockSample is one reading of the clock: the civil instant and the elapsed
// monotonic time since the run started.
type clockSample struct {
	UTC     time.Time
	Elapsed time.Duration
}

// collectionClock is the private seam every wait and deadline goes through.
type collectionClock interface {
	Now() clockSample
	Wait(ctx context.Context, delay time.Duration) error
	WithTimeout(parent context.Context, timeout time.Duration) (context.Context, context.CancelFunc)
}

// realClock reads the system clock and derives elapsed time from a monotonic
// reference taken when the run starts.
type realClock struct {
	start time.Time
}

func newRealClock() *realClock {
	return &realClock{start: time.Now()}
}

func (c *realClock) Now() clockSample {
	now := time.Now()
	return clockSample{UTC: now.UTC(), Elapsed: now.Sub(c.start)}
}

func (c *realClock) Wait(ctx context.Context, delay time.Duration) error {
	if delay <= 0 {
		return ctx.Err()
	}
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

func (c *realClock) WithTimeout(parent context.Context, timeout time.Duration) (context.Context, context.CancelFunc) {
	return context.WithTimeout(parent, timeout)
}

// clockInvalid reports whether a civil reading cannot be used as a timestamp:
// the zero instant and pre-epoch values are refused, and a reading that goes
// backwards relative to the previous one is refused too. No value is clamped.
func clockInvalid(previous, current clockSample) bool {
	if current.UTC.IsZero() || current.UTC.Year() < 1970 {
		return true
	}
	if !previous.UTC.IsZero() && current.UTC.Before(previous.UTC) {
		return true
	}
	return false
}
