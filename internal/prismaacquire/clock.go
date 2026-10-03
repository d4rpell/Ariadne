package prismaacquire

import (
	"context"
	"strconv"
	"time"
)

// Timing helpers of §6.12, §7.11 and §7.12. Durations use the monotonic clock;
// the civil clock is used only for the declared acquired_at of a page.

// canonicalInstant formats t as the F1 canonical UTC instant of ADR-0027 §5:
// YYYY-MM-DDTHH:MM:SS[.fraction]Z with one to nine fraction digits, no trailing
// zero and no fraction when it is zero. A zero time is not representable.
func canonicalInstant(t time.Time) (string, bool) {
	if t.IsZero() {
		return "", false
	}
	u := t.UTC()
	base := u.Format("2006-01-02T15:04:05")
	if ns := u.Nanosecond(); ns != 0 {
		frac := strconv.Itoa(ns)
		for len(frac) < 9 {
			frac = "0" + frac
		}
		for len(frac) > 0 && frac[len(frac)-1] == '0' {
			frac = frac[:len(frac)-1]
		}
		base += "." + frac
	}
	return base + "Z", true
}

// sleepContext is the cancellable inter-request wait of §6.12. It returns the
// context error when the caller cancels; a non-positive duration is immediate.
func sleepContext(ctx context.Context, d time.Duration) error {
	if d <= 0 {
		return nil
	}
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}
