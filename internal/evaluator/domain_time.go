package evaluator

import (
	contract "github.com/d4rpell/Ariadne/pkg/evidence"
)

// evidenceCurrent applies the age policy of ADR-0015 §7.2 with exact arithmetic:
// the observation must not be in the future and its age must be strictly below
// the limit, fractions of a second included. The subtraction is done in seconds
// and nanoseconds instead of time.Duration arithmetic, because the limit can
// reach 2^53-1 and a nanosecond conversion would overflow.
func evidenceCurrent(observedAt, evaluatedAt contract.Timestamp, maximumAgeSeconds int64) (bool, CheckReason) {
	if observedAt.Time.After(evaluatedAt.Time) {
		return false, ReasonFutureObservation
	}
	if maximumAgeSeconds < 1 {
		return false, ReasonExpired
	}
	// The comparison is exact, with fractions of a second included, and it never
	// multiplies the limit by 1e9: time.Duration would overflow at the 2^53-1
	// ceiling. Unix() truncates both instants towards the past, so the whole-second
	// difference can overstate the true age by almost one second; the nanosecond
	// remainder corrects that, borrowing one second when it is negative. Equality
	// with the limit expires.
	seconds := evaluatedAt.Unix() - observedAt.Unix()
	nanoseconds := int64(evaluatedAt.Nanosecond()) - int64(observedAt.Nanosecond())
	if nanoseconds < 0 {
		seconds--
		nanoseconds += 1_000_000_000
	}
	if seconds >= maximumAgeSeconds {
		return false, ReasonExpired
	}
	return true, ReasonVerified
}
