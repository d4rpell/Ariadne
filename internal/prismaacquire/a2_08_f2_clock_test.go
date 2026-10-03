package prismaacquire

import (
	"context"
	"testing"
	"time"
)

// Incrementos 7 y 8 de A2-08-F2: tiempo y reloj civil (ADR-0028 §6.12, §7.11,
// §7.12). Las duraciones usan reloj monotónico; acquired_at es UTC canónico y no
// admite regresión.

func TestA208F2AcquiredAt(t *testing.T) {
	cases := []struct {
		in   time.Time
		want string
		ok   bool
	}{
		{time.Time{}, "", false},
		{time.Date(2026, 10, 3, 12, 0, 0, 0, time.UTC), "2026-10-03T12:00:00Z", true},
		{time.Date(2026, 10, 3, 12, 0, 0, 500_000_000, time.UTC), "2026-10-03T12:00:00.5Z", true},
		{time.Date(2026, 10, 3, 12, 0, 0, 123_400_000, time.UTC), "2026-10-03T12:00:00.1234Z", true},
	}
	for _, tc := range cases {
		got, ok := canonicalInstant(tc.in)
		if ok != tc.ok || got != tc.want {
			t.Fatalf("canonicalInstant(%v) = %q/%v, want %q/%v", tc.in, got, ok, tc.want, tc.ok)
		}
	}
}

func TestA208F2ClockRegression(t *testing.T) {
	base := time.Date(2026, 10, 3, 12, 0, 0, 0, time.UTC)
	sequence := []time.Time{base.Add(time.Minute), base}
	index := 0
	a := &acquirer{now: func() time.Time {
		value := sequence[index]
		if index < len(sequence)-1 {
			index++
		}
		return value
	}}
	if _, err := a.acquiredAt(); err != nil {
		t.Fatalf("first timestamp rejected: %v", err)
	}
	if _, err := a.acquiredAt(); err == nil || err.Code != CodeClockInvalid {
		t.Fatalf("regressive clock: err = %v, want %s", err, CodeClockInvalid)
	}
}

func TestA208F2RequestSpacing(t *testing.T) {
	fixed := time.Date(2026, 10, 3, 12, 0, 0, 0, time.UTC)
	var waited time.Duration
	calls := 0
	a := &acquirer{
		ctx: context.Background(),
		now: func() time.Time { return fixed },
		sleep: func(context.Context, time.Duration) error {
			calls++
			return nil
		},
	}
	if err := a.waitSpacing(); err != nil {
		t.Fatalf("first spacing: %v", err)
	}
	if calls != 0 {
		t.Fatal("the first request waited")
	}
	if err := a.waitSpacing(); err != nil {
		t.Fatalf("second spacing: %v", err)
	}
	if calls != 1 {
		t.Fatalf("sleep calls = %d, want 1", calls)
	}
	waited = minRequestSpacing
	if waited != 1250*time.Millisecond {
		t.Fatalf("minimum interval = %v, want 1.25s", waited)
	}
}
