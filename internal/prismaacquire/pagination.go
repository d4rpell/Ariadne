package prismaacquire

// Pagination rules of §8.2–§8.9. The offset advances by the exact number of
// admitted records, never by the requested page size, and only an admitted empty
// page closes the sequence. Short pages and exactly-reached budgets are not
// terminal conditions.

// nextOffset returns current+n and reports whether the advance is safe. The
// offset is a bounded integer; a wraparound or a non-positive advance is an
// internal invariant failure, never a silent continuation.
func nextOffset(current, admitted int) (int, bool) {
	if admitted <= 0 {
		return 0, false
	}
	next := current + admitted
	if next <= current {
		return 0, false
	}
	return next, true
}

// isTerminalPage reports whether an admitted page closes the sequence: only an
// admitted empty array does (§8.5). A short page and an exactly-reached budget
// are explicitly not terminal.
func isTerminalPage(records int) bool { return records == 0 }
