package collector

import (
	"context"

	"github.com/d4rpell/Ariadne/internal/bundle"
)

// Raw JSON traversal of one response (ADR-0026 A.6.4, A.8). The collector does
// not decode the response into a generic tree: discarded values keep no
// representation beyond their structural walk, duplicate keys are detected
// after escape resolution, and the limits are applied before growth.

// rawScanner walks one complete JSON document with explicit budgets.
type rawScanner struct {
	data   []byte
	pos    int
	tokens uint64
	limit  uint64
	// limitHit records that a raw budget refused the document. The failure is
	// then a limit of the raw structure (A.10.2 response_limit), never a
	// malformed representation (response_invalid).
	limitHit bool
	// ctx is the run context, consulted at every consumed token so a large
	// discarded value (a deep object, a long array, a long string or a long
	// number) stops on the first token after the caller gave up. A nil context
	// disables the cooperative check.
	ctx context.Context
	// cancelledHit records that the walk stopped because that context expired:
	// the failure is then the closed code cancelled, never a malformed input.
	cancelledHit bool
}

// newRawScanner prepares a scanner over one admitted-size document.
func newRawScanner(data []byte) *rawScanner {
	return &rawScanner{data: data, limit: maxRawTokens}
}

// skipWhitespace advances over JSON whitespace. It consults the optional run
// context at every byte, so a long whitespace tail cannot be walked after the
// caller gave up: the scan stops where it is, the stop is remembered and the
// caller refuses the document instead of admitting it.
func (s *rawScanner) skipWhitespace() {
	for s.pos < len(s.data) {
		switch s.data[s.pos] {
		case ' ', '\t', '\n', '\r':
			if s.ctx != nil && s.ctx.Err() != nil {
				s.cancelledHit = true
				return
			}
			s.pos++
		default:
			return
		}
	}
}

// atEnd reports whether the scanner consumed the whole document.
func (s *rawScanner) atEnd() bool {
	s.skipWhitespace()
	return s.pos >= len(s.data)
}

// scanDocument walks exactly one complete JSON document. Trailing data, a
// truncated value or an ambiguous member is refused: a response never becomes
// a source from a prefix or from concatenated documents.
func (s *rawScanner) scanDocument() error {
	if !s.skipValue(0) {
		return s.failure()
	}
	if !s.atEnd() {
		return staticError(bundle.CodeResponseInvalid)
	}
	return nil
}

// scanToken consumes one structural token, enforcing the token budget and the
// cooperative cancellation of the run. The check runs at every token, so a
// discarded value stops on the first token consumed after the caller gave up
// and is never walked to its end.
func (s *rawScanner) scanToken() bool {
	if s.ctx != nil && s.ctx.Err() != nil {
		s.cancelledHit = true
		return false
	}
	if s.tokens >= s.limit {
		s.limitHit = true
		return false
	}
	if s.pos >= len(s.data) {
		return false
	}
	s.tokens++
	s.pos++
	return true
}

// failure classifies a failed structural walk of one raw response: an expired
// run context is the closed code cancelled, a budget of the raw structure
// (depth, tokens or members) is a limit (A.10.2 response_limit), and every
// other refusal is a malformed representation (response_invalid).
func (s *rawScanner) failure() error {
	if s.cancelledHit {
		return staticError(bundle.CodeCancelled)
	}
	if s.limitHit {
		return staticError(bundle.CodeResponseLimit)
	}
	return staticError(bundle.CodeResponseInvalid)
}

// skipValue walks one JSON value without retaining it. It enforces depth and
// token budgets and refuses malformed structure.
func (s *rawScanner) skipValue(depth int) bool {
	if depth > maxRawDepth {
		s.limitHit = true
		return false
	}
	s.skipWhitespace()
	if s.pos >= len(s.data) {
		return false
	}
	switch s.data[s.pos] {
	case '{':
		return s.skipObject(depth)
	case '[':
		return s.skipArray(depth)
	case '"':
		_, ok := s.scanString(false)
		return ok
	case 't':
		return s.skipLiteral("true")
	case 'f':
		return s.skipLiteral("false")
	case 'n':
		return s.skipLiteral("null")
	default:
		return s.skipNumber()
	}
}

// skipLiteral consumes one of the fixed literals.
func (s *rawScanner) skipLiteral(literal string) bool {
	if len(s.data)-s.pos < len(literal) {
		return false
	}
	if string(s.data[s.pos:s.pos+len(literal)]) != literal {
		return false
	}
	for index := 0; index < len(literal); index++ {
		if !s.scanToken() {
			return false
		}
	}
	return true
}

// skipNumber consumes one JSON number with the general grammar: discarded
// numbers are never judged with the semantic rules of a selected field, but the
// general grammar still applies (no leading zero, no empty fraction and no
// empty exponent).
func (s *rawScanner) skipNumber() bool {
	start := s.pos
	if s.pos < len(s.data) && s.data[s.pos] == '-' {
		if !s.scanToken() {
			return false
		}
	}
	if s.pos >= len(s.data) {
		return false
	}
	if s.data[s.pos] == '0' {
		// A leading zero is a single digit: "01" is not a JSON number.
		if !s.scanToken() {
			return false
		}
		if s.pos < len(s.data) && s.data[s.pos] >= '0' && s.data[s.pos] <= '9' {
			return false
		}
	} else if s.data[s.pos] >= '1' && s.data[s.pos] <= '9' {
		for s.pos < len(s.data) && s.data[s.pos] >= '0' && s.data[s.pos] <= '9' {
			if !s.scanToken() {
				return false
			}
		}
	} else {
		return false
	}
	if s.pos < len(s.data) && s.data[s.pos] == '.' {
		if !s.scanToken() {
			return false
		}
		fraction := 0
		for s.pos < len(s.data) && s.data[s.pos] >= '0' && s.data[s.pos] <= '9' {
			fraction++
			if !s.scanToken() {
				return false
			}
		}
		if fraction == 0 {
			return false
		}
	}
	if s.pos < len(s.data) && (s.data[s.pos] == 'e' || s.data[s.pos] == 'E') {
		if !s.scanToken() {
			return false
		}
		if s.pos < len(s.data) && (s.data[s.pos] == '+' || s.data[s.pos] == '-') {
			if !s.scanToken() {
				return false
			}
		}
		exponent := 0
		for s.pos < len(s.data) && s.data[s.pos] >= '0' && s.data[s.pos] <= '9' {
			exponent++
			if !s.scanToken() {
				return false
			}
		}
		if exponent == 0 {
			return false
		}
	}
	return s.pos > start
}

// skipObject walks one object, detecting duplicate keys after escape
// resolution and enforcing the member budget. A key is consumed with its
// decoded form only to compare it with the keys already seen of this object;
// the decoded text of a discarded member is never retained.
func (s *rawScanner) skipObject(depth int) bool {
	if depth > maxRawDepth {
		s.limitHit = true
		return false
	}
	if !s.scanToken() { // '{'
		return false
	}
	seen := map[string]bool{}
	s.skipWhitespace()
	if s.pos < len(s.data) && s.data[s.pos] == '}' {
		return s.scanToken()
	}
	for {
		s.skipWhitespace()
		if s.pos >= len(s.data) || s.data[s.pos] != '"' {
			return false
		}
		key, ok := s.scanString(true)
		if !ok {
			return false
		}
		if seen[key] {
			// A duplicate key after escape resolution is ambiguous input: it is
			// refused even inside an object this profile discards.
			return false
		}
		if len(seen) >= maxRawObjectMembers {
			s.limitHit = true
			return false
		}
		seen[key] = true
		s.skipWhitespace()
		if s.pos >= len(s.data) || s.data[s.pos] != ':' {
			return false
		}
		if !s.scanToken() {
			return false
		}
		if !s.skipValue(depth + 1) {
			return false
		}
		s.skipWhitespace()
		if s.pos >= len(s.data) {
			return false
		}
		switch s.data[s.pos] {
		case ',':
			if !s.scanToken() {
				return false
			}
			continue
		case '}':
			return s.scanToken()
		default:
			return false
		}
	}
}

// skipArray walks one array with the token and depth budgets.
func (s *rawScanner) skipArray(depth int) bool {
	if depth > maxRawDepth {
		s.limitHit = true
		return false
	}
	if !s.scanToken() { // '['
		return false
	}
	s.skipWhitespace()
	if s.pos < len(s.data) && s.data[s.pos] == ']' {
		return s.scanToken()
	}
	for {
		if !s.skipValue(depth + 1) {
			return false
		}
		s.skipWhitespace()
		if s.pos >= len(s.data) {
			return false
		}
		switch s.data[s.pos] {
		case ',':
			if !s.scanToken() {
				return false
			}
		case ']':
			return s.scanToken()
		default:
			return false
		}
	}
}
