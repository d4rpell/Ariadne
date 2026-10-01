package collector

import (
	"unicode/utf8"
)

// JSON string handling of the raw scanner (ADR-0026 A.6.4, A.8). The scanner
// validates UTF-8, resolves escapes, pairs surrogates and compares decoded
// keys; it never repairs invalid text and never retains a discarded value.
// Surrogate pairing is done with explicit code-point arithmetic: the profile
// allowlist admits no further unicode package.

// scanString consumes one JSON string. When retain is true it returns the
// decoded text, used only to compare keys of the same object; when it is false
// the text is discarded as soon as it is validated.
func (s *rawScanner) scanString(retain bool) (string, bool) {
	if s.pos >= len(s.data) || s.data[s.pos] != '"' {
		return "", false
	}
	if !s.scanToken() { // opening quote
		return "", false
	}
	var out []byte
	if retain {
		out = make([]byte, 0, 16)
	}
	for {
		if s.pos >= len(s.data) {
			return "", false
		}
		current := s.data[s.pos]
		if current == '"' {
			if !s.scanToken() {
				return "", false
			}
			return string(out), true
		}
		if current == '\\' {
			if !s.scanToken() { // backslash
				return "", false
			}
			if s.pos >= len(s.data) {
				return "", false
			}
			escape := s.data[s.pos]
			if !s.scanToken() {
				return "", false
			}
			switch escape {
			case '"', '\\', '/':
				if retain {
					out = append(out, escape)
				}
			case 'b':
				if retain {
					out = append(out, '\b')
				}
			case 'f':
				if retain {
					out = append(out, '\f')
				}
			case 'n':
				if retain {
					out = append(out, '\n')
				}
			case 'r':
				if retain {
					out = append(out, '\r')
				}
			case 't':
				if retain {
					out = append(out, '\t')
				}
			case 'u':
				r, ok := s.scanUnicodeEscape()
				if !ok {
					return "", false
				}
				if retain {
					out = utf8.AppendRune(out, r)
				}
			default:
				return "", false
			}
			continue
		}
		if current < 0x20 {
			// A raw control character is not valid JSON text.
			return "", false
		}
		if current < utf8.RuneSelf {
			if retain {
				out = append(out, current)
			}
			if !s.scanToken() {
				return "", false
			}
			continue
		}
		// Multi-byte UTF-8: the sequence is validated before it is consumed.
		r, size := utf8.DecodeRune(s.data[s.pos:])
		if r == utf8.RuneError && size == 1 {
			return "", false
		}
		if retain {
			out = append(out, s.data[s.pos:s.pos+size]...)
		}
		for index := 0; index < size; index++ {
			if !s.scanToken() {
				return "", false
			}
		}
	}
}

// scanUnicodeEscape resolves one \uXXXX escape, pairing a high surrogate with
// its following low surrogate. An isolated surrogate is invalid input.
func (s *rawScanner) scanUnicodeEscape() (rune, bool) {
	first, ok := s.scanHex4()
	if !ok {
		return 0, false
	}
	if isHighSurrogate(first) {
		if s.pos+1 >= len(s.data) || s.data[s.pos] != '\\' || s.data[s.pos+1] != 'u' {
			return 0, false
		}
		if !s.scanToken() || !s.scanToken() {
			return 0, false
		}
		second, ok := s.scanHex4()
		if !ok {
			return 0, false
		}
		if !isLowSurrogate(second) {
			return 0, false
		}
		return decodeSurrogatePair(first, second), true
	}
	if isLowSurrogate(first) {
		// A low surrogate without its high half is not valid JSON text.
		return 0, false
	}
	if first > utf8.MaxRune {
		return 0, false
	}
	return rune(first), true
}

// isHighSurrogate reports the high half of a UTF-16 surrogate pair.
func isHighSurrogate(value uint32) bool { return value >= 0xD800 && value <= 0xDBFF }

// isLowSurrogate reports the low half of a UTF-16 surrogate pair.
func isLowSurrogate(value uint32) bool { return value >= 0xDC00 && value <= 0xDFFF }

// decodeSurrogatePair combines a validated surrogate pair into its code point.
func decodeSurrogatePair(high, low uint32) rune {
	return rune(0x10000 + (high-0xD800)<<10 + (low - 0xDC00))
}

// scanHex4 consumes exactly four hexadecimal digits.
func (s *rawScanner) scanHex4() (uint32, bool) {
	var value uint32
	for index := 0; index < 4; index++ {
		if s.pos >= len(s.data) {
			return 0, false
		}
		digit := s.data[s.pos]
		switch {
		case digit >= '0' && digit <= '9':
			value = value<<4 | uint32(digit-'0')
		case digit >= 'a' && digit <= 'f':
			value = value<<4 | uint32(digit-'a'+10)
		case digit >= 'A' && digit <= 'F':
			value = value<<4 | uint32(digit-'A'+10)
		default:
			return 0, false
		}
		if !s.scanToken() {
			return 0, false
		}
	}
	return value, true
}
