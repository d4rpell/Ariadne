package ingest

import (
	"unicode"
	"unicode/utf8"
)

// Strict string handling of ADR-0025 A.3.4, A.4 and A.10.3 §5. Every string
// token of the admitted document is decoded here: keys and values share the same
// lexical rules, so a prohibited character is rejected at the same point whether
// the sanitizer wrote it literally or as an escape. Nothing is repaired: no trim,
// no Unicode normalization and no replacement with U+FFFD.

// scanStringToken scans one string token starting at its opening quote and
// returns the decoded content. rawLimit bounds the raw token including both
// quotes and every escape as written; decodedLimit bounds the decoded content
// and is zero when the profile sets no decoded budget for this field. Budgets are
// checked before the bytes they would admit are accumulated, and each lexical
// failure keeps the anchor of A.10.1.
func (s *podListScanner) scanStringToken(offset, rawLimit, decodedLimit uint64, budgetCode PodListDiagnosticCode) (string, *PodListError) {
	s.pos++
	raw := uint64(1)
	decoded := make([]byte, 0, 16)
	for {
		if s.pos >= len(s.data) {
			// A structure or an escape that cannot be completed: the anchor is the
			// total number of bytes received.
			return "", failure(PodListCodeInvalidJSON, uint64(len(s.data)))
		}
		if problem := s.checkPodBudget(uint64(s.pos)); problem != nil {
			// The Pod budget precedes the string budget at the same point of
			// advancement (A.10.3 section 4): the byte that would exceed the Pod
			// interval is never consumed.
			return "", problem
		}
		character := s.data[s.pos]
		if character == '"' {
			if raw+1 > rawLimit {
				return "", failure(budgetCode, offset)
			}
			s.pos++
			return string(decoded), nil
		}
		if character == '\\' {
			escapeOffset := uint64(s.pos)
			text, consumed, problem := s.scanEscape(escapeOffset)
			if consumed > 0 {
				// The inspected range ends at the last raw byte the escape actually read,
				// which is not the cursor when the escape was refused.
				if budgetProblem := s.checkPodBudget(escapeOffset + consumed - 1); budgetProblem != nil {
					return "", budgetProblem
				}
			}
			if raw+consumed > rawLimit {
				return "", failure(budgetCode, offset)
			}
			raw += consumed
			if problem != nil {
				return "", problem
			}
			if decodedLimit > 0 && uint64(len(decoded))+uint64(len(text)) > decodedLimit {
				return "", failure(budgetCode, offset)
			}
			decoded = append(decoded, text...)
			continue
		}
		value, size := utf8.DecodeRune(s.data[s.pos:])
		if size > 1 {
			if problem := s.checkPodBudget(uint64(s.pos + size - 1)); problem != nil {
				return "", problem
			}
		}
		if raw+uint64(size) > rawLimit {
			return "", failure(budgetCode, offset)
		}
		if value == utf8.RuneError && size <= 1 {
			return "", failure(PodListCodeInvalidUTF8, uint64(s.pos))
		}
		if value == 0 {
			return "", failure(PodListCodeNUL, uint64(s.pos))
		}
		if podListForbiddenRune(value) {
			return "", failure(PodListCodeForbiddenText, uint64(s.pos))
		}
		if decodedLimit > 0 && uint64(len(decoded))+uint64(size) > decodedLimit {
			return "", failure(budgetCode, offset)
		}
		raw += uint64(size)
		decoded = append(decoded, s.data[s.pos:s.pos+size]...)
		s.pos += size
	}
}

// scanEscape inspects one escape sequence starting at its backslash and returns
// the decoded UTF-8 bytes, the number of raw bytes it inspected and the first
// lexical failure, if any. The inspected count is reported even when the escape
// is refused, so the raw budget still precedes the lexical check at the same
// point of advancement (A.10.3 section 4). A decoded control character is
// refused exactly like a literal one: the profile admits no control or format
// character inside a string.
func (s *podListScanner) scanEscape(offset uint64) ([]byte, uint64, *PodListError) {
	if s.pos+1 >= len(s.data) {
		return nil, uint64(len(s.data) - s.pos), failure(PodListCodeInvalidJSON, uint64(len(s.data)))
	}
	marker := s.data[s.pos+1]
	switch marker {
	case '"', '\\', '/':
		s.pos += 2
		return []byte{marker}, 2, nil
	case 'b':
		s.pos += 2
		return nil, 2, failure(PodListCodeForbiddenText, offset)
	case 'f', 'n', 'r', 't':
		s.pos += 2
		return nil, 2, failure(PodListCodeForbiddenText, offset)
	case 'u':
		value, problem := s.scanHexQuad(offset)
		if problem != nil {
			if s.pos+6 > len(s.data) {
				return nil, uint64(len(s.data) - s.pos), problem
			}
			return nil, 6, problem
		}
		switch {
		case value >= 0xD800 && value <= 0xDBFF:
			return s.scanSurrogatePair(offset, value)
		case value >= 0xDC00 && value <= 0xDFFF:
			return nil, 6, failure(PodListCodeInvalidSurrogate, offset)
		}
		if problem := podListDecodedProblem(rune(value), offset); problem != nil {
			return nil, 6, problem
		}
		s.pos += 6
		return []byte(string(rune(value))), 6, nil
	default:
		return nil, 2, failure(PodListCodeInvalidJSON, offset)
	}
}

// scanHexQuad reads the four hexadecimal digits of a \u escape. A truncated
// escape is a structural failure anchored at EOF; a malformed one keeps the
// backslash anchor.
func (s *podListScanner) scanHexQuad(offset uint64) (uint32, *PodListError) {
	if s.pos+6 > len(s.data) {
		return 0, failure(PodListCodeInvalidJSON, uint64(len(s.data)))
	}
	var value uint32
	for index := 0; index < 4; index++ {
		digit := s.data[s.pos+2+index]
		if !podListHexDigit(digit) {
			return 0, failure(PodListCodeInvalidJSON, offset)
		}
		value = value<<4 | uint32(podListHexValue(digit))
	}
	return value, nil
}

// scanSurrogatePair inspects the low half of a surrogate pair. A high surrogate
// that is not followed by a valid pair keeps its own backslash anchor, even when
// the absence is discovered at EOF. The composed code point is classified like
// any other decoded character: a pair can still express a format character
// outside the BMP, which this profile refuses.
func (s *podListScanner) scanSurrogatePair(offset uint64, high uint32) ([]byte, uint64, *PodListError) {
	if s.pos+12 > len(s.data) {
		return nil, uint64(len(s.data) - s.pos), failure(PodListCodeInvalidSurrogate, offset)
	}
	if s.data[s.pos+6] != '\\' || s.data[s.pos+7] != 'u' {
		return nil, 6, failure(PodListCodeInvalidSurrogate, offset)
	}
	var low uint32
	for index := 0; index < 4; index++ {
		digit := s.data[s.pos+8+index]
		if !podListHexDigit(digit) {
			// The pair escape is itself malformed: the syntax failure wins over
			// the missing pair.
			return nil, 12, failure(PodListCodeInvalidJSON, uint64(s.pos+6))
		}
		low = low<<4 | uint32(podListHexValue(digit))
	}
	if low < 0xDC00 || low > 0xDFFF {
		return nil, 12, failure(PodListCodeInvalidSurrogate, offset)
	}
	code := 0x10000 + ((high - 0xD800) << 10) + (low - 0xDC00)
	if problem := podListDecodedProblem(rune(code), offset); problem != nil {
		return nil, 12, problem
	}
	s.pos += 12
	return []byte(string(rune(code))), 12, nil
}

// podListDecodedProblem classifies one decoded character of an escape. NUL keeps
// its own code; every other control or format character is forbidden text.
func podListDecodedProblem(value rune, offset uint64) *PodListError {
	if value == 0 {
		return failure(PodListCodeNUL, offset)
	}
	if podListForbiddenRune(value) {
		return failure(PodListCodeForbiddenText, offset)
	}
	return nil
}

// podListForbiddenRune reports the character classes the profile refuses inside
// strings: C0, DEL, C1 (unicode.Cc) and the format characters (unicode.Cf).
func podListForbiddenRune(value rune) bool {
	return unicode.Is(unicode.Cc, value) || unicode.Is(unicode.Cf, value)
}

func podListHexDigit(value byte) bool {
	return (value >= '0' && value <= '9') || (value >= 'a' && value <= 'f') || (value >= 'A' && value <= 'F')
}

func podListHexValue(value byte) byte {
	switch {
	case value >= '0' && value <= '9':
		return value - '0'
	case value >= 'a' && value <= 'f':
		return value - 'a' + 10
	default:
		return value - 'A' + 10
	}
}

// podListTextProblem reports the first lexical problem of one text buffer that
// does not belong to the JSON stream. Its positions are not stream offsets, so
// the caller reports the failure of its own stage at offset zero.
func podListTextProblem(data []byte) *PodListError {
	for position := 0; position < len(data); {
		value, size := utf8.DecodeRune(data[position:])
		if value == utf8.RuneError && size <= 1 {
			return failure(PodListCodeInvalidUTF8, uint64(position))
		}
		if value == 0 {
			return failure(PodListCodeNUL, uint64(position))
		}
		if podListForbiddenRune(value) {
			return failure(PodListCodeForbiddenText, uint64(position))
		}
		position += size
	}
	return nil
}

// podListWhitespaceSurrounded mirrors the identifier rule of the evidence
// contract: a non-empty value never carries surrounding whitespace. It never
// trims, because trimming would merge two distinct identifiers into one.
func podListWhitespaceSurrounded(value string) bool {
	first, _ := utf8.DecodeRuneInString(value)
	last, _ := utf8.DecodeLastRuneInString(value)
	return unicode.IsSpace(first) || unicode.IsSpace(last)
}
