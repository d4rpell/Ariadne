package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"unicode/utf8"
)

// Strict decoding of the two caller-supplied documents of ADR-0023 §4.2. The
// standard decoder is not the admission: it repairs what this contract rejects
// (duplicate members, unknown members, invalid UTF-8 turned into U+FFFD and
// unpaired surrogates turned into U+FFFD), so every document goes through the
// checks below before a typed decode reads it.

var (
	errStrictBOM          = errors.New("strict: byte-order mark")
	errStrictUTF8         = errors.New("strict: invalid UTF-8")
	errStrictTrailing     = errors.New("strict: trailing content")
	errStrictDuplicate    = errors.New("strict: duplicate member")
	errStrictUnknown      = errors.New("strict: unknown member")
	errStrictMissing      = errors.New("strict: missing member")
	errStrictSurrogate    = errors.New("strict: unpaired surrogate")
	errStrictType         = errors.New("strict: wrong member type")
	errStrictNull         = errors.New("strict: unexpected null")
	errStrictInteger      = errors.New("strict: not a positive decimal integer")
	errStrictTimestamp    = errors.New("strict: not a canonical UTC timestamp")
	errStrictHash         = errors.New("strict: not a sha256 digest")
	errStrictEnum         = errors.New("strict: value outside the closed vocabulary")
	errStrictString       = errors.New("strict: not a string")
	errStrictObject       = errors.New("strict: not an object")
	errStrictArray        = errors.New("strict: not an array")
	errStrictEmpty        = errors.New("strict: empty document")
	errStrictIntegerRange = errors.New("strict: integer above the supported ceiling")
)

// strictFloor rejects the two encodings JSON admits and this contract does not:
// a byte-order mark and invalid UTF-8. Both are checked on the raw bytes, before
// any decoder can substitute a replacement character for them.
func strictFloor(data []byte) error {
	if len(data) == 0 {
		return errStrictEmpty
	}
	if bytes.HasPrefix(data, []byte{0xEF, 0xBB, 0xBF}) {
		return errStrictBOM
	}
	if !utf8.Valid(data) {
		return errStrictUTF8
	}
	return nil
}

// strictSurrogates rejects a string escape that names a surrogate without its
// pair. encoding/json silently replaces it with U+FFFD, and a document whose
// bytes say one thing while its value says another must not be admitted.
func strictSurrogates(data []byte) error {
	inString := false
	for index := 0; index < len(data); index++ {
		character := data[index]
		if !inString {
			if character == '"' {
				inString = true
			}
			continue
		}
		switch character {
		case '\\':
			if index+1 >= len(data) {
				return errStrictSurrogate
			}
			escape := data[index+1]
			if escape != 'u' {
				index++
				continue
			}
			if index+5 >= len(data) {
				return errStrictSurrogate
			}
			value, ok := hexQuad(data[index+2 : index+6])
			if !ok {
				return errStrictSurrogate
			}
			index += 5
			if value >= 0xDC00 && value <= 0xDFFF {
				// A low surrogate must be preceded by its high pair, which the
				// loop already consumed and validated.
				return errStrictSurrogate
			}
			if value >= 0xD800 && value <= 0xDBFF {
				// The low half needs six more bytes: backslash, u and four hex
				// digits. The bound is the last byte actually read, not a margin
				// beyond it: a complete pair at the end of the document must be
				// admitted whatever the surrounding keys are.
				if index+7 > len(data) || data[index+1] != '\\' || data[index+2] != 'u' {
					return errStrictSurrogate
				}
				low, ok := hexQuad(data[index+3 : index+7])
				if !ok || low < 0xDC00 || low > 0xDFFF {
					return errStrictSurrogate
				}
				index += 6
			}
		case '"':
			inString = false
		}
	}
	return nil
}

func hexQuad(text []byte) (int, bool) {
	value := 0
	for _, character := range text {
		digit := 0
		switch {
		case character >= '0' && character <= '9':
			digit = int(character - '0')
		case character >= 'a' && character <= 'f':
			digit = int(character-'a') + 10
		case character >= 'A' && character <= 'F':
			digit = int(character-'A') + 10
		default:
			return 0, false
		}
		value = value*16 + digit
	}
	return value, true
}

// strictShape walks the document with its own scanner to reject duplicate
// members, unpaired members and trailing content. It decides structure only: the
// typed read happens afterwards, member by member, where every member knows its
// own rule. Duplicate detection is anchored to real key positions, so a value
// string with the same text as a key is not mistaken for a repetition.
func strictShape(data []byte) error {
	scanner := &shapeScanner{data: data}
	scanner.skipSpace()
	if scanner.at >= len(scanner.data) {
		return errStrictEmpty
	}
	if err := scanner.value(); err != nil {
		return err
	}
	scanner.skipSpace()
	if scanner.at != len(scanner.data) {
		return errStrictTrailing
	}
	return nil
}

type shapeScanner struct {
	data []byte
	at   int
}

func (scanner *shapeScanner) skipSpace() {
	for scanner.at < len(scanner.data) {
		switch scanner.data[scanner.at] {
		case ' ', '\t', '\n', '\r':
			scanner.at++
		default:
			return
		}
	}
}

func (scanner *shapeScanner) value() error {
	scanner.skipSpace()
	if scanner.at >= len(scanner.data) {
		return errStrictTrailing
	}
	switch character := scanner.data[scanner.at]; {
	case character == '{':
		return scanner.object()
	case character == '[':
		return scanner.array()
	case character == '"':
		return scanner.string()
	default:
		return scanner.literal()
	}
}

func (scanner *shapeScanner) object() error {
	scanner.at++ // '{'
	seen := map[string]bool{}
	scanner.skipSpace()
	if scanner.at < len(scanner.data) && scanner.data[scanner.at] == '}' {
		scanner.at++
		return nil
	}
	for {
		scanner.skipSpace()
		if scanner.at >= len(scanner.data) || scanner.data[scanner.at] != '"' {
			return errStrictObject
		}
		key, err := scanner.stringText()
		if err != nil {
			return err
		}
		if seen[key] {
			return fmt.Errorf("%w: %s", errStrictDuplicate, key)
		}
		seen[key] = true
		scanner.skipSpace()
		if scanner.at >= len(scanner.data) || scanner.data[scanner.at] != ':' {
			return errStrictObject
		}
		scanner.at++
		if err := scanner.value(); err != nil {
			return err
		}
		scanner.skipSpace()
		if scanner.at >= len(scanner.data) {
			return errStrictObject
		}
		switch scanner.data[scanner.at] {
		case ',':
			scanner.at++
		case '}':
			scanner.at++
			return nil
		default:
			return errStrictObject
		}
	}
}

func (scanner *shapeScanner) array() error {
	scanner.at++ // '['
	scanner.skipSpace()
	if scanner.at < len(scanner.data) && scanner.data[scanner.at] == ']' {
		scanner.at++
		return nil
	}
	for {
		if err := scanner.value(); err != nil {
			return err
		}
		scanner.skipSpace()
		if scanner.at >= len(scanner.data) {
			return errStrictArray
		}
		switch scanner.data[scanner.at] {
		case ',':
			scanner.at++
		case ']':
			scanner.at++
			return nil
		default:
			return errStrictArray
		}
	}
}

func (scanner *shapeScanner) string() error {
	_, err := scanner.stringText()
	return err
}

// stringText consumes one string token and returns its decoded text. The raw
// bytes already passed the UTF-8 and surrogate checks, so the standard unquoter
// cannot repair anything here.
func (scanner *shapeScanner) stringText() (string, error) {
	if scanner.at >= len(scanner.data) || scanner.data[scanner.at] != '"' {
		return "", errStrictString
	}
	start := scanner.at
	scanner.at++
	for scanner.at < len(scanner.data) {
		switch scanner.data[scanner.at] {
		case '\\':
			scanner.at += 2
			continue
		case '"':
			scanner.at++
			var text string
			if err := json.Unmarshal(scanner.data[start:scanner.at], &text); err != nil {
				return "", errStrictString
			}
			return text, nil
		}
		scanner.at++
	}
	return "", errStrictString
}

// literal consumes a number, true, false or null. Number grammar is checked
// where the member is read: here only the token boundary matters.
func (scanner *shapeScanner) literal() error {
	start := scanner.at
	for scanner.at < len(scanner.data) {
		switch scanner.data[scanner.at] {
		case ',', '}', ']', ' ', '\t', '\n', '\r':
			goto done
		default:
			scanner.at++
		}
	}
done:
	if scanner.at == start {
		return errStrictTrailing
	}
	return nil
}

// member is one raw member of a decoded object. Presence and null are different
// facts for this contract: a nullable member must be present, and an absent one
// is never repaired into null.
type member struct {
	raw     json.RawMessage
	present bool
}

type object map[string]member

func decodeObject(data []byte) (object, error) {
	if err := strictFloor(data); err != nil {
		return nil, err
	}
	if err := strictSurrogates(data); err != nil {
		return nil, err
	}
	if err := strictShape(data); err != nil {
		return nil, err
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(data, &fields); err != nil {
		return nil, errStrictObject
	}
	if fields == nil {
		return nil, errStrictObject
	}
	object := make(object, len(fields))
	for name, raw := range fields {
		object[name] = member{raw: raw, present: true}
	}
	return object, nil
}

// expectExact enforces the closed key set of one object: every declared member
// present, no other member admitted.
func (fields object) expectExact(declared ...string) error {
	for _, name := range declared {
		if _, ok := fields[name]; !ok {
			return fmt.Errorf("%w: %s", errStrictMissing, name)
		}
	}
	for name := range fields {
		known := false
		for _, declaredName := range declared {
			if name == declaredName {
				known = true
				break
			}
		}
		if !known {
			return fmt.Errorf("%w: %s", errStrictUnknown, name)
		}
	}
	return nil
}

func (fields object) isNull(name string) bool {
	raw := bytes.TrimSpace(fields[name].raw)
	return bytes.Equal(raw, []byte("null"))
}

func (fields object) object(name string) (object, error) {
	if fields.isNull(name) {
		return nil, fmt.Errorf("%w: %s", errStrictNull, name)
	}
	return decodeObject(fields[name].raw)
}

func (fields object) stringValue(name string, nullable bool) (*string, error) {
	if fields.isNull(name) {
		if !nullable {
			return nil, fmt.Errorf("%w: %s", errStrictNull, name)
		}
		return nil, nil
	}
	var value string
	if err := json.Unmarshal(fields[name].raw, &value); err != nil {
		return nil, fmt.Errorf("%w: %s", errStrictString, name)
	}
	return &value, nil
}

// requiredString reads one member that must be present and must be a string.
// Emptiness is not decided here: it is a semantic restriction of the Request
// (identifier, class, reference), so the value travels untouched and the kernel
// reports it with its own precedence. The decoder only enforces the
// representational rules that are its own: H, T and N.
func (fields object) requiredString(name string) (string, error) {
	value, err := fields.stringValue(name, false)
	if err != nil {
		return "", err
	}
	return *value, nil
}

func (fields object) array(name string) ([]json.RawMessage, error) {
	if fields.isNull(name) {
		return nil, fmt.Errorf("%w: %s", errStrictNull, name)
	}
	var items []json.RawMessage
	if err := json.Unmarshal(fields[name].raw, &items); err != nil {
		return nil, fmt.Errorf("%w: %s", errStrictArray, name)
	}
	if items == nil {
		return nil, fmt.Errorf("%w: %s", errStrictArray, name)
	}
	return items, nil
}

// integer reads one positive decimal integer. Fraction, exponent, a quoted
// number, a sign, a leading zero and the 2^53 ceiling are all outside the
// ratified representation.
func (fields object) integer(name string) (int64, error) {
	raw := bytes.TrimSpace(fields[name].raw)
	if bytes.Equal(raw, []byte("null")) {
		return 0, fmt.Errorf("%w: %s", errStrictNull, name)
	}
	text := string(raw)
	if text == "" || strings.ContainsAny(text, ".eE+-\"") {
		return 0, fmt.Errorf("%w: %s", errStrictInteger, name)
	}
	if len(text) > 1 && text[0] == '0' {
		return 0, fmt.Errorf("%w: %s", errStrictInteger, name)
	}
	for _, character := range text {
		if character < '0' || character > '9' {
			return 0, fmt.Errorf("%w: %s", errStrictInteger, name)
		}
	}
	value, err := strconv.ParseInt(text, 10, 64)
	if err != nil || value <= 0 {
		return 0, fmt.Errorf("%w: %s", errStrictInteger, name)
	}
	if value > maxSafeInteger {
		return 0, fmt.Errorf("%w: %s", errStrictIntegerRange, name)
	}
	return value, nil
}

// strictDepth counts the nesting of the raw document without a decoder, so an
// observed excess of the ratified depth is an input_limit of the read stage
// rather than a decode failure. Delimiters inside strings do not count; a
// malformed document is not diagnosed here — the decoder reports it — unless the
// excess was already observed, which the caller checks first.
func strictDepth(data []byte, limit int) error {
	depth := 0
	inString := false
	for index := 0; index < len(data); index++ {
		character := data[index]
		if inString {
			if character == '\\' {
				index++
				continue
			}
			if character == '"' {
				inString = false
			}
			continue
		}
		switch character {
		case '"':
			inString = true
		case '{', '[':
			depth++
			if depth > limit {
				return errStrictDepth
			}
		case '}', ']':
			depth--
		}
	}
	return nil
}

var errStrictDepth = errors.New("strict: nesting above the ratified depth")

// maxSafeInteger is the 2^53-1 ceiling shared by pack versions and the domain
// age policy.
const maxSafeInteger = int64(1<<53 - 1)

func digestOf(fields object, name string) (string, error) {
	value, err := fields.requiredString(name)
	if err != nil {
		return "", err
	}
	if !isSha256Text(value) {
		return "", fmt.Errorf("%w: %s", errStrictHash, name)
	}
	return value, nil
}

// isSha256Text is the exact digest grammar the whole project uses: the prefix
// and exactly 64 lowercase hexadecimal digits.
func isSha256Text(value string) bool {
	const prefix = "sha256:"
	if len(value) != len(prefix)+64 || !strings.HasPrefix(value, prefix) {
		return false
	}
	for _, character := range value[len(prefix):] {
		switch {
		case character >= '0' && character <= '9':
		case character >= 'a' && character <= 'f':
		default:
			return false
		}
	}
	return true
}
