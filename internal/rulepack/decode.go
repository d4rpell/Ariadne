package rulepack

import (
	"bytes"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	contract "github.com/d4rpell/Ariadne/pkg/evidence"
)

// Decode reads one pack document: strict JSON, closed schema, closed vocabulary.
// It proves shape and domain, never identity: hash, pin, version policy and
// validity belong to Admit. Empty bytes are not a decode question; Admit turns
// them into missing_pack.
func Decode(data []byte) (Pack, error) {
	if len(data) > MaxPackBytes {
		return Pack{}, limitProblem()
	}
	root, err := scanDocument(data)
	if err != nil {
		return Pack{}, err
	}
	pack, err := decodePack(root)
	if err != nil {
		return Pack{}, err
	}
	if err := pack.validate(); err != nil {
		return Pack{}, err
	}
	return pack, nil
}

// --- strict JSON scanner ---

type jsonKind int

const (
	jsonObject jsonKind = iota
	jsonArray
	jsonString
	jsonNumber
	jsonBool
	jsonNull
)

type jsonMember struct {
	key   string
	value jsonValue
}

// jsonValue is the scanned document. The scanner is purpose-built: it counts
// tokens, bounds depth, rejects duplicate keys after decoding them, rejects
// unpaired surrogates and never coerces a value into another type.
type jsonValue struct {
	kind     jsonKind
	text     string
	number   string
	boolean  bool
	members  []jsonMember
	elements []jsonValue
}

type scanner struct {
	data   []byte
	pos    int
	tokens int
}

// scanDocument accepts exactly one JSON value with optional surrounding
// whitespace: no BOM, no trailing content, no comments, valid UTF-8 throughout.
func scanDocument(data []byte) (jsonValue, error) {
	if len(data) == 0 {
		return jsonValue{}, syntaxProblem()
	}
	if bytes.HasPrefix(data, []byte{0xEF, 0xBB, 0xBF}) {
		return jsonValue{}, syntaxProblem()
	}
	if !utf8.Valid(data) {
		return jsonValue{}, syntaxProblem()
	}
	reader := &scanner{data: data}
	reader.skipSpace()
	root, err := reader.scanValue(1)
	if err != nil {
		return jsonValue{}, err
	}
	reader.skipSpace()
	if reader.pos != len(reader.data) {
		return jsonValue{}, syntaxProblem()
	}
	return root, nil
}

// token counts one JSON token: every structural delimiter, every string (key or
// value) and every scalar. The counting rule is part of the admitted limit.
func (reader *scanner) token() error {
	reader.tokens++
	if reader.tokens > MaxJSONTokens {
		return limitProblem()
	}
	return nil
}

func (reader *scanner) skipSpace() {
	for reader.pos < len(reader.data) {
		switch reader.data[reader.pos] {
		case ' ', '\t', '\n', '\r':
			reader.pos++
		default:
			return
		}
	}
}

func (reader *scanner) scanValue(depth int) (jsonValue, error) {
	if depth > MaxJSONDepth {
		return jsonValue{}, limitProblem()
	}
	if reader.pos >= len(reader.data) {
		return jsonValue{}, syntaxProblem()
	}
	if err := reader.token(); err != nil {
		return jsonValue{}, err
	}
	switch c := reader.data[reader.pos]; {
	case c == '{':
		return reader.scanObject(depth)
	case c == '[':
		return reader.scanArray(depth)
	case c == '"':
		text, err := reader.scanString()
		if err != nil {
			return jsonValue{}, err
		}
		return jsonValue{kind: jsonString, text: text}, nil
	case c == 't':
		return reader.scanLiteral("true", jsonValue{kind: jsonBool, boolean: true})
	case c == 'f':
		return reader.scanLiteral("false", jsonValue{kind: jsonBool})
	case c == 'n':
		return reader.scanLiteral("null", jsonValue{kind: jsonNull})
	case c >= '0' && c <= '9':
		return reader.scanNumber()
	default:
		return jsonValue{}, syntaxProblem()
	}
}

func (reader *scanner) scanLiteral(word string, value jsonValue) (jsonValue, error) {
	if !bytes.HasPrefix(reader.data[reader.pos:], []byte(word)) {
		return jsonValue{}, syntaxProblem()
	}
	reader.pos += len(word)
	return value, nil
}

// scanNumber accepts only a run of decimal digits. Fractional or exponent
// notation is rejected here; leading zeros, range and positivity are domain
// rules of the version field.
func (reader *scanner) scanNumber() (jsonValue, error) {
	start := reader.pos
	for reader.pos < len(reader.data) && reader.data[reader.pos] >= '0' && reader.data[reader.pos] <= '9' {
		reader.pos++
	}
	if reader.pos < len(reader.data) {
		switch reader.data[reader.pos] {
		case '.', 'e', 'E':
			return jsonValue{}, syntaxProblem()
		}
	}
	return jsonValue{kind: jsonNumber, number: string(reader.data[start:reader.pos])}, nil
}

func (reader *scanner) scanObject(depth int) (jsonValue, error) {
	reader.pos++ // '{'
	value := jsonValue{kind: jsonObject}
	reader.skipSpace()
	if reader.pos < len(reader.data) && reader.data[reader.pos] == '}' {
		if err := reader.token(); err != nil {
			return jsonValue{}, err
		}
		reader.pos++
		return value, nil
	}
	seen := make(map[string]bool)
	for {
		reader.skipSpace()
		if reader.pos >= len(reader.data) || reader.data[reader.pos] != '"' {
			return jsonValue{}, syntaxProblem()
		}
		if err := reader.token(); err != nil {
			return jsonValue{}, err
		}
		key, err := reader.scanString()
		if err != nil {
			return jsonValue{}, err
		}
		// Keys are compared after decoding, so an escaped spelling of a key is
		// the same key.
		if seen[key] {
			return jsonValue{}, syntaxProblem()
		}
		seen[key] = true

		reader.skipSpace()
		if reader.pos >= len(reader.data) || reader.data[reader.pos] != ':' {
			return jsonValue{}, syntaxProblem()
		}
		if err := reader.token(); err != nil {
			return jsonValue{}, err
		}
		reader.pos++
		reader.skipSpace()

		member, err := reader.scanValue(depth + 1)
		if err != nil {
			return jsonValue{}, err
		}
		value.members = append(value.members, jsonMember{key: key, value: member})

		reader.skipSpace()
		if reader.pos >= len(reader.data) {
			return jsonValue{}, syntaxProblem()
		}
		switch reader.data[reader.pos] {
		case ',':
			if err := reader.token(); err != nil {
				return jsonValue{}, err
			}
			reader.pos++
		case '}':
			if err := reader.token(); err != nil {
				return jsonValue{}, err
			}
			reader.pos++
			return value, nil
		default:
			return jsonValue{}, syntaxProblem()
		}
	}
}

func (reader *scanner) scanArray(depth int) (jsonValue, error) {
	reader.pos++ // '['
	value := jsonValue{kind: jsonArray}
	reader.skipSpace()
	if reader.pos < len(reader.data) && reader.data[reader.pos] == ']' {
		if err := reader.token(); err != nil {
			return jsonValue{}, err
		}
		reader.pos++
		return value, nil
	}
	for {
		reader.skipSpace()
		element, err := reader.scanValue(depth + 1)
		if err != nil {
			return jsonValue{}, err
		}
		value.elements = append(value.elements, element)

		reader.skipSpace()
		if reader.pos >= len(reader.data) {
			return jsonValue{}, syntaxProblem()
		}
		switch reader.data[reader.pos] {
		case ',':
			if err := reader.token(); err != nil {
				return jsonValue{}, err
			}
			reader.pos++
		case ']':
			if err := reader.token(); err != nil {
				return jsonValue{}, err
			}
			reader.pos++
			return value, nil
		default:
			return jsonValue{}, syntaxProblem()
		}
	}
}

// scanString decodes one JSON string within the byte budget. Surrogate escapes
// must be paired: an unpaired high or a lone low surrogate is malformed, not a
// replacement character.
func (reader *scanner) scanString() (string, error) {
	reader.pos++ // opening quote
	var builder strings.Builder
	for {
		if reader.pos >= len(reader.data) {
			return "", syntaxProblem()
		}
		c := reader.data[reader.pos]
		switch {
		case c == '"':
			reader.pos++
			if builder.Len() > MaxStringBytes {
				return "", limitProblem()
			}
			return builder.String(), nil
		case c < 0x20:
			return "", syntaxProblem()
		case c == '\\':
			if err := reader.scanEscape(&builder); err != nil {
				return "", err
			}
		default:
			r, size := utf8.DecodeRune(reader.data[reader.pos:])
			if r == utf8.RuneError && size == 1 {
				return "", syntaxProblem()
			}
			builder.Write(reader.data[reader.pos : reader.pos+size])
			reader.pos += size
		}
	}
}

func (reader *scanner) scanEscape(builder *strings.Builder) error {
	reader.pos++ // backslash
	if reader.pos >= len(reader.data) {
		return syntaxProblem()
	}
	switch reader.data[reader.pos] {
	case '"', '\\', '/':
		builder.WriteByte(reader.data[reader.pos])
		reader.pos++
	case 'b':
		builder.WriteByte('\b')
		reader.pos++
	case 'f':
		builder.WriteByte('\f')
		reader.pos++
	case 'n':
		builder.WriteByte('\n')
		reader.pos++
	case 'r':
		builder.WriteByte('\r')
		reader.pos++
	case 't':
		builder.WriteByte('\t')
		reader.pos++
	case 'u':
		high, ok := hexQuad(reader.data[reader.pos+1:])
		if !ok {
			return syntaxProblem()
		}
		reader.pos += 5
		switch {
		case high >= 0xD800 && high <= 0xDBFF:
			if reader.pos+1 >= len(reader.data) || reader.data[reader.pos] != '\\' || reader.data[reader.pos+1] != 'u' {
				return syntaxProblem()
			}
			low, ok := hexQuad(reader.data[reader.pos+2:])
			if !ok || low < 0xDC00 || low > 0xDFFF {
				return syntaxProblem()
			}
			reader.pos += 6
			builder.WriteRune(0x10000 + (high-0xD800)<<10 | (low - 0xDC00))
		case high >= 0xDC00 && high <= 0xDFFF:
			return syntaxProblem()
		default:
			builder.WriteRune(high)
		}
	default:
		return syntaxProblem()
	}
	return nil
}

func hexQuad(data []byte) (rune, bool) {
	if len(data) < 4 {
		return 0, false
	}
	var value rune
	for index := 0; index < 4; index++ {
		c := data[index]
		switch {
		case c >= '0' && c <= '9':
			value = value*16 + rune(c-'0')
		case c >= 'a' && c <= 'f':
			value = value*16 + rune(c-'a'+10)
		case c >= 'A' && c <= 'F':
			value = value*16 + rune(c-'A'+10)
		default:
			return 0, false
		}
	}
	return value, true
}

// --- schema decoding ---

var (
	packKeys     = []string{"schema_version", "profile", "pack_id", "version", "valid_from", "expires_at", "rules"}
	ruleKeys     = []string{"rule_id", "selector", "requires", "checks", "on_missing_evidence", "emit"}
	selectorKeys = []string{"coverage_method", "vulnerability_id"}
	checkKeys    = []string{"check_id", "predicate", "params"}
)

func memberValue(value jsonValue, name string) (jsonValue, bool) {
	for _, member := range value.members {
		if member.key == name {
			return member.value, true
		}
	}
	return jsonValue{}, false
}

// exactKeys rejects any key outside the declared set. A missing declared key is
// reported by the member reader that requires it.
func exactKeys(value jsonValue, allowed []string) error {
	for position, member := range value.members {
		found := false
		for _, name := range allowed {
			if member.key == name {
				found = true
				break
			}
		}
		if !found {
			return invalidProblem(position)
		}
	}
	return nil
}

func memberString(value jsonValue, name string, index int) (string, error) {
	member, ok := memberValue(value, name)
	if !ok || member.kind != jsonString {
		return "", invalidProblem(index)
	}
	return member.text, nil
}

func memberInteger(value jsonValue, name string, index int) (int64, error) {
	member, ok := memberValue(value, name)
	if !ok || member.kind != jsonNumber {
		return 0, invalidProblem(index)
	}
	digits := member.number
	if len(digits) > 1 && digits[0] == '0' {
		return 0, invalidProblem(index)
	}
	number, err := strconv.ParseInt(digits, 10, 64)
	if err != nil || number < 1 || number > MaxVersion {
		return 0, invalidProblem(index)
	}
	return number, nil
}

// memberTimestamp decodes the contractual timestamp representation: RFC 3339
// with an explicit Z, in its canonical spelling, never zero.
func memberTimestamp(value jsonValue, name string, index int) (contract.Timestamp, error) {
	text, err := memberString(value, name, index)
	if err != nil {
		return contract.Timestamp{}, err
	}
	parsed, err := time.Parse(time.RFC3339Nano, text)
	if err != nil || parsed.Location() != time.UTC || parsed.Format(time.RFC3339Nano) != text {
		return contract.Timestamp{}, invalidProblem(index)
	}
	stamp, err := contract.NewTimestamp(parsed)
	if err != nil {
		return contract.Timestamp{}, invalidProblem(index)
	}
	return stamp, nil
}

func memberArray(value jsonValue, name string, index int) ([]jsonValue, error) {
	member, ok := memberValue(value, name)
	if !ok || member.kind != jsonArray {
		return nil, invalidProblem(index)
	}
	return member.elements, nil
}

func decodePack(root jsonValue) (Pack, error) {
	if root.kind != jsonObject {
		return Pack{}, invalidProblem(-1)
	}
	if err := exactKeys(root, packKeys); err != nil {
		return Pack{}, err
	}
	schemaVersion, err := memberString(root, "schema_version", -1)
	if err != nil {
		return Pack{}, err
	}
	profile, err := memberString(root, "profile", -1)
	if err != nil {
		return Pack{}, err
	}
	packID, err := memberString(root, "pack_id", -1)
	if err != nil {
		return Pack{}, err
	}
	version, err := memberInteger(root, "version", -1)
	if err != nil {
		return Pack{}, err
	}
	validFrom, err := memberTimestamp(root, "valid_from", -1)
	if err != nil {
		return Pack{}, err
	}
	expiresAt, err := memberTimestamp(root, "expires_at", -1)
	if err != nil {
		return Pack{}, err
	}
	elements, err := memberArray(root, "rules", -1)
	if err != nil {
		return Pack{}, err
	}
	rules := make([]Rule, 0, len(elements))
	for index, element := range elements {
		rule, err := decodeRule(element, index)
		if err != nil {
			return Pack{}, err
		}
		rules = append(rules, rule)
	}
	return Pack{
		SchemaVersion: schemaVersion,
		Profile:       profile,
		PackID:        packID,
		Version:       version,
		ValidFrom:     validFrom,
		ExpiresAt:     expiresAt,
		Rules:         rules,
	}, nil
}

func decodeRule(value jsonValue, index int) (Rule, error) {
	if value.kind != jsonObject {
		return Rule{}, invalidProblem(index)
	}
	if err := exactKeys(value, ruleKeys); err != nil {
		return Rule{}, err
	}
	ruleID, err := memberString(value, "rule_id", index)
	if err != nil {
		return Rule{}, err
	}
	selector, err := decodeSelector(value, index)
	if err != nil {
		return Rule{}, err
	}
	requires, err := decodeRequires(value, index)
	if err != nil {
		return Rule{}, err
	}
	checks, err := decodeChecks(value, index)
	if err != nil {
		return Rule{}, err
	}
	onMissing, err := memberString(value, "on_missing_evidence", index)
	if err != nil {
		return Rule{}, err
	}
	emit, err := memberString(value, "emit", index)
	if err != nil {
		return Rule{}, err
	}
	return Rule{
		RuleID:            ruleID,
		Selector:          selector,
		Requires:          requires,
		Checks:            checks,
		OnMissingEvidence: onMissing,
		Emit:              emit,
	}, nil
}

func decodeSelector(value jsonValue, index int) (Selector, error) {
	member, ok := memberValue(value, "selector")
	if !ok || member.kind != jsonObject {
		return Selector{}, invalidProblem(index)
	}
	if err := exactKeys(member, selectorKeys); err != nil {
		return Selector{}, err
	}
	method, err := memberString(member, "coverage_method", index)
	if err != nil {
		return Selector{}, err
	}
	vulnerability, err := memberString(member, "vulnerability_id", index)
	if err != nil {
		return Selector{}, err
	}
	return Selector{CoverageMethod: contract.CoverageMethod(method), VulnerabilityID: vulnerability}, nil
}

func decodeRequires(value jsonValue, index int) ([]Requirement, error) {
	elements, err := memberArray(value, "requires", index)
	if err != nil {
		return nil, err
	}
	requires := make([]Requirement, 0, len(elements))
	for _, element := range elements {
		if element.kind != jsonString {
			return nil, invalidProblem(index)
		}
		requires = append(requires, Requirement(element.text))
	}
	return requires, nil
}

func decodeChecks(value jsonValue, index int) ([]Check, error) {
	elements, err := memberArray(value, "checks", index)
	if err != nil {
		return nil, err
	}
	checks := make([]Check, 0, len(elements))
	for _, element := range elements {
		check, err := decodeCheck(element, index)
		if err != nil {
			return nil, err
		}
		checks = append(checks, check)
	}
	return checks, nil
}

func decodeCheck(value jsonValue, index int) (Check, error) {
	if value.kind != jsonObject {
		return Check{}, invalidProblem(index)
	}
	if err := exactKeys(value, checkKeys); err != nil {
		return Check{}, err
	}
	checkID, err := memberString(value, "check_id", index)
	if err != nil {
		return Check{}, err
	}
	predicate, err := memberString(value, "predicate", index)
	if err != nil {
		return Check{}, err
	}
	member, ok := memberValue(value, "params")
	if !ok || member.kind != jsonObject {
		return Check{}, invalidProblem(index)
	}
	params, err := decodeParams(member, index)
	if err != nil {
		return Check{}, err
	}
	return Check{CheckID: checkID, Predicate: PredicateID(predicate), Params: params}, nil
}

// decodeParams maps the four declared parameter names onto their typed slots and
// rejects any other member. Which of them a predicate requires is a validation
// rule, not a decoding one.
func decodeParams(value jsonValue, index int) (Params, error) {
	var params Params
	for position, member := range value.members {
		if member.value.kind != jsonString {
			return Params{}, invalidProblem(index)
		}
		switch member.key {
		case "field":
			params.Field, params.FieldSet = member.value.text, true
		case "value":
			params.Value, params.ValueSet = member.value.text, true
		case "os":
			params.OS, params.OSSet = member.value.text, true
		case "architecture":
			params.Architecture, params.ArchitectureSet = member.value.text, true
		default:
			return Params{}, invalidProblem(position)
		}
	}
	return params, nil
}
