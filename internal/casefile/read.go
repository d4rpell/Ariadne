package casefile

import (
	"bytes"
	"strconv"
	"unicode/utf8"
)

// The admission reader (ADR-0030 §5.3) is directed by the canonical schema:
// it consumes exactly the keys, delimiters and escapes of §4 and refuses
// duplicates, unknown keys, case differences, omissions, wrong types and any
// non-canonical spelling. It never builds an arbitrary JSON tree and never
// repairs what it reads.

type parser struct {
	data  []byte
	pos   int
	depth int
	// Record-envelope tracking (ADR-0030 §5.1): recordStart is the offset of
	// the record's opening brace. The canonical envelope re-encodes every
	// escaped byte at its raw width, so the raw bytes consumed since the
	// brace are a strict lower bound of the final envelope; reaching the
	// record budget before the record is assembled is refused as
	// record_limit with precedence over the field budgets (§5.4).
	recordStart  int
	recordActive bool
}

// recordBudgetOK reports whether more bytes may still be consumed for this
// record. Every consumption path — strings, numbers, keys and delimiters —
// routes its advance through expect or through a loop that calls this.
func (p *parser) recordBudgetOK() bool {
	if !p.recordActive {
		return true
	}
	return p.pos-p.recordStart < MaxRecordBytes
}

func verifyBook(data []byte) (Book, error) {
	if len(data) == 0 {
		return Book{}, problem(CodeInvalidEncoding)
	}
	if len(data) > MaxBookBytes {
		return Book{}, problem(CodeBookLimit)
	}
	if !utf8.Valid(data) {
		return Book{}, problem(CodeInvalidEncoding)
	}
	records, bookFormat, bookVersion, err := parseBook(data)
	if err != nil {
		return Book{}, err
	}
	if bookFormat != BookFormat || bookVersion != FormatVersion {
		return Book{}, problem(CodeUnsupportedFormat)
	}
	for index := range records {
		record := records[index]
		if record.Format != RecordFormat || record.Version != FormatVersion {
			return Book{}, problem(CodeUnsupportedFormat)
		}
		if record.PreviousHash != nil && !isSha256(*record.PreviousHash) {
			return Book{}, problem(CodeInvalidReference)
		}
		if err := validateInput(record.Decision); err != nil {
			return Book{}, err
		}
		if !isSha256(record.Hash) {
			return Book{}, problem(CodeInvalidReference)
		}
	}
	if err := validateChain(records); err != nil {
		return Book{}, err
	}
	if !bytes.Equal(bookDocument(records), data) {
		return Book{}, problem(CodeInvalidEncoding)
	}
	return Book{initialized: true, records: records, bytes: len(data)}, nil
}

func parseBook(data []byte) ([]Record, string, string, error) {
	p := &parser{data: data}
	if err := p.enter(); err != nil {
		return nil, "", "", err
	}
	if err := p.expect('{'); err != nil {
		return nil, "", "", err
	}
	if err := p.expectKey("format"); err != nil {
		return nil, "", "", err
	}
	format, err := p.valueString()
	if err != nil {
		return nil, "", "", err
	}
	if err := p.expect(','); err != nil {
		return nil, "", "", err
	}
	if err := p.expectKey("version"); err != nil {
		return nil, "", "", err
	}
	version, err := p.valueString()
	if err != nil {
		return nil, "", "", err
	}
	if err := p.expect(','); err != nil {
		return nil, "", "", err
	}
	if err := p.expectKey("records"); err != nil {
		return nil, "", "", err
	}
	if err := p.expect('['); err != nil {
		return nil, "", "", err
	}
	if err := p.enter(); err != nil {
		return nil, "", "", err
	}

	records := []Record{}
	if p.peek() != ']' {
		for {
			if len(records) >= MaxRecords {
				return nil, "", "", problem(CodeBookLimit)
			}
			record, err := p.parseRecord()
			if err != nil {
				return nil, "", "", err
			}
			if len(recordEnvelope(record)) > MaxRecordBytes {
				return nil, "", "", problem(CodeRecordLimit)
			}
			records = append(records, record)
			if p.peek() == ',' {
				p.pos++
				continue
			}
			break
		}
	}
	if err := p.expect(']'); err != nil {
		return nil, "", "", err
	}
	p.leave()
	if err := p.expect('}'); err != nil {
		return nil, "", "", err
	}
	p.leave()
	if p.pos != len(data) {
		return nil, "", "", problem(CodeInvalidEncoding)
	}
	return records, format, version, nil
}

func (p *parser) parseRecord() (Record, error) {
	record := Record{}
	p.recordStart = p.pos
	p.recordActive = true
	defer func() { p.recordActive = false }()
	if err := p.expect('{'); err != nil {
		return record, err
	}
	if err := p.enter(); err != nil {
		return record, err
	}
	steps := []struct {
		key    string
		decode func(*Record) error
	}{
		{"format", func(r *Record) error {
			value, err := p.valueString()
			if err != nil {
				return err
			}
			r.Format = value
			return nil
		}},
		{"version", func(r *Record) error {
			value, err := p.valueString()
			if err != nil {
				return err
			}
			r.Version = value
			return nil
		}},
		{"sequence", func(r *Record) error {
			value, ok, err := p.valueNumber()
			if err != nil {
				return err
			}
			if !ok {
				// A grammar-valid integer outside uint64 stays representation:
				// the chain pass classifies it as invalid_sequence.
				r.Sequence = 0
				return nil
			}
			r.Sequence = value
			return nil
		}},
		{"previous_hash", func(r *Record) error {
			value, present, err := p.valueOptionalString()
			if err != nil {
				return err
			}
			if present {
				r.PreviousHash = &value
			}
			return nil
		}},
		{"risk_decision", func(r *Record) error {
			value, err := p.valueString()
			if err != nil {
				return err
			}
			r.Decision.RiskDecision = Decision(value)
			return nil
		}},
		{"owner", func(r *Record) error {
			value, err := p.valueStringLim(MaxActorBytes)
			if err != nil {
				return err
			}
			r.Decision.Owner = value
			return nil
		}},
		{"approver", func(r *Record) error {
			value, err := p.valueStringLim(MaxActorBytes)
			if err != nil {
				return err
			}
			r.Decision.Approver = value
			return nil
		}},
		{"rationale", func(r *Record) error {
			value, err := p.valueStringLim(MaxRationaleBytes)
			if err != nil {
				return err
			}
			r.Decision.Rationale = value
			return nil
		}},
		{"scope", p.decodeScope},
		{"controls", func(r *Record) error {
			value, err := p.valueStringArray()
			if err != nil {
				return err
			}
			r.Decision.Controls = value
			return nil
		}},
		{"decided_at", func(r *Record) error {
			value, err := p.valueString()
			if err != nil {
				return err
			}
			r.Decision.DecidedAt = value
			return nil
		}},
		{"expires_at", func(r *Record) error {
			value, present, err := p.valueOptionalString()
			if err != nil {
				return err
			}
			if present {
				r.Decision.ExpiresAt = &value
			}
			return nil
		}},
		{"supersedes", func(r *Record) error {
			value, present, err := p.valueOptionalString()
			if err != nil {
				return err
			}
			if present {
				r.Decision.Supersedes = &value
			}
			return nil
		}},
		{"hash", func(r *Record) error {
			value, err := p.valueString()
			if err != nil {
				return err
			}
			r.Hash = value
			return nil
		}},
	}
	for index, step := range steps {
		if index > 0 {
			if err := p.expect(','); err != nil {
				return record, err
			}
		}
		if err := p.expectKey(step.key); err != nil {
			return record, err
		}
		if err := step.decode(&record); err != nil {
			return record, err
		}
	}
	if err := p.expect('}'); err != nil {
		return record, err
	}
	p.leave()
	return record, nil
}

func (p *parser) decodeScope(record *Record) error {
	if err := p.expect('{'); err != nil {
		return err
	}
	if err := p.enter(); err != nil {
		return err
	}
	steps := []struct {
		key    string
		decode func(*Scope) error
	}{
		{"bundle_hash", func(s *Scope) error {
			value, err := p.valueString()
			if err != nil {
				return err
			}
			s.BundleHash = value
			return nil
		}},
		{"subject_uid", func(s *Scope) error {
			value, err := p.valueStringLim(MaxSubjectUIDBytes)
			if err != nil {
				return err
			}
			s.SubjectUID = value
			return nil
		}},
		{"container_name", func(s *Scope) error {
			value, err := p.valueStringLim(MaxContainerNameBytes)
			if err != nil {
				return err
			}
			s.ContainerName = value
			return nil
		}},
		{"container_class", func(s *Scope) error {
			value, err := p.valueString()
			if err != nil {
				return err
			}
			s.ContainerClass = ContainerClass(value)
			return nil
		}},
		{"vulnerability_id", func(s *Scope) error {
			value, err := p.valueStringLim(MaxVulnerabilityIDBytes)
			if err != nil {
				return err
			}
			s.VulnerabilityID = value
			return nil
		}},
		{"result_fingerprint", func(s *Scope) error {
			value, present, err := p.valueOptionalString()
			if err != nil {
				return err
			}
			if present {
				s.ResultFingerprint = &value
			}
			return nil
		}},
	}
	for index, step := range steps {
		if index > 0 {
			if err := p.expect(','); err != nil {
				return err
			}
		}
		if err := p.expectKey(step.key); err != nil {
			return err
		}
		if err := step.decode(&record.Decision.Scope); err != nil {
			return err
		}
	}
	if err := p.expect('}'); err != nil {
		return err
	}
	p.leave()
	return nil
}

func (p *parser) enter() error {
	p.depth++
	if p.depth > MaxDepth {
		return problem(CodeInvalidEncoding)
	}
	return nil
}

func (p *parser) leave() {
	p.depth--
}

func (p *parser) peek() byte {
	if p.pos >= len(p.data) {
		return 0
	}
	return p.data[p.pos]
}

func (p *parser) expect(want byte) error {
	if p.pos >= len(p.data) || p.data[p.pos] != want {
		return problem(CodeInvalidEncoding)
	}
	if !p.recordBudgetOK() {
		return problem(CodeRecordLimit)
	}
	p.pos++
	return nil
}

func (p *parser) expectKey(want string) error {
	value, err := p.valueString()
	if err != nil {
		return err
	}
	if value != want {
		return problem(CodeInvalidEncoding)
	}
	return p.expect(':')
}

func (p *parser) expectLiteral(literal string) (bool, error) {
	if p.pos+len(literal) > len(p.data) {
		return false, nil
	}
	for index := range literal {
		if p.data[p.pos+index] != literal[index] {
			return false, nil
		}
	}
	for range literal {
		if !p.recordBudgetOK() {
			return false, problem(CodeRecordLimit)
		}
		p.pos++
	}
	return true, nil
}

// valueString reads one canonical string token. Only the four escapes of §4.4
// are admitted, a raw byte below 0x20 is refused, and the whole token — quotes
// included — must fit MaxStringTokenBytes before the buffer grows.
// valueString reads one canonical string token with the raw-token budget only.
func (p *parser) valueString() (string, error) {
	return p.valueStringLim(-1)
}

// valueStringLim reads one canonical string token. Every budget is projected
// exactly per branch before any advance (§5.4): the closing quote costs one
// raw byte, a plain byte two, an escape three; a decoded-length limit, when
// given, is checked before the byte is appended; and the record envelope is
// bounded from below by the raw bytes consumed since the record's opening
// brace, so a record that cannot fit any more is refused as record_limit
// before the field budgets are even consulted.
func (p *parser) valueStringLim(maxDecoded int) (string, error) {
	start := p.pos
	if err := p.expect('"'); err != nil {
		return "", err
	}
	out := []byte{}
	for {
		// The record budget precedes the end-of-input check: reaching the
		// budget exactly at the last byte is a record_limit, never a
		// structural failure.
		if !p.recordBudgetOK() {
			return "", problem(CodeRecordLimit)
		}
		if p.pos >= len(p.data) {
			return "", problem(CodeInvalidEncoding)
		}
		c := p.data[p.pos]
		switch {
		case c == '"':
			if p.pos-start+1 > MaxStringTokenBytes {
				return "", problem(CodeFieldLimit)
			}
			if maxDecoded >= 0 && len(out) > maxDecoded {
				return "", problem(CodeFieldLimit)
			}
			p.pos++
			return string(out), nil
		case c == '\\':
			if p.pos-start+3 > MaxStringTokenBytes {
				return "", problem(CodeFieldLimit)
			}
			if maxDecoded >= 0 && len(out)+1 > maxDecoded {
				return "", problem(CodeFieldLimit)
			}
			p.pos++
			// The escape consumes two raw bytes: the budget is re-checked
			// before the second byte — even when the input ends there — or a
			// pair starting at MaxRecordBytes-1 would cross the record budget
			// unnoticed.
			if !p.recordBudgetOK() {
				return "", problem(CodeRecordLimit)
			}
			if p.pos >= len(p.data) {
				return "", problem(CodeInvalidEncoding)
			}
			switch p.data[p.pos] {
			case '"':
				out = append(out, '"')
			case '\\':
				out = append(out, '\\')
			case 'n':
				out = append(out, '\n')
			case 't':
				out = append(out, '\t')
			default:
				return "", problem(CodeInvalidEncoding)
			}
			p.pos++
		case c < 0x20:
			return "", problem(CodeInvalidEncoding)
		default:
			if p.pos-start+2 > MaxStringTokenBytes {
				return "", problem(CodeFieldLimit)
			}
			if maxDecoded >= 0 && len(out)+1 > maxDecoded {
				return "", problem(CodeFieldLimit)
			}
			out = append(out, c)
			p.pos++
		}
	}
}

func (p *parser) valueOptionalString() (string, bool, error) {
	present, err := p.expectLiteral("null")
	if err != nil {
		return "", false, err
	}
	if present {
		return "", false, nil
	}
	value, err := p.valueString()
	return value, true, err
}

// valueNumber reads one canonical sequence number: ASCII digits with a
// nonzero first digit. "0", "01", "1.0" and "1e0" are representation failures
// (invalid_encoding); a grammar-valid integer outside uint64 is a range
// failure that the chain pass classifies as invalid_sequence.
func (p *parser) valueNumber() (uint64, bool, error) {
	start := p.pos
	overflow := false
	for p.pos < len(p.data) && p.data[p.pos] >= '0' && p.data[p.pos] <= '9' {
		if !p.recordBudgetOK() {
			return 0, false, problem(CodeRecordLimit)
		}
		if p.pos-start == 20 {
			// A grammar-valid integer beyond uint64 is classified as a range
			// failure before the rest of the digits are consumed.
			overflow = true
		}
		p.pos++
	}
	if p.pos == start || p.data[start] == '0' {
		return 0, false, problem(CodeInvalidEncoding)
	}
	if overflow {
		return 0, false, nil
	}
	value, err := strconv.ParseUint(string(p.data[start:p.pos]), 10, 64)
	if err != nil {
		return 0, false, nil
	}
	return value, true, nil
}

func (p *parser) valueStringArray() ([]string, error) {
	if err := p.expect('['); err != nil {
		return nil, err
	}
	if err := p.enter(); err != nil {
		return nil, err
	}
	defer p.leave()
	values := []string{}
	if p.peek() == ']' {
		if !p.recordBudgetOK() {
			return nil, problem(CodeRecordLimit)
		}
		p.pos++
		return values, nil
	}
	for {
		value, err := p.valueStringLim(MaxControlBytes)
		if err != nil {
			return nil, err
		}
		values = append(values, value)
		if p.peek() == ',' {
			if !p.recordBudgetOK() {
				return nil, problem(CodeRecordLimit)
			}
			if len(values) >= MaxControls {
				return nil, problem(CodeControlLimit)
			}
			p.pos++
			continue
		}
		break
	}
	if err := p.expect(']'); err != nil {
		return nil, err
	}
	return values, nil
}
