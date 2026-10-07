package casefile

import (
	"bytes"
	"errors"
	"strings"
	"testing"
)

func TestScopeIdentityPreserved(t *testing.T) {
	input := validInput()
	book := mustAppend(t, NewBook(), input)
	records, _ := Records(book)
	scope := records[0].Decision.Scope
	if scope.BundleHash != input.Scope.BundleHash ||
		scope.SubjectUID != input.Scope.SubjectUID ||
		scope.ContainerName != input.Scope.ContainerName ||
		scope.ContainerClass != input.Scope.ContainerClass ||
		scope.VulnerabilityID != input.Scope.VulnerabilityID {
		t.Fatal("the scope was normalized or replaced")
	}
	// Case changes are conserved, never folded: they produce another record.
	upper := validInput()
	upper.Scope.VulnerabilityID = "cve-2026-1234"
	upperBook := mustAppend(t, NewBook(), upper)
	upperRecords, _ := Records(upperBook)
	if upperRecords[0].Hash == records[0].Hash {
		t.Fatal("case differences were normalized away")
	}
	// An opaque identifier needs no UUID or DNS shape.
	opaque := validInput()
	opaque.Scope.SubjectUID = "k8s/ใuid-…"
	opaque.Scope.SubjectUID = "uid with\u00a0nbsp is rejected elsewhere"
	if _, err := Append(NewBook(), opaque); !IsCode(err, CodeInvalidScope) {
		t.Fatalf("whitespace inside an identifier was admitted: %v", err)
	}
	opaque.Scope.SubjectUID = "arn:aws:eks:eu-west-1:1:pod/9ab"
	if _, err := Append(NewBook(), opaque); err != nil {
		t.Fatalf("an opaque identifier was refused: %v", err)
	}
}

func TestScopeReferenceFormats(t *testing.T) {
	badHashes := []string{
		"", "sha256:", "sha256:" + strings.Repeat("ab", 31),
		"sha256:" + strings.Repeat("ab", 33),
		"sha256:" + strings.Repeat("AB", 32),
		"sha 256:" + strings.Repeat("ab", 32),
		"md5:" + strings.Repeat("ab", 32),
		strings.Repeat("ab", 32),
		"sha256:" + strings.Repeat("ab", 32) + " ",
		"sha256:" + strings.Repeat("ab", 32) + "\n",
	}
	for _, bad := range badHashes {
		input := validInput()
		input.Scope.BundleHash = bad
		if _, err := Append(NewBook(), input); !IsCode(err, CodeInvalidReference) {
			t.Fatalf("bundle hash %q admitted: %v", bad, err)
		}
		fingerprintInput := validInput()
		fingerprint := bad
		fingerprintInput.Scope.ResultFingerprint = &fingerprint
		if _, err := Append(NewBook(), fingerprintInput); !IsCode(err, CodeInvalidReference) {
			t.Fatalf("fingerprint %q admitted: %v", bad, err)
		}
	}
	present := validInput()
	if _, err := Append(NewBook(), present); err != nil {
		t.Fatalf("a valid fingerprint was refused: %v", err)
	}
	// Invalid UTF-8 in a Go input is a representation failure, whatever the
	// field: the same bytes could never come back through Verify.
	for name, mutate := range map[string]func(*DecisionInput){
		"owner":       func(in *DecisionInput) { in.Owner = "own\xff" },
		"rationale":   func(in *DecisionInput) { in.Rationale = "ok\xff" },
		"subject_uid": func(in *DecisionInput) { in.Scope.SubjectUID = "uid\xff" },
		"control":     func(in *DecisionInput) { in.Controls = []string{"control\xff"} },
		"container":   func(in *DecisionInput) { in.Scope.ContainerName = "api\xff" },
	} {
		input := validInput()
		mutate(&input)
		if _, err := Append(NewBook(), input); !IsCode(err, CodeInvalidEncoding) {
			t.Fatalf("invalid UTF-8 in %s admitted: %v", name, err)
		}
	}
	// A literal U+FFFD is a normal character, never treated as a repair.
	replacement := validInput()
	replacement.Owner = "own�"
	if _, err := Append(NewBook(), replacement); err != nil {
		t.Fatalf("literal U+FFFD refused: %v", err)
	}
}

func TestTimestampSyntaxWithoutLifecycle(t *testing.T) {
	valid := []string{
		"0001-01-01T00:00:00Z", "1900-02-28T23:59:59Z", "2000-02-29T00:00:00Z",
		"2024-02-29T12:34:56Z", "2026-10-04T12:00:00Z", "9999-12-31T23:59:59Z",
	}
	invalid := []string{
		"", "2026-10-04T12:00:00", "2026-10-04 12:00:00Z", "2026-10-04t12:00:00z",
		"2026-10-04T12:00:00.5Z", "2026-10-04T12:00:00+00:00", "2026-13-01T00:00:00Z",
		"2026-00-01T00:00:00Z", "2026-04-31T00:00:00Z", "2023-02-29T00:00:00Z",
		"1900-02-29T00:00:00Z", "2026-10-04T24:00:00Z", "2026-10-04T12:60:00Z",
		"2026-10-04T12:00:60Z", "0000-01-01T00:00:00Z", "2026-10-04T12:00:00",
		"2026-1-04T12:00:00Z", " 2026-10-04T12:00:00Z", "2026-10-04T12:00:00ZZ",
		"20261004T120000Z",
	}
	for _, value := range valid {
		input := validInput()
		input.DecidedAt = value
		if _, err := Append(NewBook(), input); err != nil {
			t.Fatalf("timestamp %q refused: %v", value, err)
		}
	}
	for _, value := range invalid {
		input := validInput()
		input.DecidedAt = value
		if _, err := Append(NewBook(), input); !IsCode(err, CodeInvalidTimestamp) {
			t.Fatalf("timestamp %q admitted: %v", value, err)
		}
	}
	// No lifecycle: an already-past expires_at is stored as data, records are
	// never ordered by decided_at, and no comparison rejects anything.
	expired := validInput()
	expired.ExpiresAt = new(string)
	*expired.ExpiresAt = "1999-01-01T00:00:00Z"
	book := mustAppend(t, NewBook(), expired)
	reversed := validInput()
	reversed.DecidedAt = "1990-01-01T00:00:00Z"
	book = mustAppend(t, book, reversed)
	records, _ := Records(book)
	if records[0].Decision.DecidedAt != "2026-10-04T12:00:00Z" || records[1].Decision.DecidedAt != "1990-01-01T00:00:00Z" {
		t.Fatal("records were reordered by time")
	}
}

func TestCasefileBudgetBoundaries(t *testing.T) {
	t.Run("actor", func(t *testing.T) {
		for _, limit := range []int{MaxActorBytes - 1, MaxActorBytes} {
			input := validInput()
			input.Owner = strings.Repeat("o", limit)
			if _, err := Append(NewBook(), input); err != nil {
				t.Fatalf("owner of %d bytes refused: %v", limit, err)
			}
		}
		input := validInput()
		input.Owner = strings.Repeat("o", MaxActorBytes+1)
		if _, err := Append(NewBook(), input); !IsCode(err, CodeFieldLimit) {
			t.Fatalf("owner of %d bytes admitted: %v", MaxActorBytes+1, err)
		}
	})
	t.Run("rationale", func(t *testing.T) {
		for _, limit := range []int{MaxRationaleBytes - 1, MaxRationaleBytes} {
			input := validInput()
			input.Rationale = strings.Repeat("r", limit)
			if _, err := Append(NewBook(), input); err != nil {
				t.Fatalf("rationale of %d bytes refused: %v", limit, err)
			}
		}
		input := validInput()
		input.Rationale = strings.Repeat("r", MaxRationaleBytes+1)
		if _, err := Append(NewBook(), input); !IsCode(err, CodeFieldLimit) {
			t.Fatalf("rationale of %d bytes admitted: %v", MaxRationaleBytes+1, err)
		}
	})
	t.Run("controls", func(t *testing.T) {
		input := validInput()
		input.Controls = make([]string, MaxControls)
		for index := range input.Controls {
			input.Controls[index] = "control"
		}
		if _, err := Append(NewBook(), input); err != nil {
			t.Fatalf("%d controls refused: %v", MaxControls, err)
		}
		input.Controls = make([]string, MaxControls+1)
		for index := range input.Controls {
			input.Controls[index] = "control"
		}
		if _, err := Append(NewBook(), input); !IsCode(err, CodeControlLimit) {
			t.Fatalf("%d controls admitted: %v", MaxControls+1, err)
		}
	})
	t.Run("control_length", func(t *testing.T) {
		input := validInput()
		input.Controls = []string{strings.Repeat("c", MaxControlBytes)}
		if _, err := Append(NewBook(), input); err != nil {
			t.Fatalf("control of %d bytes refused: %v", MaxControlBytes, err)
		}
		input.Controls = []string{strings.Repeat("c", MaxControlBytes+1)}
		if _, err := Append(NewBook(), input); !IsCode(err, CodeFieldLimit) {
			t.Fatalf("control of %d bytes admitted: %v", MaxControlBytes+1, err)
		}
	})
	t.Run("subject_uid", func(t *testing.T) {
		for _, limit := range []int{MaxSubjectUIDBytes - 1, MaxSubjectUIDBytes} {
			input := validInput()
			input.Scope.SubjectUID = strings.Repeat("u", limit)
			if _, err := Append(NewBook(), input); err != nil {
				t.Fatalf("subject of %d bytes refused: %v", limit, err)
			}
		}
		input := validInput()
		input.Scope.SubjectUID = strings.Repeat("u", MaxSubjectUIDBytes+1)
		if _, err := Append(NewBook(), input); !IsCode(err, CodeFieldLimit) {
			t.Fatalf("subject of %d bytes admitted: %v", MaxSubjectUIDBytes+1, err)
		}
	})
	t.Run("container_name", func(t *testing.T) {
		for _, limit := range []int{MaxContainerNameBytes - 1, MaxContainerNameBytes} {
			input := validInput()
			input.Scope.ContainerName = strings.Repeat("n", limit)
			if _, err := Append(NewBook(), input); err != nil {
				t.Fatalf("container of %d bytes refused: %v", limit, err)
			}
		}
		input := validInput()
		input.Scope.ContainerName = strings.Repeat("n", MaxContainerNameBytes+1)
		if _, err := Append(NewBook(), input); !IsCode(err, CodeFieldLimit) {
			t.Fatalf("container of %d bytes admitted: %v", MaxContainerNameBytes+1, err)
		}
	})
	t.Run("vulnerability_id", func(t *testing.T) {
		for _, limit := range []int{MaxVulnerabilityIDBytes - 1, MaxVulnerabilityIDBytes} {
			input := validInput()
			input.Scope.VulnerabilityID = "C" + strings.Repeat("v", limit-1)
			if _, err := Append(NewBook(), input); err != nil {
				t.Fatalf("vulnerability of %d bytes refused: %v", limit, err)
			}
		}
		input := validInput()
		input.Scope.VulnerabilityID = "C" + strings.Repeat("v", MaxVulnerabilityIDBytes)
		if _, err := Append(NewBook(), input); !IsCode(err, CodeFieldLimit) {
			t.Fatalf("vulnerability of %d bytes admitted: %v", MaxVulnerabilityIDBytes+1, err)
		}
	})
	t.Run("raw_token_guard_precedes_decoded_limits", func(t *testing.T) {
		// A giant raw token hits MaxStringTokenBytes during reading, before the
		// decoded rationale limit can be evaluated: the code must be
		// field_limit, never invalid_rationale.
		document := string(mustEncode(t, mustAppend(t, NewBook(), validInput())))
		start := bytes.Index([]byte(document), []byte(`"rationale":"`))
		giant := document[:start+len(`"rationale":"`)] + strings.Repeat("r", MaxStringTokenBytes) + `","scope"`
		book, err := Verify([]byte(giant))
		if !IsCode(err, CodeFieldLimit) {
			t.Fatalf("giant token: %v", err)
		}
		if book.initialized {
			t.Fatal("a rejected read returned an admitted book")
		}
	})
	t.Run("record_envelope", func(t *testing.T) {
		// The fields whose shape is validated after the record is assembled
		// (risk_decision, decided_at, expires_at) are the only ones able to
		// push the envelope past MaxRecordBytes: every decoded-length field is
		// refused by its own in-read guard first. Declared limitation per
		// contract §9.3.
		var builder strings.Builder
		builder.WriteString(`{"format":"` + BookFormat + `","version":"` + FormatVersion + `","records":[`)
		builder.WriteString(`{"format":"` + RecordFormat + `","version":"` + FormatVersion + `","sequence":1,"previous_hash":null,`)
		builder.WriteString(`"risk_decision":"` + strings.Repeat("a", 49000) + `","owner":"owner","approver":"approver","rationale":"why",`)
		builder.WriteString(`"scope":{"bundle_hash":"sha256:` + strings.Repeat("12", 32) + `","subject_uid":"uid",`)
		builder.WriteString(`"container_name":"api","container_class":"regular","vulnerability_id":"CVE-1","result_fingerprint":null},`)
		builder.WriteString(`"controls":[],"decided_at":"` + strings.Repeat("2", 49000) + `","expires_at":"` + strings.Repeat("3", 49000) + `","supersedes":null,"hash":"sha256:` + strings.Repeat("ab", 32) + `"}`)
		builder.WriteString(`]}`)
		if _, err := Verify([]byte(builder.String())); !IsCode(err, CodeRecordLimit) {
			t.Fatalf("oversized record envelope: %v", err)
		}
	})
	t.Run("escaped_token_guard_fires_mid_read", func(t *testing.T) {
		// An unterminated token made of escapes must hit the raw-token budget
		// during reading, not surface as a structural failure at end of input.
		document := string(mustEncode(t, mustAppend(t, NewBook(), validInput())))
		start := strings.Index(document, `"rationale":"`)
		giant := document[:start+len(`"rationale":"`)] + strings.Repeat(`\`, 49200)
		if _, err := Verify([]byte(giant)); !IsCode(err, CodeFieldLimit) {
			t.Fatalf("giant escaped token: %v", err)
		}
	})
	t.Run("field_limit_precedes_later_structure", func(t *testing.T) {
		// An over-long owner is refused the moment its token closes, even when
		// the rest of the document could never parse.
		document := string(mustEncode(t, mustAppend(t, NewBook(), validInput())))
		start := strings.Index(document, `"owner":"`)
		broken := document[:start+len(`"owner":"`)] + strings.Repeat("o", 300) + `","scope"`
		if _, err := Verify([]byte(broken)); !IsCode(err, CodeFieldLimit) {
			t.Fatalf("oversized owner before structural garbage: %v", err)
		}
	})
	t.Run("decoded_limit_fires_mid_token", func(t *testing.T) {
		// An owner beyond 256 bytes must stop with field_limit while the token
		// is still being read, even when it never closes.
		document := string(mustEncode(t, mustAppend(t, NewBook(), validInput())))
		start := strings.Index(document, `"owner":"`)
		giant := document[:start+len(`"owner":"`)] + strings.Repeat("o", 300)
		if _, err := Verify([]byte(giant)); !IsCode(err, CodeFieldLimit) {
			t.Fatalf("oversized unterminated owner: %v", err)
		}
	})
	t.Run("exact_raw_token_boundary_is_admitted", func(t *testing.T) {
		// A token of exactly MaxStringTokenBytes raw bytes — quotes included —
		// passes the guard in both spellings: plain bytes and escapes.
		plain := strings.Replace(
			string(mustEncode(t, mustAppend(t, NewBook(), validInput()))),
			`"risk_decision":"accepted"`,
			`"risk_decision":"`+strings.Repeat("a", 49152)+`"`, 1)
		if _, err := Verify([]byte(plain)); !IsCode(err, CodeInvalidDecision) {
			t.Fatalf("exact-boundary plain token: %v", err)
		}
		// The escaped spelling must also reach the exact raw-token boundary:
		// 49152 backslashes are 24576 two-byte escape pairs, so the token spans
		// 49154 raw bytes including its quotes — the same MaxStringTokenBytes as
		// the plain vector above, not the half-width 24578 the previous fixture
		// measured.
		escapedToken := `"` + strings.Repeat(`\`, 49152) + `"`
		if len(escapedToken) != MaxStringTokenBytes {
			t.Fatalf("escaped boundary fixture is not width-exact: %d", len(escapedToken))
		}
		escaped := strings.Replace(
			string(mustEncode(t, mustAppend(t, NewBook(), validInput()))),
			`"risk_decision":"accepted"`,
			`"risk_decision":`+escapedToken, 1)
		if _, err := Verify([]byte(escaped)); !IsCode(err, CodeInvalidDecision) {
			t.Fatalf("exact-boundary escaped token: %v", err)
		}
	})
	t.Run("record_budget_fires_on_raw_consumption", func(t *testing.T) {
		// The canonical envelope re-encodes escapes at their raw width, so raw
		// bytes consumed since the brace bound the envelope from below: a
		// record that reaches MaxRecordBytes of raw consumption is refused
		// during the read, whatever follows.
		document := string(mustEncode(t, mustAppend(t, NewBook(), validInput())))
		start := strings.Index(document, `"risk_decision":"`)
		// Three near-token-limit fields on unvalidated-shape keys accumulate
		// more than MaxRecordBytes of raw consumption without any single token
		// exceeding the token budget.
		fields := `"risk_decision":"` + strings.Repeat("a", 49152) + `",` +
			`"owner":"owner","approver":"approver","rationale":"why",` +
			`"scope":{"bundle_hash":"sha256:` + strings.Repeat("12", 32) + `","subject_uid":"uid","container_name":"api","container_class":"regular","vulnerability_id":"CVE-1","result_fingerprint":null},` +
			`"controls":[],` +
			`"decided_at":"` + strings.Repeat("2", 49152) + `",` +
			`"expires_at":"` + strings.Repeat("3", 49152)
		giant := document[:start] + fields
		if _, err := Verify([]byte(giant)); !IsCode(err, CodeRecordLimit) {
			t.Fatalf("raw consumption beyond the record budget: %v", err)
		}
		digits := document[:strings.Index(document, `"sequence":`)+len(`"sequence":`)] + strings.Repeat("9", MaxRecordBytes)
		if _, err := Verify([]byte(digits)); !IsCode(err, CodeRecordLimit) {
			t.Fatalf("digit flood beyond the record budget: %v", err)
		}
	})
	t.Run("escape_and_null_crossings_are_refused", func(t *testing.T) {
		// (a) Exact midpoint crossing: padding risk_decision and decided_at
		// (the shape-free fields preceding expires_at) so the escape pair in
		// expires_at starts at MaxRecordBytes-1 — the midpoint check between
		// the two raw bytes must fire record_limit; without it the pair would
		// be consumed and the failure would surface as invalid_encoding.
		document := string(mustEncode(t, mustAppend(t, NewBook(), validInput())))
		document = strings.Replace(document, `"expires_at":null`,
			`"expires_at":"placeholder"`, 1)
		document = strings.Replace(document, `"risk_decision":"accepted"`,
			`"risk_decision":"`+strings.Repeat("a", 49152)+`"`, 1)
		document = strings.Replace(document, `"decided_at":"2026-10-04T12:00:00Z"`,
			`"decided_at":"`+strings.Repeat("2", 49152)+`"`, 1)
		// One extra byte before expires_at flips the raw-offset parity so an
		// escape pair starts exactly at MaxRecordBytes-1: the run length below is
		// then odd and the crossing is caught by the mid-pair re-check, not by the
		// top-of-loop header guard. Without the parity flip an even run places its
		// last complete pair at the boundary and the header guard masks the
		// orthogonal §5.4 midpoint check.
		document = strings.Replace(document, `CHG-0001"`, `CHG-00011"`, 1)
		valueStart := strings.Index(document, `"expires_at":"`) + len(`"expires_at":"`)
		backslashes := MaxRecordBytes - (valueStart - strings.Index(document, `{"format":"`+RecordFormat))
		if backslashes <= 0 || backslashes > 49153 {
			t.Fatalf("fixture cannot place the escape pair: %d", backslashes)
		}
		if backslashes%2 == 0 {
			t.Fatalf("fixture does not place a pair start on the boundary: %d backslashes", backslashes)
		}
		// The byte after the boundary backslash is an invalid escape ("q"), so
		// the two guards diverge: with the mid-pair re-check the crossing is a
		// record_limit before the second byte is ever read; without it the parser
		// would consume the pair and surface invalid_encoding. The assertion
		// therefore pins the mid-pair guard, not only the fixture geometry.
		giant := document[:valueStart] + strings.Repeat(`\`, backslashes) + "q"
		if _, err := Verify([]byte(giant)); !IsCode(err, CodeRecordLimit) {
			t.Fatalf("midpoint escape crossing: %v", err)
		}
		// (b) Null straddle: only fields preceding expires_at carry the
		// padding (risk_decision, decided_at and the controls elements), so
		// the four bytes of the literal cross the budget inside expectLiteral.
		zeroControls := strings.Replace(string(mustEncode(t, mustAppend(t, NewBook(), validInput()))),
			`"controls":[]`, `"controls":["x"]`, 1)
		nullStart := strings.Index(zeroControls, `"expires_at":null`) + len(`"expires_at":`)
		recordStart := strings.Index(zeroControls, `{"format":"`+RecordFormat)
		base := nullStart - recordStart
		elementSize := 0
		found := false
		for candidate := 1; candidate <= 1024 && !found; candidate++ {
			controlsBytes := 32 * (candidate + len(`""`) + 1)
			riskPad := base + controlsBytes - 49154
			if riskPad <= 0 || riskPad > 49152 {
				continue
			}
			total := 49154 + riskPad + 49154 + controlsBytes
			if total == MaxRecordBytes-2 {
				elementSize = candidate
				found = true
			}
		}
		if !found {
			t.Skip("no element size places the null exactly on the boundary")
		}
		riskPad := base + 32*(elementSize+len(`""`)+1) - 49154
		padded := strings.Replace(string(mustEncode(t, mustAppend(t, NewBook(), validInput()))),
			`"controls":[]`,
			`"controls":[`+strings.Repeat(`"`+strings.Repeat("c", elementSize)+`",`, 31)+`"`+strings.Repeat("c", elementSize)+`]`, 1)
		padded = strings.Replace(padded, `"risk_decision":"accepted"`,
			`"risk_decision":"`+strings.Repeat("a", riskPad)+`"`, 1)
		if _, err := Verify([]byte(padded)); !IsCode(err, CodeRecordLimit) {
			t.Fatalf("null straddle: %v", err)
		}
	})
	t.Run("sequence_overflow_is_a_range_failure", func(t *testing.T) {
		document := string(mustEncode(t, mustAppend(t, NewBook(), validInput())))
		overflow := strings.Replace(document, `"sequence":1`, `"sequence":123456789012345678901234567890`, 1)
		if _, err := Verify([]byte(overflow)); !IsCode(err, CodeInvalidSequence) {
			t.Fatalf("sequence overflow: %v", err)
		}
	})
	t.Run("record_count", func(t *testing.T) {
		book := NewBook()
		input := validInput()
		for index := 0; index < MaxRecords; index++ {
			book = mustAppend(t, book, input)
		}
		if _, err := Append(book, input); !IsCode(err, CodeBookLimit) {
			t.Fatalf("record %d admitted: %v", MaxRecords+1, err)
		}
		// The read path refuses the count before parsing the record that
		// would exceed it, even when every link would be broken anyway.
		oneRecord := string(mustEncode(t, mustAppend(t, NewBook(), input)))
		start := bytes.Index([]byte(oneRecord), []byte(`[`))
		end := bytes.LastIndexByte([]byte(oneRecord), ']')
		element := oneRecord[start+1 : end]
		flood := oneRecord[:start+1] + element + strings.Repeat(","+element, MaxRecords) + "]}"
		if _, err := Verify([]byte(flood)); !IsCode(err, CodeBookLimit) {
			t.Fatalf("flooded book: %v", err)
		}
	})
	t.Run("book_bytes", func(t *testing.T) {
		junk := make([]byte, MaxBookBytes+1)
		for index := range junk {
			junk[index] = ' '
		}
		if _, err := Verify(junk); !IsCode(err, CodeBookLimit) {
			t.Fatalf("oversized document: %v", err)
		}
	})
}

func TestCasefileErrorCatalogAndPrecedence(t *testing.T) {
	codes := map[string]func() error{
		string(CodeInvalidBook):       func() error { _, err := Append(Book{}, validInput()); return err },
		string(CodeInvalidEncoding):   func() error { _, err := Verify([]byte(" ")); return err },
		string(CodeUnsupportedFormat): func() error { _, err := Verify([]byte(`{"format":"other","version":"1.0","records":[]}`)); return err },
		string(CodeBookLimit):         func() error { _, err := Verify(make([]byte, MaxBookBytes+1)); return err },
		string(CodeRecordLimit): func() error {
			var builder strings.Builder
			builder.WriteString(`{"format":"` + BookFormat + `","version":"` + FormatVersion + `","records":[{"format":"` + RecordFormat + `","version":"1.0","sequence":1,"previous_hash":null,`)
			builder.WriteString(`"risk_decision":"` + strings.Repeat("a", 49000) + `","owner":"owner","approver":"approver","rationale":"why",`)
			builder.WriteString(`"scope":{"bundle_hash":"sha256:` + strings.Repeat("12", 32) + `","subject_uid":"uid","container_name":"api","container_class":"regular","vulnerability_id":"CVE-1","result_fingerprint":null},`)
			builder.WriteString(`"controls":[],"decided_at":"` + strings.Repeat("2", 49000) + `","expires_at":"` + strings.Repeat("3", 49000) + `","supersedes":null,"hash":"sha256:` + strings.Repeat("ab", 32) + `"}]}`)
			_, err := Verify([]byte(builder.String()))
			return err
		},
		string(CodeFieldLimit): func() error {
			input := validInput()
			input.Controls = []string{strings.Repeat("c", MaxControlBytes+1)}
			_, err := Append(NewBook(), input)
			return err
		},
		string(CodeControlLimit): func() error {
			input := validInput()
			input.Controls = make([]string, MaxControls+1)
			_, err := Append(NewBook(), input)
			return err
		},
		string(CodeInvalidDecision): func() error {
			input := validInput()
			input.RiskDecision = "maybe"
			_, err := Append(NewBook(), input)
			return err
		},
		string(CodeInvalidActor): func() error {
			input := validInput()
			input.Owner = ""
			_, err := Append(NewBook(), input)
			return err
		},
		string(CodeInvalidRationale): func() error {
			input := validInput()
			input.Rationale = "  \t "
			_, err := Append(NewBook(), input)
			return err
		},
		string(CodeInvalidScope): func() error {
			input := validInput()
			input.Scope.ContainerClass = "sidecar"
			_, err := Append(NewBook(), input)
			return err
		},
		string(CodeInvalidControl): func() error {
			input := validInput()
			input.Controls = []string{" padded control"}
			_, err := Append(NewBook(), input)
			return err
		},
		string(CodeInvalidTimestamp): func() error {
			input := validInput()
			input.DecidedAt = "yesterday"
			_, err := Append(NewBook(), input)
			return err
		},
		string(CodeInvalidReference): func() error {
			input := validInput()
			input.Scope.BundleHash = "sha256:short"
			_, err := Append(NewBook(), input)
			return err
		},
		string(CodeInvalidSequence): func() error {
			document := string(mustEncode(t, mustAppend(t, NewBook(), validInput())))
			broken := bytes.Replace([]byte(document), []byte(`"sequence":1`), []byte(`"sequence":7`), 1)
			_, err := Verify(broken)
			return err
		},
		string(CodeChainMismatch): func() error {
			first := mustEncode(t, mustAppend(t, NewBook(), validInput()))
			other := validInput()
			other.Rationale = "a different genesis record"
			second := mustEncode(t, mustAppend(t, mustAppend(t, NewBook(), other), validInput()))
			stitched := spliceRecords(t, first, second, 1)
			_, err := Verify(stitched)
			return err
		},
		string(CodeHashMismatch): func() error {
			document := mustEncode(t, mustAppend(t, NewBook(), validInput()))
			tampered := bytes.Replace(document, []byte("platform owner"), []byte("Platform owner"), 1)
			_, err := Verify(tampered)
			return err
		},
		string(CodeInvalidWriter): func() error {
			var typedNil *countedWriter
			return Write(NewBook(), typedNil)
		},
		string(CodeWriteFailed): func() error {
			return Write(mustAppend(t, NewBook(), validInput()), failingWriter{Err: errDestination})
		},
		string(CodeShortWrite): func() error {
			return Write(mustAppend(t, NewBook(), validInput()), shortWriter{Count: 1})
		},
	}
	for code, produce := range codes {
		err := produce()
		if !IsCode(err, ErrorCode(code)) {
			t.Fatalf("code %s: got %v", code, err)
		}
		if err.Error() != "casefile: "+code {
			t.Fatalf("code %s: message %q", code, err.Error())
		}
		if strings.Contains(err.Error(), "owner") || strings.Contains(err.Error(), "CHG") || strings.Contains(err.Error(), "uid") {
			t.Fatalf("code %s leaks input: %q", code, err.Error())
		}
	}
	t.Run("simultaneous_defects", func(t *testing.T) {
		// Sequence representation beats range: "0" is invalid_encoding even
		// though 0 also breaks the continuity rule.
		document := string(mustEncode(t, mustAppend(t, NewBook(), validInput())))
		zero := bytes.Replace([]byte(document), []byte(`"sequence":1`), []byte(`"sequence":0`), 1)
		if _, err := Verify(zero); !IsCode(err, CodeInvalidEncoding) {
			t.Fatalf("sequence 0: %v", err)
		}
		// Field order beats later fields: an over-long owner is reported as a
		// budget failure before the broken rationale is ever inspected.
		input := validInput()
		input.Owner = strings.Repeat("o", MaxActorBytes+1)
		input.Rationale = "   "
		if _, err := Append(NewBook(), input); !IsCode(err, CodeFieldLimit) {
			t.Fatalf("field precedence: %v", err)
		}
		// The book-bytes guard precedes any content analysis.
		garbage := make([]byte, MaxBookBytes+1)
		for index := range garbage {
			garbage[index] = 0xFF
		}
		if _, err := Verify(garbage); !IsCode(err, CodeBookLimit) {
			t.Fatalf("byte precedence: %v", err)
		}
	})
}

// spliceRecords builds a two-record document whose second record links to the
// chain of a different book: genesis, links and hashes are internally
// inconsistent in exactly one direction.
func spliceRecords(t *testing.T, firstBook, secondBook []byte, count int) []byte {
	t.Helper()
	second := recordElements(t, secondBook)[1]
	first := recordElements(t, firstBook)[0]
	document := `{"format":"` + BookFormat + `","version":"` + FormatVersion + `","records":[` + first + `,` + second + `]}`
	return []byte(document)
}

// recordElements splits a canonical book document into its raw record
// elements. The fixtures used with it never contain the separator sequence
// inside a string value.
func recordElements(t *testing.T, document []byte) []string {
	t.Helper()
	start := bytes.Index(document, []byte(`"records":[`))
	end := bytes.LastIndexByte(document, ']')
	if start < 0 || end < start {
		t.Fatal("malformed fixture document")
	}
	body := string(document[start+len(`"records":[`) : end])
	if body == "" {
		return nil
	}
	elements := bytes.Split([]byte(body), []byte("},{"))
	for index := range elements {
		if index > 0 {
			elements[index] = append([]byte("{"), elements[index]...)
		}
		if index < len(elements)-1 {
			elements[index] = append(elements[index], '}')
		}
	}
	result := make([]string, len(elements))
	for index, element := range elements {
		result[index] = string(element)
	}
	return result
}

func TestCasefileErrorsDoNotLeakInput(t *testing.T) {
	markers := []string{"CHG-0001", "018f6d2a", "payments-api", "CVE-2026-1234", testFingerprint}
	inputs := []func() DecisionInput{
		func() DecisionInput { in := validInput(); in.Owner = "CHG-0001 owner"; in.Rationale = ""; return in },
		func() DecisionInput { in := validInput(); in.Scope.SubjectUID = ""; return in },
		func() DecisionInput { in := validInput(); in.DecidedAt = "payments-api"; return in },
		func() DecisionInput { in := validInput(); in.Scope.BundleHash = "CHG-0001"; return in },
		func() DecisionInput {
			in := validInput()
			in.Controls = []string{"CVE-2026-1234 control"}
			in.Controls[0] = strings.Repeat("x", MaxControlBytes+1)
			return in
		},
	}
	for index, build := range inputs {
		_, err := Append(NewBook(), build())
		if err == nil {
			t.Fatalf("case %d was admitted", index)
		}
		for _, marker := range markers {
			if strings.Contains(err.Error(), marker) {
				t.Fatalf("case %d leaked %q: %q", index, marker, err.Error())
			}
		}
	}
	book := mustAppend(t, NewBook(), validInput())
	if err := Write(book, failingWriter{Err: errDestination}); !IsCode(err, CodeWriteFailed) {
		t.Fatalf("write failure: %v", err)
	}
	if wrapped := Write(book, failingWriter{Err: errDestination}); errors.Is(wrapped, errDestination) {
		t.Fatal("the writer error leaked into the diagnostic")
	}
}
