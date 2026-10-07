package ingest

import (
	"errors"
	"io"
	"strings"
	"testing"

	contract "github.com/d4rpell/Ariadne/pkg/evidence"
)

// AX-03 — hostile-input tests for the prisma-v1 parser (T1–T3).
//
// Every offset, reason and counter asserted here is a literal derived by hand
// from the input bytes (ADR-0007/ADR-0008), never read back from a production
// constant: a mutation that moves the boundary must fail these tests.
//
// The formula-injection payloads are *valid data* and are covered as inert text
// by TestA108ParserInertValues (internal/ingest/a1_08_contract_test.go); they are
// not re-tested here beyond the one positive control in TestAX03FormulaStaysInert
// and the presentation anchors in internal/report.

// ax03RowWithRaw rewrites one column of the full 15-column row without quoting,
// so the injected bytes stay exactly the ones under test.
func ax03RowWithRaw(field int, value string) string {
	parts := strings.Split(a108FullRow, ",")
	parts[field] = value
	return strings.Join(parts, ",")
}

// ax03RowWith rewrites one column of the full row and quotes it, so a value that
// would otherwise delimit fields travels intact.
func ax03RowWith(field int, value string) string {
	parts := strings.Split(a108FullRow, ",")
	parts[field] = `"` + strings.ReplaceAll(value, `"`, `""`) + `"`
	return strings.Join(parts, ",")
}

// requireAX03Abort asserts the whole abort classification of a structural
// failure: offset, reason, accounting and completeness.
func requireAX03Abort(t *testing.T, result Result, err error, offset uint64, reason Reason) {
	t.Helper()
	fileErr := requireFileError(t, err, reason)
	if fileErr.Offset != offset {
		t.Fatalf("offset = %d, want the literal %d", fileErr.Offset, offset)
	}
	requireA108Accounting(t, result, contract.TerminationAborted, contract.CompletenessUnknown, false, 0, 0, 0)
}

// requireAX03Rejection asserts one delimited rejection with its exact reason and
// the finished/partial accounting, and returns the rejection.
func requireAX03Rejection(t *testing.T, result Result, err error, reason Reason, accepted, rejected uint64) Rejection {
	t.Helper()
	if err != nil {
		t.Fatalf("a delimited rejection must not abort: %v", err)
	}
	completeness := contract.CompletenessPartial
	if rejected == 0 {
		completeness = contract.CompletenessComplete
	}
	requireA108Accounting(t, result, contract.TerminationFinished, completeness, true, accepted+rejected, accepted, rejected)
	if len(result.Rejections) == 0 {
		t.Fatal("expected a rejection, got none")
	}
	if got := result.Rejections[0].Reason; got != reason {
		t.Fatalf("reason = %q, want %q", got, reason)
	}
	return result.Rejections[0]
}

// TestAX03HeaderLimits (H1) pins that the field, record and field-count budgets
// apply to the header record, which is delimited by the same reader as any data
// record. The data-record cap does not apply to it.
func TestAX03HeaderLimits(t *testing.T) {
	t.Run("header field byte limit", func(t *testing.T) {
		// One quoted selector longer than the 65_536-byte field budget: the raw
		// field representation (outer quotes included) is what counts.
		header := `"` + strings.Repeat("a", 66_000) + `",vulnerability_id` + "\r\n"
		result, err := parse(t, header)
		requireAX03Abort(t, result, err, 65_536, ReasonFieldLimit)
	})

	t.Run("header record byte limit", func(t *testing.T) {
		// Thirty selectors whose raw bytes exceed the 262_144-byte record budget
		// while every individual field stays under its own budget.
		fields := make([]string, 0, 30)
		for i := 0; i < 29; i++ {
			fields = append(fields, strings.Repeat("a", 9_000))
		}
		fields = append(fields, strings.Repeat("b", 20_000))
		header := strings.Join(fields, ",") + "\r\n"
		if len(header) <= 262_144 {
			t.Fatalf("built a %d-byte header, want more than the record budget", len(header))
		}
		result, err := parse(t, header)
		requireAX03Abort(t, result, err, 262_144, ReasonRecordLimit)
	})

	t.Run("header field count limit", func(t *testing.T) {
		// Thirty-three selectors: the field-count budget is reached at the 32nd
		// field, and the reported offset is the comma that closes it.
		fields := make([]string, 33)
		for i := range fields {
			fields[i] = "x"
		}
		header := strings.Join(fields, ",") + "\r\n"
		const wantOffset = 63 // the 32nd comma in the literal header
		if header[wantOffset] != ',' {
			t.Fatalf("literal offset %d is %q, want the closing comma", wantOffset, header[wantOffset])
		}
		result, err := parse(t, header)
		requireAX03Abort(t, result, err, wantOffset, ReasonFieldCountLimit)
	})

	t.Run("a 32-field header is not a limit failure", func(t *testing.T) {
		// The same shape one field short reaches the selector check instead of the
		// count budget: the limit is the count itself, not "many fields".
		fields := make([]string, 32)
		for i := range fields {
			fields[i] = "x"
		}
		result, err := parse(t, strings.Join(fields, ",")+"\r\n")
		requireAX03Abort(t, result, err, 0, ReasonUnknownSelector)
	})
}

// TestAX03HostileEncodings (H2) covers the byte encodings a hostile source can
// carry: a UTF-16 BOM, a leading NUL, overlong NUL, a CESU-8 surrogate, a lone
// continuation byte, truncated multibyte sequences and an incomplete BOM. Each
// is classified exactly, and a valid 4-byte rune is the positive control.
func TestAX03HostileEncodings(t *testing.T) {
	aborts := []struct {
		name   string
		input  string
		offset uint64
		reason Reason
	}{
		{"utf16 bom", "\xff\xfe" + a108FullHeader + "\r\n", 0, ReasonInvalidUTF8},
		{"leading nul", "\x00" + a108FullHeader + "\r\n", 0, ReasonNUL},
		{"incomplete bom", "\xef\xbb", 0, ReasonInvalidUTF8},
	}
	for _, tc := range aborts {
		t.Run(tc.name, func(t *testing.T) {
			result, err := parse(t, tc.input)
			requireAX03Abort(t, result, err, tc.offset, tc.reason)
		})
	}

	// A row with as many fields as the header (15), so the text filter runs and
	// is not shadowed by the field-count classification.
	rejections := []struct {
		name   string
		value  string
		reason Reason
	}{
		{"overlong nul", "\xc0\x80", ReasonInvalidUTF8},
		{"cesu8 surrogate", "\xed\xa0\x80", ReasonInvalidUTF8},
		{"lone continuation", "a\x80b", ReasonInvalidUTF8},
		{"truncated two byte", "abc\xc3", ReasonInvalidUTF8},
		{"truncated three byte", "abc\xe2", ReasonInvalidUTF8},
		{"raw high byte", "abc\xff", ReasonInvalidUTF8},
		{"bidi override", "a\u202Eb", ReasonForbiddenText},
		{"zero width no-break space", "a\ufeffb", ReasonForbiddenText},
	}
	for _, tc := range rejections {
		t.Run(tc.name, func(t *testing.T) {
			row := ax03RowWithRaw(12, tc.value)
			result, err := parse(t, a108FullHeader+"\r\n"+row+"\r\n")
			rejection := requireAX03Rejection(t, result, err, tc.reason, 0, 1)
			// The locator still points at the rejected record: the interval is the
			// CSV syntax of the record, computed from the literal bytes.
			want := a108Locator(a108FullHeader, row, "\r\n")
			if rejection.Locator != want {
				t.Fatalf("locator = %+v, want %+v", rejection.Locator, want)
			}
		})
	}

	t.Run("truncated sequence at the real end of the stream", func(t *testing.T) {
		// The last column carries the incomplete sequence and the record has no
		// terminator, so the undecodable byte is the last byte of the file. The
		// text filter runs before the date validation of that column, so the
		// classification is the encoding, not the date.
		row := ax03RowWithRaw(14, "abc\xe2")
		input := a108FullHeader + "\r\n" + row
		result, err := parse(t, input)
		rejection := requireAX03Rejection(t, result, err, ReasonInvalidUTF8, 0, 1)
		// The helper's terminator argument is the header's own CRLF; the record
		// under test has no terminator of its own.
		want := a108Locator(a108FullHeader, row, "\r\n")
		if rejection.Locator != want {
			t.Fatalf("locator = %+v, want %+v", rejection.Locator, want)
		}
	})

	t.Run("valid four byte rune is accepted and preserved", func(t *testing.T) {
		const value = "e \U0001F600 f"
		row := ax03RowWith(12, value)
		result, err := parse(t, a108FullHeader+"\r\n"+row+"\r\n")
		if err != nil {
			t.Fatalf("unexpected abort: %v", err)
		}
		requireA108Accounting(t, result, contract.TerminationFinished, contract.CompletenessComplete, true, 1, 1, 0)
		if got := result.Findings[0].Description; got != value {
			t.Fatalf("description = %q, want the literal bytes %q", got, value)
		}
	})
}

// TestAX03HostileSelectors (H3) covers header selectors that are not a canonical
// column name: empty, whitespace-only, leading space, tab and a formula prefix.
// These travel through headerTextProblem/headerIndexes, not columnProblem.
func TestAX03HostileSelectors(t *testing.T) {
	cases := []struct {
		name   string
		header string
		offset uint64
		reason Reason
	}{
		{"empty selector", "schema_version,,package_name,installed_version,fix_status,image_registry,image_repository", 15, ReasonUnknownSelector},
		{"space only selector", "schema_version, ,package_name,installed_version,fix_status,image_registry,image_repository", 15, ReasonUnknownSelector},
		{"leading space selector", " schema_version,vulnerability_id,package_name,installed_version,fix_status,image_registry,image_repository", 0, ReasonUnknownSelector},
		{"tab selector", "schema_version,\tvulnerability_id,package_name,installed_version,fix_status,image_registry,image_repository", 15, ReasonForbiddenText},
		{"formula selector", "=schema_version,vulnerability_id,package_name,installed_version,fix_status,image_registry,image_repository", 0, ReasonUnknownSelector},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// The literal offset is a byte position in the header under test.
			if int(tc.offset) >= len(tc.header) {
				t.Fatalf("literal offset %d is past the %d-byte header", tc.offset, len(tc.header))
			}
			result, err := parse(t, tc.header+"\r\n")
			requireAX03Abort(t, result, err, tc.offset, tc.reason)
		})
	}
}

// TestAX03DuplicateColumns (H4) covers a duplicate column at the tail of the
// header and a duplicate optional column, which the existing header test does
// not exercise (it duplicates the first required column).
func TestAX03DuplicateColumns(t *testing.T) {
	cases := []struct {
		name   string
		header string
		offset uint64
	}{
		{"required duplicate after a short header", testHeader + ",schema_version", 106},
		{"required duplicate after the full header", a108FullHeader + ",schema_version", 196},
		{"optional duplicate at the tail", a108FullHeader + ",severity", 196},
		{"optional duplicate in place", "schema_version,vulnerability_id,package_name,installed_version,fix_status,image_registry,image_repository,severity,severity", 115},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// The literal offset is the start of the duplicated selector.
			if int(tc.offset) >= len(tc.header) {
				t.Fatalf("literal offset %d is past the %d-byte header", tc.offset, len(tc.header))
			}
			if tc.header[tc.offset] == ',' {
				t.Fatalf("literal offset %d points at a comma, want a selector start", tc.offset)
			}
			result, err := parse(t, tc.header+"\r\n")
			requireAX03Abort(t, result, err, tc.offset, ReasonDuplicateColumn)
		})
	}
}

// TestAX03NULInsideQuotedField (H5) pins that quoting does not exempt a field
// from the forbidden-text filter: a NUL between quotes is still a NUL.
func TestAX03NULInsideQuotedField(t *testing.T) {
	row := ax03RowWith(12, "a\x00b")
	result, err := parse(t, a108FullHeader+"\r\n"+row+"\r\n")
	requireAX03Rejection(t, result, err, ReasonNUL, 0, 1)
}

// ax03StallingReader serves its payload and then keeps returning (0, nil)
// forever. The rescue error bounds the suite, but the tests assert the exact
// call count themselves: a parser that spins on a non-progressing reader would
// hit the rescue error and still report a read failure, so only the count pins
// the defect.
type ax03StallingReader struct {
	data  []byte
	calls int
}

func (r *ax03StallingReader) Read(p []byte) (int, error) {
	r.calls++
	if r.calls > 64 {
		return 0, errors.New("ax03: reader called too many times without progress")
	}
	if len(r.data) == 0 {
		return 0, nil
	}
	n := copy(p, r.data)
	r.data = r.data[n:]
	return n, nil
}

// TestAX03NoProgressReader (H6) pins that a reader returning (0, nil) is a read
// failure, never a clean end of stream and never a spin.
func TestAX03NoProgressReader(t *testing.T) {
	t.Run("stall from the first byte", func(t *testing.T) {
		reader := &ax03StallingReader{}
		result, err := ParsePrismaV1(reader)
		requireFileError(t, err, ReasonReadFailure)
		// Exactly one call: the first non-progressing read fails the parser. A
		// spinning parser reaches the rescue error and would report the same
		// reason with the same (empty) accounting, so only the count catches it.
		if reader.calls != 1 {
			t.Fatalf("reader calls = %d, want 1", reader.calls)
		}
		requireA108Accounting(t, result, contract.TerminationAborted, contract.CompletenessUnknown, false, 0, 0, 0)
	})

	t.Run("stall after the header and one valid row", func(t *testing.T) {
		// The header plus a complete valid row fit in one read; the next read is
		// the first non-progressing one. The parser keeps the verified progress
		// and reports the read failure, instead of treating the stall as a clean
		// end of file.
		input := testHeader + "\r\n" + testRow + "\r\n"
		reader := &ax03StallingReader{data: []byte(input)}
		result, err := ParsePrismaV1(reader)
		requireFileError(t, err, ReasonReadFailure)
		if reader.calls != 2 {
			t.Fatalf("reader calls = %d, want 2 (one delivery, one non-progressing read)", reader.calls)
		}
		requireA108Accounting(t, result, contract.TerminationAborted, contract.CompletenessPartial, false, 0, 1, 0)
	})
}

// ax03ErrorAtLimitReader serves exactly limit bytes and then returns a non-EOF
// error instead of io.EOF, exercising the single-byte probe that distinguishes an
// exact-size file from an oversized one.
type ax03ErrorAtLimitReader struct {
	data []byte
	err  error
}

func (r *ax03ErrorAtLimitReader) Read(p []byte) (int, error) {
	if len(r.data) == 0 {
		return 0, r.err
	}
	n := copy(p, r.data)
	r.data = r.data[n:]
	return n, nil
}

// TestAX03ReadFailureAtFileLimitProbe (H7) pins that a reader failing exactly at
// the file-limit probe is a read failure, not a file-limit excess: the probe
// reads one byte to tell "exact size" from "one byte past", and a real error on
// that probe is an I/O failure.
func TestAX03ReadFailureAtFileLimitProbe(t *testing.T) {
	exact := buildBudgetFile(t, 67_108_864)
	reader := &ax03ErrorAtLimitReader{data: exact, err: errors.New("ax03: synthetic probe failure")}
	result, err := ParsePrismaV1(reader)
	fileErr := requireFileError(t, err, ReasonReadFailure)
	if fileErr.Offset != 67_108_864 {
		t.Fatalf("offset = %d, want the file budget 67108864", fileErr.Offset)
	}
	if result.Coverage.Termination != contract.TerminationAborted {
		t.Fatalf("termination = %q, want aborted", result.Coverage.Termination)
	}
	if result.Coverage.Rows.Total != nil {
		t.Fatalf("a failed read must not invent a total: %d", *result.Coverage.Rows.Total)
	}
}

// TestAX03UnknownReasonFallsBackToAllowlist (H8, vocabulary level) pins that a
// Reason value outside the allowlist is reported as the fixed `invalid input`
// literal in both the rejection and the file error. This is the assertion that
// catches a mutation of the Reason.message default; it is deliberately
// independent of any parser input, because a parser never produces a
// non-allowlisted Reason from CSV bytes.
func TestAX03UnknownReasonFallsBackToAllowlist(t *testing.T) {
	const canary = "SYNTHETIC-CANARY"
	unknown := Reason(canary)

	locator := Locator{Record: 1, StartByte: 0, EndByte: 1}
	rejection := Rejection{Locator: locator, Reason: unknown}
	const wantRejection = "ingest: prisma-v1: record/1/bytes/0-1: invalid input"
	if got := rejection.String(); got != wantRejection {
		t.Fatalf("rejection = %q, want %q", got, wantRejection)
	}
	if strings.Contains(rejection.String(), canary) {
		t.Fatalf("rejection leaked the unknown reason: %q", rejection.String())
	}

	fileErr := &FileError{Offset: 3, Reason: unknown}
	const wantFileError = "ingest: prisma-v1: byte/3: invalid input"
	if got := fileErr.Error(); got != wantFileError {
		t.Fatalf("file error = %q, want %q", got, wantFileError)
	}
	if strings.Contains(fileErr.Error(), canary) {
		t.Fatalf("file error leaked the unknown reason: %q", fileErr.Error())
	}
}

// TestAX03RequiredValueSurroundings (H8 support, M10 target) pins the required
// value rule on a data row: empty, only whitespace and a leading/trailing
// Unicode space are all rejected, while an interior space is preserved. It runs
// columnProblem, which the header selector tests do not reach.
func TestAX03RequiredValueSurroundings(t *testing.T) {
	rejected := []struct {
		name  string
		value string
	}{
		{"empty", ""},
		{"single space", " "},
		{"leading ascii space", " pkg"},
		{"trailing ascii space", "pkg "},
		{"leading nbsp", "\u00a0pkg"},
		{"trailing nbsp", "pkg\u00a0"},
	}
	for _, tc := range rejected {
		t.Run(tc.name, func(t *testing.T) {
			row := ax03RowWith(2, tc.value)
			result, err := parse(t, a108FullHeader+"\r\n"+row+"\r\n")
			requireAX03Rejection(t, result, err, ReasonRequiredValue, 0, 1)
		})
	}

	t.Run("interior nbsp is preserved", func(t *testing.T) {
		const value = "p\u00a0kg"
		row := ax03RowWith(2, value)
		result, err := parse(t, a108FullHeader+"\r\n"+row+"\r\n")
		if err != nil {
			t.Fatalf("unexpected abort: %v", err)
		}
		requireA108Accounting(t, result, contract.TerminationFinished, contract.CompletenessComplete, true, 1, 1, 0)
		if got := result.Findings[0].PackageName; got != value {
			t.Fatalf("package name = %q, want %q", got, value)
		}
	})
}

// TestAX03FormulaStaysInert (H0) is the single positive control of the formula
// class in this file: a formula prefix in an identity column is valid data and
// is preserved byte for byte, never escaped or rejected during ingestion. The
// full inert-text coverage lives in TestA108ParserInertValues.
func TestAX03FormulaStaysInert(t *testing.T) {
	const payload = "=1+1"
	row := ax03RowWithRaw(6, payload) // image_repository
	result, err := parse(t, a108FullHeader+"\r\n"+row+"\r\n")
	if err != nil {
		t.Fatalf("unexpected abort: %v", err)
	}
	requireA108Accounting(t, result, contract.TerminationFinished, contract.CompletenessComplete, true, 1, 1, 0)
	if got := result.Findings[0].ImageRepository; got != payload {
		t.Fatalf("image repository = %q, want the literal payload %q", got, payload)
	}
}

// ax03LeakReader wraps a payload in a reader and, when read, returns a raw error
// whose text carries a private marker, to check that no raw cause reaches the
// public error.
type ax03LeakReader struct {
	prefix []byte
	err    error
}

func (r *ax03LeakReader) Read(p []byte) (int, error) {
	if len(r.prefix) == 0 {
		return 0, r.err
	}
	n := copy(p, r.prefix)
	r.prefix = r.prefix[n:]
	return n, nil
}

// TestAX03DiagnosticsNeverCarryInputBytes (H8, parser level) embeds a distinct
// canary per hostile class and asserts the *serialized* diagnostic for each one:
// the exact locator and the allowlisted literal, and never a byte of the input.
// Row rejections and structural aborts are both covered.
func TestAX03DiagnosticsNeverCarryInputBytes(t *testing.T) {
	const marker = "AX03PRIVATECANARY"

	assertClean := func(t *testing.T, got, want string) {
		t.Helper()
		if got != want {
			t.Fatalf("diagnostic = %q, want %q", got, want)
		}
		if strings.Contains(got, marker) {
			t.Fatalf("diagnostic leaked input data: %s", got)
		}
	}

	t.Run("row rejection for a forbidden byte", func(t *testing.T) {
		// A NUL inside a quoted field: the record is rejected, not aborted.
		row := ax03RowWith(12, marker+"\x00tail")
		result, err := parse(t, a108FullHeader+"\r\n"+row+"\r\n")
		rejection := requireAX03Rejection(t, result, err, ReasonNUL, 0, 1)
		want := "ingest: prisma-v1: " + a108Locator(a108FullHeader, row, "\r\n").String() + ": NUL is not allowed"
		assertClean(t, rejection.String(), want)
	})

	t.Run("row rejection for invalid utf8", func(t *testing.T) {
		row := ax03RowWithRaw(12, "x\xff"+marker)
		result, err := parse(t, a108FullHeader+"\r\n"+row+"\r\n")
		rejection := requireAX03Rejection(t, result, err, ReasonInvalidUTF8, 0, 1)
		want := "ingest: prisma-v1: " + a108Locator(a108FullHeader, row, "\r\n").String() + ": invalid UTF-8"
		assertClean(t, rejection.String(), want)
	})

	t.Run("row rejection for the field budget", func(t *testing.T) {
		// The oversized field carries the canary; the rejection names the record
		// interval and the budget, never a fragment of the field.
		row := ax03RowWith(12, strings.Repeat("a", 65_600)+marker)
		result, err := parse(t, a108FullHeader+"\r\n"+row+"\r\n")
		rejection := requireAX03Rejection(t, result, err, ReasonFieldLimit, 0, 1)
		want := "ingest: prisma-v1: " + a108Locator(a108FullHeader, row, "\r\n").String() + ": field byte limit exceeded"
		assertClean(t, rejection.String(), want)
	})

	t.Run("header abort for a duplicate column", func(t *testing.T) {
		// The canary travels in the data row while the header carries the defect:
		// the abort names the duplicated selector offset and nothing else.
		header := testHeader + ",vulnerability_id"
		row := testRow[:len(testRow)-len("synthetic/repository")] + marker
		result, err := parse(t, header+"\r\n"+row+"\r\n")
		fileErr := requireFileError(t, err, ReasonDuplicateColumn)
		if fileErr.Offset != 106 {
			t.Fatalf("offset = %d, want the literal 106", fileErr.Offset)
		}
		assertClean(t, fileErr.Error(), "ingest: prisma-v1: byte/106: duplicate column")
		requireA108Accounting(t, result, contract.TerminationAborted, contract.CompletenessUnknown, false, 0, 0, 0)
	})

	t.Run("abort for the record budget", func(t *testing.T) {
		// A row past the record budget with the canary inside the oversized field:
		// the abort reports the stream offset 262144 plus the 107-byte header line.
		row := strings.Repeat("a", 262_200) + marker
		result, err := parse(t, testHeader+"\r\n"+row+"\r\n")
		fileErr := requireFileError(t, err, ReasonRecordLimit)
		if fileErr.Offset != 262_144+107 {
			t.Fatalf("offset = %d, want the literal 262251", fileErr.Offset)
		}
		assertClean(t, fileErr.Error(), "ingest: prisma-v1: byte/262251: record byte limit exceeded")
		requireA108Accounting(t, result, contract.TerminationAborted, contract.CompletenessUnknown, false, 0, 0, 0)
	})

	t.Run("header abort for an unknown selector", func(t *testing.T) {
		// An unknown selector whose text carries the marker: the abort names the
		// offset and the reason, never the selector text.
		header := "schema_version," + marker + "_selector,package_name,installed_version,fix_status,image_registry,image_repository"
		result, err := parse(t, header+"\r\n")
		fileErr := requireFileError(t, err, ReasonUnknownSelector)
		if fileErr.Offset != 15 {
			t.Fatalf("offset = %d, want the literal 15", fileErr.Offset)
		}
		assertClean(t, fileErr.Error(), "ingest: prisma-v1: byte/15: unknown selector")
		requireA108Accounting(t, result, contract.TerminationAborted, contract.CompletenessUnknown, false, 0, 0, 0)
	})

	t.Run("raw read cause carries no bytes", func(t *testing.T) {
		reader := &ax03LeakReader{
			prefix: []byte(testHeader + "\r\n" + testRow + "\r\n"),
			err:    errors.New(marker + " raw reader failure"),
		}
		result, err := ParsePrismaV1(reader)
		fileErr := requireFileError(t, err, ReasonReadFailure)
		assertClean(t, fileErr.Error(), "ingest: prisma-v1: byte/193: input read failed")
		requireA108Accounting(t, result, contract.TerminationAborted, contract.CompletenessPartial, false, 0, 1, 0)
	})
}

var _ io.Reader = &ax03StallingReader{}
var _ io.Reader = &ax03ErrorAtLimitReader{}
var _ io.Reader = &ax03LeakReader{}
