package ingest

import (
	"errors"
	"io"
	"strings"
	"testing"

	contract "github.com/d4rpell/Ariadne/pkg/evidence"
)

// a108FullHeader and a108FullRow exercise every canonical column in order.
const (
	a108FullHeader = "schema_version,vulnerability_id,package_name,installed_version,fix_status,image_registry,image_repository,image_tag,package_type,package_id,path,severity,description,published_date,discovery_date"
	a108FullRow    = "1.0,CVE-2026-1234,synthetic-package,1.2.3,open,registry.example,synthetic/repository,release,os,package-id-1,/usr/bin/synthetic,high,synthetic description,2026-09-25,2026-09-26"
	a108BadVersion = "2.0,CVE-2026-1234,synthetic-package,1.2.3,open,registry.example,synthetic/repository"
)

func a108Uint64Ptr(value uint64) *uint64 { return &value }

// a108RowWith rewrites one column of the full row and quotes the new value so
// the test can inject bytes that would otherwise delimit fields.
func a108RowWith(field int, value string) string {
	parts := strings.Split(a108FullRow, ",")
	parts[field] = `"` + strings.ReplaceAll(value, `"`, `""`) + `"`
	return strings.Join(parts, ",")
}

// a108RowWithRaw rewrites one column of the full row without quoting it.
func a108RowWithRaw(field int, value string) string {
	parts := strings.Split(a108FullRow, ",")
	parts[field] = value
	return strings.Join(parts, ",")
}

// requireA108Accounting asserts each accounting field of a Result.
func requireA108Accounting(t *testing.T, result Result, termination contract.CoverageTermination, completeness contract.Completeness, totalKnown bool, total, accepted, rejected uint64) {
	t.Helper()
	if result.Coverage.Method != contract.CoverageFindingsImport {
		t.Fatalf("coverage method = %q, want %q", result.Coverage.Method, contract.CoverageFindingsImport)
	}
	if result.Coverage.Termination != termination {
		t.Fatalf("termination = %q, want %q", result.Coverage.Termination, termination)
	}
	if result.Completeness != completeness {
		t.Fatalf("completeness = %q, want %q", result.Completeness, completeness)
	}
	rows := result.Coverage.Rows
	if rows == nil {
		t.Fatal("coverage rows must not be nil")
	}
	switch {
	case totalKnown && rows.Total == nil:
		t.Fatal("expected a known total, got nil")
	case !totalKnown && rows.Total != nil:
		t.Fatalf("expected an unknown total, got %d", *rows.Total)
	case totalKnown && *rows.Total != total:
		t.Fatalf("total = %d, want %d", *rows.Total, total)
	}
	if rows.Accepted != accepted || rows.Rejected != rejected {
		t.Fatalf("counters = accepted %d, rejected %d; want %d/%d", rows.Accepted, rows.Rejected, accepted, rejected)
	}
	if uint64(len(result.Findings)) != accepted || uint64(len(result.Rejections)) != rejected {
		t.Fatalf("slices = %d findings, %d rejections; want %d/%d", len(result.Findings), len(result.Rejections), accepted, rejected)
	}
}

// a108Locator computes the expected locator of the first data record, from the
// literal byte lengths of the test inputs.
func a108Locator(header, record, terminator string) Locator {
	start := uint64(len(header) + len(terminator))
	return Locator{Record: 1, StartByte: start, EndByte: start + uint64(len(record))}
}

// a108ResultsEqual compares two parse results structurally, including coverage
// counters, completeness and every finding and rejection.
func a108ResultsEqual(a, b Result) bool {
	if len(a.Header) != len(b.Header) || len(a.Findings) != len(b.Findings) || len(a.Rejections) != len(b.Rejections) {
		return false
	}
	for i := range a.Header {
		if a.Header[i] != b.Header[i] {
			return false
		}
	}
	for i := range a.Findings {
		if a.Findings[i] != b.Findings[i] {
			return false
		}
	}
	for i := range a.Rejections {
		if a.Rejections[i] != b.Rejections[i] {
			return false
		}
	}
	if a.Completeness != b.Completeness || a.Coverage.Termination != b.Coverage.Termination ||
		a.Coverage.Method != b.Coverage.Method || a.Coverage.Rows == nil || b.Coverage.Rows == nil {
		return false
	}
	ar, br := a.Coverage.Rows, b.Coverage.Rows
	if ar.Accepted != br.Accepted || ar.Rejected != br.Rejected {
		return false
	}
	switch {
	case ar.Total == nil && br.Total != nil, ar.Total != nil && br.Total == nil:
		return false
	case ar.Total != nil && *ar.Total != *br.Total:
		return false
	}
	return true
}

func TestA108ParserHeaders(t *testing.T) {
	valid := []struct {
		name   string
		header string
		row    string
	}{
		{"minimal required columns", testHeader, testRow},
		{"all canonical columns", a108FullHeader, a108FullRow},
		{
			"optional subsequence",
			"schema_version,vulnerability_id,package_name,installed_version,fix_status,image_registry,image_repository,package_type,description",
			"1.0,CVE-2026-1234,synthetic-package,1.2.3,open,registry.example,synthetic/repository,os,synthetic description",
		},
	}
	for _, tc := range valid {
		t.Run(tc.name, func(t *testing.T) {
			result, err := parse(t, tc.header+"\r\n"+tc.row+"\r\n")
			if err != nil {
				t.Fatalf("unexpected abort: %v", err)
			}
			requireA108Accounting(t, result, contract.TerminationFinished, contract.CompletenessComplete, true, 1, 1, 0)
			want := strings.Split(tc.header, ",")
			if len(result.Header) != len(want) {
				t.Fatalf("header = %v, want %v", result.Header, want)
			}
			for i := range want {
				if result.Header[i] != want[i] {
					t.Fatalf("header[%d] = %q, want %q", i, result.Header[i], want[i])
				}
			}
		})
	}

	invalid := []struct {
		name       string
		header     string
		reason     Reason
		wantOffset int // -1 skips the offset assertion
	}{
		{"duplicate column", testHeader + ",package_name", ReasonDuplicateColumn, len(testHeader) + 1},
		{"unknown selector", testHeader + ",normalized_digest", ReasonUnknownSelector, len(testHeader) + 1},
		{"alias", testHeader + ",CVE", ReasonUnknownSelector, len(testHeader) + 1},
		{"case change", "Schema_version,vulnerability_id,package_name,installed_version,fix_status,image_registry,image_repository", ReasonUnknownSelector, 0},
		{"reordered", "vulnerability_id,schema_version,package_name,installed_version,fix_status,image_registry,image_repository", ReasonInvalidHeader, len("vulnerability_id") + 1},
		{"missing required", "schema_version,vulnerability_id,package_name,installed_version,fix_status,image_registry", ReasonMissingRequiredColumn, -1},
		{"trailing comma", testHeader + ",", ReasonUnknownSelector, len(testHeader) + 1},
	}
	for _, tc := range invalid {
		t.Run(tc.name, func(t *testing.T) {
			input := tc.header + "\r\n" + a108FullRow + "\r\n"
			result, err := parse(t, input)
			fileErr := requireFileError(t, err, tc.reason)
			if tc.wantOffset >= 0 && fileErr.Offset != uint64(tc.wantOffset) {
				t.Fatalf("offset = %d, want %d", fileErr.Offset, tc.wantOffset)
			}
			requireA108Accounting(t, result, contract.TerminationAborted, contract.CompletenessUnknown, false, 0, 0, 0)
			if len(result.Findings) != 0 {
				t.Fatalf("rows accepted after an invalid header: %+v", result.Findings)
			}
		})
	}

	t.Run("bom", func(t *testing.T) {
		input := "\xEF\xBB\xBF" + testHeader + "\r\n" + testRow + "\r\n"
		result, err := parse(t, input)
		fileErr := requireFileError(t, err, ReasonBOM)
		if fileErr.Offset != 0 {
			t.Fatalf("offset = %d, want 0", fileErr.Offset)
		}
		requireA108Accounting(t, result, contract.TerminationAborted, contract.CompletenessUnknown, false, 0, 0, 0)
	})

	t.Run("zero bytes", func(t *testing.T) {
		result, err := parse(t, "")
		requireFileError(t, err, ReasonInvalidHeader)
		requireA108Accounting(t, result, contract.TerminationAborted, contract.CompletenessUnknown, false, 0, 0, 0)
	})
}

func TestA108ParserText(t *testing.T) {
	headerText := []struct {
		name   string
		header string
		reason Reason
		needle string
	}{
		{"nul", "schema\x00_version," + strings.TrimPrefix(testHeader, "schema_version,"), ReasonNUL, "\x00"},
		{"invalid utf8", "schema\xff_version," + strings.TrimPrefix(testHeader, "schema_version,"), ReasonInvalidUTF8, "\xff"},
		{"tab", "schema\tversion," + strings.TrimPrefix(testHeader, "schema_version,"), ReasonForbiddenText, "\t"},
		{"del", "schema\x7fversion," + strings.TrimPrefix(testHeader, "schema_version,"), ReasonForbiddenText, "\x7f"},
		{"c1 control", "schema\u0085version," + strings.TrimPrefix(testHeader, "schema_version,"), ReasonForbiddenText, "\u0085"},
		{"format character", "schema\u200bversion," + strings.TrimPrefix(testHeader, "schema_version,"), ReasonForbiddenText, "\u200b"},
	}
	for _, tc := range headerText {
		t.Run("header "+tc.name, func(t *testing.T) {
			input := tc.header + "\r\n" + a108FullRow + "\r\n"
			result, err := parse(t, input)
			fileErr := requireFileError(t, err, tc.reason)
			want := uint64(strings.Index(tc.header, tc.needle))
			if fileErr.Offset != want {
				t.Fatalf("offset = %d, want the first offending byte at %d", fileErr.Offset, want)
			}
			requireA108Accounting(t, result, contract.TerminationAborted, contract.CompletenessUnknown, false, 0, 0, 0)
		})
	}

	recordText := []struct {
		name   string
		field  int
		value  string
		reason Reason
	}{
		{"nul in description", 12, "bad\x00text", ReasonNUL},
		{"invalid utf8 in path", 10, "bad\xfftext", ReasonInvalidUTF8},
		{"tab in severity", 11, "high\t", ReasonForbiddenText},
		{"del in package type", 8, "o\x7fs", ReasonForbiddenText},
		{"c1 control in description", 12, "description\u0085end", ReasonForbiddenText},
		{"format character in path", 10, "/usr/\u200bbin", ReasonForbiddenText},
	}
	for _, tc := range recordText {
		t.Run(tc.name, func(t *testing.T) {
			row := a108RowWith(tc.field, tc.value)
			result, err := parse(t, a108FullHeader+"\r\n"+row+"\r\n")
			if err != nil {
				t.Fatalf("unexpected abort: %v", err)
			}
			requireA108Accounting(t, result, contract.TerminationFinished, contract.CompletenessPartial, true, 1, 0, 1)
			rejection := result.Rejections[0]
			if rejection.Reason != tc.reason {
				t.Fatalf("reason = %q, want %q", rejection.Reason, tc.reason)
			}
			want := a108Locator(a108FullHeader, row, "\r\n")
			if rejection.Locator != want {
				t.Fatalf("locator = %+v, want %+v", rejection.Locator, want)
			}
		})
	}

	t.Run("valid unicode text is preserved", func(t *testing.T) {
		value := "café ñ 漢字 καθ"
		row := a108RowWith(12, value)
		result, err := parse(t, a108FullHeader+"\r\n"+row+"\r\n")
		if err != nil {
			t.Fatalf("unexpected abort: %v", err)
		}
		requireA108Accounting(t, result, contract.TerminationFinished, contract.CompletenessComplete, true, 1, 1, 0)
		if got := result.Findings[0].Description; got != value {
			t.Fatalf("description = %q, want %q", got, value)
		}
	})

	t.Run("quoted cr and lf are preserved", func(t *testing.T) {
		value := "line one\r\nline two\nline three"
		row := a108RowWith(12, value)
		result, err := parse(t, a108FullHeader+"\r\n"+row+"\r\n")
		if err != nil {
			t.Fatalf("unexpected abort: %v", err)
		}
		requireA108Accounting(t, result, contract.TerminationFinished, contract.CompletenessComplete, true, 1, 1, 0)
		if got := result.Findings[0].Description; got != value {
			t.Fatalf("description = %q, want %q", got, value)
		}
	})

	t.Run("optional surrounding spaces are preserved", func(t *testing.T) {
		header := testHeader + ",path,severity"
		row := testRow + `," /usr/bin/tool "," high "`
		result, err := parse(t, header+"\r\n"+row+"\r\n")
		if err != nil {
			t.Fatalf("unexpected abort: %v", err)
		}
		requireA108Accounting(t, result, contract.TerminationFinished, contract.CompletenessComplete, true, 1, 1, 0)
		finding := result.Findings[0]
		if finding.Path != " /usr/bin/tool " || finding.Severity != " high " {
			t.Fatalf("optional spaces were altered: path %q severity %q", finding.Path, finding.Severity)
		}
	})
}

func TestA108ParserStructure(t *testing.T) {
	aborts := []struct {
		name  string
		first string
		bad   string
	}{
		{"unclosed quote at eof", testRow, `1.0,CVE-2026-1234,"synthetic-package`},
		{"quote inside unquoted field", testRow, `1.0,CVE-2026-1234,syn"thetic,1.2.3,open,registry.example,synthetic/repository`},
		{"content after closing quote", testRow, `1.0,CVE-2026-1234,"synthetic"package,1.2.3,open,registry.example,synthetic/repository`},
		{"lone cr after closing quote", testRow, "1.0,CVE-2026-1234,\"synthetic\"\rx,1.2.3,open,registry.example,synthetic/repository"},
	}
	for _, tc := range aborts {
		t.Run(tc.name, func(t *testing.T) {
			input := testHeader + "\r\n" + tc.first + "\r\n" + tc.bad + "\r\n"
			result, err := parse(t, input)
			requireFileError(t, err, ReasonInvalidCSV)
			requireA108Accounting(t, result, contract.TerminationAborted, contract.CompletenessPartial, false, 0, 1, 0)
		})
	}

	t.Run("structural abort without progress", func(t *testing.T) {
		input := testHeader + "\r\n" + `"unclosed`
		result, err := parse(t, input)
		fileErr := requireFileError(t, err, ReasonInvalidCSV)
		if fileErr.Offset != uint64(len(input)) {
			t.Fatalf("offset = %d, want the stream end %d", fileErr.Offset, len(input))
		}
		requireA108Accounting(t, result, contract.TerminationAborted, contract.CompletenessUnknown, false, 0, 0, 0)
	})

	const sixFieldsRow = "1.0,CVE-2026-1234,synthetic-package,1.2.3,open,registry.example"
	recoverable := []struct {
		name string
		row  string
		want Locator
	}{
		{"six fields", sixFieldsRow, a108Locator(testHeader, sixFieldsRow, "\r\n")},
		{"eight fields", testRow + ",extra", a108Locator(testHeader, testRow+",extra", "\r\n")},
		{"empty line", "", a108Locator(testHeader, "", "\r\n")},
	}
	for _, tc := range recoverable {
		t.Run(tc.name, func(t *testing.T) {
			result, err := parse(t, testHeader+"\r\n"+tc.row+"\r\n")
			if err != nil {
				t.Fatalf("a delimited rejection must not abort: %v", err)
			}
			requireA108Accounting(t, result, contract.TerminationFinished, contract.CompletenessPartial, true, 1, 0, 1)
			rejection := result.Rejections[0]
			if rejection.Reason != ReasonFieldCount {
				t.Fatalf("reason = %q, want %q", rejection.Reason, ReasonFieldCount)
			}
			if rejection.Locator != tc.want {
				t.Fatalf("locator = %+v, want %+v", rejection.Locator, tc.want)
			}
		})
	}
}

func TestA108ParserLexicalValues(t *testing.T) {
	cases := []struct {
		name   string
		header string
		row    string
		reason Reason // empty means accepted
	}{
		{"version leading zero", testHeader, "01.0,CVE-2026-1234,synthetic-package,1.2.3,open,registry.example,synthetic/repository", ReasonInvalidVersion},
		{"version zero minor digits", testHeader, "1.00,CVE-2026-1234,synthetic-package,1.2.3,open,registry.example,synthetic/repository", ReasonInvalidVersion},
		{"version three parts", testHeader, "1.0.0,CVE-2026-1234,synthetic-package,1.2.3,open,registry.example,synthetic/repository", ReasonInvalidVersion},
		{"version unsupported minor", testHeader, "1.1,CVE-2026-1234,synthetic-package,1.2.3,open,registry.example,synthetic/repository", ReasonUnsupportedVersion},
		{"version unsupported major", testHeader, "2.0,CVE-2026-1234,synthetic-package,1.2.3,open,registry.example,synthetic/repository", ReasonUnsupportedVersion},
		{"version leading space", testHeader, " 1.0,CVE-2026-1234,synthetic-package,1.2.3,open,registry.example,synthetic/repository", ReasonRequiredValue},
		{"version trailing space", testHeader, "1.0 ,CVE-2026-1234,synthetic-package,1.2.3,open,registry.example,synthetic/repository", ReasonRequiredValue},
		{"cve empty sequence", testHeader, "1.0,CVE-2026-123,synthetic-package,1.2.3,open,registry.example,synthetic/repository", ReasonInvalidCVE},
		{"cve lowercase", testHeader, "1.0,cve-2026-1234,synthetic-package,1.2.3,open,registry.example,synthetic/repository", ReasonInvalidCVE},
		{"cve missing prefix", testHeader, "1.0,2026-1234,synthetic-package,1.2.3,open,registry.example,synthetic/repository", ReasonInvalidCVE},
		{"cve lexical zeros", testHeader, "1.0,CVE-0000-0000,synthetic-package,1.2.3,open,registry.example,synthetic/repository", ""},
		{"installed version surrounded", testHeader, "1.0,CVE-2026-1234,synthetic-package, 1.2.3,open,registry.example,synthetic/repository", ReasonRequiredValue},
		{"installed version trailing", testHeader, "1.0,CVE-2026-1234,synthetic-package,1.2.3 ,open,registry.example,synthetic/repository", ReasonRequiredValue},
		{"fix status empty", testHeader, "1.0,CVE-2026-1234,synthetic-package,1.2.3,,registry.example,synthetic/repository", ReasonRequiredValue},
		{"registry surrounded", testHeader, "1.0,CVE-2026-1234,synthetic-package,1.2.3,open, registry.example,synthetic/repository", ReasonRequiredValue},
		{"repository surrounded", testHeader, "1.0,CVE-2026-1234,synthetic-package,1.2.3,open,registry.example, synthetic/repository ", ReasonRequiredValue},
		{"date year zero", testHeader + ",published_date", testRow + ",0000-01-01", ReasonInvalidDate},
		{"date not a leap year", testHeader + ",published_date", testRow + ",2023-02-29", ReasonInvalidDate},
		{"date leap year", testHeader + ",published_date", testRow + ",2024-02-29", ""},
		{"date short month", testHeader + ",published_date", testRow + ",2026-9-01", ReasonInvalidDate},
		{"date with surrounding space", testHeader + ",published_date", testRow + `,"2026-09-25 "`, ReasonInvalidDate},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			result, err := parse(t, tc.header+"\r\n"+tc.row+"\r\n")
			if err != nil {
				t.Fatalf("unexpected abort: %v", err)
			}
			if tc.reason == "" {
				requireA108Accounting(t, result, contract.TerminationFinished, contract.CompletenessComplete, true, 1, 1, 0)
				return
			}
			requireA108Accounting(t, result, contract.TerminationFinished, contract.CompletenessPartial, true, 1, 0, 1)
			if got := result.Rejections[0].Reason; got != tc.reason {
				t.Fatalf("reason = %q, want %q", got, tc.reason)
			}
		})
	}

	t.Run("optional values are never trimmed", func(t *testing.T) {
		value := "  synthetic description with edges  "
		row := a108RowWith(12, value)
		result, err := parse(t, a108FullHeader+"\r\n"+row+"\r\n")
		if err != nil {
			t.Fatalf("unexpected abort: %v", err)
		}
		requireA108Accounting(t, result, contract.TerminationFinished, contract.CompletenessComplete, true, 1, 1, 0)
		if got := result.Findings[0].Description; got != value {
			t.Fatalf("description = %q, want %q", got, value)
		}
	})
}

func TestA108ParserInertValues(t *testing.T) {
	values := []string{
		"=1+1",
		"+1",
		"-1",
		"@SUM(1)",
		"=cmd|' /C calc'!A0",
		"$(touch /tmp/synthetic)",
		"; rm -rf /",
		"`synthetic-command`",
		"|cat",
		"%COMSPEC%",
		"&synthetic",
		">synthetic-file",
		"=1+1\r\n+2",
	}
	for _, value := range values {
		t.Run("description "+value, func(t *testing.T) {
			row := a108RowWith(12, value)
			result, err := parse(t, a108FullHeader+"\r\n"+row+"\r\n")
			if err != nil {
				t.Fatalf("value %q: unexpected abort: %v", value, err)
			}
			requireA108Accounting(t, result, contract.TerminationFinished, contract.CompletenessComplete, true, 1, 1, 0)
			if got := result.Findings[0].Description; got != value {
				t.Fatalf("description = %q, want the literal bytes %q", got, value)
			}
		})
	}

	t.Run("required field with a formula prefix is inert", func(t *testing.T) {
		row := a108RowWithRaw(2, "=synthetic-package")
		result, err := parse(t, a108FullHeader+"\r\n"+row+"\r\n")
		if err != nil {
			t.Fatalf("unexpected abort: %v", err)
		}
		requireA108Accounting(t, result, contract.TerminationFinished, contract.CompletenessComplete, true, 1, 1, 0)
		if got := result.Findings[0].PackageName; got != "=synthetic-package" {
			t.Fatalf("package name = %q", got)
		}
	})

	t.Run("tab is still rejected inside inert text", func(t *testing.T) {
		row := a108RowWith(12, "=1+\t1")
		result, err := parse(t, a108FullHeader+"\r\n"+row+"\r\n")
		if err != nil {
			t.Fatalf("unexpected abort: %v", err)
		}
		requireA108Accounting(t, result, contract.TerminationFinished, contract.CompletenessPartial, true, 1, 0, 1)
		if got := result.Rejections[0].Reason; got != ReasonForbiddenText {
			t.Fatalf("reason = %q, want %q", got, ReasonForbiddenText)
		}
	})
}

// a108OneShotErrorReader delivers its payload together with a non-EOF error in
// its first Read call and a clean io.EOF afterwards: the io.Reader contract
// allows an error to be reported exactly once, so a parser that relies on the
// reader repeating it would silently treat a truncated stream as a clean end.
type a108OneShotErrorReader struct {
	data []byte
	err  error
	done bool
}

func (r *a108OneShotErrorReader) Read(p []byte) (int, error) {
	if r.done {
		return 0, io.EOF
	}
	r.done = true
	return copy(p, r.data), r.err
}

// newStringsReader adapts a string corpus to an io.Reader for the oracle probes.
type stringsReader struct {
	data []byte
}

func (r *stringsReader) Read(p []byte) (int, error) {
	if len(r.data) == 0 {
		return 0, io.EOF
	}
	n := copy(p, r.data)
	r.data = r.data[n:]
	return n, nil
}

func newStringsReader(s string) *stringsReader { return &stringsReader{data: []byte(s)} }

func TestA108ParserAccounting(t *testing.T) {
	cases := []struct {
		name         string
		input        string
		termination  contract.CoverageTermination
		completeness contract.Completeness
		totalKnown   bool
		total        uint64
		accepted     uint64
		rejected     uint64
		reason       Reason
	}{
		{"header only lf", testHeader + "\n", contract.TerminationFinished, contract.CompletenessComplete, true, 0, 0, 0, ""},
		{"header only crlf", testHeader + "\r\n", contract.TerminationFinished, contract.CompletenessComplete, true, 0, 0, 0, ""},
		{"one accepted record", testHeader + "\r\n" + testRow + "\r\n", contract.TerminationFinished, contract.CompletenessComplete, true, 1, 1, 0, ""},
		{"duplicates counted by occurrence", testHeader + "\r\n" + testRow + "\r\n" + testRow + "\r\n", contract.TerminationFinished, contract.CompletenessComplete, true, 2, 2, 0, ""},
		{"eof with rejections", testHeader + "\r\n" + a108BadVersion + "\r\n" + a108BadVersion + "\r\n", contract.TerminationFinished, contract.CompletenessPartial, true, 2, 0, 2, ""},
		{"accepted and rejected", testHeader + "\r\n" + testRow + "\r\n" + a108BadVersion + "\r\n", contract.TerminationFinished, contract.CompletenessPartial, true, 2, 1, 1, ""},
		{"last record without terminator", testHeader + "\r\n" + testRow, contract.TerminationFinished, contract.CompletenessComplete, true, 1, 1, 0, ""},
		{"abort without progress", testHeader + "\r\n" + `"unclosed`, contract.TerminationAborted, contract.CompletenessUnknown, false, 0, 0, 0, ReasonInvalidCSV},
		{"abort with progress", testHeader + "\r\n" + testRow + "\r\n" + `"unclosed`, contract.TerminationAborted, contract.CompletenessPartial, false, 0, 1, 0, ReasonInvalidCSV},
		{"abort after one rejection", testHeader + "\r\n" + a108BadVersion + "\r\n" + `"unclosed`, contract.TerminationAborted, contract.CompletenessPartial, false, 0, 0, 1, ReasonInvalidCSV},
		{"empty input", "", contract.TerminationAborted, contract.CompletenessUnknown, false, 0, 0, 0, ReasonInvalidHeader},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			result, err := parse(t, tc.input)
			if tc.reason == "" {
				if err != nil {
					t.Fatalf("unexpected abort: %v", err)
				}
			} else {
				requireFileError(t, err, tc.reason)
			}
			requireA108Accounting(t, result, tc.termination, tc.completeness, tc.totalKnown, tc.total, tc.accepted, tc.rejected)
		})
	}

	t.Run("reader delivering data with eof", func(t *testing.T) {
		result, err := ParsePrismaV1(&dataThenEOF{data: []byte(testHeader + "\r\n" + testRow + "\r\n")})
		if err != nil {
			t.Fatalf("unexpected abort: %v", err)
		}
		requireA108Accounting(t, result, contract.TerminationFinished, contract.CompletenessComplete, true, 1, 1, 0)
	})

	t.Run("reader delivering data with an error", func(t *testing.T) {
		reader := &dataAndError{data: []byte(testHeader + "\r\n" + testRow + "\r\n")}
		result, err := ParsePrismaV1(reader)
		requireFileError(t, err, ReasonReadFailure)
		requireA108Accounting(t, result, contract.TerminationAborted, contract.CompletenessPartial, false, 0, 1, 0)
	})

	t.Run("error delivered once with data still aborts", func(t *testing.T) {
		// A one-shot reader that returns its error together with the final bytes
		// and then a clean io.EOF: the reader contract allows the error to travel
		// exactly once, so the parser must not treat the later EOF as a clean end
		// of stream and must not lose the delivered error.
		reader := &a108OneShotErrorReader{data: []byte(testHeader + "\r\n" + testRow + "\r\n"),
			err: errors.New("SYNTHETIC_PRIVATE_MARKER delayed read failure")}
		result, err := ParsePrismaV1(reader)
		requireFileError(t, err, ReasonReadFailure)
		if strings.Contains(err.Error(), "SYNTHETIC_PRIVATE_MARKER") {
			t.Fatalf("file error leaked the raw cause: %v", err)
		}
		requireA108Accounting(t, result, contract.TerminationAborted, contract.CompletenessPartial, false, 0, 1, 0)
	})

	t.Run("identical repeats are byte-for-byte stable", func(t *testing.T) {
		input := testHeader + "\r\n" + testRow + "\r\n" + a108BadVersion + "\r\n"
		first, err := parse(t, input)
		if err != nil {
			t.Fatalf("unexpected abort: %v", err)
		}
		second, err := parse(t, input)
		if err != nil {
			t.Fatalf("unexpected abort: %v", err)
		}
		if !a108ResultsEqual(first, second) {
			t.Fatalf("repeated parses differ:\nfirst  %+v\nsecond %+v", first, second)
		}
	})
}
