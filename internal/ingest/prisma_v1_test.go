package ingest

import (
	"bytes"
	"errors"
	"io"
	"strings"
	"sync"
	"testing"

	contract "github.com/d4rpell/Ariadne/pkg/evidence"
)

const (
	testHeader = "schema_version,vulnerability_id,package_name,installed_version,fix_status,image_registry,image_repository"
	testRow    = "1.0,CVE-2026-1234,synthetic-package,1.2.3,open,registry.example,synthetic/repository"
)

func parse(t *testing.T, input string) (Result, error) {
	t.Helper()
	return ParsePrismaV1(strings.NewReader(input))
}

func requireFileError(t *testing.T, err error, reason Reason) *FileError {
	t.Helper()
	if err == nil {
		t.Fatalf("expected an error, got nil")
	}
	var fileErr *FileError
	if !errors.As(err, &fileErr) {
		t.Fatalf("error type = %T, want *FileError", err)
	}
	if fileErr.Reason != reason {
		t.Fatalf("reason = %q, want %q", fileErr.Reason, reason)
	}
	return fileErr
}

func requireFinished(t *testing.T, result Result, accepted, rejected uint64, completeness contract.Completeness) {
	t.Helper()
	if result.Coverage.Termination != contract.TerminationFinished {
		t.Fatalf("termination = %q, want finished", result.Coverage.Termination)
	}
	if result.Completeness != completeness {
		t.Fatalf("completeness = %q, want %q", result.Completeness, completeness)
	}
	rows := result.Coverage.Rows
	if rows == nil {
		t.Fatal("coverage rows must not be nil")
	}
	if rows.Total == nil {
		t.Fatal("finished import must carry a known total")
	}
	if *rows.Total != accepted+rejected || rows.Accepted != accepted || rows.Rejected != rejected {
		t.Fatalf("counters = total %d, accepted %d, rejected %d; want %d/%d/%d",
			*rows.Total, rows.Accepted, rows.Rejected, accepted+rejected, accepted, rejected)
	}
}

func requireAborted(t *testing.T, result Result, accepted, rejected uint64, completeness contract.Completeness) {
	t.Helper()
	if result.Coverage.Termination != contract.TerminationAborted {
		t.Fatalf("termination = %q, want aborted", result.Coverage.Termination)
	}
	if result.Completeness != completeness {
		t.Fatalf("completeness = %q, want %q", result.Completeness, completeness)
	}
	rows := result.Coverage.Rows
	if rows == nil {
		t.Fatal("coverage rows must not be nil")
	}
	if rows.Total != nil {
		t.Fatalf("aborted import must not invent a total, got %d", *rows.Total)
	}
	if rows.Accepted != accepted || rows.Rejected != rejected {
		t.Fatalf("counters = accepted %d, rejected %d; want %d/%d", rows.Accepted, rows.Rejected, accepted, rejected)
	}
}

func TestParsePrismaV1AcceptsMinimalRecord(t *testing.T) {
	input := testHeader + "\r\n" + testRow + "\r\n"
	result, err := parse(t, input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	requireFinished(t, result, 1, 0, contract.CompletenessComplete)
	if len(result.Findings) != 1 {
		t.Fatalf("findings = %d, want 1", len(result.Findings))
	}
	finding := result.Findings[0]
	if finding.SchemaVersion != "1.0" || finding.VulnerabilityID != "CVE-2026-1234" ||
		finding.PackageName != "synthetic-package" || finding.InstalledVersion != "1.2.3" ||
		finding.FixStatus != "open" || finding.ImageRegistry != "registry.example" ||
		finding.ImageRepository != "synthetic/repository" {
		t.Fatalf("unexpected finding: %+v", finding)
	}
	if finding.ImageTag != "" || finding.Path != "" || finding.PublishedDate != "" {
		t.Fatalf("omitted columns must stay empty: %+v", finding)
	}
	if len(result.Header) != 7 {
		t.Fatalf("header = %v, want seven columns", result.Header)
	}
	if result.Coverage.Method != contract.CoverageFindingsImport {
		t.Fatalf("method = %q, want findings_import", result.Coverage.Method)
	}
}

func TestParsePrismaV1AcceptsLFAndCRLFTerminators(t *testing.T) {
	for _, terminator := range []string{"\r\n", "\n"} {
		input := testHeader + terminator + testRow + terminator
		result, err := parse(t, input)
		if err != nil {
			t.Fatalf("terminator %q: unexpected error: %v", terminator, err)
		}
		requireFinished(t, result, 1, 0, contract.CompletenessComplete)
	}
}

func TestParsePrismaV1AcceptsLastRecordWithoutTerminator(t *testing.T) {
	result, err := parse(t, testHeader+"\r\n"+testRow)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	requireFinished(t, result, 1, 0, contract.CompletenessComplete)
}

func TestParsePrismaV1HeaderSubsequences(t *testing.T) {
	valid := []string{
		testHeader,
		"schema_version,vulnerability_id,package_name,installed_version,fix_status,image_registry,image_repository,image_tag,package_type,package_id,path,severity,description,published_date,discovery_date",
	}
	for _, header := range valid {
		row := testRow
		if header != testHeader {
			row = testRow + ",,,,,,,," // eight omitted optional columns
		}
		result, err := parse(t, header+"\r\n"+row+"\r\n")
		if err != nil {
			t.Fatalf("header %q: unexpected error: %v", header, err)
		}
		requireFinished(t, result, 1, 0, contract.CompletenessComplete)
	}
	_, err := parse(t, "schema_version,package_name,vulnerability_id\r\n1.0,synthetic-package,CVE-2026-1234\r\n")
	requireFileError(t, err, ReasonInvalidHeader)
}

func TestParsePrismaV1HeaderFailures(t *testing.T) {
	cases := []struct {
		name   string
		header string
		reason Reason
	}{
		{"unknown selector", testHeader + ",normalized_digest", ReasonUnknownSelector},
		{"alias", testHeader + ",CVE", ReasonUnknownSelector},
		{"case change", "Schema_version,vulnerability_id,package_name,installed_version,fix_status,image_registry,image_repository", ReasonUnknownSelector},
		{"empty name", testHeader + ",", ReasonUnknownSelector},
		{"surrounding space", "schema_version, vulnerability_id,package_name,installed_version,fix_status,image_registry,image_repository", ReasonUnknownSelector},
		{"reordered", "vulnerability_id,schema_version,package_name,installed_version,fix_status,image_registry,image_repository", ReasonInvalidHeader},
		{"duplicate", testHeader + ",package_name", ReasonDuplicateColumn},
		{"missing required", "schema_version,vulnerability_id,package_name,installed_version,fix_status,image_registry", ReasonMissingRequiredColumn},
		{"nul", "schema\x00_version,vulnerability_id,package_name,installed_version,fix_status,image_registry,image_repository", ReasonNUL},
		{"invalid utf8", "schema_version,vulnerability_id,package_name,installed_version,fix_status,image_registry,image_repository,x\xff", ReasonInvalidUTF8},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			result, err := parse(t, tc.header+"\r\n"+testRow+"\r\n")
			requireFileError(t, err, tc.reason)
			requireAborted(t, result, 0, 0, contract.CompletenessUnknown)
		})
	}
}

func TestParsePrismaV1HeaderExcessAborts(t *testing.T) {
	var header strings.Builder
	header.WriteString(testHeader)
	for i := 0; i < 26; i++ {
		header.WriteString(",package_name")
	}
	if got := strings.Count(header.String(), ",") + 1; got != 33 {
		t.Fatalf("generated %d header fields, want 33", got)
	}
	result, err := parse(t, header.String()+"\r\n"+testRow+"\r\n")
	requireFileError(t, err, ReasonFieldCountLimit)
	requireAborted(t, result, 0, 0, contract.CompletenessUnknown)
}

func TestParsePrismaV1HeaderErrorOffsetIsTheOffendingByte(t *testing.T) {
	cases := []struct {
		name   string
		header string
		reason Reason
		needle string
	}{
		{"nul after the first byte", "schema_version,package\x00name,package_name,installed_version,fix_status,image_registry,image_repository", ReasonNUL, "\x00"},
		{"format character after the first byte", "schema_version,package\u200b_name,package_name,installed_version,fix_status,image_registry,image_repository", ReasonForbiddenText, "\u200b"},
		{"invalid utf8 after the first byte", "schema_version,package\xffname,package_name,installed_version,fix_status,image_registry,image_repository", ReasonInvalidUTF8, "\xff"},
		{"quoted header with nul", "\"schema\x00_version\",vulnerability_id,package_name,installed_version,fix_status,image_registry,image_repository", ReasonNUL, "\x00"},
		{"quoted header with an escaped quote before the nul", "\"schema\"\"_\x00version\",vulnerability_id,package_name,installed_version,fix_status,image_registry,image_repository", ReasonNUL, "\x00"},
		{"quoted header with a format character", "\"schema\u200b_version\",vulnerability_id,package_name,installed_version,fix_status,image_registry,image_repository", ReasonForbiddenText, "\u200b"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			result, err := parse(t, tc.header+"\r\n"+testRow+"\r\n")
			fileErr := requireFileError(t, err, tc.reason)
			want := uint64(strings.Index(tc.header, tc.needle))
			if fileErr.Offset != want {
				t.Fatalf("offset = %d, want the first offending byte at %d", fileErr.Offset, want)
			}
			requireAborted(t, result, 0, 0, contract.CompletenessUnknown)
		})
	}
}

func TestParsePrismaV1RejectsBOM(t *testing.T) {
	input := "\xEF\xBB\xBF" + testHeader + "\r\n" + testRow + "\r\n"
	result, err := parse(t, input)
	requireFileError(t, err, ReasonBOM)
	requireAborted(t, result, 0, 0, contract.CompletenessUnknown)
}

func TestParsePrismaV1EmptyInputIsNotComplete(t *testing.T) {
	result, err := parse(t, "")
	requireFileError(t, err, ReasonInvalidHeader)
	requireAborted(t, result, 0, 0, contract.CompletenessUnknown)
}

func TestParsePrismaV1HeaderOnlyIsComplete(t *testing.T) {
	result, err := parse(t, testHeader+"\r\n")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	requireFinished(t, result, 0, 0, contract.CompletenessComplete)
}

func TestParsePrismaV1RowFailures(t *testing.T) {
	cases := []struct {
		name   string
		row    string
		reason Reason
	}{
		{"version unsupported", "2.0,CVE-2026-1234,synthetic-package,1.2.3,open,registry.example,synthetic/repository", ReasonUnsupportedVersion},
		{"version invalid leading zero", "01.0,CVE-2026-1234,synthetic-package,1.2.3,open,registry.example,synthetic/repository", ReasonInvalidVersion},
		{"version empty", ",CVE-2026-1234,synthetic-package,1.2.3,open,registry.example,synthetic/repository", ReasonRequiredValue},
		{"version surrounded", " 1.0,CVE-2026-1234,synthetic-package,1.2.3,open,registry.example,synthetic/repository", ReasonRequiredValue},
		{"cve empty", "1.0,,synthetic-package,1.2.3,open,registry.example,synthetic/repository", ReasonRequiredValue},
		{"cve lowercase", "1.0,cve-2026-1234,synthetic-package,1.2.3,open,registry.example,synthetic/repository", ReasonInvalidCVE},
		{"cve short year", "1.0,CVE-26-1234,synthetic-package,1.2.3,open,registry.example,synthetic/repository", ReasonInvalidCVE},
		{"cve short sequence", "1.0,CVE-2026-123,synthetic-package,1.2.3,open,registry.example,synthetic/repository", ReasonInvalidCVE},
		{"cve zeros are lexical", "1.0,CVE-0000-0000,synthetic-package,1.2.3,open,registry.example,synthetic/repository", ""},
		{"package empty", "1.0,CVE-2026-1234,,1.2.3,open,registry.example,synthetic/repository", ReasonRequiredValue},
		{"package spaces", "1.0,CVE-2026-1234,   ,1.2.3,open,registry.example,synthetic/repository", ReasonRequiredValue},
		{"fix status empty", "1.0,CVE-2026-1234,synthetic-package,1.2.3,,registry.example,synthetic/repository", ReasonRequiredValue},
		{"registry empty", "1.0,CVE-2026-1234,synthetic-package,1.2.3,open,,synthetic/repository", ReasonRequiredValue},
		{"repository empty", "1.0,CVE-2026-1234,synthetic-package,1.2.3,open,registry.example,", ReasonRequiredValue},
		{"nul", "1.0,CVE-2026-1234,syn\x00thetic,1.2.3,open,registry.example,synthetic/repository", ReasonNUL},
		{"invalid utf8", "1.0,CVE-2026-1234,synthetic\xff,1.2.3,open,registry.example,synthetic/repository", ReasonInvalidUTF8},
		{"zero width space", "1.0,CVE-2026-1234,synthetic\u200bpackage,1.2.3,open,registry.example,synthetic/repository", ReasonForbiddenText},
		{"bidi control", "1.0,CVE-2026-1234,synthetic\u202epackage,1.2.3,open,registry.example,synthetic/repository", ReasonForbiddenText},
		{"tab control", "1.0,CVE-2026-1234,synthetic\tpackage,1.2.3,open,registry.example,synthetic/repository", ReasonForbiddenText},
		{"del control", "1.0,CVE-2026-1234,synthetic\x7fpackage,1.2.3,open,registry.example,synthetic/repository", ReasonForbiddenText},
		{"c1 control", "1.0,CVE-2026-1234,synthetic\u0085package,1.2.3,open,registry.example,synthetic/repository", ReasonForbiddenText},
		{"bom character in a row", "1.0,CVE-2026-1234,\ufeffsynthetic,1.2.3,open,registry.example,synthetic/repository", ReasonForbiddenText},
		{"overlong utf8", "1.0,CVE-2026-1234,synthetic\xc0\xaf,1.2.3,open,registry.example,synthetic/repository", ReasonInvalidUTF8},
		{"truncated utf8", "1.0,CVE-2026-1234,synthetic\xe2\x82,1.2.3,open,registry.example,synthetic/repository", ReasonInvalidUTF8},
		{"installed version empty", "1.0,CVE-2026-1234,synthetic-package,,open,registry.example,synthetic/repository", ReasonRequiredValue},
		{"required value is one unicode space", "1.0,CVE-2026-1234,\u00a0,1.2.3,open,registry.example,synthetic/repository", ReasonRequiredValue},
		{"required value has leading unicode space", "1.0,CVE-2026-1234,\u2003synthetic-package,1.2.3,open,registry.example,synthetic/repository", ReasonRequiredValue},
		{"required value has trailing unicode space", "1.0,CVE-2026-1234,synthetic-package\u00a0,1.2.3,open,registry.example,synthetic/repository", ReasonRequiredValue},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			result, err := parse(t, testHeader+"\r\n"+tc.row+"\r\n")
			if err != nil {
				t.Fatalf("unexpected abort: %v", err)
			}
			if tc.reason == "" {
				requireFinished(t, result, 1, 0, contract.CompletenessComplete)
				return
			}
			requireFinished(t, result, 0, 1, contract.CompletenessPartial)
			if got := result.Rejections[0].Reason; got != tc.reason {
				t.Fatalf("reason = %q, want %q", got, tc.reason)
			}
		})
	}
}

func TestParsePrismaV1DateMatrix(t *testing.T) {
	header := testHeader + ",published_date,discovery_date"
	cases := []struct {
		name   string
		value  string
		reason Reason
	}{
		{"empty", "", ""},
		{"leap day", "2024-02-29", ""},
		{"not a leap day", "2023-02-29", ReasonInvalidDate},
		{"april 31", "2026-04-31", ReasonInvalidDate},
		{"month 13", "2026-13-01", ReasonInvalidDate},
		{"short month", "2026-9-01", ReasonInvalidDate},
		{"timestamp", "2026-09-25T00:00:00Z", ReasonInvalidDate},
		{"year zero", "0000-01-01", ReasonInvalidDate},
		{"spaces", " 2026-09-25", ReasonInvalidDate},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			result, err := parse(t, header+"\r\n"+testRow+","+tc.value+","+tc.value+"\r\n")
			if err != nil {
				t.Fatalf("unexpected abort: %v", err)
			}
			if tc.reason == "" {
				requireFinished(t, result, 1, 0, contract.CompletenessComplete)
				return
			}
			requireFinished(t, result, 0, 1, contract.CompletenessPartial)
			if got := result.Rejections[0].Reason; got != tc.reason {
				t.Fatalf("reason = %q, want %q", got, tc.reason)
			}
		})
	}
}

func TestParsePrismaV1TextPrecedesTypesInOneRow(t *testing.T) {
	row := "2.0,CVE-2026-1234,syn\x00thetic,1.2.3,open,registry.example,synthetic/repository"
	result, err := parse(t, testHeader+"\r\n"+row+"\r\n")
	if err != nil {
		t.Fatalf("unexpected abort: %v", err)
	}
	requireFinished(t, result, 0, 1, contract.CompletenessPartial)
	if got := result.Rejections[0].Reason; got != ReasonNUL {
		t.Fatalf("reason = %q, want %q", got, ReasonNUL)
	}
}

func TestParsePrismaV1QuotedFieldsPreserved(t *testing.T) {
	header := testHeader + ",description"
	row := `1.0,CVE-2026-1234,"synthetic, package",1.2.3,open,registry.example,synthetic/repository,"line one` + "\r\n" + `line ""two"""`
	result, err := parse(t, header+"\r\n"+row+"\r\n")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	requireFinished(t, result, 1, 0, contract.CompletenessComplete)
	finding := result.Findings[0]
	if finding.PackageName != "synthetic, package" {
		t.Fatalf("package name = %q, want %q", finding.PackageName, "synthetic, package")
	}
	want := "line one\r\nline \"two\""
	if finding.Description != want {
		t.Fatalf("description = %q, want %q", finding.Description, want)
	}
}

func TestParsePrismaV1AcceptsFormulaAsInertText(t *testing.T) {
	header := testHeader + ",description"
	for _, value := range []string{"=1+1", "+1", "-1", "@SUM(1)", " =1+1", "=cmd|' /C calc'!A0", "=1+1\r\n+2"} {
		row := `1.0,CVE-2026-1234,synthetic-package,1.2.3,open,registry.example,synthetic/repository,"` + value + `"`
		result, err := parse(t, header+"\r\n"+row+"\r\n")
		if err != nil {
			t.Fatalf("value %q: unexpected error: %v", value, err)
		}
		requireFinished(t, result, 1, 0, contract.CompletenessComplete)
		if got := result.Findings[0].Description; got != value {
			t.Fatalf("description = %q, want %q", got, value)
		}
	}
}

func TestParsePrismaV1PreservesBytesWithoutNormalization(t *testing.T) {
	header := testHeader + ",description"
	values := []string{"é", "e\u0301", "  1.2.3-4.el9  ", "paquete con espacios ", "\u00a0", "\u2003"}
	for _, value := range values {
		row := `1.0,CVE-2026-1234,synthetic-package,1.2.3,open,registry.example,synthetic/repository,"` + value + `"`
		result, err := parse(t, header+"\r\n"+row+"\r\n")
		if err != nil {
			t.Fatalf("value %q: unexpected error: %v", value, err)
		}
		if got := result.Findings[0].Description; got != value {
			t.Fatalf("description = %q, want %q", got, value)
		}
		// Multibyte characters split across Read calls must survive unchanged.
		chunked, err := ParsePrismaV1(&chunkReader{data: []byte(header + "\r\n" + row + "\r\n"), max: 1})
		if err != nil {
			t.Fatalf("value %q: chunked read: unexpected error: %v", value, err)
		}
		if got := chunked.Findings[0].Description; got != value {
			t.Fatalf("chunked description = %q, want %q", got, value)
		}
	}
}

func TestParsePrismaV1InvalidCSVStructureAborts(t *testing.T) {
	cases := []struct {
		name  string
		input string
	}{
		{"unclosed quote at EOF", testHeader + "\r\n" + `1.0,CVE-2026-1234,"synthetic-package`},
		{"quote inside unquoted field", testHeader + "\r\n" + `1.0,CVE-2026-1234,syn"thetic,1.2.3,open,registry.example,synthetic/repository`},
		{"text after closing quote", testHeader + "\r\n" + `1.0,CVE-2026-1234,"synthetic"package,1.2.3,open,registry.example,synthetic/repository`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			result, err := parse(t, tc.input)
			requireFileError(t, err, ReasonInvalidCSV)
			requireAborted(t, result, 0, 0, contract.CompletenessUnknown)
		})
	}
}

func TestParsePrismaV1FieldCountDifferences(t *testing.T) {
	six := "1.0,CVE-2026-1234,synthetic-package,1.2.3,open,registry.example"
	eight := testRow + ",extra"
	result, err := parse(t, testHeader+"\r\n"+six+"\r\n"+eight+"\r\n")
	if err != nil {
		t.Fatalf("unexpected abort: %v", err)
	}
	requireFinished(t, result, 0, 2, contract.CompletenessPartial)
	for _, rejection := range result.Rejections {
		if rejection.Reason != ReasonFieldCount {
			t.Fatalf("reason = %q, want %q", rejection.Reason, ReasonFieldCount)
		}
	}
}

func TestParsePrismaV1EmptyLineIsARecord(t *testing.T) {
	result, err := parse(t, testHeader+"\r\n"+testRow+"\r\n\r\n")
	if err != nil {
		t.Fatalf("unexpected abort: %v", err)
	}
	requireFinished(t, result, 1, 1, contract.CompletenessPartial)
	if result.Rejections[0].Reason != ReasonFieldCount {
		t.Fatalf("reason = %q, want %q", result.Rejections[0].Reason, ReasonFieldCount)
	}
}

func TestParsePrismaV1LoneCRIsContent(t *testing.T) {
	row := "1.0,CVE-2026-1234,synthetic-package,1.2.3,open,registry.example,synthetic\r/repository"
	result, err := parse(t, testHeader+"\r\n"+row+"\r\n")
	if err != nil {
		t.Fatalf("unexpected abort: %v", err)
	}
	requireFinished(t, result, 0, 1, contract.CompletenessPartial)
	if got := result.Rejections[0].Reason; got != ReasonForbiddenText {
		t.Fatalf("reason = %q, want %q", got, ReasonForbiddenText)
	}
}

func TestParsePrismaV1DuplicatesCountedByOccurrence(t *testing.T) {
	result, err := parse(t, testHeader+"\r\n"+testRow+"\r\n"+testRow+"\r\n")
	if err != nil {
		t.Fatalf("unexpected abort: %v", err)
	}
	requireFinished(t, result, 2, 0, contract.CompletenessComplete)
	if result.Findings[0].Locator == result.Findings[1].Locator {
		t.Fatalf("duplicate records must keep distinct locators: %+v", result.Findings)
	}
}

func TestParsePrismaV1FieldLimitBoundary(t *testing.T) {
	header := testHeader + ",description"
	atLimit := `1.0,CVE-2026-1234,synthetic-package,1.2.3,open,registry.example,synthetic/repository,` + strings.Repeat("a", 64*1024)
	overLimit := `1.0,CVE-2026-1234,synthetic-package,1.2.3,open,registry.example,synthetic/repository,` + strings.Repeat("a", 64*1024+1)

	result, err := parse(t, header+"\r\n"+atLimit+"\r\n")
	if err != nil {
		t.Fatalf("exact field budget: unexpected abort: %v", err)
	}
	requireFinished(t, result, 1, 0, contract.CompletenessComplete)

	result, err = parse(t, header+"\r\n"+overLimit+"\r\n")
	if err != nil {
		t.Fatalf("recoverable field excess must not abort: %v", err)
	}
	requireFinished(t, result, 0, 1, contract.CompletenessPartial)
	if got := result.Rejections[0].Reason; got != ReasonFieldLimit {
		t.Fatalf("reason = %q, want %q", got, ReasonFieldLimit)
	}
}

func TestParsePrismaV1FieldBudgetCountsRawBytes(t *testing.T) {
	header := testHeader + ",description"

	multibyte := strings.Repeat("é", 32*1024) // 65_536 raw bytes
	result, err := parse(t, header+"\r\n"+testRow+","+multibyte+"\r\n")
	if err != nil {
		t.Fatalf("exact multibyte field budget: unexpected abort: %v", err)
	}
	requireFinished(t, result, 1, 0, contract.CompletenessComplete)

	multibyteOver := strings.Repeat("é", 32*1024+1)
	result, err = parse(t, header+"\r\n"+testRow+","+multibyteOver+"\r\n")
	if err != nil {
		t.Fatalf("recoverable excess must not abort: %v", err)
	}
	requireFinished(t, result, 0, 1, contract.CompletenessPartial)
	if got := result.Rejections[0].Reason; got != ReasonFieldLimit {
		t.Fatalf("reason = %q, want %q", got, ReasonFieldLimit)
	}

	// Escaped quotes count as two raw bytes of the field representation.
	atEscapeLimit := `"` + strings.Repeat("q", 65_532) + `""` + `"` // 65_536 raw bytes
	if len(atEscapeLimit) != 64*1024 {
		t.Fatalf("built %d field bytes, want %d", len(atEscapeLimit), 64*1024)
	}
	result, err = parse(t, header+"\r\n"+testRow+","+atEscapeLimit+"\r\n")
	if err != nil {
		t.Fatalf("exact escaped field budget: unexpected abort: %v", err)
	}
	requireFinished(t, result, 1, 0, contract.CompletenessComplete)
	if got := result.Findings[0].Description; len(got) != 65_533 || !strings.HasSuffix(got, `"`) {
		t.Fatalf("escaped content = %d bytes ending %q", len(got), got[len(got)-1:])
	}

	overEscapeLimit := `"` + strings.Repeat("q", 65_533) + `""` + `"` // 65_537 raw bytes
	result, err = parse(t, header+"\r\n"+testRow+","+overEscapeLimit+"\r\n")
	if err != nil {
		t.Fatalf("recoverable excess must not abort: %v", err)
	}
	requireFinished(t, result, 0, 1, contract.CompletenessPartial)
	if got := result.Rejections[0].Reason; got != ReasonFieldLimit {
		t.Fatalf("reason = %q, want %q", got, ReasonFieldLimit)
	}
}

func TestParsePrismaV1FieldCountLimitIsRecoverable(t *testing.T) {
	fields := make([]string, 33)
	for i := range fields {
		fields[i] = "x"
	}
	result, err := parse(t, testHeader+"\r\n"+strings.Join(fields, ",")+"\r\n")
	if err != nil {
		t.Fatalf("recoverable field-count excess must not abort: %v", err)
	}
	requireFinished(t, result, 0, 1, contract.CompletenessPartial)
	if got := result.Rejections[0].Reason; got != ReasonFieldCountLimit {
		t.Fatalf("reason = %q, want %q", got, ReasonFieldCountLimit)
	}
}

// buildRecordRow returns a 12-field row whose raw CSV length, excluding the
// outer terminator, is exactly size bytes. Every field stays below the field
// budget; when quoted is set, the description is quoted with an internal CRLF
// so quoting bytes count towards the record budget.
func buildRecordRow(t *testing.T, size int, quoted bool) string {
	t.Helper()
	fixed := []string{"1.0", "CVE-2026-1234", "synthetic-package", "1.2.3", "open", "registry.example", "synthetic/repository"}
	overhead := 11 // delimiters between twelve fields
	for _, field := range fixed {
		overhead += len(field)
	}
	remaining := size - overhead
	if quoted {
		remaining -= 4 // the two outer quotes and the internal CRLF
	}
	share := remaining / 5
	if remaining < 0 || share >= 64*1024 {
		t.Fatalf("cannot distribute %d bytes across five fields below the field budget", remaining)
	}
	optional := make([]string, 5)
	for i := range optional {
		optional[i] = strings.Repeat(string(rune('a'+i)), share)
	}
	optional[4] += strings.Repeat("z", remaining-5*share)
	row := strings.Join(fixed, ",") + "," + strings.Join(optional[:4], ",") + ","
	if quoted {
		half := len(optional[4]) / 2
		row += `"` + optional[4][:half] + "\r\n" + optional[4][half:] + `"`
	} else {
		row += optional[4]
	}
	if len(row) != size {
		t.Fatalf("built %d record bytes, want %d", len(row), size)
	}
	for _, field := range optional {
		if len(field) >= 64*1024 {
			t.Fatalf("field of %d bytes exceeds the field budget", len(field))
		}
	}
	return row
}

func TestParsePrismaV1RecordBudgetBoundaries(t *testing.T) {
	const limit = 256 * 1024
	header := testHeader + ",package_type,package_id,path,severity,description"

	atLimit := buildRecordRow(t, limit, false)
	result, err := parse(t, header+"\r\n"+atLimit+"\r\n")
	if err != nil {
		t.Fatalf("exact record budget: unexpected abort: %v", err)
	}
	requireFinished(t, result, 1, 0, contract.CompletenessComplete)

	result, err = parse(t, header+"\r\n"+atLimit)
	if err != nil {
		t.Fatalf("exact record budget without terminator: unexpected abort: %v", err)
	}
	requireFinished(t, result, 1, 0, contract.CompletenessComplete)

	quoted := buildRecordRow(t, limit, true)
	result, err = parse(t, header+"\r\n"+quoted+"\r\n")
	if err != nil {
		t.Fatalf("quoted record at the exact budget: unexpected abort: %v", err)
	}
	requireFinished(t, result, 1, 0, contract.CompletenessComplete)
	if finding := result.Findings[0].Description; !strings.Contains(finding, "\r\n") {
		t.Fatalf("quoted CRLF was not preserved: %q", finding)
	}

	over := buildRecordRow(t, limit+1, false)
	result, err = parse(t, header+"\r\n"+over+"\r\n")
	requireFileError(t, err, ReasonRecordLimit)
	requireAborted(t, result, 0, 0, contract.CompletenessUnknown)

	result, err = parse(t, header+"\r\n"+over)
	requireFileError(t, err, ReasonRecordLimit)
	requireAborted(t, result, 0, 0, contract.CompletenessUnknown)
}

func TestParsePrismaV1RecordExcessBeatsFieldExcess(t *testing.T) {
	header := testHeader + ",package_type,package_id,path,severity,description"
	huge := testRow + "," + strings.Repeat("a", 300_000)
	result, err := parse(t, header+"\r\n"+huge+"\r\n")
	requireFileError(t, err, ReasonRecordLimit)
	requireAborted(t, result, 0, 0, contract.CompletenessUnknown)
}

func TestParsePrismaV1AccountingMatrix(t *testing.T) {
	badVersion := "2.0,CVE-2026-1234,synthetic-package,1.2.3,open,registry.example,synthetic/repository"
	cases := []struct {
		name         string
		input        string
		accepted     uint64
		rejected     uint64
		completeness contract.Completeness
	}{
		{"header only", testHeader + "\r\n", 0, 0, contract.CompletenessComplete},
		{"two valid", testHeader + "\r\n" + testRow + "\r\n" + testRow + "\r\n", 2, 0, contract.CompletenessComplete},
		{"one valid one invalid", testHeader + "\r\n" + testRow + "\r\n" + badVersion + "\r\n", 1, 1, contract.CompletenessPartial},
		{"two invalid", testHeader + "\r\n" + badVersion + "\r\n" + badVersion + "\r\n", 0, 2, contract.CompletenessPartial},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			result, err := parse(t, tc.input)
			if err != nil {
				t.Fatalf("unexpected abort: %v", err)
			}
			requireFinished(t, result, tc.accepted, tc.rejected, tc.completeness)
		})
	}

	t.Run("valid row then unclosed quote", func(t *testing.T) {
		result, err := parse(t, testHeader+"\r\n"+testRow+"\r\n"+`"unclosed`)
		requireFileError(t, err, ReasonInvalidCSV)
		requireAborted(t, result, 1, 0, contract.CompletenessPartial)
	})
	t.Run("rejected row then abort", func(t *testing.T) {
		result, err := parse(t, testHeader+"\r\n"+badVersion+"\r\n"+`"unclosed`)
		requireFileError(t, err, ReasonInvalidCSV)
		requireAborted(t, result, 0, 1, contract.CompletenessPartial)
	})
	t.Run("abort before first row", func(t *testing.T) {
		result, err := parse(t, testHeader+"\r\n"+`"unclosed`)
		requireFileError(t, err, ReasonInvalidCSV)
		requireAborted(t, result, 0, 0, contract.CompletenessUnknown)
	})
}

func TestParsePrismaV1NilReader(t *testing.T) {
	result, err := ParsePrismaV1(nil)
	if err == nil || err.Error() != "ingest: prisma-v1: nil reader" {
		t.Fatalf("error = %v, want the fixed nil reader error", err)
	}
	requireAborted(t, result, 0, 0, contract.CompletenessUnknown)
}

// failReader returns a fixed error once the prefix is exhausted.
type failReader struct {
	prefix []byte
	err    error
}

func (r *failReader) Read(p []byte) (int, error) {
	if len(r.prefix) == 0 {
		return 0, r.err
	}
	n := copy(p, r.prefix)
	r.prefix = r.prefix[n:]
	return n, nil
}

func TestParsePrismaV1ReadFailureIsSanitized(t *testing.T) {
	prefix := testHeader + "\r\n" + testRow + "\r\n"
	reader := &failReader{prefix: []byte(prefix), err: errors.New("SYNTHETIC_PRIVATE_MARKER raw failure")}
	result, err := ParsePrismaV1(reader)
	requireFileError(t, err, ReasonReadFailure)
	if strings.Contains(err.Error(), "SYNTHETIC_PRIVATE_MARKER") {
		t.Fatalf("file error leaked the raw cause: %v", err)
	}
	requireAborted(t, result, 1, 0, contract.CompletenessPartial)
	if len(reader.prefix) != 0 {
		t.Fatalf("parser left unread bytes: %d", len(reader.prefix))
	}
}

// dataAndError delivers its payload together with a non-EOF error in the same
// Read call, as the io.Reader contract allows.
type dataAndError struct {
	data []byte
	err  error
	done bool
}

func (r *dataAndError) Read(p []byte) (int, error) {
	if r.done {
		return 0, r.err
	}
	r.done = true
	return copy(p, r.data), r.err
}

func TestParsePrismaV1ProcessesBytesDeliveredWithAnError(t *testing.T) {
	reader := &dataAndError{
		data: []byte(testHeader + "\r\n" + testRow + "\r\n"),
		err:  errors.New("SYNTHETIC_PRIVATE_MARKER read failure"),
	}
	result, err := ParsePrismaV1(reader)
	requireFileError(t, err, ReasonReadFailure)
	if strings.Contains(err.Error(), "SYNTHETIC_PRIVATE_MARKER") {
		t.Fatalf("file error leaked the raw cause: %v", err)
	}
	requireAborted(t, result, 1, 0, contract.CompletenessPartial)
}

// dataThenEOF hands over its payload together with io.EOF, as the io.Reader
// contract allows.
type dataThenEOF struct {
	data []byte
	done bool
}

func (r *dataThenEOF) Read(p []byte) (int, error) {
	if r.done {
		return 0, io.EOF
	}
	n := copy(p, r.data)
	r.done = true
	return n, io.EOF
}

func TestParsePrismaV1ReadsDataDeliveredWithEOF(t *testing.T) {
	result, err := ParsePrismaV1(&dataThenEOF{data: []byte(testHeader + "\r\n" + testRow + "\r\n")})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	requireFinished(t, result, 1, 0, contract.CompletenessComplete)
}

// chunkReader serves at most max bytes per Read call.
type chunkReader struct {
	data []byte
	max  int
}

func (r *chunkReader) Read(p []byte) (int, error) {
	if len(r.data) == 0 {
		return 0, io.EOF
	}
	n := r.max
	if n > len(r.data) {
		n = len(r.data)
	}
	if n > len(p) {
		n = len(p)
	}
	copy(p, r.data[:n])
	r.data = r.data[n:]
	return n, nil
}

func TestParsePrismaV1ResultIsChunkingIndependent(t *testing.T) {
	input := testHeader + "\r\n" + testRow + "\r\n" +
		"2.0,CVE-2026-1234,synthetic-package,1.2.3,open,registry.example,synthetic/repository\r\n" +
		`1.0,CVE-2026-1234,"synthetic, package",1.2.3,open,registry.example,synthetic/repository` + "\r\n"
	expected, err := parse(t, input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	for _, chunk := range []int{1, 2, 7, 4096} {
		result, err := ParsePrismaV1(&chunkReader{data: []byte(input), max: chunk})
		if err != nil {
			t.Fatalf("chunk %d: unexpected error: %v", chunk, err)
		}
		if result.Coverage.Termination != expected.Coverage.Termination ||
			result.Completeness != expected.Completeness ||
			len(result.Findings) != len(expected.Findings) ||
			len(result.Rejections) != len(expected.Rejections) {
			t.Fatalf("chunk %d: coverage differs from the whole-buffer parse", chunk)
		}
		for i := range result.Findings {
			if result.Findings[i] != expected.Findings[i] {
				t.Fatalf("chunk %d: finding %d differs: %+v", chunk, i, result.Findings[i])
			}
		}
		for i := range result.Rejections {
			if result.Rejections[i] != expected.Rejections[i] {
				t.Fatalf("chunk %d: rejection %d differs: %+v", chunk, i, result.Rejections[i])
			}
		}
	}
}

// countingReader records how many bytes were actually served.
type countingReader struct {
	r io.Reader
	n int64
}

func (c *countingReader) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	c.n += int64(n)
	return n, err
}

// buildBudgetFile returns a valid prisma-v1 file of exactly size bytes whose
// records stay below every per-record budget.
func buildBudgetFile(t *testing.T, size int) []byte {
	t.Helper()
	header := testHeader + ",description\r\n"
	rowPrefix := testRow + ","
	rowSuffix := "\r\n"
	fullRow := rowPrefix + strings.Repeat("a", 60_000) + rowSuffix
	buf := make([]byte, 0, size+1)
	buf = append(buf, header...)
	for size-len(buf) > len(fullRow)+len(rowPrefix)+len(rowSuffix) {
		buf = append(buf, fullRow...)
	}
	remaining := size - len(buf)
	buf = append(buf, rowPrefix...)
	for i := 0; i < remaining-len(rowPrefix)-len(rowSuffix); i++ {
		buf = append(buf, 'b')
	}
	buf = append(buf, rowSuffix...)
	if len(buf) != size {
		t.Fatalf("generated %d bytes, want %d", len(buf), size)
	}
	return buf
}

func TestParsePrismaV1FileBudget(t *testing.T) {
	const limit = 64 * 1024 * 1024
	exact := buildBudgetFile(t, limit)

	served := &countingReader{r: bytes.NewReader(exact)}
	result, err := ParsePrismaV1(served)
	if err != nil {
		t.Fatalf("exact-size file: unexpected abort: %v", err)
	}
	if result.Coverage.Termination != contract.TerminationFinished || result.Completeness != contract.CompletenessComplete {
		t.Fatalf("exact-size file: termination %q, completeness %q", result.Coverage.Termination, result.Completeness)
	}
	if served.n != limit {
		t.Fatalf("exact-size file: parser consumed %d bytes, want %d", served.n, limit)
	}

	over := append(exact, 'x')
	served = &countingReader{r: bytes.NewReader(over)}
	result, err = ParsePrismaV1(served)
	requireFileError(t, err, ReasonFileLimit)
	requireAborted(t, result, result.Coverage.Rows.Accepted, result.Coverage.Rows.Rejected, result.Completeness)
	if served.n != limit+1 {
		t.Fatalf("oversized file: parser consumed %d bytes, want the single probe byte past %d", served.n, limit)
	}
}

func TestParsePrismaV1DataRecordBudget(t *testing.T) {
	row := testRow + "\r\n"
	var exact strings.Builder
	exact.WriteString(testHeader + "\r\n")
	for i := 0; i < 100_000; i++ {
		exact.WriteString(row)
	}
	result, err := parse(t, exact.String())
	if err != nil {
		t.Fatalf("100.000 records: unexpected abort: %v", err)
	}
	requireFinished(t, result, 100_000, 0, contract.CompletenessComplete)

	over := exact.String() + row
	result, err = parse(t, over)
	requireFileError(t, err, ReasonDataRecordLimit)
	requireAborted(t, result, 100_000, 0, contract.CompletenessPartial)
}

func TestParsePrismaV1IsDeterministicAndConcurrentSafe(t *testing.T) {
	input := testHeader + "\r\n" + testRow + "\r\n" + "\r\n"
	first, err := parse(t, input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	second, err := parse(t, input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(first.Findings) != len(second.Findings) || len(first.Rejections) != len(second.Rejections) {
		t.Fatal("repeat parse differs")
	}
	var wg sync.WaitGroup
	results := make([]Result, 8)
	for i := range results {
		wg.Add(1)
		go func(index int) {
			defer wg.Done()
			parsed, err := ParsePrismaV1(strings.NewReader(input))
			if err != nil {
				t.Errorf("concurrent parse: %v", err)
				return
			}
			results[index] = parsed
		}(i)
	}
	wg.Wait()
	for i := range results {
		if len(results[i].Findings) != len(first.Findings) || len(results[i].Rejections) != len(first.Rejections) {
			t.Fatalf("concurrent result %d differs", i)
		}
	}
}

func TestParsePrismaV1DiagnosticsDoNotLeakValues(t *testing.T) {
	const marker = "SYNTHETIC_PRIVATE_MARKER"
	row := "1.0," + marker + "-not-a-cve,synthetic-package,1.2.3,open,registry.example,synthetic/repository"
	result, err := parse(t, testHeader+"\r\n"+row+"\r\n")
	if err != nil {
		t.Fatalf("unexpected abort: %v", err)
	}
	requireFinished(t, result, 0, 1, contract.CompletenessPartial)
	if strings.Contains(result.Rejections[0].String(), marker) {
		t.Fatalf("rejection leaked input data: %s", result.Rejections[0].String())
	}
}

func TestLocatorAndErrorFormatting(t *testing.T) {
	locator := Locator{Record: 3, StartByte: 12, EndByte: 48}
	if got := locator.String(); got != "record/3/bytes/12-48" {
		t.Fatalf("locator = %q", got)
	}
	rejection := Rejection{Locator: locator, Reason: ReasonFieldCount}
	if got := rejection.String(); got != "ingest: prisma-v1: record/3/bytes/12-48: unexpected field count" {
		t.Fatalf("rejection = %q", got)
	}
	fileErr := &FileError{Offset: 7, Reason: ReasonReadFailure}
	if got := fileErr.Error(); got != "ingest: prisma-v1: byte/7: input read failed" {
		t.Fatalf("file error = %q", got)
	}
	rejection = Rejection{Locator: locator, Reason: Reason("value built by a caller")}
	if got := rejection.String(); !strings.Contains(got, "invalid input") || strings.Contains(got, "caller") {
		t.Fatalf("unknown reason must fall back to the allowlist: %q", got)
	}
	var nilError *FileError
	if got := nilError.Error(); got != "ingest: prisma-v1: byte/0: invalid input" {
		t.Fatalf("nil file error = %q", got)
	}
}
