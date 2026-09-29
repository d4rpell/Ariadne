package ingest

import (
	"bytes"
	"io"
	"strings"
	"testing"

	"github.com/d4rpell/Ariadne/internal/schema"
	contract "github.com/d4rpell/Ariadne/pkg/evidence"
)

// TestA108CSVLimits exercises every prisma-v1 limit with its literal ratified
// value, the N-1/N/N+1 boundaries and the dominance between overlapping
// budgets. Constants are asserted against their ADR-0007/ADR-0008 literals in
// addition to being used, so a changed constant in production is detected here
// even though the boundary arithmetic follows the same constant.
func TestA108CSVLimits(t *testing.T) {
	t.Run("ratified constants keep their literal values", func(t *testing.T) {
		checks := []struct {
			name string
			got  int
			want int
		}{
			{"PrismaV1MaxFileBytes", schema.PrismaV1MaxFileBytes, 67_108_864},
			{"PrismaV1MaxDataRecords", schema.PrismaV1MaxDataRecords, 100_000},
			{"PrismaV1MaxFields", schema.PrismaV1MaxFields, 32},
			{"PrismaV1MaxFieldBytes", schema.PrismaV1MaxFieldBytes, 65_536},
			{"PrismaV1MaxRecordBytes", schema.PrismaV1MaxRecordBytes, 262_144},
		}
		for _, check := range checks {
			if check.got != check.want {
				t.Fatalf("%s = %d, want the ratified literal %d", check.name, check.got, check.want)
			}
		}
		if schema.PrismaV1Version != "1.0" {
			t.Fatalf("PrismaV1Version = %q, want %q", schema.PrismaV1Version, "1.0")
		}
	})

	t.Run("file budget boundary", func(t *testing.T) {
		const limit = 67_108_864
		exact := buildBudgetFile(t, limit)
		if len(exact) != limit {
			t.Fatalf("generated %d bytes, want %d", len(exact), limit)
		}
		served := &countingReader{r: bytes.NewReader(exact)}
		result, err := ParsePrismaV1(served)
		if err != nil {
			t.Fatalf("N bytes: unexpected abort: %v", err)
		}
		if result.Completeness != contract.CompletenessComplete {
			t.Fatalf("N bytes: completeness = %q, want complete", result.Completeness)
		}
		if served.n != limit {
			t.Fatalf("N bytes: consumed %d bytes, want %d", served.n, limit)
		}
		acceptedAtLimit := result.Coverage.Rows.Accepted
		if acceptedAtLimit == 0 {
			t.Fatalf("N bytes: no records were accepted, the generated file is not exercising the boundary")
		}

		served = &countingReader{r: bytes.NewReader(append(append([]byte{}, exact...), 'x'))}
		result, err = ParsePrismaV1(served)
		fileErr := requireFileError(t, err, ReasonFileLimit)
		if fileErr.Offset != limit {
			t.Fatalf("offset = %d, want the file budget %d", fileErr.Offset, limit)
		}
		// An abort with progress is partial: the import did not finish, so the
		// file is never reported complete even though every read row was accepted.
		requireA108Accounting(t, result, contract.TerminationAborted, contract.CompletenessPartial, false, 0, acceptedAtLimit, 0)
		if served.n != limit+1 {
			t.Fatalf("N+1: consumed %d bytes, want a single probe byte past %d", served.n, limit)
		}
	})

	t.Run("data record budget boundary", func(t *testing.T) {
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
		requireA108Accounting(t, result, contract.TerminationFinished, contract.CompletenessComplete, true, 100_000, 100_000, 0)

		result, err = parse(t, exact.String()+row)
		fileErr := requireFileError(t, err, ReasonDataRecordLimit)
		wantOffset := uint64(exact.Len())
		if fileErr.Offset != wantOffset {
			t.Fatalf("offset = %d, want the first byte after 100.000 records at %d", fileErr.Offset, wantOffset)
		}
		requireA108Accounting(t, result, contract.TerminationAborted, contract.CompletenessPartial, false, 0, 100_000, 0)
	})

	t.Run("field byte limit counts raw csv bytes", func(t *testing.T) {
		header := testHeader + ",description"
		quotes := `""`
		// At the limit: two outer quotes plus one escaped pair plus 65_532 content
		// bytes total exactly 65_536 raw field bytes.
		atLimit := `"` + strings.Repeat("a", 65_532) + quotes + `"`
		if len(atLimit) != 65_536 {
			t.Fatalf("built %d raw field bytes, want 65_536", len(atLimit))
		}
		result, err := parse(t, header+"\r\n"+testRow+","+atLimit+"\r\n")
		if err != nil {
			t.Fatalf("N raw bytes: unexpected abort: %v", err)
		}
		requireA108Accounting(t, result, contract.TerminationFinished, contract.CompletenessComplete, true, 1, 1, 0)
		if got := len(result.Findings[0].Description); got != 65_533 {
			t.Fatalf("decoded field = %d bytes, want 65_533 after unescaping", got)
		}

		overLimit := `"` + strings.Repeat("a", 65_533) + quotes + `"`
		if len(overLimit) != 65_537 {
			t.Fatalf("built %d raw field bytes, want 65_537", len(overLimit))
		}
		result, err = parse(t, header+"\r\n"+testRow+","+overLimit+"\r\n")
		if err != nil {
			t.Fatalf("N+1 raw bytes: a delimited excess must not abort: %v", err)
		}
		requireA108Accounting(t, result, contract.TerminationFinished, contract.CompletenessPartial, true, 1, 0, 1)
		if got := result.Rejections[0].Reason; got != ReasonFieldLimit {
			t.Fatalf("reason = %q, want %q", got, ReasonFieldLimit)
		}

		// 32_768 two-byte runes are exactly 65_536 raw bytes; one more rune is
		// two bytes past the budget, which the raw-byte unit must detect.
		multibyte := strings.Repeat("é", 32_768)
		if len(multibyte) != 65_536 {
			t.Fatalf("built %d raw multibyte bytes, want 65_536", len(multibyte))
		}
		result, err = parse(t, header+"\r\n"+testRow+","+multibyte+"\r\n")
		if err != nil {
			t.Fatalf("N multibyte bytes: unexpected abort: %v", err)
		}
		requireA108Accounting(t, result, contract.TerminationFinished, contract.CompletenessComplete, true, 1, 1, 0)

		multibyteOver := strings.Repeat("é", 32_769)
		result, err = parse(t, header+"\r\n"+testRow+","+multibyteOver+"\r\n")
		if err != nil {
			t.Fatalf("N+2 multibyte bytes: unexpected abort: %v", err)
		}
		requireA108Accounting(t, result, contract.TerminationFinished, contract.CompletenessPartial, true, 1, 0, 1)
		if got := result.Rejections[0].Reason; got != ReasonFieldLimit {
			t.Fatalf("multibyte reason = %q, want %q", got, ReasonFieldLimit)
		}
	})

	t.Run("record byte limit counts delimiters and quoting", func(t *testing.T) {
		const limit = 262_144
		header := testHeader + ",package_type,package_id,path,severity,description"

		atLimit := buildRecordRow(t, limit, false)
		if len(atLimit) != limit {
			t.Fatalf("built %d record bytes, want %d", len(atLimit), limit)
		}
		result, err := parse(t, header+"\r\n"+atLimit+"\r\n")
		if err != nil {
			t.Fatalf("N record bytes: unexpected abort: %v", err)
		}
		requireA108Accounting(t, result, contract.TerminationFinished, contract.CompletenessComplete, true, 1, 1, 0)

		// The same budget with quoting: quotes and internal CRLF count as raw bytes.
		quoted := buildRecordRow(t, limit, true)
		result, err = parse(t, header+"\r\n"+quoted+"\r\n")
		if err != nil {
			t.Fatalf("quoted N record bytes: unexpected abort: %v", err)
		}
		requireA108Accounting(t, result, contract.TerminationFinished, contract.CompletenessComplete, true, 1, 1, 0)

		over := buildRecordRow(t, limit+1, false)
		result, err = parse(t, header+"\r\n"+over+"\r\n")
		fileErr := requireFileError(t, err, ReasonRecordLimit)
		if fileErr.Offset == 0 {
			t.Fatalf("record excess must report a verified offset")
		}
		requireA108Accounting(t, result, contract.TerminationAborted, contract.CompletenessUnknown, false, 0, 0, 0)

		// Last record without terminator shares the same boundary.
		result, err = parse(t, header+"\r\n"+over)
		requireFileError(t, err, ReasonRecordLimit)
		requireA108Accounting(t, result, contract.TerminationAborted, contract.CompletenessUnknown, false, 0, 0, 0)
	})

	t.Run("record excess dominates field excess", func(t *testing.T) {
		header := testHeader + ",package_type,package_id,path,severity,description"
		huge := testRow + "," + strings.Repeat("a", 300_000)
		result, err := parse(t, header+"\r\n"+huge+"\r\n")
		requireFileError(t, err, ReasonRecordLimit)
		requireA108Accounting(t, result, contract.TerminationAborted, contract.CompletenessUnknown, false, 0, 0, 0)
	})

	t.Run("field count limit with 32 and 33 fields is recoverable", func(t *testing.T) {
		// 31 and 32 delimited fields are structurally admissible: with a 15-column
		// header they cannot all map to canonical columns, so they fail as
		// delimited rejections (unexpected field count), not as structural aborts.
		header := a108FullHeader // fifteen columns
		fields31 := make([]string, 31)
		fields32 := make([]string, 32)
		for i := range fields31 {
			fields31[i] = "x"
		}
		for i := range fields32 {
			fields32[i] = "x"
		}
		for _, tc := range []struct {
			name   string
			fields []string
		}{{"31 fields", fields31}, {"32 fields", fields32}} {
			t.Run(tc.name, func(t *testing.T) {
				result, err := parse(t, header+"\r\n"+strings.Join(tc.fields, ",")+"\r\n")
				if err != nil {
					t.Fatalf("%s: a delimited mismatch must not abort: %v", tc.name, err)
				}
				requireA108Accounting(t, result, contract.TerminationFinished, contract.CompletenessPartial, true, 1, 0, 1)
				if got := result.Rejections[0].Reason; got != ReasonFieldCount {
					t.Fatalf("%s reason = %q, want %q", tc.name, got, ReasonFieldCount)
				}
			})
		}

		// 33 fields reach the structural field-count limit and are recoverable.
		fields33 := make([]string, 33)
		for i := range fields33 {
			fields33[i] = "x"
		}
		result, err := parse(t, header+"\r\n"+strings.Join(fields33, ",")+"\r\n")
		if err != nil {
			t.Fatalf("33 fields: unexpected abort: %v", err)
		}
		requireA108Accounting(t, result, contract.TerminationFinished, contract.CompletenessPartial, true, 1, 0, 1)
		if got := result.Rejections[0].Reason; got != ReasonFieldCountLimit {
			t.Fatalf("33-field reason = %q, want %q", got, ReasonFieldCountLimit)
		}
	})

	t.Run("oversized stream is not drained", func(t *testing.T) {
		const limit = 67_108_864
		// A reader that would serve a huge amount of bytes after the budget must
		// not be consumed beyond the single probe byte.
		exact := buildBudgetFile(t, limit)
		served := &countingReader{r: bytes.NewReader(exact)}
		result, err := ParsePrismaV1(served)
		if err != nil {
			t.Fatalf("N bytes: unexpected abort: %v", err)
		}
		acceptedAtLimit := result.Coverage.Rows.Accepted
		overflowSource := io.MultiReader(bytes.NewReader(exact), strings.NewReader(strings.Repeat("x", 1_048_576)))
		served = &countingReader{r: overflowSource}
		result, err = ParsePrismaV1(served)
		// The consumption check runs before the error check on purpose: draining
		// the rest of the stream after the budget abort would make the limit
		// error disappear, and the counter is the measurement that names the
		// drain itself.
		if served.n != limit+1 {
			t.Fatalf("parser consumed %d bytes of an oversized stream, want %d: the rest of the stream must never be drained", served.n, limit+1)
		}
		requireFileError(t, err, ReasonFileLimit)
		requireA108Accounting(t, result, contract.TerminationAborted, contract.CompletenessPartial, false, 0, acceptedAtLimit, 0)
	})
}
