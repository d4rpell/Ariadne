package ingest

import (
	"errors"
	"io"
	"math/rand"
	"strings"
	"testing"

	contract "github.com/d4rpell/Ariadne/pkg/evidence"
)

// a108RejectBadVersion is a delimited record that fails schema validation.
const a108RejectBadVersion = "2.0,CVE-2026-1234,synthetic-package,1.2.3,open,registry.example,synthetic/repository"

// a108PropertyCorpus is a stream that mixes accepted records, rejected records,
// quoted fields with escapes and internal CRLF, multibyte text, one empty line
// and a final record without terminator.
func a108PropertyCorpus() string {
	header := a108FullHeader
	row1 := a108FullRow
	row2 := a108RowWith(12, "line one\r\nline two \"quoted\" end")
	row3 := a108RowWith(12, "café 漢字 καθ né")
	row4 := a108RejectBadVersion
	row5 := a108RowWithRaw(6, "bytes\xffinvalid")
	return header + "\r\n" +
		row1 + "\r\n" +
		row2 + "\r\n" +
		row3 + "\r\n" +
		row4 + "\r\n" +
		row5 + "\r\n" +
		"\r\n" +
		row1
}

// a108AbortCorpus ends with an unclosed quote after some accepted records.
func a108AbortCorpus() string {
	return a108FullHeader + "\r\n" + a108FullRow + "\r\n" + a108RowWith(12, "ok \"text\"") + "\r\n" + `"unclosed`
}

// a108CorpusRecord is one literal record of a property corpus, in stream order.
type a108CorpusRecord struct {
	row    string
	reason Reason // rejection reason; empty means the record is accepted
	empty  bool   // the record is the empty line: rejected as an unexpected field count
	noTerm bool   // final record without terminator
}

// a108MixedCorpusRecords is the literal table of a108PropertyCorpus, in order.
func a108MixedCorpusRecords() []a108CorpusRecord {
	return []a108CorpusRecord{
		{row: a108FullRow},
		{row: a108RowWith(12, "line one\r\nline two \"quoted\" end")},
		{row: a108RowWith(12, "café 漢字 καθ né")},
		{row: a108RejectBadVersion, reason: ReasonFieldCount},
		{row: a108RowWithRaw(6, "bytes\xffinvalid"), reason: ReasonInvalidUTF8},
		{empty: true, reason: ReasonFieldCount},
		{row: a108FullRow, noTerm: true},
	}
}

// a108AbortCorpusRecords is the literal table of a108AbortCorpus: the aborting
// final record is an unterminated quote with no complete row of its own.
func a108AbortCorpusRecords() []a108CorpusRecord {
	return []a108CorpusRecord{
		{row: a108FullRow},
		{row: a108RowWith(12, "ok \"text\"")},
	}
}

// a108HeaderColumns are the literal columns of the full header.
func a108HeaderColumns() []string {
	return strings.Split(a108FullHeader, ",")
}

// a108ColumnsOf delimits one literal CSV row of the property corpus: it splits
// on commas and undoes CSV quoting exactly as the ratified grammar does (strip
// one outer pair, turn a doubled quote into one). None of these rows carries a
// comma inside a quoted value, so the literal split is exact.
func a108ColumnsOf(row string) []string {
	parts := strings.Split(row, ",")
	for index, part := range parts {
		if len(part) >= 2 && strings.HasPrefix(part, `"`) && strings.HasSuffix(part, `"`) {
			parts[index] = strings.ReplaceAll(part[1:len(part)-1], `""`, `"`)
		}
	}
	return parts
}

// a108FindingFromColumns builds the Finding the parser must produce for one
// literal row, from the canonical columns of a108FullHeader.
func a108FindingFromColumns(t *testing.T, columns []string, locator Locator) Finding {
	t.Helper()
	if len(columns) != 15 {
		t.Fatalf("the literal row has %d columns, want the 15 of the full header", len(columns))
	}
	return Finding{
		Locator:          locator,
		SchemaVersion:    columns[0],
		VulnerabilityID:  columns[1],
		PackageName:      columns[2],
		InstalledVersion: columns[3],
		FixStatus:        columns[4],
		ImageRegistry:    columns[5],
		ImageRepository:  columns[6],
		ImageTag:         columns[7],
		PackageType:      columns[8],
		PackageID:        columns[9],
		Path:             columns[10],
		Severity:         columns[11],
		Description:      columns[12],
		PublishedDate:    columns[13],
		DiscoveryDate:    columns[14],
	}
}

// a108RebuildFromLiterals walks the literal table of one corpus and builds the
// Result the parser must produce: accepted rows become findings and records with
// a reason become rejections, with every locator computed from the byte lengths
// of the literal stream. The accounting follows the ratified rules applied by
// hand (`finished` unless the copy states otherwise).
func a108RebuildFromLiterals(t *testing.T, name string, records []a108CorpusRecord) Result {
	t.Helper()
	findings := []Finding{}
	rejections := []Rejection{}
	offset := uint64(len(a108FullHeader) + 2)
	record := uint64(0)
	for _, literal := range records {
		record++
		switch {
		case literal.empty:
			// The empty line is one record with a single empty field: rejected by
			// the schema, its interval covers zero bytes before its terminator.
			rejections = append(rejections, Rejection{Locator: Locator{Record: record, StartByte: offset, EndByte: offset}, Reason: literal.reason})
			offset += 2
		case literal.noTerm:
			end := offset + uint64(len(literal.row))
			findings = append(findings, a108FindingFromColumns(t, a108ColumnsOf(literal.row), Locator{Record: record, StartByte: offset, EndByte: end}))
			offset = end
		default:
			end := offset + uint64(len(literal.row))
			if literal.reason != "" {
				rejections = append(rejections, Rejection{Locator: Locator{Record: record, StartByte: offset, EndByte: end}, Reason: literal.reason})
			} else {
				findings = append(findings, a108FindingFromColumns(t, a108ColumnsOf(literal.row), Locator{Record: record, StartByte: offset, EndByte: end}))
			}
			offset = end + 2
		}
	}
	completeness := contract.CompletenessComplete
	if len(rejections) > 0 {
		completeness = contract.CompletenessPartial
	}
	total := record
	return Result{
		Header:       a108HeaderColumns(),
		Findings:     findings,
		Rejections:   rejections,
		Coverage:     contract.Coverage{Method: contract.CoverageFindingsImport, Termination: contract.TerminationFinished, Rows: &contract.CoverageRows{Total: &total, Accepted: uint64(len(findings)), Rejected: uint64(len(rejections))}},
		Completeness: completeness,
	}
}

// a108IndependentExpectation rebuilds the whole expectation of a corpus from its
// literal table and byte lengths, without calling the parser: a consistently
// wrong parser — one that normalizes a locator, loses a column or misclassifies
// a record — fails the comparison against it. The chunked parses are compared
// against this expectation.
func a108IndependentExpectation(t *testing.T, name, input string) (Result, error) {
	t.Helper()
	switch name {
	case "mixed records":
		return a108RebuildFromLiterals(t, name, a108MixedCorpusRecords()), nil
	case "abort with unclosed quote":
		result := a108RebuildFromLiterals(t, name, a108AbortCorpusRecords())
		// A structural abort returns the verified prefix, an unknown total and
		// partial completeness; the offset is the end of the literal stream.
		result.Coverage.Termination = contract.TerminationAborted
		result.Coverage.Rows.Total = nil
		result.Completeness = contract.CompletenessPartial
		return result, &FileError{Offset: uint64(len(input)), Reason: ReasonInvalidCSV}
	case "header only":
		total := uint64(0)
		return Result{
			Header:       a108HeaderColumns(),
			Findings:     []Finding{},
			Rejections:   []Rejection{},
			Coverage:     contract.Coverage{Method: contract.CoverageFindingsImport, Termination: contract.TerminationFinished, Rows: &contract.CoverageRows{Total: &total}},
			Completeness: contract.CompletenessComplete,
		}, nil
	}
	t.Fatalf("no independent expectation for corpus %q", name)
	return Result{}, nil
}

// a108ChunkReader serves exactly n bytes per Read until the data is exhausted.
type a108ChunkReader struct {
	data []byte
	n    int
}

func (r *a108ChunkReader) Read(p []byte) (int, error) {
	if len(r.data) == 0 {
		return 0, io.EOF
	}
	n := r.n
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

// requireA108SameResult compares every field of two parse results, including
// the exact failure classification when both aborted.
func requireA108SameResult(t *testing.T, name string, got Result, gotErr error, want Result, wantErr error) {
	t.Helper()
	if !a108ResultsEqual(got, want) {
		t.Fatalf("%s: result differs\n got  %+v\n want %+v", name, got, want)
	}
	switch {
	case wantErr == nil && gotErr != nil:
		t.Fatalf("%s: unexpected error: %v", name, gotErr)
	case wantErr != nil && gotErr == nil:
		t.Fatalf("%s: missing error, want %v", name, wantErr)
	case wantErr != nil && gotErr != nil:
		var wantFile, gotFile *FileError
		if !errors.As(wantErr, &wantFile) || !errors.As(gotErr, &gotFile) {
			t.Fatalf("%s: error types differ: got %T, want %T", name, gotErr, wantErr)
		}
		if *gotFile != *wantFile {
			t.Fatalf("%s: failure differs: got %+v, want %+v", name, gotFile, wantFile)
		}
		if gotErr.Error() != wantErr.Error() {
			t.Fatalf("%s: error text differs: got %q, want %q", name, gotErr, wantErr)
		}
	}
}

func TestA108ParserChunking(t *testing.T) {
	corpora := []struct {
		name  string
		input string
	}{
		{"mixed records", a108PropertyCorpus()},
		{"abort with unclosed quote", a108AbortCorpus()},
		{"header only", a108FullHeader + "\r\n"},
	}
	// Literal cuts ratified by the handoff (§5.1) plus the reader buffer boundary.
	// The literal sizes are pinned as data, never derived from readChunkBytes: a
	// changed buffer constant must not silently move the exercised cuts.
	chunkSizes := []int{1, 2, 7, 4095, 4096, 4097, readChunkBytes - 1, readChunkBytes, readChunkBytes + 1}
	if readChunkBytes != 8192 {
		t.Fatalf("readChunkBytes = %d, want the ratified 8192", readChunkBytes)
	}
	for _, corpus := range corpora {
		t.Run(corpus.name, func(t *testing.T) {
			// Independent oracle: the expectation is rebuilt from the literal bytes
			// of the corpus, not read back from a whole-buffer parse of the same
			// reader path. a108ExpectedCorpusAccounting below is the literal contract
			// of each corpus.
			want, wantErr := a108IndependentExpectation(t, corpus.name, corpus.input)
			for _, size := range chunkSizes {
				reader := &a108ChunkReader{data: []byte(corpus.input), n: size}
				got, gotErr := ParsePrismaV1(reader)
				requireA108SameResult(t, corpus.name, got, gotErr, want, wantErr)
			}
		})
	}

	t.Run("cuts inside utf8 and escapes", func(t *testing.T) {
		// Every byte boundary of a small multibyte corpus is exercised: the
		// parser must not depend on where a Read call happens to cut. The
		// expectation is built from the literal row, not from a parse.
		const value = "é\"漢\"\r\nx"
		row := a108RowWith(12, value)
		input := a108FullHeader + "\r\n" + row + "\r\n"
		want := a108RebuildFromLiterals(t, "cut corpus", []a108CorpusRecord{{row: row}})
		for size := 1; size <= 3; size++ {
			reader := &a108ChunkReader{data: []byte(input), n: size}
			got, gotErr := ParsePrismaV1(reader)
			requireA108SameResult(t, "cut corpus", got, gotErr, want, nil)
		}
	})

	t.Run("randomized chunk sizes are deterministic", func(t *testing.T) {
		input := a108PropertyCorpus()
		want := a108RebuildFromLiterals(t, "random chunk size", a108MixedCorpusRecords())
		rng := rand.New(rand.NewSource(20260929))
		for i := 0; i < 25; i++ {
			size := 1 + rng.Intn(3*readChunkBytes)
			reader := &a108ChunkReader{data: []byte(input), n: size}
			got, gotErr := ParsePrismaV1(reader)
			requireA108SameResult(t, "random chunk size", got, gotErr, want, nil)
		}
	})
}

// a108FactsWithoutLocator returns the finding with its locator zeroed, so two
// representations of the same logical record can be compared by their facts.
func a108FactsWithoutLocator(f Finding) Finding {
	f.Locator = Locator{}
	return f
}

func TestA108ParserRepresentations(t *testing.T) {
	lf := testHeader + "\n" + testRow + "\n" + a108BadVersion + "\n"
	crlf := testHeader + "\r\n" + testRow + "\r\n" + a108BadVersion + "\r\n"

	lfResult, err := parse(t, lf)
	if err != nil {
		t.Fatalf("lf: unexpected abort: %v", err)
	}
	crlfResult, err := parse(t, crlf)
	if err != nil {
		t.Fatalf("crlf: unexpected abort: %v", err)
	}
	requireA108Accounting(t, lfResult, contract.TerminationFinished, contract.CompletenessPartial, true, 2, 1, 1)
	requireA108Accounting(t, crlfResult, contract.TerminationFinished, contract.CompletenessPartial, true, 2, 1, 1)
	if a108FactsWithoutLocator(lfResult.Findings[0]) != a108FactsWithoutLocator(crlfResult.Findings[0]) {
		t.Fatalf("facts differ between lf and crlf: %+v vs %+v", lfResult.Findings[0], crlfResult.Findings[0])
	}

	// Locators differ exactly by the bytes of the terminators, computed from the
	// literal stream bytes rather than from production constants.
	lfAccepted := a108Locator(testHeader, testRow, "\n")
	if lfResult.Findings[0].Locator != lfAccepted {
		t.Fatalf("lf locator = %+v, want %+v", lfResult.Findings[0].Locator, lfAccepted)
	}
	crlfRejectedStart := uint64(len(testHeader) + 2 + len(testRow) + 2)
	crlfRejected := Locator{Record: 2, StartByte: crlfRejectedStart, EndByte: crlfRejectedStart + uint64(len(a108BadVersion))}
	if got := crlfResult.Rejections[0].Locator; got != crlfRejected {
		t.Fatalf("crlf rejection locator = %+v, want %+v", got, crlfRejected)
	}

	t.Run("duplicating a record adds one occurrence", func(t *testing.T) {
		single := a108FullHeader + "\r\n" + a108FullRow + "\r\n"
		double := single + a108FullRow + "\r\n"
		one, err := parse(t, single)
		if err != nil {
			t.Fatalf("single: unexpected abort: %v", err)
		}
		two, err := parse(t, double)
		if err != nil {
			t.Fatalf("double: unexpected abort: %v", err)
		}
		requireA108Accounting(t, one, contract.TerminationFinished, contract.CompletenessComplete, true, 1, 1, 0)
		requireA108Accounting(t, two, contract.TerminationFinished, contract.CompletenessComplete, true, 2, 2, 0)
		if a108FactsWithoutLocator(two.Findings[0]) != a108FactsWithoutLocator(one.Findings[0]) {
			t.Fatalf("first occurrence changed: %+v vs %+v", two.Findings[0], one.Findings[0])
		}
		if a108FactsWithoutLocator(two.Findings[1]) != a108FactsWithoutLocator(two.Findings[0]) {
			t.Fatalf("duplicated record differs beyond its locator: %+v vs %+v", two.Findings[1], two.Findings[0])
		}
		if two.Findings[1].Locator == two.Findings[0].Locator {
			t.Fatalf("duplicated record kept the same locator: %+v", two.Findings)
		}
	})

	t.Run("removing an empty optional does not fabricate a fact", func(t *testing.T) {
		withEmpty := testHeader + ",severity\r\n" + testRow + ",\r\n"
		without := testHeader + "\r\n" + testRow + "\r\n"
		withResult, err := parse(t, withEmpty)
		if err != nil {
			t.Fatalf("with empty optional: unexpected abort: %v", err)
		}
		withoutResult, err := parse(t, without)
		if err != nil {
			t.Fatalf("without optional: unexpected abort: %v", err)
		}
		requireA108Accounting(t, withResult, contract.TerminationFinished, contract.CompletenessComplete, true, 1, 1, 0)
		requireA108Accounting(t, withoutResult, contract.TerminationFinished, contract.CompletenessComplete, true, 1, 1, 0)
		if withResult.Findings[0].Severity != "" {
			t.Fatalf("empty optional was not kept empty: %q", withResult.Findings[0].Severity)
		}
		if withResult.Findings[0].PackageName != withoutResult.Findings[0].PackageName {
			t.Fatalf("required facts changed with the optional column: %+v vs %+v",
				withResult.Findings[0], withoutResult.Findings[0])
		}
	})

	t.Run("different terminators change locators but not facts", func(t *testing.T) {
		// The same logical stream written with CRLF and with LF must produce the
		// same findings modulo the byte interval, which follows the raw bytes.
		rowValue := "synthetic, value with comma"
		lfRow := a108RowWith(12, rowValue)
		lfInput := a108FullHeader + "\n" + lfRow + "\n"
		crlfInput := a108FullHeader + "\r\n" + lfRow + "\r\n"
		lfParsed, err := parse(t, lfInput)
		if err != nil {
			t.Fatalf("lf: %v", err)
		}
		crlfParsed, err := parse(t, crlfInput)
		if err != nil {
			t.Fatalf("crlf: %v", err)
		}
		if lfParsed.Findings[0].Description != crlfParsed.Findings[0].Description {
			t.Fatalf("fact changed with the terminator: %q vs %q",
				lfParsed.Findings[0].Description, crlfParsed.Findings[0].Description)
		}
		wantLF := a108Locator(a108FullHeader, lfRow, "\n")
		if lfParsed.Findings[0].Locator != wantLF {
			t.Fatalf("lf locator = %+v, want %+v", lfParsed.Findings[0].Locator, wantLF)
		}
		wantCRLF := a108Locator(a108FullHeader, lfRow, "\r\n")
		if crlfParsed.Findings[0].Locator != wantCRLF {
			t.Fatalf("crlf locator = %+v, want %+v", crlfParsed.Findings[0].Locator, wantCRLF)
		}
	})
}

// a108GeneratedCases builds a bounded, reproducible corpus of valid and invalid
// records. The seed is fixed and recorded in the test itself.
func a108GeneratedCases(seed int64, count int) []string {
	rng := rand.New(rand.NewSource(seed))
	validValues := []string{
		"synthetic-package", "pkg-2", "paquete-ñ", "with space", "-dash", ".dot",
	}
	invalidValues := []string{"", " ", "\t", "\u200b", "é\xff"}
	var cases []string
	for i := 0; i < count; i++ {
		switch rng.Intn(4) {
		case 0:
			value := validValues[rng.Intn(len(validValues))]
			cases = append(cases, "1.0,CVE-2026-1234,"+value+",1.2.3,open,registry.example,synthetic/repository")
		case 1:
			value := invalidValues[rng.Intn(len(invalidValues))]
			cases = append(cases, "1.0,CVE-2026-1234,"+value+",1.2.3,open,registry.example,synthetic/repository")
		case 2:
			cases = append(cases, a108BadVersion)
		default:
			cases = append(cases, `1.0,CVE-2026-1234,"quoted, value",1.2.3,open,registry.example,synthetic/repository`)
		}
	}
	return cases
}

// a108ExpectedReason maps each generated record to the rejection reason the
// parser must produce, derived from the record's literal shape — not from a
// parser call. Four record shapes exist in a108GeneratedCases: the bad schema
// version, the quoted value, a valid package name, and the invalid package
// values with their own reasons.
func a108ExpectedReason(t *testing.T, record string) (Reason, bool) {
	t.Helper()
	const prefix = "1.0,CVE-2026-1234,"
	if record == a108BadVersion {
		return ReasonUnsupportedVersion, false
	}
	if !strings.HasPrefix(record, prefix) {
		t.Fatalf("generated record has an unknown shape: %q", record)
	}
	rest := strings.TrimPrefix(record, prefix)
	// The quoted shape has no comma in its value and stays inside quotes.
	if strings.HasPrefix(rest, `"`) {
		return "", true
	}
	value := rest[:strings.Index(rest, ",")]
	switch value {
	case "synthetic-package", "pkg-2", "paquete-ñ", "with space", "-dash", ".dot":
		return "", true
	case "", " ":
		return ReasonRequiredValue, false
	case "\t", "\u200b":
		return ReasonForbiddenText, false
	case "é\xff":
		return ReasonInvalidUTF8, false
	}
	t.Fatalf("generated record carries an unmapped value: %q", value)
	return "", false
}

func TestA108ParserGeneratedCases(t *testing.T) {
	const seed = 20260929
	records := a108GeneratedCases(seed, 120)
	if len(records) != 120 {
		t.Fatalf("generated %d records, want 120", len(records))
	}

	// The expectation of every record is derived from its literal shape: the
	// accepted/rejected classification and the rejection reasons never come from
	// a parser call, so a consistently wrong parser fails this test.
	var builder strings.Builder
	builder.WriteString(testHeader + "\r\n")
	accepted, rejected := uint64(0), uint64(0)
	wantReasons := make([]Reason, 0, len(records))
	for _, record := range records {
		builder.WriteString(record + "\r\n")
		wantReason, accept := a108ExpectedReason(t, record)
		if accept {
			accepted++
			continue
		}
		rejected++
		wantReasons = append(wantReasons, wantReason)
	}

	whole, err := parse(t, builder.String())
	if err != nil {
		t.Fatalf("seed %d: unexpected abort: %v", seed, err)
	}
	wantCompleteness := contract.CompletenessComplete
	if rejected > 0 {
		wantCompleteness = contract.CompletenessPartial
	}
	requireA108Accounting(t, whole, contract.TerminationFinished, wantCompleteness,
		true, uint64(len(records)), accepted, rejected)

	// The batch reasons must equal the literal expectation in order.
	if len(whole.Rejections) != len(wantReasons) {
		t.Fatalf("seed %d: %d rejections, want %d", seed, len(whole.Rejections), len(wantReasons))
	}
	for position, rejection := range whole.Rejections {
		if rejection.Reason != wantReasons[position] {
			t.Fatalf("seed %d: rejection %d reason = %q, want %q", seed, position, rejection.Reason, wantReasons[position])
		}
	}

	// Re-running with the same seed must produce the same corpus: the generator
	// is deterministic and its failures are reproducible from seed alone.
	again := a108GeneratedCases(seed, 120)
	if strings.Join(again, "\n") != strings.Join(records, "\n") {
		t.Fatalf("seed %d: generator is not reproducible", seed)
	}
}
