package casefile

import (
	"bytes"
	"errors"
	"reflect"
	"strings"
	"testing"
)

// testFingerprint is a syntactically valid digest reused by the fixtures.
var testFingerprint = "sha256:" + strings.Repeat("ef", 32)

// validInput returns a declaration that passes every rule of §5.2. Tests
// mutate single fields from this base; the fingerprint pointer is fresh per
// call so a test mutation can never reach another fixture.
func validInput() DecisionInput {
	fingerprint := testFingerprint
	return DecisionInput{
		RiskDecision: DecisionAccepted,
		Owner:        "platform owner",
		Approver:     "security approver",
		Rationale:    "compensating controls reviewed in change CHG-0001",
		Scope: Scope{
			BundleHash:        "sha256:" + strings.Repeat("12", 32),
			SubjectUID:        "018f6d2a-7c1d-4c21-9a10-3f9a1b2c3d4e",
			ContainerName:     "payments-api",
			ContainerClass:    ContainerRegular,
			VulnerabilityID:   "CVE-2026-1234",
			ResultFingerprint: &fingerprint,
		},
		Controls:  []string{"network policy", "read-only filesystem"},
		DecidedAt: "2026-10-04T12:00:00Z",
	}
}

func mustAppend(t *testing.T, book Book, input DecisionInput) Book {
	t.Helper()
	next, err := Append(book, input)
	if err != nil {
		t.Fatalf("Append rejected a valid declaration: %v", err)
	}
	return next
}

func mustEncode(t *testing.T, book Book) []byte {
	t.Helper()
	data, err := Encode(book)
	if err != nil {
		t.Fatalf("Encode rejected a valid book: %v", err)
	}
	return data
}

func TestNewBookAndZeroValue(t *testing.T) {
	book := NewBook()
	records, err := Records(book)
	if err != nil || len(records) != 0 {
		t.Fatalf("empty book: records=%v err=%v", records, err)
	}
	if head, err := HeadHash(book); err != nil || head != "" {
		t.Fatalf("empty book head=%q err=%v", head, err)
	}
	if !bytes.Equal(mustEncode(t, book), []byte(emptyBookDocument)) {
		t.Fatal("empty book is not the empty document")
	}

	var zero Book
	if _, err := Append(zero, validInput()); !IsCode(err, CodeInvalidBook) {
		t.Fatalf("zero Append: %v", err)
	}
	if _, err := Verify(nil); err == nil {
		t.Fatal("Verify of nothing must fail")
	}
	if _, err := Records(zero); !IsCode(err, CodeInvalidBook) {
		t.Fatalf("zero Records: %v", err)
	}
	if _, err := HeadHash(zero); !IsCode(err, CodeInvalidBook) {
		t.Fatalf("zero HeadHash: %v", err)
	}
	if _, err := Encode(zero); !IsCode(err, CodeInvalidBook) {
		t.Fatalf("zero Encode: %v", err)
	}
	if err := Write(zero, discardingWriter{}); !IsCode(err, CodeInvalidBook) {
		t.Fatalf("zero Write: %v", err)
	}
}

func TestDecisionVocabularyClosed(t *testing.T) {
	for _, decision := range []Decision{DecisionAccepted, DecisionDeferred, DecisionRejected} {
		input := validInput()
		input.RiskDecision = decision
		if _, err := Append(NewBook(), input); err != nil {
			t.Fatalf("decision %q rejected: %v", decision, err)
		}
	}
	for _, decision := range []Decision{"", "not_assessed", "Accepted", "ACCEPTED", " accepted", "unknown", "exceptional"} {
		input := validInput()
		input.RiskDecision = decision
		if _, err := Append(NewBook(), input); !IsCode(err, CodeInvalidDecision) {
			t.Fatalf("decision %q admitted: %v", decision, err)
		}
	}
}

func TestDecisionRequiredFields(t *testing.T) {
	mutations := map[string]func(*DecisionInput){
		"owner empty":        func(in *DecisionInput) { in.Owner = "" },
		"owner blank":        func(in *DecisionInput) { in.Owner = "   " },
		"owner long":         func(in *DecisionInput) { in.Owner = strings.Repeat("o", MaxActorBytes+1) },
		"owner control":      func(in *DecisionInput) { in.Owner = "own\x1ber" },
		"approver empty":     func(in *DecisionInput) { in.Approver = "" },
		"approver pad":       func(in *DecisionInput) { in.Approver = "ap\x07prover" },
		"rationale blank":    func(in *DecisionInput) { in.Rationale = " \t\n " },
		"rationale long":     func(in *DecisionInput) { in.Rationale = strings.Repeat("r", MaxRationaleBytes+1) },
		"rationale escape":   func(in *DecisionInput) { in.Rationale = "ok\u200bx" },
		"bundle hash bare":   func(in *DecisionInput) { in.Scope.BundleHash = strings.Repeat("12", 32) },
		"bundle hash upper":  func(in *DecisionInput) { in.Scope.BundleHash = "sha256:" + strings.Repeat("AB", 32) },
		"subject empty":      func(in *DecisionInput) { in.Scope.SubjectUID = "" },
		"subject spaced":     func(in *DecisionInput) { in.Scope.SubjectUID = "uid\u00a01" },
		"container empty":    func(in *DecisionInput) { in.Scope.ContainerName = "" },
		"class unknown":      func(in *DecisionInput) { in.Scope.ContainerClass = "sidecar" },
		"class empty":        func(in *DecisionInput) { in.Scope.ContainerClass = "" },
		"vuln empty":         func(in *DecisionInput) { in.Scope.VulnerabilityID = "" },
		"vuln prefix":        func(in *DecisionInput) { in.Scope.VulnerabilityID = "-cve-1" },
		"vuln space":         func(in *DecisionInput) { in.Scope.VulnerabilityID = "CVE 1234" },
		"fingerprint empty":  func(in *DecisionInput) { in.Scope.ResultFingerprint = new(string) },
		"fingerprint short":  func(in *DecisionInput) { value := "sha256:ab"; in.Scope.ResultFingerprint = &value },
		"decided empty":      func(in *DecisionInput) { in.DecidedAt = "" },
		"decided offset":     func(in *DecisionInput) { in.DecidedAt = "2026-10-04T12:00:00+00:00" },
		"decided fraction":   func(in *DecisionInput) { in.DecidedAt = "2026-10-04T12:00:00.5Z" },
		"expires malformed":  func(in *DecisionInput) { value := "2026-13-01T00:00:00Z"; in.ExpiresAt = &value },
		"supersedes bare":    func(in *DecisionInput) { value := strings.Repeat("cd", 32); in.Supersedes = &value },
		"control empty":      func(in *DecisionInput) { in.Controls = []string{""} },
		"control pad":        func(in *DecisionInput) { in.Controls = []string{" pad"} },
		"control long":       func(in *DecisionInput) { in.Controls = []string{strings.Repeat("c", MaxControlBytes+1)} },
		"too many controls":  func(in *DecisionInput) { in.Controls = make([]string, MaxControls+1) },
		"controls with nils": func(in *DecisionInput) { in.Controls = []string{"ok", ""} },
	}
	for _, decision := range []Decision{DecisionAccepted, DecisionDeferred, DecisionRejected} {
		for name, mutate := range mutations {
			input := validInput()
			input.RiskDecision = decision
			mutate(&input)
			book, err := Append(NewBook(), input)
			if err == nil {
				t.Fatalf("%s with %q admitted", name, decision)
			}
			if book.initialized {
				t.Fatalf("%s returned an admitted book", name)
			}
		}
	}
}

func TestDecisionLayersRemainSeparate(t *testing.T) {
	book := mustAppend(t, mustAppend(t, NewBook(), validInput()), func() DecisionInput {
		input := validInput()
		input.RiskDecision = DecisionDeferred
		return input
	}())
	document := mustEncode(t, book)
	for _, state := range []string{"product_status", "exploitability", "EXCEPCIONABLE", "not_affected", "under_investigation", "conditions_met", "conditions_not_met"} {
		if bytes.Contains(document, []byte(state)) {
			t.Fatalf("document leaks the decision-layer token %q", state)
		}
	}
	recordType := reflect.TypeOf(Record{})
	for _, name := range []string{"ProductStatus", "Exploitability", "Status", "Exception"} {
		if _, found := recordType.FieldByName(name); found {
			t.Fatalf("Record carries the technical field %q", name)
		}
	}
	if _, err := Append(book, validInput()); err != nil {
		t.Fatalf("append stopped being accepted: %v", err)
	}
}

func TestAppendPreservesHistoricalRecords(t *testing.T) {
	book := NewBook()
	for index := 0; index < 3; index++ {
		input := validInput()
		input.Rationale = input.Rationale + string(rune('a'+index))
		book = mustAppend(t, book, input)
	}
	before, err := Records(book)
	if err != nil {
		t.Fatal(err)
	}
	beforeBytes := mustEncode(t, book)
	beforeHashes := make([]string, len(before))
	for index := range before {
		beforeHashes[index] = before[index].Hash
	}

	correction := validInput()
	correction.RiskDecision = DecisionRejected
	correction.Rationale = "corrected decision"
	book = mustAppend(t, book, correction)

	after, err := Records(book)
	if err != nil {
		t.Fatal(err)
	}
	if len(after) != len(before)+1 {
		t.Fatalf("records after append: %d", len(after))
	}
	for index := range before {
		if !bytes.Equal(recordEnvelope(before[index]), recordEnvelope(after[index])) {
			t.Fatalf("record %d changed after a later append", index)
		}
		if after[index].Hash != beforeHashes[index] {
			t.Fatalf("hash of record %d changed", index)
		}
	}
	if !bytes.Equal(mustEncode(t, book), bookDocument(after)) {
		t.Fatal("document and records disagree")
	}
	// The untouched receiver keeps its own bytes.
	if _, err := Verify(beforeBytes); err != nil {
		t.Fatalf("the three-record document stopped verifying: %v", err)
	}
}

func TestAppendAddsExactlyOneRecord(t *testing.T) {
	book := NewBook()
	for index := 0; index < 4; index++ {
		book = mustAppend(t, book, validInput())
		records, err := Records(book)
		if err != nil {
			t.Fatal(err)
		}
		if len(records) != index+1 {
			t.Fatalf("after %d appends the book holds %d records", index+1, len(records))
		}
	}
	// Repeating an input is not deduplication: it adds another record with
	// another sequence and another predecessor.
	base := mustAppend(t, NewBook(), validInput())
	first := mustAppend(t, base, validInput())
	second := mustAppend(t, base, validInput())
	if !bytes.Equal(mustEncode(t, first), mustEncode(t, second)) {
		t.Fatal("equal appends from one base produced different books")
	}
	firstRecords, _ := Records(first)
	baseRecords, _ := Records(base)
	if len(firstRecords) != len(baseRecords)+1 {
		t.Fatal("an append changed the record count by something else than one")
	}
}

func TestAppendDoesNotAliasInputsOrOutputs(t *testing.T) {
	input := validInput()
	book := mustAppend(t, NewBook(), input)

	input.Controls[0] = "mutated after append"
	*input.Scope.ResultFingerprint = "sha256:" + strings.Repeat("ff", 32)
	records, err := Records(book)
	if err != nil {
		t.Fatal(err)
	}
	if records[0].Decision.Controls[0] != "network policy" {
		t.Fatal("the stored controls alias the caller slice")
	}
	if *records[0].Decision.Scope.ResultFingerprint != testFingerprint {
		t.Fatal("the stored fingerprint aliases the caller pointer")
	}

	records[0].Decision.Owner = "rewritten"
	records[0].Decision.Controls[0] = "rewritten"
	again, _ := Records(book)
	if again[0].Decision.Owner == "rewritten" || again[0].Decision.Controls[0] == "rewritten" {
		t.Fatal("Records returned live interior storage")
	}

	// Encode must hand out bytes that alias no interior storage: mutating the
	// returned buffer in place — and comparing a second call against it — cannot
	// alter what the book encodes. A copy-and-mutate on a detached slice, as the
	// previous fixture did, proved nothing.
	data := mustEncode(t, book)
	original := append([]byte{}, data...)
	data[0] = 'X'
	data[len(data)-2] = 'x'
	if !bytes.Equal(mustEncode(t, book), original) {
		t.Fatal("Encode returned mutable shared storage")
	}
	if _, err := Verify(original); err != nil {
		t.Fatalf("original bytes stopped verifying: %v", err)
	}
}

func TestAppendFailureIsAtomicInMemory(t *testing.T) {
	base := mustAppend(t, NewBook(), validInput())
	baseBytes := mustEncode(t, base)
	failures := []DecisionInput{
		{RiskDecision: "", Owner: "o", Approver: "a", Rationale: "r", Scope: validInput().Scope, DecidedAt: "2026-10-04T12:00:00Z"},
		func() DecisionInput { in := validInput(); in.Owner = ""; return in }(),
		func() DecisionInput { in := validInput(); in.DecidedAt = "nope"; return in }(),
		func() DecisionInput { in := validInput(); in.Supersedes = &testFingerprint; return in }(),
		func() DecisionInput {
			in := validInput()
			in.Controls = make([]string, MaxControls+1)
			return in
		}(),
	}
	for index, input := range failures {
		next, err := Append(base, input)
		if err == nil {
			t.Fatalf("failure %d was admitted", index)
		}
		if next.initialized {
			t.Fatalf("failure %d returned an admitted book", index)
		}
		if !bytes.Equal(mustEncode(t, base), baseBytes) {
			t.Fatalf("failure %d changed the receiver", index)
		}
	}
	// The zero-book rejection is atomic as well.
	var zero Book
	if _, err := Append(zero, validInput()); !IsCode(err, CodeInvalidBook) {
		t.Fatalf("zero append: %v", err)
	}
}

func TestRecordSequenceAndGenesis(t *testing.T) {
	book := NewBook()
	for index := 0; index < 5; index++ {
		book = mustAppend(t, book, validInput())
	}
	records, _ := Records(book)
	for index, record := range records {
		if record.Sequence != uint64(index+1) {
			t.Fatalf("record %d carries sequence %d", index, record.Sequence)
		}
		if index == 0 {
			if record.PreviousHash != nil {
				t.Fatal("the first record carries a predecessor")
			}
			continue
		}
		if record.PreviousHash == nil || *record.PreviousHash != records[index-1].Hash {
			t.Fatalf("record %d does not link its immediate predecessor", index)
		}
	}
}

func TestRecordHashCoversEveryField(t *testing.T) {
	base := mustAppend(t, NewBook(), validInput())
	baseRecords, _ := Records(base)
	baseHash := baseRecords[0].Hash

	mutations := map[string]func(*DecisionInput){
		"risk_decision":       func(in *DecisionInput) { in.RiskDecision = DecisionDeferred },
		"owner":               func(in *DecisionInput) { in.Owner = "other owner" },
		"approver":            func(in *DecisionInput) { in.Approver = "other approver" },
		"rationale":           func(in *DecisionInput) { in.Rationale = "other rationale" },
		"bundle_hash":         func(in *DecisionInput) { in.Scope.BundleHash = "sha256:" + strings.Repeat("34", 32) },
		"subject_uid":         func(in *DecisionInput) { in.Scope.SubjectUID = "other-uid" },
		"container_name":      func(in *DecisionInput) { in.Scope.ContainerName = "other-api" },
		"container_class":     func(in *DecisionInput) { in.Scope.ContainerClass = ContainerInit },
		"vulnerability_id":    func(in *DecisionInput) { in.Scope.VulnerabilityID = "CVE-2026-9999" },
		"result_fingerprint":  func(in *DecisionInput) { in.Scope.ResultFingerprint = nil },
		"controls":            func(in *DecisionInput) { in.Controls = nil },
		"controls_order":      func(in *DecisionInput) { in.Controls = []string{"read-only filesystem", "network policy"} },
		"decided_at":          func(in *DecisionInput) { in.DecidedAt = "2026-10-04T12:00:01Z" },
		"expires_at":          func(in *DecisionInput) { value := "2027-01-01T00:00:00Z"; in.ExpiresAt = &value },
		"case_change_subject": func(in *DecisionInput) { in.Scope.SubjectUID = strings.ToUpper(in.Scope.SubjectUID) },
	}
	for name, mutate := range mutations {
		input := validInput()
		mutate(&input)
		book, err := Append(NewBook(), input)
		if err != nil {
			t.Fatalf("mutation %s rejected: %v", name, err)
		}
		records, _ := Records(book)
		if records[0].Hash == baseHash {
			t.Fatalf("mutation %s left the hash unchanged", name)
		}
	}
	// The positive direction above proves every field is inside the preimage; the
	// rejection direction proves the bytes are covered, not merely counted: for
	// each field the canonical envelope is regenerated with the mutation but its
	// own hash member is rewritten back to the base hash, so a verifier that
	// accepted the altered bytes would admit a record whose hash lies about its
	// content.
	for name, mutate := range mutations {
		input := validInput()
		mutate(&input)
		document := string(mustEncode(t, mustAppend(t, NewBook(), input)))
		// Positive control: the mutated record with its own coherent hash must
		// verify, so the hash_mismatch below is attributable to the altered
		// bytes alone, not to some other inconsistency the mutation introduced.
		if _, err := Verify([]byte(document)); err != nil {
			t.Fatalf("mutation %s: coherent envelope rejected: %v", name, err)
		}
		hashStart := strings.LastIndex(document, `"hash":"`) + len(`"hash":"`)
		if hashStart < len(`"hash":"`) {
			t.Fatalf("mutation %s: hash member not found", name)
		}
		rewritten := document[:hashStart] + baseHash + document[hashStart+len(baseHash):]
		if _, verr := Verify([]byte(rewritten)); !IsCode(verr, CodeHashMismatch) {
			t.Fatalf("mutation %s: altered bytes with the base hash were not rejected: %v", name, verr)
		}
	}
	// The supersedes reference lives only on a later record: its presence and
	// absence must change that record's hash.
	head := mustAppend(t, NewBook(), validInput())
	headRecords, _ := Records(head)
	headHash := headRecords[0].Hash
	withReference := validInput()
	withReference.Supersedes = &headHash
	superseding := mustAppend(t, head, withReference)
	plain := validInput()
	without := mustAppend(t, head, plain)
	supersedingRecords, _ := Records(superseding)
	withoutRecords, _ := Records(without)
	if supersedingRecords[1].Hash == withoutRecords[1].Hash {
		t.Fatal("the supersedes reference is outside the preimage")
	}
}

func TestSupersedesReferenceWithoutInvalidation(t *testing.T) {
	first := mustAppend(t, NewBook(), validInput())
	firstRecords, _ := Records(first)
	firstHash := firstRecords[0].Hash

	correction := validInput()
	correction.RiskDecision = DecisionRejected
	correction.Rationale = "superseding declaration"
	correction.Supersedes = &firstHash
	book := mustAppend(t, first, correction)

	records, _ := Records(book)
	if len(records) != 2 {
		t.Fatalf("the superseded record disappeared: %d records", len(records))
	}
	if records[0].Hash != firstHash {
		t.Fatal("the superseded record changed")
	}
	if records[1].Decision.Supersedes == nil || *records[1].Decision.Supersedes != firstHash {
		t.Fatal("the superseding record lost its reference")
	}
	if !bytes.Equal(mustEncode(t, book), bookDocument(records)) {
		t.Fatal("document disagrees with records")
	}

	unknown := "sha256:" + strings.Repeat("99", 32)
	input := validInput()
	input.Supersedes = &unknown
	if _, err := Append(first, input); !IsCode(err, CodeInvalidReference) {
		t.Fatalf("unknown supersedes admitted: %v", err)
	}
	genesis := validInput()
	genesis.Supersedes = &unknown
	if _, err := Append(NewBook(), genesis); !IsCode(err, CodeInvalidReference) {
		t.Fatalf("supersedes without history admitted: %v", err)
	}
}

func TestControlsPreserveOrderAndDuplicates(t *testing.T) {
	input := validInput()
	input.Controls = []string{"b control", "a control", "b control", "c control"}
	book := mustAppend(t, NewBook(), input)
	records, _ := Records(book)
	got := records[0].Decision.Controls
	if len(got) != 4 || got[0] != "b control" || got[1] != "a control" || got[2] != "b control" || got[3] != "c control" {
		t.Fatalf("controls were reordered or deduplicated: %v", got)
	}
	absent := validInput()
	absent.Controls = nil
	empty := validInput()
	empty.Controls = []string{}
	if !bytes.Equal(mustEncode(t, mustAppend(t, NewBook(), absent)), mustEncode(t, mustAppend(t, NewBook(), empty))) {
		t.Fatal("nil and empty controls diverge on the wire")
	}
	if !bytes.Contains(mustEncode(t, book), []byte(`"controls":["b control","a control","b control","c control"]`)) {
		t.Fatal("the document does not carry the controls verbatim")
	}
}

func TestCasefileDeterminism(t *testing.T) {
	build := func() []byte {
		book := NewBook()
		for index := 0; index < 4; index++ {
			input := validInput()
			input.Rationale = input.Rationale + string(rune('a'+index))
			if index%2 == 0 {
				input.RiskDecision = DecisionDeferred
			} else {
				input.RiskDecision = DecisionRejected
			}
			book = mustAppend(t, book, input)
		}
		return mustEncode(t, book)
	}
	first := build()
	for attempt := 0; attempt < 8; attempt++ {
		if !bytes.Equal(build(), first) {
			t.Fatalf("build %d diverged", attempt)
		}
	}
	back, err := Verify(first)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(mustEncode(t, back), first) {
		t.Fatal("verify-encode roundtrip diverged")
	}
}

func TestVerifyDocumentsUnanchoredHistoryLimits(t *testing.T) {
	book := NewBook()
	for index := 0; index < 3; index++ {
		book = mustAppend(t, book, validInput())
	}
	threeRecords := mustEncode(t, book)
	if _, err := Verify(threeRecords); err != nil {
		t.Fatal(err)
	}

	// A coherently rebuilt shorter book is a valid book: the chain proves
	// internal consistency, never completeness of the delivered history.
	oneRecord := mustEncode(t, mustAppend(t, NewBook(), validInput()))
	if _, err := Verify(oneRecord); err != nil {
		t.Fatalf("a legitimate prefix book must verify: %v", err)
	}

	// Removing the last record of the document yields another valid book;
	// internal verification cannot detect the truncation and must not claim to.
	cut := bytes.LastIndex(threeRecords, []byte(`,{"format":"`+RecordFormat))
	truncated := append(append([]byte{}, threeRecords[:cut]...), ']', '}')
	if _, err := Verify(truncated); err != nil {
		t.Fatalf("suffix removal is undetectable by design, got: %v", err)
	}

	// Two branches from one base are both valid; the library does not referee.
	base := mustAppend(t, NewBook(), validInput())
	left := validInput()
	left.RiskDecision = DecisionDeferred
	right := validInput()
	right.RiskDecision = DecisionRejected
	if _, err := Verify(mustEncode(t, mustAppend(t, base, left))); err != nil {
		t.Fatal(err)
	}
	if _, err := Verify(mustEncode(t, mustAppend(t, base, right))); err != nil {
		t.Fatal(err)
	}
}

type discardingWriter struct{}

func (discardingWriter) Write(p []byte) (int, error) { return len(p), nil }

type failingWriter struct {
	Err error
}

func (writer failingWriter) Write([]byte) (int, error) { return 0, writer.Err }

type shortWriter struct {
	Count int
}

func (writer shortWriter) Write([]byte) (int, error) { return writer.Count, nil }

type countedWriter struct {
	Calls int
	Data  []byte
}

func (writer *countedWriter) Write(p []byte) (int, error) {
	writer.Calls++
	writer.Data = append(writer.Data, p...)
	return len(p), nil
}

var errDestination = errors.New("synthetic destination failure")
