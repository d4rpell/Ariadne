package casefile

import (
	"bytes"
	"reflect"
	"strings"
	"testing"
)

// declaration builds a valid declaration for the assessment tests. Only the
// vulnerability identifier, the decision time and the optional expiry vary;
// every other field keeps the shape of validInput.
func declaration(vuln, decided string, expires *string) DecisionInput {
	input := validInput()
	input.Scope.VulnerabilityID = vuln
	input.DecidedAt = decided
	input.ExpiresAt = expires
	return input
}

func stamp(value string) *string { return &value }

// appendDeclaration appends one declaration and returns the new book with the
// hash of the record just added.
func appendDeclaration(t *testing.T, book Book, input DecisionInput) (Book, string) {
	t.Helper()
	next := mustAppend(t, book, input)
	head, err := HeadHash(next)
	if err != nil {
		t.Fatal(err)
	}
	return next, head
}

func entriesOf(t *testing.T, book Book, asOf string) []Entry {
	t.Helper()
	view, err := Assess(book, asOf)
	if err != nil {
		t.Fatalf("Assess rejected a valid book: %v", err)
	}
	entries, err := view.Entries()
	if err != nil {
		t.Fatalf("Entries failed: %v", err)
	}
	return entries
}

func entry(t *testing.T, book Book, asOf, hash string) Entry {
	t.Helper()
	for _, candidate := range entriesOf(t, book, asOf) {
		if candidate.Hash == hash {
			return candidate
		}
	}
	t.Fatalf("no entry with hash %s", hash)
	return Entry{}
}

func TestAssessEmptyBook(t *testing.T) {
	view, err := Assess(NewBook(), "2026-03-01T00:00:00Z")
	if err != nil {
		t.Fatalf("Assess on the empty book failed: %v", err)
	}
	entries, err := view.Entries()
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatalf("the empty book produced %d entries", len(entries))
	}
}

func TestAssessStandingMatrix(t *testing.T) {
	asOf := "2026-03-01T00:00:00Z"
	book := NewBook()
	book, effective := appendDeclaration(t, book, declaration("CVE-A", "2026-01-01T00:00:00Z", stamp("2026-06-01T00:00:00Z")))
	book, expired := appendDeclaration(t, book, declaration("CVE-B", "2026-01-01T00:00:00Z", stamp("2026-02-01T00:00:00Z")))
	book, pending := appendDeclaration(t, book, declaration("CVE-C", "2026-12-01T00:00:00Z", nil))
	book, superseded := appendDeclaration(t, book, declaration("CVE-D", "2026-01-01T00:00:00Z", nil))
	book, successor := appendDeclaration(t, book, func() DecisionInput {
		input := declaration("CVE-D", "2026-02-01T00:00:00Z", nil)
		input.RiskDecision = DecisionRejected
		input.Supersedes = &superseded
		return input
	}())

	want := map[string]Standing{
		effective:  StandingEffective,
		expired:    StandingExpired,
		pending:    StandingPending,
		superseded: StandingSuperseded,
		successor:  StandingEffective,
	}
	for hash, standing := range want {
		if got := entry(t, book, asOf, hash).Standing; got != standing {
			t.Fatalf("record %s: standing %s, want %s", hash, got, standing)
		}
	}
}

func TestAssessPrecedence(t *testing.T) {
	asOf := "2026-03-01T00:00:00Z"

	// pending wins over expired: the declaration has not started yet.
	book := NewBook()
	book, hash := appendDeclaration(t, book, declaration("CVE-A", "2026-12-01T00:00:00Z", stamp("2026-02-01T00:00:00Z")))
	if got := entry(t, book, asOf, hash).Standing; got != StandingPending {
		t.Fatalf("pending+expired: standing %s, want pending", got)
	}

	// superseded wins over expired: a successor is more informative.
	book = NewBook()
	book, first := appendDeclaration(t, book, declaration("CVE-B", "2026-01-01T00:00:00Z", stamp("2026-02-01T00:00:00Z")))
	input := declaration("CVE-B", "2026-01-15T00:00:00Z", nil)
	input.Supersedes = &first
	book, _ = appendDeclaration(t, book, input)
	if got := entry(t, book, asOf, first).Standing; got != StandingSuperseded {
		t.Fatalf("superseded+expired: standing %s, want superseded", got)
	}
}

func TestAssessSupersedesDirect(t *testing.T) {
	asOf := "2026-03-01T00:00:00Z"
	book := NewBook()
	book, first := appendDeclaration(t, book, declaration("CVE-A", "2026-01-01T00:00:00Z", nil))
	input := declaration("CVE-A", "2026-02-01T00:00:00Z", nil)
	input.Supersedes = &first
	book, second := appendDeclaration(t, book, input)

	got := entry(t, book, asOf, first)
	if got.Standing != StandingSuperseded {
		t.Fatalf("predecessor standing %s, want superseded", got.Standing)
	}
	if got.SupersededBy == nil || *got.SupersededBy != second {
		t.Fatalf("SupersededBy %v, want %s", got.SupersededBy, second)
	}
	if successor := entry(t, book, asOf, second); successor.Standing != StandingEffective {
		t.Fatalf("successor standing %s, want effective", successor.Standing)
	}
}

func TestAssessSupersedesTransitive(t *testing.T) {
	asOf := "2026-03-01T00:00:00Z"
	book := NewBook()
	book, first := appendDeclaration(t, book, declaration("CVE-A", "2026-01-01T00:00:00Z", nil))
	input2 := declaration("CVE-A", "2026-02-01T00:00:00Z", nil)
	input2.Supersedes = &first
	book, second := appendDeclaration(t, book, input2)
	input3 := declaration("CVE-A", "2026-02-15T00:00:00Z", nil)
	input3.Supersedes = &second
	book, _ = appendDeclaration(t, book, input3)

	got := entry(t, book, asOf, first)
	if got.Standing != StandingSuperseded {
		t.Fatalf("transitive predecessor standing %s, want superseded", got.Standing)
	}
	if got.SupersededBy == nil || *got.SupersededBy != second {
		t.Fatalf("SupersededBy %v, want the direct successor %s", got.SupersededBy, second)
	}
}

func TestAssessSupersededByExpiredSuccessor(t *testing.T) {
	asOf := "2026-03-01T00:00:00Z"
	book := NewBook()
	book, first := appendDeclaration(t, book, declaration("CVE-A", "2026-01-01T00:00:00Z", stamp("2026-02-01T00:00:00Z")))
	input := declaration("CVE-A", "2026-01-15T00:00:00Z", stamp("2026-02-01T00:00:00Z"))
	input.Supersedes = &first
	book, second := appendDeclaration(t, book, input)

	if got := entry(t, book, asOf, first); got.Standing != StandingSuperseded {
		t.Fatalf("predecessor standing %s, want superseded even when the successor expired", got.Standing)
	}
	if got := entry(t, book, asOf, second); got.Standing != StandingExpired {
		t.Fatalf("successor standing %s, want expired", got.Standing)
	}
}

func TestAssessActivationPerEdge(t *testing.T) {
	book := NewBook()
	book, first := appendDeclaration(t, book, declaration("CVE-A", "2026-01-01T00:00:00Z", nil))
	input2 := declaration("CVE-A", "2026-03-01T00:00:00Z", nil)
	input2.Supersedes = &first
	book, second := appendDeclaration(t, book, input2)
	input3 := declaration("CVE-A", "2026-02-01T00:00:00Z", nil)
	input3.Supersedes = &second
	book, third := appendDeclaration(t, book, input3)

	asOf := "2026-02-01T00:00:00Z"
	if got := entry(t, book, asOf, first).Standing; got != StandingEffective {
		t.Fatalf("first standing %s, want effective (its only successor is future-dated)", got)
	}
	if got := entry(t, book, asOf, second).Standing; got != StandingPending {
		t.Fatalf("second standing %s, want pending", got)
	}
	if got := entry(t, book, asOf, third).Standing; got != StandingEffective {
		t.Fatalf("third standing %s, want effective", got)
	}
}

func TestAssessSupersedesFutureDated(t *testing.T) {
	asOf := "2026-03-01T00:00:00Z"
	book := NewBook()
	book, first := appendDeclaration(t, book, declaration("CVE-A", "2026-01-01T00:00:00Z", nil))
	input := declaration("CVE-A", "2026-05-01T00:00:00Z", nil)
	input.Supersedes = &first
	book, second := appendDeclaration(t, book, input)

	if got := entry(t, book, asOf, first).Standing; got != StandingEffective {
		t.Fatalf("predecessor standing %s, want effective before the edge activates", got)
	}
	if got := entry(t, book, asOf, second).Standing; got != StandingPending {
		t.Fatalf("future successor standing %s, want pending", got)
	}
}

func TestAssessDecidedAtEqualsAsOf(t *testing.T) {
	asOf := "2026-03-01T00:00:00Z"
	book := NewBook()
	book, first := appendDeclaration(t, book, declaration("CVE-A", "2026-01-01T00:00:00Z", nil))
	input := declaration("CVE-A", asOf, nil)
	input.Supersedes = &first
	book, second := appendDeclaration(t, book, input)

	if got := entry(t, book, asOf, first); got.Standing != StandingSuperseded {
		t.Fatalf("predecessor standing %s, want superseded (edge is inclusive)", got.Standing)
	}
	if got := entry(t, book, asOf, second); got.Standing != StandingEffective {
		t.Fatalf("successor standing %s, want effective at its own decided_at", got.Standing)
	}
}

func TestAssessSupersedesSubjectMismatch(t *testing.T) {
	asOf := "2026-03-01T00:00:00Z"
	book := NewBook()
	book, first := appendDeclaration(t, book, declaration("CVE-A", "2026-01-01T00:00:00Z", nil))
	input := declaration("CVE-B", "2026-02-01T00:00:00Z", nil)
	input.Supersedes = &first
	book, second := appendDeclaration(t, book, input)

	if got := entry(t, book, asOf, first).Standing; got != StandingEffective {
		t.Fatalf("cross-subject reference invalidated the predecessor: standing %s", got)
	}
	successor := entry(t, book, asOf, second)
	if !hasAnomaly(successor, AnomalySupersedesSubjectMismatch) {
		t.Fatalf("successor missing supersedes_subject_mismatch: %v", successor.Anomalies)
	}
}

func TestAssessAmbiguousSupersession(t *testing.T) {
	book := NewBook()
	book, first := appendDeclaration(t, book, declaration("CVE-A", "2026-01-01T00:00:00Z", nil))
	input2 := declaration("CVE-A", "2026-02-01T00:00:00Z", nil)
	input2.Supersedes = &first
	book, second := appendDeclaration(t, book, input2)
	input3 := declaration("CVE-A", "2026-03-01T00:00:00Z", nil)
	input3.Supersedes = &first
	book, third := appendDeclaration(t, book, input3)

	ambiguous := entry(t, book, "2026-03-15T00:00:00Z", first)
	if !hasAnomaly(ambiguous, AnomalyAmbiguousSupersession) {
		t.Fatalf("expected ambiguous_supersession at the later instant: %v", ambiguous.Anomalies)
	}
	if ambiguous.SupersededBy == nil || *ambiguous.SupersededBy != second {
		t.Fatalf("SupersededBy %v, want the lowest-sequence successor %s", ambiguous.SupersededBy, second)
	}

	single := entry(t, book, "2026-02-15T00:00:00Z", first)
	if hasAnomaly(single, AnomalyAmbiguousSupersession) {
		t.Fatalf("ambiguous_supersession present when only one successor is admissible: %v", single.Anomalies)
	}
	if single.SupersededBy == nil || *single.SupersededBy != second {
		t.Fatalf("SupersededBy %v, want %s", single.SupersededBy, second)
	}
	_ = third
}

func TestAssessSubjectComponentIsolation(t *testing.T) {
	base := validInput().Scope
	baseSubject := SubjectOf(base)
	variants := map[string]Scope{}
	uid := base
	uid.SubjectUID = "other-uid"
	variants["uid"] = uid
	name := base
	name.ContainerName = "other-container"
	variants["name"] = name
	class := base
	class.ContainerClass = ContainerInit
	variants["class"] = class
	vuln := base
	vuln.VulnerabilityID = "CVE-2026-9999"
	variants["vulnerability"] = vuln

	if SubjectOf(base) != baseSubject {
		t.Fatal("SubjectOf is not stable for an identical scope")
	}
	for label, scope := range variants {
		if SubjectOf(scope) == baseSubject {
			t.Fatalf("changing %s did not change the Subject", label)
		}
	}
	// Bundle hash and fingerprint are not part of the continuity key.
	ignored := base
	ignored.BundleHash = "sha256:" + strings.Repeat("00", 32)
	ignored.ResultFingerprint = stamp("sha256:" + strings.Repeat("aa", 32))
	if SubjectOf(ignored) != baseSubject {
		t.Fatal("Subject must ignore the bundle hash and the result fingerprint")
	}
}

func TestAssessExpiryBoundary(t *testing.T) {
	book := NewBook()
	book, hash := appendDeclaration(t, book, declaration("CVE-A", "2026-01-01T00:00:00Z", stamp("2026-06-01T00:00:00Z")))
	if got := entry(t, book, "2026-06-01T00:00:00Z", hash).Standing; got != StandingExpired {
		t.Fatalf("at expires_at: standing %s, want expired (inclusive)", got)
	}
	if got := entry(t, book, "2026-05-31T23:59:59Z", hash).Standing; got != StandingEffective {
		t.Fatalf("one second before expires_at: standing %s, want effective", got)
	}
}

func TestAssessExpiredAndEffectiveCoexist(t *testing.T) {
	asOf := "2026-03-01T00:00:00Z"
	book := NewBook()
	book, expiredHash := appendDeclaration(t, book, declaration("CVE-A", "2026-01-01T00:00:00Z", stamp("2026-02-01T00:00:00Z")))
	book, effectiveHash := appendDeclaration(t, book, declaration("CVE-A", "2026-01-01T00:00:00Z", nil))

	if got := entry(t, book, asOf, expiredHash).Standing; got != StandingExpired {
		t.Fatalf("first standing %s, want expired", got)
	}
	if got := entry(t, book, asOf, effectiveHash).Standing; got != StandingEffective {
		t.Fatalf("second standing %s, want effective", got)
	}
	view, err := Assess(book, asOf)
	if err != nil {
		t.Fatal(err)
	}
	query := SubjectOf(validInput().Scope)
	query.VulnerabilityID = "CVE-A"
	candidates, err := view.Candidates(query)
	if err != nil {
		t.Fatal(err)
	}
	if len(candidates) != 1 || candidates[0].Hash != effectiveHash {
		t.Fatalf("Candidates %+v, want only the effective record", candidates)
	}
}

func TestAssessCandidatesQuery(t *testing.T) {
	asOf := "2026-03-01T00:00:00Z"
	subject := SubjectOf(validInput().Scope)

	empty := NewBook()
	view, err := Assess(empty, asOf)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := view.Candidates(subject); err != nil || len(got) != 0 {
		t.Fatalf("empty book: candidates %v, err %v", got, err)
	}

	one := NewBook()
	one, _ = appendDeclaration(t, one, declaration("CVE-2026-1234", "2026-01-01T00:00:00Z", nil))
	view, _ = Assess(one, asOf)
	if got, _ := view.Candidates(subject); len(got) != 1 {
		t.Fatalf("one effective record: candidates %d, want 1", len(got))
	}

	two := NewBook()
	two, _ = appendDeclaration(t, two, declaration("CVE-2026-1234", "2026-01-01T00:00:00Z", nil))
	two, _ = appendDeclaration(t, two, declaration("CVE-2026-1234", "2026-02-01T00:00:00Z", nil))
	view, _ = Assess(two, asOf)
	got, err := view.Candidates(subject)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Fatalf("two effective records: candidates %d, want 2 (no collapse)", len(got))
	}
	if got[0].Scope.BundleHash == "" || got[0].Scope.ResultFingerprint == nil {
		t.Fatal("candidate Entry must conserve the full Scope")
	}
}

func TestAssessPendingNotCandidate(t *testing.T) {
	asOf := "2026-03-01T00:00:00Z"
	book := NewBook()
	book, _ = appendDeclaration(t, book, declaration("CVE-2026-1234", "2026-12-01T00:00:00Z", nil))
	view, err := Assess(book, asOf)
	if err != nil {
		t.Fatal(err)
	}
	if got, _ := view.Candidates(SubjectOf(validInput().Scope)); len(got) != 0 {
		t.Fatalf("a pending record must not be a candidate: %v", got)
	}
}

func TestAssessDecisionsConserved(t *testing.T) {
	asOf := "2026-03-01T00:00:00Z"
	book := NewBook()
	book, accepted := appendDeclaration(t, book, declaration("CVE-A", "2026-01-01T00:00:00Z", nil))
	deferredInput := declaration("CVE-B", "2026-01-01T00:00:00Z", nil)
	deferredInput.RiskDecision = DecisionDeferred
	book, deferred := appendDeclaration(t, book, deferredInput)
	rejectedInput := declaration("CVE-C", "2026-01-01T00:00:00Z", nil)
	rejectedInput.RiskDecision = DecisionRejected
	book, rejected := appendDeclaration(t, book, rejectedInput)

	want := map[string]Decision{accepted: DecisionAccepted, deferred: DecisionDeferred, rejected: DecisionRejected}
	for hash, decision := range want {
		if got := entry(t, book, asOf, hash).Decision; got != decision {
			t.Fatalf("record %s: decision %s, want %s", hash, got, decision)
		}
	}
}

func TestAssessRejectsInvalidBook(t *testing.T) {
	if _, err := Assess(Book{}, "2026-03-01T00:00:00Z"); !IsCode(err, CodeInvalidBook) {
		t.Fatalf("zero book: err %v, want invalid_book", err)
	}

	book := NewBook()
	book, _ = appendDeclaration(t, book, declaration("CVE-A", "2026-01-01T00:00:00Z", nil))
	records, err := Records(book)
	if err != nil {
		t.Fatal(err)
	}
	records[0].Hash = "sha256:" + strings.Repeat("00", 32)
	broken := Book{initialized: true, records: records}
	if _, err := Assess(broken, "2026-03-01T00:00:00Z"); !IsCode(err, CodeHashMismatch) {
		t.Fatalf("tampered chain: err %v, want hash_mismatch", err)
	}
}

func TestAssessRejectsInvalidAsOf(t *testing.T) {
	book := NewBook()
	book, _ = appendDeclaration(t, book, declaration("CVE-A", "2026-01-01T00:00:00Z", nil))
	for _, bad := range []string{"", "2026-13-01T00:00:00Z", "2026-03-01T00:00:00", "2026-03-01t00:00:00z"} {
		if _, err := Assess(book, bad); !IsCode(err, CodeInvalidTimestamp) {
			t.Fatalf("as_of %q: err %v, want invalid_timestamp", bad, err)
		}
	}
}

func TestAssessInvalidViewQueries(t *testing.T) {
	var view View
	if _, err := view.Entries(); !IsCode(err, CodeInvalidBook) {
		t.Fatalf("zero view Entries: err %v, want invalid_book", err)
	}
	if _, err := view.Candidates(Subject{}); !IsCode(err, CodeInvalidBook) {
		t.Fatalf("zero view Candidates: err %v, want invalid_book", err)
	}
}

func TestAssessDeepCopy(t *testing.T) {
	asOf := "2026-03-01T00:00:00Z"
	book := NewBook()
	book, first := appendDeclaration(t, book, declaration("CVE-A", "2026-01-01T00:00:00Z", stamp("2026-02-01T00:00:00Z")))
	input := declaration("CVE-A", "2026-01-15T00:00:00Z", nil)
	input.Supersedes = &first
	book, _ = appendDeclaration(t, book, input)

	view, err := Assess(book, asOf)
	if err != nil {
		t.Fatal(err)
	}
	entries, err := view.Entries()
	if err != nil {
		t.Fatal(err)
	}
	target := -1
	for index := range entries {
		if entries[index].Hash == first {
			target = index
		}
	}
	if target < 0 || entries[target].SupersededBy == nil {
		t.Fatal("expected the superseded record first")
	}
	*entries[target].SupersededBy = "mutated"
	entries[target].Anomalies = append(entries[target].Anomalies, AnomalyAmbiguousSupersession)
	if entries[target].ExpiresAt != nil {
		*entries[target].ExpiresAt = "mutated"
	}
	entries[target].Scope.SubjectUID = "mutated"

	again, err := view.Entries()
	if err != nil {
		t.Fatal(err)
	}
	if *again[target].SupersededBy == "mutated" || again[target].Scope.SubjectUID == "mutated" {
		t.Fatal("mutating a returned Entry affected the view")
	}
	for _, anomaly := range again[target].Anomalies {
		if anomaly == AnomalyAmbiguousSupersession {
			t.Fatal("mutating a returned Anomalies slice affected the view")
		}
	}
}

func TestAssessDeterministic(t *testing.T) {
	asOf := "2026-03-01T00:00:00Z"
	book := NewBook()
	book, first := appendDeclaration(t, book, declaration("CVE-A", "2026-01-01T00:00:00Z", nil))
	input := declaration("CVE-A", "2026-02-01T00:00:00Z", nil)
	input.Supersedes = &first
	book, _ = appendDeclaration(t, book, input)

	before := mustEncode(t, book)
	firstView, err := Assess(book, asOf)
	if err != nil {
		t.Fatal(err)
	}
	secondView, err := Assess(book, asOf)
	if err != nil {
		t.Fatal(err)
	}
	firstEntries, _ := firstView.Entries()
	secondEntries, _ := secondView.Entries()
	if !reflect.DeepEqual(firstEntries, secondEntries) {
		t.Fatal("Assess is not deterministic")
	}
	subject := SubjectOf(validInput().Scope)
	subject.VulnerabilityID = "CVE-A"
	firstCandidates, _ := firstView.Candidates(subject)
	secondCandidates, _ := secondView.Candidates(subject)
	if !reflect.DeepEqual(firstCandidates, secondCandidates) {
		t.Fatal("Candidates is not deterministic")
	}
	if !bytes.Equal(before, mustEncode(t, book)) {
		t.Fatal("Assess mutated the book")
	}
}

// TestAssessPendingRetainsAdmissibleRelations covers contract §2.3/§3.3: a
// record that has not started still carries its admissible successors and their
// ambiguity, because those are computed independently of the standing.
func TestAssessPendingRetainsAdmissibleRelations(t *testing.T) {
	book, root := appendDeclaration(t, NewBook(), declaration("CVE-A", "2026-01-03T00:00:00Z", nil))

	first := declaration("CVE-A", "2026-01-01T00:00:00Z", nil)
	first.Supersedes = &root
	book, firstHash := appendDeclaration(t, book, first)

	second := declaration("CVE-A", "2026-01-02T00:00:00Z", nil)
	second.Supersedes = &root
	book, _ = appendDeclaration(t, book, second)

	got := entry(t, book, "2026-01-02T00:00:00Z", root)
	if got.Standing != StandingPending {
		t.Fatalf("standing = %s, want pending", got.Standing)
	}
	if !hasAnomaly(got, AnomalyAmbiguousSupersession) {
		t.Errorf("missing ambiguity for two admissible successors: %v", got.Anomalies)
	}
	if got.SupersededBy == nil || *got.SupersededBy != firstHash {
		t.Errorf("SupersededBy = %v, want %s", got.SupersededBy, firstHash)
	}
}

// TestAssessQueryCopiesAllMutableFields mutates every mutable field of Entries
// and Candidates results against an independently admitted view.
func TestAssessQueryCopiesAllMutableFields(t *testing.T) {
	const asOf = "2026-03-01T00:00:00Z"
	expires := "2026-12-01T00:00:00Z"

	book, root := appendDeclaration(t, NewBook(), declaration("CVE-A", "2026-01-01T00:00:00Z", &expires))

	cross := declaration("CVE-B", "2026-01-02T00:00:00Z", &expires)
	cross.Supersedes = &root
	book, _ = appendDeclaration(t, book, cross)

	successor := declaration("CVE-A", "2026-01-03T00:00:00Z", &expires)
	successor.Supersedes = &root
	book, _ = appendDeclaration(t, book, successor)
	raw := mustEncode(t, book)

	queries := map[string]func(View) ([]Entry, error){
		"Entries": func(v View) ([]Entry, error) { return v.Entries() },
		"Candidates": func(v View) ([]Entry, error) {
			return v.Candidates(SubjectOf(cross.Scope))
		},
	}
	for name, query := range queries {
		t.Run(name, func(t *testing.T) {
			fresh := func() (Book, View) {
				parsed, err := Verify(raw)
				if err != nil {
					t.Fatal(err)
				}
				view, err := Assess(parsed, asOf)
				if err != nil {
					t.Fatal(err)
				}
				return parsed, view
			}
			original, view := fresh()
			_, independent := fresh()
			want, err := query(independent)
			if err != nil {
				t.Fatal(err)
			}
			got, err := query(view)
			if err != nil || len(got) == 0 {
				t.Fatalf("query: entries=%v err=%v", got, err)
			}
			for index := range got {
				got[index].Hash = "changed"
				got[index].Scope.BundleHash = "changed"
				if pointer := got[index].Scope.ResultFingerprint; pointer != nil {
					*pointer = "changed"
				}
				if pointer := got[index].ExpiresAt; pointer != nil {
					*pointer = "changed"
				}
				if pointer := got[index].SupersededBy; pointer != nil {
					*pointer = "changed"
				}
				for anomaly := range got[index].Anomalies {
					got[index].Anomalies[anomaly] = Anomaly("changed")
				}
			}
			again, err := query(view)
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(again, want) {
				t.Fatal("mutating query results changed the view")
			}
			if !bytes.Equal(raw, mustEncode(t, original)) {
				t.Fatal("mutating query results changed the book")
			}
		})
	}
}

func hasAnomaly(entry Entry, anomaly Anomaly) bool {
	for _, candidate := range entry.Anomalies {
		if candidate == anomaly {
			return true
		}
	}
	return false
}
