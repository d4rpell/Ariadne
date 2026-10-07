package casefile

import "testing"

// The fixture a3-10-diff.book.json is produced by an independent Python oracle
// (.internal/a3-10-fixture-gen.py) that recomputes every preimage and SHA-256
// from the canonical format. The expected structure below is derived by hand
// from the Assess rules, not by this package.

const (
	diffSince = "2026-02-01T00:00:00Z"
	diffAsOf  = "2026-05-01T00:00:00Z"
)

func diffFixture(t *testing.T) Book {
	t.Helper()
	return loadVector(t, "a3-10-diff.book.json")
}

func TestDiffGolden(t *testing.T) {
	book := diffFixture(t)
	records, err := Records(book)
	if err != nil {
		t.Fatal(err)
	}
	view, err := Diff(book, diffSince, diffAsOf)
	if err != nil {
		t.Fatalf("Diff: %v", err)
	}
	entries, err := view.Entries()
	if err != nil {
		t.Fatal(err)
	}

	uidOrder := []string{"uid-A", "uid-B", "uid-C", "uid-D", "uid-E", "uid-F"}
	changeOrder := []Change{ChangeRevised, ChangeUnchanged, ChangeUnchanged, ChangeGranted, ChangeReopened, ChangeRevised}
	if len(entries) != len(uidOrder) {
		t.Fatalf("entries = %d, want %d", len(entries), len(uidOrder))
	}
	for index := range entries {
		if entries[index].Subject.SubjectUID != uidOrder[index] {
			t.Fatalf("entry %d subject = %s, want %s", index, entries[index].Subject.SubjectUID, uidOrder[index])
		}
		if entries[index].Change != changeOrder[index] {
			t.Fatalf("entry %d (%s) change = %s, want %s", index, uidOrder[index], entries[index].Change, changeOrder[index])
		}
	}

	sinceA := entries[0].SinceHashes
	asOfA := entries[0].AsOfHashes
	if len(sinceA) != 1 || sinceA[0] != records[0].Hash {
		t.Fatalf("subject A since = %v, want [%s]", sinceA, records[0].Hash)
	}
	if len(asOfA) != 2 || asOfA[0] != records[2].Hash || asOfA[1] != records[6].Hash {
		t.Fatalf("subject A as-of = %v, want [%s %s]", asOfA, records[2].Hash, records[6].Hash)
	}
	if len(entries[3].SinceHashes) != 0 || entries[3].AsOfHashes[0] != records[4].Hash {
		t.Fatalf("subject D not granted: %+v", entries[3])
	}
	if len(entries[4].AsOfHashes) != 0 || entries[4].SinceHashes[0] != records[5].Hash {
		t.Fatalf("subject E not reopened: %+v", entries[4])
	}
	if len(entries[5].AsOfHashes) != 2 || entries[5].AsOfHashes[0] != records[8].Hash || entries[5].AsOfHashes[1] != records[9].Hash {
		t.Fatalf("subject F as-of set wrong: %+v", entries[5])
	}

	declarations, err := view.Declarations()
	if err != nil {
		t.Fatal(err)
	}
	want := []string{records[2].Hash, records[3].Hash, records[4].Hash, records[6].Hash, records[8].Hash, records[9].Hash}
	if len(declarations) != len(want) {
		t.Fatalf("declarations = %v, want %v", declarations, want)
	}
	for index := range want {
		if declarations[index] != want[index] {
			t.Fatalf("declaration %d = %s, want %s", index, declarations[index], want[index])
		}
	}

	anomalies, err := view.Anomalies()
	if err != nil {
		t.Fatal(err)
	}
	wantAnomalies := []DiffAnomaly{
		{Sequence: 7, Anomaly: AnomalySupersedesSubjectMismatch},
		{Sequence: 8, Anomaly: AnomalyAmbiguousSupersession},
	}
	if len(anomalies) != len(wantAnomalies) {
		t.Fatalf("anomalies = %v, want %v", anomalies, wantAnomalies)
	}
	for index := range wantAnomalies {
		if anomalies[index] != wantAnomalies[index] {
			t.Fatalf("anomaly %d = %+v, want %+v", index, anomalies[index], wantAnomalies[index])
		}
	}
}

func TestDiffSinceEqualsAsOfIsAllUnchanged(t *testing.T) {
	book := diffFixture(t)
	view, err := Diff(book, diffAsOf, diffAsOf)
	if err != nil {
		t.Fatal(err)
	}
	entries, err := view.Entries()
	if err != nil {
		t.Fatal(err)
	}
	for index := range entries {
		if entries[index].Change != ChangeUnchanged {
			t.Fatalf("entry %d change = %s, want unchanged", index, entries[index].Change)
		}
	}
	declarations, err := view.Declarations()
	if err != nil {
		t.Fatal(err)
	}
	if len(declarations) != 0 {
		t.Fatalf("declarations = %v, want empty", declarations)
	}
}

func TestDiffEmptyBook(t *testing.T) {
	view, err := Diff(NewBook(), diffSince, diffAsOf)
	if err != nil {
		t.Fatal(err)
	}
	entries, err := view.Entries()
	if err != nil {
		t.Fatal(err)
	}
	declarations, err := view.Declarations()
	if err != nil {
		t.Fatal(err)
	}
	anomalies, err := view.Anomalies()
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 || len(declarations) != 0 || len(anomalies) != 0 {
		t.Fatalf("empty book diff not empty: %v %v %v", entries, declarations, anomalies)
	}
}

func TestDiffDeclarationsWindowBoundaries(t *testing.T) {
	book := diffFixture(t)
	records, err := Records(book)
	if err != nil {
		t.Fatal(err)
	}
	// since == records[0].decided_at is excluded; as_of == records[6].decided_at
	// (2026-03-25) is included. records[1] (2026-01-02) is before since.
	view, err := Diff(book, records[0].Decision.DecidedAt, records[6].Decision.DecidedAt)
	if err != nil {
		t.Fatal(err)
	}
	declarations, err := view.Declarations()
	if err != nil {
		t.Fatal(err)
	}
	for _, hash := range declarations {
		if hash == records[0].Hash {
			t.Fatalf("decided_at == since leaked into declarations")
		}
	}
	found := false
	for _, hash := range declarations {
		if hash == records[6].Hash {
			found = true
		}
	}
	if !found {
		t.Fatalf("decided_at == as_of was excluded from declarations")
	}
}

func TestDiffValidationPrecedence(t *testing.T) {
	t.Run("invalid book", func(t *testing.T) {
		if _, err := Diff(Book{}, diffSince, diffAsOf); !IsCode(err, CodeInvalidBook) {
			t.Fatalf("err = %v, want invalid_book", err)
		}
	})
	t.Run("book before timestamps", func(t *testing.T) {
		// An invalid book and two invalid instants at once: the book decides first.
		if _, err := Diff(Book{}, "2026-02-01", "2026-2-1T00:00:00Z"); !IsCode(err, CodeInvalidBook) {
			t.Fatalf("err = %v, want invalid_book before invalid_timestamp", err)
		}
	})
	t.Run("invalid since", func(t *testing.T) {
		if _, err := Diff(NewBook(), "2026-02-01", diffAsOf); !IsCode(err, CodeInvalidTimestamp) {
			t.Fatalf("err = %v, want invalid_timestamp", err)
		}
	})
	t.Run("invalid as-of", func(t *testing.T) {
		if _, err := Diff(NewBook(), diffSince, "2026-2-1T00:00:00Z"); !IsCode(err, CodeInvalidTimestamp) {
			t.Fatalf("err = %v, want invalid_timestamp", err)
		}
	})
	t.Run("inverted interval", func(t *testing.T) {
		if _, err := Diff(NewBook(), diffAsOf, diffSince); !IsCode(err, CodeInvalidTimestamp) {
			t.Fatalf("err = %v, want invalid_timestamp", err)
		}
	})
}

// TestDiffRevisedWithSameRepresentative pins the P1-class border the F5 review
// asked for: a subject whose in-force set differs while the highest-sequence
// hash is shared. A change rule that compared only the representative (the last
// hash) would answer unchanged; the set comparison answers revised.
func TestDiffRevisedWithSameRepresentative(t *testing.T) {
	book := NewBook()
	for _, input := range []DecisionInput{
		diffInput("uid-X", "2026-01-01T00:00:00Z", "2026-03-01T00:00:00Z"), // expires inside the window
		diffInput("uid-X", "2026-01-02T00:00:00Z", "2027-01-01T00:00:00Z"), // stays in force
	} {
		grown, err := Append(book, input)
		if err != nil {
			t.Fatalf("append: %v", err)
		}
		book = grown
	}
	view, err := Diff(book, "2026-02-01T00:00:00Z", "2026-04-01T00:00:00Z")
	if err != nil {
		t.Fatal(err)
	}
	entries, err := view.Entries()
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 {
		t.Fatalf("entries = %d, want 1 subject", len(entries))
	}
	if len(entries[0].SinceHashes) != 2 || len(entries[0].AsOfHashes) != 1 {
		t.Fatalf("sets = %d/%d, want 2/1", len(entries[0].SinceHashes), len(entries[0].AsOfHashes))
	}
	if entries[0].SinceHashes[1] != entries[0].AsOfHashes[0] {
		t.Fatalf("the highest-sequence representative is not shared: %v / %v", entries[0].SinceHashes, entries[0].AsOfHashes)
	}
	if entries[0].Change != ChangeRevised {
		t.Fatalf("change = %s, want revised (same representative, different set)", entries[0].Change)
	}
}

func diffInput(uid, decided, expires string) DecisionInput {
	expiry := expires
	return DecisionInput{
		RiskDecision: DecisionAccepted,
		Owner:        "owner-example",
		Approver:     "approver-example",
		Rationale:    "synthetic rationale",
		Scope: Scope{
			BundleHash:      "sha256:" + repeat("11", 32),
			SubjectUID:      uid,
			ContainerName:   "api",
			ContainerClass:  ContainerRegular,
			VulnerabilityID: "CVE-1",
		},
		DecidedAt: decided,
		ExpiresAt: &expiry,
	}
}

func TestDiffZeroViewAccessors(t *testing.T) {
	view := DiffView{}
	if _, err := view.Entries(); !IsCode(err, CodeInvalidBook) {
		t.Fatalf("Entries err = %v, want invalid_book", err)
	}
	if _, err := view.Declarations(); !IsCode(err, CodeInvalidBook) {
		t.Fatalf("Declarations err = %v, want invalid_book", err)
	}
	if _, err := view.Anomalies(); !IsCode(err, CodeInvalidBook) {
		t.Fatalf("Anomalies err = %v, want invalid_book", err)
	}
}

func TestDiffDeepCopies(t *testing.T) {
	book := diffFixture(t)
	view, err := Diff(book, diffSince, diffAsOf)
	if err != nil {
		t.Fatal(err)
	}
	entries, err := view.Entries()
	if err != nil {
		t.Fatal(err)
	}
	entries[0].AsOfHashes[0] = "mutated"
	again, err := view.Entries()
	if err != nil {
		t.Fatal(err)
	}
	if again[0].AsOfHashes[0] == "mutated" {
		t.Fatalf("Entries leaked an alias into the view")
	}
}
