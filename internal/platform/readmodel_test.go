package platform

import (
	"bytes"
	"testing"

	"github.com/d4rpell/Ariadne/internal/casefile"
)

func TestBuildModelOrderStandingAndSupersession(t *testing.T) {
	book := loadGoldenBook(t)
	model, err := BuildModel(book, goldenAsOf)
	if err != nil {
		t.Fatalf("BuildModel: %v", err)
	}
	if model.AsOf != goldenAsOf {
		t.Fatalf("AsOf = %q, want %q", model.AsOf, goldenAsOf)
	}
	if model.RecordCount != 6 || len(model.Entries) != 6 {
		t.Fatalf("records = %d, entries = %d, want 6", model.RecordCount, len(model.Entries))
	}
	if !model.HasHead() {
		t.Fatal("a six-record book must have a head")
	}

	// Append order: Sequence 1..6 in the order the records were written.
	for position := range model.Entries {
		if model.Entries[position].Sequence != uint64(position+1) {
			t.Fatalf("entry %d has sequence %d, want append order", position, model.Entries[position].Sequence)
		}
	}

	wantStanding := []string{"effective", "pending", "expired", "superseded", "effective", "effective"}
	for position, want := range wantStanding {
		if got := model.Entries[position].Standing; got != want {
			t.Fatalf("sequence %d: standing %q, want %q", position+1, got, want)
		}
	}

	// The superseded record points at its direct successor (sequence 5).
	superseded := model.Entries[3]
	if superseded.SupersededBy == nil || *superseded.SupersededBy != model.Entries[4].Hash {
		t.Fatalf("sequence 4 SupersededBy = %v, want the hash of sequence 5", superseded.SupersededBy)
	}
	if model.Entries[1].ExpiresAt != nil {
		t.Fatal("sequence 2 declares no expiry and must stay nil")
	}

	// The cross-subject reference is a visible anomaly, not a silent drop.
	last := model.Entries[5]
	if len(last.Anomalies) != 1 || last.Anomalies[0] != string(casefile.AnomalySupersedesSubjectMismatch) {
		t.Fatalf("sequence 6 anomalies = %v, want the subject mismatch", last.Anomalies)
	}
}

func TestBuildModelDoesNotMutateBook(t *testing.T) {
	book := loadGoldenBook(t)
	before, err := casefile.Encode(book)
	if err != nil {
		t.Fatal(err)
	}

	model, err := BuildModel(book, goldenAsOf)
	if err != nil {
		t.Fatal(err)
	}
	// Mutate every mutable field of the returned model.
	model.Entries[0].Scope.SubjectUID = "mutated"
	if model.Entries[3].SupersededBy != nil {
		*model.Entries[3].SupersededBy = "mutated"
	}
	if len(model.Entries[5].Anomalies) > 0 {
		model.Entries[5].Anomalies[0] = "mutated"
	}

	after, err := casefile.Encode(book)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(before, after) {
		t.Fatal("BuildModel or the model itself mutated the book")
	}

	// A second projection is identical to the frozen one.
	again, err := BuildModel(book, goldenAsOf)
	if err != nil {
		t.Fatal(err)
	}
	if again.Entries[0].Scope.SubjectUID != "uid-a" {
		t.Fatal("mutating the model leaked into the book projection")
	}
}

func TestBuildModelEmptyBook(t *testing.T) {
	model, err := BuildModel(casefile.NewBook(), goldenAsOf)
	if err != nil {
		t.Fatalf("BuildModel on the empty book: %v", err)
	}
	if model.RecordCount != 0 || len(model.Entries) != 0 {
		t.Fatalf("empty book produced %d records", model.RecordCount)
	}
	if model.HasHead() {
		t.Fatal("the empty book has no head")
	}
}

func TestBuildModelRejectsInvalidAsOf(t *testing.T) {
	book := loadGoldenBook(t)
	for _, bad := range []string{"", "2026-13-01T00:00:00Z", "2026-03-01T00:00:00", "2026-03-01t00:00:00z"} {
		if _, err := BuildModel(book, bad); err == nil {
			t.Fatalf("as_of %q was accepted", bad)
		}
	}
}

func TestBuildModelEntryLookup(t *testing.T) {
	model, err := BuildModel(loadGoldenBook(t), goldenAsOf)
	if err != nil {
		t.Fatal(err)
	}
	if _, found := model.Entry(1); !found {
		t.Fatal("sequence 1 must exist")
	}
	if _, found := model.Entry(0); found {
		t.Fatal("sequence 0 must not exist")
	}
	if _, found := model.Entry(999); found {
		t.Fatal("an absent sequence must not resolve")
	}
}
