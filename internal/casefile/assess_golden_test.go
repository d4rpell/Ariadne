package casefile

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

// The two fixtures below were produced by an independent Python oracle that
// recomputed every record preimage and SHA-256 from the canonical format, not
// by this package. Verify then re-admits the frozen bytes, and Assess derives
// the standings asserted here by hand.

const (
	expiryVector     = "casefile-expiry.book.json"
	expiryRecordHash = "sha256:b35b6ce38945400efbb7660136e02c79d106aa80bb81fbf18dc231d9765e4635"

	supersedesVector      = "casefile-supersedes.book.json"
	supersedesPredecessor = "sha256:d34610a9b562053ea616b514bbfa12fe886a33d03a65f88bdba05107d2785b03"
	supersedesSuccessor   = "sha256:0191d9518ae1feb0900a62e0675b49c0e0aa8f0e78b67b51b1698c78cb7e8058"
)

func loadVector(t *testing.T, name string) Book {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatal(err)
	}
	book, err := Verify(data)
	if err != nil {
		t.Fatalf("frozen vector %s must verify: %v", name, err)
	}
	if !bytes.Equal(mustEncode(t, book), data) {
		t.Fatalf("re-encoding %s diverged from the frozen bytes", name)
	}
	return book
}

func TestAssessExpiryFixture(t *testing.T) {
	book := loadVector(t, expiryVector)
	records, err := Records(book)
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 1 || records[0].Hash != expiryRecordHash {
		t.Fatalf("expiry vector: got %d records, first hash %s", len(records), records[0].Hash)
	}
	if got := entry(t, book, "2026-03-01T00:00:00Z", expiryRecordHash).Standing; got != StandingEffective {
		t.Fatalf("before expiry: standing %s, want effective", got)
	}
	if got := entry(t, book, "2027-01-01T00:00:00Z", expiryRecordHash).Standing; got != StandingExpired {
		t.Fatalf("after expiry: standing %s, want expired", got)
	}
}

func TestAssessSupersedesFixture(t *testing.T) {
	book := loadVector(t, supersedesVector)
	asOf := "2026-03-01T00:00:00Z"

	predecessor := entry(t, book, asOf, supersedesPredecessor)
	if predecessor.Standing != StandingSuperseded {
		t.Fatalf("predecessor standing %s, want superseded", predecessor.Standing)
	}
	if predecessor.SupersededBy == nil || *predecessor.SupersededBy != supersedesSuccessor {
		t.Fatalf("predecessor SupersededBy %v, want %s", predecessor.SupersededBy, supersedesSuccessor)
	}
	successor := entry(t, book, asOf, supersedesSuccessor)
	if successor.Standing != StandingEffective {
		t.Fatalf("successor standing %s, want effective", successor.Standing)
	}
	if !bytes.Equal([]byte(predecessor.Scope.BundleHash), []byte("sha256:"+repeat("11", 32))) {
		t.Fatalf("predecessor scope not conserved: %s", predecessor.Scope.BundleHash)
	}
	if !bytes.Equal([]byte(successor.Scope.BundleHash), []byte("sha256:"+repeat("22", 32))) {
		t.Fatalf("successor scope not conserved: %s", successor.Scope.BundleHash)
	}

	view, err := Assess(book, asOf)
	if err != nil {
		t.Fatal(err)
	}
	candidates, err := view.Candidates(SubjectOf(successor.Scope))
	if err != nil {
		t.Fatal(err)
	}
	if len(candidates) != 1 || candidates[0].Hash != supersedesSuccessor {
		t.Fatalf("candidates %+v, want only the successor", candidates)
	}
}

func repeat(pair string, count int) string {
	out := make([]byte, 0, len(pair)*count)
	for index := 0; index < count; index++ {
		out = append(out, pair...)
	}
	return string(out)
}
