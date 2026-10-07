package casefile

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// AX-04 group C (F15, digest-invalidates-exception), casefile half. The
// committed book declares one decision scoped to the digest of bundle A. This
// test re-admits the frozen bytes, proves they re-encode byte for byte, and
// asserts that the effective candidate's Scope.BundleHash equals A's digest and
// differs from B's, so the decision does not apply to the new bundle.
//
// The continuity key (SubjectOf) excludes the bundle hash, so Assess does NOT
// return zero candidates for B: asserting that would be false. What is
// accredited is the scope mismatch, not a consumer-side rejection. Automatic
// invalidation by digest does not exist in this package; the declared
// invalidation via supersedes is accredited by the casefile-supersedes vector
// (A3-02) and is cited, not duplicated. The bundle half of F15 lives in
// internal/bundle; the two halves meet through the committed expected.json.

const ax04F15BookDir = "../../fixtures/F15-digest-invalidates-exception/0.2/exception-book"

type ax04F15Expected struct {
	AsOf              string `json:"as_of"`
	EffectiveCount    int    `json:"effective_candidates"`
	CandidateBundle   string `json:"candidate_bundle_hash"`
	BundleHashDiffers string `json:"other_bundle_hash"`
	Records           int    `json:"records"`
	RecordHash        string `json:"record_hash"`
}

func TestAX04F15ExceptionBook(t *testing.T) {
	bookBytes, err := os.ReadFile(filepath.Join(ax04F15BookDir, "book.json"))
	if err != nil {
		t.Fatalf("read book.json: %v", err)
	}
	var expected ax04F15Expected
	expectedBytes, err := os.ReadFile(filepath.Join(ax04F15BookDir, "expected.json"))
	if err != nil {
		t.Fatalf("read expected.json: %v", err)
	}
	if err := json.Unmarshal(expectedBytes, &expected); err != nil {
		t.Fatalf("expected.json does not decode: %v", err)
	}
	if expected.CandidateBundle == expected.BundleHashDiffers {
		t.Fatal("the committed digests must differ")
	}

	// The frozen bytes must be exactly what the canonical format produces: a
	// book that only Verify accepts but that re-encodes differently would be a
	// corrupt vector.
	book, err := Verify(bookBytes)
	if err != nil {
		t.Fatalf("the committed book must verify: %v", err)
	}
	reencoded, err := Encode(book)
	if err != nil {
		t.Fatalf("encode book: %v", err)
	}
	if !bytes.Equal(reencoded, bookBytes) {
		t.Fatal("re-encoding the committed book diverged from its frozen bytes")
	}

	records, err := Records(book)
	if err != nil {
		t.Fatalf("records: %v", err)
	}
	if len(records) != expected.Records {
		t.Fatalf("records = %d, want %d", len(records), expected.Records)
	}
	if records[0].Hash != expected.RecordHash {
		t.Fatalf("record hash = %s, want the committed %s", records[0].Hash, expected.RecordHash)
	}
	if records[0].Decision.Scope.BundleHash != expected.CandidateBundle {
		t.Fatalf("record scope bundle hash = %s, want A (%s)", records[0].Decision.Scope.BundleHash, expected.CandidateBundle)
	}

	view, err := Assess(book, expected.AsOf)
	if err != nil {
		t.Fatalf("assess: %v", err)
	}
	candidates, err := view.Candidates(SubjectOf(records[0].Decision.Scope))
	if err != nil {
		t.Fatalf("candidates: %v", err)
	}
	if len(candidates) != expected.EffectiveCount {
		t.Fatalf("effective candidates = %d, want %d", len(candidates), expected.EffectiveCount)
	}
	// The candidate is scoped to the bundle hash of A. This asserts conservation
	// of the scope through production (Records → Assess → Candidates): the scope
	// is not dropped, rewritten or aliased. The inequality against B expresses the
	// intent (a different bundle hash) but, given A != B and candidate == A, it is
	// implied; the conclusion is limited to a documentary scope mismatch, not a
	// consumer-side rejection.
	if candidates[0].Scope.BundleHash != expected.CandidateBundle {
		t.Fatalf("candidate bundle hash = %s, want the bundle hash of A (%s)", candidates[0].Scope.BundleHash, expected.CandidateBundle)
	}
	if candidates[0].Scope.BundleHash == expected.BundleHashDiffers {
		t.Fatal("the decision must not be scoped to the bundle hash of B")
	}
}
