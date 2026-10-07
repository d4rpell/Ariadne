package bundle_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/d4rpell/Ariadne/internal/bundle"
	contract "github.com/d4rpell/Ariadne/pkg/evidence"
)

// AX-04 group C (F15, digest-invalidates-exception), bundle half: two bundles of
// the SAME subject and container whose observed digest differs, frozen as
// committed triplets, plus the committed expectation that pins both digests.
// The casefile half of F15 lives in internal/casefile (that package is
// stdlib-only and cannot import this one); the two halves meet through the
// committed expected.json, whose digest literals this test recomputes with the
// real encoder.
//
// What this accredit: the two bundles differ in the digest-derived fields and
// the committed expectation matches them. What it does not accredit: automatic
// invalidation by digest (it does not exist in casefile) and no consumer-side
// rejection.

const ax04F15Fixture = "F15-digest-invalidates-exception"

const (
	ax04F15DigestA = "sha256:" + "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	ax04F15DigestB = "sha256:" + "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	ax04F15RawA    = "registry.example/payments/api@" + ax04F15DigestA
	ax04F15RawB    = "registry.example/payments/api@" + ax04F15DigestB
)

func ax04F15Build(t *testing.T, digest string) contract.Bundle {
	t.Helper()
	raw := "registry.example/payments/api@" + digest
	return ax04BuildFI(t, "release", ax04FIBinding{
		raw:      &raw,
		digest:   &digest,
		platform: contract.PlatformKnown,
		os:       "linux",
		arch:     "amd64",
	})
}

// ax04F15Expected is the committed expectation shared by both halves of F15.
type ax04F15Expected struct {
	AsOf              string `json:"as_of"`
	EffectiveCount    int    `json:"effective_candidates"`
	CandidateBundle   string `json:"candidate_bundle_hash"`
	BundleHashDiffers string `json:"other_bundle_hash"`
	Records           int    `json:"records"`
}

func ax04F15Read(t *testing.T, caseName, file string) []byte {
	t.Helper()
	path := filepath.Join("..", "..", "fixtures", ax04F15Fixture, "0.2", caseName, file)
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return body
}

func ax04F15Expectation(t *testing.T) ax04F15Expected {
	t.Helper()
	var expected ax04F15Expected
	if err := json.Unmarshal(ax04F15Read(t, "exception-book", "expected.json"), &expected); err != nil {
		t.Fatalf("expected.json does not decode: %v", err)
	}
	return expected
}

func TestAX04F15DigestPair(t *testing.T) {
	a := ax04F15Build(t, ax04F15DigestA)
	b := ax04F15Build(t, ax04F15DigestB)

	artifactsA, err := bundle.Encode(a)
	if err != nil {
		t.Fatalf("encode A: %v", err)
	}
	artifactsB, err := bundle.Encode(b)
	if err != nil {
		t.Fatalf("encode B: %v", err)
	}
	if artifactsA.Hash == artifactsB.Hash {
		t.Fatal("the two bundles must carry different digests")
	}
	if a.Subject.UID != b.Subject.UID {
		t.Fatalf("subject uid = %q/%q, want the same subject", a.Subject.UID, b.Subject.UID)
	}
	if a.Images[0].ContainerName != b.Images[0].ContainerName {
		t.Fatal("both bundles must describe the same container")
	}
	if a.Images[0].RawImageID == nil || string(*a.Images[0].RawImageID) != ax04F15RawA {
		t.Fatalf("A raw = %v, want %s", a.Images[0].RawImageID, ax04F15RawA)
	}
	if b.Images[0].RawImageID == nil || string(*b.Images[0].RawImageID) != ax04F15RawB {
		t.Fatalf("B raw = %v, want %s", b.Images[0].RawImageID, ax04F15RawB)
	}

	// The committed expectation pins exactly the digests the encoder produces:
	// the casefile half compares its scope against these literals.
	expected := ax04F15Expectation(t)
	if artifactsA.Hash != expected.CandidateBundle {
		t.Fatalf("A digest = %s, want the committed %s", artifactsA.Hash, expected.CandidateBundle)
	}
	if artifactsB.Hash != expected.BundleHashDiffers {
		t.Fatalf("B digest = %s, want the committed %s", artifactsB.Hash, expected.BundleHashDiffers)
	}
	if expected.CandidateBundle == expected.BundleHashDiffers {
		t.Fatal("the committed digests must differ")
	}
	// The committed triplets are contrasted last, after every semantic assertion
	// above has been reached.
	ax04CompareTriplet(t, ax04F15Fixture, "digest-a", a)
	ax04CompareTriplet(t, ax04F15Fixture, "digest-b", b)
}
