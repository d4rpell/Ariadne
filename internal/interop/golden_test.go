package interop

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/d4rpell/Ariadne/internal/evaluator"
	contract "github.com/d4rpell/Ariadne/pkg/evidence"
)

// goldenBundleHash is the projection hash of goldenBundle(), computed once with
// the canonical encoder and frozen here, in the Python oracle and in the SARIF
// goldens. It binds the input bundle to its hash: if canonicalization changes,
// the binding assertion fails before any golden is compared.
const goldenBundleHash = "sha256:17f94f4cdb45b940131720ac05de48bcfbdff6acbd3c097b294f53f367a06031"

const (
	goldenPackHash   = "sha256:4444444444444444444444444444444444444444444444444444444444444444"
	goldenSourceHash = "sha256:3333333333333333333333333333333333333333333333333333333333333333"
)

func goldenIssuer(t *testing.T) Issuer {
	t.Helper()
	return Issuer{
		DocumentID: "https://example.test/vex/2026-0001",
		Author:     "Example Security Team",
		IssuedAt:   goldenInstant(t, 2026),
	}
}

func goldenTarget(t *testing.T) evaluator.Target {
	t.Helper()
	return evaluator.Target{
		SubjectUID:      contract.UID("uid-0001"),
		ContainerClass:  contract.ContainerRegular,
		ContainerName:   contract.ContainerName("api"),
		VulnerabilityID: "CVE-2026-0001",
		Source:          "findings.csv",
		SourceHash:      contract.SourceHash(goldenSourceHash),
		Locator:         contract.SourceLocator("row:1"),
		ObservedAt:      goldenInstant(t, 2026),
	}
}

func goldenResult(t *testing.T, profile string, status contract.ProductStatus, candidates []evaluator.Candidate) evaluator.Result {
	t.Helper()
	return evaluator.Result{
		EngineVersion:  evaluator.EngineVersion,
		ProfileVersion: profile,
		BundleHash:     goldenBundleHash,
		PackID:         "example-pack",
		PackVersion:    1,
		PackHash:       goldenPackHash,
		Target:         goldenTarget(t),
		ProductStatus:  status,
		Exploitability: contract.ExploitabilityNotAssessed,
		Candidates:     candidates,
		Rules:          []evaluator.RuleTrace{},
	}
}

func candidate(ruleID string, status contract.ProductStatus) evaluator.Candidate {
	return evaluator.Candidate{RuleID: ruleID, ProductStatus: status}
}

func compareGolden(t *testing.T, name string, got []byte) {
	t.Helper()
	path := filepath.Join("testdata", name)
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read golden %s: %v", name, err)
	}
	if !equalBytes(got, want) {
		t.Fatalf("golden %s mismatch:\n got: %s\nwant: %s", name, got, want)
	}
}

func equalBytes(left, right []byte) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}

func TestGoldenBundleHashBinding(t *testing.T) {
	hash, err := canonicalHash(goldenBundle())
	if err != nil {
		t.Fatalf("hash: %v", err)
	}
	if hash != goldenBundleHash {
		t.Fatalf("golden bundle hash is %s, want %s", hash, goldenBundleHash)
	}
}

func TestGoldenOpenVEX(t *testing.T) {
	bundle := goldenBundle()
	cases := []struct {
		name          string
		golden        string
		profile       string
		status        contract.ProductStatus
		candidateRule string
	}{
		{"not_affected", "openvex.not_affected.json", profileProduct, contract.ProductNotAffected, "rule-a"},
		{"affected", "openvex.affected.json", profileProduct, contract.ProductAffected, "rule-a"},
		{"fixed", "openvex.fixed.json", profileProduct, contract.ProductFixed, "rule-a"},
		{"under_investigation", "openvex.under_investigation.json", profileReadiness, contract.ProductUnderInvestigation, ""},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			var candidates []evaluator.Candidate
			if testCase.candidateRule != "" {
				candidates = []evaluator.Candidate{candidate(testCase.candidateRule, testCase.status)}
			}
			result := goldenResult(t, testCase.profile, testCase.status, candidates)
			document, err := OpenVEX(result, bundle, goldenIssuer(t))
			if err != nil {
				t.Fatalf("OpenVEX: %v", err)
			}
			compareGolden(t, testCase.golden, document)
		})
	}
}

func TestGoldenSARIF(t *testing.T) {
	bundle := goldenBundle()
	t.Run("candidates", func(t *testing.T) {
		result := goldenResult(t, profileProduct, contract.ProductNotAffected, []evaluator.Candidate{
			candidate("rule-a", contract.ProductNotAffected),
			candidate("rule-b", contract.ProductNotAffected),
			candidate("rule-a", contract.ProductNotAffected),
		})
		document, err := SARIF(result, bundle)
		if err != nil {
			t.Fatalf("SARIF: %v", err)
		}
		compareGolden(t, "sarif.candidates.json", document)
	})
	t.Run("no_candidates", func(t *testing.T) {
		result := goldenResult(t, profileReadiness, contract.ProductUnderInvestigation, nil)
		document, err := SARIF(result, bundle)
		if err != nil {
			t.Fatalf("SARIF: %v", err)
		}
		compareGolden(t, "sarif.no_candidates.json", document)
	})
}

func TestTimestampFormat(t *testing.T) {
	instant := goldenInstant(t, 2026)
	if got := formatTimestamp(instant); got != "2026-01-02T03:04:05Z" {
		t.Fatalf("formatTimestamp = %q", got)
	}
}
