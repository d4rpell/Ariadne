package interop

import (
	"strings"
	"testing"
	"time"

	"github.com/d4rpell/Ariadne/internal/evaluator"
	contract "github.com/d4rpell/Ariadne/pkg/evidence"
)

func goldenCSAFIssuer(t *testing.T) CSAFIssuer {
	t.Helper()
	return CSAFIssuer{
		DocumentID:         "https://example.test/vex/2026-0001",
		PublisherName:      "Example Security Team",
		PublisherNamespace: "https://example.test",
		IssuedAt:           goldenInstant(t, 2026),
	}
}

func notAffectedResult(t *testing.T) evaluator.Result {
	t.Helper()
	return goldenResult(t, profileProduct, contract.ProductNotAffected, []evaluator.Candidate{candidate("rule-a", contract.ProductNotAffected)})
}

func affectedResult(t *testing.T) evaluator.Result {
	t.Helper()
	return goldenResult(t, profileProduct, contract.ProductAffected, []evaluator.Candidate{candidate("rule-a", contract.ProductAffected)})
}

func withCVEEdit(result evaluator.Result, cve string) evaluator.Result {
	result.Target.VulnerabilityID = cve
	return result
}

func withBundleHashEdit(result evaluator.Result, hash string) evaluator.Result {
	result.BundleHash = hash
	return result
}

func TestGoldenCSAF(t *testing.T) {
	bundle := goldenBundle()
	remediation := &CSAFRemediation{Category: "mitigation", Details: "Apply the vendor advisory for the affected package."}
	cases := []struct {
		name        string
		golden      string
		result      evaluator.Result
		remediation *CSAFRemediation
	}{
		{"known_not_affected", "csaf.known_not_affected.json", notAffectedResult(t), nil},
		{"known_affected", "csaf.known_affected.json", affectedResult(t), remediation},
		{"fixed", "csaf.fixed.json", goldenResult(t, profileProduct, contract.ProductFixed, []evaluator.Candidate{candidate("rule-a", contract.ProductFixed)}), nil},
		{"under_investigation", "csaf.under_investigation.json", goldenResult(t, profileReadiness, contract.ProductUnderInvestigation, nil), nil},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			document, err := CSAF(testCase.result, bundle, goldenCSAFIssuer(t), testCase.remediation)
			if err != nil {
				t.Fatalf("CSAF: %v", err)
			}
			compareGolden(t, testCase.golden, document)
		})
	}
}

func TestCSAFStatusMapping(t *testing.T) {
	bundle := goldenBundle()
	cases := []struct {
		status contract.ProductStatus
		key    string
	}{
		{contract.ProductAffected, "known_affected"},
		{contract.ProductNotAffected, "known_not_affected"},
		{contract.ProductFixed, "fixed"},
		{contract.ProductUnderInvestigation, "under_investigation"},
	}
	for _, testCase := range cases {
		t.Run(testCase.key, func(t *testing.T) {
			profile := profileProduct
			var remediation *CSAFRemediation
			if testCase.status == contract.ProductUnderInvestigation {
				profile = profileReadiness
			}
			if testCase.status == contract.ProductAffected {
				remediation = &CSAFRemediation{Category: "none_available", Details: "see record"}
			}
			result := goldenResult(t, profile, testCase.status, nil)
			document, err := CSAF(result, bundle, goldenCSAFIssuer(t), remediation)
			if err != nil {
				t.Fatalf("CSAF: %v", err)
			}
			if !strings.Contains(string(document), `"product_status":{"`+testCase.key+`":`) {
				t.Fatalf("status %s did not map to %s: %s", testCase.status, testCase.key, document)
			}
		})
	}
}

func TestCSAFDeterminism(t *testing.T) {
	bundle := goldenBundle()
	result := affectedResult(t)
	remediation := &CSAFRemediation{Category: "vendor_fix", Details: "upgrade"}
	first, err := CSAF(result, bundle, goldenCSAFIssuer(t), remediation)
	if err != nil {
		t.Fatalf("CSAF: %v", err)
	}
	second, err := CSAF(result, bundle, goldenCSAFIssuer(t), remediation)
	if err != nil {
		t.Fatalf("CSAF: %v", err)
	}
	if !equalBytes(first, second) {
		t.Fatal("CSAF is not deterministic")
	}
}

func TestCSAFValidation(t *testing.T) {
	bundle := goldenBundle()
	issuer := goldenCSAFIssuer(t)
	validRemediation := &CSAFRemediation{Category: "mitigation", Details: "apply the vendor advisory"}
	nonUTCInstant := contract.Timestamp{Time: time.Date(2026, time.January, 2, 3, 4, 5, 0, time.FixedZone("X", 3600))}
	badHash := "sha256:" + strings.Repeat("0", 64)
	cases := []struct {
		name        string
		result      evaluator.Result
		issuer      CSAFIssuer
		remediation *CSAFRemediation
		code        ErrorCode
	}{
		{"affected_without_remediation", affectedResult(t), issuer, nil, CodeInvalidRemediation},
		{"affected_unknown_category", affectedResult(t), issuer, &CSAFRemediation{Category: "none", Details: "x"}, CodeInvalidRemediation},
		{"affected_empty_category", affectedResult(t), issuer, &CSAFRemediation{Category: "", Details: "x"}, CodeInvalidRemediation},
		{"affected_empty_details", affectedResult(t), issuer, &CSAFRemediation{Category: "mitigation", Details: ""}, CodeInvalidRemediation},
		{"affected_control_details", affectedResult(t), issuer, &CSAFRemediation{Category: "mitigation", Details: "bad\x00"}, CodeInvalidRemediation},
		{"not_affected_with_remediation", notAffectedResult(t), issuer, validRemediation, CodeInvalidRemediation},
		{"bad_cve_ghsa", withCVEEdit(notAffectedResult(t), "GHSA-1234-5678-9012"), issuer, nil, CodeInvalidResult},
		{"bad_cve_short", withCVEEdit(notAffectedResult(t), "CVE-2026-1"), issuer, nil, CodeInvalidResult},
		{"bad_cve_lowercase", withCVEEdit(notAffectedResult(t), "cve-2026-0001"), issuer, nil, CodeInvalidResult},
		{"issuer_empty_id", notAffectedResult(t), CSAFIssuer{PublisherName: "x", PublisherNamespace: "https://e.test", IssuedAt: goldenInstant(t, 2026)}, nil, CodeInvalidIssuer},
		{"issuer_bad_namespace", notAffectedResult(t), CSAFIssuer{DocumentID: "d", PublisherName: "x", PublisherNamespace: "not a uri", IssuedAt: goldenInstant(t, 2026)}, nil, CodeInvalidIssuer},
		{"issuer_non_utc_instant", notAffectedResult(t), CSAFIssuer{DocumentID: "d", PublisherName: "x", PublisherNamespace: "https://e.test", IssuedAt: nonUTCInstant}, nil, CodeInvalidIssuer},
		{"bundle_hash_mismatch", withBundleHashEdit(notAffectedResult(t), badHash), issuer, nil, CodeBundleHashMismatch},
		{"bad_profile", goldenResult(t, "bogus-profile", contract.ProductUnderInvestigation, nil), issuer, nil, CodeInvalidResult},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			_, err := CSAF(testCase.result, bundle, testCase.issuer, testCase.remediation)
			if !IsCode(err, testCase.code) {
				t.Fatalf("CSAF error = %v, want code %s", err, testCase.code)
			}
		})
	}
}
