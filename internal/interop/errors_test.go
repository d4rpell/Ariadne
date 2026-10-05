package interop

import (
	"testing"
	"time"

	"github.com/d4rpell/Ariadne/internal/evaluator"
	contract "github.com/d4rpell/Ariadne/pkg/evidence"
)

func validResult(t *testing.T) evaluator.Result {
	t.Helper()
	return goldenResult(t, profileProduct, contract.ProductNotAffected, []evaluator.Candidate{candidate("rule-a", contract.ProductNotAffected)})
}

func TestErrorText(t *testing.T) {
	cases := []struct {
		code ErrorCode
		text string
	}{
		{CodeInvalidResult, "interop: invalid_result"},
		{CodeInvalidBundle, "interop: invalid_bundle"},
		{CodeBundleHashMismatch, "interop: bundle_hash_mismatch"},
		{CodeInvalidIssuer, "interop: invalid_issuer"},
		{CodeRenderFailure, "interop: render_failure"},
	}
	for _, testCase := range cases {
		err := problem(testCase.code)
		if err.Error() != testCase.text {
			t.Fatalf("error text = %q, want %q", err.Error(), testCase.text)
		}
		if !IsCode(err, testCase.code) {
			t.Fatalf("IsCode does not recognise %s", testCase.code)
		}
		if IsCode(err, CodeInvalidResult) && testCase.code != CodeInvalidResult {
			t.Fatalf("IsCode is not code-specific for %s", testCase.code)
		}
	}
}

func TestInvalidResultForm(t *testing.T) {
	bundle := goldenBundle()
	result := validResult(t)
	result.ProfileVersion = "not-a-profile"
	if _, err := OpenVEX(result, bundle, goldenIssuer(t)); !IsCode(err, CodeInvalidResult) {
		t.Fatalf("err = %v, want invalid_result", err)
	}
	if _, err := SARIF(result, bundle); !IsCode(err, CodeInvalidResult) {
		t.Fatalf("SARIF err = %v, want invalid_result", err)
	}
	t.Run("candidate_under_investigation", func(t *testing.T) {
		bad := validResult(t)
		bad.Candidates = []evaluator.Candidate{candidate("rule-a", contract.ProductUnderInvestigation)}
		if _, err := SARIF(bad, bundle); !IsCode(err, CodeInvalidResult) {
			t.Fatalf("err = %v, want invalid_result", err)
		}
	})
	t.Run("observed_at_not_utc", func(t *testing.T) {
		bad := validResult(t)
		offset := time.Date(2026, time.January, 2, 3, 4, 5, 0, time.FixedZone("UTC", 0))
		bad.Target.ObservedAt = contract.Timestamp{Time: offset}
		if _, err := SARIF(bad, bundle); !IsCode(err, CodeInvalidResult) {
			t.Fatalf("err = %v, want invalid_result", err)
		}
	})
}

func TestInvalidBundle(t *testing.T) {
	result := validResult(t)
	if _, err := OpenVEX(result, contract.Bundle{}, goldenIssuer(t)); !IsCode(err, CodeInvalidBundle) {
		t.Fatalf("err = %v, want invalid_bundle", err)
	}
}

func TestBundleHashMismatch(t *testing.T) {
	bundle := goldenBundle()
	result := validResult(t)
	result.BundleHash = "sha256:9999999999999999999999999999999999999999999999999999999999999999"
	if _, err := OpenVEX(result, bundle, goldenIssuer(t)); !IsCode(err, CodeBundleHashMismatch) {
		t.Fatalf("err = %v, want bundle_hash_mismatch", err)
	}
	if _, err := SARIF(result, bundle); !IsCode(err, CodeBundleHashMismatch) {
		t.Fatalf("SARIF err = %v, want bundle_hash_mismatch", err)
	}
}

func TestIssuerForm(t *testing.T) {
	bundle := goldenBundle()
	result := validResult(t)
	cases := map[string]Issuer{
		"document_has_no_scheme": {DocumentID: "no-scheme", Author: "A", IssuedAt: goldenInstant(t, 2026)},
		"document_empty_scheme":  {DocumentID: ":x", Author: "A", IssuedAt: goldenInstant(t, 2026)},
		"document_has_space":     {DocumentID: "urn:ariadne:x y", Author: "A", IssuedAt: goldenInstant(t, 2026)},
		"document_has_control":   {DocumentID: "urn:ariadne:\x01", Author: "A", IssuedAt: goldenInstant(t, 2026)},
		"document_has_delete":    {DocumentID: "urn:ariadne:\x7f", Author: "A", IssuedAt: goldenInstant(t, 2026)},
		"author_empty":           {DocumentID: "urn:ariadne:x", Author: "", IssuedAt: goldenInstant(t, 2026)},
		"author_has_control":     {DocumentID: "urn:ariadne:x", Author: "A\x01B", IssuedAt: goldenInstant(t, 2026)},
		"issued_at_zero":         {DocumentID: "urn:ariadne:x", Author: "A"},
	}
	for name, issuer := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := OpenVEX(result, bundle, issuer); !IsCode(err, CodeInvalidIssuer) {
				t.Fatalf("err = %v, want invalid_issuer", err)
			}
		})
	}
}

func TestDeterminism(t *testing.T) {
	bundle := goldenBundle()
	result := validResult(t)
	issuer := goldenIssuer(t)
	firstVEX, err := OpenVEX(result, bundle, issuer)
	if err != nil {
		t.Fatalf("OpenVEX: %v", err)
	}
	secondVEX, err := OpenVEX(result, bundle, issuer)
	if err != nil {
		t.Fatalf("OpenVEX: %v", err)
	}
	if !equalBytes(firstVEX, secondVEX) {
		t.Fatal("OpenVEX is not deterministic")
	}
	firstSARIF, err := SARIF(result, bundle)
	if err != nil {
		t.Fatalf("SARIF: %v", err)
	}
	secondSARIF, err := SARIF(result, bundle)
	if err != nil {
		t.Fatalf("SARIF: %v", err)
	}
	if !equalBytes(firstSARIF, secondSARIF) {
		t.Fatal("SARIF is not deterministic")
	}
}
