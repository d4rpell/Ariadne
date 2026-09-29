package evaluator

import (
	"reflect"
	"strings"
	"testing"

	"github.com/d4rpell/Ariadne/internal/rulepack"
	contract "github.com/d4rpell/Ariadne/pkg/evidence"
)

// a108Want is the typed expectation of one admission row: an evaluation code,
// a pack-phase code, or admission (both empty).
type a108Want struct {
	code     ErrorCode
	packCode rulepack.ErrorCode
}

func (want a108Want) check(t *testing.T, err error) {
	t.Helper()
	switch {
	case want.packCode != "":
		wantRulepackCode(t, err, want.packCode)
	case want.code != "":
		wantCode(t, err, want.code)
	default:
		if err != nil {
			t.Fatalf("expected admission, got %v", err)
		}
	}
}

// TestA108DomainAdmissionMatrix covers E07: the literal cross of ADR-0018 §5 with
// its exact typed code on every rejection and the zero Result. Each row is one
// combination of recognized profile, domain presence, document completeness,
// context size, pack validity and hash correctness; every earlier phase stays
// valid except the concurrent failure named by the row.
func TestA108DomainAdmissionMatrix(t *testing.T) {
	productDoc := func() string {
		return productPackDocument(
			productRuleJSON("rule.terminal", emitFor(proofVulnerableBuild), a108TerminalFor(proofVulnerableBuild)))
	}
	readinessDoc := func() string {
		return packDocument(ruleJSON("rule.readiness", cveA,
			`{"check_id":"check.one","predicate":"finding_field_present","params":{"field":"package_name"}}`,
			`"bundle.complete","finding.row","finding.package_name"`))
	}
	assemble := func(t *testing.T, document string, bundle contract.Bundle) Request {
		t.Helper()
		return Request{
			Bundle:             bundle,
			ExpectedBundleHash: mustBundleHash(t, bundle),
			Target:             baseTarget(t),
			PackBytes:          []byte(document),
			Admission:          baseContext(t, document),
		}
	}
	productControl := func(t *testing.T) Request {
		t.Helper()
		request := assemble(t, productDoc(), productControlBundle(t, proofVulnerableBuild))
		domain := productDomainContext(t)
		request.Domain = &domain
		return request
	}

	cases := []struct {
		name  string
		build func(*testing.T) Request
		want  a108Want
	}{
		{
			name: "readiness recognized without domain continues",
			build: func(t *testing.T) Request {
				return assemble(t, readinessDoc(), baseBundle(t))
			},
			want: a108Want{},
		},
		{
			name: "readiness recognized with a valid domain is invalid_context",
			build: func(t *testing.T) Request {
				request := assemble(t, readinessDoc(), baseBundle(t))
				domain := productDomainContext(t)
				request.Domain = &domain
				return request
			},
			want: a108Want{packCode: rulepack.CodeInvalidContext},
		},
		{
			name: "product recognized without domain is invalid_context",
			build: func(t *testing.T) Request {
				return assemble(t, productDoc(), productControlBundle(t, proofVulnerableBuild))
			},
			want: a108Want{packCode: rulepack.CodeInvalidContext},
		},
		{
			name: "malformed domain on the readiness profile is invalid_context",
			build: func(t *testing.T) Request {
				request := assemble(t, readinessDoc(), baseBundle(t))
				domain := productDomainContext(t)
				domain.MaximumEvidenceAgeSeconds = 0
				request.Domain = &domain
				return request
			},
			want: a108Want{packCode: rulepack.CodeInvalidContext},
		},
		{
			// The discriminating row: a malformed domain on the product profile,
			// where the domain is genuinely required, so the rejection comes from the
			// context form and not from a forbidden presence.
			name: "malformed domain on the product profile is invalid_context",
			build: func(t *testing.T) Request {
				request := productControl(t)
				domain := copyDomainContext(*request.Domain)
				domain.MaximumEvidenceAgeSeconds = 0
				request.Domain = &domain
				return request
			},
			want: a108Want{packCode: rulepack.CodeInvalidContext},
		},
		{
			// A presence on the product profile with a malformed target: the context
			// form precedes the target form, so the context error wins.
			name: "malformed context precedes a malformed target",
			build: func(t *testing.T) Request {
				request := productControl(t)
				domain := copyDomainContext(*request.Domain)
				domain.SourcePins = nil
				request.Domain = &domain
				request.Target.VulnerabilityID = "not-a-cve"
				return request
			},
			want: a108Want{packCode: rulepack.CodeInvalidContext},
		},
		{
			name: "context over the byte budget wins over any later defect",
			build: func(t *testing.T) Request {
				request := productControl(t)
				domain := copyDomainContext(*request.Domain)
				domain.SourcePins = []SourcePin{
					{Role: SourceRoleMapping, Source: strings.Repeat("a", MaxContextTotalBytes/2), SourceHash: independentSourceHash("a")},
					{Role: SourceRoleArtifact, Source: strings.Repeat("b", MaxContextTotalBytes/2), SourceHash: independentSourceHash("b")},
				}
				request.Domain = &domain
				request.Admission.ExpectedPackHash = independentDocumentHash("not the pack")
				return request
			},
			want: a108Want{code: CodeInputLimit},
		},
		{
			name: "product recognized without domain and a wrong pack hash is invalid_context",
			build: func(t *testing.T) Request {
				request := assemble(t, productDoc(), productControlBundle(t, proofVulnerableBuild))
				request.Admission.ExpectedPackHash = independentDocumentHash("not the pack")
				return request
			},
			want: a108Want{packCode: rulepack.CodeInvalidContext},
		},
		{
			name: "readiness with a valid domain and a wrong pack hash is invalid_context",
			build: func(t *testing.T) Request {
				request := assemble(t, readinessDoc(), baseBundle(t))
				domain := productDomainContext(t)
				request.Domain = &domain
				request.Admission.ExpectedPackHash = independentDocumentHash("not the pack")
				return request
			},
			want: a108Want{packCode: rulepack.CodeInvalidContext},
		},
		{
			// §5.3 fixes this precedence: with a valid domain supplied to the
			// readiness profile, the context form rejects before the bundle and
			// the pack hash ever speak, even when both are defective.
			name: "readiness with a valid domain and a defective bundle plus a wrong pack hash is invalid_context",
			build: func(t *testing.T) Request {
				request := assemble(t, readinessDoc(), baseBundle(t))
				domain := productDomainContext(t)
				request.Domain = &domain
				request.Bundle.Evidence = nil
				request.ExpectedBundleHash = independentDocumentHash("whatever")
				request.Admission.ExpectedPackHash = independentDocumentHash("not the pack")
				return request
			},
			want: a108Want{packCode: rulepack.CodeInvalidContext},
		},
		{
			name: "domain absent with an empty pack is missing_pack",
			build: func(t *testing.T) Request {
				request := productControl(t)
				request.Domain = nil
				request.PackBytes = nil
				request.Admission.ExpectedPackHash = independentDocumentHash("")
				return request
			},
			want: a108Want{packCode: rulepack.CodeMissingPack},
		},
		{
			name: "domain absent with an indeterminate profile and a wrong hash is pack_hash_mismatch",
			build: func(t *testing.T) Request {
				document := strings.Replace(productDoc(), rulepack.ProductEvidenceProfile, "product-evidence-v9", 1)
				request := assemble(t, document, productControlBundle(t, proofVulnerableBuild))
				request.Admission.ExpectedPackHash = independentDocumentHash("other document")
				return request
			},
			want: a108Want{packCode: rulepack.CodePackHashMismatch},
		},
		{
			name: "domain absent with a truncated document and the right hash is invalid_pack",
			build: func(t *testing.T) Request {
				document := productDoc()
				return assemble(t, document[:len(document)-1], productControlBundle(t, proofVulnerableBuild))
			},
			want: a108Want{packCode: rulepack.CodeInvalidPack},
		},
		{
			name: "domain absent with a duplicated key and the right hash is invalid_pack",
			build: func(t *testing.T) Request {
				document := strings.Replace(productDoc(), `"version":7`, `"version":7,"version":7`, 1)
				return assemble(t, document, productControlBundle(t, proofVulnerableBuild))
			},
			want: a108Want{packCode: rulepack.CodeInvalidPack},
		},
		{
			name: "domain absent with a null profile and the right hash is invalid_pack",
			build: func(t *testing.T) Request {
				document := strings.Replace(productDoc(),
					`"profile":"`+rulepack.ProductEvidenceProfile+`"`, `"profile":null`, 1)
				return assemble(t, document, productControlBundle(t, proofVulnerableBuild))
			},
			want: a108Want{packCode: rulepack.CodeInvalidPack},
		},
		{
			name: "domain absent with an absent profile and the right hash is invalid_pack",
			build: func(t *testing.T) Request {
				document := strings.Replace(productDoc(), `"profile":"`+rulepack.ProductEvidenceProfile+`",`, ``, 1)
				return assemble(t, document, productControlBundle(t, proofVulnerableBuild))
			},
			want: a108Want{packCode: rulepack.CodeInvalidPack},
		},
		{
			name: "domain absent with a numeric profile and the right hash is invalid_pack",
			build: func(t *testing.T) Request {
				document := strings.Replace(productDoc(),
					`"profile":"`+rulepack.ProductEvidenceProfile+`"`, `"profile":1`, 1)
				return assemble(t, document, productControlBundle(t, proofVulnerableBuild))
			},
			want: a108Want{packCode: rulepack.CodeInvalidPack},
		},
		{
			name: "domain absent with a well-formed unknown profile is unsupported_pack",
			build: func(t *testing.T) Request {
				document := strings.Replace(productDoc(), rulepack.ProductEvidenceProfile, "product-evidence-v9", 1)
				return assemble(t, document, productControlBundle(t, proofVulnerableBuild))
			},
			want: a108Want{packCode: rulepack.CodeUnsupportedPack},
		},
		{
			name: "product recognized without domain and an unknown requirement is invalid_context",
			build: func(t *testing.T) Request {
				document := strings.Replace(productDoc(), `"domain.current"`, `"domain.future"`, 1)
				return assemble(t, document, productControlBundle(t, proofVulnerableBuild))
			},
			want: a108Want{packCode: rulepack.CodeInvalidContext},
		},
		{
			name: "product recognized with a valid domain and an unknown requirement is unsupported_pack",
			build: func(t *testing.T) Request {
				document := strings.Replace(productDoc(), `"domain.current"`, `"domain.future"`, 1)
				request := assemble(t, document, productControlBundle(t, proofVulnerableBuild))
				domain := productDomainContext(t)
				request.Domain = &domain
				return request
			},
			want: a108Want{packCode: rulepack.CodeUnsupportedPack},
		},
		{
			name: "product with a valid domain over bundle 0.1 and a wrong pack hash is pack_hash_mismatch",
			build: func(t *testing.T) Request {
				bundle := productControlBundle(t, proofVulnerableBuild)
				bundle.SchemaVersion = "0.1"
				request := assemble(t, productDoc(), bundle)
				domain := productDomainContext(t)
				request.Domain = &domain
				request.Admission.ExpectedPackHash = independentDocumentHash("not the pack")
				return request
			},
			want: a108Want{packCode: rulepack.CodePackHashMismatch},
		},
		{
			name: "product with a valid domain over bundle 0.1 and an expired pack is invalid_pack",
			build: func(t *testing.T) Request {
				bundle := productControlBundle(t, proofVulnerableBuild)
				bundle.SchemaVersion = "0.1"
				request := assemble(t, productDoc(), bundle)
				domain := productDomainContext(t)
				request.Domain = &domain
				request.Admission.EvaluatedAt = mustStamp(t, evaluatedAt.AddDate(2, 0, 0))
				return request
			},
			want: a108Want{packCode: rulepack.CodeInvalidPack},
		},
		{
			name: "a malformed bundle wins over a wrong pack hash",
			build: func(t *testing.T) Request {
				// The concurrent failure §5.3 requires: the bundle is defective and
				// the pack hash is wrong at the same time. The bundle phase runs
				// first, so the exact code is invalid_bundle and the pack hash never
				// gets to speak.
				request := assemble(t, productDoc(), productControlBundle(t, proofVulnerableBuild))
				domain := productDomainContext(t)
				request.Domain = &domain
				request.Bundle.Evidence = nil
				request.ExpectedBundleHash = independentDocumentHash("whatever")
				request.Admission.ExpectedPackHash = independentDocumentHash("not the pack")
				return request
			},
			want: a108Want{code: CodeInvalidBundle},
		},
		{
			name: "indeterminate profile with an invalid bundle is invalid_bundle",
			build: func(t *testing.T) Request {
				document := productDoc()
				request := assemble(t, document[:len(document)-1], productControlBundle(t, proofVulnerableBuild))
				request.Bundle.Evidence = nil
				request.ExpectedBundleHash = independentDocumentHash("whatever")
				return request
			},
			want: a108Want{code: CodeInvalidBundle},
		},
		{
			name: "readiness keeps accepting bundle 0.1",
			build: func(t *testing.T) Request {
				bundle := baseBundle(t)
				bundle.SchemaVersion = "0.1"
				return assemble(t, readinessDoc(), bundle)
			},
			want: a108Want{},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			result, err := Evaluate(tc.build(t))
			if tc.want == (a108Want{}) {
				if err != nil {
					t.Fatalf("the control row must evaluate, got %v", err)
				}
				return
			}
			if err == nil {
				t.Fatalf("expected a rejection, got status %s", result.ProductStatus)
			}
			if !reflect.DeepEqual(result, Result{}) {
				t.Fatalf("a rejection must return the zero Result, got %+v", result)
			}
			tc.want.check(t, err)
		})
	}

	t.Run("the affirmative control of the matrix evaluates", func(t *testing.T) {
		result, err := Evaluate(productControl(t))
		if err != nil {
			t.Fatalf("the product control must evaluate: %v", err)
		}
		if result.ProductStatus != contract.ProductAffected {
			t.Fatalf("control status = %s, want affected", result.ProductStatus)
		}
	})
}

// TestA108AdmissionFailures covers E08: every integrity failure returns its
// exact typed code and the zero Result, starting from a valid affirmative
// control.
func TestA108AdmissionFailures(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*Request)
		want   a108Want
	}{
		{"pack bytes removed", func(r *Request) { r.PackBytes = nil }, a108Want{packCode: rulepack.CodeMissingPack}},
		{"pack hash mismatch", func(r *Request) { r.Admission.ExpectedPackHash = independentDocumentHash("other") }, a108Want{packCode: rulepack.CodePackHashMismatch}},
		{"pack id mismatch", func(r *Request) { r.Admission.ExpectedPackID = "pack.other" }, a108Want{packCode: rulepack.CodePackIdentityMismatch}},
		{"bundle hash mismatch", func(r *Request) {
			r.ExpectedBundleHash = independentDocumentHash("other")
		}, a108Want{code: CodeBundleHashMismatch}},
		{"bundle evidence removed", func(r *Request) { r.Bundle.Evidence = nil }, a108Want{code: CodeInvalidBundle}},
		{"foreign target", func(r *Request) {
			r.Target.SubjectUID = contract.UID("uid-z")
		}, a108Want{code: CodeInvalidTarget}},
		{"downgrade", func(r *Request) {
			previous := rulepack.PreviousVersion{Version: 8, Hash: independentDocumentHash("older")}
			r.Admission.Previous = &previous
		}, a108Want{packCode: rulepack.CodePackDowngrade}},
		{"expired pack", func(r *Request) {
			r.Admission.EvaluatedAt = mustStamp(t, evaluatedAt.AddDate(2, 0, 0))
		}, a108Want{packCode: rulepack.CodePackExpired}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			request, _ := a108AffirmativeRequest(t, proofVulnerableBuild)
			tc.mutate(&request)
			result, err := Evaluate(request)
			if err == nil {
				t.Fatalf("%s: expected a rejection", tc.name)
			}
			if !reflect.DeepEqual(result, Result{}) {
				t.Fatalf("%s: rejection returned %+v", tc.name, result)
			}
			tc.want.check(t, err)
		})
	}

	t.Run("value hash tampering is rejected", func(t *testing.T) {
		request, _ := a108AffirmativeRequest(t, proofVulnerableBuild)
		request.Bundle = cloneBundle(request.Bundle)
		tampered := false
		for index := range request.Bundle.Evidence {
			item := &request.Bundle.Evidence[index]
			if item.Type != "prisma_v1.package_name" || item.Value == nil {
				continue
			}
			changed := *item.Value + "-tampered"
			item.Value = &changed
			tampered = true
			break
		}
		if !tampered {
			t.Fatal("the control bundle must carry a package name item")
		}
		// The projection hash stays coherent with the tampered bytes: the failure
		// exercised here is the value hash, not the bundle hash.
		request = a108Rehash(t, request)
		result, err := Evaluate(request)
		if err == nil {
			t.Fatalf("a tampered value hash must be rejected, got status %s", result.ProductStatus)
		}
		if !reflect.DeepEqual(result, Result{}) {
			t.Fatalf("a rejection must return the zero Result, got %+v", result)
		}
		wantCode(t, err, CodeValueHashMismatch)
	})

	t.Run("equivocation is not a downgrade", func(t *testing.T) {
		request, _ := a108AffirmativeRequest(t, proofVulnerableBuild)
		previous := rulepack.PreviousVersion{Version: 7, Hash: independentDocumentHash("another document")}
		request.Admission.Previous = &previous
		result, err := Evaluate(request)
		if err == nil {
			t.Fatalf("an equivocation must be rejected, got status %s", result.ProductStatus)
		}
		if !reflect.DeepEqual(result, Result{}) {
			t.Fatalf("a rejection must return the zero Result, got %+v", result)
		}
		wantRulepackCode(t, err, rulepack.CodePackEquivocation)
	})

	t.Run("minimum version above the pack version is a downgrade", func(t *testing.T) {
		request, _ := a108AffirmativeRequest(t, proofVulnerableBuild)
		request.Admission.MinimumVersion = 8
		result, err := Evaluate(request)
		if err == nil {
			t.Fatalf("a version below the minimum must be rejected, got status %s", result.ProductStatus)
		}
		if !reflect.DeepEqual(result, Result{}) {
			t.Fatalf("a rejection must return the zero Result, got %+v", result)
		}
		wantRulepackCode(t, err, rulepack.CodePackDowngrade)
	})
}
