package evaluator

import (
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/d4rpell/Ariadne/internal/rulepack"
	contract "github.com/d4rpell/Ariadne/pkg/evidence"
)

// productControlBundle is the affirmative control of the product profile: row,
// observation, mapping, artifact and one complete vulnerable_build proof.
func productControlBundle(t *testing.T, kind proofKind) contract.Bundle {
	t.Helper()
	subject := baseSubject(t)
	bundle := productBundle(t, mappingItems(t, subject, containerA)...)
	bundle.Evidence = append(bundle.Evidence, artifactItems(t, subject, containerA)...)
	bundle.Evidence = append(bundle.Evidence, vendorItems(t, subject, containerA, kind)...)
	return bundle
}

// TestProductProfileBundleVersion is I-15: the cross admits only Bundle 0.2 with
// the product profile, and a mismatched combination is invalid_pack without a
// result.
func TestProductProfileBundleVersion(t *testing.T) {
	for _, version := range []string{"0.0", "0.1"} {
		t.Run("product with "+version, func(t *testing.T) {
			bundle := productControlBundle(t, proofVulnerableBuild)
			bundle.SchemaVersion = version
			request := productRequest(t, bundle)
			result, err := Evaluate(request)
			wantRulepackCode(t, err, rulepack.CodeInvalidPack)
			if !reflect.DeepEqual(result, Result{}) {
				t.Fatal("a rejected cross must not return a partial result")
			}
		})
	}
	t.Run("product with 0.2", func(t *testing.T) {
		if _, err := Evaluate(productRequest(t, productControlBundle(t, proofVulnerableBuild))); err != nil {
			t.Fatalf("the ratified combination must evaluate: %v", err)
		}
	})
	t.Run("readiness with 0.1 and 0.2", func(t *testing.T) {
		for _, version := range []string{"0.1", "0.2"} {
			bundle := baseBundle(t)
			bundle.SchemaVersion = version
			request := baseRequest(t)
			request.Bundle = bundle
			request.ExpectedBundleHash = mustBundleHash(t, bundle)
			if _, err := Evaluate(request); err != nil {
				t.Fatalf("readiness must keep accepting %s: %v", version, err)
			}
		}
	})
}

// TestProductCrossFailurePrecedence is I-16/I-17: inside the schema phase the
// unknown vocabulary wins over the cross, the cross wins over anti-downgrade,
// expiry and ruleset linkage, and a wrong pack hash wins over the cross because
// the pack hash phase precedes the schema phase (X-1).
func TestProductCrossFailurePrecedence(t *testing.T) {
	legacyBundle := func(t *testing.T) contract.Bundle {
		t.Helper()
		bundle := productControlBundle(t, proofVulnerableBuild)
		bundle.SchemaVersion = "0.1"
		return bundle
	}

	t.Run("unknown profile", func(t *testing.T) {
		bundle := legacyBundle(t)
		request := productRequest(t, bundle)
		document := strings.Replace(string(request.PackBytes), rulepack.ProductEvidenceProfile, "product-evidence-v9", 1)
		request.PackBytes = []byte(document)
		request.Admission.ExpectedPackHash = independentDocumentHash(document)
		_, err := Evaluate(request)
		wantRulepackCode(t, err, rulepack.CodeUnsupportedPack)
	})

	t.Run("expired", func(t *testing.T) {
		request := productRequest(t, legacyBundle(t))
		request.Admission.EvaluatedAt = mustStamp(t, evaluatedAt.AddDate(1, 0, 0))
		_, err := Evaluate(request)
		wantRulepackCode(t, err, rulepack.CodeInvalidPack)
	})

	t.Run("downgrade", func(t *testing.T) {
		request := productRequest(t, legacyBundle(t))
		previous := rulepack.PreviousVersion{Version: 8, Hash: independentDocumentHash("older")}
		request.Admission.Previous = &previous
		_, err := Evaluate(request)
		wantRulepackCode(t, err, rulepack.CodeInvalidPack)
	})

	t.Run("ruleset mismatch", func(t *testing.T) {
		bundle := legacyBundle(t)
		bundle.Provenance.Ruleset = contract.RulesetRef{
			Path: "rules/", Hash: contract.SourceHash(independentDocumentHash("another pack")), Version: "2026-09",
		}
		request := productRequest(t, bundle)
		_, err := Evaluate(request)
		wantRulepackCode(t, err, rulepack.CodeInvalidPack)
	})

	t.Run("hash mismatch wins over the cross", func(t *testing.T) {
		request := productRequest(t, legacyBundle(t))
		request.Admission.ExpectedPackHash = independentDocumentHash("not the pack")
		result, err := Evaluate(request)
		wantRulepackCode(t, err, rulepack.CodePackHashMismatch)
		if !reflect.DeepEqual(result, Result{}) {
			t.Fatal("a rejected hash must not return a partial result")
		}
	})
}

// TestProductAdmissionFailureHasNoResult is I-18: every rejection is the exact
// zero Result, and the readiness profile keeps its own contract.
func TestProductAdmissionFailureHasNoResult(t *testing.T) {
	cases := map[string]func(*Request){
		"missing pack":   func(r *Request) { r.PackBytes = nil },
		"wrong hash":     func(r *Request) { r.Admission.ExpectedPackHash = independentDocumentHash("other") },
		"wrong id":       func(r *Request) { r.Admission.ExpectedPackID = "pack.other" },
		"absent context": func(r *Request) { r.Domain = nil },
		"invalid bundle": func(r *Request) { r.Bundle.Evidence = nil },
		"wrong bundle hash": func(r *Request) {
			r.ExpectedBundleHash = independentDocumentHash("other")
		},
		"foreign target": func(r *Request) { r.Target.SubjectUID = contract.UID("uid-b") },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			request := productRequest(t, productControlBundle(t, proofVulnerableBuild))
			mutate(&request)
			result, err := Evaluate(request)
			if err == nil {
				t.Fatalf("%s must be rejected", name)
			}
			if !reflect.DeepEqual(result, Result{}) {
				t.Fatalf("%s returned a partial result", name)
			}
		})
	}
}

// TestReadinessProfilePreserved is I-18 (legacy half): readiness keeps its
// inconclusive result, its reasons and the absence of Domain and Candidates.
func TestReadinessProfilePreserved(t *testing.T) {
	request := baseRequest(t)
	result, err := Evaluate(request)
	if err != nil {
		t.Fatalf("the readiness control must evaluate: %v", err)
	}
	if result.Domain != nil {
		t.Fatal("the legacy result must not carry a domain context")
	}
	if len(result.Candidates) != 0 {
		t.Fatal("the legacy result must not carry candidates")
	}
	if result.ProductStatus != contract.ProductUnderInvestigation {
		t.Fatalf("status = %s, want under_investigation", result.ProductStatus)
	}
	if result.Exploitability != contract.ExploitabilityNotAssessed {
		t.Fatalf("exploitability = %s, want not_assessed", result.Exploitability)
	}
	if !containsGlobalReason(result.Reasons, ReasonDomainAssessmentDeferred) {
		t.Fatal("the legacy profile keeps the deferred-domain reason")
	}
	if containsGlobalReason(result.Reasons, ReasonNoAffirmativeCandidate) {
		t.Fatal("the legacy profile must not emit product-profile reasons")
	}
}

// TestDomainMappingSelection is I-28: the mapping is unique by CVE and the three
// scanner package fields, and an incompatible alternative blocks instead of
// being discarded.
func TestDomainMappingSelection(t *testing.T) {
	subject := baseSubject(t)

	t.Run("control maps", func(t *testing.T) {
		bundle := productBundle(t, mappingItems(t, subject, containerA)...)
		assessment := assessDomain(newResolver(mustCanonical(t, bundle), baseTarget(t), evaluatedAt, &referenceBudget{}), productDomainContext(t))
		if !assessment.mappingOK {
			t.Fatalf("the control mapping must be selected: %v", assessment.blockers)
		}
	})

	t.Run("no mapping", func(t *testing.T) {
		bundle := productBundle(t)
		assessment := assessDomain(newResolver(mustCanonical(t, bundle), baseTarget(t), evaluatedAt, &referenceBudget{}), productDomainContext(t))
		if assessment.mappingOK {
			t.Fatal("without a mapping the requirement is missing")
		}
	})

	t.Run("incompatible alternative blocks", func(t *testing.T) {
		bundle := productBundle(t, mappingItems(t, subject, containerA)...)
		alternative := mappingItems(t, subject, containerA)
		for index := range alternative {
			switch alternative[index].Type {
			case "product_v1.mapping.product_release":
				replaceValue(&alternative[index], "10")
			case "product_v1.mapping.locator_placeholder":
			}
		}
		// The alternative must be a different record: another locator.
		for index := range alternative {
			alternative[index].Locator = "records/mapping/1"
		}
		bundle.Evidence = append(bundle.Evidence, alternative...)
		assessment := assessDomain(newResolver(mustCanonical(t, bundle), baseTarget(t), evaluatedAt, &referenceBudget{}), productDomainContext(t))
		if assessment.mappingOK {
			t.Fatal("two different mapping identities must block")
		}
		if len(assessment.blockers[ReasonConflict]) == 0 {
			t.Fatalf("blockers = %v, want conflict", assessment.blockers)
		}
	})

	t.Run("equivalent duplicates keep references", func(t *testing.T) {
		bundle := productBundle(t, mappingItems(t, subject, containerA)...)
		duplicate := mappingItems(t, subject, containerA)
		for index := range duplicate {
			duplicate[index].Locator = "records/mapping/1"
		}
		bundle.Evidence = append(bundle.Evidence, duplicate...)
		assessment := assessDomain(newResolver(mustCanonical(t, bundle), baseTarget(t), evaluatedAt, &referenceBudget{}), productDomainContext(t))
		if !assessment.mappingOK {
			t.Fatal("equivalent mappings must still map")
		}
	})
}

// TestDomainArtifactBinding is I-29: the artifact binds to the observed manifest
// digest, and an index or an ambiguous digest never fills normalized_digest.
func TestDomainArtifactBinding(t *testing.T) {
	subject := baseSubject(t)

	t.Run("control binds", func(t *testing.T) {
		bundle := productControlBundle(t, proofVulnerableBuild)
		assessment := assessDomain(newResolver(mustCanonical(t, bundle), baseTarget(t), evaluatedAt, &referenceBudget{}), productDomainContext(t))
		if !assessment.artifactOK {
			t.Fatalf("the control artifact must bind: %v", assessment.blockers)
		}
	})

	t.Run("wrong digest blocks", func(t *testing.T) {
		bundle := productBundle(t, mappingItems(t, subject, containerA)...)
		artifacts := artifactItems(t, subject, containerA)
		for index := range artifacts {
			if artifacts[index].Type == "product_v1.artifact.artifact_digest" {
				replaceValue(&artifacts[index], "sha256:"+strings.Repeat("e", 64))
			}
		}
		bundle.Evidence = append(bundle.Evidence, artifacts...)
		assessment := assessDomain(newResolver(mustCanonical(t, bundle), baseTarget(t), evaluatedAt, &referenceBudget{}), productDomainContext(t))
		if assessment.artifactOK {
			t.Fatal("an artifact with another digest must not bind")
		}
		if len(assessment.blockers[ReasonMismatch]) == 0 {
			t.Fatalf("blockers = %v, want mismatch", assessment.blockers)
		}
	})

	t.Run("package identity contradicting the mapping blocks", func(t *testing.T) {
		// Same digest and platform, but the build inspects another package: the
		// artifact is incompatible with the mapped component, never a valid
		// alternative selected by convenience.
		bundle := productControlBundle(t, proofVulnerableBuild)
		changed := cloneBundle(bundle)
		for index := range changed.Evidence {
			if changed.Evidence[index].Type == "product_v1.artifact.package_name" {
				replaceValue(&changed.Evidence[index], "curl")
			}
		}
		assessment := assessDomain(newResolver(mustCanonical(t, changed), baseTarget(t), evaluatedAt, &referenceBudget{}), productDomainContext(t))
		if assessment.artifactOK {
			t.Fatal("an artifact of another package must not bind the mapped component")
		}
		if len(assessment.blockers[ReasonMismatch]) == 0 {
			t.Fatalf("blockers = %v, want mismatch", assessment.blockers)
		}
	})

	t.Run("index never becomes a manifest", func(t *testing.T) {
		bundle := productBundle(t, mappingItems(t, subject, containerA)...)
		artifacts := artifactItems(t, subject, containerA)
		for index := range artifacts {
			if artifacts[index].Type == "product_v1.artifact.digest_kind" {
				replaceValue(&artifacts[index], "index")
			}
		}
		bundle.Evidence = append(bundle.Evidence, artifacts...)
		assessment := assessDomain(newResolver(mustCanonical(t, bundle), baseTarget(t), evaluatedAt, &referenceBudget{}), productDomainContext(t))
		if assessment.artifactOK {
			t.Fatal("an index digest kind must not satisfy the artifact requirement")
		}
	})

	t.Run("ambiguous normalized digest blocks", func(t *testing.T) {
		// Two images of the same class and name with different digests: the
		// identity is ambiguous and no conclusion may rest on it.
		bundle := productControlBundle(t, proofVulnerableBuild)
		second := bundle.Images[0]
		otherDigest := contract.NormalizedDigest("sha256:" + strings.Repeat("f", 64))
		second.NormalizedDigest = &otherDigest
		bundle.Images = append(bundle.Images, second)
		assessment := assessDomain(newResolver(mustCanonical(t, bundle), baseTarget(t), evaluatedAt, &referenceBudget{}), productDomainContext(t))
		if assessment.artifactOK {
			t.Fatal("an ambiguous image identity must not bind an artifact")
		}
	})
}

// TestDomainVendorApplicability is I-30: a record is not applicable only with an
// explicit foreign identity; an incomplete one is never discarded to save
// another.
func TestDomainVendorApplicability(t *testing.T) {
	subject := baseSubject(t)

	t.Run("foreign identity is not applicable", func(t *testing.T) {
		bundle := productBundle(t, mappingItems(t, subject, containerA)...)
		bundle.Evidence = append(bundle.Evidence, artifactItems(t, subject, containerA)...)
		foreign := vendorItems(t, subject, containerA, proofFixedBuild)
		for index := range foreign {
			if foreign[index].Type == "product_v1.vendor.product_release" {
				replaceValue(&foreign[index], "8")
			}
		}
		bundle.Evidence = append(bundle.Evidence, foreign...)
		assessment := assessDomain(newResolver(mustCanonical(t, bundle), baseTarget(t), evaluatedAt, &referenceBudget{}), productDomainContext(t))
		if len(assessment.proofs) != 0 {
			t.Fatal("a proof of another product release is not applicable")
		}
	})

	t.Run("incomplete record keeps blocking", func(t *testing.T) {
		bundle := productBundle(t, mappingItems(t, subject, containerA)...)
		bundle.Evidence = append(bundle.Evidence, artifactItems(t, subject, containerA)...)
		bundle.Evidence = append(bundle.Evidence, vendorItems(t, subject, containerA, proofVulnerableBuild)...)
		// A second group of the same source is missing fields: nothing proves it
		// foreign, so it must not be discarded to save the complete one.
		partial := vendorItems(t, subject, containerA, proofFixedBuild)[:5]
		for index := range partial {
			partial[index].Locator = "records/proof/1"
		}
		bundle.Evidence = append(bundle.Evidence, partial...)
		result, err := Evaluate(productRequest(t, bundle))
		if err != nil {
			t.Fatalf("an incomplete record is uncertainty, not a rejection: %v", err)
		}
		if result.ProductStatus != contract.ProductUnderInvestigation {
			t.Fatalf("status = %s, want under_investigation", result.ProductStatus)
		}
	})
}

// TestDomainPinsExactAndComplete is I-21: the pin match is exact in both
// directions. A role, source, hash or revision that does not match exactly is a
// different source, a more recent revision is never selected by itself, and a
// pin without a candidate is a gap that is never silently satisfied.
func TestDomainPinsExactAndComplete(t *testing.T) {
	subject := baseSubject(t)
	control := func(t *testing.T) (Request, contract.Bundle) {
		t.Helper()
		bundle := productControlBundle(t, proofVulnerableBuild)
		return productRequest(t, bundle), bundle
	}

	rejectedFields := []struct {
		name   string
		mutate func(*DomainContext)
	}{
		{"role", func(context *DomainContext) {
			context.SourcePins[2].Role = SourceRoleArtifact
			context.SourcePins[2].AdvisoryID = nil
			context.SourcePins[2].AdvisoryRevision = nil
		}},
		{"source", func(context *DomainContext) { context.SourcePins[2].Source = "advisory-2.json" }},
		{"hash", func(context *DomainContext) {
			context.SourcePins[2].SourceHash = independentSourceHash("another advisory body\n")
		}},
		{"advisory id", func(context *DomainContext) {
			value := "RHSA-2026:9999"
			context.SourcePins[2].AdvisoryID = &value
		}},
		{"advisory revision", func(context *DomainContext) {
			value := "2"
			context.SourcePins[2].AdvisoryRevision = &value
		}},
	}
	for _, testCase := range rejectedFields {
		t.Run("mismatched "+testCase.name+" is not the pinned source", func(t *testing.T) {
			request, _ := control(t)
			domain := copyDomainContext(*request.Domain)
			testCase.mutate(&domain)
			request.Domain = &domain
			result, err := Evaluate(request)
			if err != nil {
				t.Fatalf("a pin mismatch is uncertainty, not a rejection: %v", err)
			}
			if result.ProductStatus != contract.ProductUnderInvestigation {
				t.Fatalf("status = %s, want under_investigation", result.ProductStatus)
			}
			if !containsGlobalReason(result.Reasons, ReasonDomainSourceUnapproved) {
				t.Fatalf("reasons = %v, want domain_source_unapproved", result.Reasons)
			}
		})
	}

	t.Run("a newer revision is not authorized by itself", func(t *testing.T) {
		// A second applicable proof of advisory revision 2 exists in the bundle
		// and is complete, but only revision 1 is pinned: recency never selects,
		// and the unpinned newer proof is not silently discarded either, because
		// its identity matches the exact build.
		request, _ := control(t)
		revisionTwo := vendorItems(t, subject, containerA, proofVulnerableBuild)
		for index := range revisionTwo {
			revisionTwo[index].Locator = "records/proof/1"
			if revisionTwo[index].Type == "product_v1.vendor.advisory_revision" {
				replaceValue(&revisionTwo[index], "2")
			}
		}
		bundle := request.Bundle
		bundle.Evidence = append(bundle.Evidence, revisionTwo...)
		request.Bundle = bundle
		request.ExpectedBundleHash = mustBundleHash(t, bundle)
		result, err := Evaluate(request)
		if err != nil {
			t.Fatalf("control: %v", err)
		}
		if result.ProductStatus != contract.ProductUnderInvestigation {
			t.Fatalf("status = %s, want under_investigation: revision 2 is not pinned", result.ProductStatus)
		}
		if !containsGlobalReason(result.Reasons, ReasonDomainSourceUnapproved) {
			t.Fatalf("reasons = %v, want domain_source_unapproved", result.Reasons)
		}
		if len(result.Candidates) != 0 {
			t.Fatal("a newer revision must not sustain a candidate by itself")
		}
	})

	t.Run("a pin without any candidate blocks the affirmation", func(t *testing.T) {
		request, _ := control(t)
		domain := copyDomainContext(*request.Domain)
		domain.SourcePins = append(domain.SourcePins, SourcePin{
			Role: SourceRoleVendor, Source: "advisory-2.json",
			SourceHash: independentSourceHash("advisory 2 body\n"),
			AdvisoryID: strPointer("RHSA-2026:0009"), AdvisoryRevision: strPointer("1"),
		})
		request.Domain = &domain
		result, err := Evaluate(request)
		if err != nil {
			t.Fatalf("a pin without a candidate is uncertainty: %v", err)
		}
		if result.ProductStatus != contract.ProductUnderInvestigation {
			t.Fatalf("status = %s, want under_investigation", result.ProductStatus)
		}
		if !containsGlobalReason(result.Reasons, ReasonDomainSourceUnapproved) {
			t.Fatalf("reasons = %v, want domain_source_unapproved", result.Reasons)
		}
	})
}

// TestDomainGlobalBlockers is I-31: an absent source, a pin without a candidate,
// an unauthorized candidate and an unknown record all block the favourable
// chain.
func TestDomainGlobalBlockers(t *testing.T) {
	t.Run("pin without a candidate", func(t *testing.T) {
		bundle := productControlBundle(t, proofVulnerableBuild)
		request := productRequest(t, bundle)
		extra := SourcePin{Role: SourceRoleArtifact, Source: "unused.json", SourceHash: independentSourceHash("unused")}
		domain := copyDomainContext(*request.Domain)
		domain.SourcePins = append(domain.SourcePins, extra)
		request.Domain = &domain
		result, err := Evaluate(request)
		if err != nil {
			t.Fatalf("a pin without a candidate is uncertainty: %v", err)
		}
		if result.ProductStatus != contract.ProductUnderInvestigation {
			t.Fatalf("status = %s, want under_investigation", result.ProductStatus)
		}
		if !containsGlobalReason(result.Reasons, ReasonDomainSourceUnapproved) {
			t.Fatalf("reasons = %v, want domain_source_unapproved", result.Reasons)
		}
	})

	t.Run("candidate without a pin", func(t *testing.T) {
		bundle := productControlBundle(t, proofVulnerableBuild)
		request := productRequest(t, bundle)
		// Drop the vendor pin: its proof becomes unauthorized.
		domain := copyDomainContext(*request.Domain)
		domain.SourcePins = domain.SourcePins[:2]
		request.Domain = &domain
		result, err := Evaluate(request)
		if err != nil {
			t.Fatalf("an unauthorized candidate is uncertainty: %v", err)
		}
		if !containsGlobalReason(result.Reasons, ReasonDomainSourceUnapproved) {
			t.Fatalf("reasons = %v, want domain_source_unapproved", result.Reasons)
		}
	})

	t.Run("foreign source is not silently incorporated", func(t *testing.T) {
		bundle := productControlBundle(t, proofVulnerableBuild)
		request := productRequest(t, bundle)
		domain := copyDomainContext(*request.Domain)
		domain.SourcePins[1].SourceHash = independentSourceHash("another inspection body")
		request.Domain = &domain
		result, err := Evaluate(request)
		if err != nil {
			t.Fatalf("a hash mismatch of pins is uncertainty: %v", err)
		}
		if !containsGlobalReason(result.Reasons, ReasonDomainSourceUnapproved) {
			t.Fatalf("reasons = %v, want domain_source_unapproved", result.Reasons)
		}
	})
}

// TestDomainEvidenceAge is I-32: the age comparison is exact, with the three
// distinguishable outcomes and no overflow at the maximum policy.
func TestDomainEvidenceAge(t *testing.T) {
	base := mustStamp(t, time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC))

	t.Run("exact boundary cases", func(t *testing.T) {
		earlier := mustStamp(t, base.Add(-30*time.Second))
		current, reason := evidenceCurrent(earlier, base, 31)
		if !current || reason != ReasonVerified {
			t.Fatalf("age below the limit must verify: %v/%s", current, reason)
		}

		atLimit := mustStamp(t, base.Add(-30*time.Second))
		current, reason = evidenceCurrent(atLimit, base, 30)
		if current || reason != ReasonExpired {
			t.Fatalf("equality with the limit expires: %v/%s", current, reason)
		}

		future := mustStamp(t, base.Add(1*time.Second))
		current, reason = evidenceCurrent(future, base, 3600)
		if current || reason != ReasonFutureObservation {
			t.Fatalf("a future observation must be refused: %v/%s", current, reason)
		}

		justUnder := mustStamp(t, time.Date(2026, 10, 1, 11, 59, 30, 1, time.UTC))
		current, reason = evidenceCurrent(justUnder, base, 30)
		if !current || reason != ReasonVerified {
			t.Fatalf("29.999999999 s is below a 30 s limit and must verify: %v/%s", current, reason)
		}

		justOver := mustStamp(t, time.Date(2026, 10, 1, 11, 59, 29, 999999999, time.UTC))
		current, reason = evidenceCurrent(justOver, base, 30)
		if current || reason != ReasonExpired {
			t.Fatalf("30.000000001 s is over a 30 s limit and must expire: %v/%s", current, reason)
		}

		justInside := mustStamp(t, time.Date(2026, 10, 1, 11, 59, 30, 999999999, time.UTC))
		current, reason = evidenceCurrent(justInside, base, 31)
		if !current || reason != ReasonVerified {
			t.Fatalf("a fraction below the limit verifies: %v/%s", current, reason)
		}
	})

	t.Run("maximum policy does not overflow", func(t *testing.T) {
		veryOld := mustStamp(t, time.Date(1970, 1, 2, 0, 0, 0, 0, time.UTC))
		current, _ := evidenceCurrent(veryOld, base, MaxDomainEvidenceAgeSeconds)
		if !current {
			t.Fatal("the maximum policy must accept any non-future observation")
		}
		// An observation from 1800 is 226 years old, far beyond what a nanosecond
		// Duration can express for the maximum policy: 2^53-1 seconds times 1e9
		// wraps into a much smaller Duration, so a Duration comparison would
		// wrongly expire it. The seconds comparison accepts it, which is the
		// point of not converting the limit.
		ancient := mustStamp(t, time.Date(1800, 1, 1, 0, 0, 0, 0, time.UTC))
		current, reason := evidenceCurrent(ancient, base, MaxDomainEvidenceAgeSeconds)
		if !current || reason != ReasonVerified {
			t.Fatalf("an observation from 1800 must verify under the maximum policy: %v/%s", current, reason)
		}
		// One second over the maximum cannot be expressed as a Duration without
		// overflow, which is exactly why the comparison is done in seconds.
		oneSecondOver := mustStamp(t, time.Date(1970, 1, 1, 23, 59, 59, 0, time.UTC))
		current, reason = evidenceCurrent(oneSecondOver, base, 0)
		if current || reason != ReasonExpired {
			t.Fatalf("a policy of zero seconds expires: %v/%s", current, reason)
		}
	})
}

// TestProductExpirySeparation is I-33: an expired pack is an error without a
// result, while expired evidence inside a valid pack is an inconclusive result
// that keeps its references.
func TestProductExpirySeparation(t *testing.T) {
	t.Run("expired pack", func(t *testing.T) {
		request := productRequest(t, productControlBundle(t, proofVulnerableBuild))
		request.Admission.EvaluatedAt = mustStamp(t, evaluatedAt.AddDate(2, 0, 0))
		result, err := Evaluate(request)
		wantRulepackCode(t, err, rulepack.CodePackExpired)
		if !reflect.DeepEqual(result, Result{}) {
			t.Fatal("an expired pack must not produce a result")
		}
	})

	t.Run("expired evidence", func(t *testing.T) {
		bundle := productControlBundle(t, proofVulnerableBuild)
		request := productRequest(t, bundle)
		domain := copyDomainContext(*request.Domain)
		domain.MaximumEvidenceAgeSeconds = 1
		request.Domain = &domain
		result, err := Evaluate(request)
		if err != nil {
			t.Fatalf("expired evidence is an inconclusive result, not an error: %v", err)
		}
		if result.ProductStatus != contract.ProductUnderInvestigation {
			t.Fatalf("status = %s, want under_investigation", result.ProductStatus)
		}
		if !containsGlobalReason(result.Reasons, ReasonDomainEvidenceExpired) {
			t.Fatalf("reasons = %v, want domain_evidence_expired", result.Reasons)
		}
		if len(result.EvidenceReferences) == 0 {
			t.Fatal("the expired evidence must stay referenced")
		}
	})
}

// TestDomainPredicatesThreeValued is I-34: the five predicates keep their
// normative pass/fail/unknown behaviour, and missing prerequisites leave the
// checks empty instead of inventing an executed one.
func TestDomainPredicatesThreeValued(t *testing.T) {
	subject := baseSubject(t)

	assessmentFor := func(t *testing.T, bundle contract.Bundle) *domainAssessment {
		t.Helper()
		assessment := assessDomain(newResolver(mustCanonical(t, bundle), baseTarget(t), evaluatedAt, &referenceBudget{}), productDomainContext(t))
		return &assessment
	}

	t.Run("auxiliaries never fail", func(t *testing.T) {
		_ = subject
		empty := assessmentFor(t, productBundle(t))
		facts := newFactSet(newResolver(mustCanonical(t, productBundle(t)), baseTarget(t), evaluatedAt, &referenceBudget{}), empty)
		for _, predicate := range []rulepack.PredicateID{rulepack.PredicateRedhatProductMapped, rulepack.PredicateRedhatArtifactBound} {
			trace := runDomainCheck(rulepack.Check{CheckID: "check.aux", Predicate: predicate}, facts, empty)
			if trace.Outcome == OutcomeFail {
				t.Fatalf("%s must never fail", predicate)
			}
			if trace.Outcome != OutcomeUnknown {
				t.Fatalf("%s = %s, want unknown without records", predicate, trace.Outcome)
			}
		}
	})

	t.Run("terminal outcomes", func(t *testing.T) {
		cases := []struct {
			name      string
			bundle    contract.Bundle
			predicate rulepack.PredicateID
			want      CheckOutcome
		}{
			{
				"affected passes with its proof",
				productControlBundle(t, proofVulnerableBuild),
				rulepack.PredicateRedhatBuildAffected,
				OutcomePass,
			},
			{
				"affected fails with a complete foreign proof",
				productControlBundle(t, proofFixedBuild),
				rulepack.PredicateRedhatBuildAffected,
				OutcomeFail,
			},
			{
				"affected unknown without proofs",
				productBundle(t, mappingItems(t, subject, containerA)...),
				rulepack.PredicateRedhatBuildAffected,
				OutcomeUnknown,
			},
			{
				"fixed passes with its proof",
				productControlBundle(t, proofFixedBuild),
				rulepack.PredicateRedhatBuildFixed,
				OutcomePass,
			},
			{
				"code excluded passes with its proof",
				productControlBundle(t, proofCodeExcludedBuild),
				rulepack.PredicateRedhatCodeExcluded,
				OutcomePass,
			},
		}
		for _, testCase := range cases {
			t.Run(testCase.name, func(t *testing.T) {
				assessment := assessmentFor(t, testCase.bundle)
				resolver := newResolver(mustCanonical(t, testCase.bundle), baseTarget(t), evaluatedAt, &referenceBudget{})
				facts := newFactSet(resolver, assessment)
				trace := runDomainCheck(rulepack.Check{CheckID: "check.terminal", Predicate: testCase.predicate}, facts, assessment)
				if trace.Outcome != testCase.want {
					t.Fatalf("%s = %s, want %s (blockers %v)", testCase.predicate, trace.Outcome, testCase.want, assessment.blockers)
				}
			})
		}
	})
}

// TestDomainTerminalChecksWholeChain is I-35: the terminal verifies the whole
// chain even when the pack omits the auxiliaries, and the requirement map of the
// engine matches the admission map.
func TestDomainTerminalChecksWholeChain(t *testing.T) {
	t.Run("terminal without auxiliaries", func(t *testing.T) {
		bundle := productControlBundle(t, proofVulnerableBuild)
		request := productRequest(t, bundle,
			productRuleJSON("rule.affected", rulepack.OutputAffected, "redhat_build_affected"))
		result, err := Evaluate(request)
		if err != nil {
			t.Fatalf("the terminal alone must evaluate: %v", err)
		}
		if result.ProductStatus != contract.ProductAffected {
			t.Fatalf("status = %s, want affected", result.ProductStatus)
		}
	})

	t.Run("requirements match admission", func(t *testing.T) {
		// The rule fixtures declare every requirement the engine resolves for the
		// domain: dropping one from the fixture must be refused by admission, which
		// proves both maps agree without exporting either.
		for _, requirement := range []string{
			"finding.package_type", "finding.package_name", "finding.package_id",
			"image.bound_digest", "image.known_platform",
			"domain.mapping", "domain.artifact", "domain.vendor_proof", "domain.current",
		} {
			document := productPackDocument(productRuleJSON("rule.affected", rulepack.OutputAffected, "redhat_build_affected"))
			document = removeQuoted(document, requirement)
			if _, err := rulepack.Decode([]byte(document)); err == nil {
				t.Fatalf("admission accepted a rule without %s", requirement)
			}
		}
	})
}

// removeQuoted deletes one quoted JSON array element, tolerating both the
// middle position (trailing comma) and the last one (leading comma).
func removeQuoted(document, name string) string {
	quoted := `"` + name + `"`
	if strings.Contains(document, quoted+",") {
		return strings.Replace(document, quoted+",", "", 1)
	}
	if strings.Contains(document, ","+quoted) {
		return strings.Replace(document, ","+quoted, "", 1)
	}
	return document
}

func mustCanonical(t *testing.T, bundle contract.Bundle) contract.Bundle {
	t.Helper()
	ordered, err := canonicalCopy(bundle)
	if err != nil {
		t.Fatalf("canonical copy: %v", err)
	}
	return ordered
}
