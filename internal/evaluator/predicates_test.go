package evaluator

import (
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/d4rpell/Ariadne/internal/rulepack"
	contract "github.com/d4rpell/Ariadne/pkg/evidence"
)

// packWith replaces the control pack with one built from the given rules.
func packWith(t *testing.T, request Request, rules string) Request {
	t.Helper()
	document := packDocument(rules)
	mutated := request
	mutated.PackBytes = []byte(document)
	mutated.Admission = baseContext(t, document)
	return mutated
}

// TestPredicatesThreeValued is I-16: every predicate is three-valued, a missing,
// redacted, unavailable or future value is unknown instead of fail or pass, and
// the comparison is exact over UTF-8 bytes.
func TestPredicatesThreeValued(t *testing.T) {
	request := baseRequest(t)

	t.Run("equals passes on the exact value", func(t *testing.T) {
		result := evaluate(t, request)
		trace := ruleTrace(t, result, "rule.a")
		if len(trace.Checks) != 1 || trace.Checks[0].Outcome != OutcomePass {
			t.Fatalf("the control value must pass: %+v", trace.Checks)
		}
		if len(trace.Checks[0].EvidenceReferences) != 1 {
			t.Fatalf("the passing check must reference its evidence: %+v", trace.Checks[0])
		}
	})

	t.Run("equals fails on a different value", func(t *testing.T) {
		changed := packWith(t, request, ruleJSON("rule.a", cveA,
			`{"check_id":"check.a","predicate":"finding_field_equals","params":{"field":"fix_status","value":"not_fixed"}}`,
			`"bundle.complete","finding.row","finding.fix_status"`))
		result := evaluate(t, changed)
		trace := ruleTrace(t, result, "rule.a")
		if len(trace.Checks) != 1 || trace.Checks[0].Outcome != OutcomeFail {
			t.Fatalf("a different value must fail, not error: %+v", trace.Checks)
		}
		if !resultReason(result, ReasonChecksFailed) {
			t.Fatalf("a failing check must be visible: %v", result.Reasons)
		}
		if result.ProductStatus != contract.ProductUnderInvestigation {
			t.Fatalf("a failing check cannot change the profile outcome")
		}
	})

	t.Run("comparison is exact and case sensitive", func(t *testing.T) {
		changed := packWith(t, request, ruleJSON("rule.a", cveA,
			`{"check_id":"check.a","predicate":"finding_field_equals","params":{"field":"fix_status","value":"Fixed"}}`,
			`"bundle.complete","finding.row","finding.fix_status"`))
		result := evaluate(t, changed)
		if outcome := ruleTrace(t, result, "rule.a").Checks[0].Outcome; outcome != OutcomeFail {
			t.Fatalf("case must matter: %q", outcome)
		}
	})

	t.Run("comparison is exact over Unicode", func(t *testing.T) {
		composed := mutateRequest(t, request, func(bundle *contract.Bundle) {
			for index := range bundle.Evidence {
				if bundle.Evidence[index].Type == "prisma_v1.package_name" {
					bundle.Evidence[index].Value = strPointer("caf\u00e9")
					hash := independentValueHash("caf\u00e9")
					bundle.Evidence[index].ValueHash = &hash
				}
			}
		})
		decomposed := mutateRequest(t, composed, func(bundle *contract.Bundle) {
			for index := range bundle.Evidence {
				if bundle.Evidence[index].Type == "prisma_v1.package_name" {
					bundle.Evidence[index].Value = strPointer("cafe\u0301")
					hash := independentValueHash("cafe\u0301")
					bundle.Evidence[index].ValueHash = &hash
				}
			}
		})
		pack := packWith(t, decomposed, ruleJSON("rule.a", cveA,
			`{"check_id":"check.a","predicate":"finding_field_equals","params":{"field":"package_name","value":"caf\u00e9"}}`,
			`"bundle.complete","finding.row","finding.package_name"`))
		result := evaluate(t, pack)
		if outcome := ruleTrace(t, result, "rule.a").Checks[0].Outcome; outcome != OutcomeFail {
			t.Fatalf("no Unicode normalization may be applied: %q", outcome)
		}
	})

	t.Run("missing field is unknown", func(t *testing.T) {
		reduced := mutateRequest(t, request, func(bundle *contract.Bundle) {
			kept := []contract.EvidenceItem{}
			for _, item := range bundle.Evidence {
				if item.Type != "prisma_v1.installed_version" {
					kept = append(kept, item)
				}
			}
			bundle.Evidence = kept
		})
		pack := packWith(t, reduced, ruleJSON("rule.a", cveA,
			`{"check_id":"check.a","predicate":"finding_field_present","params":{"field":"installed_version"}}`,
			`"bundle.complete","finding.row","finding.installed_version"`))
		result := evaluate(t, pack)
		trace := ruleTrace(t, result, "rule.a")
		if trace.State != RuleMissingEvidence || !requiresReason(trace.Reasons, ReasonMissing) {
			t.Fatalf("a missing value leaves the requirement missing, never a fail: %+v", trace)
		}
		if len(trace.Checks) != 0 {
			t.Fatalf("a rule without its requirement runs no check: %+v", trace.Checks)
		}
		if !resultReason(result, ReasonRequirementsMissing) {
			t.Fatalf("the missing requirement must be visible: %v", result.Reasons)
		}
	})

	t.Run("unavailable confidence is unknown", func(t *testing.T) {
		reduced := mutateRequest(t, request, func(bundle *contract.Bundle) {
			for index := range bundle.Evidence {
				if bundle.Evidence[index].Type == "prisma_v1.fix_status" {
					bundle.Evidence[index].Confidence = contract.ProvenanceUnavailable
				}
			}
		})
		result := evaluate(t, reduced)
		trace := ruleTrace(t, result, "rule.a")
		if trace.State != RuleMissingEvidence || !requiresReason(trace.Reasons, ReasonMismatch) {
			t.Fatalf("evidence that does not carry the declared provenance is unknown: %+v", trace)
		}
	})

	t.Run("future observation is unknown", func(t *testing.T) {
		future := mutateRequest(t, request, func(bundle *contract.Bundle) {
			for index := range bundle.Evidence {
				if strings.HasPrefix(bundle.Evidence[index].Type, "prisma_v1.") {
					stamp := mustStamp(t, evaluatedAt.Add(time.Hour))
					bundle.Evidence[index].ObservedAt = stampPointer(stamp)
				}
			}
		})
		future.Target.ObservedAt = mustStamp(t, evaluatedAt.Add(time.Hour))
		result := evaluate(t, future)
		trace := ruleTrace(t, result, "rule.a")
		if trace.State != RuleMissingEvidence || !requiresReason(trace.Reasons, ReasonFutureObservation) {
			t.Fatalf("an observation after the evaluation instant is unknown: %+v", trace)
		}
	})

	t.Run("image platform comparison", func(t *testing.T) {
		matching := packWith(t, request, ruleJSON("rule.a", cveA,
			`{"check_id":"check.a","predicate":"image_platform_known","params":{"os":"linux","architecture":"amd64"}}`,
			`"bundle.complete","finding.row","image.bound_digest","image.known_platform"`))
		result := evaluate(t, matching)
		if outcome := ruleTrace(t, result, "rule.a").Checks[0].Outcome; outcome != OutcomePass {
			t.Fatalf("the accredited platform must pass: %q", outcome)
		}

		other := packWith(t, request, ruleJSON("rule.a", cveA,
			`{"check_id":"check.a","predicate":"image_platform_known","params":{"os":"linux","architecture":"arm64"}}`,
			`"bundle.complete","finding.row","image.bound_digest","image.known_platform"`))
		result = evaluate(t, other)
		if outcome := ruleTrace(t, result, "rule.a").Checks[0].Outcome; outcome != OutcomeFail {
			t.Fatalf("a different architecture must fail: %q", outcome)
		}

		unknownPlatform := mutateRequest(t, request, func(bundle *contract.Bundle) {
			bundle.Images[0].Platform = contract.Platform{Status: contract.PlatformUnknown}
		})
		unknownPlatform = packWith(t, unknownPlatform, ruleJSON("rule.a", cveA,
			`{"check_id":"check.a","predicate":"image_platform_known","params":{"os":"linux","architecture":"amd64"}}`,
			`"bundle.complete","finding.row","image.bound_digest","image.known_platform"`))
		result = evaluate(t, unknownPlatform)
		trace := ruleTrace(t, result, "rule.a")
		if trace.State != RuleMissingEvidence || len(trace.Checks) != 0 {
			t.Fatalf("an unobserved platform leaves the requirement missing: %+v", trace)
		}
		if !requiresReason(trace.Reasons, ReasonMissing) {
			t.Fatalf("the missing platform evidence must be named: %v", trace.Reasons)
		}
	})

	// Declared unreachable branch of this profile: a checked rule always has
	// every requirement satisfied, and a satisfied requirement of this vocabulary
	// is a unique interpretable value or a fully accredited image. The three
	// outcomes stay in the contract, but OutcomeUnknown cannot be isolated: the
	// trace rule of ADR-0013 §7 makes such a rule missing_evidence with empty
	// checks first. The unknowns that would produce it are asserted above at rule
	// level (missing, redacted, unavailable, conflict, future_observation), and
	// TestRuleTraceAggregation covers the missing-requirement path.
	t.Run("unknown check outcome is structurally unreachable", func(t *testing.T) {
		degradations := []func(*contract.Bundle){
			func(bundle *contract.Bundle) {
				bundle.Provenance.Completeness = contract.CompletenessPartial
				bundle.Provenance.Coverage.Termination = contract.TerminationAborted
				bundle.Provenance.Errors = []string{"capture partial"}
			},
			func(bundle *contract.Bundle) {
				bundle.Images[0].NormalizedDigest = nil
				bundle.Images[0].Platform = contract.Platform{Status: contract.PlatformUnknown}
			},
			func(bundle *contract.Bundle) { bundle.Images[0].RawImageID = nil },
			func(bundle *contract.Bundle) { bundle.Images[0].ObservedAt = nil },
		}
		for _, degrade := range degradations {
			degraded := mutateRequest(t, request, degrade)
			result := evaluate(t, degraded)
			for _, trace := range result.Rules {
				for _, check := range trace.Checks {
					if check.Outcome == OutcomeUnknown {
						t.Fatalf("an unknown check outcome was reachable: %+v", check)
					}
				}
			}
		}
	})
}

// TestRuleTraceAggregation is I-17: rules are ordered by ASCII id, a selector
// that does not match is not_applicable, missing requirements are ordered and
// leave the checks empty, and no check short-circuits another.
func TestRuleTraceAggregation(t *testing.T) {
	request := baseRequest(t)

	t.Run("order by rule id", func(t *testing.T) {
		result := evaluate(t, request)
		previous := ""
		for _, trace := range result.Rules {
			if trace.RuleID < previous {
				t.Fatalf("rules are not ordered by id: %q after %q", trace.RuleID, previous)
			}
			previous = trace.RuleID
		}
	})

	t.Run("selector without a match", func(t *testing.T) {
		result := evaluate(t, request)
		trace := ruleTrace(t, result, "rule.d")
		if trace.State != RuleNotApplicable || len(trace.Checks) != 0 {
			t.Fatalf("a rule of another vulnerability is not_applicable: %+v", trace)
		}
		if len(result.Rules) != 4 {
			t.Fatalf("every rule of the pack must be traced: %d", len(result.Rules))
		}
	})

	t.Run("missing requirements stop the checks", func(t *testing.T) {
		reduced := mutateRequest(t, request, func(bundle *contract.Bundle) {
			kept := []contract.EvidenceItem{}
			for _, item := range bundle.Evidence {
				if item.Type != "prisma_v1.package_id" {
					kept = append(kept, item)
				}
			}
			bundle.Evidence = kept
		})
		pack := packWith(t, reduced, ruleJSON("rule.a", cveA,
			`{"check_id":"check.a","predicate":"finding_field_present","params":{"field":"package_id"}}`,
			`"bundle.complete","finding.row","finding.package_id"`))
		result := evaluate(t, pack)
		trace := ruleTrace(t, result, "rule.a")
		if trace.State != RuleMissingEvidence {
			t.Fatalf("expected missing_evidence: %+v", trace)
		}
		if len(trace.MissingRequirements) != 1 || trace.MissingRequirements[0] != rulepack.FindingRequirement(rulepack.FieldPackageID) {
			t.Fatalf("the missing requirement must be named and ordered: %+v", trace.MissingRequirements)
		}
		if len(trace.Checks) != 0 {
			t.Fatalf("a rule with missing evidence runs no check: %+v", trace.Checks)
		}
		if !resultReason(result, ReasonRequirementsMissing) {
			t.Fatalf("the global reasons must report the missing requirement: %v", result.Reasons)
		}
	})

	t.Run("no short-circuit between checks", func(t *testing.T) {
		pack := packWith(t, request, ruleJSON("rule.a", cveA,
			`{"check_id":"check.b","predicate":"finding_field_present","params":{"field":"package_name"}},`+
				`{"check_id":"check.a","predicate":"finding_field_equals","params":{"field":"fix_status","value":"not_fixed"}}`,
			`"bundle.complete","finding.row","finding.fix_status","finding.package_name"`))
		result := evaluate(t, pack)
		trace := ruleTrace(t, result, "rule.a")
		if trace.State != RuleChecked || len(trace.Checks) != 2 {
			t.Fatalf("every check of a checked rule must run: %+v", trace)
		}
		if trace.Checks[0].CheckID != "check.a" || trace.Checks[0].Outcome != OutcomeFail {
			t.Fatalf("checks must be ordered by id and keep their own outcome: %+v", trace.Checks)
		}
		if trace.Checks[1].CheckID != "check.b" || trace.Checks[1].Outcome != OutcomePass {
			t.Fatalf("the second check must still run: %+v", trace.Checks)
		}
	})
}

// TestInitialProfileStatusBoundary is I-18: the profile rejects any other output
// at admission and every evaluated result stays inconclusive with the deferred
// domain assessment always present.
func TestInitialProfileStatusBoundary(t *testing.T) {
	request := baseRequest(t)

	declaredEmit := packWith(t, request, strings.Replace(
		ruleJSON("rule.a", cveA, `{"check_id":"check.a","predicate":"image_digest_bound","params":{}}`, `"bundle.complete","finding.row","image.bound_digest"`),
		`"emit":"under_investigation"`, `"emit":"fixed"`, 1))
	if _, err := Evaluate(declaredEmit); !rulepack.Is(err, rulepack.CodeUnsupportedPack) {
		t.Fatalf("an affirmative output must be rejected at admission, got %v", err)
	}

	governance := packWith(t, request, strings.Replace(
		ruleJSON("rule.a", cveA, `{"check_id":"check.a","predicate":"image_digest_bound","params":{}}`, `"bundle.complete","finding.row","image.bound_digest"`),
		`"emit":"under_investigation"`, `"emit":"under_investigation","risk_decision":"accepted"`, 1))
	if _, err := Evaluate(governance); !rulepack.Is(err, rulepack.CodeInvalidPack) {
		t.Fatalf("a governance field must not exist in a pack, got %v", err)
	}

	result := evaluate(t, request)
	if result.ProductStatus != contract.ProductUnderInvestigation {
		t.Fatalf("product_status must stay under_investigation: %q", result.ProductStatus)
	}
	if result.Exploitability != contract.ExploitabilityNotAssessed {
		t.Fatalf("exploitability must stay not_assessed: %q", result.Exploitability)
	}
	if !resultReason(result, ReasonDomainAssessmentDeferred) {
		t.Fatalf("domain_assessment_deferred must always be present: %v", result.Reasons)
	}
	for _, trace := range result.Rules {
		for _, check := range trace.Checks {
			if check.Outcome == OutcomePass && result.ProductStatus != contract.ProductUnderInvestigation {
				t.Fatalf("a passing check never yields a favourable state")
			}
		}
	}
}

// TestCheckRequirementsMatchPackValidation ties the execution-side requirement
// mapping to the validation rule of the pack package: a pack declaring exactly
// what the evaluator reads is admitted, and one requirement less is not.
func TestCheckRequirementsMatchPackValidation(t *testing.T) {
	request := baseRequest(t)
	checks := []rulepack.Check{
		{CheckID: "check.a", Predicate: rulepack.PredicateFindingFieldPresent, Params: rulepack.Params{Field: "fix_status", FieldSet: true}},
		{CheckID: "check.a", Predicate: rulepack.PredicateFindingFieldEquals, Params: rulepack.Params{Field: "fix_status", FieldSet: true, Value: "fixed", ValueSet: true}},
		{CheckID: "check.a", Predicate: rulepack.PredicateImageDigestBound},
		{CheckID: "check.a", Predicate: rulepack.PredicateImagePlatformKnown, Params: rulepack.Params{OS: "linux", OSSet: true, Architecture: "amd64", ArchitectureSet: true}},
	}
	for _, check := range checks {
		t.Run(string(check.Predicate), func(t *testing.T) {
			requirements := []string{`"bundle.complete"`, `"finding.row"`}
			for _, requirement := range checkRequirements(check) {
				requirements = append(requirements, `"`+string(requirement)+`"`)
			}
			admitted := packWith(t, request, ruleJSON("rule.a", cveA, checkDocument(check), strings.Join(requirements, ",")))
			if _, err := Evaluate(admitted); err != nil {
				t.Fatalf("a pack declaring exactly the read requirements must be admitted: %v", err)
			}

			if len(checkRequirements(check)) == 0 {
				return
			}
			short := requirements[:len(requirements)-1]
			rejected := packWith(t, request, ruleJSON("rule.a", cveA, checkDocument(check), strings.Join(short, ",")))
			if _, err := Evaluate(rejected); err == nil {
				t.Fatalf("omitting a mandatory requirement must be rejected")
			}
		})
	}
}

// checkDocument renders one check as the pack document spells it, so the
// consistency test builds the same shape a pack author writes.
func checkDocument(check rulepack.Check) string {
	switch check.Predicate {
	case rulepack.PredicateFindingFieldPresent:
		return `{"check_id":"check.a","predicate":"finding_field_present","params":{"field":"` + check.Params.Field + `"}}`
	case rulepack.PredicateFindingFieldEquals:
		return `{"check_id":"check.a","predicate":"finding_field_equals","params":{"field":"` + check.Params.Field + `","value":"` + check.Params.Value + `"}}`
	case rulepack.PredicateImageDigestBound:
		return `{"check_id":"check.a","predicate":"image_digest_bound","params":{}}`
	case rulepack.PredicateImagePlatformKnown:
		return `{"check_id":"check.a","predicate":"image_platform_known","params":{"os":"` + check.Params.OS + `","architecture":"` + check.Params.Architecture + `"}}`
	}
	return ""
}

// TestValidPackMissingEvidence is the other half of I-07: an admissible pack over
// missing evidence produces an inconclusive result with reasons and traces, never
// an error and never a favourable state.
func TestValidPackMissingEvidence(t *testing.T) {
	request := baseRequest(t)
	reduced := mutateRequest(t, request, func(bundle *contract.Bundle) {
		bundle.Evidence = []contract.EvidenceItem{}
		bundle.Images = []contract.ImageIdentity{}
	})
	result := evaluate(t, reduced)
	if result.ProductStatus != contract.ProductUnderInvestigation || result.Exploitability != contract.ExploitabilityNotAssessed {
		t.Fatalf("missing evidence never yields a favourable state: %+v", result)
	}
	if !resultReason(result, ReasonRequirementsMissing) {
		t.Fatalf("the reasons must be traceable: %v", result.Reasons)
	}
	if len(result.Rules) != 4 {
		t.Fatalf("every rule of the pack must be traced: %d", len(result.Rules))
	}
	for _, trace := range result.Rules {
		if trace.State == RuleChecked {
			t.Fatalf("a rule without evidence cannot be checked: %+v", trace)
		}
	}
}

// TestMissingRequirementsAreOrdered declares the requirements out of order and
// leaves three of them unsatisfied: the trace must order them lexicographically.
func TestMissingRequirementsAreOrdered(t *testing.T) {
	request := baseRequest(t)
	broken := mutateRequest(t, request, func(bundle *contract.Bundle) {
		kept := []contract.EvidenceItem{}
		for _, item := range bundle.Evidence {
			if !strings.HasPrefix(item.Type, "prisma_v1.") {
				kept = append(kept, item)
			}
		}
		bundle.Evidence = kept
		bundle.Provenance.Completeness = contract.CompletenessPartial
		bundle.Provenance.Coverage.Termination = contract.TerminationAborted
		bundle.Provenance.Errors = []string{"capture partial"}
	})
	pack := packWith(t, broken, ruleJSON("rule.a", cveA,
		`{"check_id":"check.a","predicate":"image_digest_bound","params":{}}`,
		`"finding.package_name","finding.row","bundle.complete","image.bound_digest"`))
	result := evaluate(t, pack)
	trace := ruleTrace(t, result, "rule.a")
	if trace.State != RuleMissingEvidence {
		t.Fatalf("expected missing_evidence: %+v", trace)
	}
	want := []rulepack.Requirement{
		rulepack.RequirementBundleComplete,
		rulepack.FindingRequirement(rulepack.FieldPackageName),
		rulepack.RequirementFindingRow,
	}
	if !reflect.DeepEqual(trace.MissingRequirements, want) {
		t.Fatalf("missing requirements must be ordered: %+v", trace.MissingRequirements)
	}
}
