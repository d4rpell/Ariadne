package evaluator

import (
	"testing"

	"github.com/d4rpell/Ariadne/internal/rulepack"
	contract "github.com/d4rpell/Ariadne/pkg/evidence"
)

// TestProductCoverageIsNotProof is I-36: coverage=complete, a complete import
// and a scanner fix_status never substitute the vendor support the affirmative
// chain requires. A rule that only reads the import must not sustain any state.
func TestProductCoverageIsNotProof(t *testing.T) {
	subject := baseSubject(t)

	t.Run("coverage complete without the chain publishes nothing", func(t *testing.T) {
		// The bundle is complete, the import is complete and the row declares
		// fix_status=fixed, but no mapping, artifact or vendor proof exists.
		bundle := productBundle(t)
		result, err := Evaluate(productRequest(t, bundle))
		if err != nil {
			t.Fatalf("a complete import is uncertainty, not a rejection: %v", err)
		}
		if result.ProductStatus != contract.ProductUnderInvestigation {
			t.Fatalf("status = %s, want under_investigation", result.ProductStatus)
		}
		if len(result.Candidates) != 0 {
			t.Fatal("coverage and the scanner row must not sustain a candidate")
		}
		if !containsGlobalReason(result.Reasons, ReasonRequirementsMissing) {
			t.Fatalf("reasons = %v, want requirements_missing", result.Reasons)
		}
	})

	t.Run("a scanner-only rule retires its own candidate", func(t *testing.T) {
		// A branch that checks the scanner row alone passes its check, but since
		// it demands the domain chain, the missing evidence leaves it without a
		// candidate: the import column has no authority over the state.
		bundle := productBundle(t)
		scannerOnly := productRuleJSON("rule.scanner", rulepack.OutputFixed, "redhat_build_fixed")
		scannerOnly = addRequirement(scannerOnly, `"finding.fix_status"`)
		scannerOnly = addCheck(scannerOnly,
			`{"check_id":"check.fix_status","predicate":"finding_field_equals","params":{"field":"fix_status","value":"fixed"}}`)
		result, err := Evaluate(productRequest(t, bundle, scannerOnly))
		if err != nil {
			t.Fatalf("control: %v", err)
		}
		if result.ProductStatus != contract.ProductUnderInvestigation {
			t.Fatalf("status = %s, want under_investigation", result.ProductStatus)
		}
		if len(result.Candidates) != 0 {
			t.Fatal("fix_status alone must never sustain a state")
		}
	})

	t.Run("severity is not part of any decision", func(t *testing.T) {
		// Changing the severity of the row must not change the result of the
		// control: it is a source fact, not an operand of the affirmative chain.
		// The fixture carries the item, and the mutation is verified to change
		// the bundle before the results are compared, so the test cannot pass
		// because nothing was replaced.
		bundle := productControlBundle(t, proofVulnerableBuild)
		changed := cloneBundle(bundle)
		replaced := 0
		for index := range changed.Evidence {
			if changed.Evidence[index].Type == "prisma_v1.severity" {
				replaceValue(&changed.Evidence[index], "critical")
				replaced++
			}
		}
		if replaced != 1 {
			t.Fatalf("the fixture must carry exactly one severity item, found %d", replaced)
		}
		if mustBundleHash(t, changed) == mustBundleHash(t, bundle) {
			t.Fatal("the severity mutation did not change the bundle hash")
		}
		control, err := Evaluate(productRequest(t, bundle))
		if err != nil {
			t.Fatalf("control: %v", err)
		}
		mutated, err := Evaluate(productRequest(t, changed))
		if err != nil {
			t.Fatalf("severity is inert: %v", err)
		}
		if mutated.ProductStatus != control.ProductStatus || mutated.Exploitability != control.Exploitability {
			t.Fatalf("severity changed the result: %s/%s vs %s/%s",
				mutated.ProductStatus, mutated.Exploitability, control.ProductStatus, control.Exploitability)
		}
		if len(mutated.EvidenceReferences) != len(control.EvidenceReferences) {
			t.Fatalf("severity changed the references: %d vs %d", len(mutated.EvidenceReferences), len(control.EvidenceReferences))
		}
	})

	t.Run("an old upstream version never rewrites the state", func(t *testing.T) {
		// The scanner claims a vulnerable upstream version, but the exact vendor
		// proof of this build says fixed: the proof decides, and the earlier
		// upstream string is not an operand.
		bundle := productControlBundle(t, proofFixedBuild)
		changed := cloneBundle(bundle)
		for index := range changed.Evidence {
			if changed.Evidence[index].Type == "prisma_v1.installed_version" {
				replaceValue(&changed.Evidence[index], "1.2.3-1")
			}
		}
		result, err := Evaluate(productRequest(t, changed,
			productRuleJSON("rule.fixed", rulepack.OutputFixed, "redhat_build_fixed")))
		if err != nil {
			t.Fatalf("control: %v", err)
		}
		if result.ProductStatus != contract.ProductFixed {
			t.Fatalf("status = %s, want fixed: the exact proof decides, not the upstream string", result.ProductStatus)
		}
	})

	_ = subject
}
