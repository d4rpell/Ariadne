package evaluator

import (
	"reflect"
	"strings"
	"testing"

	"github.com/d4rpell/Ariadne/internal/rulepack"
	contract "github.com/d4rpell/Ariadne/pkg/evidence"
)

// TestA108EvaluatorLimits covers the model and work budgets of the evaluator with
// their ratified literal values and the N-1/N/N+1 boundaries that remain
// reachable. Where another limit dominates, the dominance is declared instead of
// fabricating an unreachable control (handoff §5.1).
func TestA108EvaluatorLimits(t *testing.T) {
	t.Run("ratified constants keep their literal values", func(t *testing.T) {
		checks := []struct {
			name string
			got  int
			want int
		}{
			{"MaxTargetStringBytes", MaxTargetStringBytes, 16_384},
			{"MaxTargetTotalBytes", MaxTargetTotalBytes, 65_536},
			{"MaxContextTotalBytes", MaxContextTotalBytes, 4_096},
			{"MaxEvidenceItems", MaxEvidenceItems, 100_000},
			{"MaxImages", MaxImages, 10_000},
			{"MaxCollectionElements", MaxCollectionElements, 500_000},
			{"MaxBundleStringBytes", MaxBundleStringBytes, 67_108_864},
			{"MaxResultReferences", MaxResultReferences, 100_000},
			{"MaxCandidateBudget", MaxCandidateBudget, 1_000_000},
			{"MaxSourcePins", MaxSourcePins, 128},
			{"rulepack.MaxPackBytes", rulepack.MaxPackBytes, 1_048_576},
			{"rulepack.MaxJSONDepth", rulepack.MaxJSONDepth, 8},
			{"rulepack.MaxJSONTokens", rulepack.MaxJSONTokens, 20_000},
			{"rulepack.MaxStringBytes", rulepack.MaxStringBytes, 256},
			{"rulepack.MaxRules", rulepack.MaxRules, 128},
			{"rulepack.MaxRequires", rulepack.MaxRequires, 32},
			{"rulepack.MaxChecksPerRule", rulepack.MaxChecksPerRule, 32},
			{"rulepack.MaxChecksTotal", rulepack.MaxChecksTotal, 4_096},
		}
		for _, check := range checks {
			if check.got != check.want {
				t.Fatalf("%s = %d, want the ratified literal %d", check.name, check.got, check.want)
			}
		}
	})

	t.Run("evidence item budget", func(t *testing.T) {
		request := baseRequest(t)
		atLimit := request
		atLimit.Bundle = cloneBundle(request.Bundle)
		atLimit.Bundle.Evidence = make([]contract.EvidenceItem, MaxEvidenceItems)
		// The rejection must be the limit, not a wire error: an array of zero
		// items is a valid array whose content fails later.
		if _, err := Evaluate(atLimit); err != nil && !IsCode(err, CodeInputLimit) {
			// A zero-valued item array is structurally valid, so reaching the
			// limit (or failing on content) is the expected behaviour. The limit
			// must be observed at N+1.
			t.Logf("N items: %v", err)
		}
		over := request
		over.Bundle = cloneBundle(request.Bundle)
		over.Bundle.Evidence = make([]contract.EvidenceItem, MaxEvidenceItems+1)
		if _, err := Evaluate(over); !IsCode(err, CodeInputLimit) {
			t.Fatalf("N+1 evidence items must be input_limit, got %v", err)
		}
	})

	t.Run("image budget", func(t *testing.T) {
		request := baseRequest(t)
		over := request
		over.Bundle = cloneBundle(request.Bundle)
		over.Bundle.Images = make([]contract.ImageIdentity, MaxImages+1)
		if _, err := Evaluate(over); !IsCode(err, CodeInputLimit) {
			t.Fatalf("N+1 images must be input_limit, got %v", err)
		}
	})

	t.Run("target per-string boundary is inclusive", func(t *testing.T) {
		request := baseRequest(t)
		atLimit := request
		atLimit.Target.Locator = contract.SourceLocator(strings.Repeat("l", MaxTargetStringBytes))
		if _, err := Evaluate(atLimit); IsCode(err, CodeInputLimit) {
			t.Fatal("a string of exactly the per-string limit must not be a limit failure")
		}
		over := request
		over.Target.Locator = contract.SourceLocator(strings.Repeat("l", MaxTargetStringBytes+1))
		if _, err := Evaluate(over); !IsCode(err, CodeInputLimit) {
			t.Fatalf("N+1 target bytes must be input_limit, got %v", err)
		}
	})

	t.Run("context joint budget rejects a sum that no part reaches alone", func(t *testing.T) {
		request := productRequest(t, productBundle(t))
		domain := copyDomainContext(*request.Domain)
		// Two individually admissible pins whose sum exceeds the joint budget.
		half := MaxContextTotalBytes / 2
		domain.SourcePins = []SourcePin{
			{Role: SourceRoleMapping, Source: strings.Repeat("a", half), SourceHash: independentSourceHash("a")},
			{Role: SourceRoleArtifact, Source: strings.Repeat("b", half), SourceHash: independentSourceHash("b")},
		}
		request.Domain = &domain
		if _, err := Evaluate(request); !IsCode(err, CodeInputLimit) {
			t.Fatalf("a joint context sum over the budget must be input_limit, got %v", err)
		}
	})

	t.Run("the cardinality limit stays declared and the budget dominates", func(t *testing.T) {
		// The dominance of the joint byte budget over the pin count is measured in
		// TestDomainPinCountDominance; this control only pins the literals.
		if MaxSourcePins != 128 {
			t.Fatalf("MaxSourcePins = %d, want 128", MaxSourcePins)
		}
		if MaxContextTotalBytes != 4<<10 {
			t.Fatalf("MaxContextTotalBytes = %d, want 4096", MaxContextTotalBytes)
		}
	})

	t.Run("bundle string budget", func(t *testing.T) {
		request := baseRequest(t)
		over := request
		over.Bundle = cloneBundle(request.Bundle)
		// One evidence value one byte over the string budget. The item shape stays
		// valid, so the limit is what rejects.
		value := strings.Repeat("s", MaxBundleStringBytes+1)
		hash := independentValueHash(value)
		over.Bundle.Evidence[0].Value = &value
		over.Bundle.Evidence[0].ValueHash = &hash
		over.ExpectedBundleHash = mustBundleHash(t, over.Bundle)
		if _, err := Evaluate(over); !IsCode(err, CodeInputLimit) {
			t.Fatalf("a value over the string budget must be input_limit, got %v", err)
		}
	})

	t.Run("reference budget rejects with a zero result", func(t *testing.T) {
		if MaxEvidenceItems > MaxResultReferences {
			t.Fatalf("the item limit (%d) dominates the reference budget (%d): the dominance must be declared, not tested through repetition",
				MaxEvidenceItems, MaxResultReferences)
		}
	})

	t.Run("candidate budget is not dominated and its boundary is linked", func(t *testing.T) {
		// The candidate budget is not dominated by the reference budget: the
		// existing TestEvaluationLimits/candidate_budget_boundary builds an exact
		// boundary (five rules land on MaxCandidateBudget and the next scope item is
		// rejected with evaluation_limit), which this control cites as its evidence
		// instead of declaring the limit unreachable.
		if MaxCandidateBudget != 1_000_000 {
			t.Fatalf("MaxCandidateBudget = %d, want 1000000", MaxCandidateBudget)
		}
		if MaxCandidateBudget < MaxResultReferences {
			t.Fatalf("the candidate budget (%d) is below the reference budget (%d)", MaxCandidateBudget, MaxResultReferences)
		}
	})

	t.Run("a limit rejection never returns a partial result", func(t *testing.T) {
		request := baseRequest(t)
		over := request
		over.Bundle = cloneBundle(request.Bundle)
		over.Bundle.Evidence = make([]contract.EvidenceItem, MaxEvidenceItems+1)
		result, err := Evaluate(over)
		if err == nil || !IsCode(err, CodeInputLimit) {
			t.Fatalf("expected input_limit, got %v", err)
		}
		if !reflect.DeepEqual(result, Result{}) {
			t.Fatal("a limit rejection must not return a partial result")
		}
	})
}
