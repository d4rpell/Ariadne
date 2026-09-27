package evaluator

import (
	"reflect"
	"strconv"
	"testing"

	"github.com/d4rpell/Ariadne/internal/rulepack"
	contract "github.com/d4rpell/Ariadne/pkg/evidence"
)

// TestDomainPinCountDominance is the layered measurement accepted for X-2: the
// joint byte budget and the pin cardinality limit are separate limits, and the
// byte budget dominates the count for any realistic pin, so a request cannot
// reach 129 pins without failing the byte budget first. The two rules are
// measured independently here; no limit is modified to fabricate a boundary.
func TestDomainPinCountDominance(t *testing.T) {
	t.Run("cardinality alone is enforced", func(t *testing.T) {
		// Minimal pins: one-byte source, shortest role, full-length hash. The
		// hash dominates: 71 bytes per pin means 128 pins cannot fit in 4 KiB,
		// which is exactly the declared dominance.
		pin := SourcePin{
			Role:       SourceRoleMapping,
			Source:     "s",
			SourceHash: independentSourceHash("s"),
		}
		domain := DomainContext{MaximumEvidenceAgeSeconds: 60}
		for index := 0; index < MaxSourcePins; index++ {
			candidate := pin
			candidate.Source = "s" + suffixOf(index) + suffixOf(index/676)
			domain.SourcePins = append(domain.SourcePins, candidate)
		}
		if err := validateDomainContext(domain); err != nil {
			t.Fatalf("128 distinct pins are a valid form: %v", err)
		}

		// The same 128 pins exceed the joint byte budget, so production rejects
		// them before the count rule is reached.
		request := productRequest(t, productBundle(t))
		request.Domain = &domain
		if _, err := Evaluate(request); err == nil {
			t.Fatal("128 pins with their hashes must exceed the joint byte budget")
		} else if !IsCode(err, CodeInputLimit) && !rulepack.Is(err, rulepack.CodeInvalidContext) {
			t.Fatalf("the rejection must be a limit or a context error, got %v", err)
		}

		domain.SourcePins = append(domain.SourcePins, SourcePin{
			Role:       SourceRoleMapping,
			Source:     "extra",
			SourceHash: independentSourceHash("extra"),
		})
		if err := validateDomainContext(domain); err == nil {
			t.Fatal("129 pins must exceed the cardinality limit")
		}
	})

	t.Run("byte budget is reachable with a small pin count", func(t *testing.T) {
		// A single over-long source reaches the byte budget with one pin, which
		// proves the byte rule does not depend on the cardinality rule.
		request := productRequest(t, productBundle(t))
		domain := copyDomainContext(*request.Domain)
		domain.SourcePins = domain.SourcePins[:1]
		domain.SourcePins[0].Source = longString(MaxContextTotalBytes)
		request.Domain = &domain
		_, err := Evaluate(request)
		wantCode(t, err, CodeInputLimit)
	})

	t.Run("both limits are declared, neither is relaxed", func(t *testing.T) {
		if MaxSourcePins != 128 {
			t.Fatalf("the cardinality limit changed: %d", MaxSourcePins)
		}
		if MaxContextTotalBytes != 4<<10 {
			t.Fatalf("the joint byte budget changed: %d", MaxContextTotalBytes)
		}
	})
}

// TestProductLimitDominance records which limit wins when two of them could
// apply, so a boundary test cannot be built on an unreachable combination.
func TestProductLimitDominance(t *testing.T) {
	t.Run("the pack byte limit precedes the context form", func(t *testing.T) {
		request := productRequest(t, productBundle(t))
		request.PackBytes = make([]byte, rulepack.MaxPackBytes+1)
		wantLimitAndNoResult(t, request)
	})

	t.Run("the context byte budget precedes the context form", func(t *testing.T) {
		request := productRequest(t, productBundle(t))
		domain := DomainContext{MaximumEvidenceAgeSeconds: 0}
		request.Domain = &domain
		domain.SourcePins = []SourcePin{{
			Role:       SourceRoleMapping,
			Source:     longString(MaxContextTotalBytes),
			SourceHash: independentSourceHash("s"),
		}}
		request.Domain = &domain
		_, err := Evaluate(request)
		wantCode(t, err, CodeInputLimit)
	})

	t.Run("the bundle budget precedes the pack hash", func(t *testing.T) {
		request := productRequest(t, productBundle(t))
		request.Bundle.Evidence = make([]contract.EvidenceItem, MaxEvidenceItems+1)
		wantLimitAndNoResult(t, request)
	})

	t.Run("the global references are dominated by the bundle item limit", func(t *testing.T) {
		// The global inspection stores at most one reference per evidence item, and
		// the bundle admits at most MaxEvidenceItems of them, so the global
		// references alone cannot exceed the reference budget: what exceeds it is
		// the repetition of the same occurrence across requirements, traces, checks
		// and the aggregated list, which TestProductEvaluationBudgets exercises.
		if MaxEvidenceItems > MaxResultReferences {
			t.Fatalf("the bundle item limit (%d) would dominate the reference budget (%d) and no repetition would be needed to exceed it", MaxEvidenceItems, MaxResultReferences)
		}
	})

	t.Run("every reference of a stored result resolves", func(t *testing.T) {
		request := productReplayRequest(t, proofVulnerableBuild)
		result, err := Evaluate(request)
		if err != nil {
			t.Fatalf("control: %v", err)
		}
		if len(result.Candidates) == 0 || len(result.Candidates[0].EvidenceReferences) == 0 {
			t.Fatal("the candidate references must be charged and stored")
		}
		for _, reference := range result.EvidenceReferences {
			if reference.ItemIndex < 0 || reference.ItemIndex >= len(request.Bundle.Evidence) {
				t.Fatalf("the reference %d does not resolve", reference.ItemIndex)
			}
		}
	})
}

// crowdedDomainBundle returns the control bundle plus the requested number of
// complete mapping records, each under its own locator, so every copy is a
// separate pertinent candidate: the reference budget then has to count the
// repetitions and the global inspection together.
func crowdedDomainBundle(t *testing.T, copies int) contract.Bundle {
	t.Helper()
	subject := baseSubject(t)
	bundle := productControlBundle(t, proofVulnerableBuild)
	for copy := 0; copy < copies; copy++ {
		extra := mappingItems(t, subject, containerA)
		for index := range extra {
			extra[index].Locator = contract.SourceLocator("records/mapping/" + strconv.Itoa(copy+1))
		}
		bundle.Evidence = append(bundle.Evidence, extra...)
	}
	return bundle
}

// wantLimitAndNoResult requires the exact input_limit code and a zero result.
func wantLimitAndNoResult(t *testing.T, request Request) {
	t.Helper()
	result, err := Evaluate(request)
	wantCode(t, err, CodeInputLimit)
	if !reflect.DeepEqual(result, Result{}) {
		t.Fatal("a rejected limit must not return a partial result")
	}
}

func longString(size int) string {
	buffer := make([]byte, size)
	for index := range buffer {
		buffer[index] = 'a'
	}
	return string(buffer)
}
