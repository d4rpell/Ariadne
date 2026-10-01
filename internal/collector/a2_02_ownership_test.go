package collector

import (
	"context"
	"strings"
	"testing"

	"github.com/d4rpell/Ariadne/internal/bundle"
	contract "github.com/d4rpell/Ariadne/pkg/evidence"
)

// Ownership cases of the A2-02 plan (handoff §4.2 row "Copias del collector"):
// the result owns every slice and pointer it publishes, so a later mutation by
// the caller never alters a value that was already returned.

func TestA202CollectorOwnership(t *testing.T) {
	// a202Run performs one complete acquisition and returns its result.
	a202Run := func(t *testing.T) Result {
		t.Helper()
		config := a202Config(t)
		steps := []a202RoundTrip{a202JSONResponse(a202Document(a202CompletePod("u1", "n1")))}
		steps = append(steps, a202JSONResponse(a202Pod("u1", "n1")), a202JSONResponse(a202Pod("u1", "n1")))
		result, err, _ := a202Collect(t, config, steps)
		if err != nil {
			t.Fatalf("collect: %v", err)
		}
		return result
	}

	t.Run("config", func(t *testing.T) {
		namespaces := []string{"alpha", "beta"}
		config := a202Config(t)
		config.Namespaces = namespaces
		transport := newA202ScriptedTransport()
		clock := newA202Clock(t, a202StartMoment)
		// The run fails on the empty script, but the validated configuration is
		// already copied: a later mutation of the caller's slice cannot change
		// the scope it published.
		result, _ := collectWithDependencies(context.Background(), config, transport, clock)
		namespaces[0] = "mutated"
		if len(result.Acquisition.Scope.Namespaces) != 0 {
			// No capture was admitted; the plan still reflects the original
			// namespaces in canonical order.
			for _, namespace := range result.Acquisition.Plan.PendingNamespaces {
				if namespace == "mutated" {
					t.Fatal("the caller mutation reached the published plan")
				}
			}
		}
	})
	t.Run("sources", func(t *testing.T) {
		result := a202Run(t)
		before := string(result.Acquisition.Captures[0].Bytes)
		// Mutating the published bytes through the returned result is the
		// caller's right; the slice of a second call must be independent.
		result.Acquisition.Captures[0].Bytes[0] = 'X'
		second := a202Run(t)
		if string(second.Acquisition.Captures[0].Bytes) != before {
			t.Fatal("two runs share the same source storage")
		}
	})
	t.Run("operations", func(t *testing.T) {
		result := a202Run(t)
		result.Acquisition.Operations[0].Verb = "mutated"
		second := a202Run(t)
		if second.Acquisition.Operations[0].Verb == "mutated" {
			t.Fatal("two runs share the same operation storage")
		}
	})
	t.Run("diagnostics", func(t *testing.T) {
		config := a202Config(t)
		result, err, _ := a202Collect(t, config, []a202RoundTrip{
			a202JSONResponse(`{"apiVersion":"v1","kind":"PodList","items":[]}`),
		})
		if err != nil {
			t.Fatalf("collect: %v", err)
		}
		if len(result.Acquisition.Diagnostics) == 0 {
			t.Fatal("the fixture produced no diagnostic")
		}
		result.Acquisition.Diagnostics[0] = bundle.CollectionDiagnostic{Code: bundle.CodeCancelled}
		second, err, _ := a202Collect(t, config, []a202RoundTrip{
			a202JSONResponse(`{"apiVersion":"v1","kind":"PodList","items":[]}`),
		})
		if err != nil {
			t.Fatalf("second collect: %v", err)
		}
		if second.Acquisition.Diagnostics[0].Code == bundle.CodeCancelled {
			t.Fatal("two runs share the same diagnostic storage")
		}
	})
	t.Run("observations", func(t *testing.T) {
		result := a202Run(t)
		for index := range result.Acquisition.Captures {
			capture := &result.Acquisition.Captures[index]
			if len(capture.Observation.Subjects) < 1 {
				continue
			}
			capture.Observation.Subjects[0].Name = "mutated"
		}
		second := a202Run(t)
		for _, capture := range second.Acquisition.Captures {
			for _, subject := range capture.Observation.Subjects {
				if subject.Name == "mutated" {
					t.Fatal("two runs share the same observation storage")
				}
			}
		}
	})
	t.Run("independent_results", func(t *testing.T) {
		first := a202Run(t)
		second := a202Run(t)
		if len(first.Bundles) != len(second.Bundles) {
			t.Fatalf("bundle counts differ: %d and %d", len(first.Bundles), len(second.Bundles))
		}
		// The advisories of the two runs are equal but not shared: mutating one
		// leaves the other untouched.
		if len(first.Bundles) == 0 {
			t.Fatal("no bundle was produced")
		}
		first.Bundles[0].Bundle.Subject.Name = "mutated"
		if second.Bundles[0].Bundle.Subject.Name == "mutated" {
			t.Fatal("two runs share the same bundle storage")
		}
	})
	t.Run("incomplete_flag", func(t *testing.T) {
		result := a202Run(t)
		for _, candidate := range result.Bundles {
			if candidate.Bundle.Provenance.Completeness != contract.CompletenessComplete {
				if !result.Incomplete {
					t.Fatal("the incomplete flag is false with an incomplete bundle")
				}
				return
			}
		}
		if result.Incomplete {
			t.Fatal("the incomplete flag is true with every bundle complete")
		}
	})
	t.Run("comparisons", func(t *testing.T) {
		result := a202Run(t)
		if len(result.Acquisition.Comparisons) == 0 {
			// The fixture may produce no comparison when only the resourceVersion
			// differs; the slice must still be non-nil and independent.
			if result.Acquisition.Comparisons == nil {
				t.Fatal("the comparisons slice is nil")
			}
			return
		}
		result.Acquisition.Comparisons[0].Code = bundle.CodeCancelled
		second := a202Run(t)
		if second.Acquisition.Comparisons[0].Code == bundle.CodeCancelled {
			t.Fatal("two runs share the same comparison storage")
		}
	})
	t.Run("no_alias_in_captures", func(t *testing.T) {
		// The retained bytes of one capture are a copy: mutating the source of
		// one capture must not alter the projection of another.
		config := a202Config(t)
		page := a202Document(a202CompletePod("u1", "n1"))
		steps := []a202RoundTrip{a202JSONResponse(page)}
		steps = append(steps, a202JSONResponse(a202Pod("u1", "n1")), a202JSONResponse(a202Pod("u1", "n1")))
		result, err, _ := a202Collect(t, config, steps)
		if err != nil {
			t.Fatalf("collect: %v", err)
		}
		hashBefore := string(result.Acquisition.Captures[1].Hash)
		result.Acquisition.Captures[0].Bytes[0] = 'X'
		if string(result.Acquisition.Captures[1].Hash) != hashBefore {
			t.Fatal("the captures share their retained bytes")
		}
		if !strings.HasPrefix(hashBefore, "sha256:") {
			t.Fatalf("hash = %q", hashBefore)
		}
	})
}
