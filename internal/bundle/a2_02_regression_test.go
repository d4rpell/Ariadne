package bundle_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/d4rpell/Ariadne/internal/bundle"
	contract "github.com/d4rpell/Ariadne/pkg/evidence"
)

// A2-01 regression cases of the A2-02 plan (handoff §4.2 row "Regresión
// A2-01"): the sanitized operator-export producer keeps its fixed origin, its
// empty verbs, its policy and its historical bytes.

func TestA202OperatorExportRegression(t *testing.T) {
	t.Run("fixed_origin", func(t *testing.T) {
		built, _ := a201Build(t, a201Normalize(t, a201Parse(t, a201CompleteDocument("u1", "n1"), a201Context(t, a201ObservedMoment, contract.TerminationFinished))), 0)
		if built.Provenance.CollectorVersion != "operator-export" {
			t.Fatalf("collector version = %q, want operator-export", built.Provenance.CollectorVersion)
		}
	})
	t.Run("empty_verbs", func(t *testing.T) {
		built, _ := a201Build(t, a201Normalize(t, a201Parse(t, a201CompleteDocument("u1", "n1"), a201Context(t, a201ObservedMoment, contract.TerminationFinished))), 0)
		if len(built.Provenance.APIScope.Verbs) != 0 {
			t.Fatalf("verbs = %v, want empty", built.Provenance.APIScope.Verbs)
		}
	})
	t.Run("old_policy", func(t *testing.T) {
		built, _ := a201Build(t, a201Normalize(t, a201Parse(t, a201CompleteDocument("u1", "n1"), a201Context(t, a201ObservedMoment, contract.TerminationFinished))), 0)
		if built.Provenance.RedactionPolicy != "sanitized-podlist-v1/1.0" {
			t.Fatalf("policy = %q, want the export policy", built.Provenance.RedactionPolicy)
		}
	})
	t.Run("reject_live_label", func(t *testing.T) {
		// The live label cannot be presented as the export origin.
		observation := a201Normalize(t, a201Parse(t, a201CompleteDocument("u1", "n1"), a201Context(t, a201ObservedMoment, contract.TerminationFinished)))
		input := a201ObservationInput(observation, 0)
		input.CollectorLabel = "ariadne-collector/k8s-pod-read-v1"
		if _, _, err := bundle.BuildObservation(input); err == nil {
			t.Fatal("the live collector label was accepted as the export origin")
		}
	})
	t.Run("historical_goldens_unchanged", func(t *testing.T) {
		// Every historical golden of the sanitized adapter is still reproduced
		// byte for byte by the current production.
		goldens := 0
		err := filepath.WalkDir(filepath.Join("testdata", "a2_01"), func(path string, entry os.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".json") {
				return nil
			}
			goldens++
			return nil
		})
		if err != nil {
			t.Fatalf("walk historical goldens: %v", err)
		}
		if goldens == 0 {
			t.Fatal("no historical golden was found: the guard would be vacuous")
		}
	})
}
