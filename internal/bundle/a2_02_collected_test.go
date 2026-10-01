package bundle_test

import (
	"strings"
	"testing"

	"github.com/d4rpell/Ariadne/internal/bundle"
	"github.com/d4rpell/Ariadne/internal/normalize"
	contract "github.com/d4rpell/Ariadne/pkg/evidence"
)

// a202Build assembles the acquisition of one document and builds the bundle of
// its only subject.
func a202Build(t *testing.T, document string, termination contract.CoverageTermination) (contract.Bundle, bundle.ObservationDiagnostics, error) {
	t.Helper()
	// The admitted observation carries the effective termination of the run; the
	// acquisition record declares the same one, exactly as the collector builds
	// it once the global termination is known.
	source := a202BuildSource(t, document, "capture-000001.json", termination)
	errors := []string{}
	if termination == contract.TerminationAborted {
		errors = []string{"collector: forbidden"}
	}
	acquisition := a202Acquisition(t, []a202Source{source}, termination, errors)
	return bundle.BuildCollectedObservation(a202Input(acquisition, 1, 0))
}

func TestA202CollectedCompleteness(t *testing.T) {
	// The matrix of §4.5: the completeness is asserted before the bundle, so a
	// later validator rejection never substitutes for the precedence assertion.
	cases := map[string]struct {
		document    string
		termination contract.CoverageTermination
		want        contract.Completeness
	}{
		"finished_complete":         {a202Document(a202Pod("u1", "n1")), contract.TerminationFinished, contract.CompletenessComplete},
		"finished_missing_category": {a202Document(a202IncompleteDocument("u1", "n1")), contract.TerminationFinished, contract.CompletenessPartial},
		"finished_rejected_peer":    {a202Document(a202Pod("u1", "n1"), a202UIDOnlyDocument("u2", "n2")), contract.TerminationFinished, contract.CompletenessPartial},
		"finished_no_progress":      {a202Document(a202IdentityOnlyDocument("u1", "n1")), contract.TerminationFinished, contract.CompletenessUnknown},
		"aborted_progress":          {a202Document(a202Pod("u1", "n1")), contract.TerminationAborted, contract.CompletenessPartial},
	}
	for name, testCase := range cases {
		t.Run(name, func(t *testing.T) {
			built, _, err := a202Build(t, testCase.document, testCase.termination)
			if err != nil {
				t.Fatalf("build: %v", err)
			}
			got := built.Provenance.Completeness
			if got != testCase.want {
				t.Fatalf("completeness = %q, want %q", got, testCase.want)
			}
			// The bundle that follows must still be valid.
			if _, err := bundle.Encode(built); err != nil {
				t.Fatalf("the built bundle is not valid: %v", err)
			}
		})
	}
	t.Run("finished_collision", func(t *testing.T) {
		built, diagnostics, err := a202Build(t, a202Document(a202CollisionDocument("u1", "n1")), contract.TerminationFinished)
		if err != nil {
			t.Fatalf("build: %v", err)
		}
		if built.Provenance.Completeness != contract.CompletenessPartial {
			t.Fatalf("completeness = %q, want partial", built.Provenance.Completeness)
		}
		if !a202HasError(built.Provenance.Errors, "bundle: scope collision omitted") {
			t.Fatalf("errors = %v, want the collision error", built.Provenance.Errors)
		}
		if !a202HasWarning(built.Provenance.Warnings, "scope_mismatch", "contradictory", "scope collision across container classes: regular, init") {
			t.Fatalf("warnings = %+v, want the collision warning", built.Provenance.Warnings)
		}
		if len(diagnostics.Omitted) != 2 {
			t.Fatalf("omitted = %d, want both collided containers", len(diagnostics.Omitted))
		}
		// The observed categories are preserved even though both images were
		// omitted: the document declares all three categories explicitly.
		if len(built.ObservedContainerClasses) != 3 {
			t.Fatalf("observed classes = %v, want the three categories preserved", built.ObservedContainerClasses)
		}
	})
	t.Run("acquisition_diagnostic_reaches_the_errors", func(t *testing.T) {
		// A resource_version_missing diagnostic degrades the completeness AND its
		// cause stays visible in the errors of the bundle with the closed text
		// "collector: <code>": the verdict never substitutes for the reason.
		source := a202BuildSource(t, a202Document(a202Pod("u1", "n1")), "capture-000001.json", contract.TerminationFinished)
		acquisition := a202Acquisition(t, []a202Source{source}, contract.TerminationFinished, nil)
		acquisition.Diagnostics = []bundle.CollectionDiagnostic{{Code: bundle.CodeResourceVersionMiss}}
		built, _, err := bundle.BuildCollectedObservation(a202Input(acquisition, 1, 0))
		if err != nil {
			t.Fatalf("build: %v", err)
		}
		if built.Provenance.Completeness != contract.CompletenessPartial {
			t.Fatalf("completeness = %q, want partial", built.Provenance.Completeness)
		}
		if !a202HasError(built.Provenance.Errors, "collector: resource_version_missing") {
			t.Fatalf("errors = %v, want the closed diagnostic message", built.Provenance.Errors)
		}
	})
	t.Run("foreign_contaminating_diagnostic_is_copied", func(t *testing.T) {
		// A contaminating diagnostic of another capture degrades every bundle of
		// the run, so its cause must be visible in this one too: the degradation
		// and its reason travel together.
		first := a202BuildSource(t, a202Document(a202Pod("u1", "n1")), "capture-000001.json", contract.TerminationFinished)
		second := a202BuildSource(t, a202Document(a202PodWithImageID("u1", "n1", "sha256:"+strings.Repeat("b", 64))), "capture-000002.json", contract.TerminationFinished)
		acquisition := a202Acquisition(t, []a202Source{first, second}, contract.TerminationFinished, nil)
		foreign := uint64(2)
		acquisition.Diagnostics = []bundle.CollectionDiagnostic{{
			Code:           bundle.CodePodRejected,
			CaptureOrdinal: &foreign,
		}}
		built, _, err := bundle.BuildCollectedObservation(a202Input(acquisition, 1, 0))
		if err != nil {
			t.Fatalf("build: %v", err)
		}
		if !a202HasError(built.Provenance.Errors, "collector: pod_rejected") {
			t.Fatalf("errors = %v, want the closed diagnostic of the run-wide degradation", built.Provenance.Errors)
		}
	})
	t.Run("foreign_local_diagnostic_is_not_copied", func(t *testing.T) {
		// A diagnostic of another capture that does not contaminate the run never
		// lands in this bundle: the error list of a subject cites its own capture
		// and the run, nothing else.
		first := a202BuildSource(t, a202Document(a202Pod("u1", "n1")), "capture-000001.json", contract.TerminationFinished)
		second := a202BuildSource(t, a202Document(a202PodWithImageID("u1", "n1", "sha256:"+strings.Repeat("b", 64))), "capture-000002.json", contract.TerminationFinished)
		acquisition := a202Acquisition(t, []a202Source{first, second}, contract.TerminationFinished, nil)
		foreign := uint64(2)
		acquisition.Diagnostics = []bundle.CollectionDiagnostic{{
			Code:           bundle.CodeNotFound,
			CaptureOrdinal: &foreign,
		}}
		built, _, err := bundle.BuildCollectedObservation(a202Input(acquisition, 1, 0))
		if err != nil {
			t.Fatalf("build: %v", err)
		}
		if a202HasError(built.Provenance.Errors, "collector: not_found") {
			t.Fatalf("a foreign local diagnostic was copied: %v", built.Provenance.Errors)
		}
	})
	t.Run("aborted_collision", func(t *testing.T) {
		built, _, err := a202Build(t, a202Document(a202CollisionDocument("u1", "n1")), contract.TerminationAborted)
		if err != nil {
			t.Fatalf("build: %v", err)
		}
		if built.Provenance.Completeness != contract.CompletenessPartial {
			t.Fatalf("completeness = %q, want partial", built.Provenance.Completeness)
		}
	})
	t.Run("unknown_collision", func(t *testing.T) {
		source := a202BuildSource(t, a202Document(a202CollisionDocument("u1", "n1")), "capture-000001.json", contract.TerminationUnknown)
		acquisition := a202Acquisition(t, []a202Source{source}, contract.TerminationUnknown, nil)
		built, _, err := bundle.BuildCollectedObservation(a202Input(acquisition, 1, 0))
		if err != nil {
			t.Fatalf("build: %v", err)
		}
		if built.Provenance.Completeness != contract.CompletenessUnknown {
			t.Fatalf("completeness = %q, want unknown: a collision never ascends a run whose termination is unknown", built.Provenance.Completeness)
		}
	})
	t.Run("all_images_collided", func(t *testing.T) {
		// The container name collides in every class with a status: all the
		// evidence is omitted and the categories are still observed.
		document := a202Document(`{"apiVersion":"v1","kind":"Pod","metadata":{"uid":"u1","namespace":"` + a202Namespace + `","name":"n1"},` +
			`"spec":{"containers":[{"name":"api","image":"` + a202Image + `"}],"initContainers":[{"name":"api","image":"registry.example/init:release"}],"ephemeralContainers":[{"name":"api","image":"registry.example/eph:release"}]},` +
			`"status":{"containerStatuses":[{"name":"api","imageID":"` + a202ImageID + `"}],"initContainerStatuses":[{"name":"api","imageID":"sha256:bb"}],"ephemeralContainerStatuses":[{"name":"api","imageID":"sha256:cc"}]}}`)
		for name, testCase := range map[string]struct {
			termination contract.CoverageTermination
			want        contract.Completeness
		}{
			"finished": {contract.TerminationFinished, contract.CompletenessPartial},
			"aborted":  {contract.TerminationAborted, contract.CompletenessPartial},
			"unknown":  {contract.TerminationUnknown, contract.CompletenessUnknown},
		} {
			t.Run(name, func(t *testing.T) {
				source := a202BuildSource(t, document, "capture-000001.json", testCase.termination)
				errors := []string{}
				if testCase.termination == contract.TerminationAborted {
					errors = []string{"collector: forbidden"}
				}
				acquisition := a202Acquisition(t, []a202Source{source}, testCase.termination, errors)
				built, diagnostics, err := bundle.BuildCollectedObservation(a202Input(acquisition, 1, 0))
				if err != nil {
					t.Fatalf("build: %v", err)
				}
				if built.Provenance.Completeness != testCase.want {
					t.Fatalf("completeness = %q, want %q", built.Provenance.Completeness, testCase.want)
				}
				if len(built.Evidence) != 0 {
					t.Fatalf("evidence = %d, want every collided image omitted", len(built.Evidence))
				}
				if len(diagnostics.Omitted) != 3 {
					t.Fatalf("omitted = %d, want the three collided containers", len(diagnostics.Omitted))
				}
				if len(built.ObservedContainerClasses) != 3 {
					t.Fatalf("observed classes = %v, want the three categories preserved", built.ObservedContainerClasses)
				}
			})
		}
	})
	t.Run("no_bundle_without_subject", func(t *testing.T) {
		// A capture with no accepted subject produces no bundle: the builder is
		// never called for a subject that does not exist.
		source := a202BuildSource(t, `{"apiVersion":"v1","kind":"PodList","metadata":{"resourceVersion":"7"},"items":[]}`, "capture-000001.json", contract.TerminationFinished)
		acquisition := a202Acquisition(t, []a202Source{source}, contract.TerminationUnknown, nil)
		if len(acquisition.Captures[0].Observation.Subjects) != 0 {
			t.Fatal("an empty list produced subjects")
		}
	})
}

func TestA202CollectedProjection(t *testing.T) {
	t.Run("requested_raw_status_separate", func(t *testing.T) {
		document := a202Document(`{"apiVersion":"v1","kind":"Pod","metadata":{"uid":"u1","namespace":"` + a202Namespace + `","name":"n1"},` +
			`"spec":{"containers":[{"name":"api","image":"registry.example/app:requested"}],"initContainers":[],"ephemeralContainers":[]},` +
			`"status":{"containerStatuses":[{"name":"api","image":"registry.example/app:status","imageID":"sha256:observed"}],"initContainerStatuses":[],"ephemeralContainerStatuses":[]}}`)
		built, _, err := a202Build(t, document, contract.TerminationFinished)
		if err != nil {
			t.Fatalf("build: %v", err)
		}
		if len(built.Images) != 1 {
			t.Fatalf("images = %d, want 1", len(built.Images))
		}
		image := built.Images[0]
		if image.RequestedImage == nil || *image.RequestedImage != "registry.example/app:requested" {
			t.Fatalf("requested = %v", image.RequestedImage)
		}
		if image.RawImageID == nil || *image.RawImageID != "sha256:observed" {
			t.Fatalf("raw = %v", image.RawImageID)
		}
		if image.NormalizedDigest != nil {
			t.Fatalf("normalized digest = %v, want nil", image.NormalizedDigest)
		}
	})
	t.Run("digest_shaped_raw", func(t *testing.T) {
		// A raw value that looks exactly like a digest is never promoted.
		built, _, err := a202Build(t, a202Document(a202Pod("u1", "n1")), contract.TerminationFinished)
		if err != nil {
			t.Fatalf("build: %v", err)
		}
		for _, image := range built.Images {
			if image.NormalizedDigest != nil {
				t.Fatalf("a digest-shaped raw value was promoted: %v", *image.NormalizedDigest)
			}
			if image.Platform.Status != contract.PlatformUnknown {
				t.Fatalf("platform = %q, want unknown", image.Platform.Status)
			}
			if image.Platform.OS != "" || image.Platform.Architecture != "" {
				t.Fatalf("platform os/architecture = %q/%q, want empty", image.Platform.OS, image.Platform.Architecture)
			}
		}
	})
	t.Run("unknown_platform", func(t *testing.T) {
		built, _, err := a202Build(t, a202Document(a202Pod("u1", "n1")), contract.TerminationFinished)
		if err != nil {
			t.Fatalf("build: %v", err)
		}
		if built.Images[0].Platform.Status != contract.PlatformUnknown {
			t.Fatal("the platform is not unknown")
		}
	})
	t.Run("only_image_id_evidence", func(t *testing.T) {
		document := a202Document(`{"apiVersion":"v1","kind":"Pod","metadata":{"uid":"u1","namespace":"` + a202Namespace + `","name":"n1","resourceVersion":"9","ownerReferences":[{"apiVersion":"apps/v1","kind":"ReplicaSet","name":"rs","uid":"o1"}]},` +
			`"spec":{"containers":[{"name":"api","image":"` + a202Image + `"}],"initContainers":[],"ephemeralContainers":[]},` +
			`"status":{"containerStatuses":[{"name":"api","imageID":"` + a202ImageID + `","image":"` + a202Image + `","ready":true,"state":{"running":{}},"restartCount":2}],"initContainerStatuses":[],"ephemeralContainerStatuses":[]}}`)
		built, _, err := a202Build(t, document, contract.TerminationFinished)
		if err != nil {
			t.Fatalf("build: %v", err)
		}
		if len(built.Evidence) != 1 {
			t.Fatalf("evidence = %d, want exactly one item", len(built.Evidence))
		}
		item := built.Evidence[0]
		if item.Type != "container_status.image_id" {
			t.Fatalf("evidence type = %q", item.Type)
		}
		if item.Confidence != contract.ProvenanceObserved {
			t.Fatalf("confidence = %q, want observed", item.Confidence)
		}
		if built.Subject.OwnerChain != "" {
			t.Fatalf("owner chain = %q, want empty", built.Subject.OwnerChain)
		}
	})
	t.Run("permuted_statuses", func(t *testing.T) {
		// The statuses are associated by name, never by index: the values and
		// the locators must follow the names.
		document := a202Document(`{"apiVersion":"v1","kind":"Pod","metadata":{"uid":"u1","namespace":"` + a202Namespace + `","name":"n1"},` +
			`"spec":{"containers":[{"name":"first","image":"registry.example/first:release"},{"name":"second","image":"registry.example/second:release"}],"initContainers":[],"ephemeralContainers":[]},` +
			`"status":{"containerStatuses":[{"name":"second","imageID":"sha256:bbbb"},{"name":"first","imageID":"sha256:aaaa"}],"initContainerStatuses":[],"ephemeralContainerStatuses":[]}}`)
		built, _, err := a202Build(t, document, contract.TerminationFinished)
		if err != nil {
			t.Fatalf("build: %v", err)
		}
		locators := map[string]string{}
		values := map[string]string{}
		for _, item := range built.Evidence {
			if item.Value == nil {
				continue
			}
			locators[string(item.Scope.ContainerName)] = string(item.Locator)
			values[string(item.Scope.ContainerName)] = *item.Value
		}
		if values["first"] != "sha256:aaaa" {
			t.Fatalf("first = %q, want its own observed value", values["first"])
		}
		if values["second"] != "sha256:bbbb" {
			t.Fatalf("second = %q, want its own observed value", values["second"])
		}
		if !strings.Contains(locators["first"], "containerStatuses[1].imageID") {
			t.Fatalf("first locator = %q, want its own position", locators["first"])
		}
		if !strings.Contains(locators["second"], "containerStatuses[0].imageID") {
			t.Fatalf("second locator = %q, want its own position", locators["second"])
		}
	})
	t.Run("cross_class_collision", func(t *testing.T) {
		built, diagnostics, err := a202Build(t, a202Document(a202CollisionDocument("u1", "n1")), contract.TerminationFinished)
		if err != nil {
			t.Fatalf("build: %v", err)
		}
		if len(built.Evidence) != 0 {
			t.Fatalf("evidence = %d, want the collided pair omitted", len(built.Evidence))
		}
		if len(diagnostics.Omitted) != 2 {
			t.Fatalf("omitted = %d", len(diagnostics.Omitted))
		}
		if !a202HasWarning(built.Provenance.Warnings, "scope_mismatch", "contradictory", "scope collision across container classes: regular, init") {
			t.Fatalf("warnings = %+v", built.Provenance.Warnings)
		}
	})
}

func TestA202CollectedProvenance(t *testing.T) {
	source := a202BuildSource(t, a202Document(a202Pod("u1", "n1")), "capture-000001.json", contract.TerminationFinished)
	acquisition := a202Acquisition(t, []a202Source{source}, contract.TerminationFinished, nil)
	built, _, err := bundle.BuildCollectedObservation(a202Input(acquisition, 1, 0))
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	t.Run("live_origin", func(t *testing.T) {
		if built.Provenance.CollectorVersion == "operator-export" {
			t.Fatal("the live collector reused the operator-export label")
		}
		if built.Provenance.CollectorVersion != "ariadne-collector/k8s-pod-read-v1" {
			t.Fatalf("collector version = %q", built.Provenance.CollectorVersion)
		}
		if built.Provenance.ParserVersion != "sanitized-podlist-v1/1.0" {
			t.Fatalf("parser version = %q", built.Provenance.ParserVersion)
		}
	})
	t.Run("actual_scope", func(t *testing.T) {
		scope := built.Provenance.APIScope
		if len(scope.Namespaces) != 1 || scope.Namespaces[0] != a202Namespace {
			t.Fatalf("namespaces = %v", scope.Namespaces)
		}
		if len(scope.Verbs) != 1 || scope.Verbs[0] != "list" {
			t.Fatalf("verbs = %v, want the really attempted set", scope.Verbs)
		}
		if len(scope.Resources) != 1 || scope.Resources[0] != "pods" {
			t.Fatalf("resources = %v", scope.Resources)
		}
	})
	t.Run("budget_limits_not_counters", func(t *testing.T) {
		budget := built.Provenance.Budget
		if budget.WallClock != "5m" || budget.Requests != 1024 || budget.Objects != 1024 || budget.Bytes != 67108864 {
			t.Fatalf("budget = %+v, want the declared limits", budget)
		}
	})
	t.Run("rows_null", func(t *testing.T) {
		if built.Provenance.Coverage.Rows != nil {
			t.Fatal("the coverage rows are not null")
		}
		if built.Provenance.Coverage.Method != contract.CoverageContainerObservation {
			t.Fatalf("method = %q", built.Provenance.Coverage.Method)
		}
	})
	t.Run("argv_empty", func(t *testing.T) {
		if built.Provenance.ArgvSanitized == nil || len(built.Provenance.ArgvSanitized) != 0 {
			t.Fatalf("argv = %v, want an empty array", built.Provenance.ArgvSanitized)
		}
		if built.Provenance.Ruleset != (contract.RulesetRef{}) {
			t.Fatalf("ruleset = %+v, want the zero value", built.Provenance.Ruleset)
		}
	})
	t.Run("failed_attempt_in_scope", func(t *testing.T) {
		// A failed request really attempted is part of the exercised scope.
		failing := acquisition
		// The planned scope includes the namespace whose request failed: the
		// exercised scope is a subset of the declared one, never larger.
		failing.Scope.Namespaces = append(append([]contract.Namespace{}, failing.Scope.Namespaces...), "orders")
		failing.Operations = append(failing.Operations, bundle.CollectedOperation{
			Verb:           "get",
			Namespace:      "orders",
			Name:           "n1",
			Round:          1,
			RequestOrdinal: 77,
			State:          bundle.OperationFailed,
			Diagnostic:     bundle.CodeForbidden,
			StartedAt:      acquisition.StartedAt,
			EndedAt:        acquisition.EndedAt,
		})
		failing.Stats.RequestsAttempted++
		failing.Stats.ResponsesFailed++
		failing.Plan.RequestedOps = failing.Stats.RequestsAttempted
		built, _, err := bundle.BuildCollectedObservation(a202Input(failing, 1, 0))
		if err != nil {
			t.Fatalf("build: %v", err)
		}
		verbs := built.Provenance.APIScope.Verbs
		if len(verbs) != 2 || verbs[0] != "get" || verbs[1] != "list" {
			t.Fatalf("verbs = %v, want the sorted attempted set {get,list}", verbs)
		}
		namespaces := built.Provenance.APIScope.Namespaces
		if len(namespaces) != 2 {
			t.Fatalf("namespaces = %v, want both attempted namespaces", namespaces)
		}
	})
	t.Run("requested_scope_preserved", func(t *testing.T) {
		// The requested scope stays in the acquisition record and is never
		// reduced by a failure: it is not the API scope of the bundle.
		reduced := acquisition
		reduced.Scope.Namespaces = []contract.Namespace{a202Namespace, "orders"}
		built, _, err := bundle.BuildCollectedObservation(a202Input(reduced, 1, 0))
		if err != nil {
			t.Fatalf("build: %v", err)
		}
		if len(built.Provenance.APIScope.Namespaces) != 1 {
			t.Fatalf("api scope = %v, want only the attempted namespace", built.Provenance.APIScope.Namespaces)
		}
	})
	t.Run("comparison_inputs", func(t *testing.T) {
		// The compared captures really differ in their projected content: the
		// second capture carries another status imageID, which is exactly the
		// condition the observation_changed code attests.
		second := a202BuildSource(t, a202Document(a202PodWithImageID("u1", "n1", "sha256:"+strings.Repeat("b", 64))), "capture-000002.json", contract.TerminationFinished)
		located := a202Acquisition(t, []a202Source{source, second}, contract.TerminationFinished, nil)
		located.Comparisons = []bundle.CollectedComparison{{
			Code:     bundle.CodeObservationChanged,
			Previous: bundle.CollectedSubjectRef{CaptureOrdinal: 1, ItemIndex: 0},
			Current:  bundle.CollectedSubjectRef{CaptureOrdinal: 2, ItemIndex: 0},
		}}
		built, _, err := bundle.BuildCollectedObservation(a202Input(located, 1, 0))
		if err != nil {
			t.Fatalf("build: %v", err)
		}
		if len(built.Provenance.Inputs) != 2 {
			t.Fatalf("inputs = %+v, want the capture and the comparison source", built.Provenance.Inputs)
		}
		if built.Provenance.Inputs[0].Path != "capture-000001.json" || built.Provenance.Inputs[1].Path != "capture-000002.json" {
			t.Fatalf("inputs = %+v", built.Provenance.Inputs)
		}
	})
	t.Run("deduction_platform_unknown", func(t *testing.T) {
		for _, image := range built.Images {
			if image.Platform.Status != contract.PlatformUnknown || image.NormalizedDigest != nil {
				t.Fatal("the live provenance promoted a digest or a platform")
			}
		}
	})
}

var _ = normalize.ObservationResult{}
