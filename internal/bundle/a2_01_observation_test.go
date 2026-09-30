package bundle

import (
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/d4rpell/Ariadne/internal/ingest"
	"github.com/d4rpell/Ariadne/internal/normalize"
	contract "github.com/d4rpell/Ariadne/pkg/evidence"
)

// Observation projection tests of ADR-0025 A.9 and A.12.1: one bundle per
// subject, exactly one emitted evidence type, no digest or platform promotion,
// visible collisions, and a completion matrix that never promotes an unknown
// capture.

func observationTimestamp(t *testing.T, moment string) *contract.Timestamp {
	t.Helper()
	parsed, err := time.Parse(time.RFC3339, moment)
	if err != nil {
		t.Fatalf("parse timestamp: %v", err)
	}
	stamp, err := contract.NewTimestamp(parsed)
	if err != nil {
		t.Fatalf("new timestamp: %v", err)
	}
	return &stamp
}

func observationSourceName() string { return "sanitized-pods.json" }

func observationHash() contract.SourceHash {
	return contract.SourceHash("sha256:" + strings.Repeat("a", 64))
}

func TestA201Projection(t *testing.T) {
	t.Run("one bundle with only the admitted evidence type", func(t *testing.T) {
		imageID := "registry.example/app@sha256:" + strings.Repeat("ab", 32)
		image := "registry.example/app:release"
		subject := normalize.ObservationSubject{
			UID:                contract.UID("uid-0001"),
			Namespace:          contract.Namespace("payments"),
			Name:               "payments-api-7f4d",
			CategoriesObserved: map[contract.ContainerClass]bool{contract.ContainerRegular: true},
			CategoriesComplete: map[contract.ContainerClass]bool{},
			CollidedClasses:    map[string][]contract.ContainerClass{},
			Containers: []normalize.ObservationContainer{{
				Class:         contract.ContainerRegular,
				Name:          "api",
				SpecIndex:     0,
				StatusIndex:   0,
				SpecPresent:   true,
				StatusPresent: true,
				Image:         &image,
				ImageID:       &imageID,
			}},
		}
		result := normalize.ObservationResult{
			// The fixtures declare the accounting the producer would have declared.
			TotalItems:   1,
			Source:       normalize.ObservationSource{Name: observationSourceName(), Hash: observationHash()},
			Namespace:    contract.Namespace("payments"),
			ClusterAlias: contract.ClusterAlias("cluster-a"),
			ObservedAt:   observationTimestamp(t, "2026-09-30T12:00:00Z"),
			Termination:  contract.TerminationFinished,
			Subjects:     []normalize.ObservationSubject{subject},
		}
		built, diagnostics, err := BuildObservation(ObservationInput{
			Result:         result,
			SubjectIndex:   0,
			CollectorLabel: "operator-export",
			ParserVersion:  "sanitized-podlist-v1/1.0",
			ObservedAt:     result.ObservedAt,
		})
		if err != nil {
			t.Fatalf("BuildObservation: %v", err)
		}
		if len(diagnostics.Omitted) != 0 {
			t.Fatalf("omissions = %v, want none", diagnostics.Omitted)
		}
		if built.SchemaVersion != contract.SchemaVersionSupported {
			t.Fatalf("schema version = %q", built.SchemaVersion)
		}
		if built.Subject.UID != subject.UID || built.Subject.Kind != "Pod" {
			t.Fatalf("subject = %+v", built.Subject)
		}
		if built.Subject.OwnerChain != "" {
			t.Fatal("owner chain must stay absent: owner references are context, not a resolved chain")
		}
		if len(built.Images) != 1 {
			t.Fatalf("images = %d, want 1", len(built.Images))
		}
		projected := built.Images[0]
		if projected.NormalizedDigest != nil {
			t.Fatal("a PodList must never promote a guaranteed digest")
		}
		if projected.Platform.Status != contract.PlatformUnknown {
			t.Fatalf("platform = %q, want unknown", projected.Platform.Status)
		}
		if projected.RawImageID == nil || string(*projected.RawImageID) != imageID {
			t.Fatalf("raw image id = %v, want the observed value preserved", projected.RawImageID)
		}
		if projected.RequestedImage == nil || string(*projected.RequestedImage) != "registry.example/app:release" {
			t.Fatalf("requested image = %v, want the declared value verbatim", projected.RequestedImage)
		}
		if len(built.Evidence) != 1 {
			t.Fatalf("evidence = %d, want exactly one item", len(built.Evidence))
		}
		item := built.Evidence[0]
		if item.Type != "container_status.image_id" {
			t.Fatalf("evidence type = %q, want the only emitted type", item.Type)
		}
		if item.Confidence != contract.ProvenanceObserved {
			t.Fatalf("confidence = %q, want observed", item.Confidence)
		}
		if item.Value == nil || *item.Value != imageID {
			t.Fatalf("value = %v, want the exact decoded value", item.Value)
		}
		if item.ValueHash == nil || *item.ValueHash != HashValue(imageID) {
			t.Fatal("value hash is not the SHA-256 of the exact value bytes")
		}
		if item.Locator != "items[0].status.containerStatuses[0].imageID" {
			t.Fatalf("locator = %q", item.Locator)
		}
		if item.Scope.SubjectUID != subject.UID || item.Scope.ContainerName != "api" {
			t.Fatalf("scope = %+v", item.Scope)
		}
		if built.Provenance.Coverage.Method != contract.CoverageContainerObservation {
			t.Fatalf("coverage method = %q", built.Provenance.Coverage.Method)
		}
		if built.Provenance.Coverage.Rows != nil {
			t.Fatal("coverage rows must stay null for a container observation")
		}
		if built.Provenance.Consistency != contract.ConsistencyNotAtomic {
			t.Fatalf("consistency = %q, want not-atomic", built.Provenance.Consistency)
		}
		if built.Provenance.APIScope.Verbs == nil || len(built.Provenance.APIScope.Verbs) != 0 {
			t.Fatal("no API verb was exercised and none may be declared")
		}
		if len(built.Provenance.APIScope.Resources) != 1 || built.Provenance.APIScope.Resources[0] != "pods" {
			t.Fatalf("api_scope.resources = %v", built.Provenance.APIScope.Resources)
		}
	})

	t.Run("no evidence item without an observed imageID", func(t *testing.T) {
		image := "registry.example/app:release"
		subject := normalize.ObservationSubject{
			UID:                contract.UID("uid-0001"),
			Namespace:          contract.Namespace("payments"),
			Name:               "payments-api-7f4d",
			CategoriesObserved: map[contract.ContainerClass]bool{contract.ContainerRegular: true},
			CategoriesComplete: map[contract.ContainerClass]bool{},
			CollidedClasses:    map[string][]contract.ContainerClass{},
			Containers: []normalize.ObservationContainer{{
				Class: contract.ContainerRegular, Name: "api", SpecPresent: true, StatusPresent: true, Image: &image,
			}},
		}
		result := normalize.ObservationResult{
			// The fixtures declare the accounting the producer would have declared.
			TotalItems:   1,
			Source:       normalize.ObservationSource{Name: observationSourceName(), Hash: observationHash()},
			Namespace:    contract.Namespace("payments"),
			ClusterAlias: contract.ClusterAlias("cluster-a"),
			ObservedAt:   observationTimestamp(t, "2026-09-30T12:00:00Z"),
			Termination:  contract.TerminationFinished,
			Subjects:     []normalize.ObservationSubject{subject},
		}
		built, _, err := BuildObservation(ObservationInput{
			Result: result, SubjectIndex: 0, CollectorLabel: "operator-export",
			ParserVersion: "sanitized-podlist-v1/1.0", ObservedAt: result.ObservedAt,
		})
		if err != nil {
			t.Fatalf("BuildObservation: %v", err)
		}
		if len(built.Evidence) != 0 {
			t.Fatalf("evidence = %d, want none without an observed imageID", len(built.Evidence))
		}
		if len(built.Images) != 1 || built.Images[0].RawImageID != nil {
			t.Fatalf("images = %+v, want one image without raw id", built.Images)
		}
	})
}

func TestA201TerminationCollisionMatrix(t *testing.T) {
	// Six combinations of declared termination and scope collision over an
	// otherwise pristine subject: finished/complete, aborted/partial,
	// unknown/unknown, and each of those with a collision that never promotes
	// an unknown termination.
	newResult := func(termination contract.CoverageTermination, collided bool) normalize.ObservationResult {
		imageID := "registry.example/app@sha256:" + strings.Repeat("ab", 32)
		image := "registry.example/app:release"
		subject := normalize.ObservationSubject{
			UID:                contract.UID("uid-0001"),
			Namespace:          contract.Namespace("payments"),
			Name:               "payments-api-7f4d",
			CategoriesObserved: map[contract.ContainerClass]bool{},
			CategoriesComplete: map[contract.ContainerClass]bool{},
			CollidedClasses:    map[string][]contract.ContainerClass{},
			Containers: []normalize.ObservationContainer{
				{Class: contract.ContainerRegular, Name: "api", SpecIndex: 0, StatusIndex: 0, SpecPresent: true, StatusPresent: true, Image: &image, ImageID: &imageID},
				{Class: contract.ContainerInit, Name: "setup", SpecIndex: 0, StatusIndex: 0, SpecPresent: true, StatusPresent: true, Image: &image, ImageID: &imageID},
				{Class: contract.ContainerEphemeral, Name: "debug", SpecIndex: 0, StatusIndex: 0, SpecPresent: true, StatusPresent: true, Image: &image, ImageID: &imageID},
			},
		}
		for _, class := range []contract.ContainerClass{contract.ContainerRegular, contract.ContainerInit, contract.ContainerEphemeral} {
			subject.CategoriesObserved[class] = true
			subject.CategoriesComplete[class] = true
		}
		if collided {
			// A second container named "api" in the init class collides with the
			// regular one: both keys are omitted and the categories stay observed.
			subject.Containers = append(subject.Containers, normalize.ObservationContainer{
				Class: contract.ContainerInit, Name: "api", SpecIndex: 1, StatusIndex: 1, SpecPresent: true, StatusPresent: true, Image: &image, ImageID: &imageID,
			})
			subject.CollidedClasses["api"] = []contract.ContainerClass{contract.ContainerRegular, contract.ContainerInit}
		}
		return normalize.ObservationResult{
			// The fixtures declare the accounting the producer would have declared.
			TotalItems:   1,
			Source:       normalize.ObservationSource{Name: observationSourceName(), Hash: observationHash()},
			Namespace:    contract.Namespace("payments"),
			ClusterAlias: contract.ClusterAlias("cluster-a"),
			ObservedAt:   observationTimestamp(t, "2026-09-30T12:00:00Z"),
			Termination:  termination,
			Subjects:     []normalize.ObservationSubject{subject},
		}
	}

	cases := []struct {
		name        string
		termination contract.CoverageTermination
		collided    bool
		want        contract.Completeness
	}{
		{"finished without collision", contract.TerminationFinished, false, contract.CompletenessComplete},
		{"finished with collision", contract.TerminationFinished, true, contract.CompletenessPartial},
		{"aborted without collision", contract.TerminationAborted, false, contract.CompletenessPartial},
		{"aborted with collision", contract.TerminationAborted, true, contract.CompletenessPartial},
		{"unknown without collision", contract.TerminationUnknown, false, contract.CompletenessUnknown},
		{"unknown with collision", contract.TerminationUnknown, true, contract.CompletenessUnknown},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			result := newResult(testCase.termination, testCase.collided)
			built, diagnostics, err := BuildObservation(ObservationInput{
				Result: result, SubjectIndex: 0, CollectorLabel: "operator-export",
				ParserVersion: "sanitized-podlist-v1/1.0", ObservedAt: result.ObservedAt,
			})
			if err != nil {
				t.Fatalf("BuildObservation: %v", err)
			}
			if built.Provenance.Completeness != testCase.want {
				t.Fatalf("completeness = %q, want %q", built.Provenance.Completeness, testCase.want)
			}
			if built.Provenance.Coverage.Termination != testCase.termination {
				t.Fatalf("termination = %q, want %q", built.Provenance.Coverage.Termination, testCase.termination)
			}
			if !testCase.collided {
				if len(diagnostics.Omitted) != 0 {
					t.Fatalf("omissions = %v, want none", diagnostics.Omitted)
				}
				return
			}
			if len(diagnostics.Omitted) != 2 {
				t.Fatalf("omissions = %d, want the two collided keys", len(diagnostics.Omitted))
			}
			// The collided key is gone from the projection, the rest is preserved.
			for _, image := range built.Images {
				if image.ContainerName == "api" {
					t.Fatalf("a collided container was projected: %+v", image)
				}
			}
			foundCollisionError := false
			for _, message := range built.Provenance.Errors {
				if message == "bundle: scope collision omitted" {
					foundCollisionError = true
				}
			}
			if !foundCollisionError {
				t.Fatalf("errors = %v, want the collision error", built.Provenance.Errors)
			}
			foundCollisionWarning := false
			for _, warning := range built.Provenance.Warnings {
				if warning.Code == "scope_mismatch" && warning.Class == contract.WarningContradictory {
					foundCollisionWarning = true
				}
			}
			if !foundCollisionWarning {
				t.Fatalf("warnings = %v, want the scope_mismatch contradictory warning", built.Provenance.Warnings)
			}
			// Observed categories survive the omission.
			if len(built.ObservedContainerClasses) != 3 {
				t.Fatalf("observed classes = %v, want the three categories preserved", built.ObservedContainerClasses)
			}
		})
	}
}

func TestA201InvalidObservationDTO(t *testing.T) {
	valid := func() (ObservationInput, normalize.ObservationResult) {
		imageID := "registry.example/app@sha256:" + strings.Repeat("ab", 32)
		subject := normalize.ObservationSubject{
			UID:                contract.UID("uid-0001"),
			Namespace:          contract.Namespace("payments"),
			Name:               "payments-api-7f4d",
			CategoriesObserved: map[contract.ContainerClass]bool{},
			CategoriesComplete: map[contract.ContainerClass]bool{},
			CollidedClasses:    map[string][]contract.ContainerClass{},
			Containers: []normalize.ObservationContainer{{
				Class: contract.ContainerRegular, Name: "api", SpecPresent: true, StatusPresent: true, ImageID: &imageID,
			}},
		}
		result := normalize.ObservationResult{
			// The fixtures declare the accounting the producer would have declared.
			TotalItems:   1,
			Source:       normalize.ObservationSource{Name: observationSourceName(), Hash: observationHash()},
			Namespace:    contract.Namespace("payments"),
			ClusterAlias: contract.ClusterAlias("cluster-a"),
			ObservedAt:   observationTimestamp(t, "2026-09-30T12:00:00Z"),
			Termination:  contract.TerminationFinished,
			Subjects:     []normalize.ObservationSubject{subject},
		}
		return ObservationInput{
			Result: result, SubjectIndex: 0, CollectorLabel: "operator-export",
			ParserVersion: "sanitized-podlist-v1/1.0", ObservedAt: result.ObservedAt,
		}, result
	}

	cases := []struct {
		name   string
		mutate func(*ObservationInput)
	}{
		{"subject out of range", func(input *ObservationInput) { input.SubjectIndex = 3 }},
		{"bad source hash", func(input *ObservationInput) { input.Result.Source.Hash = "sha256:short" }},
		{"empty namespace", func(input *ObservationInput) { input.Result.Namespace = "" }},
		{"namespace divergence", func(input *ObservationInput) { input.Result.Subjects[0].Namespace = "other" }},
		{"empty uid", func(input *ObservationInput) { input.Result.Subjects[0].UID = "" }},
		{"empty container name", func(input *ObservationInput) { input.Result.Subjects[0].Containers[0].Name = "" }},
		{"invalid class", func(input *ObservationInput) { input.Result.Subjects[0].Containers[0].Class = "sidecar" }},
		{"duplicate container key", func(input *ObservationInput) {
			input.Result.Subjects[0].Containers = append(input.Result.Subjects[0].Containers, input.Result.Subjects[0].Containers[0])
		}},
		{"declared collision without observations", func(input *ObservationInput) {
			input.Result.Subjects[0].CollidedClasses["api"] = []contract.ContainerClass{contract.ContainerRegular, contract.ContainerInit}
		}},
		{"missing observation time", func(input *ObservationInput) { input.ObservedAt = nil }},
		{"undeclared termination", func(input *ObservationInput) { input.Result.Termination = "invented" }},
		{"empty collector label", func(input *ObservationInput) { input.CollectorLabel = "" }},
		{"empty parser version", func(input *ObservationInput) { input.ParserVersion = "" }},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			input, _ := valid()
			testCase.mutate(&input)
			built, _, err := BuildObservation(input)
			if err == nil {
				t.Fatal("an incoherent DTO must be refused")
			}
			if len(built.Evidence) != 0 || len(built.Images) != 0 || built.Subject.UID != "" {
				t.Fatalf("a refused DTO produced a bundle: %+v", built)
			}
		})
	}
}

func TestA201BuildOwnership(t *testing.T) {
	// Mutating the input after the build never rewrites what was returned, and
	// mutating the returned bundle never rewrites the input.
	imageID := "registry.example/app@sha256:" + strings.Repeat("ab", 32)
	image := "registry.example/app:release"
	subject := normalize.ObservationSubject{
		UID:                contract.UID("uid-0001"),
		Namespace:          contract.Namespace("payments"),
		Name:               "payments-api-7f4d",
		CategoriesObserved: map[contract.ContainerClass]bool{contract.ContainerRegular: true},
		CategoriesComplete: map[contract.ContainerClass]bool{},
		CollidedClasses:    map[string][]contract.ContainerClass{},
		Containers: []normalize.ObservationContainer{{
			Class: contract.ContainerRegular, Name: "api", SpecPresent: true, StatusPresent: true, Image: &image, ImageID: &imageID,
		}},
	}
	result := normalize.ObservationResult{
		// The fixtures declare the accounting the producer would have declared.
		TotalItems:   1,
		Source:       normalize.ObservationSource{Name: observationSourceName(), Hash: observationHash()},
		Namespace:    contract.Namespace("payments"),
		ClusterAlias: contract.ClusterAlias("cluster-a"),
		ObservedAt:   observationTimestamp(t, "2026-09-30T12:00:00Z"),
		Termination:  contract.TerminationFinished,
		Subjects:     []normalize.ObservationSubject{subject},
	}
	built, _, err := BuildObservation(ObservationInput{
		Result: result, SubjectIndex: 0, CollectorLabel: "operator-export",
		ParserVersion: "sanitized-podlist-v1/1.0", ObservedAt: result.ObservedAt,
	})
	if err != nil {
		t.Fatalf("BuildObservation: %v", err)
	}
	originalValue := *built.Evidence[0].Value
	// Mutating the input after the build must not change the returned bundle.
	imageID = "mutated"
	result.Subjects[0].Containers[0].ImageID = &imageID
	if *built.Evidence[0].Value != originalValue {
		t.Fatal("the returned bundle changed after the input was mutated")
	}
	// Mutating the returned bundle must not change the caller's input.
	*built.Evidence[0].Value = "rewritten"
	if result.Subjects[0].Containers[0].ImageID == nil || *result.Subjects[0].Containers[0].ImageID != "mutated" {
		t.Fatal("the caller input changed after the bundle was mutated")
	}
}

// a201CollisionSubject builds one subject whose containers use the given classes
// for the collided name, so the collision table and the containers always agree.
func a201CollisionSubject(name string, collidedClasses []contract.ContainerClass, extra []normalize.ObservationContainer) normalize.ObservationSubject {
	containers := []normalize.ObservationContainer{}
	for index, class := range collidedClasses {
		image := "registry.example/" + name + ":release"
		imageID := "sha256:" + name + "-" + string(class)
		containers = append(containers, normalize.ObservationContainer{
			Class:         class,
			Name:          name,
			SpecIndex:     index,
			StatusIndex:   index,
			SpecPresent:   true,
			StatusPresent: true,
			Image:         &image,
			ImageID:       &imageID,
		})
	}
	containers = append(containers, extra...)
	return normalize.ObservationSubject{
		UID:                contract.UID("uid-0001"),
		Namespace:          contract.Namespace("payments"),
		Name:               "payments-api-7f4d",
		CategoriesObserved: map[contract.ContainerClass]bool{contract.ContainerRegular: true, contract.ContainerInit: true, contract.ContainerEphemeral: true},
		CategoriesComplete: map[contract.ContainerClass]bool{contract.ContainerRegular: true, contract.ContainerInit: true, contract.ContainerEphemeral: true},
		CollidedClasses: map[string][]contract.ContainerClass{
			// The declared table always enumerates the classes in canonical order,
			// while the containers keep the appearance order of the source.
			name: orderedContainerClasses(a201ClassSet(collidedClasses)),
		},
		Containers: containers,
	}
}

func a201CollisionBuild(t *testing.T, subject normalize.ObservationSubject) (contract.Bundle, ObservationDiagnostics) {
	t.Helper()
	result := normalize.ObservationResult{
		// The fixtures declare the accounting the producer would have declared.
		TotalItems:   1,
		Source:       normalize.ObservationSource{Name: observationSourceName(), Hash: observationHash()},
		Namespace:    contract.Namespace("payments"),
		ClusterAlias: contract.ClusterAlias("cluster-a"),
		ObservedAt:   observationTimestamp(t, "2026-09-30T12:00:00Z"),
		Termination:  contract.TerminationFinished,
		Subjects:     []normalize.ObservationSubject{subject},
	}
	built, diagnostics, err := BuildObservation(ObservationInput{
		Result: result, SubjectIndex: 0, CollectorLabel: "operator-export",
		ParserVersion: "sanitized-podlist-v1/1.0", ObservedAt: result.ObservedAt,
	})
	if err != nil {
		t.Fatalf("BuildObservation: %v", err)
	}
	return built, diagnostics
}

// a201CollisionWarning returns the collision warning of one bundle.
func a201CollisionWarning(t *testing.T, built contract.Bundle) contract.Warning {
	t.Helper()
	found := []contract.Warning{}
	for _, warning := range built.Provenance.Warnings {
		if warning.Code == "scope_mismatch" {
			found = append(found, warning)
		}
	}
	if len(found) != 1 {
		t.Fatalf("scope_mismatch warnings = %d, want exactly 1", len(found))
	}
	if found[0].Class != contract.WarningContradictory {
		t.Fatalf("warning class = %q, want contradictory", found[0].Class)
	}
	return found[0]
}

// a201HasError reports whether one bundle keeps the given error visible.
func a201HasError(built contract.Bundle, want string) bool {
	for _, message := range built.Provenance.Errors {
		if message == want {
			return true
		}
	}
	return false
}

// a201ClassSet builds the class set of one collision vector.
func a201ClassSet(classes []contract.ContainerClass) map[contract.ContainerClass]bool {
	set := map[contract.ContainerClass]bool{}
	for _, class := range classes {
		set[class] = true
	}
	return set
}

// TestA201ScopeCollisions covers the collisions row of A.12.1: the collided key
// is omitted exactly, the rest of the subject is preserved, the classes of the
// message are always in canonical order and the result is never complete.
func TestA201ScopeCollisions(t *testing.T) {
	t.Run("two classes with the rest preserved", func(t *testing.T) {
		workerImage := "registry.example/worker:release"
		workerID := "sha256:worker"
		subject := a201CollisionSubject("api", []contract.ContainerClass{contract.ContainerRegular, contract.ContainerInit},
			[]normalize.ObservationContainer{{
				Class: contract.ContainerRegular, Name: "worker", SpecIndex: 9, StatusIndex: 9,
				SpecPresent: true, StatusPresent: true, Image: &workerImage, ImageID: &workerID,
			}})
		built, diagnostics := a201CollisionBuild(t, subject)
		if len(diagnostics.Omitted) != 2 {
			t.Fatalf("omissions = %d, want the two collided observations", len(diagnostics.Omitted))
		}
		for _, omission := range diagnostics.Omitted {
			if string(omission.Key.ContainerName) != "api" || omission.Reason != OmissionCollision {
				t.Fatalf("omission = %+v, want the collided key only", omission)
			}
		}
		if len(built.Images) != 1 || string(built.Images[0].ContainerName) != "worker" {
			t.Fatalf("images = %+v, want the non-collided container preserved", built.Images)
		}
		if len(built.Evidence) != 1 || built.Evidence[0].Scope.ContainerName != "worker" {
			t.Fatalf("evidence = %+v, want the preserved observation only", built.Evidence)
		}
		warning := a201CollisionWarning(t, built)
		if warning.Message != "scope collision across container classes: regular, init" {
			t.Fatalf("warning message = %q", warning.Message)
		}
		if !a201HasError(built, "bundle: scope collision omitted") {
			t.Fatalf("errors = %v, want the visible collision omission", built.Provenance.Errors)
		}
		if built.Provenance.Completeness != contract.CompletenessPartial {
			t.Fatalf("completeness = %q, want partial with a finished capture", built.Provenance.Completeness)
		}
		if len(built.ObservedContainerClasses) != 3 {
			t.Fatalf("observed classes = %v, want the observed categories preserved", built.ObservedContainerClasses)
		}
	})

	t.Run("three classes keep the canonical order", func(t *testing.T) {
		// The containers are declared in a different order than the message: the
		// warning always enumerates regular, init, ephemeral.
		subject := a201CollisionSubject("api", []contract.ContainerClass{contract.ContainerEphemeral, contract.ContainerInit, contract.ContainerRegular}, nil)
		built, diagnostics := a201CollisionBuild(t, subject)
		if len(diagnostics.Omitted) != 3 {
			t.Fatalf("omissions = %d, want 3", len(diagnostics.Omitted))
		}
		if warning := a201CollisionWarning(t, built); warning.Message != "scope collision across container classes: regular, init, ephemeral" {
			t.Fatalf("warning message = %q, want the canonical class order", warning.Message)
		}
	})

	t.Run("all images omitted still yields a valid bundle", func(t *testing.T) {
		subject := a201CollisionSubject("api", []contract.ContainerClass{contract.ContainerRegular, contract.ContainerInit}, nil)
		built, diagnostics := a201CollisionBuild(t, subject)
		if len(diagnostics.Omitted) != 2 {
			t.Fatalf("omissions = %d, want 2", len(diagnostics.Omitted))
		}
		if len(built.Images) != 0 || len(built.Evidence) != 0 {
			t.Fatalf("images = %d and evidence = %d, want an incomplete bundle without invented evidence", len(built.Images), len(built.Evidence))
		}
		if built.Provenance.Completeness != contract.CompletenessPartial {
			t.Fatalf("completeness = %q, want partial: the categories stay observed even when every image is omitted", built.Provenance.Completeness)
		}
		if _, err := Encode(built); err != nil {
			t.Fatalf("an incomplete bundle must stay encodable: %v", err)
		}
	})

	t.Run("a collision never promotes the completeness", func(t *testing.T) {
		subject := a201CollisionSubject("api", []contract.ContainerClass{contract.ContainerRegular, contract.ContainerInit}, nil)
		built, _ := a201CollisionBuild(t, subject)
		if built.Provenance.Completeness == contract.CompletenessComplete {
			t.Fatal("a collision produced a complete observation")
		}
		if !a201HasError(built, "bundle: scope collision omitted") {
			t.Fatal("the collision omission is not visible")
		}
	})
}

// TestA201HiddenCollisionIsRefused is the A.8.4 defence of the projection: the
// collision table is rebuilt from the containers, so a DTO that hides a collision
// cannot project two observations whose wire scope is identical. The wire
// validator cannot see that ambiguity, which is why the adapter refuses it.
func TestA201HiddenCollisionIsRefused(t *testing.T) {
	for _, hidden := range []string{"empty", "partial", "unsorted"} {
		t.Run(hidden, func(t *testing.T) {
			subject := a201CollisionSubject("api",
				[]contract.ContainerClass{contract.ContainerRegular, contract.ContainerInit}, nil)
			switch hidden {
			case "empty":
				subject.CollidedClasses = map[string][]contract.ContainerClass{}
			case "partial":
				subject.CollidedClasses = map[string][]contract.ContainerClass{
					"api": {contract.ContainerRegular},
				}
			case "unsorted":
				subject.CollidedClasses = map[string][]contract.ContainerClass{
					"api": {contract.ContainerInit, contract.ContainerRegular},
				}
			}
			result := normalize.ObservationResult{
				// The fixtures declare the accounting the producer would have declared.
				TotalItems:   1,
				Source:       normalize.ObservationSource{Name: observationSourceName(), Hash: observationHash()},
				Namespace:    contract.Namespace("payments"),
				ClusterAlias: contract.ClusterAlias("cluster-a"),
				ObservedAt:   observationTimestamp(t, "2026-09-30T12:00:00Z"),
				Termination:  contract.TerminationFinished,
				Subjects:     []normalize.ObservationSubject{subject},
			}
			built, _, err := BuildObservation(ObservationInput{
				Result: result, SubjectIndex: 0, CollectorLabel: "operator-export",
				ParserVersion: "sanitized-podlist-v1/1.0", ObservedAt: result.ObservedAt,
			})
			if err == nil {
				t.Fatalf("a DTO with a %s collision table was projected: %+v", hidden, built.Images)
			}
			if !reflect.DeepEqual(built, contract.Bundle{}) {
				t.Fatal("a refused DTO produced a bundle")
			}
		})
	}
}

// TestA201AllImagesOmittedMatrix repeats the collision matrix when every image
// ends up omitted: the completeness follows the declared termination and the
// observed categories survive, never the omissions (ADR-0025 A.12.1, handoff
// §4.4).
func TestA201AllImagesOmittedMatrix(t *testing.T) {
	cases := []struct {
		termination  contract.CoverageTermination
		completeness contract.Completeness
	}{
		{contract.TerminationFinished, contract.CompletenessPartial},
		{contract.TerminationAborted, contract.CompletenessPartial},
		{contract.TerminationUnknown, contract.CompletenessUnknown},
	}
	for _, testCase := range cases {
		t.Run(string(testCase.termination), func(t *testing.T) {
			subject := a201CollisionSubject("api",
				[]contract.ContainerClass{contract.ContainerRegular, contract.ContainerInit, contract.ContainerEphemeral}, nil)
			result := normalize.ObservationResult{
				// The fixtures declare the accounting the producer would have declared.
				TotalItems:   1,
				Source:       normalize.ObservationSource{Name: observationSourceName(), Hash: observationHash()},
				Namespace:    contract.Namespace("payments"),
				ClusterAlias: contract.ClusterAlias("cluster-a"),
				ObservedAt:   observationTimestamp(t, "2026-09-30T12:00:00Z"),
				Termination:  testCase.termination,
				Subjects:     []normalize.ObservationSubject{subject},
			}
			built, diagnostics, err := BuildObservation(ObservationInput{
				Result: result, SubjectIndex: 0, CollectorLabel: "operator-export",
				ParserVersion: "sanitized-podlist-v1/1.0", ObservedAt: result.ObservedAt,
			})
			if err != nil {
				t.Fatalf("BuildObservation: %v", err)
			}
			if len(diagnostics.Omitted) != 3 {
				t.Fatalf("omissions = %d, want every collided observation", len(diagnostics.Omitted))
			}
			if len(built.Images) != 0 || len(built.Evidence) != 0 {
				t.Fatalf("images = %d and evidence = %d, want no invented evidence", len(built.Images), len(built.Evidence))
			}
			if built.Provenance.Coverage.Termination != testCase.termination {
				t.Fatalf("termination = %q, want the declared one", built.Provenance.Coverage.Termination)
			}
			if built.Provenance.Completeness != testCase.completeness {
				t.Fatalf("completeness = %q, want %q", built.Provenance.Completeness, testCase.completeness)
			}
			if len(built.ObservedContainerClasses) != 3 {
				t.Fatalf("observed classes = %v, want the categories preserved", built.ObservedContainerClasses)
			}
			if !a201HasError(built, "bundle: scope collision omitted") {
				t.Fatalf("errors = %v, want the visible omission", built.Provenance.Errors)
			}
			if warning := a201CollisionWarning(t, built); warning.Message != "scope collision across container classes: regular, init, ephemeral" {
				t.Fatalf("warning message = %q", warning.Message)
			}
			if _, err := Encode(built); err != nil {
				t.Fatalf("an incomplete bundle must stay encodable: %v", err)
			}
		})
	}
}

// TestA201IncoherentDiagnosticsAreRefused keeps a normalized run out of the
// projection when one of its diagnostics could not come from an admitted source:
// a code outside the closed catalog, a locator that is not a path of the
// document, or an offset past the last byte of that source (ADR-0025 A.10.1,
// A.11.2).
func TestA201IncoherentDiagnosticsAreRefused(t *testing.T) {
	base := func() normalize.ObservationResult {
		subject := a201CollisionSubject("api",
			[]contract.ContainerClass{contract.ContainerRegular, contract.ContainerInit}, nil)
		return normalize.ObservationResult{
			// The fixtures declare the accounting the producer would have declared.
			TotalItems:   1,
			Source:       normalize.ObservationSource{Name: observationSourceName(), Hash: observationHash(), ByteCount: 512},
			Namespace:    contract.Namespace("payments"),
			ClusterAlias: contract.ClusterAlias("cluster-a"),
			ObservedAt:   observationTimestamp(t, "2026-09-30T12:00:00Z"),
			Termination:  contract.TerminationFinished,
			Subjects:     []normalize.ObservationSubject{subject},
		}
	}
	cases := []struct {
		name       string
		diagnostic normalize.ObservationDiagnostic
	}{
		{
			name:       "unknown code",
			diagnostic: normalize.ObservationDiagnostic{Code: "attacker_controlled", Offset: 1},
		},
		{
			name:       "locator outside the grammar",
			diagnostic: normalize.ObservationDiagnostic{Code: "status_unobserved", Offset: 1, Locator: "MARKER_SECRET"},
		},
		{
			name:       "offset beyond the admitted source",
			diagnostic: normalize.ObservationDiagnostic{Code: "status_unobserved", Offset: 513},
		},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			result := base()
			result.Subjects[0].Diagnostics = []normalize.ObservationDiagnostic{testCase.diagnostic}
			built, _, err := BuildObservation(ObservationInput{
				Result: result, SubjectIndex: 0, CollectorLabel: "operator-export",
				ParserVersion: "sanitized-podlist-v1/1.0", ObservedAt: result.ObservedAt,
			})
			if err == nil {
				t.Fatalf("an incoherent diagnostic was projected: %+v", built.Provenance.Errors)
			}
			if !reflect.DeepEqual(built, contract.Bundle{}) {
				t.Fatal("a refused DTO produced a bundle")
			}
		})
	}
	t.Run("the diagnostic of a real run is admitted", func(t *testing.T) {
		result := base()
		result.Subjects[0].Diagnostics = []normalize.ObservationDiagnostic{{
			Code: "status_unobserved", Offset: 200,
			Locator: "items[0].status.containerStatuses[0].imageID",
		}}
		if _, _, err := BuildObservation(ObservationInput{
			Result: result, SubjectIndex: 0, CollectorLabel: "operator-export",
			ParserVersion: "sanitized-podlist-v1/1.0", ObservedAt: result.ObservedAt,
		}); err != nil {
			t.Fatalf("a coherent diagnostic was refused: %v", err)
		}
	})
}

// TestA201CompleteCoverageNeedsTheAssociations refuses a DTO that claims a
// complete category while its own containers say the status was never observed.
func TestA201CompleteCoverageNeedsTheAssociations(t *testing.T) {
	subject := a201CollisionSubject("api",
		[]contract.ContainerClass{contract.ContainerRegular, contract.ContainerInit}, nil)
	// The containers keep their statuses, so the DTO is coherent; dropping one
	// status while the category stays complete is what must be refused.
	subject.CollidedClasses = map[string][]contract.ContainerClass{}
	for index := range subject.Containers {
		subject.Containers[index].StatusPresent = false
		subject.Containers[index].StatusIndex = -1
		subject.Containers[index].ImageID = nil
		subject.Containers[index].ImageIDPresence = ingest.PresenceAbsent
	}
	result := normalize.ObservationResult{
		// The fixtures declare the accounting the producer would have declared.
		TotalItems:   1,
		Source:       normalize.ObservationSource{Name: observationSourceName(), Hash: observationHash()},
		Namespace:    contract.Namespace("payments"),
		ClusterAlias: contract.ClusterAlias("cluster-a"),
		ObservedAt:   observationTimestamp(t, "2026-09-30T12:00:00Z"),
		Termination:  contract.TerminationFinished,
		Subjects:     []normalize.ObservationSubject{subject},
	}
	built, _, err := BuildObservation(ObservationInput{
		Result: result, SubjectIndex: 0, CollectorLabel: "operator-export",
		ParserVersion: "sanitized-podlist-v1/1.0", ObservedAt: result.ObservedAt,
	})
	if err == nil {
		t.Fatalf("a complete category without its statuses was projected: completeness = %q", built.Provenance.Completeness)
	}
	// The base is a valid DTO, so the only reason to refuse it is the relation
	// between the claimed completeness and the containers.
	if !strings.Contains(err.Error(), "subject is not coherent") {
		t.Fatalf("error = %v, want the coherence failure of the subject", err)
	}
	if !reflect.DeepEqual(built, contract.Bundle{}) {
		t.Fatal("a refused DTO produced a bundle")
	}
}

// TestA201OmissionLocatorPointsToARealField keeps the omission traceable: the
// locator names the observed status field when it existed and the declaration
// otherwise, never a field the source did not carry.
func TestA201OmissionLocatorPointsToARealField(t *testing.T) {
	t.Run("with an observed status", func(t *testing.T) {
		subject := a201CollisionSubject("api",
			[]contract.ContainerClass{contract.ContainerRegular, contract.ContainerInit}, nil)
		_, diagnostics := a201CollisionBuild(t, subject)
		if len(diagnostics.Omitted) != 2 {
			t.Fatalf("omissions = %d, want 2", len(diagnostics.Omitted))
		}
		for _, omission := range diagnostics.Omitted {
			if !ingest.PodListLocatorValid(string(omission.Locator)) || omission.Locator == "" {
				t.Fatalf("omission locator = %q, want a real status field", omission.Locator)
			}
		}
	})
	t.Run("without a status, the declaration is named", func(t *testing.T) {
		subject := a201CollisionSubject("api",
			[]contract.ContainerClass{contract.ContainerRegular, contract.ContainerInit}, nil)
		for index := range subject.Containers {
			subject.Containers[index].StatusPresent = false
			subject.Containers[index].StatusIndex = -1
			subject.Containers[index].ImageID = nil
			subject.Containers[index].ImageIDPresence = ingest.PresenceAbsent
		}
		// The DTO must stay coherent with its own containers: a category without
		// statuses is not complete.
		subject.CategoriesComplete = map[contract.ContainerClass]bool{}
		_, diagnostics := a201CollisionBuild(t, subject)
		if len(diagnostics.Omitted) != 2 {
			t.Fatalf("omissions = %d, want 2", len(diagnostics.Omitted))
		}
		for _, omission := range diagnostics.Omitted {
			if omission.Locator == "" {
				t.Fatal("the omission lost its origin")
			}
			if !strings.HasSuffix(string(omission.Locator), ".name") {
				t.Fatalf("omission locator = %q, want the declared name when no status was observed", omission.Locator)
			}
			if strings.Contains(string(omission.Locator), "[-1]") {
				t.Fatalf("omission locator = %q, want a position that exists", omission.Locator)
			}
		}
	})
}

// TestA201AccountingIsRevalidated refuses a normalized run whose counters do not
// describe its own items: the accepted subjects plus the rejected items are the
// known total, and the subtraction is checked without overflow.
func TestA201AccountingIsRevalidated(t *testing.T) {
	base := func() normalize.ObservationResult {
		subject := normalize.ObservationSubject{
			UID:                contract.UID("uid-0001"),
			Namespace:          contract.Namespace("payments"),
			Name:               "payments-api-7f4d",
			StartByte:          10,
			EndByte:            200,
			CategoriesObserved: map[contract.ContainerClass]bool{contract.ContainerRegular: true},
			CategoriesComplete: map[contract.ContainerClass]bool{},
			CollidedClasses:    map[string][]contract.ContainerClass{},
			Containers: []normalize.ObservationContainer{{
				Class: contract.ContainerRegular, Name: "api", SpecIndex: 0, StatusIndex: 0,
				SpecPresent: true, StatusPresent: true,
			}},
		}
		return normalize.ObservationResult{
			Source:       normalize.ObservationSource{Name: observationSourceName(), Hash: observationHash(), ByteCount: 512},
			Namespace:    contract.Namespace("payments"),
			ClusterAlias: contract.ClusterAlias("cluster-a"),
			ObservedAt:   observationTimestamp(t, "2026-09-30T12:00:00Z"),
			Termination:  contract.TerminationFinished,
			TotalItems:   1,
			Subjects:     []normalize.ObservationSubject{subject},
		}
	}
	build := func(result normalize.ObservationResult) error {
		_, _, err := BuildObservation(ObservationInput{
			Result: result, SubjectIndex: 0, CollectorLabel: "operator-export",
			ParserVersion: "sanitized-podlist-v1/1.0", ObservedAt: result.ObservedAt,
		})
		return err
	}
	t.Run("the declared total cannot contradict the subjects", func(t *testing.T) {
		result := base()
		result.TotalItems = 0
		if err := build(result); err == nil {
			t.Fatal("a total that contradicts the accepted subjects was projected")
		}
	})
	t.Run("the rejected items count towards the total", func(t *testing.T) {
		result := base()
		result.TotalItems = 3
		// One accepted subject plus one rejected item cannot be a total of three.
		result.RejectedItems = 1
		if err := build(result); err == nil {
			t.Fatal("a total that contradicts the subjects and the rejections was projected")
		}
	})
	t.Run("a coherent accounting is admitted", func(t *testing.T) {
		result := base()
		result.TotalItems = 3
		result.RejectedItems = 2
		// One accepted subject plus two rejected items: the totals agree.
		if err := build(result); err != nil {
			t.Fatalf("a coherent accounting was refused: %v", err)
		}
	})
}

// TestA201DiagnosticAnchorsInsideTheSource refuses anchors that cannot exist:
// a surrogate failure always anchors on its backslash, so it can never name the
// end of the source, and a subject diagnostic is anchored inside the interval
// the producer declared for that subject.
func TestA201DiagnosticAnchorsInsideTheSource(t *testing.T) {
	base := func() normalize.ObservationResult {
		subject := normalize.ObservationSubject{
			UID:                contract.UID("uid-0001"),
			Namespace:          contract.Namespace("payments"),
			Name:               "payments-api-7f4d",
			StartByte:          10,
			EndByte:            200,
			CategoriesObserved: map[contract.ContainerClass]bool{contract.ContainerRegular: true},
			CategoriesComplete: map[contract.ContainerClass]bool{},
			CollidedClasses:    map[string][]contract.ContainerClass{},
			Containers: []normalize.ObservationContainer{{
				Class: contract.ContainerRegular, Name: "api", SpecIndex: 0, StatusIndex: 0,
				SpecPresent: true, StatusPresent: true,
			}},
		}
		subject.StartByte = 10
		subject.EndByte = 200
		return normalize.ObservationResult{
			Source:       normalize.ObservationSource{Name: observationSourceName(), Hash: observationHash(), ByteCount: 512},
			Namespace:    contract.Namespace("payments"),
			ClusterAlias: contract.ClusterAlias("cluster-a"),
			ObservedAt:   observationTimestamp(t, "2026-09-30T12:00:00Z"),
			Termination:  contract.TerminationFinished,
			TotalItems:   1,
			Subjects:     []normalize.ObservationSubject{subject},
		}
	}
	build := func(result normalize.ObservationResult) error {
		_, _, err := BuildObservation(ObservationInput{
			Result: result, SubjectIndex: 0, CollectorLabel: "operator-export",
			ParserVersion: "sanitized-podlist-v1/1.0", ObservedAt: result.ObservedAt,
		})
		return err
	}
	t.Run("surrogate anchor at the end of the source", func(t *testing.T) {
		result := base()
		result.Subjects[0].Diagnostics = []normalize.ObservationDiagnostic{{
			Code: "invalid_surrogate", Offset: result.Source.ByteCount,
		}}
		if err := build(result); err == nil {
			t.Fatal("an anchor at the end of the source was admitted for a surrogate failure")
		}
	})
	t.Run("anchor outside the declared subject interval", func(t *testing.T) {
		result := base()
		result.Subjects[0].Diagnostics = []normalize.ObservationDiagnostic{{
			Code: "status_unobserved", Offset: 0,
		}}
		if err := build(result); err == nil {
			t.Fatal("an anchor outside the subject interval was admitted")
		}
	})
	t.Run("inclusive interval cannot end at the end of the source", func(t *testing.T) {
		result := base()
		result.Subjects[0].EndByte = result.Source.ByteCount
		if err := build(result); err == nil {
			t.Fatal("an inclusive interval ending past the last byte was admitted")
		}
	})
	t.Run("a coherent anchor is admitted", func(t *testing.T) {
		result := base()
		result.Subjects[0].Diagnostics = []normalize.ObservationDiagnostic{{
			Code: "status_unobserved", Offset: 50,
			Locator: "items[0].status.containerStatuses[0].imageID",
		}}
		if err := build(result); err != nil {
			t.Fatalf("a coherent anchor was refused: %v", err)
		}
	})
}
