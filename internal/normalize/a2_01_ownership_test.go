// This file uses the external test package normalize_test: it exercises only
// the exported NormalizePodList surface, and the internal test files of this
// directory already declare TestA201NormalizeOwnership.
package normalize_test

import (
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/d4rpell/Ariadne/internal/ingest"
	"github.com/d4rpell/Ariadne/internal/normalize"
	contract "github.com/d4rpell/Ariadne/pkg/evidence"
)

func a201OwnershipContext() ingest.PodListContext {
	return ingest.PodListContext{
		Selector:           "sanitized-podlist-v1",
		Version:            "1.0",
		RedactionPolicy:    "sanitized-podlist-v1/1.0",
		SourceName:         "sanitized-pods.json",
		ClusterAlias:       "cluster-a",
		Namespace:          "payments",
		ObservedAt:         time.Date(2026, 9, 30, 12, 0, 0, 0, time.UTC),
		CaptureTermination: contract.TerminationFinished,
	}
}

func a201OwnershipSource() *ingest.PodListSource {
	return &ingest.PodListSource{
		Name:      "sanitized-pods.json",
		Hash:      contract.SourceHash("sha256:" + strings.Repeat("a", 64)),
		ByteCount: 512,
	}
}

func a201OwnershipString(value string) ingest.PodOptionalString {
	return ingest.PodOptionalString{Present: ingest.PresenceValue, Value: value}
}

func a201OwnershipInt(value int) *int {
	return &value
}

// a201Counted declares the accounting of one hand-built parse: the fixtures state
// the counters the producer would have declared, so the validation of the input
// is exercised instead of bypassed.
func a201Counted(result ingest.PodListResult) ingest.PodListResult {
	total := uint64(len(result.Subjects)) + uint64(len(result.Rejections))
	result.TotalItems = &total
	result.Accepted = uint64(len(result.Subjects))
	result.Rejected = uint64(len(result.Rejections))
	return result
}

func TestA201NormalizeOwnership(t *testing.T) {
	regular := contract.ContainerRegular
	diagnostics := []ingest.PodListDiagnostic{{
		Code:         ingest.PodListCodeCategoryUnobserved,
		ByteOffset:   42,
		ItemIndex:    a201OwnershipInt(0),
		FieldLocator: "items[0].spec.containers[0].image",
	}}
	subject := ingest.PodSubject{
		ItemIndex:   0,
		UID:         "uid-a201-0001",
		Namespace:   "payments",
		Name:        "payments-api-7f4d",
		SpecPresent: map[contract.ContainerClass]bool{regular: true},
		Statuses:    map[contract.ContainerClass]bool{regular: true},
		SpecContainers: map[contract.ContainerClass][]ingest.PodContainerSpec{
			regular: {{Class: regular, Name: "api", Image: a201OwnershipString("registry.example/app:release")}},
		},
		StatusContainers: map[contract.ContainerClass][]ingest.PodContainerStatus{
			regular: {{Class: regular, Name: "api", ImageID: a201OwnershipString("sha256:observado-a201")}},
		},
		Diagnostics: diagnostics,
	}
	input := a201Counted(ingest.PodListResult{
		Context:     a201OwnershipContext(),
		Source:      a201OwnershipSource(),
		Subjects:    []ingest.PodSubject{subject},
		Diagnostics: diagnostics,
	})

	result, err := normalize.NormalizePodList(input)
	if err != nil {
		t.Fatalf("NormalizePodList: unexpected error: %v", err)
	}
	if len(result.Subjects) != 1 || len(result.Subjects[0].Containers) != 1 {
		t.Fatalf("unexpected result shape: subjects=%d containers=%d", len(result.Subjects), len(result.Subjects[0].Containers))
	}
	diagnosticsBefore := append([]normalize.ObservationDiagnostic(nil), result.GlobalDiagnostics...)
	categoriesBefore := make(map[contract.ContainerClass]bool, len(result.Subjects[0].CategoriesObserved))
	for class, observed := range result.Subjects[0].CategoriesObserved {
		categoriesBefore[class] = observed
	}

	// Mutating the input DTO after normalization must not change the result.
	input.Subjects[0].Name = "mutated-a201"
	input.Subjects[0].SpecContainers[regular][0].Name = "mutated-a201"
	input.Subjects[0].SpecContainers[regular] = append(input.Subjects[0].SpecContainers[regular], ingest.PodContainerSpec{Class: regular, Name: "injected-a201"})
	input.Subjects[0].Diagnostics = append(input.Subjects[0].Diagnostics, ingest.PodListDiagnostic{Code: ingest.PodListCodeInvalidInput})

	if result.Subjects[0].Name != "payments-api-7f4d" {
		t.Fatalf("subject name changed after the input was mutated: %q", result.Subjects[0].Name)
	}
	if len(result.Subjects[0].Containers) != 1 {
		t.Fatalf("containers = %d after the input slice grew, want 1", len(result.Subjects[0].Containers))
	}
	container := result.Subjects[0].Containers[0]
	if container.Name != "api" {
		t.Fatalf("container name changed after the input was mutated: %q", container.Name)
	}
	if container.Image == nil || *container.Image != "registry.example/app:release" {
		t.Fatalf("requested image changed after the input was mutated: %v", container.Image)
	}
	if container.ImageID == nil || *container.ImageID != "sha256:observado-a201" {
		t.Fatalf("raw image ID changed after the input was mutated: %v", container.ImageID)
	}
	if !reflect.DeepEqual(result.GlobalDiagnostics, diagnosticsBefore) {
		t.Fatalf("diagnostics changed after the input was mutated: %v, want %v", result.GlobalDiagnostics, diagnosticsBefore)
	}
	if !reflect.DeepEqual(result.Subjects[0].CategoriesObserved, categoriesBefore) {
		t.Fatalf("observed categories changed after the input was mutated: %v, want %v", result.Subjects[0].CategoriesObserved, categoriesBefore)
	}

	// Mutating the returned result must not change the input DTO.
	result.Subjects[0].Containers[0].Name = "mutated-result-a201"
	result.Subjects[0].CategoriesObserved[contract.ContainerEphemeral] = true
	result.GlobalDiagnostics[0].Code = "mutated-result-a201"
	result.GlobalDiagnostics = append(result.GlobalDiagnostics, normalize.ObservationDiagnostic{Code: "mutated-result-a201"})

	if !input.Subjects[0].SpecPresent[regular] {
		t.Fatal("mutating the result cleared the input regular category")
	}
	if input.Subjects[0].SpecPresent[contract.ContainerEphemeral] {
		t.Fatal("mutating the result marked an ephemeral category on the input")
	}
	foundInjected := false
	for _, spec := range input.Subjects[0].SpecContainers[regular] {
		if spec.Name == "mutated-result-a201" {
			t.Fatal("mutating the result changed an input container name")
		}
		if spec.Name == "injected-a201" {
			foundInjected = true
		}
	}
	if !foundInjected {
		t.Fatal("the input container slice lost its own appended entry")
	}
	if len(input.Subjects[0].Diagnostics) != 2 || input.Subjects[0].Diagnostics[0].Code != ingest.PodListCodeCategoryUnobserved {
		t.Fatalf("mutating the result changed the input diagnostics: %v", input.Subjects[0].Diagnostics)
	}

	// A result without an admitted source is refused with an empty result.
	empty, err := normalize.NormalizePodList(a201Counted(ingest.PodListResult{Context: a201OwnershipContext()}))
	if err == nil {
		t.Fatal("a DTO without an admitted source was accepted, want rejection")
	}
	if !reflect.DeepEqual(empty, normalize.ObservationResult{}) {
		t.Fatalf("rejected DTO returned a non-empty result: %+v", empty)
	}

	// A zero observation time is refused with an empty result.
	zeroTime := a201OwnershipContext()
	zeroTime.ObservedAt = time.Time{}
	empty, err = normalize.NormalizePodList(a201Counted(ingest.PodListResult{Context: zeroTime, Source: a201OwnershipSource()}))
	if err == nil {
		t.Fatal("a zero observation time was accepted, want rejection")
	}
	if !reflect.DeepEqual(empty, normalize.ObservationResult{}) {
		t.Fatalf("zero-time DTO returned a non-empty result: %+v", empty)
	}
}
