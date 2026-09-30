package ingest

import (
	"testing"

	contract "github.com/d4rpell/Ariadne/pkg/evidence"
)

// Ownership of the result (ADR-0025 A.11.2): the parse never hands out a view of
// its internal buffers, and a caller who mutates what it received cannot rewrite
// another result or a later parse.

func TestA201ParseOwnership(t *testing.T) {
	document := a201List(
		a201CompletePod("uid-1", "api", "sha256:aaaa"),
		a201CompletePod("uid-2", "worker", "sha256:bbbb"),
	)
	first := a201MustParse(t, document)
	second := a201MustParse(t, document)
	if len(first.Subjects) != 2 || len(second.Subjects) != 2 {
		t.Fatalf("subjects = %d and %d, want 2 and 2", len(first.Subjects), len(second.Subjects))
	}

	// Mutate every mutable part of the first result: nested values, slices,
	// maps and pointers.
	first.Subjects[0].Name = "mutated"
	first.Subjects[0].SpecContainers[contract.ContainerRegular][0].Name = "mutated"
	first.Subjects[0].SpecContainers[contract.ContainerRegular] = nil
	first.Subjects[0].StatusContainers[contract.ContainerRegular][0].ImageID.Value = "mutated"
	first.Subjects[0].SpecPresent[contract.ContainerInit] = false
	first.Subjects[0].OwnerReferences = append(first.Subjects[0].OwnerReferences, PodOwnerReference{Name: "invented"})
	first.Subjects[0].Diagnostics = append(first.Subjects[0].Diagnostics, PodListDiagnostic{Code: PodListCodeInvalidInput})
	first.Subjects = first.Subjects[:1]
	first.Rejections = append(first.Rejections, PodListRejection{Code: PodListCodeInvalidInput})
	first.Diagnostics = append(first.Diagnostics, PodListDiagnostic{Code: PodListCodeInvalidInput})
	first.Source.Name = "mutated"

	if second.Subjects[0].Name != "api" || second.Subjects[1].Name != "worker" {
		t.Fatalf("the second parse saw the mutation: %q and %q", second.Subjects[0].Name, second.Subjects[1].Name)
	}
	if len(second.Subjects[0].SpecContainers[contract.ContainerRegular]) != 1 {
		t.Fatal("the second parse shared the spec slice of the first")
	}
	if second.Subjects[0].StatusContainers[contract.ContainerRegular][0].ImageID.Value != "sha256:aaaa" {
		t.Fatal("the second parse shared the status carrier of the first")
	}
	if !second.Subjects[0].SpecPresent[contract.ContainerInit] {
		t.Fatal("the second parse shared the category map of the first")
	}
	if len(second.Subjects[0].OwnerReferences) != 0 {
		t.Fatal("the second parse shared the owner reference slice of the first")
	}
	if len(second.Subjects[0].Diagnostics) != 0 {
		t.Fatal("the second parse shared the diagnostics of the first")
	}
	if len(second.Subjects) != 2 || len(second.Rejections) != 0 || len(second.Diagnostics) != 0 {
		t.Fatal("the second parse shared a slice of the first")
	}
	if second.Source.Name != "sanitized-pods.json" {
		t.Fatal("the second parse shared the source name of the first")
	}

	// Mutating a result must not corrupt its own remaining state either.
	third := a201MustParse(t, document)
	third.Subjects[0].SpecContainers[contract.ContainerRegular][0].Image.Value = "mutated"
	if third.Subjects[0].SpecContainers[contract.ContainerRegular][0].Name != "api" {
		t.Fatal("mutating one field rewrote another field of the same result")
	}
	if len(third.Subjects[1].SpecContainers[contract.ContainerRegular]) != 1 {
		t.Fatal("mutating one subject rewrote another")
	}
	if third.Subjects[1].SpecContainers[contract.ContainerRegular][0].Image.Value != "registry.example/app:release" {
		t.Fatal("mutating one subject rewrote the carrier of another")
	}

	// The carriers of two different subjects are independent allocations.
	if third.Subjects[0].StatusContainers[contract.ContainerRegular][0].ImageID ==
		third.Subjects[1].StatusContainers[contract.ContainerRegular][0].ImageID {
		t.Fatal("two observations share one imageID carrier")
	}
	if third.Subjects[0].SpecContainers[contract.ContainerRegular][0].Image ==
		third.Subjects[1].SpecContainers[contract.ContainerRegular][0].Image {
		t.Fatal("two observations share one requested-image carrier")
	}
}
