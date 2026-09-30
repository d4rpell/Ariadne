package normalize

import (
	"reflect"
	"testing"
	"time"

	"github.com/d4rpell/Ariadne/internal/ingest"
	contract "github.com/d4rpell/Ariadne/pkg/evidence"
)

// Normalization tests of ADR-0025 A.8: status joins by name within its class
// and never by index, requested stays the declared spec value, raw stays the
// observed imageID, and the status image is context that never substitutes
// either of them.

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

func a201Context(t *testing.T) ingest.PodListContext {
	t.Helper()
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

func a201Source() *ingest.PodListSource {
	return &ingest.PodListSource{
		Name:      "sanitized-pods.json",
		Hash:      contract.SourceHash("sha256:" + "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
		ByteCount: 512,
	}
}

func a201String(value string) ingest.PodOptionalString {
	return ingest.PodOptionalString{Present: ingest.PresenceValue, Value: value}
}

// TestA201StatusJoin permutes the status array so a positional join would
// attribute the wrong imageID: only a join by name within the class survives.
func TestA201StatusJoin(t *testing.T) {
	regular := contract.ContainerRegular
	subject := ingest.PodSubject{
		ItemIndex:   0,
		UID:         "uid-0001",
		Namespace:   "payments",
		Name:        "payments-api-7f4d",
		SpecPresent: map[contract.ContainerClass]bool{regular: true},
		Statuses:    map[contract.ContainerClass]bool{regular: true},
		SpecContainers: map[contract.ContainerClass][]ingest.PodContainerSpec{
			regular: {
				{Class: regular, Name: "api", Image: a201String("registry.example/app:release")},
				{Class: regular, Name: "worker", Image: a201String("registry.example/worker:release")},
			},
		},
		StatusContainers: map[contract.ContainerClass][]ingest.PodContainerStatus{
			// Deliberately permuted: worker first, api second.
			regular: {
				{Class: regular, Name: "worker", ImageID: a201String("sha256:worker-observed")},
				{Class: regular, Name: "api", ImageID: a201String("sha256:api-observed")},
			},
		},
	}
	result, err := NormalizePodList(a201Counted(ingest.PodListResult{
		Context:  a201Context(t),
		Source:   a201Source(),
		Subjects: []ingest.PodSubject{subject},
	}))
	if err != nil {
		t.Fatalf("NormalizePodList: %v", err)
	}
	subjectOut := result.Subjects[0]
	if len(subjectOut.Containers) != 2 {
		t.Fatalf("containers = %d, want 2", len(subjectOut.Containers))
	}
	for _, container := range subjectOut.Containers {
		switch container.Name {
		case "api":
			if container.ImageID == nil || *container.ImageID != "sha256:api-observed" {
				t.Fatalf("api imageID = %v, want the api status joined by name", container.ImageID)
			}
		case "worker":
			if container.ImageID == nil || *container.ImageID != "sha256:worker-observed" {
				t.Fatalf("worker imageID = %v, want the worker status joined by name", container.ImageID)
			}
		}
	}

	bindings, err := ObservationBindings(result, 0)
	if err != nil {
		t.Fatalf("ObservationBindings: %v", err)
	}
	for _, binding := range bindings {
		if string(binding.Key.SubjectUID) != subject.UID {
			t.Fatalf("binding subject uid = %q, want the Pod uid %q", binding.Key.SubjectUID, subject.UID)
		}
		switch string(binding.Key.ContainerName) {
		case "api":
			if binding.RawImageID == nil || string(*binding.RawImageID) != "sha256:api-observed" {
				t.Fatalf("api raw = %v, want the observed value", binding.RawImageID)
			}
			if binding.Locator != "items[0].status.containerStatuses[1].imageID" {
				t.Fatalf("api locator = %q, want the original position of its status", binding.Locator)
			}
		case "worker":
			if binding.Locator != "items[0].status.containerStatuses[0].imageID" {
				t.Fatalf("worker locator = %q, want the original position of its status", binding.Locator)
			}
		}
	}
}

// TestA201ImageSeparation keeps requested, status image and imageID apart, and
// refuses to promote a digest-shaped raw value.
func TestA201ImageSeparation(t *testing.T) {
	regular := contract.ContainerRegular
	digestShaped := "registry.example/app@sha256:" + "abababababababababababababababababababababababababababababababab"
	subject := ingest.PodSubject{
		ItemIndex:   0,
		UID:         "uid-0001",
		Namespace:   "payments",
		Name:        "payments-api-7f4d",
		SpecPresent: map[contract.ContainerClass]bool{regular: true},
		Statuses:    map[contract.ContainerClass]bool{regular: true},
		SpecContainers: map[contract.ContainerClass][]ingest.PodContainerSpec{
			regular: {{Class: regular, Name: "api", Image: a201String("registry.example/app:release")}},
		},
		StatusContainers: map[contract.ContainerClass][]ingest.PodContainerStatus{
			regular: {{
				Class:   regular,
				Name:    "api",
				ImageID: a201String(digestShaped),
				Image:   a201String("registry.example/app@sha256:different"),
			}},
		},
	}
	result, err := NormalizePodList(a201Counted(ingest.PodListResult{
		Context:  a201Context(t),
		Source:   a201Source(),
		Subjects: []ingest.PodSubject{subject},
	}))
	if err != nil {
		t.Fatalf("NormalizePodList: %v", err)
	}
	container := result.Subjects[0].Containers[0]
	if container.Image == nil || *container.Image != "registry.example/app:release" {
		t.Fatalf("requested = %v, want the spec declaration", container.Image)
	}
	if container.ImageID == nil || *container.ImageID != digestShaped {
		t.Fatalf("raw = %v, want the observed imageID preserved verbatim", container.ImageID)
	}
	if container.StatusImage == nil || *container.StatusImage != "registry.example/app@sha256:different" {
		t.Fatalf("status image = %v, want the separate context value", container.StatusImage)
	}

	bindings, err := ObservationBindings(result, 0)
	if err != nil {
		t.Fatalf("ObservationBindings: %v", err)
	}
	binding := bindings[0]
	if binding.RequestedImage == nil || string(*binding.RequestedImage) != "registry.example/app:release" {
		t.Fatalf("binding requested = %v", binding.RequestedImage)
	}
	if binding.RawImageID == nil || string(*binding.RawImageID) != digestShaped {
		t.Fatalf("binding raw = %v", binding.RawImageID)
	}
	// The adapter proves no digest: ObservationBinding has no guaranteed-digest
	// field at all, so a PodList cannot promote one through this path. The
	// conversion to identity keeps Platform unknown and never sets a digest.
}

// TestA201ImageSeparationStatusOnly keeps the status image out of the requested
// reference when the declaration carried no image at all: the PodList observed
// one field and the other stays absent, never filled from its neighbour.
func TestA201ImageSeparationStatusOnly(t *testing.T) {
	regular := contract.ContainerRegular
	subject := ingest.PodSubject{
		ItemIndex:   0,
		UID:         "uid-0001",
		Namespace:   "payments",
		Name:        "payments-api-7f4d",
		SpecPresent: map[contract.ContainerClass]bool{regular: true},
		Statuses:    map[contract.ContainerClass]bool{regular: true},
		SpecContainers: map[contract.ContainerClass][]ingest.PodContainerSpec{
			// No image: requested stays unavailable.
			regular: {{Class: regular, Name: "api"}},
		},
		StatusContainers: map[contract.ContainerClass][]ingest.PodContainerStatus{
			regular: {{
				Class:   regular,
				Name:    "api",
				ImageID: a201String("sha256:observed"),
				Image:   a201String("registry.example/app:release"),
			}},
		},
	}
	result, err := NormalizePodList(a201Counted(ingest.PodListResult{
		Context:  a201Context(t),
		Source:   a201Source(),
		Subjects: []ingest.PodSubject{subject},
	}))
	if err != nil {
		t.Fatalf("NormalizePodList: %v", err)
	}
	container := result.Subjects[0].Containers[0]
	if container.Image != nil {
		t.Fatalf("requested = %v, want null: the status image never becomes the declaration", container.Image)
	}
	if container.StatusImage == nil || *container.StatusImage != "registry.example/app:release" {
		t.Fatalf("status image = %v, want the context value preserved", container.StatusImage)
	}
	if container.ImageID == nil || *container.ImageID != "sha256:observed" {
		t.Fatalf("raw = %v, want the observed value", container.ImageID)
	}
	bindings, err := ObservationBindings(result, 0)
	if err != nil {
		t.Fatalf("ObservationBindings: %v", err)
	}
	if bindings[0].RequestedImage != nil {
		t.Fatalf("binding requested = %v, want none", bindings[0].RequestedImage)
	}
	if bindings[0].RawImageID == nil || string(*bindings[0].RawImageID) != "sha256:observed" {
		t.Fatalf("binding raw = %v", bindings[0].RawImageID)
	}
}

// TestA201PresenceIsPreserved keeps absence and emptiness apart across the
// normalization boundary: an omitted reference, an empty one and a declared one
// are three different observations (ADR-0025 A.7.3, A.9.3), and so are an
// omitted state object and the empty object.
func TestA201PresenceIsPreserved(t *testing.T) {
	regular := contract.ContainerRegular
	build := func(spec ingest.PodContainerSpec, status ingest.PodContainerStatus) ObservationSubject {
		t.Helper()
		result, err := NormalizePodList(a201Counted(ingest.PodListResult{
			Context: a201Context(t),
			Source:  a201Source(),
			Subjects: []ingest.PodSubject{{
				ItemIndex:   0,
				UID:         "uid-0001",
				Namespace:   "payments",
				Name:        "payments-api-7f4d",
				SpecPresent: map[contract.ContainerClass]bool{regular: true},
				Statuses:    map[contract.ContainerClass]bool{regular: true},
				SpecContainers: map[contract.ContainerClass][]ingest.PodContainerSpec{
					regular: {spec},
				},
				StatusContainers: map[contract.ContainerClass][]ingest.PodContainerStatus{
					regular: {status},
				},
			}},
		}))
		if err != nil {
			t.Fatalf("NormalizePodList: %v", err)
		}
		return result.Subjects[0]
	}

	t.Run("absent image versus empty image", func(t *testing.T) {
		absent := build(
			ingest.PodContainerSpec{Class: regular, Name: "api"},
			ingest.PodContainerStatus{Class: regular, Name: "api"},
		).Containers[0]
		if absent.ImagePresence != ingest.PresenceAbsent || absent.Image != nil {
			t.Fatalf("absent image = %+v / presence %v", absent.Image, absent.ImagePresence)
		}
		empty := build(
			ingest.PodContainerSpec{Class: regular, Name: "api", Image: ingest.PodOptionalString{Present: ingest.PresenceEmpty}},
			ingest.PodContainerStatus{Class: regular, Name: "api"},
		).Containers[0]
		if empty.ImagePresence != ingest.PresenceEmpty {
			t.Fatalf("empty image presence = %v, want empty", empty.ImagePresence)
		}
		declared := build(
			ingest.PodContainerSpec{Class: regular, Name: "api", Image: a201String("registry.example/app:release")},
			ingest.PodContainerStatus{Class: regular, Name: "api"},
		).Containers[0]
		if declared.ImagePresence != ingest.PresenceValue || declared.Image == nil {
			t.Fatalf("declared image = %+v / presence %v", declared.Image, declared.ImagePresence)
		}
	})
	t.Run("absent imageID versus empty imageID", func(t *testing.T) {
		absent := build(
			ingest.PodContainerSpec{Class: regular, Name: "api"},
			ingest.PodContainerStatus{Class: regular, Name: "api"},
		).Containers[0]
		if absent.ImageIDPresence != ingest.PresenceAbsent || absent.ImageID != nil {
			t.Fatalf("absent imageID = %+v / presence %v", absent.ImageID, absent.ImageIDPresence)
		}
		empty := build(
			ingest.PodContainerSpec{Class: regular, Name: "api"},
			ingest.PodContainerStatus{Class: regular, Name: "api", ImageID: ingest.PodOptionalString{Present: ingest.PresenceEmpty}},
		).Containers[0]
		if empty.ImageIDPresence != ingest.PresenceEmpty || empty.ImageID != nil {
			t.Fatalf("empty imageID = %+v / presence %v", empty.ImageID, empty.ImageIDPresence)
		}
	})
	t.Run("absent state versus empty state", func(t *testing.T) {
		absent := build(
			ingest.PodContainerSpec{Class: regular, Name: "api"},
			ingest.PodContainerStatus{Class: regular, Name: "api"},
		).Containers[0]
		if absent.StatePresence != ingest.PresenceAbsent {
			t.Fatalf("absent state presence = %v", absent.StatePresence)
		}
		empty := build(
			ingest.PodContainerSpec{Class: regular, Name: "api"},
			ingest.PodContainerStatus{Class: regular, Name: "api", StatePresent: true},
		).Containers[0]
		if empty.StatePresence != ingest.PresenceValue || empty.State != "" {
			t.Fatalf("empty state = %q / presence %v", empty.State, empty.StatePresence)
		}
	})
}

// TestA201IncoherentInputIsRefused keeps an incoherent parse out of the result:
// a diagnostic outside the closed catalog, a locator that is not a path of the
// admitted document and a status without its declaration are static errors, so
// no supplied text can reach an artifact as evidence (ADR-0025 A.10.1, A.11.2).
func TestA201IncoherentInputIsRefused(t *testing.T) {
	base := func() ingest.PodListResult {
		return a201Counted(ingest.PodListResult{
			Context: a201Context(t),
			Source:  a201Source(),
			Subjects: []ingest.PodSubject{{
				ItemIndex:   0,
				UID:         "uid-0001",
				Namespace:   "payments",
				Name:        "payments-api-7f4d",
				SpecPresent: map[contract.ContainerClass]bool{},
				Statuses:    map[contract.ContainerClass]bool{},
				SpecContainers: map[contract.ContainerClass][]ingest.PodContainerSpec{
					contract.ContainerRegular: {{Class: contract.ContainerRegular, Name: "api"}},
				},
				StatusContainers: map[contract.ContainerClass][]ingest.PodContainerStatus{},
			}},
		})
	}
	t.Run("unknown diagnostic code", func(t *testing.T) {
		input := base()
		input.Diagnostics = []ingest.PodListDiagnostic{{Code: ingest.PodListDiagnosticCode("attacker_controlled"), ByteOffset: 7}}
		result, err := NormalizePodList(input)
		if err == nil {
			t.Fatal("a code outside the closed catalog was admitted")
		}
		if !reflect.DeepEqual(result, ObservationResult{}) {
			t.Fatal("a refused input produced a result")
		}
	})
	t.Run("locator with free text", func(t *testing.T) {
		input := base()
		input.Subjects[0].Diagnostics = []ingest.PodListDiagnostic{{
			Code:         ingest.PodListCodeCategoryUnobserved,
			ByteOffset:   0,
			FieldLocator: "MARKER_SECRET",
		}}
		if _, err := NormalizePodList(input); err == nil {
			t.Fatal("a locator outside the closed grammar was admitted")
		}
	})
	t.Run("status without its declaration", func(t *testing.T) {
		input := base()
		input.Subjects[0].Statuses = map[contract.ContainerClass]bool{contract.ContainerRegular: true}
		input.Subjects[0].StatusContainers = map[contract.ContainerClass][]ingest.PodContainerStatus{
			contract.ContainerRegular: {{Class: contract.ContainerRegular, Name: "other"}},
		}
		if _, err := NormalizePodList(input); err == nil {
			t.Fatal("an orphan status introduced through the DTO was admitted")
		}
	})
	t.Run("declared counters that contradict the items", func(t *testing.T) {
		input := base()
		total := uint64(5)
		input.TotalItems = &total
		input.Accepted = 1
		input.Rejected = 1
		if _, err := NormalizePodList(input); err == nil {
			t.Fatal("counters that contradict the items were admitted")
		}
	})
}
