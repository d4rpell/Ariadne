package identity

import (
	"reflect"
	"strings"
	"testing"
	"time"

	contract "github.com/d4rpell/Ariadne/pkg/evidence"
)

func TestResolveNeverMergesDistinctUIDs(t *testing.T) {
	first := syntheticBinding("api")
	first.GuaranteedDigest = guaranteedDigest(t, "sha256:"+strings.Repeat("11", 32))
	second := syntheticBinding("api")
	second.Key.SubjectUID = contract.UID("uid-0002")
	second.GuaranteedDigest = guaranteedDigest(t, "sha256:"+strings.Repeat("22", 32))

	resolutions, err := Resolve([]ImageBinding{first, second})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(resolutions) != 2 {
		t.Fatalf("resolutions = %d, want 2: same name and class, different UID are different subjects", len(resolutions))
	}
	if resolutions[0].Key.SubjectUID == resolutions[1].Key.SubjectUID {
		t.Fatal("distinct UIDs collapsed into one resolution")
	}
	for _, resolution := range resolutions {
		if resolution.State != ResolutionResolved || resolution.ConflictCode != "" {
			t.Fatalf("uid %q: state = %q, conflict = %q", resolution.Key.SubjectUID, resolution.State, resolution.ConflictCode)
		}
	}
}

func TestResolveContainerClassesDoNotMerge(t *testing.T) {
	classes := []contract.ContainerClass{contract.ContainerRegular, contract.ContainerInit, contract.ContainerEphemeral}
	bindings := make([]ImageBinding, 0, len(classes))
	for i, class := range classes {
		binding := syntheticBinding("api")
		binding.Key.ContainerClass = class
		binding.GuaranteedDigest = guaranteedDigest(t, "sha256:"+strings.Repeat(string(rune('a'+i)), 64))
		bindings = append(bindings, binding)
	}
	resolutions, err := Resolve(bindings)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(resolutions) != len(classes) {
		t.Fatalf("resolutions = %d, want %d: container classes are separate scopes", len(resolutions), len(classes))
	}
	seen := map[contract.ContainerClass]bool{}
	for _, resolution := range resolutions {
		if resolution.State != ResolutionResolved {
			t.Fatalf("class %q: state = %q", resolution.Key.ContainerClass, resolution.State)
		}
		seen[resolution.Key.ContainerClass] = true
	}
	for _, class := range classes {
		if !seen[class] {
			t.Fatalf("class %q lost during grouping", class)
		}
	}
}

func TestResolveConflictIsVisibleAndNonAffirmative(t *testing.T) {
	first := syntheticBinding("api")
	first.SourceName = "sanitized-export-a.json"
	first.GuaranteedDigest = guaranteedDigest(t, "sha256:"+strings.Repeat("11", 32))
	second := syntheticBinding("api")
	second.SourceName = "sanitized-export-b.json"
	second.RawImageID = rawImageID("registry.example/app@sha256:" + strings.Repeat("22", 32))

	resolutions, err := Resolve([]ImageBinding{first, second})
	if err == nil {
		t.Fatal("two observations of the same key accepted silently, want a visible conflict")
	}
	if len(resolutions) != 1 {
		t.Fatalf("resolutions = %d, want 1 conflicting key", len(resolutions))
	}
	conflict := resolutions[0]
	if conflict.State != ResolutionUnknown {
		t.Fatalf("state = %q, want %q: a conflict never resolves affirmatively", conflict.State, ResolutionUnknown)
	}
	if conflict.ConflictCode != ConflictSourceConflict {
		t.Fatalf("conflict code = %q, want %q", conflict.ConflictCode, ConflictSourceConflict)
	}
	if conflict.Binding != nil {
		t.Fatal("conflict kept one observation: choosing between conflicting sources is forbidden")
	}
	if conflict.BindingCount != 2 {
		t.Fatalf("binding count = %d, want 2", conflict.BindingCount)
	}
	if !strings.Contains(err.Error(), ConflictSourceConflict) {
		t.Fatalf("error %q does not name the conflict", err)
	}
}

func TestResolveConflictDoesNotLeakInput(t *testing.T) {
	first := syntheticBinding("api")
	first.SourceName = "SYNTHETIC_PRIVATE_MARKER.json"
	first.Key.ContainerName = contract.ContainerName("SYNTHETIC_PRIVATE_MARKER")
	second := first
	second.RawImageID = rawImageID("registry.example/app@sha256:" + strings.Repeat("ab", 32))
	resolutions, err := Resolve([]ImageBinding{first, second})
	if err == nil {
		t.Fatal("expected conflict error")
	}
	if strings.Contains(err.Error(), "SYNTHETIC_PRIVATE_MARKER") {
		t.Fatalf("error %q leaks input data", err)
	}
	if resolutions[0].ConflictCode != ConflictSourceConflict {
		t.Fatalf("conflict code = %q", resolutions[0].ConflictCode)
	}
}

func TestResolveAcceptsRepeatedIdenticalObservation(t *testing.T) {
	binding := syntheticBinding("api")
	binding.SourceName = "sanitized-pods.json"
	binding.SourceHash = contract.SourceHash("sha256:" + strings.Repeat("a", 64))
	binding.Locator = contract.SourceLocator("items[0].status.containerStatuses[0].imageID")
	binding.RawImageID = rawImageID("registry.example/app@sha256:" + strings.Repeat("ab", 32))

	resolutions, err := Resolve([]ImageBinding{binding, binding})
	if err != nil {
		t.Fatalf("identical observation rejected: %v", err)
	}
	if len(resolutions) != 1 {
		t.Fatalf("resolutions = %d, want 1 shared observation", len(resolutions))
	}
	resolution := resolutions[0]
	if resolution.State != ResolutionResolved {
		t.Fatalf("state = %q, want %q", resolution.State, ResolutionResolved)
	}
	if resolution.BindingCount != 2 {
		t.Fatalf("binding count = %d, want 2", resolution.BindingCount)
	}
	if resolution.ConflictCode != "" {
		t.Fatalf("identical observation reported conflict %q", resolution.ConflictCode)
	}
}

func TestResolveRejectsEveryDivergentObservationField(t *testing.T) {
	observedAt, err := contract.NewTimestamp(time.Date(2026, 9, 25, 12, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatalf("NewTimestamp: %v", err)
	}
	baseline := syntheticBinding("api")
	baseline.SourceName = "sanitized-pods.json"
	baseline.SourceHash = contract.SourceHash("sha256:" + strings.Repeat("a", 64))
	baseline.Locator = contract.SourceLocator("items[0].status.containerStatuses[0].imageID")
	baseline.RawImageID = rawImageID("registry.example/app@sha256:" + strings.Repeat("ab", 32))
	baseline.GuaranteedDigest = guaranteedDigest(t, "sha256:"+strings.Repeat("cd", 32))
	baseline.ObservedAt = &observedAt

	cases := map[string]func(ImageBinding) ImageBinding{
		"input kind": func(binding ImageBinding) ImageBinding {
			binding.InputKind = InputContainerObservation
			return binding
		},
		"source name": func(binding ImageBinding) ImageBinding {
			binding.SourceName = "other-pods.json"
			return binding
		},
		"source hash": func(binding ImageBinding) ImageBinding {
			binding.SourceHash = contract.SourceHash("sha256:" + strings.Repeat("b", 64))
			return binding
		},
		"locator": func(binding ImageBinding) ImageBinding {
			binding.Locator = contract.SourceLocator("items[1].status.containerStatuses[0].imageID")
			return binding
		},
		"platform": func(binding ImageBinding) ImageBinding {
			binding.Platform = contract.PlatformKnown
			return binding
		},
		"raw image id": func(binding ImageBinding) ImageBinding {
			binding.RawImageID = rawImageID("registry.example/app@sha256:" + strings.Repeat("ef", 32))
			return binding
		},
		"guaranteed digest": func(binding ImageBinding) ImageBinding {
			binding.GuaranteedDigest = guaranteedDigest(t, "sha256:"+strings.Repeat("01", 32))
			return binding
		},
		"observed at": func(binding ImageBinding) ImageBinding {
			other, timestampErr := contract.NewTimestamp(time.Date(2026, 9, 25, 12, 0, 1, 0, time.UTC))
			if timestampErr != nil {
				t.Fatalf("NewTimestamp: %v", timestampErr)
			}
			binding.ObservedAt = &other
			return binding
		},
	}
	for name, mutate := range cases {
		candidate := mutate(baseline)
		resolutions, resolveErr := Resolve([]ImageBinding{baseline, candidate})
		if resolveErr == nil {
			t.Errorf("%s: divergent observations accepted", name)
			continue
		}
		if len(resolutions) != 1 || resolutions[0].State != ResolutionUnknown {
			t.Errorf("%s: resolutions = %+v, want one unknown resolution", name, resolutions)
		}
		if len(resolutions) == 1 && resolutions[0].ConflictCode != ConflictSourceConflict {
			t.Errorf("%s: conflict code = %q, want %q", name, resolutions[0].ConflictCode, ConflictSourceConflict)
		}
	}
}

func TestResolveAllowsDifferentRequestedImagesForSharedObservation(t *testing.T) {
	first := syntheticBinding("api")
	first.SourceName = "sanitized-pods.json"
	first.SourceHash = contract.SourceHash("sha256:" + strings.Repeat("a", 64))
	first.Locator = contract.SourceLocator("items[0].status.containerStatuses[0].imageID")
	first.RawImageID = rawImageID("registry.example/app@sha256:" + strings.Repeat("ab", 32))
	first.RequestedImage = requestedImage("registry.example/app:release")
	second := first
	second.RequestedImage = requestedImage("registry.example/app:stable")

	resolutions, err := Resolve([]ImageBinding{first, second})
	if err != nil {
		t.Fatalf("different declarations for one observation rejected: %v", err)
	}
	if len(resolutions) != 1 || resolutions[0].State != ResolutionResolved {
		t.Fatalf("resolutions = %+v, want one resolved shared observation", resolutions)
	}
	if resolutions[0].Binding == nil || resolutions[0].Binding.RequestedImage == nil || *resolutions[0].Binding.RequestedImage != *first.RequestedImage {
		t.Fatal("shared resolution did not preserve the first observation binding")
	}
	if resolutions[0].BindingCount != 2 {
		t.Fatalf("binding count = %d, want 2", resolutions[0].BindingCount)
	}
}

func TestResolveRevalidatesIdenticalRepeatedObservations(t *testing.T) {
	invalidDigest := contract.NormalizedDigest("sha256:" + strings.Repeat("AB", 32))
	invalidDigestBinding := syntheticBinding("api")
	invalidDigestBinding.GuaranteedDigest = &invalidDigest
	invalidRawBinding := syntheticBinding("worker")
	invalidRawBinding.RawImageID = rawImageID("")
	knownPlatformBinding := syntheticBinding("metrics")
	knownPlatformBinding.Platform = contract.PlatformKnown

	cases := map[string]ImageBinding{
		"invalid digest":  invalidDigestBinding,
		"empty raw image": invalidRawBinding,
		"known platform":  knownPlatformBinding,
	}
	for name, binding := range cases {
		resolutions, err := Resolve([]ImageBinding{binding, binding})
		if err == nil {
			t.Errorf("%s: invalid repeated observation accepted", name)
			continue
		}
		if len(resolutions) != 1 || resolutions[0].State == ResolutionResolved || resolutions[0].Binding != nil {
			t.Errorf("%s: invalid repeated observation resolved: %+v", name, resolutions)
		}
	}
}

func TestResolvePreservesFirstAppearanceOrder(t *testing.T) {
	names := []string{"api", "worker", "metrics"}
	bindings := make([]ImageBinding, 0, len(names))
	for i, name := range names {
		binding := syntheticBinding(name)
		binding.GuaranteedDigest = guaranteedDigest(t, "sha256:"+strings.Repeat(string(rune('a'+i)), 64))
		bindings = append(bindings, binding)
	}
	resolutions, err := Resolve(bindings)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	for i, resolution := range resolutions {
		if string(resolution.Key.ContainerName) != names[i] {
			t.Fatalf("position %d: key = %q, want %q", i, resolution.Key.ContainerName, names[i])
		}
	}
}

func TestResolveEmptyInput(t *testing.T) {
	for name, bindings := range map[string][]ImageBinding{"nil": nil, "empty": {}} {
		resolutions, err := Resolve(bindings)
		if err != nil {
			t.Fatalf("%s: unexpected error: %v", name, err)
		}
		if resolutions == nil || len(resolutions) != 0 {
			t.Fatalf("%s: resolutions = %#v, want a non-nil empty slice", name, resolutions)
		}
	}
}

func TestResolveInvalidKeyStaysNonAffirmative(t *testing.T) {
	binding := syntheticBinding("api")
	binding.Key.ContainerClass = "sidecar"
	binding.GuaranteedDigest = guaranteedDigest(t, "sha256:"+strings.Repeat("11", 32))

	resolutions, err := Resolve([]ImageBinding{binding})
	if err == nil {
		t.Fatal("invalid container class accepted, want rejection")
	}
	if len(resolutions) != 1 || resolutions[0].State == ResolutionResolved {
		t.Fatalf("invalid key resolved: %+v", resolutions)
	}
}

func TestResolveSingleKeyMatchesResolveOne(t *testing.T) {
	binding := syntheticBinding("api")
	binding.RequestedImage = requestedImage("registry.example/app:release")
	binding.RawImageID = rawImageID("registry.example/app@sha256:" + strings.Repeat("33", 32))

	single, err := ResolveOne(binding)
	if err != nil {
		t.Fatalf("ResolveOne: unexpected error: %v", err)
	}
	resolutions, err := Resolve([]ImageBinding{binding})
	if err != nil {
		t.Fatalf("Resolve: unexpected error: %v", err)
	}
	if len(resolutions) != 1 {
		t.Fatalf("resolutions = %d, want 1", len(resolutions))
	}
	if !reflect.DeepEqual(single, resolutions[0]) {
		t.Fatalf("single-key Resolve = %+v, want ResolveOne result %+v", resolutions[0], single)
	}
}
