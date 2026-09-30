package identity

import (
	"strings"
	"testing"

	contract "github.com/d4rpell/Ariadne/pkg/evidence"
)

// ADR-0025 A.11.1 enables InputContainerObservation for the bindings of the
// sanitized PodList profile. Admitting the label must not authenticate the
// origin, must not promote a digest-shaped raw image ID, and must leave the
// synthetic path unchanged.

func a201ObservationKey(name string) ContainerKey {
	return ContainerKey{
		SubjectUID:     contract.UID("uid-a201-0001"),
		ContainerClass: contract.ContainerRegular,
		ContainerName:  contract.ContainerName(name),
	}
}

func a201ObservationBinding(name string) ImageBinding {
	return ImageBinding{
		Key:       a201ObservationKey(name),
		InputKind: InputContainerObservation,
		Platform:  contract.PlatformUnknown,
	}
}

func a201ObservationRaw(value string) *contract.RawImageID {
	raw := contract.RawImageID(value)
	return &raw
}

func a201ObservationRequested(value string) *contract.RequestedImage {
	requested := contract.RequestedImage(value)
	return &requested
}

func a201ObservationGuaranteed(t *testing.T, value string) *contract.NormalizedDigest {
	t.Helper()
	digest, err := NewGuaranteedDigest(value)
	if err != nil {
		t.Fatalf("NewGuaranteedDigest(%q): unexpected error: %v", value, err)
	}
	return &digest
}

func TestA201ObservationInputKind(t *testing.T) {
	t.Run("container observation with raw image id resolves", func(t *testing.T) {
		binding := a201ObservationBinding("api")
		binding.RawImageID = a201ObservationRaw("sha256:" + strings.Repeat("ab", 32))
		resolution, err := ResolveOne(binding)
		if err != nil {
			t.Fatalf("ResolveOne: unexpected error: %v", err)
		}
		if resolution.State != ResolutionResolved {
			t.Fatalf("state = %q, want %q", resolution.State, ResolutionResolved)
		}
		if resolution.Binding == nil {
			t.Fatal("a resolved observation returned no binding")
		}
	})

	t.Run("requested image alone stays unresolved", func(t *testing.T) {
		binding := a201ObservationBinding("api")
		binding.RequestedImage = a201ObservationRequested("registry.example/app:release")
		resolution, err := ResolveOne(binding)
		if err != nil {
			t.Fatalf("ResolveOne: unexpected error: %v", err)
		}
		if resolution.State != ResolutionUnresolved {
			t.Fatalf("state = %q, want %q", resolution.State, ResolutionUnresolved)
		}
	})

	t.Run("unknown input kind fails closed", func(t *testing.T) {
		binding := a201ObservationBinding("api")
		binding.InputKind = InputKind("scanner_csv")
		binding.RawImageID = a201ObservationRaw("sha256:" + strings.Repeat("ab", 32))
		resolution, err := ResolveOne(binding)
		if err == nil {
			t.Fatal("unknown input kind accepted, want fail-closed rejection")
		}
		if resolution.State == ResolutionResolved {
			t.Fatal("unknown input kind resolved affirmatively")
		}
	})

	t.Run("synthetic kind is unchanged", func(t *testing.T) {
		plain := a201ObservationBinding("api")
		plain.InputKind = InputSynthetic
		resolution, err := ResolveOne(plain)
		if err != nil {
			t.Fatalf("synthetic without evidence: unexpected error: %v", err)
		}
		if resolution.State != ResolutionUnresolved {
			t.Fatalf("synthetic without evidence: state = %q, want %q", resolution.State, ResolutionUnresolved)
		}

		withDigest := plain
		withDigest.GuaranteedDigest = a201ObservationGuaranteed(t, "sha256:"+strings.Repeat("cd", 32))
		resolution, err = ResolveOne(withDigest)
		if err != nil {
			t.Fatalf("synthetic with digest: unexpected error: %v", err)
		}
		if resolution.State != ResolutionResolved {
			t.Fatalf("synthetic with digest: state = %q, want %q", resolution.State, ResolutionResolved)
		}

		withRaw := plain
		withRaw.RawImageID = a201ObservationRaw("sha256:" + strings.Repeat("ef", 32))
		resolution, err = ResolveOne(withRaw)
		if err != nil {
			t.Fatalf("synthetic with raw image id: unexpected error: %v", err)
		}
		if resolution.State != ResolutionResolved {
			t.Fatalf("synthetic with raw image id: state = %q, want %q", resolution.State, ResolutionResolved)
		}
	})

	t.Run("digest shaped raw image id is not promoted", func(t *testing.T) {
		raw := "sha256:" + strings.Repeat("ab", 32)
		binding := a201ObservationBinding("api")
		binding.RawImageID = a201ObservationRaw(raw)
		resolution, err := ResolveOne(binding)
		if err != nil {
			t.Fatalf("ResolveOne: unexpected error: %v", err)
		}
		if resolution.State != ResolutionResolved {
			t.Fatalf("state = %q, want %q", resolution.State, ResolutionResolved)
		}
		if binding.GuaranteedDigest != nil {
			t.Fatalf("ResolveOne promoted the raw value %q on the caller binding", raw)
		}
		if resolution.Binding == nil {
			t.Fatal("a resolved observation returned no binding")
		}
		if resolution.Binding.GuaranteedDigest != nil {
			t.Fatalf("raw value %q was promoted to a guaranteed digest", raw)
		}
		if resolution.Binding.Platform != contract.PlatformUnknown {
			t.Fatalf("platform = %q, want %q", resolution.Binding.Platform, contract.PlatformUnknown)
		}
		if resolution.Binding.PlatformOS != "" || resolution.Binding.PlatformArchitecture != "" {
			t.Fatalf("platform carriers = %q/%q, want both empty", resolution.Binding.PlatformOS, resolution.Binding.PlatformArchitecture)
		}
	})

	t.Run("unknown platform with observed os is refused", func(t *testing.T) {
		binding := a201ObservationBinding("api")
		binding.RawImageID = a201ObservationRaw("sha256:" + strings.Repeat("ab", 32))
		binding.PlatformOS = "linux"
		if _, err := ResolveOne(binding); err == nil {
			t.Fatal("unknown platform carrying an observed os was accepted, want rejection")
		}
	})
}
