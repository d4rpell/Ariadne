package identity

import (
	"testing"

	contract "github.com/d4rpell/Ariadne/pkg/evidence"
)

// TestA108IdentityMatrix covers the identity invariants of I-03: explicit
// uid+class+name keys, refused fabrications, preserved separation between
// requested, raw and proven digest, and platform that is never inferred.
func TestA108IdentityMatrix(t *testing.T) {
	t.Run("requested raw and digest stay separate fields", func(t *testing.T) {
		binding := syntheticBinding("api")
		binding.RequestedImage = requestedImage("registry.example/app:release")
		binding.RawImageID = rawImageID("registry.example/app@sha256:" + digestBody("a"))
		binding.GuaranteedDigest = guaranteedDigest(t, "sha256:"+digestBody("a"))

		resolution, err := ResolveOne(binding)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if resolution.State != ResolutionResolved {
			t.Fatalf("state = %q, want resolved", resolution.State)
		}
		kept := resolution.Binding
		if kept == nil {
			t.Fatal("a resolved observation must keep its binding")
		}
		if string(*kept.RequestedImage) != "registry.example/app:release" {
			t.Fatalf("requested image = %q", *kept.RequestedImage)
		}
		if string(*kept.RawImageID) != "registry.example/app@sha256:"+digestBody("a") {
			t.Fatalf("raw image id = %q", *kept.RawImageID)
		}
		if string(*kept.GuaranteedDigest) != "sha256:"+digestBody("a") {
			t.Fatalf("digest = %q", *kept.GuaranteedDigest)
		}
		if kept.RequestedImage == binding.RequestedImage {
			t.Fatal("the resolution must not alias the caller's pointers")
		}
	})

	t.Run("a requested tag alone is never content identity", func(t *testing.T) {
		binding := syntheticBinding("api")
		binding.RequestedImage = requestedImage("registry.example/app:latest")
		resolution, err := ResolveOne(binding)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if resolution.State != ResolutionUnresolved {
			t.Fatalf("state = %q, want unresolved for a tag without digest", resolution.State)
		}
	})

	t.Run("raw image id alone is affirmative content identity", func(t *testing.T) {
		binding := syntheticBinding("api")
		binding.RawImageID = rawImageID("registry.example/app@sha256:" + digestBody("b"))
		resolution, err := ResolveOne(binding)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if resolution.State != ResolutionResolved {
			t.Fatalf("state = %q, want resolved for an observed raw id", resolution.State)
		}
	})

	t.Run("an index digest stays raw and never becomes normalized_digest", func(t *testing.T) {
		binding := syntheticBinding("api")
		binding.RawImageID = rawImageID("registry.example/app@sha256:" + digestBody("c"))
		resolution, err := ResolveOne(binding)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if resolution.State != ResolutionResolved {
			t.Fatalf("state = %q, want resolved by raw observation", resolution.State)
		}
		if resolution.Binding.GuaranteedDigest != nil {
			t.Fatalf("an index digest was promoted: %q", *resolution.Binding.GuaranteedDigest)
		}
		if resolution.Binding.Platform != contract.PlatformUnknown {
			t.Fatalf("platform = %q, want unknown", resolution.Binding.Platform)
		}
	})

	t.Run("key uses uid class and name", func(t *testing.T) {
		first := syntheticBinding("api")
		second := syntheticBinding("api")
		second.Key.SubjectUID = contract.UID("uid-0002")
		third := syntheticBinding("api")
		third.Key.ContainerClass = contract.ContainerInit

		firstResolution, err := ResolveOne(first)
		if err != nil {
			t.Fatalf("first: %v", err)
		}
		secondResolution, err := ResolveOne(second)
		if err != nil {
			t.Fatalf("second: %v", err)
		}
		thirdResolution, err := ResolveOne(third)
		if err != nil {
			t.Fatalf("third: %v", err)
		}
		if firstResolution.Key == secondResolution.Key {
			t.Fatal("a different UID must change the key")
		}
		if firstResolution.Key == thirdResolution.Key {
			t.Fatal("a different container class must change the key")
		}
	})

	t.Run("invalid keys keep a non-affirmative state", func(t *testing.T) {
		cases := []struct {
			name string
			key  ContainerKey
		}{
			{"empty uid", ContainerKey{ContainerClass: contract.ContainerRegular, ContainerName: "api"}},
			{"empty name", ContainerKey{SubjectUID: contract.UID("uid-0001"), ContainerClass: contract.ContainerRegular}},
			{"surrounding space in name", ContainerKey{SubjectUID: contract.UID("uid-0001"), ContainerClass: contract.ContainerRegular, ContainerName: " api"}},
			{"invented class", ContainerKey{SubjectUID: contract.UID("uid-0001"), ContainerClass: contract.ContainerClass("sidecar"), ContainerName: "api"}},
		}
		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				binding := syntheticBinding("api")
				binding.Key = tc.key
				binding.RawImageID = rawImageID("registry.example/app@sha256:" + digestBody("d"))
				resolution, err := ResolveOne(binding)
				if err == nil {
					t.Fatalf("expected a refused key, got %+v", resolution)
				}
				if resolution.State == ResolutionResolved {
					t.Fatalf("a refused key must not be resolved: %+v", resolution)
				}
				if resolution.Binding != nil {
					t.Fatal("a refused key must not carry a binding")
				}
			})
		}
	})

	t.Run("digest format is revalidated and never repaired", func(t *testing.T) {
		cases := []string{
			"sha256:" + repeatHex("A"), // uppercase
			"sha256:" + repeatHex("a"), // 64 lowercase is valid, see below
			"sha256:" + "abc",          // short
			"SHA256:" + repeatHex("a"), // wrong prefix case
			repeatHex("a"),             // no prefix
			"sha256:" + repeatHex("g"), // non-hex
		}
		for _, tc := range cases {
			t.Run(tc, func(t *testing.T) {
				binding := syntheticBinding("api")
				if tc == "sha256:"+repeatHex("a") {
					binding.GuaranteedDigest = guaranteedDigest(t, tc)
					if _, err := ResolveOne(binding); err != nil {
						t.Fatalf("the exact lowercase form must be accepted: %v", err)
					}
					return
				}
				value := contract.NormalizedDigest(tc)
				binding.GuaranteedDigest = &value
				resolution, err := ResolveOne(binding)
				if err == nil {
					t.Fatalf("a malformed digest was accepted: %+v", resolution)
				}
				if resolution.Binding != nil {
					t.Fatal("a refused binding must not keep a binding")
				}
			})
		}
	})

	t.Run("platform is never inferred", func(t *testing.T) {
		binding := syntheticBinding("api")
		binding.RawImageID = rawImageID("registry.example/app@sha256:" + digestBody("e"))
		// PlatformUnknown with carriers is refused instead of being silently dropped.
		binding.PlatformOS = "linux"
		if _, err := ResolveOne(binding); err == nil {
			t.Fatal("an unobserved platform carrying an observed carrier must be refused")
		}
		binding.PlatformOS = ""
		binding.PlatformArchitecture = ""
		if _, err := ResolveOne(binding); err != nil {
			t.Fatalf("an unknown platform without carrier is the conservative default: %v", err)
		}

		// A known platform requires the carrier and a proven digest.
		known := syntheticBinding("api")
		known.Platform = contract.PlatformKnown
		known.PlatformOS = "linux"
		known.PlatformArchitecture = "amd64"
		if _, err := ResolveOne(known); err == nil {
			t.Fatal("a known platform without a guaranteed digest must be refused")
		}
		known.GuaranteedDigest = guaranteedDigest(t, "sha256:"+digestBody("f"))
		resolution, err := ResolveOne(known)
		if err != nil {
			t.Fatalf("known platform with carrier and digest: %v", err)
		}
		if resolution.Binding.PlatformOS != "linux" || resolution.Binding.PlatformArchitecture != "amd64" {
			t.Fatalf("carrier = %q/%q", resolution.Binding.PlatformOS, resolution.Binding.PlatformArchitecture)
		}
	})

	t.Run("input kind is closed", func(t *testing.T) {
		binding := syntheticBinding("api")
		binding.InputKind = InputKind("invented")
		if _, err := ResolveOne(binding); err == nil {
			t.Fatal("an unsupported input kind must be refused fail-closed")
		}
	})
}

func repeatHex(letter string) string {
	out := make([]byte, 64)
	for i := range out {
		out[i] = letter[0]
	}
	return string(out)
}

func digestBody(letter string) string {
	return repeatHex(letter)
}

// TestA108IdentityResolutionIsDetached pins the no-aliasing property: mutating
// the binding a caller still holds must not change what a resolution asserts.
func TestA108IdentityResolutionIsDetached(t *testing.T) {
	binding := syntheticBinding("api")
	binding.RequestedImage = requestedImage("registry.example/app:release")
	binding.RawImageID = rawImageID("registry.example/app@sha256:" + digestBody("a"))

	resolution, err := ResolveOne(binding)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	alias := *binding.RequestedImage
	*binding.RequestedImage = alias + "-rewritten"
	*binding.RawImageID = contract.RawImageID("rewritten")
	if got := string(*resolution.Binding.RequestedImage); got != "registry.example/app:release" {
		t.Fatalf("resolution followed a caller mutation: %q", got)
	}
	if got := string(*resolution.Binding.RawImageID); got != "registry.example/app@sha256:"+digestBody("a") {
		t.Fatalf("resolution followed a caller mutation of the raw id: %q", got)
	}
}
