package identity

import (
	"reflect"
	"strings"
	"testing"

	contract "github.com/d4rpell/Ariadne/pkg/evidence"
)

func key(name string) ContainerKey {
	return ContainerKey{
		SubjectUID:     contract.UID("uid-0001"),
		ContainerClass: contract.ContainerRegular,
		ContainerName:  contract.ContainerName(name),
	}
}

func requestedImage(value string) *contract.RequestedImage {
	image := contract.RequestedImage(value)
	return &image
}

func rawImageID(value string) *contract.RawImageID {
	image := contract.RawImageID(value)
	return &image
}

func guaranteedDigest(t *testing.T, value string) *contract.NormalizedDigest {
	t.Helper()
	digest, err := NewGuaranteedDigest(value)
	if err != nil {
		t.Fatalf("NewGuaranteedDigest(%q): unexpected error: %v", value, err)
	}
	return &digest
}

func syntheticBinding(name string) ImageBinding {
	return ImageBinding{
		Key:       key(name),
		InputKind: InputSynthetic,
		Platform:  contract.PlatformUnknown,
	}
}

func TestNewGuaranteedDigestAcceptsOnlyExactLowercaseSha256(t *testing.T) {
	valid := "sha256:" + strings.Repeat("0a1b2c3d", 8)
	digest, err := NewGuaranteedDigest(valid)
	if err != nil {
		t.Fatalf("NewGuaranteedDigest(%q): unexpected error: %v", valid, err)
	}
	if string(digest) != valid {
		t.Fatalf("digest = %q, want %q", digest, valid)
	}

	rejected := map[string]string{
		"empty":            "",
		"prefix only":      "sha256:",
		"uppercase prefix": "SHA256:" + strings.Repeat("ab", 32),
		"uppercase hex":    "sha256:" + strings.Repeat("AB", 32),
		"mixed case hex":   "sha256:" + strings.Repeat("aB", 32),
		"sha512":           "sha512:" + strings.Repeat("ab", 64),
		"too short":        "sha256:" + strings.Repeat("ab", 31),
		"too long":         "sha256:" + strings.Repeat("ab", 32) + "c",
		"leading space":    " sha256:" + strings.Repeat("ab", 32),
		"trailing space":   "sha256:" + strings.Repeat("ab", 32) + " ",
		"leading newline":  "\nsha256:" + strings.Repeat("ab", 32),
		"non hex digit":    "sha256:" + strings.Repeat("ab", 31) + "gz",
		"tag shaped":       "registry.example/app:release",
		"digest shaped":    "registry.example/app@sha256:" + strings.Repeat("ab", 32),
	}
	for name, value := range rejected {
		if _, err := NewGuaranteedDigest(value); err == nil {
			t.Errorf("NewGuaranteedDigest(%s): accepted %q, want rejection", name, value)
		}
	}
}

func TestResolveOneRefusesMalformedKey(t *testing.T) {
	cases := map[string]ContainerKey{
		"empty uid":         {ContainerClass: contract.ContainerRegular, ContainerName: "api"},
		"empty container":   {SubjectUID: "uid-0001", ContainerClass: contract.ContainerRegular},
		"uid whitespace":    {SubjectUID: " uid-0001", ContainerClass: contract.ContainerRegular, ContainerName: "api"},
		"name whitespace":   {SubjectUID: "uid-0001", ContainerClass: contract.ContainerRegular, ContainerName: "api "},
		"name only spaces":  {SubjectUID: "uid-0001", ContainerClass: contract.ContainerRegular, ContainerName: "   "},
		"empty class":       {SubjectUID: "uid-0001", ContainerName: "api"},
		"unknown class":     {SubjectUID: "uid-0001", ContainerClass: "sidecar", ContainerName: "api"},
		"invalid utf8 name": {SubjectUID: "uid-0001", ContainerClass: contract.ContainerRegular, ContainerName: "\xff"},
	}
	for name, invalid := range cases {
		binding := syntheticBinding("api")
		binding.Key = invalid
		resolution, err := ResolveOne(binding)
		if err == nil {
			t.Errorf("%s: expected error, got none", name)
		}
		if resolution.State != ResolutionUnknown {
			t.Errorf("%s: state = %q, want %q", name, resolution.State, ResolutionUnknown)
		}
		if resolution.Binding != nil {
			t.Errorf("%s: refused input still returned a binding", name)
		}
		if resolution.Key != invalid {
			t.Errorf("%s: key not echoed for diagnostics", name)
		}
	}
}

func TestResolveOneRefusesUnsupportedInputKind(t *testing.T) {
	cases := map[string]InputKind{
		"empty":   "",
		"unknown": "scanner_csv",
	}
	for name, kind := range cases {
		binding := syntheticBinding("api")
		binding.InputKind = kind
		binding.GuaranteedDigest = guaranteedDigest(t, "sha256:"+strings.Repeat("ab", 32))
		resolution, err := ResolveOne(binding)
		if err == nil {
			t.Errorf("%s: expected fail-closed error, got none", name)
		}
		if resolution.State == ResolutionResolved {
			t.Errorf("%s: unsupported kind resolved affirmatively", name)
		}
	}
	if _, err := ResolveOne(syntheticBinding("api")); err != nil {
		t.Fatalf("synthetic kind rejected: %v", err)
	}
}

func TestResolveOneRefusesUndeclaredPlatform(t *testing.T) {
	binding := syntheticBinding("api")
	binding.Platform = ""
	if _, err := ResolveOne(binding); err == nil {
		t.Fatal("undeclared platform accepted, want rejection")
	}
	if _, err := ResolveOne(syntheticBinding("api")); err != nil {
		t.Fatalf("platform unknown rejected: %v", err)
	}
}

func TestResolveOneAcceptsKnownPlatformWithCarrier(t *testing.T) {
	binding := syntheticBinding("api")
	binding.GuaranteedDigest = guaranteedDigest(t, "sha256:"+strings.Repeat("ab", 32))
	binding.Platform = contract.PlatformKnown
	binding.PlatformOS = "linux"
	binding.PlatformArchitecture = "amd64"

	resolution, err := ResolveOne(binding)
	if err != nil {
		t.Fatalf("observed platform rejected: %v", err)
	}
	if resolution.State != ResolutionResolved {
		t.Fatalf("state = %q, want %q", resolution.State, ResolutionResolved)
	}
	if resolution.Binding.PlatformOS != "linux" || resolution.Binding.PlatformArchitecture != "amd64" {
		t.Fatalf("observed platform not preserved: %+v", resolution.Binding)
	}
	if resolution.Binding.Platform != contract.PlatformKnown {
		t.Fatalf("status = %q, want %q", resolution.Binding.Platform, contract.PlatformKnown)
	}
}

func TestResolveOneRefusesInvalidPlatformCarrier(t *testing.T) {
	cases := map[string]func(ImageBinding) ImageBinding{
		"known without carrier": func(binding ImageBinding) ImageBinding {
			return binding
		},
		"known with os only": func(binding ImageBinding) ImageBinding {
			binding.PlatformOS = "linux"
			return binding
		},
		"known with architecture only": func(binding ImageBinding) ImageBinding {
			binding.PlatformArchitecture = "amd64"
			return binding
		},
		"known with blank os": func(binding ImageBinding) ImageBinding {
			binding.PlatformOS = "   "
			binding.PlatformArchitecture = "amd64"
			return binding
		},
		"known with os surrounding space": func(binding ImageBinding) ImageBinding {
			binding.PlatformOS = " linux"
			binding.PlatformArchitecture = "amd64"
			return binding
		},
		"known with non ascii architecture": func(binding ImageBinding) ImageBinding {
			binding.PlatformOS = "linux"
			binding.PlatformArchitecture = "amd64\xff"
			return binding
		},
		"known without digest": func(binding ImageBinding) ImageBinding {
			binding.GuaranteedDigest = nil
			binding.PlatformOS = "linux"
			binding.PlatformArchitecture = "amd64"
			return binding
		},
	}
	for name, mutate := range cases {
		binding := syntheticBinding("api")
		binding.GuaranteedDigest = guaranteedDigest(t, "sha256:"+strings.Repeat("ab", 32))
		binding.Platform = contract.PlatformKnown
		binding = mutate(binding)

		resolution, err := ResolveOne(binding)
		if err == nil {
			t.Errorf("%s: accepted, want rejection", name)
		}
		if resolution.State == ResolutionResolved {
			t.Errorf("%s: resolved affirmatively", name)
		}
		if resolution.Binding != nil {
			t.Errorf("%s: refused input still returned a binding", name)
		}
	}
}

func TestResolveOneRefusesUnobservedPlatformCarrier(t *testing.T) {
	cases := map[string]func(ImageBinding) ImageBinding{
		"unknown with observed os": func(binding ImageBinding) ImageBinding {
			binding.PlatformOS = "linux"
			return binding
		},
		"unknown with observed architecture": func(binding ImageBinding) ImageBinding {
			binding.PlatformArchitecture = "amd64"
			return binding
		},
	}
	for name, mutate := range cases {
		binding := mutate(syntheticBinding("api"))
		binding.RawImageID = rawImageID("registry.example/app@sha256:" + strings.Repeat("ab", 32))
		resolution, err := ResolveOne(binding)
		if err == nil {
			t.Errorf("%s: accepted, want rejection", name)
		}
		if resolution.State == ResolutionResolved || resolution.Binding != nil {
			t.Errorf("%s: unobserved platform carrier resolved: %+v", name, resolution)
		}
	}
}

// TestResolveOneNeverInfersPlatform pins invariant I-5: with no observation the
// carrier stays empty, so nothing is taken from the host, the build or the
// architecture of the running process.
func TestResolveOneNeverInfersPlatform(t *testing.T) {
	binding := syntheticBinding("api")
	binding.RawImageID = rawImageID("registry.example/app@sha256:" + strings.Repeat("ab", 32))
	resolution, err := ResolveOne(binding)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resolution.Binding.Platform != contract.PlatformUnknown {
		t.Fatalf("status = %q, want %q", resolution.Binding.Platform, contract.PlatformUnknown)
	}
	if resolution.Binding.PlatformOS != "" || resolution.Binding.PlatformArchitecture != "" {
		t.Fatalf("platform fabricated: os=%q arch=%q", resolution.Binding.PlatformOS, resolution.Binding.PlatformArchitecture)
	}
}

func TestResolveOneRefusesUnprovenImageFields(t *testing.T) {
	unproven := contract.NormalizedDigest("sha256:" + strings.Repeat("AB", 32))
	cases := map[string]ImageBinding{
		"digest set around the constructor": func() ImageBinding {
			binding := syntheticBinding("api")
			binding.GuaranteedDigest = &unproven
			return binding
		}(),
		"empty raw image id": func() ImageBinding {
			binding := syntheticBinding("api")
			binding.RawImageID = rawImageID("")
			return binding
		}(),
		"raw image id with surrounding space": func() ImageBinding {
			binding := syntheticBinding("api")
			binding.RawImageID = rawImageID(" reg.example/app@sha256:" + strings.Repeat("ab", 32))
			return binding
		}(),
		"blank requested image": func() ImageBinding {
			binding := syntheticBinding("api")
			binding.RequestedImage = requestedImage("   ")
			return binding
		}(),
	}
	for name, binding := range cases {
		resolution, err := ResolveOne(binding)
		if err == nil {
			t.Errorf("%s: accepted, want rejection", name)
		}
		if resolution.State == ResolutionResolved {
			t.Errorf("%s: resolved affirmatively", name)
		}
		if resolution.Binding != nil {
			t.Errorf("%s: refused input still returned a binding", name)
		}
	}
}

func TestResolveOneKeepsRequestedAndObservedSeparate(t *testing.T) {
	requested := "registry.example/app:release"
	observed := "registry.example/app@sha256:" + strings.Repeat("ab", 32)
	binding := syntheticBinding("api")
	binding.RequestedImage = requestedImage(requested)
	binding.RawImageID = rawImageID(observed)

	resolution, err := ResolveOne(binding)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resolution.State != ResolutionResolved {
		t.Fatalf("state = %q, want %q", resolution.State, ResolutionResolved)
	}
	if resolution.Binding.RequestedImage == nil || *resolution.Binding.RequestedImage != contract.RequestedImage(requested) {
		t.Fatal("requested image lost while observing the image ID")
	}
	if resolution.Binding.RawImageID == nil || *resolution.Binding.RawImageID != contract.RawImageID(observed) {
		t.Fatal("observed image ID lost while carrying the requested image")
	}
	if resolution.Binding.GuaranteedDigest != nil {
		t.Fatal("a digest was derived from the requested tag or the observed image ID")
	}
}

func TestResolveOneAffirmativeOnlyWithDigestOrRaw(t *testing.T) {
	tagOnly := syntheticBinding("api")
	tagOnly.RequestedImage = requestedImage("registry.example/app:release")
	resolution, err := ResolveOne(tagOnly)
	if err != nil {
		t.Fatalf("tag only: unexpected error: %v", err)
	}
	if resolution.State != ResolutionUnresolved {
		t.Fatalf("tag only: state = %q, want %q", resolution.State, ResolutionUnresolved)
	}
	if resolution.Binding == nil || resolution.Binding.GuaranteedDigest != nil {
		t.Fatal("tag only: a digest was fabricated or the binding was dropped")
	}

	empty := syntheticBinding("api")
	if resolution, err = ResolveOne(empty); err != nil {
		t.Fatalf("empty image: unexpected error: %v", err)
	}
	if resolution.State != ResolutionUnresolved || resolution.Binding == nil {
		t.Fatalf("empty image: state = %q, want %q with binding kept", resolution.State, ResolutionUnresolved)
	}

	rawOnly := syntheticBinding("api")
	rawOnly.RawImageID = rawImageID("registry.example/app@sha256:" + strings.Repeat("cd", 32))
	if resolution, err = ResolveOne(rawOnly); err != nil {
		t.Fatalf("raw only: unexpected error: %v", err)
	}
	if resolution.State != ResolutionResolved {
		t.Fatalf("raw only: state = %q, want %q", resolution.State, ResolutionResolved)
	}
	if resolution.Binding.GuaranteedDigest != nil {
		t.Fatal("raw only: a guaranteed digest was inferred from the raw image ID")
	}

	digestOnly := syntheticBinding("api")
	digestOnly.GuaranteedDigest = guaranteedDigest(t, "sha256:"+strings.Repeat("ef", 32))
	if resolution, err = ResolveOne(digestOnly); err != nil {
		t.Fatalf("digest only: unexpected error: %v", err)
	}
	if resolution.State != ResolutionResolved {
		t.Fatalf("digest only: state = %q, want %q", resolution.State, ResolutionResolved)
	}
	if resolution.BindingCount != 1 || resolution.ConflictCode != "" {
		t.Fatalf("single binding reported as conflict: %+v", resolution)
	}
}

func TestResolveOneFabricatesNothing(t *testing.T) {
	binding := syntheticBinding("api")
	binding.RawImageID = rawImageID("registry.example/app@sha256:" + strings.Repeat("ab", 32))
	first, err := ResolveOne(binding)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if first.Binding.ObservedAt != nil {
		t.Fatal("timestamp fabricated for a binding without observation time")
	}
	if first.AdvisoryNotes != nil {
		t.Fatal("advisory notes fabricated without a ratified vocabulary")
	}
	second, err := ResolveOne(binding)
	if err != nil {
		t.Fatalf("second call: unexpected error: %v", err)
	}
	if !reflect.DeepEqual(first, second) {
		t.Fatal("resolution is not deterministic across identical calls")
	}
}

// TestIndexDigestIsKeptAsRawWithUnknownPlatform pins the ADR-0010 rule: a digest
// that is not proven to be a per-platform manifest never becomes a guaranteed
// digest. It is preserved as the observed raw image ID, with no digest and no
// platform claim, so no conclusion is transferred across platforms.
func TestIndexDigestIsKeptAsRawWithUnknownPlatform(t *testing.T) {
	indexDigest := "registry.example/app@sha256:" + strings.Repeat("ab", 32)
	binding := syntheticBinding("api")
	binding.RawImageID = rawImageID(indexDigest)

	resolution, err := ResolveOne(binding)
	if err != nil {
		t.Fatalf("observed raw image ID rejected: %v", err)
	}
	if resolution.State != ResolutionResolved {
		t.Fatalf("state = %q, want %q: the observation is preserved", resolution.State, ResolutionResolved)
	}
	if resolution.Binding.RawImageID == nil || *resolution.Binding.RawImageID != contract.RawImageID(indexDigest) {
		t.Fatal("observed raw image ID was not preserved verbatim")
	}
	if resolution.Binding.GuaranteedDigest != nil {
		t.Fatal("an index digest was promoted to a guaranteed digest")
	}
	if resolution.Binding.Platform != contract.PlatformUnknown || resolution.Binding.PlatformOS != "" || resolution.Binding.PlatformArchitecture != "" {
		t.Fatalf("platform claimed from a digest: %+v", resolution.Binding)
	}
}

// TestResolveOneDetachesObservationPointers pins the no-alias rule for the
// resolution: the caller cannot rewrite what a resolution asserts, and the
// resolution cannot rewrite what the caller still holds.
func TestResolveOneDetachesObservationPointers(t *testing.T) {
	binding := syntheticBinding("api")
	binding.RequestedImage = requestedImage("registry.example/app:release")
	binding.RawImageID = rawImageID("registry.example/app@sha256:" + strings.Repeat("ab", 32))
	binding.GuaranteedDigest = guaranteedDigest(t, "sha256:"+strings.Repeat("cd", 32))

	resolution, err := ResolveOne(binding)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resolution.Binding.RequestedImage == binding.RequestedImage ||
		resolution.Binding.RawImageID == binding.RawImageID ||
		resolution.Binding.GuaranteedDigest == binding.GuaranteedDigest {
		t.Fatal("resolution aliases the caller's observation")
	}

	keptRaw := *resolution.Binding.RawImageID
	keptDigest := *resolution.Binding.GuaranteedDigest
	*binding.RawImageID = contract.RawImageID("mutated")
	*binding.GuaranteedDigest = contract.NormalizedDigest("mutated")
	if *resolution.Binding.RawImageID != keptRaw || *resolution.Binding.GuaranteedDigest != keptDigest {
		t.Fatal("resolution changed after the caller rewrote its observation")
	}
}

// TestContainerKeyHasNoNamespaceOrNameFields pins invariant I-1 structurally:
// the key cannot express namespace/name, so no future change can start grouping
// by them without deleting a field that this test names explicitly.
func TestContainerKeyHasNoNamespaceOrNameFields(t *testing.T) {
	fields := reflect.TypeOf(ContainerKey{})
	for _, forbidden := range []string{"Namespace", "Name", "ClusterAlias", "Kind"} {
		if _, found := fields.FieldByName(forbidden); found {
			t.Errorf("ContainerKey exposes %q: namespace/name is context, never identity", forbidden)
		}
	}
	bindingFields := reflect.TypeOf(ImageBinding{})
	for _, forbidden := range []string{"Namespace", "Name"} {
		if _, found := bindingFields.FieldByName(forbidden); found {
			t.Errorf("ImageBinding exposes %q: only ContainerKey carries identity", forbidden)
		}
	}
}
