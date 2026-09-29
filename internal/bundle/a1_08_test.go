package bundle

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	canonical "github.com/d4rpell/Ariadne/internal/evidence"
	"github.com/d4rpell/Ariadne/internal/identity"
	"github.com/d4rpell/Ariadne/internal/normalize"
	contract "github.com/d4rpell/Ariadne/pkg/evidence"
)

// a108AlternateBinding is a complete observation whose uid differs from the
// test subject, used to exercise the other_subject partition.
func a108AlternateBinding(t *testing.T, index int, uid string) normalize.Binding {
	t.Helper()
	digest, err := identity.NewGuaranteedDigest(testDigest("b"))
	if err != nil {
		t.Fatalf("guaranteed digest: %v", err)
	}
	raw := contract.RawImageID("registry.example/payments/api@" + testDigest("b"))
	key := identity.ContainerKey{
		SubjectUID:     contract.UID(uid),
		ContainerClass: contract.ContainerRegular,
		ContainerName:  contract.ContainerName("api"),
	}
	image := identity.ImageBinding{
		Key:                  key,
		InputKind:            identity.InputSynthetic,
		SourceName:           "sanitized-pods.json",
		SourceHash:           contract.SourceHash(testDigest("c")),
		Locator:              contract.SourceLocator("items[3].status.containerStatuses[0].imageID"),
		RawImageID:           &raw,
		GuaranteedDigest:     &digest,
		Platform:             contract.PlatformKnown,
		PlatformOS:           "linux",
		PlatformArchitecture: "amd64",
		ObservedAt:           testTimestamp(t, "2026-09-26T09:00:00Z"),
	}
	return normalize.Binding{FindingIndex: index, ContainerKey: key, Image: image}
}

// TestA108BundlePartition covers B03 and I-07: unbound and other_subject are a
// partition and never change completeness; a projection defect of the subject
// itself does change it, visibly.
func TestA108BundlePartition(t *testing.T) {
	t.Run("partition keeps completeness and adds no messages", func(t *testing.T) {
		csv := csvFromRows(
			csvRowFor("CVE-2024-1234", "payments/api", "release"),
			csvRowFor("CVE-2024-5678", "payments/api", "release"),
			csvRowFor("CVE-2024-9999", "payments/api", "release"),
		)
		input := testInput(t, csv, []normalize.Binding{
			testBinding(t, 0, contract.UID("pod-uid-1"), contract.ContainerRegular, contract.ContainerName("api")),
			a108AlternateBinding(t, 1, "pod-uid-2"),
			testBinding(t, 2, contract.UID("pod-uid-1"), contract.ContainerRegular, contract.ContainerName("worker")),
		})
		bundle, diagnostics := buildForTest(t, input)
		if bundle.Provenance.Completeness != contract.CompletenessComplete {
			t.Fatalf("completeness = %q, want complete: a partition is not a defect", bundle.Provenance.Completeness)
		}
		if len(bundle.Provenance.Errors) != 0 {
			t.Fatalf("partition produced errors: %+v", bundle.Provenance.Errors)
		}
		if len(diagnostics.Omissions) != 1 {
			t.Fatalf("omissions = %+v, want exactly the foreign subject", diagnostics.Omissions)
		}
		if diagnostics.Omissions[0].Reason != OmissionOtherSubject || diagnostics.Omissions[0].FindingIndex != 1 {
			t.Fatalf("omission = %+v", diagnostics.Omissions[0])
		}
		if len(bundle.Images) != 2 {
			t.Fatalf("images = %d, want the two subject containers", len(bundle.Images))
		}
	})

	t.Run("unbound findings are omitted without degrading completeness", func(t *testing.T) {
		csv := csvFromRows(
			csvRowFor("CVE-2024-1234", "payments/api", "release"),
			csvRowFor("CVE-2024-5678", "payments/api", "release"),
		)
		input := testInput(t, csv, []normalize.Binding{
			testBinding(t, 0, contract.UID("pod-uid-1"), contract.ContainerRegular, contract.ContainerName("api")),
		})
		bundle, diagnostics := buildForTest(t, input)
		if bundle.Provenance.Completeness != contract.CompletenessComplete {
			t.Fatalf("completeness = %q, want complete", bundle.Provenance.Completeness)
		}
		if len(diagnostics.Omissions) != 1 || diagnostics.Omissions[0].Reason != OmissionUnbound {
			t.Fatalf("omissions = %+v, want one unbound", diagnostics.Omissions)
		}
	})

	t.Run("requested image defect adds a visible error and partial", func(t *testing.T) {
		// A non-representable tag makes the requested image nil: the projection
		// defect must be visible and the bundle must go partial.
		csv := testCSVHeader + "1.0,CVE-2024-1234,openssl,1.1.1k,fixed,registry.example,payments/api,.bad-tag,high\n"
		input := testInput(t, csv, []normalize.Binding{
			testBinding(t, 0, contract.UID("pod-uid-1"), contract.ContainerRegular, contract.ContainerName("api")),
		})
		bundle, diagnostics := buildForTest(t, input)
		if bundle.Provenance.Completeness != contract.CompletenessPartial {
			t.Fatalf("completeness = %q, want partial after a projection defect", bundle.Provenance.Completeness)
		}
		found := false
		for _, message := range bundle.Provenance.Errors {
			if message == errRequestedImageBlocked.Error() {
				found = true
			}
		}
		if !found {
			t.Fatalf("errors = %+v, want the visible requested-image defect", bundle.Provenance.Errors)
		}
		omitted := false
		for _, omission := range diagnostics.Omissions {
			if omission.Reason == OmissionRequestedImage {
				omitted = true
			}
		}
		if !omitted {
			t.Fatalf("omissions = %+v, want the requested image omission", diagnostics.Omissions)
		}
	})

	t.Run("scope collision is refused visibly and degrades completeness", func(t *testing.T) {
		csv := csvFromRows(
			csvRowFor("CVE-2024-1234", "payments/api", "release"),
			csvRowFor("CVE-2024-5678", "payments/api", "release"),
		)
		input := testInput(t, csv, []normalize.Binding{
			testBinding(t, 0, contract.UID("pod-uid-1"), contract.ContainerRegular, contract.ContainerName("api")),
			testBinding(t, 1, contract.UID("pod-uid-1"), contract.ContainerInit, contract.ContainerName("api")),
		})
		bundle, diagnostics := buildForTest(t, input)
		if diagnostics.CollisionCount != 1 {
			t.Fatalf("collision count = %d, want 1", diagnostics.CollisionCount)
		}
		if len(diagnostics.Omissions) != 2 {
			t.Fatalf("omissions = %+v, want both halves of the collided key", diagnostics.Omissions)
		}
		for _, omission := range diagnostics.Omissions {
			if omission.Reason != OmissionScopeCollision {
				t.Fatalf("omission reason = %q, want scope_collision", omission.Reason)
			}
		}
		if bundle.Provenance.Completeness != contract.CompletenessPartial {
			t.Fatalf("completeness = %q, want partial", bundle.Provenance.Completeness)
		}
		warned := false
		for _, warning := range bundle.Provenance.Warnings {
			if warning.Code == "scope_mismatch" && warning.Class == contract.WarningContradictory {
				warned = true
			}
		}
		if !warned {
			t.Fatalf("warnings = %+v, want the collision warning", bundle.Provenance.Warnings)
		}
	})
}

// TestA108ProjectionDefects covers B04: incoherent DTOs are refused instead of
// repaired, and the two directions of the collision/partition distinction are
// exercised.
func TestA108ProjectionDefects(t *testing.T) {
	t.Run("an incoherent resolution is refused", func(t *testing.T) {
		input := fixtureInput(t)
		finding := &input.Normalized.Findings[0]
		resolution := *finding.Resolution
		resolution.State = identity.ResolutionState("invented")
		finding.Resolution = &resolution
		bundle, _, err := Build(input)
		if err == nil {
			t.Fatal("a fabricated resolution state must be refused")
		}
		if !reflectZeroBundle(bundle) {
			t.Fatal("a refused input must not produce a bundle")
		}
	})
	t.Run("a binding replaced by another observation is refused", func(t *testing.T) {
		input := fixtureInput(t)
		finding := &input.Normalized.Findings[0]
		resolution := *finding.Resolution
		divergent := *finding.Binding
		divergent.Locator = contract.SourceLocator("items[9].status.containerStatuses[0].imageID")
		resolution.Binding = &divergent
		finding.Resolution = &resolution
		if _, _, err := Build(input); err == nil {
			t.Fatal("a binding that does not correspond to its resolution must be refused")
		}
	})

	t.Run("requested image is never repaired from the declaration", func(t *testing.T) {
		csv := testCSVHeader + "1.0,CVE-2024-1234,openssl,1.1.1k,fixed,registry.example,payments/api,.bad-tag,high\n"
		input := testInput(t, csv, []normalize.Binding{
			testBinding(t, 0, contract.UID("pod-uid-1"), contract.ContainerRegular, contract.ContainerName("api")),
		})
		bundle, _ := buildForTest(t, input)
		for _, item := range bundle.Evidence {
			if item.Type == "prisma_v1.requested_image" {
				t.Fatalf("a blocked declaration was repaired into %q", *item.Value)
			}
		}
	})

	t.Run("a valid projection defect never fabricates evidence", func(t *testing.T) {
		csv := testCSVHeader + "1.0,CVE-2024-1234,openssl,1.1.1k,fixed,registry.example,payments/api,.bad-tag,high\n"
		input := testInput(t, csv, []normalize.Binding{
			testBinding(t, 0, contract.UID("pod-uid-1"), contract.ContainerRegular, contract.ContainerName("api")),
		})
		bundle, _ := buildForTest(t, input)
		// The declared column is legitimately projected; what must not exist is a
		// composed requested_image item, because the declaration is not
		// representable under the ADR-0009 grammar.
		for _, item := range bundle.Evidence {
			if item.Type == "prisma_v1.requested_image" {
				t.Fatalf("a blocked declaration was repaired into a requested image: %v", item.Value)
			}
		}
		if len(evidenceOfType(bundle.Evidence, "prisma_v1.image_tag")) != 1 {
			t.Fatal("the declared tag column must stay auditable as a source fact")
		}
		if strings.Contains(envelopeOf(t, bundle), "requested_image_unrepresentable") {
			t.Fatal("an internal omission reason leaked into the wire")
		}
	})
}

// reflectZeroBundle reports whether a bundle is the zero value.
func reflectZeroBundle(bundle contract.Bundle) bool {
	return reflect.DeepEqual(bundle, contract.Bundle{})
}

// TestA108HashPreimages covers B05: the source hash covers the complete source
// and the value hash covers the exact bytes of the value; independent
// computation over literal bytes is used as the oracle.
func TestA108HashPreimages(t *testing.T) {
	t.Run("hash source covers the exact bytes", func(t *testing.T) {
		value := "schema_version,vulnerability_id\r\n1.0,CVE-2024-1234\r\n"
		expected := sha256.Sum256([]byte(value))
		want := "sha256:" + hex.EncodeToString(expected[:])
		if got := string(HashSource([]byte(value))); got != want {
			t.Fatalf("HashSource = %q, want an independent sha256 %q", got, want)
		}
		if HashSource([]byte(value)) == HashSource([]byte(value+" ")) {
			t.Fatal("one trailing byte must change the source hash")
		}
	})

	t.Run("hash value is the exact value bytes", func(t *testing.T) {
		for _, value := range []string{"", " ", " padded ", "value", "café", "=1+1"} {
			expected := sha256.Sum256([]byte(value))
			want := "sha256:" + hex.EncodeToString(expected[:])
			if got := string(HashValue(value)); got != want {
				t.Fatalf("HashValue(%q) = %q, want %q", value, got, want)
			}
		}
		if HashValue("value") == HashValue("value ") {
			t.Fatal("the preimage must not be trimmed")
		}
		if HashValue("value") == HashValue(`"value"`) {
			t.Fatal("the preimage must not include JSON quoting")
		}
	})

	t.Run("bundle evidence cites the complete source", func(t *testing.T) {
		input := fixtureInput(t)
		bundle, _ := buildForTest(t, input)
		if len(bundle.Provenance.Inputs) != 1 {
			t.Fatalf("inputs = %+v", bundle.Provenance.Inputs)
		}
		if bundle.Provenance.Inputs[0].Hash != input.Source.Hash {
			t.Fatalf("input hash = %q, want %q", bundle.Provenance.Inputs[0].Hash, input.Source.Hash)
		}
		if len(bundle.Evidence) == 0 {
			t.Fatal("expected declared evidence")
		}
		for _, item := range bundle.Evidence {
			if !strings.HasPrefix(item.Type, "prisma_v1.") {
				continue
			}
			if item.SourceHash != input.Source.Hash {
				t.Fatalf("item %q cites source hash %q", item.Type, item.SourceHash)
			}
			if item.ValueHash == nil {
				t.Fatalf("item %q carries no value hash", item.Type)
			}
			if item.Value != nil {
				expected := HashValue(*item.Value)
				if *item.ValueHash != expected {
					t.Fatalf("item %q value hash = %q, want the exact-byte hash %q", item.Type, *item.ValueHash, expected)
				}
			}
		}
	})
}

// a108NullVariant builds the four N1-N4 variants as explicit synthetic bundles,
// sharing the constructors with F3 through this helper's documented contract.
func a108NullVariant(t *testing.T, caseName string) contract.Bundle {
	t.Helper()
	bundle := fixtureBundle(t, 1)
	switch caseName {
	case "owner-null":
		bundle.Subject.OwnerChain = contract.OwnerChain("")
	case "ruleset-null":
		bundle.Provenance.Ruleset = contract.RulesetRef{}
	case "image-optionals-null":
		if len(bundle.Images) == 0 {
			t.Fatal("variant fixture has no image to clear")
		}
		bundle.Images[0].RequestedImage = nil
		bundle.Images[0].RawImageID = nil
		bundle.Images[0].NormalizedDigest = nil
		bundle.Images[0].Platform = contract.Platform{OS: "", Architecture: "", Status: contract.PlatformUnknown}
	case "run-start-only":
		bundle.Provenance.EndedAt = nil
		if bundle.Provenance.StartedAt == nil {
			bundle.Provenance.StartedAt = testTimestamp(t, "2026-09-26T10:00:00Z")
		}
	case "run-end-only":
		bundle.Provenance.StartedAt = nil
		if bundle.Provenance.EndedAt == nil {
			bundle.Provenance.EndedAt = testTimestamp(t, "2026-09-26T11:00:00Z")
		}
	case "run-neither":
		bundle.Provenance.StartedAt = nil
		bundle.Provenance.EndedAt = nil
	case "run-both":
		bundle.Provenance.StartedAt = testTimestamp(t, "2026-09-26T10:00:00Z")
		bundle.Provenance.EndedAt = testTimestamp(t, "2026-09-26T11:00:00Z")
	default:
		t.Fatalf("unknown null variant %q", caseName)
	}
	return bundle
}

// a108RebuildProjection reconstructs the ADR-0006 §1(a) projection from the
// canonical envelope with the test's own ordered structs: the section order of
// the projection document and the ruleset reduction to path/hash are declared
// here, not read from the delivered artifact nor delegated to the production
// helper. The comparison against artifacts.HashInput then proves the delivered
// projection is the one the envelope implies.
func a108RebuildProjection(envelope []byte) ([]byte, error) {
	type ruleset struct {
		Path json.RawMessage `json:"path"`
		Hash json.RawMessage `json:"hash"`
	}
	type projectedProvenance struct {
		Ruleset         json.RawMessage `json:"ruleset"`
		Inputs          json.RawMessage `json:"inputs"`
		APIScope        json.RawMessage `json:"api_scope"`
		Coverage        json.RawMessage `json:"coverage"`
		Completeness    json.RawMessage `json:"completeness"`
		Consistency     json.RawMessage `json:"consistency"`
		RedactionPolicy json.RawMessage `json:"redaction_policy"`
		Warnings        json.RawMessage `json:"warnings"`
		Errors          json.RawMessage `json:"errors"`
	}
	type projection struct {
		SchemaVersion            json.RawMessage     `json:"schema_version"`
		Subject                  json.RawMessage     `json:"subject"`
		Images                   json.RawMessage     `json:"images"`
		Evidence                 json.RawMessage     `json:"evidence"`
		ObservedContainerClasses json.RawMessage     `json:"observed_container_classes"`
		Provenance               projectedProvenance `json:"provenance"`
	}
	type envelopeSections struct {
		SchemaVersion            json.RawMessage `json:"schema_version"`
		Subject                  json.RawMessage `json:"subject"`
		Images                   json.RawMessage `json:"images"`
		Evidence                 json.RawMessage `json:"evidence"`
		ObservedContainerClasses json.RawMessage `json:"observed_container_classes"`
		Provenance               struct {
			Ruleset json.RawMessage `json:"ruleset"`
			projectedProvenance
		} `json:"provenance"`
	}

	var full envelopeSections
	if err := json.Unmarshal(envelope, &full); err != nil {
		return nil, err
	}
	rulesetJSON := json.RawMessage("null")
	if string(full.Provenance.Ruleset) != "null" {
		var sections struct {
			Path json.RawMessage `json:"path"`
			Hash json.RawMessage `json:"hash"`
		}
		if err := json.Unmarshal(full.Provenance.Ruleset, &sections); err != nil {
			return nil, err
		}
		built, err := json.Marshal(ruleset{Path: sections.Path, Hash: sections.Hash})
		if err != nil {
			return nil, err
		}
		rulesetJSON = built
	}
	document := projection{
		SchemaVersion:            full.SchemaVersion,
		Subject:                  full.Subject,
		Images:                   full.Images,
		Evidence:                 full.Evidence,
		ObservedContainerClasses: full.ObservedContainerClasses,
		Provenance: projectedProvenance{
			Ruleset:         rulesetJSON,
			Inputs:          full.Provenance.Inputs,
			APIScope:        full.Provenance.APIScope,
			Coverage:        full.Provenance.Coverage,
			Completeness:    full.Provenance.Completeness,
			Consistency:     full.Provenance.Consistency,
			RedactionPolicy: full.Provenance.RedactionPolicy,
			Warnings:        full.Provenance.Warnings,
			Errors:          full.Provenance.Errors,
		},
	}
	var buffer bytes.Buffer
	encoder := json.NewEncoder(&buffer)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(document); err != nil {
		return nil, err
	}
	return bytes.TrimSuffix(buffer.Bytes(), []byte("\n")), nil
}

// TestA108CanonicalNullVariants covers B06 and N1-N4: the envelope carries the
// documented nulls, the projection rebuilds from the envelope, and the digest
// covers the projection exactly.
func TestA108CanonicalNullVariants(t *testing.T) {
	variants := []string{"owner-null", "ruleset-null", "image-optionals-null", "run-start-only", "run-end-only", "run-neither", "run-both"}
	for _, name := range variants {
		t.Run(name, func(t *testing.T) {
			bundle := a108NullVariant(t, name)
			if err := contract.ValidateBundle(bundle); err != nil {
				t.Fatalf("variant is not a valid bundle: %v", err)
			}
			artifacts, err := Encode(bundle)
			if err != nil {
				t.Fatalf("encode: %v", err)
			}
			envelope, err := canonical.CanonicalJSON(bundle)
			if err != nil {
				t.Fatalf("canonical json: %v", err)
			}
			if string(artifacts.Envelope) != string(envelope) {
				t.Fatal("the envelope artifact is not the canonical envelope")
			}
			// Independent reconstruction: the projection is rebuilt from the envelope
			// by a path that does not share the delivered HashInput, and only then is
			// the digest checked with the stdlib. A bundle whose projection were
			// generated from the wrong fields would fail the byte comparison here.
			rebuilt, err := a108RebuildProjection(artifacts.Envelope)
			if err != nil {
				t.Fatalf("rebuild projection: %v", err)
			}
			if !bytes.Equal(rebuilt, artifacts.HashInput) {
				t.Fatalf("the delivered projection is not the reconstruction from the envelope: got %s, want %s",
					rebuilt, artifacts.HashInput)
			}
			expected := sha256.Sum256(rebuilt)
			if artifacts.Hash != "sha256:"+hex.EncodeToString(expected[:]) {
				t.Fatalf("digest = %q, want the independent sha256 of the reconstructed projection", artifacts.Hash)
			}
			// The projection must exclude the operational metadata of ADR-0006
			// §1(a): run timestamps, budget and argv. redaction_policy stays: it
			// is a provenance claim, not operational metadata.
			projection := string(artifacts.HashInput)
			for _, excluded := range []string{"started_at", "ended_at", "budget", "argv_sanitized", "collector_version", "parser_version"} {
				if strings.Contains(projection, excluded) {
					t.Fatalf("projection carries operational metadata %q", excluded)
				}
			}
			for _, included := range []string{"redaction_policy", "inputs", "coverage", "completeness", "consistency"} {
				if !strings.Contains(projection, included) {
					t.Fatalf("projection is missing the claim %q", included)
				}
			}
		})
	}

	t.Run("owner null is explicit in envelope and projection", func(t *testing.T) {
		bundle := a108NullVariant(t, "owner-null")
		artifacts, err := Encode(bundle)
		if err != nil {
			t.Fatalf("encode: %v", err)
		}
		for name, document := range map[string][]byte{"envelope": artifacts.Envelope, "projection": artifacts.HashInput} {
			if !strings.Contains(string(document), `"owner_chain":null`) {
				t.Fatalf("%s does not carry owner_chain:null", name)
			}
		}
	})

	t.Run("ruleset null is explicit in both documents", func(t *testing.T) {
		bundle := a108NullVariant(t, "ruleset-null")
		artifacts, err := Encode(bundle)
		if err != nil {
			t.Fatalf("encode: %v", err)
		}
		for name, document := range map[string][]byte{"envelope": artifacts.Envelope, "projection": artifacts.HashInput} {
			if !strings.Contains(string(document), `"ruleset":null`) {
				t.Fatalf("%s does not carry ruleset:null", name)
			}
		}
	})

	t.Run("image optionals null and unknown platform", func(t *testing.T) {
		bundle := a108NullVariant(t, "image-optionals-null")
		artifacts, err := Encode(bundle)
		if err != nil {
			t.Fatalf("encode: %v", err)
		}
		image := string(artifacts.Envelope)
		for _, field := range []string{`"requested_image":null`, `"raw_image_id":null`, `"normalized_digest":null`, `"status":"unknown"`} {
			if !strings.Contains(image, field) {
				t.Fatalf("envelope does not carry %s", field)
			}
		}
	})

	t.Run("run timestamps are null in the envelope and absent from the projection", func(t *testing.T) {
		for _, name := range []string{"run-start-only", "run-end-only", "run-neither", "run-both"} {
			bundle := a108NullVariant(t, name)
			artifacts, err := Encode(bundle)
			if err != nil {
				t.Fatalf("%s: encode: %v", name, err)
			}
			projection := string(artifacts.HashInput)
			if strings.Contains(projection, `"started_at"`) || strings.Contains(projection, `"ended_at"`) {
				t.Fatalf("%s: projection carries run timestamps", name)
			}
			var decoded struct {
				Provenance struct {
					StartedAt json.RawMessage `json:"started_at"`
					EndedAt   json.RawMessage `json:"ended_at"`
				} `json:"provenance"`
			}
			if err := json.Unmarshal(artifacts.Envelope, &decoded); err != nil {
				t.Fatalf("%s: decode envelope: %v", name, err)
			}
			if name != "run-both" && name != "run-start-only" && string(decoded.Provenance.StartedAt) != "null" {
				t.Fatalf("%s: started_at = %s, want null", name, decoded.Provenance.StartedAt)
			}
			if name != "run-both" && name != "run-end-only" && string(decoded.Provenance.EndedAt) != "null" {
				t.Fatalf("%s: ended_at = %s, want null", name, decoded.Provenance.EndedAt)
			}
		}
	})
}

// TestA108CanonicalMetamorphisms covers B07: allowed permutations preserve the
// bytes, multiplicity is preserved, a covered change moves the hash and an
// operational-only change can move the envelope while the hash stays.
func TestA108CanonicalMetamorphisms(t *testing.T) {
	t.Run("reversing independent arrays preserves the hash", func(t *testing.T) {
		// Arrays whose order the canonical projection does not depend on (evidence,
		// inputs, namespaces, warnings) may be permuted freely: the digest of the
		// projection must stay identical. The image array is not permuted here
		// because its order is part of the projection.
		bundle := fixtureBundle(t, 3)
		base, err := Encode(bundle)
		if err != nil {
			t.Fatalf("encode: %v", err)
		}

		reversed := cloneBundle(bundle)
		for left, right := 0, len(reversed.Evidence)-1; left < right; left, right = left+1, right-1 {
			reversed.Evidence[left], reversed.Evidence[right] = reversed.Evidence[right], reversed.Evidence[left]
		}
		for left, right := 0, len(reversed.Provenance.Inputs)-1; left < right; left, right = left+1, right-1 {
			reversed.Provenance.Inputs[left], reversed.Provenance.Inputs[right] = reversed.Provenance.Inputs[right], reversed.Provenance.Inputs[left]
		}
		for left, right := 0, len(reversed.Provenance.Warnings)-1; left < right; left, right = left+1, right-1 {
			reversed.Provenance.Warnings[left], reversed.Provenance.Warnings[right] = reversed.Provenance.Warnings[right], reversed.Provenance.Warnings[left]
		}
		shuffled, err := Encode(reversed)
		if err != nil {
			t.Fatalf("encode reversed: %v", err)
		}
		permutable := len(bundle.Evidence) > 1 || len(bundle.Provenance.Inputs) > 1 || len(bundle.Provenance.Warnings) > 1
		if !permutable {
			t.Fatal("the fixture has no permutable array: the control is vacuous")
		}
		if shuffled.Hash != base.Hash {
			t.Fatalf("a permutation of order-independent arrays moved the hash: %q vs %q", shuffled.Hash, base.Hash)
		}
		second, err := Encode(cloneBundle(bundle))
		if err != nil {
			t.Fatalf("encode clone: %v", err)
		}
		if string(base.Envelope) != string(second.Envelope) || base.Hash != second.Hash {
			t.Fatal("a detached copy of the same bundle produced different bytes")
		}
	})

	t.Run("a covered change moves the hash", func(t *testing.T) {
		bundle := fixtureBundle(t, 1)
		before, err := Encode(bundle)
		if err != nil {
			t.Fatalf("encode: %v", err)
		}
		changed := cloneBundle(bundle)
		changed.Subject.Name = "payments-api-changed"
		after, err := Encode(changed)
		if err != nil {
			t.Fatalf("encode changed: %v", err)
		}
		if before.Hash == after.Hash {
			t.Fatal("a change to the subject must change the projection hash")
		}
	})

	t.Run("an operational-only change can move the envelope and keep the hash", func(t *testing.T) {
		bundle := fixtureBundle(t, 1)
		before, err := Encode(bundle)
		if err != nil {
			t.Fatalf("encode: %v", err)
		}
		operational := cloneBundle(bundle)
		operational.Provenance.ArgvSanitized = []string{"import", "other.csv", "--schema", "prisma-v1"}
		after, err := Encode(operational)
		if err != nil {
			t.Fatalf("encode operational: %v", err)
		}
		if string(before.Envelope) == string(after.Envelope) {
			t.Fatal("the operational change was expected to alter the envelope")
		}
		if before.Hash != after.Hash {
			t.Fatalf("an excluded operational change moved the hash: %q vs %q", before.Hash, after.Hash)
		}
	})

	t.Run("multiplicity is preserved", func(t *testing.T) {
		// Two identical findings under different containers must keep both their
		// evidence items: no deduplication anywhere in the projection.
		csv := csvFromRows(
			csvRowFor("CVE-2024-1234", "payments/api", "release"),
			csvRowFor("CVE-2024-1234", "payments/api", "release"),
		)
		input := testInput(t, csv, []normalize.Binding{
			testBinding(t, 0, contract.UID("pod-uid-1"), contract.ContainerRegular, contract.ContainerName("api")),
			testBinding(t, 1, contract.UID("pod-uid-1"), contract.ContainerRegular, contract.ContainerName("worker")),
		})
		bundle, _ := buildForTest(t, input)
		count := 0
		for _, item := range bundle.Evidence {
			if item.Type == "prisma_v1.vulnerability_id" {
				count++
			}
		}
		if count != 2 {
			t.Fatalf("vulnerability_id items = %d, want 2 occurrences preserved", count)
		}
	})
}

// TestA108BundleWriters covers B08: prevalidation, nil destinations including a
// typed nil, short writes and writer errors; an incomplete delivery is never an
// error-free success.
func TestA108BundleWriters(t *testing.T) {
	bundle := fixtureBundle(t, 1)

	t.Run("nil destinations are refused before encoding", func(t *testing.T) {
		cases := []struct {
			name string
			dest Destinations
		}{
			{"all nil", Destinations{}},
			{"missing hash input", Destinations{Envelope: &recordingWriter{}, Hash: &recordingWriter{}}},
			{"missing hash", Destinations{Envelope: &recordingWriter{}, HashInput: &recordingWriter{}}},
		}
		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				if err := Write(bundle, tc.dest); err == nil {
					t.Fatal("a missing destination must be refused")
				}
			})
		}
	})

	t.Run("a typed nil writer is refused", func(t *testing.T) {
		var typedNil *recordingWriter
		dest := Destinations{Envelope: typedNil, HashInput: &recordingWriter{}, Hash: &recordingWriter{}}
		if err := Write(bundle, dest); err == nil {
			t.Fatal("a typed nil destination must be refused")
		}
	})

	t.Run("prevalidation happens before the first write", func(t *testing.T) {
		var typedNil *recordingWriter
		counter := &recordingWriter{}
		dest := Destinations{Envelope: counter, HashInput: typedNil, Hash: counter}
		_ = Write(bundle, dest)
		if counter.callCount != 0 {
			t.Fatalf("writer was called %d times before validation", counter.callCount)
		}
	})

	t.Run("a failing writer is reported and not announced as success", func(t *testing.T) {
		failing := &recordingWriter{failWith: errTransportFailed}
		dest := Destinations{Envelope: &recordingWriter{}, HashInput: failing, Hash: &recordingWriter{}}
		if err := Write(bundle, dest); err == nil {
			t.Fatal("a writer failure must be reported")
		}
	})

	t.Run("a short write is an incomplete delivery", func(t *testing.T) {
		short := &recordingWriter{shortBy: 7}
		dest := Destinations{Envelope: short, HashInput: &recordingWriter{}, Hash: &recordingWriter{}}
		err := Write(bundle, dest)
		if err == nil {
			t.Fatal("a short write must be reported as incomplete")
		}
		if !strings.Contains(err.Error(), "incomplete") {
			t.Fatalf("error = %v, want the incomplete delivery classification", err)
		}
	})

	t.Run("a successful delivery writes all three artifacts in order", func(t *testing.T) {
		envelope := &recordingWriter{}
		hashInput := &recordingWriter{}
		hashSidecar := &recordingWriter{}
		if err := Write(bundle, Destinations{Envelope: envelope, HashInput: hashInput, Hash: hashSidecar}); err != nil {
			t.Fatalf("write: %v", err)
		}
		artifacts, err := Encode(bundle)
		if err != nil {
			t.Fatalf("encode: %v", err)
		}
		if string(envelope.data) != string(artifacts.Envelope) {
			t.Fatal("the envelope delivery differs from the artifact")
		}
		if string(hashInput.data) != string(artifacts.HashInput) {
			t.Fatal("the projection delivery differs from the artifact")
		}
		if string(hashSidecar.data) != artifacts.Hash+"\n" {
			t.Fatalf("hash sidecar = %q, want the digest plus one LF", hashSidecar.data)
		}
	})
}
