package bundle

import (
	"strings"
	"testing"

	canonical "github.com/d4rpell/Ariadne/internal/evidence"
	"github.com/d4rpell/Ariadne/internal/normalize"
	contract "github.com/d4rpell/Ariadne/pkg/evidence"
)

// TestBuildEmitsV02 fixes emission policy A1 of ADR-0016 §6.3: every new bundle
// leaves Build as 0.2, including a plain prisma-v1 import with no domain
// vocabulary at all. Build offers no version parameter and no downgrade.
func TestBuildEmitsV02(t *testing.T) {
	bundle, _ := buildForTest(t, testInput(t, csvOneRow, []normalize.Binding{
		testBinding(t, 0, contract.UID("pod-uid-1"), contract.ContainerRegular, contract.ContainerName("api")),
	}))
	if bundle.SchemaVersion != "0.2" {
		t.Fatalf("Build emitted schema_version %q, want 0.2", bundle.SchemaVersion)
	}
	if err := contract.ValidateBundle(bundle); err != nil {
		t.Fatalf("the emitted bundle is invalid: %v", err)
	}
}

// TestBuildCatalogUnchanged checks the rest of the projection survives the bump:
// the CSV catalog, the observation facts and the requested image keep their type
// names and values, and only schema_version moves.
func TestBuildCatalogUnchanged(t *testing.T) {
	bundle, _ := buildForTest(t, testInput(t, csvOneRow, []normalize.Binding{
		testBinding(t, 0, contract.UID("pod-uid-1"), contract.ContainerRegular, contract.ContainerName("api")),
	}))

	for _, declared := range []string{"prisma_v1.vulnerability_id", "prisma_v1.package_name", "prisma_v1.fix_status", "prisma_v1.requested_image"} {
		if len(evidenceOfType(bundle.Evidence, declared)) == 0 {
			t.Fatalf("the bump dropped the declared type %s", declared)
		}
	}
	for _, observed := range []string{"container_status.image_id", "container_status.normalized_digest", "container_status.platform.os", "container_status.platform.architecture"} {
		if len(evidenceOfType(bundle.Evidence, observed)) == 0 {
			t.Fatalf("the bump dropped the observation type %s", observed)
		}
	}
	for _, item := range bundle.Evidence {
		if strings.HasPrefix(item.Type, "product_v1.") {
			t.Fatalf("Build must not project domain vocabulary yet: %s", item.Type)
		}
	}

	envelope := envelopeOf(t, bundle)
	if !strings.Contains(envelope, `"schema_version":"0.2"`) {
		t.Fatalf("the envelope does not carry the emitted version: %s", envelope[:80])
	}
	value := "1.0"
	if len(evidenceOfType(bundle.Evidence, "prisma_v1.schema_version")) != 1 {
		t.Fatal("the CSV schema_version column must stay projected as a declared value")
	}
	found := false
	for _, item := range evidenceOfType(bundle.Evidence, "prisma_v1.schema_version") {
		if item.Value != nil && *item.Value == value {
			found = true
		}
	}
	if !found {
		t.Fatal("the CSV value 1.0 must remain the declared schema_version value")
	}
}

// TestEncodeVersionsAgree covers both versions through the whole transport: the
// canonicalizer and Encode agree for 0.1 and 0.2, and the delivered digest covers
// the delivered projection in each.
func TestEncodeVersionsAgree(t *testing.T) {
	for _, version := range []string{"0.1", "0.2"} {
		t.Run(version, func(t *testing.T) {
			bundle := fixtureBundle(t, 2)
			bundle.SchemaVersion = version
			artifacts, err := Encode(bundle)
			if err != nil {
				t.Fatalf("encode %s: %v", version, err)
			}
			envelope, err := canonical.CanonicalJSON(bundle)
			if err != nil {
				t.Fatalf("canonical json %s: %v", version, err)
			}
			hash, err := canonical.HashCanonicalJSON(bundle)
			if err != nil {
				t.Fatalf("canonical hash %s: %v", version, err)
			}
			if string(artifacts.Envelope) != string(envelope) {
				t.Fatalf("the %s envelope artifact is not the frozen canonical envelope", version)
			}
			if artifacts.Hash != hash {
				t.Fatalf("%s hash = %q, want %q", version, artifacts.Hash, hash)
			}
			if computed := HashSource(artifacts.HashInput); string(computed) != artifacts.Hash {
				t.Fatalf("the %s digest does not cover the delivered projection", version)
			}
			if !strings.HasPrefix(string(artifacts.HashInput), `{"schema_version":"`+version+`"`) {
				t.Fatalf("the %s projection does not open with its version", version)
			}
		})
	}

	legacy := fixtureBundle(t, 2)
	legacy.SchemaVersion = "0.1"
	bumped := fixtureBundle(t, 2)
	bumped.SchemaVersion = "0.2"
	legacyHash, err := canonical.HashCanonicalJSON(legacy)
	if err != nil {
		t.Fatalf("legacy hash: %v", err)
	}
	bumpedHash, err := canonical.HashCanonicalJSON(bumped)
	if err != nil {
		t.Fatalf("bumped hash: %v", err)
	}
	if legacyHash == bumpedHash {
		t.Fatal("the same data under 0.1 and 0.2 must not share a bundle digest")
	}
}

// TestWriteV02Artifacts fixes the transport contract for 0.2: the hash sidecar
// carries the digest and exactly one LF, and the two JSON artifacts carry no LF
// and no BOM.
func TestWriteV02Artifacts(t *testing.T) {
	bundle, _ := buildForTest(t, testInput(t, csvOneRow, []normalize.Binding{
		testBinding(t, 0, contract.UID("pod-uid-1"), contract.ContainerRegular, contract.ContainerName("api")),
	}))
	envelope := &recordingWriter{}
	hashInput := &recordingWriter{}
	hash := &recordingWriter{}
	if err := Write(bundle, Destinations{Envelope: envelope, HashInput: hashInput, Hash: hash}); err != nil {
		t.Fatalf("write: %v", err)
	}
	artifacts, err := Encode(bundle)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	if string(envelope.data) != string(artifacts.Envelope) {
		t.Fatal("the delivered envelope differs from the artifact")
	}
	if string(hashInput.data) != string(artifacts.HashInput) {
		t.Fatal("the delivered projection differs from the artifact")
	}
	if string(hash.data) != artifacts.Hash+"\n" {
		t.Fatalf("hash sidecar = %q, want the digest plus one LF", hash.data)
	}
	if strings.Count(string(hash.data), "\n") != 1 {
		t.Fatal("the hash sidecar must carry exactly one LF")
	}
	for name, document := range map[string][]byte{"envelope": envelope.data, "projection": hashInput.data} {
		if strings.HasSuffix(string(document), "\n") {
			t.Fatalf("%s carries a trailing newline", name)
		}
		if strings.HasPrefix(string(document), "\ufeff") {
			t.Fatalf("%s carries a BOM", name)
		}
	}
	if !strings.Contains(string(envelope.data), `"schema_version":"0.2"`) {
		t.Fatal("the delivered envelope does not carry the emitted version")
	}
}
