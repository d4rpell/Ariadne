package bundle

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// a108GoldenCases are the seven committed null-variant triplets of A1-08 F3.
// Each is the exact artifact set of one a108NullVariant constructor whose name
// equals the case directory; the fixtures/*/0.2 READMEs link the constructor
// and document fields, scope, instant and residual.
var a108GoldenCases = []struct {
	caseName string
	fixture  string
}{
	{"owner-null", "F08-partial-list-get"},
	{"image-optionals-null", "F08-partial-list-get"},
	{"ruleset-null", "F11-malformed-csv"},
	{"run-start-only", "F12-partial-source-failure"},
	{"run-end-only", "F12-partial-source-failure"},
	{"run-neither", "F12-partial-source-failure"},
	{"run-both", "F12-partial-source-failure"},
}

// TestA108GoldenNullVariants consumes the seven committed triplets: the
// committed bytes are the exact Encode output of the shared a108NullVariant
// constructor for each case name, the delivered projection is the
// reconstruction from the delivered envelope, and the delivered digest is an
// independent SHA-256 of those projection bytes.
func TestA108GoldenNullVariants(t *testing.T) {
	for _, golden := range a108GoldenCases {
		t.Run(golden.caseName, func(t *testing.T) {
			dir := filepath.Join("..", "..", "fixtures", golden.fixture, "0.2", golden.caseName, "expected")
			envelope := readA108GoldenFile(t, dir, "bundle.json")
			projection := readA108GoldenFile(t, dir, "bundle.hash-input.json")
			digest := strings.TrimSuffix(string(readA108GoldenFile(t, dir, "bundle.sha256")), "\n")

			// The committed triplet must be the exact artifact set of the shared
			// constructor for this case name: this pins the fixture to the
			// constructor, so a triplet of another variant cannot stand in for it.
			bundle := a108NullVariant(t, golden.caseName)
			constructed, err := Encode(bundle)
			if err != nil {
				t.Fatalf("encode constructor bundle: %v", err)
			}
			if !bytes.Equal(constructed.Envelope, envelope) {
				t.Fatalf("the committed envelope is not the Encode output of the %s constructor", golden.caseName)
			}
			if !bytes.Equal(constructed.HashInput, projection) {
				t.Fatalf("the committed projection is not the Encode output of the %s constructor", golden.caseName)
			}
			if constructed.Hash+"\n" != string(readA108GoldenFile(t, dir, "bundle.sha256")) {
				t.Fatalf("the committed sidecar is not the Encode output of the %s constructor", golden.caseName)
			}

			rebuilt, err := a108RebuildProjection(envelope)
			if err != nil {
				t.Fatalf("rebuild projection: %v", err)
			}
			if !bytes.Equal(rebuilt, projection) {
				t.Fatalf("the delivered projection is not the reconstruction from the delivered envelope: got %s, want %s", rebuilt, projection)
			}
			expected := sha256.Sum256(projection)
			if digest != "sha256:"+hex.EncodeToString(expected[:]) {
				t.Fatalf("digest = %q, want the independent sha256 of the projection", digest)
			}

			var sections struct {
				SchemaVersion string `json:"schema_version"`
			}
			if err := json.Unmarshal(envelope, &sections); err != nil {
				t.Fatalf("decode envelope: %v", err)
			}
			if sections.SchemaVersion != "0.2" {
				t.Fatalf("schema_version = %q, want 0.2", sections.SchemaVersion)
			}
		})
	}

	t.Run("the case name selects the committed null", func(t *testing.T) {
		// Each committed envelope carries exactly the null its case name declares;
		// a triplet materialized from another variant fails here.
		for _, golden := range a108GoldenCases {
			dir := filepath.Join("..", "..", "fixtures", golden.fixture, "0.2", golden.caseName, "expected")
			envelope := readA108GoldenFile(t, dir, "bundle.json")
			var decoded struct {
				Subject struct {
					OwnerChain json.RawMessage `json:"owner_chain"`
				} `json:"subject"`
				Images []struct {
					RequestedImage   json.RawMessage `json:"requested_image"`
					RawImageID       json.RawMessage `json:"raw_image_id"`
					NormalizedDigest json.RawMessage `json:"normalized_digest"`
					Platform         struct {
						OS           string `json:"os"`
						Architecture string `json:"architecture"`
						Status       string `json:"status"`
					} `json:"platform"`
				} `json:"images"`
				Provenance struct {
					Ruleset   json.RawMessage `json:"ruleset"`
					StartedAt json.RawMessage `json:"started_at"`
					EndedAt   json.RawMessage `json:"ended_at"`
				} `json:"provenance"`
			}
			if err := json.Unmarshal(envelope, &decoded); err != nil {
				t.Fatalf("%s: decode envelope: %v", golden.caseName, err)
			}
			null := func(raw json.RawMessage) bool { return string(raw) == "null" }
			switch golden.caseName {
			case "owner-null":
				if !null(decoded.Subject.OwnerChain) {
					t.Fatal("owner_chain is not null")
				}
			case "image-optionals-null":
				image := decoded.Images[0]
				if !null(image.RequestedImage) || !null(image.RawImageID) || !null(image.NormalizedDigest) {
					t.Fatal("image optionals are not all null")
				}
				if image.Platform.Status != "unknown" || image.Platform.OS != "" || image.Platform.Architecture != "" {
					t.Fatalf("platform = %+v, want unknown with empty os and architecture", image.Platform)
				}
			case "ruleset-null":
				if !null(decoded.Provenance.Ruleset) {
					t.Fatal("ruleset is not null")
				}
			case "run-start-only":
				if null(decoded.Provenance.StartedAt) || !null(decoded.Provenance.EndedAt) {
					t.Fatal("run-start-only must carry started_at and a null ended_at")
				}
			case "run-end-only":
				if !null(decoded.Provenance.StartedAt) || null(decoded.Provenance.EndedAt) {
					t.Fatal("run-end-only must carry ended_at and a null started_at")
				}
			case "run-neither":
				if !null(decoded.Provenance.StartedAt) || !null(decoded.Provenance.EndedAt) {
					t.Fatal("run-neither must carry both timestamps null")
				}
			case "run-both":
				if null(decoded.Provenance.StartedAt) || null(decoded.Provenance.EndedAt) {
					t.Fatal("run-both must carry both timestamps")
				}
			}
		}
	})

	t.Run("the four run variants share one projection and differ in envelope", func(t *testing.T) {
		// Run timestamps are operational metadata excluded from the hash-input
		// projection of ADR-0006 §1(a): the four run-* envelopes differ, but the
		// committed projection bytes and the digest must be identical.
		var digest string
		var projection []byte
		for _, golden := range a108GoldenCases {
			if !strings.HasPrefix(golden.caseName, "run-") {
				continue
			}
			dir := filepath.Join("..", "..", "fixtures", golden.fixture, "0.2", golden.caseName, "expected")
			current := readA108GoldenFile(t, dir, "bundle.hash-input.json")
			currentDigest := strings.TrimSuffix(string(readA108GoldenFile(t, dir, "bundle.sha256")), "\n")
			if digest == "" {
				digest, projection = currentDigest, current
				continue
			}
			if !bytes.Equal(current, projection) {
				t.Fatalf("%s: projection differs from the other run variants", golden.caseName)
			}
			if currentDigest != digest {
				t.Fatalf("%s: digest differs from the other run variants", golden.caseName)
			}
		}
	})
}

func readA108GoldenFile(t *testing.T, dir, name string) []byte {
	t.Helper()
	body, err := os.ReadFile(filepath.Join(dir, name))
	if err != nil {
		t.Fatalf("read %s: %v", filepath.Join(dir, name), err)
	}
	if len(body) == 0 {
		t.Fatalf("%s is empty", filepath.Join(dir, name))
	}
	return body
}
