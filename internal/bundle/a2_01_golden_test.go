package bundle_test

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/d4rpell/Ariadne/internal/bundle"
	"github.com/d4rpell/Ariadne/internal/ingest"
	"github.com/d4rpell/Ariadne/internal/normalize"
	contract "github.com/d4rpell/Ariadne/pkg/evidence"
)

// Golden tests of the sanitized PodList adapter (ADR-0025 A.12.5 and handoff
// F1 §4.6). Each case of §1.5 travels parse -> normalize -> build -> Encode over
// the real APIs and is contrasted byte by byte with the three frozen artifacts
// under internal/bundle/testdata/a2_01/<case>/. The observation context is fixed
// in Go (a201Context); the fixture directory holds only the sanitized document
// and the three deliverables.
//
// The projection is rebuilt here by an independent oracle that only uses
// encoding/json, crypto/sha256 and encoding/hex: it never calls CanonicalJSON,
// HashCanonicalJSON, Encode or any private helper of internal/evidence or
// internal/bundle. The frozen vectors were reviewed by hand before freezing
// (`complete` and `unknown-collision` were read member by member against
// ADR-0025 A.9 and ADR-0006 §1(a)) and cross-checked with an external Python
// recalculation of projection, digest, source hash and value hashes.
//
// What these tests acreditan: the exact bytes of the nine cases, the projection
// membership and order, the digest boundary and the determinism of the adapter.
// What they do not acreditan: any real capture, cluster, sanitizer, platform or
// digest, and no acceptance or release is implied.

// a201GoldenCase is one frozen case of handoff §1.5 with the contract
// expectations its bytes must satisfy. Every expectation below is written
// literally from ADR-0025 A.7.4/A.8.4/A.9/A.10.4, never read from a production
// table.
type a201GoldenCase struct {
	name         string
	termination  contract.CoverageTermination
	completeness contract.Completeness
	classes      []string
	images       int
	evidence     int
	warnings     []string
	errors       []string
}

func a201GoldenCases() []a201GoldenCase {
	threeClasses := []string{"ephemeral", "init", "regular"}
	collisionWarnings := []string{"partial_observation", "redaction_applied", "scope_mismatch"}
	return []a201GoldenCase{
		{
			name:         "complete",
			termination:  contract.TerminationFinished,
			completeness: contract.CompletenessComplete,
			classes:      threeClasses,
			images:       1,
			evidence:     1,
			warnings:     []string{"redaction_applied"},
			errors:       []string{},
		},
		{
			name:         "explicit-empty",
			termination:  contract.TerminationFinished,
			completeness: contract.CompletenessComplete,
			classes:      threeClasses,
			images:       0,
			evidence:     0,
			warnings:     []string{"redaction_applied"},
			errors:       []string{},
		},
		{
			name:         "partial-category",
			termination:  contract.TerminationFinished,
			completeness: contract.CompletenessPartial,
			classes:      []string{"ephemeral", "regular"},
			images:       1,
			evidence:     1,
			warnings:     []string{"partial_observation", "redaction_applied"},
			errors:       []string{"ingest: sanitized-podlist-v1: byte/159: container category was not observed"},
		},
		{
			name:         "finished-collision",
			termination:  contract.TerminationFinished,
			completeness: contract.CompletenessPartial,
			classes:      threeClasses,
			images:       1,
			evidence:     1,
			warnings:     collisionWarnings,
			errors:       []string{"bundle: scope collision omitted"},
		},
		{
			// The collision defects never promote an unknown capture: completeness
			// stays unknown while omissions, error and warning remain visible.
			name:         "unknown-collision",
			termination:  contract.TerminationUnknown,
			completeness: contract.CompletenessUnknown,
			classes:      threeClasses,
			images:       1,
			evidence:     1,
			warnings:     collisionWarnings,
			errors: []string{
				"bundle: scope collision omitted",
				"ingest: sanitized-podlist-v1: byte/0: export capture termination is unknown",
			},
		},
		{
			// Every resulting image is omitted by the collision and the observed
			// categories survive: the bundle stays valid and partial.
			name:         "all-collided",
			termination:  contract.TerminationFinished,
			completeness: contract.CompletenessPartial,
			classes:      threeClasses,
			images:       0,
			evidence:     0,
			warnings:     collisionWarnings,
			errors:       []string{"bundle: scope collision omitted"},
		},
		{
			// Aborted with verifiable progress (a category observed and an image
			// inventoried) is partial, never unknown.
			name:         "aborted-progress",
			termination:  contract.TerminationAborted,
			completeness: contract.CompletenessPartial,
			classes:      []string{"regular"},
			images:       1,
			evidence:     1,
			warnings:     []string{"partial_observation", "redaction_applied"},
			errors: []string{
				"ingest: sanitized-podlist-v1: byte/0: export capture was aborted",
				"ingest: sanitized-podlist-v1: byte/159: container category was not observed",
				"ingest: sanitized-podlist-v1: byte/159: container category was not observed",
			},
		},
		{
			// A rejected peer stays visible in the surviving subject and forbids
			// "complete"; the valid Pod keeps its own observation.
			name:         "rejected-peer",
			termination:  contract.TerminationFinished,
			completeness: contract.CompletenessPartial,
			classes:      threeClasses,
			images:       1,
			evidence:     1,
			warnings:     []string{"partial_observation", "redaction_applied"},
			errors: []string{
				"ingest: sanitized-podlist-v1: byte/44: source contains rejected Pod items",
				"ingest: sanitized-podlist-v1: byte/517: invalid identifier",
			},
		},
		{
			// One imageID arrives escaped (\u0061) and another carries literal
			// multibyte text: both decode to their exact value and keep their own
			// value hash; the source hash covers the exact bytes.
			name:         "utf8-escaped",
			termination:  contract.TerminationFinished,
			completeness: contract.CompletenessComplete,
			classes:      threeClasses,
			images:       2,
			evidence:     2,
			warnings:     []string{"redaction_applied"},
			errors:       []string{},
		},
	}
}

func a201GoldenPath(name, file string) string {
	return filepath.Join("testdata", "a2_01", name, file)
}

func a201GoldenFile(t *testing.T, name, file string) []byte {
	t.Helper()
	data, err := os.ReadFile(a201GoldenPath(name, file))
	if err != nil {
		t.Fatalf("read golden %s/%s: %v", name, file, err)
	}
	return data
}

// a201GoldenRun travels the whole pipeline of one case with its declared
// termination and returns the three encoded artifacts.
func a201GoldenRun(t *testing.T, testCase a201GoldenCase) (contract.Bundle, bundle.Artifacts) {
	t.Helper()
	document := a201GoldenFile(t, testCase.name, "podlist.json")
	context := a201Context(t, a201ObservedMoment, testCase.termination)
	parsed := a201Parse(t, string(document), context)
	observation := a201Normalize(t, parsed)
	built, _ := a201Build(t, observation, 0)
	artifacts, err := bundle.Encode(built)
	if err != nil {
		t.Fatalf("%s: encode: %v", testCase.name, err)
	}
	return built, artifacts
}

// TestA201ObservationGolden is handoff §4.6 point 2: every case matches its
// three frozen artifacts byte by byte, the JSON artifacts are compact and
// newline-free, the digest line is ASCII with one LF, Write reproduces Encode,
// and the wire values of A.7.4/A.8.4/A.9 hold per case.
func TestA201ObservationGolden(t *testing.T) {
	for _, testCase := range a201GoldenCases() {
		t.Run(testCase.name, func(t *testing.T) {
			built, artifacts := a201GoldenRun(t, testCase)

			envelope := a201GoldenFile(t, testCase.name, "bundle.json")
			projection := a201GoldenFile(t, testCase.name, "bundle.hash-input.json")
			digest := a201GoldenFile(t, testCase.name, "bundle.sha256")
			if !bytes.Equal(artifacts.Envelope, envelope) {
				t.Fatalf("envelope diverges from bundle.json: %d vs %d bytes", len(artifacts.Envelope), len(envelope))
			}
			if !bytes.Equal(artifacts.HashInput, projection) {
				t.Fatalf("hash input diverges from bundle.hash-input.json: %d vs %d bytes", len(artifacts.HashInput), len(projection))
			}
			if want := artifacts.Hash + "\n"; string(digest) != want {
				t.Fatalf("bundle.sha256 = %q, want the digest plus one LF %q", digest, want)
			}
			a201RequireCompactJSON(t, "bundle.json", artifacts.Envelope)
			a201RequireCompactJSON(t, "bundle.hash-input.json", artifacts.HashInput)
			a201RequireDigestLine(t, "bundle.sha256", digest)

			// Contract expectations that the frozen bytes encode, stated here so a
			// regenerated vector cannot silently carry a different status.
			if built.Provenance.Coverage.Termination != testCase.termination {
				t.Fatalf("termination = %q, want the declared %q", built.Provenance.Coverage.Termination, testCase.termination)
			}
			if built.Provenance.Completeness != testCase.completeness {
				t.Fatalf("completeness = %q, want %q", built.Provenance.Completeness, testCase.completeness)
			}
			if len(built.Images) != testCase.images || len(built.Evidence) != testCase.evidence {
				t.Fatalf("images/evidence = %d/%d, want %d/%d", len(built.Images), len(built.Evidence), testCase.images, testCase.evidence)
			}
			for _, item := range built.Evidence {
				if item.Type != "container_status.image_id" {
					t.Fatalf("evidence type = %q, want the only emitted type", item.Type)
				}
				if item.Scope.SubjectUID != built.Subject.UID || item.Scope.ContainerName == "" {
					t.Fatalf("scope = %+v, want the subject UID and a container name", item.Scope)
				}
				if item.Value == nil || *item.Value == "" || item.ValueHash == nil {
					t.Fatalf("evidence item = %+v, want a non-empty value with its preimage hash", item)
				}
			}

			view := a201EnvelopeViewOf(t, testCase.name, artifacts.Envelope)
			a201RequireWarningCodes(t, testCase.name, view.Provenance.Warnings, testCase.warnings)
			if !reflect.DeepEqual(view.Provenance.Errors, testCase.errors) {
				t.Fatalf("errors = %q, want %q", view.Provenance.Errors, testCase.errors)
			}
			a201RequireCollisionWarnings(t, testCase.name, view.Provenance.Warnings, testCase.warnings)

			// Write transports exactly the Encode artifacts, with the LF of the
			// digest line being its only addition (A.12.5 point 8).
			envelopeSink := &a201SpyWriter{}
			projectionSink := &a201SpyWriter{}
			hashSink := &a201SpyWriter{}
			if err := bundle.Write(built, bundle.Destinations{
				Envelope: envelopeSink, HashInput: projectionSink, Hash: hashSink,
			}); err != nil {
				t.Fatalf("write: %v", err)
			}
			if !bytes.Equal(envelopeSink.data, artifacts.Envelope) || !bytes.Equal(projectionSink.data, artifacts.HashInput) {
				t.Fatal("Write must transport the Encode artifacts without alteration")
			}
			if string(hashSink.data) != artifacts.Hash+"\n" {
				t.Fatalf("written digest = %q, want the digest plus one LF", hashSink.data)
			}
		})
	}
}

// a201WireWarning is the warning object of the wire (§3.5), parsed only to read
// the frozen expectations back from the envelope.
type a201WireWarning struct {
	Code    string `json:"code"`
	Class   string `json:"class"`
	Message string `json:"message"`
}

type a201WireEnvelope struct {
	Provenance struct {
		Warnings []a201WireWarning `json:"warnings"`
		Errors   []string          `json:"errors"`
	} `json:"provenance"`
}

func a201EnvelopeViewOf(t *testing.T, label string, envelope []byte) a201WireEnvelope {
	t.Helper()
	var view a201WireEnvelope
	if err := json.Unmarshal(envelope, &view); err != nil {
		t.Fatalf("%s: envelope is not a JSON object: %v", label, err)
	}
	return view
}

func a201RequireWarningCodes(t *testing.T, label string, warnings []a201WireWarning, want []string) {
	t.Helper()
	got := make([]string, 0, len(warnings))
	for _, warning := range warnings {
		got = append(got, warning.Code)
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("%s: warning codes = %q, want %q", label, got, want)
	}
}

// a201RequireCollisionWarnings pins the A.8.4 literals when a case declares the
// contradictory collision warning: the classes are enumerated in regular, init,
// ephemeral order and the class is contradictory.
func a201RequireCollisionWarnings(t *testing.T, label string, warnings []a201WireWarning, want []string) {
	t.Helper()
	expectsCollision := false
	for _, code := range want {
		if code == "scope_mismatch" {
			expectsCollision = true
		}
	}
	if !expectsCollision {
		return
	}
	for _, warning := range warnings {
		if warning.Code != "scope_mismatch" {
			continue
		}
		if warning.Class != "contradictory" {
			t.Fatalf("%s: scope_mismatch class = %q, want contradictory", label, warning.Class)
		}
		if warning.Message != "scope collision across container classes: regular, init" {
			t.Fatalf("%s: scope_mismatch message = %q, want the literal ordered by class", label, warning.Message)
		}
		return
	}
	t.Fatalf("%s: the expected scope_mismatch warning is missing", label)
}

// a201RequireCompactJSON checks the canonical byte grammar of A.12.5: no BOM,
// no whitespace outside strings (hence no indentation and no trailing LF) and a
// terminated set of strings. The scan is independent of the producers.
func a201RequireCompactJSON(t *testing.T, label string, document []byte) {
	t.Helper()
	if len(document) == 0 {
		t.Fatalf("%s: empty document", label)
	}
	if bytes.HasPrefix(document, []byte{0xEF, 0xBB, 0xBF}) {
		t.Fatalf("%s: a BOM is not allowed", label)
	}
	if bytes.HasSuffix(document, []byte("\n")) {
		t.Fatalf("%s: a trailing LF is not allowed", label)
	}
	inString := false
	escaped := false
	for index, character := range document {
		if inString {
			if escaped {
				escaped = false
				continue
			}
			switch character {
			case '\\':
				escaped = true
			case '"':
				inString = false
			}
			continue
		}
		switch character {
		case '"':
			inString = true
		case ' ', '\t', '\n', '\r':
			t.Fatalf("%s: whitespace at byte %d outside a string", label, index)
		}
	}
	if inString {
		t.Fatalf("%s: unterminated JSON string", label)
	}
}

// a201RequireDigestLine checks the digest artifact grammar: ASCII
// "sha256:" + 64 lowercase hex digits + exactly one trailing LF.
func a201RequireDigestLine(t *testing.T, label string, digest []byte) {
	t.Helper()
	if !bytes.HasSuffix(digest, []byte("\n")) {
		t.Fatalf("%s: the digest line must end with one LF", label)
	}
	line := digest[:len(digest)-1]
	if bytes.ContainsAny(line, "\n\r") {
		t.Fatalf("%s: the digest artifact must hold exactly one line", label)
	}
	if !a201IsSha256(string(line)) {
		t.Fatalf("%s = %q, want sha256: plus 64 lowercase hex digits", label, line)
	}
}

// TestA201ObservationCanonicalProjection is handoff §4.6 point 7: null is not
// [], a container produces one image, a non-empty imageID produces exactly one
// container_status.image_id item, and the contractual orders of the wire hold.
func TestA201ObservationCanonicalProjection(t *testing.T) {
	knownWarningCodes := map[string]bool{
		"uid_changed": true, "scope_mismatch": true, "partial_observation": true,
		"stale_observation": true, "source_conflict": true, "redaction_applied": true,
		"tool_failure": true,
	}
	validClasses := map[string]bool{"regular": true, "init": true, "ephemeral": true}

	for _, testCase := range a201GoldenCases() {
		t.Run(testCase.name, func(t *testing.T) {
			document := a201GoldenFile(t, testCase.name, "podlist.json")
			context := a201Context(t, a201ObservedMoment, testCase.termination)
			parsed := a201Parse(t, string(document), context)
			observation := a201Normalize(t, parsed)
			if len(observation.Subjects) != 1 {
				t.Fatalf("subjects = %d, want one", len(observation.Subjects))
			}
			built, _ := a201Build(t, observation, 0)
			artifacts, err := bundle.Encode(built)
			if err != nil {
				t.Fatalf("encode: %v", err)
			}
			var members map[string]json.RawMessage
			if err := json.Unmarshal(artifacts.Envelope, &members); err != nil {
				t.Fatalf("envelope: %v", err)
			}
			var provenance map[string]json.RawMessage
			if err := json.Unmarshal(members["provenance"], &provenance); err != nil {
				t.Fatalf("provenance: %v", err)
			}

			// Arrays are never null and the two nullable collections are explicitly
			// null: coverage.rows stays null for a container observation.
			for _, key := range []string{"images", "evidence", "observed_container_classes"} {
				a201RequireJSONArray(t, testCase.name+"."+key, members[key])
			}
			for _, key := range []string{"argv_sanitized", "inputs", "warnings", "errors"} {
				a201RequireJSONArray(t, testCase.name+".provenance."+key, provenance[key])
			}
			a201RequireJSONNull(t, testCase.name+".provenance.ruleset", provenance["ruleset"])
			var coverage map[string]json.RawMessage
			if err := json.Unmarshal(provenance["coverage"], &coverage); err != nil {
				t.Fatalf("coverage: %v", err)
			}
			a201RequireJSONNull(t, testCase.name+".coverage.rows", coverage["rows"])
			var apiScope map[string]json.RawMessage
			if err := json.Unmarshal(provenance["api_scope"], &apiScope); err != nil {
				t.Fatalf("api_scope: %v", err)
			}
			for _, key := range []string{"namespaces", "verbs", "resources"} {
				a201RequireJSONArray(t, testCase.name+".api_scope."+key, apiScope[key])
			}

			// Every image carries a conservative identity: no digest, no inferred
			// platform, and every optional member present as null or a value.
			var images []map[string]json.RawMessage
			if err := json.Unmarshal(members["images"], &images); err != nil {
				t.Fatalf("images: %v", err)
			}
			for index, image := range images {
				a201RequireJSONNull(t, testCase.name+".images[].normalized_digest", image["normalized_digest"])
				var platform map[string]json.RawMessage
				if err := json.Unmarshal(image["platform"], &platform); err != nil {
					t.Fatalf("platform: %v", err)
				}
				a201RequireJSONNull(t, testCase.name+".platform.os", platform["os"])
				a201RequireJSONNull(t, testCase.name+".platform.architecture", platform["architecture"])
				if string(bytes.TrimSpace(platform["status"])) != `"unknown"` {
					t.Fatalf("image %d platform status = %s, want unknown", index, platform["status"])
				}
			}

			// Multiplicities, derived from the normalized DTO and contrasted with
			// the case table: one image per non-collided container and one evidence
			// item per non-empty imageID of a non-collided container.
			subject := observation.Subjects[0]
			wantImages, wantEvidence := 0, 0
			for _, container := range subject.Containers {
				if a201ContainerCollided(subject, container) {
					continue
				}
				wantImages++
				if container.ImageID != nil && *container.ImageID != "" {
					wantEvidence++
				}
			}
			if wantImages != testCase.images || wantEvidence != testCase.evidence {
				t.Fatalf("derived images/evidence = %d/%d, want the table %d/%d", wantImages, wantEvidence, testCase.images, testCase.evidence)
			}
			if len(built.Images) != wantImages || len(built.Evidence) != wantEvidence {
				t.Fatalf("projected images/evidence = %d/%d, want %d/%d", len(built.Images), len(built.Evidence), wantImages, wantEvidence)
			}
			for _, container := range subject.Containers {
				if a201ContainerCollided(subject, container) {
					continue
				}
				matches := 0
				for _, image := range built.Images {
					if image.ContainerClass == container.Class && string(image.ContainerName) == container.Name {
						matches++
					}
				}
				if matches != 1 {
					t.Fatalf("container %s/%s projects %d images, want exactly one", container.Class, container.Name, matches)
				}
				if container.ImageID == nil || *container.ImageID == "" {
					continue
				}
				items := 0
				for _, item := range built.Evidence {
					if item.Scope.ContainerName == contract.ContainerName(container.Name) && item.Type == "container_status.image_id" {
						items++
					}
				}
				if items != 1 {
					t.Fatalf("container %s/%s projects %d image_id items, want exactly one", container.Class, container.Name, items)
				}
			}

			// Contractual orders (wire §6): observed_container_classes is sorted
			// and deduplicated on the wire, images sort by class then name,
			// evidence by its scope tuple, and warning codes are the canonical
			// order of §4.5.
			for _, class := range built.ObservedContainerClasses {
				if !validClasses[string(class)] {
					t.Fatalf("observed class %q is outside the vocabulary", class)
				}
			}
			var wireClasses []string
			if err := json.Unmarshal(members["observed_container_classes"], &wireClasses); err != nil {
				t.Fatalf("observed_container_classes: %v", err)
			}
			if !reflect.DeepEqual(wireClasses, testCase.classes) {
				t.Fatalf("observed_container_classes = %q, want the canonical %q", wireClasses, testCase.classes)
			}
			a201RequireNonDecreasing(t, testCase.name+".images", a201ImageOrderKeys(built))
			a201RequireNonDecreasing(t, testCase.name+".evidence", a201EvidenceOrderKeys(built))
			view := a201EnvelopeViewOf(t, testCase.name, artifacts.Envelope)
			a201RequireWarningCodes(t, testCase.name, view.Provenance.Warnings, testCase.warnings)
			for _, warning := range view.Provenance.Warnings {
				if !knownWarningCodes[warning.Code] {
					t.Fatalf("warning code %q is not in the 0.2 vocabulary", warning.Code)
				}
				if warning.Class != "informational" && warning.Class != "contradictory" {
					t.Fatalf("warning class %q is not a wire class", warning.Class)
				}
				if strings.TrimSpace(warning.Message) == "" {
					t.Fatalf("warning %q carries an empty message", warning.Code)
				}
			}
		})
	}
}

// a201ContainerCollided reports whether one container key is omitted by an
// ADR-0010 §2 scope collision, using only the normalized DTO.
func a201ContainerCollided(subject normalize.ObservationSubject, container normalize.ObservationContainer) bool {
	for _, class := range subject.CollidedClasses[container.Name] {
		if class == container.Class {
			return true
		}
	}
	return false
}

func a201ImageOrderKeys(built contract.Bundle) []string {
	keys := make([]string, 0, len(built.Images))
	for _, image := range built.Images {
		keys = append(keys, string(image.ContainerClass)+"\x00"+string(image.ContainerName))
	}
	return keys
}

func a201EvidenceOrderKeys(built contract.Bundle) []string {
	keys := make([]string, 0, len(built.Evidence))
	for _, item := range built.Evidence {
		keys = append(keys, string(item.Scope.SubjectUID)+"\x00"+string(item.Scope.ContainerName)+"\x00"+
			item.Type+"\x00"+item.Source+"\x00"+string(item.Locator))
	}
	return keys
}

func a201RequireNonDecreasing(t *testing.T, label string, keys []string) {
	t.Helper()
	for index := 1; index < len(keys); index++ {
		if keys[index-1] > keys[index] {
			t.Fatalf("%s order = %q, want the canonical non-decreasing order", label, keys)
		}
	}
}

func a201RequireJSONArray(t *testing.T, label string, raw json.RawMessage) {
	t.Helper()
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 || trimmed[0] != '[' {
		t.Fatalf("%s = %s, want a JSON array (never null)", label, raw)
	}
}

func a201RequireJSONNull(t *testing.T, label string, raw json.RawMessage) {
	t.Helper()
	if string(bytes.TrimSpace(raw)) != "null" {
		t.Fatalf("%s = %s, want null", label, raw)
	}
}

// TestA201ObservationHash is handoff §4.6: the hash input is exactly the
// declared projection, its SHA-256 is the declared digest, and Encode refuses a
// zero bundle without producing bytes.
func TestA201ObservationHash(t *testing.T) {
	for _, testCase := range a201GoldenCases() {
		t.Run(testCase.name, func(t *testing.T) {
			_, artifacts := a201GoldenRun(t, testCase)
			envelope := a201GoldenFile(t, testCase.name, "bundle.json")
			if !bytes.Equal(artifacts.Envelope, envelope) {
				t.Fatal("the encoded envelope diverges from the frozen bundle.json")
			}
			oracle := a201ProjectionOracle(t, envelope)
			if !bytes.Equal(oracle, artifacts.HashInput) {
				t.Fatalf("oracle projection (%d bytes) differs from the encoded hash input (%d bytes)",
					len(oracle), len(artifacts.HashInput))
			}
			if got := a201OracleDigest(oracle); got != artifacts.Hash {
				t.Fatalf("oracle digest = %q, want the declared %q", got, artifacts.Hash)
			}
			if got := a201OracleDigest(artifacts.HashInput); got != artifacts.Hash {
				t.Fatalf("SHA-256 over the hash input = %q, want %q", got, artifacts.Hash)
			}
			frozen := a201GoldenFile(t, testCase.name, "bundle.hash-input.json")
			if !bytes.Equal(oracle, frozen) {
				t.Fatal("the oracle projection differs from the frozen bundle.hash-input.json")
			}
		})
	}

	t.Run("a zero bundle yields an error and no bytes", func(t *testing.T) {
		artifacts, err := bundle.Encode(contract.Bundle{})
		if err == nil {
			t.Fatal("Encode must refuse a zero bundle")
		}
		if len(artifacts.Envelope) != 0 || len(artifacts.HashInput) != 0 || artifacts.Hash != "" {
			t.Fatalf("a refused bundle produced artifacts: %+v", artifacts)
		}
	})
}

// TestA201ObservationDeterminism is handoff §4.6: the same source and context
// produce exactly the same three artifacts, and an internal permutation that
// preserves provenance canonicalizes to the same artifacts.
//
// Permuting the bytes of the JSON document is deliberately not covered by that
// equality: a different byte order changes source_hash and can change the
// locators, so the bundle hash changes and no equality may be demanded
// (ADR-0025 A.12.5). The control below only asserts that the source hash
// changes, never that the artifacts match.
func TestA201ObservationDeterminism(t *testing.T) {
	document := string(a201GoldenFile(t, "complete", "podlist.json"))
	context := a201Context(t, a201ObservedMoment, contract.TerminationFinished)

	t.Run("the same source and context reproduce the three artifacts", func(t *testing.T) {
		first, firstArtifacts := a201PipelineArtifacts(t, document, context)
		second, secondArtifacts := a201PipelineArtifacts(t, document, context)
		if !reflect.DeepEqual(firstArtifacts, secondArtifacts) {
			t.Fatal("two runs over the same source and context produced different artifacts")
		}
		if string(first.Evidence[0].SourceHash) != string(second.Evidence[0].SourceHash) {
			t.Fatal("the source hash of the same bytes must be identical")
		}
	})

	t.Run("an internal permutation that preserves provenance canonicalizes alike", func(t *testing.T) {
		_, baseArtifacts := a201PipelineArtifacts(t, document, context)
		parsed := a201Parse(t, document, context)
		observation := a201Normalize(t, parsed)
		built, _ := a201Build(t, observation, 0)
		envelope, err := bundle.Encode(built)
		if err != nil {
			t.Fatalf("encode: %v", err)
		}
		if !bytes.Equal(envelope.Envelope, baseArtifacts.Envelope) {
			t.Fatal("the same input must produce the same envelope")
		}
		// The container slice of the DTO carries the status indexes; permuting its
		// order changes nothing else. The canonical sort fixes the artifact order
		// and the locators ride with each container, so the artifacts stay equal.
		reversed := append([]normalize.ObservationContainer(nil), observation.Subjects[0].Containers...)
		for left, right := 0, len(reversed)-1; left < right; left, right = left+1, right-1 {
			reversed[left], reversed[right] = reversed[right], reversed[left]
		}
		observation.Subjects[0].Containers = reversed
		permuted, _ := a201Build(t, observation, 0)
		permutedArtifacts, err := bundle.Encode(permuted)
		if err != nil {
			t.Fatalf("encode permuted: %v", err)
		}
		if !reflect.DeepEqual(permutedArtifacts, baseArtifacts) {
			t.Fatal("an internal permutation that preserves provenance must canonicalize to the same artifacts")
		}
	})

	t.Run("reordering the JSON bytes changes the source hash", func(t *testing.T) {
		reordered := strings.Replace(document,
			`{"apiVersion":"v1","kind":"PodList"`,
			`{"kind":"PodList","apiVersion":"v1"`, 1)
		if reordered == document {
			t.Fatal("the key-order control must differ in bytes")
		}
		base, _ := a201PipelineArtifacts(t, document, context)
		other, _ := a201PipelineArtifacts(t, reordered, context)
		if len(base.Evidence) != 1 || len(other.Evidence) != 1 {
			t.Fatal("both documents must carry one evidence item")
		}
		if base.Evidence[0].SourceHash == other.Evidence[0].SourceHash {
			t.Fatal("a different byte order must produce a different source hash")
		}
		if base.Evidence[0].Value == nil || other.Evidence[0].Value == nil || *base.Evidence[0].Value != *other.Evidence[0].Value {
			t.Fatal("the decoded value must be the same in both orders")
		}
	})
}

// a201PipelineArtifacts runs one document through the whole pipeline and returns
// the built bundle and its encoded artifacts.
func a201PipelineArtifacts(t *testing.T, document string, context ingest.PodListContext) (contract.Bundle, bundle.Artifacts) {
	t.Helper()
	parsed := a201Parse(t, document, context)
	observation := a201Normalize(t, parsed)
	built, _ := a201Build(t, observation, 0)
	artifacts, err := bundle.Encode(built)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	return built, artifacts
}

// TestA201OperationalMetadataHash is handoff §4.6: the operational metadata
// excluded by ADR-0006 §1(a) changes the envelope but never the projection nor
// the digest, while a different source or observation time does change both.
func TestA201OperationalMetadataHash(t *testing.T) {
	document := a201GoldenFile(t, "complete", "podlist.json")
	context := a201Context(t, a201ObservedMoment, contract.TerminationFinished)
	parsed := a201Parse(t, string(document), context)
	observation := a201Normalize(t, parsed)

	baseInput := a201ObservationInput(observation, 0)
	baseBuilt, _, err := bundle.BuildObservation(baseInput)
	if err != nil {
		t.Fatalf("build base: %v", err)
	}
	baseArtifacts, err := bundle.Encode(baseBuilt)
	if err != nil {
		t.Fatalf("encode base: %v", err)
	}

	variant := baseInput
	started := a201Stamp(t, "2026-09-30T11:59:00Z")
	ended := a201Stamp(t, "2026-09-30T12:00:30Z")
	variant.StartedAt = &started
	variant.EndedAt = &ended
	variant.Budget = contract.Budget{WallClock: "1m30s", Requests: 12, Objects: 3, Bytes: 4096}
	// The collector identification is fixed by A.9.4: a caller-supplied label
	// must not replace it as provenance, so the variant is refused before the
	// hash is compared.
	variant.CollectorLabel = "operator-export-revision-2"
	if _, _, err := bundle.BuildObservation(variant); err == nil {
		t.Fatal("a caller-supplied collector label replaced the fixed identification")
	}
	variant.CollectorLabel = a201Collector
	variant.ParserVersion = "sanitized-podlist-v1/1.0+build2"
	variantBuilt, _, err := bundle.BuildObservation(variant)
	if err != nil {
		t.Fatalf("build variant: %v", err)
	}
	variantArtifacts, err := bundle.Encode(variantBuilt)
	if err != nil {
		t.Fatalf("encode variant: %v", err)
	}
	if variantArtifacts.Hash != baseArtifacts.Hash {
		t.Fatalf("hash changed with operational metadata: %q vs %q", variantArtifacts.Hash, baseArtifacts.Hash)
	}
	if !bytes.Equal(variantArtifacts.HashInput, baseArtifacts.HashInput) {
		t.Fatal("the projection must not change with operational metadata")
	}
	if bytes.Equal(variantArtifacts.Envelope, baseArtifacts.Envelope) {
		t.Fatal("the excluded metadata must still appear in the full envelope")
	}
	for _, excluded := range []string{"collector_version", "parser_version", "argv_sanitized", "started_at", "ended_at", "budget"} {
		if bytes.Contains(baseArtifacts.HashInput, []byte(excluded)) {
			t.Fatalf("the projection must not carry the excluded member %q", excluded)
		}
	}

	t.Run("another source changes the hash", func(t *testing.T) {
		otherDocument := strings.Replace(string(document), "uid-0001", "uid-0002", 1)
		if otherDocument == string(document) {
			t.Fatal("the source control must differ in bytes")
		}
		otherParsed := a201Parse(t, otherDocument, context)
		otherObservation := a201Normalize(t, otherParsed)
		otherBuilt, _ := a201Build(t, otherObservation, 0)
		otherArtifacts, err := bundle.Encode(otherBuilt)
		if err != nil {
			t.Fatalf("encode other source: %v", err)
		}
		if otherArtifacts.Hash == baseArtifacts.Hash {
			t.Fatal("a different source must change the bundle hash")
		}
	})

	t.Run("another observation time changes the hash", func(t *testing.T) {
		// The time travels with the export that declared it: the same document
		// under another declared instant is another observation and changes the
		// projection. An instant substituted on the call is refused instead, so
		// the retained value can only come from the source context.
		shiftedContext := a201Context(t, "2026-09-30T13:00:00Z", contract.TerminationFinished)
		_, shiftedArtifacts := a201PipelineArtifacts(t, string(document), shiftedContext)
		if shiftedArtifacts.Hash == baseArtifacts.Hash {
			t.Fatal("a different observation time must change the bundle hash")
		}
		shiftedInput := a201ObservationInput(observation, 0)
		substituted := a201Stamp(t, "2026-09-30T13:00:00Z")
		shiftedInput.ObservedAt = &substituted
		if _, _, err := bundle.BuildObservation(shiftedInput); err == nil {
			t.Fatal("a substituted observation time was accepted")
		}
	})
}

// a201Stamp converts a literal UTC instant into the declared timestamp type.
func a201Stamp(t *testing.T, moment string) contract.Timestamp {
	t.Helper()
	stamp, err := contract.NewTimestamp(a201ObservedAt(t, moment))
	if err != nil {
		t.Fatalf("timestamp %q: %v", moment, err)
	}
	return stamp
}

// a201ProjectionOracle rebuilds the ADR-0006 §1(a) hash projection from the
// canonical envelope with encoding/json alone: generic maps of raw messages,
// the six envelope members and the nine projected provenance members selected
// in their contractual order, and the ruleset reduced to path and hash. It
// never calls CanonicalJSON, HashCanonicalJSON, Encode or a private helper of
// the packages under test.
func a201ProjectionOracle(t *testing.T, envelope []byte) []byte {
	t.Helper()
	var members map[string]json.RawMessage
	if err := json.Unmarshal(envelope, &members); err != nil {
		t.Fatalf("oracle: the envelope is not a JSON object: %v", err)
	}
	var buffer bytes.Buffer
	buffer.WriteByte('{')
	for index, key := range []string{"schema_version", "subject", "images", "evidence", "observed_container_classes"} {
		raw, found := members[key]
		if !found {
			t.Fatalf("oracle: the envelope has no %q member", key)
		}
		a201WriteMember(&buffer, key, raw, index > 0)
	}
	provenanceRaw, found := members["provenance"]
	if !found {
		t.Fatal("oracle: the envelope has no provenance member")
	}
	var provenance map[string]json.RawMessage
	if err := json.Unmarshal(provenanceRaw, &provenance); err != nil {
		t.Fatalf("oracle: provenance is not a JSON object: %v", err)
	}
	rulesetRaw, found := provenance["ruleset"]
	if !found {
		t.Fatal("oracle: provenance has no ruleset member")
	}
	reduced := rulesetRaw
	if string(bytes.TrimSpace(rulesetRaw)) != "null" {
		var ruleset map[string]json.RawMessage
		if err := json.Unmarshal(rulesetRaw, &ruleset); err != nil {
			t.Fatalf("oracle: ruleset is not a JSON object: %v", err)
		}
		path, hasPath := ruleset["path"]
		hash, hasHash := ruleset["hash"]
		if !hasPath || !hasHash {
			t.Fatal("oracle: a non-null ruleset needs path and hash")
		}
		var reducedBuffer bytes.Buffer
		reducedBuffer.WriteByte('{')
		a201WriteMember(&reducedBuffer, "path", path, false)
		a201WriteMember(&reducedBuffer, "hash", hash, true)
		reducedBuffer.WriteByte('}')
		reduced = reducedBuffer.Bytes()
	}
	buffer.WriteString(`,"provenance":{`)
	for index, key := range []string{"ruleset", "inputs", "api_scope", "coverage", "completeness", "consistency", "redaction_policy", "warnings", "errors"} {
		raw := provenance[key]
		if key == "ruleset" {
			raw = reduced
		}
		if len(raw) == 0 {
			t.Fatalf("oracle: provenance has no %q member", key)
		}
		a201WriteMember(&buffer, key, raw, index > 0)
	}
	buffer.WriteString("}}")
	return buffer.Bytes()
}

func a201WriteMember(buffer *bytes.Buffer, key string, raw []byte, comma bool) {
	if comma {
		buffer.WriteByte(',')
	}
	buffer.WriteByte('"')
	buffer.WriteString(key)
	buffer.WriteString(`":`)
	buffer.Write(raw)
}

// a201OracleDigest is the independent digest oracle: crypto/sha256 over the
// projection bytes plus encoding/hex, with the wire prefix.
func a201OracleDigest(projection []byte) string {
	digest := sha256.Sum256(projection)
	return "sha256:" + hex.EncodeToString(digest[:])
}
