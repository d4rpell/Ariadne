package bundle_test

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/d4rpell/Ariadne/internal/bundle"
	contract "github.com/d4rpell/Ariadne/pkg/evidence"
)

// AX-04 group A, container-observation cases (F01, F05, F06, F07). Each case
// travels the real pipeline (parse -> normalize -> build -> Encode) and is
// contrasted byte by byte with the frozen artifacts committed under
// fixtures/<fixture>/0.2/<case>/expected/. Every expectation is written
// literally from ADR-0006 §5, ADR-0009/0010, ADR-0025 A.7.4/A.9 and the A0-04
// matrix; nothing is read from a production table. Fixtures are synthetic
// throughout.
//
// What these tests accredit: the exact bytes of each case, the projection
// membership and order, the digest boundary, and the invariant each case
// declares. What they do not accredit: any real capture, cluster or sanitizer,
// a monitor/timeline for F06, and real stale-status detection for F07.

const ax04COFixtureF01 = "F01-pod-uid-replacement"
const ax04COFixtureF05 = "F05-init-and-sidecar"
const ax04COFixtureF06 = "F06-ephemeral-added-later"
const ax04COFixtureF07 = "F07-stale-status"

// ax04COCase is one frozen container-observation case: its fixture directory,
// the constructor that produces the bundle through the real pipeline, and the
// discriminating assertions of the invariant it carries.
type ax04COCase struct {
	name    string
	fixture string
	build   func(t *testing.T) contract.Bundle
	assert  func(t *testing.T, built contract.Bundle)
}

// ax04CODocument runs parse -> normalize -> build over one document and one
// subject index.
func ax04CODocument(t *testing.T, document string, subjectIndex int) contract.Bundle {
	t.Helper()
	context := a201Context(t, a201ObservedMoment, contract.TerminationFinished)
	parsed := a201Parse(t, document, context)
	observation := a201Normalize(t, parsed)
	built, _ := a201Build(t, observation, subjectIndex)
	return built
}

func ax04COCases() []ax04COCase {
	return []ax04COCase{
		{
			// F01: two Pods sharing namespace/name with different UIDs stay
			// separate; neither is merged and the container change per subject is
			// preserved. The conflict is declared because the document carries two
			// conflicting Pod identities, not because a UID changed over time.
			name:    "uid-a",
			fixture: ax04COFixtureF01,
			build: func(t *testing.T) contract.Bundle {
				return ax04CODocument(t, ax04F01Document(), 0)
			},
			assert: func(t *testing.T, built contract.Bundle) {
				if string(built.Subject.UID) != "uid-0001" {
					t.Fatalf("subject uid = %q, want uid-0001", built.Subject.UID)
				}
				if built.Subject.Name != "payments-api" {
					t.Fatalf("subject name = %q, want payments-api", built.Subject.Name)
				}
				if len(built.Images) != 1 || string(built.Images[0].ContainerName) != "api" {
					t.Fatalf("images = %+v, want only the api container of uid-0001", built.Images)
				}
				if !a201HasWarning(built, "source_conflict", contract.WarningContradictory) {
					t.Fatalf("warnings = %+v, want source_conflict on the conflicting document", built.Provenance.Warnings)
				}
				if !ax04HasErrorSuffix(built, "source contains conflicting Pod identity context") {
					t.Fatalf("errors = %v, want the subject_context_conflict diagnostic", built.Provenance.Errors)
				}
				ax04AssertEvidenceScope(t, built, "uid-0001", "api")
			},
		},
		{
			name:    "uid-b",
			fixture: ax04COFixtureF01,
			build: func(t *testing.T) contract.Bundle {
				return ax04CODocument(t, ax04F01Document(), 1)
			},
			assert: func(t *testing.T, built contract.Bundle) {
				if string(built.Subject.UID) != "uid-0002" {
					t.Fatalf("subject uid = %q, want uid-0002", built.Subject.UID)
				}
				if built.Subject.Name != "payments-api" {
					t.Fatalf("subject name = %q, want payments-api", built.Subject.Name)
				}
				if len(built.Images) != 1 || string(built.Images[0].ContainerName) != "worker" {
					t.Fatalf("images = %+v, want only the worker container of uid-0002", built.Images)
				}
				if built.Evidence[0].Scope.SubjectUID != "uid-0002" {
					t.Fatalf("evidence scope uid = %q, want uid-0002 (no crossed evidence)", built.Evidence[0].Scope.SubjectUID)
				}
				if !a201HasWarning(built, "source_conflict", contract.WarningContradictory) {
					t.Fatalf("warnings = %+v, want source_conflict on the conflicting document", built.Provenance.Warnings)
				}
				ax04AssertEvidenceScope(t, built, "uid-0002", "worker")
			},
		},
		{
			// F05: regular, init and ephemeral are inventoried as separate
			// categories; an explicitly empty ephemeral array is an observed
			// category, never an absent one. The init container keeps its own
			// status.
			name:    "three-classes",
			fixture: ax04COFixtureF05,
			build: func(t *testing.T) contract.Bundle {
				spec := a201Spec(
					a201Array(a201SpecContainer("api", a201DefaultImage)),
					a201Array(a201SpecContainer("init-setup", "registry.example/init:release")),
					a201EmptyArray(),
				)
				status := a201StatusArrays(
					a201Array(a201StatusContainer("api", a201ImageID)),
					a201Array(a201StatusContainer("init-setup", a201ImageIDOther)),
					a201EmptyArray(),
				)
				document := a201List(a201PodWithStatus("uid-0001", "payments-api", spec, status))
				return ax04CODocument(t, document, 0)
			},
			assert: func(t *testing.T, built contract.Bundle) {
				// The three categories are exactly present, with no duplicate and
				// none missing: a length check alone would accept a repeated class.
				counts := map[contract.ContainerClass]int{}
				for _, class := range built.ObservedContainerClasses {
					counts[class]++
				}
				if len(counts) != 3 ||
					counts[contract.ContainerRegular] != 1 ||
					counts[contract.ContainerInit] != 1 ||
					counts[contract.ContainerEphemeral] != 1 {
					t.Fatalf("observed classes = %v, want exactly regular/init/ephemeral once each", built.ObservedContainerClasses)
				}
				if len(built.Images) != 2 {
					t.Fatalf("images = %d, want the regular and the init container", len(built.Images))
				}
				var initImage *contract.ImageIdentity
				for index := range built.Images {
					if built.Images[index].ContainerClass == contract.ContainerInit {
						initImage = &built.Images[index]
					}
				}
				if initImage == nil || string(initImage.ContainerName) != "init-setup" {
					t.Fatalf("init image = %+v, want the init container bound to its own status", initImage)
				}
				if initImage.RawImageID == nil || string(*initImage.RawImageID) != a201ImageIDOther {
					t.Fatalf("init raw image id = %v, want its own status value", initImage.RawImageID)
				}
			},
		},
		{
			// F05: two regular containers with distinct names are two images of
			// class regular. There is no "sidecar" class in the vocabulary.
			name:    "sidecar-is-regular",
			fixture: ax04COFixtureF05,
			build: func(t *testing.T) contract.Bundle {
				spec := a201Spec(
					a201Array(a201SpecContainer("api", a201DefaultImage), a201SpecContainer("sidecar", "registry.example/sidecar:release")),
					a201EmptyArray(),
					a201EmptyArray(),
				)
				status := a201StatusArrays(
					a201Array(a201StatusContainer("api", a201ImageID), a201StatusContainer("sidecar", a201ImageIDOther)),
					a201EmptyArray(),
					a201EmptyArray(),
				)
				document := a201List(a201PodWithStatus("uid-0001", "payments-api", spec, status))
				return ax04CODocument(t, document, 0)
			},
			assert: func(t *testing.T, built contract.Bundle) {
				if len(built.Images) != 2 {
					t.Fatalf("images = %d, want two regular containers", len(built.Images))
				}
				names := map[string]bool{}
				for _, image := range built.Images {
					if image.ContainerClass != contract.ContainerRegular {
						t.Fatalf("class = %q, want regular (no sidecar class exists)", image.ContainerClass)
					}
					names[string(image.ContainerName)] = true
				}
				if !names["api"] || !names["sidecar"] {
					t.Fatalf("names = %v, want api and sidecar as distinct regular containers", names)
				}
				for _, class := range built.ObservedContainerClasses {
					if class != contract.ContainerRegular && class != contract.ContainerInit && class != contract.ContainerEphemeral {
						t.Fatalf("observed class %q is outside the closed vocabulary", class)
					}
				}
			},
		},
		{
			// F05: the same container name in two classes cannot be distinguished
			// by the wire scope, so the collided key is omitted visibly; the
			// healthy container of the subject survives and completeness drops to
			// partial.
			name:    "collision-refused",
			fixture: ax04COFixtureF05,
			build: func(t *testing.T) contract.Bundle {
				spec := a201Spec(
					a201Array(a201SpecContainer("api", a201DefaultImage), a201SpecContainer("sidecar", "registry.example/sidecar:release")),
					a201Array(a201SpecContainer("api", "registry.example/init:release")),
					a201EmptyArray(),
				)
				status := a201StatusArrays(
					a201Array(a201StatusContainer("api", a201ImageID), a201StatusContainer("sidecar", a201ImageIDOther)),
					a201Array(a201StatusContainer("api", a201ImageIDOther)),
					a201EmptyArray(),
				)
				document := a201List(a201PodWithStatus("uid-0001", "payments-api", spec, status))
				return ax04CODocument(t, document, 0)
			},
			assert: func(t *testing.T, built contract.Bundle) {
				if len(built.Images) != 1 || string(built.Images[0].ContainerName) != "sidecar" {
					t.Fatalf("images = %+v, want only the healthy sidecar container", built.Images)
				}
				if built.Provenance.Completeness != contract.CompletenessPartial {
					t.Fatalf("completeness = %q, want partial", built.Provenance.Completeness)
				}
				if !a201HasError(built, "bundle: scope collision omitted") {
					t.Fatalf("errors = %v, want the scope collision diagnostic", built.Provenance.Errors)
				}
			},
		},
		{
			// F06 first capture: an explicitly empty ephemeral array is an
			// observed category. It proves nothing about the future.
			name:    "first-empty",
			fixture: ax04COFixtureF06,
			build: func(t *testing.T) contract.Bundle {
				return ax04F06Capture(t, true)
			},
			assert: func(t *testing.T, built contract.Bundle) {
				observed := false
				for _, class := range built.ObservedContainerClasses {
					if class == contract.ContainerEphemeral {
						observed = true
					}
				}
				if !observed {
					t.Fatalf("observed classes = %v, want ephemeral observed as explicitly empty", built.ObservedContainerClasses)
				}
				for _, image := range built.Images {
					if image.ContainerClass == contract.ContainerEphemeral {
						t.Fatalf("images = %+v, want no ephemeral container in the first capture", built.Images)
					}
				}
			},
		},
		{
			// F06 second capture: the ephemeral container and its status are
			// incorporated; source hash and observed_at belong to this capture.
			name:    "second-added",
			fixture: ax04COFixtureF06,
			build: func(t *testing.T) contract.Bundle {
				return ax04F06Capture(t, false)
			},
			assert: func(t *testing.T, built contract.Bundle) {
				var debug *contract.ImageIdentity
				for index := range built.Images {
					if built.Images[index].ContainerName == "debug" {
						debug = &built.Images[index]
					}
				}
				if debug == nil {
					t.Fatalf("images = %+v, want the ephemeral container with its status", built.Images)
				}
				if debug.ContainerClass != contract.ContainerEphemeral {
					t.Fatalf("class = %q, want ephemeral", debug.ContainerClass)
				}
				if debug.RawImageID == nil || string(*debug.RawImageID) != a201ImageIDOther {
					t.Fatalf("ephemeral raw image id = %v, want its own status value", debug.RawImageID)
				}
				if got := built.Evidence[0].ObservedAt.UTC().Format("2006-01-02T15:04:05Z"); got != "2026-09-30T14:00:00Z" {
					t.Fatalf("observed_at = %q, want this capture's declared instant", got)
				}
				// The two captures are independent: different source bytes, hence
				// different source hashes, and the second instant is strictly later
				// than the first.
				first := ax04F06Capture(t, true)
				if first.Evidence[0].SourceHash == built.Evidence[0].SourceHash {
					t.Fatal("the two captures must keep their own source hash")
				}
				if !first.Evidence[0].ObservedAt.UTC().Before(built.Evidence[0].ObservedAt.UTC()) {
					t.Fatalf("the second capture (%s) must be strictly later than the first (%s)",
						built.Evidence[0].ObservedAt.UTC().Format("2006-01-02T15:04:05Z"),
						first.Evidence[0].ObservedAt.UTC().Format("2006-01-02T15:04:05Z"))
				}
			},
		},
		{
			// F07: two captures of the same namespace/name whose UID and
			// resourceVersion changed. Each keeps its own identity, instant and
			// resourceVersion, and no evidence crosses between them. This is the
			// observable slice of F07; real stale-status detection is not claimed.
			name:    "reread-uid-changed",
			fixture: ax04COFixtureF07,
			build: func(t *testing.T) contract.Bundle {
				return ax04F07Capture(t, "uid-0002", "rv-8", a201ImageIDOther, "2026-09-30T11:00:00Z")
			},
			assert: func(t *testing.T, built contract.Bundle) {
				previous := ax04F07Capture(t, "uid-0001", "rv-7", a201ImageID, "2026-09-30T10:00:00Z")
				if string(built.Subject.UID) != "uid-0002" {
					t.Fatalf("subject uid = %q, want uid-0002 (no mixing with the previous capture)", built.Subject.UID)
				}
				if string(previous.Subject.UID) != "uid-0001" {
					t.Fatalf("previous uid = %q, want uid-0001", previous.Subject.UID)
				}
				if built.Subject.UID == previous.Subject.UID {
					t.Fatal("the UID change must separate the two captures")
				}
				if got := built.Evidence[0].ObservedAt.UTC().Format("2006-01-02T15:04:05Z"); got != "2026-09-30T11:00:00Z" {
					t.Fatalf("observed_at = %q, want this capture's declared instant", got)
				}
				if !previous.Evidence[0].ObservedAt.UTC().Before(built.Evidence[0].ObservedAt.UTC()) {
					t.Fatal("the re-read must be strictly later than the first capture")
				}
				ax04AssertEvidenceScope(t, previous, "uid-0001", "api")
				ax04AssertEvidenceScope(t, built, "uid-0002", "api")
			},
		},
	}
}

// ax04F01Document is the F01 source: two Pods sharing namespace/name with
// different UIDs and different containers, in one document.
func ax04F01Document() string {
	firstSpec := a201Spec(a201Array(a201SpecContainer("api", a201DefaultImage)), a201EmptyArray(), a201EmptyArray())
	firstStatus := a201StatusArrays(a201Array(a201StatusContainer("api", a201ImageID)), a201EmptyArray(), a201EmptyArray())
	secondSpec := a201Spec(a201Array(a201SpecContainer("worker", a201DefaultImage)), a201EmptyArray(), a201EmptyArray())
	secondStatus := a201StatusArrays(a201Array(a201StatusContainer("worker", a201ImageIDOther)), a201EmptyArray(), a201EmptyArray())
	return a201List(
		a201PodWithStatus("uid-0001", "payments-api", firstSpec, firstStatus),
		a201PodWithStatus("uid-0002", "payments-api", secondSpec, secondStatus),
	)
}

// ax04F06Capture builds the F06 first capture (empty = true, observed at
// 2026-09-30T10:00:00Z) or the second one (empty = false, with the ephemeral
// container, observed at 2026-09-30T14:00:00Z). The two captures have different
// source bytes, so their source hashes differ.
func ax04F06Capture(t *testing.T, empty bool) contract.Bundle {
	t.Helper()
	moment := "2026-09-30T14:00:00Z"
	spec := a201Spec(a201Array(a201SpecContainer("api", a201DefaultImage)), a201EmptyArray(), a201Array(a201SpecContainer("debug", a201DefaultImage)))
	status := a201StatusArrays(a201Array(a201StatusContainer("api", a201ImageID)), a201EmptyArray(), a201Array(a201StatusContainer("debug", a201ImageIDOther)))
	if empty {
		moment = "2026-09-30T10:00:00Z"
		spec = a201Spec(a201Array(a201SpecContainer("api", a201DefaultImage)), a201EmptyArray(), a201EmptyArray())
		status = a201StatusArrays(a201Array(a201StatusContainer("api", a201ImageID)), a201EmptyArray(), a201EmptyArray())
	}
	document := a201List(a201PodWithStatus("uid-0001", "payments-api", spec, status))
	context := a201Context(t, moment, contract.TerminationFinished)
	parsed := a201Parse(t, document, context)
	observation := a201Normalize(t, parsed)
	built, _ := a201Build(t, observation, 0)
	return built
}

// ax04F07Capture builds one F07 capture with its own UID, resourceVersion,
// image id and instant.
func ax04F07Capture(t *testing.T, uid, resourceVersion, imageID, moment string) contract.Bundle {
	t.Helper()
	spec := a201Spec(a201Array(a201SpecContainer("api", a201DefaultImage)), a201EmptyArray(), a201EmptyArray())
	status := a201StatusArrays(a201Array(a201StatusContainer("api", imageID)), a201EmptyArray(), a201EmptyArray())
	document := a201List(a201PodWithResourceVersion(uid, "payments-api", resourceVersion, spec, status))
	context := a201Context(t, moment, contract.TerminationFinished)
	parsed := a201Parse(t, document, context)
	observation := a201Normalize(t, parsed)
	// The capture's own resourceVersion must survive normalization; a capture
	// that lost it could not be contrasted with the other.
	if observation.Subjects[0].ResourceVersion != resourceVersion {
		t.Fatalf("resourceVersion = %q, want %q for uid %s", observation.Subjects[0].ResourceVersion, resourceVersion, uid)
	}
	built, _ := a201Build(t, observation, 0)
	return built
}

// ax04COGoldenDir is the committed artifact directory of one group A case.
func ax04COGoldenDir(fixture, name string) string {
	return filepath.Join("..", "..", "fixtures", fixture, "0.2", name, "expected")
}

// ax04CompareTriplet pins the committed triplet to the constructor of the case,
// rebuilds the projection with the independent oracle and recomputes the digest
// outside the production helpers.
func ax04CompareTriplet(t *testing.T, fixture, name string, built contract.Bundle) {
	t.Helper()
	dir := ax04COGoldenDir(fixture, name)
	envelope := ax04ReadGolden(t, dir, "bundle.json")
	projection := ax04ReadGolden(t, dir, "bundle.hash-input.json")
	sidecar := ax04ReadGolden(t, dir, "bundle.sha256")

	artifacts, err := bundle.Encode(built)
	if err != nil {
		t.Fatalf("%s/%s: encode: %v", fixture, name, err)
	}
	if !bytes.Equal(artifacts.Envelope, envelope) {
		t.Fatalf("%s/%s: the committed envelope is not the Encode output of this case's constructor", fixture, name)
	}
	if !bytes.Equal(artifacts.HashInput, projection) {
		t.Fatalf("%s/%s: the committed projection is not the Encode output of this case's constructor", fixture, name)
	}
	if artifacts.Hash+"\n" != string(sidecar) {
		t.Fatalf("%s/%s: the committed sidecar is not the Encode output of this case's constructor", fixture, name)
	}

	rebuilt := a201ProjectionOracle(t, envelope)
	if !bytes.Equal(rebuilt, projection) {
		t.Fatalf("%s/%s: the committed projection is not the reconstruction from the committed envelope", fixture, name)
	}
	if want := a201OracleDigest(projection); strings.TrimSuffix(string(sidecar), "\n") != want {
		t.Fatalf("%s/%s: digest = %q, want the independent sha256 of the projection", fixture, name, strings.TrimSuffix(string(sidecar), "\n"))
	}
	if built.SchemaVersion != "0.2" {
		t.Fatalf("%s/%s: schema_version = %q, want 0.2", fixture, name, built.SchemaVersion)
	}
}

func ax04ReadGolden(t *testing.T, dir, name string) []byte {
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

// ax04HasErrorSuffix reports whether one provenance error ends with the given
// diagnostic text: the ingest prefix carries a byte offset that is part of the
// frozen bytes but not of the assertion.
func ax04HasErrorSuffix(built contract.Bundle, suffix string) bool {
	for _, failure := range built.Provenance.Errors {
		if strings.HasSuffix(failure, suffix) {
			return true
		}
	}
	return false
}

// ax04AssertEvidenceScope requires EVERY evidence item to be scoped to the
// declared subject and container: a single crossed item is a contract bug, and
// checking only the first item would not exclude it.
func ax04AssertEvidenceScope(t *testing.T, built contract.Bundle, uid, container string) {
	t.Helper()
	if len(built.Evidence) == 0 {
		t.Fatal("the bundle carries no evidence to scope-check")
	}
	for index, item := range built.Evidence {
		if item.Scope.SubjectUID != contract.UID(uid) || string(item.Scope.ContainerName) != container {
			t.Fatalf("evidence[%d] scope = %s/%s, want %s/%s (crossed evidence)", index, item.Scope.SubjectUID, item.Scope.ContainerName, uid, container)
		}
	}
}

// TestAX04COFixtureGoldens is the group A suite: every case of the list is
// compared against its committed triplet and its own invariant is asserted.
func TestAX04COFixtureGoldens(t *testing.T) {
	cases := ax04COCases()
	if len(cases) != 8 {
		t.Fatalf("case inventory = %d, want 8 (a missing case must break this test)", len(cases))
	}
	for _, testCase := range cases {
		t.Run(testCase.fixture+"/"+testCase.name, func(t *testing.T) {
			built := testCase.build(t)
			// The semantic assertion runs first: a mutation of the projection is
			// attributed to the invariant it breaks, not to the byte comparison.
			testCase.assert(t, built)
			ax04CompareTriplet(t, testCase.fixture, testCase.name, built)
		})
	}
}

// TestAX04COFixtureInventory fails if a declared case directory is missing, so a
// deleted fixture cannot silently reduce coverage.
func TestAX04COFixtureInventory(t *testing.T) {
	for _, testCase := range ax04COCases() {
		dir := ax04COGoldenDir(testCase.fixture, testCase.name)
		for _, name := range []string{"bundle.json", "bundle.hash-input.json", "bundle.sha256"} {
			if _, err := os.Stat(filepath.Join(dir, name)); err != nil {
				t.Fatalf("%s/%s is not materialized: %v", testCase.fixture, testCase.name, err)
			}
		}
	}
}
