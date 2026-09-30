package bundle_test

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/d4rpell/Ariadne/internal/bundle"
	"github.com/d4rpell/Ariadne/internal/evaluator"
	"github.com/d4rpell/Ariadne/internal/ingest"
	"github.com/d4rpell/Ariadne/internal/normalize"
	"github.com/d4rpell/Ariadne/internal/rulepack"
	contract "github.com/d4rpell/Ariadne/pkg/evidence"
)

// Construction helpers of the A2-01 integration tests (ADR-0025 A.12/A.13 and
// handoff F1 §4.1/§4.5/§4.6). Every document, context and evaluation input is
// synthetic: the namespace, pods, images, timestamps and markers below are
// fabricated and no real cluster, customer or scanner data is used.
//
// The helpers only build inputs and observe outputs. Contract expectations are
// written literally inside each test from ADR-0025 A.3/A.9/A.10, never read
// from production tables.

const (
	a201Selector     = "sanitized-podlist-v1"
	a201Version      = "1.0"
	a201Policy       = "sanitized-podlist-v1/1.0"
	a201SourceName   = "sanitized-pods.json"
	a201ClusterAlias = "cluster-a"
	a201Namespace    = "payments"
	a201Collector    = "operator-export"
	a201Parser       = "sanitized-podlist-v1/1.0"

	a201DefaultImage = "registry.example/app:release"
	a201ImageID      = "sha256:" + "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	a201ImageIDOther = "sha256:" + "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"

	a201ObservedMoment = "2026-09-30T12:00:00Z"
)

// a201PackDocument is the admitted product profile pack of the conservative
// evaluation cases. It asks for a favourable "not_affected" conclusion, so the
// tests can prove that this producer never sustains one. The preference
// requirements and the terminal predicate are the profile vocabulary, not
// values read from a production table.
const a201PackDocument = `{"schema_version":"0.1","profile":"product-evidence-v1","pack_id":"pack.observations","version":1,` +
	`"valid_from":"2026-09-01T00:00:00Z","expires_at":"2026-12-31T23:59:59Z","rules":[` +
	`{"rule_id":"rule.code-excluded","selector":{"coverage_method":"container_observation","vulnerability_id":"CVE-2026-12345"},` +
	`"requires":["bundle.complete","finding.row","finding.package_type","finding.package_name","finding.package_id",` +
	`"image.bound_digest","image.known_platform","domain.mapping","domain.artifact","domain.vendor_proof","domain.current"],` +
	`"checks":[{"check_id":"check.terminal","predicate":"redhat_build_code_excluded","params":{}}],` +
	`"on_missing_evidence":"under_investigation","emit":"not_affected"}]}`

// a201IndependentHash is the independent SHA-256 oracle of the tests:
// crypto/sha256 over exact bytes plus encoding/hex, with the wire prefix. It
// never calls the production hashing helpers.
func a201IndependentHash(data []byte) string {
	digest := sha256.Sum256(data)
	return "sha256:" + hex.EncodeToString(digest[:])
}

// a201IsSha256 checks the digest grammar literally: the prefix plus 64
// lowercase hexadecimal digits.
func a201IsSha256(value string) bool {
	const prefix = "sha256:"
	if len(value) != len(prefix)+64 || !strings.HasPrefix(value, prefix) {
		return false
	}
	for index := len(prefix); index < len(value); index++ {
		digit := value[index]
		if (digit < '0' || digit > '9') && (digit < 'a' || digit > 'f') {
			return false
		}
	}
	return true
}

func a201ObservedAt(t *testing.T, moment string) time.Time {
	t.Helper()
	parsed, err := time.Parse(time.RFC3339, moment)
	if err != nil {
		t.Fatalf("parse timestamp %q: %v", moment, err)
	}
	if parsed.Location() != time.UTC {
		t.Fatalf("timestamp %q is not UTC", moment)
	}
	return parsed
}

// a201Context is the explicit observation context of ADR-0025 A.6. Every value
// is declared here; nothing is read from a clock, an mtime or a resource.
func a201Context(t *testing.T, moment string, termination contract.CoverageTermination) ingest.PodListContext {
	t.Helper()
	return ingest.PodListContext{
		Selector:           a201Selector,
		Version:            a201Version,
		RedactionPolicy:    a201Policy,
		SourceName:         a201SourceName,
		ClusterAlias:       a201ClusterAlias,
		Namespace:          a201Namespace,
		ObservedAt:         a201ObservedAt(t, moment),
		CaptureTermination: termination,
	}
}

// Document builders. The profile requires explicit arrays for the three spec
// and status categories, so every builder writes them explicitly.

func a201Array(items ...string) string {
	return "[" + strings.Join(items, ",") + "]"
}

func a201EmptyArray() string { return "[]" }

func a201SpecContainer(name, image string) string {
	return `{"name":"` + name + `","image":"` + image + `"}`
}

func a201StatusContainer(name, imageID string) string {
	return `{"name":"` + name + `","imageID":"` + imageID + `"}`
}

func a201Spec(containers, initContainers, ephemeralContainers string) string {
	return `{"containers":` + containers + `,"initContainers":` + initContainers + `,"ephemeralContainers":` + ephemeralContainers + `}`
}

func a201StatusArrays(regular, init, ephemeral string) string {
	return `{"containerStatuses":` + regular + `,"initContainerStatuses":` + init + `,"ephemeralContainerStatuses":` + ephemeral + `}`
}

func a201PodBody(uid, name, spec, status string) string {
	return `{"apiVersion":"v1","kind":"Pod","metadata":{"uid":"` + uid + `","namespace":"` + a201Namespace + `","name":"` + name + `"},"spec":` + spec + `,"status":` + status + `}`
}

// a201PodWithStatus builds one Pod with an explicit spec and status.
func a201PodWithStatus(uid, name, spec, status string) string {
	return a201PodBody(uid, name, spec, status)
}

// a201PodWithoutStatus builds one Pod whose status is absent: the absence never
// means an observed empty status.
func a201PodWithoutStatus(uid, name, spec string) string {
	return `{"apiVersion":"v1","kind":"Pod","metadata":{"uid":"` + uid + `","namespace":"` + a201Namespace + `","name":"` + name + `"},"spec":` + spec + `}`
}

// a201PodMetadata extends one Pod with an admitted resourceVersion, kept as
// opaque context.
func a201PodWithResourceVersion(uid, name, resourceVersion, spec, status string) string {
	return `{"apiVersion":"v1","kind":"Pod","metadata":{"uid":"` + uid + `","namespace":"` + a201Namespace + `","name":"` + name + `","resourceVersion":"` + resourceVersion + `"},"spec":` + spec + `,"status":` + status + `}`
}

func a201List(items ...string) string {
	return `{"apiVersion":"v1","kind":"PodList","items":` + a201Array(items...) + `}`
}

// a201CompletePod is one Pod with all three categories explicitly present and
// fully associated: the shape that can reach "complete" with a finished
// capture.
func a201CompletePod(uid, name string) string {
	spec := a201Spec(a201Array(a201SpecContainer("api", a201DefaultImage)), a201EmptyArray(), a201EmptyArray())
	status := a201StatusArrays(a201Array(a201StatusContainer("api", a201ImageID)), a201EmptyArray(), a201EmptyArray())
	return a201PodWithStatus(uid, name, spec, status)
}

func a201CompleteDocument(uid, name string) string {
	return a201List(a201CompletePod(uid, name))
}

// Pipeline helpers: parse, normalize and build over the real APIs.

func a201Parse(t *testing.T, document string, context ingest.PodListContext) ingest.PodListResult {
	t.Helper()
	parsed, err := ingest.ParseSanitizedPodList(strings.NewReader(document), context)
	if err != nil {
		t.Fatalf("parse sanitized podlist: %v", err)
	}
	return parsed
}

func a201Normalize(t *testing.T, parsed ingest.PodListResult) normalize.ObservationResult {
	t.Helper()
	observation, err := normalize.NormalizePodList(parsed)
	if err != nil {
		t.Fatalf("normalize podlist: %v", err)
	}
	return observation
}

// a201ObservationInput is the explicit build input: the declared observation
// time of the normalized result is used verbatim, so no clock participates.
func a201ObservationInput(observation normalize.ObservationResult, subjectIndex int) bundle.ObservationInput {
	return bundle.ObservationInput{
		Result:         observation,
		SubjectIndex:   subjectIndex,
		CollectorLabel: a201Collector,
		ParserVersion:  a201Parser,
		ObservedAt:     observation.ObservedAt,
	}
}

func a201Build(t *testing.T, observation normalize.ObservationResult, subjectIndex int) (contract.Bundle, bundle.ObservationDiagnostics) {
	t.Helper()
	built, diagnostics, err := bundle.BuildObservation(a201ObservationInput(observation, subjectIndex))
	if err != nil {
		t.Fatalf("build observation: %v", err)
	}
	return built, diagnostics
}

// a201BuildPipeline runs parse, normalize and build over one document.
func a201BuildPipeline(t *testing.T, document string, context ingest.PodListContext) (contract.Bundle, normalize.ObservationResult) {
	t.Helper()
	parsed := a201Parse(t, document, context)
	observation := a201Normalize(t, parsed)
	built, _ := a201Build(t, observation, 0)
	return built, observation
}

// Evaluation helpers over the existing evaluator surface.

func a201PackBytes() []byte { return []byte(a201PackDocument) }

// a201Admission pins the pack identity and the replay instant. The hash is the
// independent oracle over the exact pack bytes.
func a201Admission() rulepack.AdmissionContext {
	stamp, err := contract.NewTimestamp(time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC))
	if err != nil {
		panic(err)
	}
	return rulepack.AdmissionContext{
		EvaluatedAt:      stamp,
		ExpectedPackID:   "pack.observations",
		ExpectedPackHash: a201IndependentHash(a201PackBytes()),
		MinimumVersion:   1,
	}
}

// a201DomainContext is the explicit caller policy the product profile
// requires. It authorizes one synthetic vendor advisory.
func a201DomainContext() *evaluator.DomainContext {
	advisory := "RHSA-2026:0001"
	revision := "1"
	return &evaluator.DomainContext{
		MaximumEvidenceAgeSeconds: 86400,
		SourcePins: []evaluator.SourcePin{{
			Role:             evaluator.SourceRoleVendor,
			Source:           "synthetic-redhat-advisory",
			SourceHash:       contract.SourceHash(a201IndependentHash([]byte("synthetic-redhat-advisory"))),
			AdvisoryID:       &advisory,
			AdvisoryRevision: &revision,
		}},
	}
}

// a201Target cites one bundle and one exact row occurrence. The container name
// is passed explicitly so a test can cite a row outside the observed scope.
func a201Target(built contract.Bundle, vulnerability, container, locator string, observedAt contract.Timestamp) evaluator.Target {
	return evaluator.Target{
		SubjectUID:      built.Subject.UID,
		ContainerClass:  contract.ContainerRegular,
		ContainerName:   contract.ContainerName(container),
		VulnerabilityID: vulnerability,
		Source:          built.Provenance.Inputs[0].Path,
		SourceHash:      built.Provenance.Inputs[0].Hash,
		Locator:         contract.SourceLocator(locator),
		ObservedAt:      observedAt,
	}
}

func a201Evaluate(t *testing.T, built contract.Bundle, target evaluator.Target) evaluator.Result {
	t.Helper()
	artifacts, err := bundle.Encode(built)
	if err != nil {
		t.Fatalf("encode bundle: %v", err)
	}
	result, err := evaluator.Evaluate(evaluator.Request{
		Bundle:             built,
		ExpectedBundleHash: artifacts.Hash,
		Target:             target,
		PackBytes:          a201PackBytes(),
		Admission:          a201Admission(),
		Domain:             a201DomainContext(),
	})
	if err != nil {
		t.Fatalf("evaluate: %v", err)
	}
	return result
}

func a201HasReason(reasons []evaluator.Reason, wanted evaluator.Reason) bool {
	for _, reason := range reasons {
		if reason == wanted {
			return true
		}
	}
	return false
}

// a201RequireMissing fails when the first rule trace does not list the
// requirement as missing evidence.
func a201RequireMissing(t *testing.T, result evaluator.Result, wanted rulepack.Requirement) {
	t.Helper()
	for _, trace := range result.Rules {
		for _, missing := range trace.MissingRequirements {
			if missing == wanted {
				return
			}
		}
	}
	t.Fatalf("no rule trace reports %q as missing: %+v", wanted, result.Rules)
}

func a201HasWarning(built contract.Bundle, code string, class contract.WarningClass) bool {
	for _, warning := range built.Provenance.Warnings {
		if warning.Code == code && warning.Class == class {
			return true
		}
	}
	return false
}

func a201HasError(built contract.Bundle, message string) bool {
	for _, failure := range built.Provenance.Errors {
		if failure == message {
			return true
		}
	}
	return false
}

// a201FormattedDiagnostics renders the local diagnostics and rejections of one
// parse result with the production formatter, so a marker scan never bypasses
// the sanitized message.
func a201FormattedDiagnostics(parsed ingest.PodListResult) []string {
	rendered := []string{}
	for _, diagnostic := range parsed.Diagnostics {
		rendered = append(rendered, diagnostic.Error())
	}
	for _, rejection := range parsed.Rejections {
		rendered = append(rendered, rejection.String())
	}
	return rendered
}

func a201ObservationIsEmpty(observation normalize.ObservationResult) bool {
	return reflect.DeepEqual(observation, normalize.ObservationResult{})
}

// a201SpyWriter counts every write call and byte it receives. It is the writer
// probe of the persistence boundary: after a rejection it must stay untouched.
type a201SpyWriter struct {
	calls int
	bytes int
	data  []byte
}

func (writer *a201SpyWriter) Write(chunk []byte) (int, error) {
	writer.calls++
	writer.bytes += len(chunk)
	writer.data = append(writer.data, chunk...)
	return len(chunk), nil
}

// a201ErrorReader delivers its bytes and an error in the same read call, the
// shape A-2 uses to prove the original reader error is never exposed.
type a201ErrorReader struct {
	data   []byte
	err    error
	failed bool
}

func (reader *a201ErrorReader) Read(buffer []byte) (int, error) {
	if reader.failed {
		return 0, io.EOF
	}
	reader.failed = true
	return copy(buffer, reader.data), reader.err
}

// a201CountingReader counts how many times it was read: a rejected context must
// never consume the reader.
type a201CountingReader struct{ reads int }

func (reader *a201CountingReader) Read(buffer []byte) (int, error) {
	reader.reads++
	return 0, io.EOF
}

// a201MarkerError is the unsanitized reader failure of the F12 case: its text
// must never reach a diagnostic, an error or a result.
func a201MarkerError(marker string) error {
	return errors.New("reader failed with " + marker)
}
