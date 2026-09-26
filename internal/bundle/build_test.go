package bundle

import (
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	canonical "github.com/d4rpell/Ariadne/internal/evidence"
	"github.com/d4rpell/Ariadne/internal/identity"
	"github.com/d4rpell/Ariadne/internal/ingest"
	"github.com/d4rpell/Ariadne/internal/normalize"
	contract "github.com/d4rpell/Ariadne/pkg/evidence"
)

const testCSVHeader = "schema_version,vulnerability_id,package_name,installed_version,fix_status,image_registry,image_repository,image_tag,severity\n"

const csvOneRow = testCSVHeader +
	"1.0,CVE-2024-1234,openssl,1.1.1k,fixed,registry.example,payments/api,release,high\n"

const csvTwoRows = testCSVHeader +
	"1.0,CVE-2024-1234,openssl,1.1.1k,fixed,registry.example,payments/api,release,high\n" +
	"1.0,CVE-2024-5678,zlib,1.2.11,fixed,registry.example,payments/worker,release,medium\n"

func testDigest(letter string) string {
	return "sha256:" + strings.Repeat(letter, 64)
}

func testTimestamp(t *testing.T, value string) *contract.Timestamp {
	t.Helper()
	parsed, err := time.Parse(time.RFC3339Nano, value)
	if err != nil {
		t.Fatalf("timestamp %q: %v", value, err)
	}
	stamp, err := contract.NewTimestamp(parsed)
	if err != nil {
		t.Fatalf("timestamp %q: %v", value, err)
	}
	return &stamp
}

func testSubject() contract.Subject {
	return contract.Subject{
		ClusterAlias: contract.ClusterAlias("cluster-a"),
		Namespace:    contract.Namespace("payments"),
		Kind:         "Pod",
		Name:         "payments-api-7f4d",
		UID:          contract.UID("pod-uid-1"),
		OwnerChain:   contract.OwnerChain("deployments/payments-api"),
	}
}

func testRun(t *testing.T) RunContext {
	t.Helper()
	return RunContext{
		CollectorVersion: "0.1.0",
		ParserVersion:    "prisma-v1.0",
		ArgvSanitized:    []string{"import", "findings.csv", "--schema", "prisma-v1"},
		Budget:           contract.Budget{WallClock: "5m", Requests: 3, Objects: 5, Bytes: 4096},
		Consistency:      contract.ConsistencyPointObservation,
		RedactionPolicy:  "default-v1",
		Warnings:         []contract.Warning{},
	}
}

type parsedImport struct {
	result ingest.Result
	source ImportSource
}

func parseImport(t *testing.T, csv string) parsedImport {
	t.Helper()
	result, err := ingest.ParsePrismaV1(strings.NewReader(csv))
	if err != nil {
		t.Fatalf("parse prisma-v1: %v", err)
	}
	return parsedImport{
		result: result,
		source: ImportSource{
			Path:       "findings.csv",
			Hash:       HashSource([]byte(csv)),
			ObservedAt: testTimestamp(t, "2026-09-26T10:00:00Z"),
		},
	}
}

// testBinding builds one synthetic observation of a container. Every binding
// carries a complete observation provenance unless a test removes a field.
func testBinding(t *testing.T, index int, uid contract.UID, class contract.ContainerClass, name contract.ContainerName) normalize.Binding {
	t.Helper()
	digest, err := identity.NewGuaranteedDigest(testDigest("a"))
	if err != nil {
		t.Fatalf("guaranteed digest: %v", err)
	}
	raw := contract.RawImageID("registry.example/payments/api@" + testDigest("a"))
	key := identity.ContainerKey{SubjectUID: uid, ContainerClass: class, ContainerName: name}
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

// testTaggedBinding builds an unresolved observation: a requested reference is
// declared by the row, but the observation carries no content reference.
func testTaggedBinding(t *testing.T, index int, uid contract.UID, name contract.ContainerName) normalize.Binding {
	t.Helper()
	key := identity.ContainerKey{SubjectUID: uid, ContainerClass: contract.ContainerRegular, ContainerName: name}
	image := identity.ImageBinding{
		Key:        key,
		InputKind:  identity.InputSynthetic,
		SourceName: "sanitized-pods.json",
		SourceHash: contract.SourceHash(testDigest("c")),
		Locator:    contract.SourceLocator("items[3].spec.containers[0].image"),
		Platform:   contract.PlatformUnknown,
		ObservedAt: testTimestamp(t, "2026-09-26T09:00:00Z"),
	}
	return normalize.Binding{FindingIndex: index, ContainerKey: key, Image: image}
}

func normalizeImport(t *testing.T, parsed parsedImport, bindings []normalize.Binding) normalize.Result {
	t.Helper()
	result, err := normalize.Normalize(normalize.Input{Import: parsed.result, Bindings: bindings})
	if err != nil {
		t.Fatalf("normalize: %v", err)
	}
	return result
}

func testInput(t *testing.T, csv string, bindings []normalize.Binding) Input {
	t.Helper()
	parsed := parseImport(t, csv)
	return Input{
		Normalized: normalizeImport(t, parsed, bindings),
		Subject:    testSubject(),
		Source:     parsed.source,
		Run:        testRun(t),
	}
}

func buildForTest(t *testing.T, input Input) (contract.Bundle, Diagnostics) {
	t.Helper()
	bundle, diagnostics, err := Build(input)
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	return bundle, diagnostics
}

func envelopeOf(t *testing.T, bundle contract.Bundle) string {
	t.Helper()
	encoded, err := canonical.CanonicalJSON(bundle)
	if err != nil {
		t.Fatalf("canonical json: %v", err)
	}
	return string(encoded)
}

func evidenceOfType(items []contract.EvidenceItem, itemType string) []contract.EvidenceItem {
	var found []contract.EvidenceItem
	for _, item := range items {
		if item.Type == itemType {
			found = append(found, item)
		}
	}
	return found
}

func TestBuildSeparatesSubjectsAndContainers(t *testing.T) {
	input := testInput(t, csvTwoRows, []normalize.Binding{
		testBinding(t, 0, contract.UID("pod-uid-1"), contract.ContainerRegular, contract.ContainerName("api")),
		testBinding(t, 1, contract.UID("pod-uid-2"), contract.ContainerRegular, contract.ContainerName("api")),
	})
	bundle, _ := buildForTest(t, input)

	if len(bundle.Images) != 1 || len(evidenceOfType(bundle.Evidence, "prisma_v1.vulnerability_id")) != 1 {
		t.Fatalf("images=%d evidence=%d, want one image and one row of the subject", len(bundle.Images), len(bundle.Evidence))
	}
	if bundle.Images[0].ContainerName != contract.ContainerName("api") {
		t.Fatalf("container = %q", bundle.Images[0].ContainerName)
	}
	envelope := envelopeOf(t, bundle)
	if strings.Contains(envelope, "CVE-2024-5678") {
		t.Fatal("evidence of another subject leaked into the bundle")
	}
	for _, item := range bundle.Evidence {
		if item.Scope.SubjectUID != contract.UID("pod-uid-1") {
			t.Fatalf("item %q scoped to %q", item.Type, item.Scope.SubjectUID)
		}
	}
}

func TestBuildPreservesImportCoverage(t *testing.T) {
	csv := testCSVHeader + csvRow("CVE-2024-1234") + "1.0,NOT-A-CVE,openssl,1.1.1k,fixed,registry.example,payments/api,release,high\n"
	input := testInput(t, csv, []normalize.Binding{
		testBinding(t, 0, contract.UID("pod-uid-1"), contract.ContainerRegular, contract.ContainerName("api")),
	})
	if input.Normalized.Completeness != contract.CompletenessPartial {
		t.Fatalf("import completeness = %q, want partial", input.Normalized.Completeness)
	}
	bundle, diagnostics := buildForTest(t, input)

	coverage := bundle.Provenance.Coverage
	if coverage.Method != contract.CoverageFindingsImport || coverage.Termination != contract.TerminationFinished {
		t.Fatalf("coverage = %+v", coverage)
	}
	if coverage.Rows == nil || coverage.Rows.Total == nil || *coverage.Rows.Total != 2 ||
		coverage.Rows.Accepted != 1 || coverage.Rows.Rejected != 1 {
		t.Fatalf("rows = %+v", coverage.Rows)
	}
	if bundle.Provenance.Completeness != contract.CompletenessPartial {
		t.Fatalf("completeness = %q, want partial", bundle.Provenance.Completeness)
	}
	if len(diagnostics.Ingest.Rejections) != 1 {
		t.Fatalf("rejections = %d", len(diagnostics.Ingest.Rejections))
	}
}

func csvRow(cve string) string {
	return "1.0," + cve + ",openssl,1.1.1k,fixed,registry.example,payments/api,release,high\n"
}

func TestBuildImportIsNotInventory(t *testing.T) {
	input := testInput(t, csvOneRow, []normalize.Binding{
		testBinding(t, 0, contract.UID("pod-uid-1"), contract.ContainerRegular, contract.ContainerName("api")),
	})
	bundle, _ := buildForTest(t, input)

	if bundle.ObservedContainerClasses == nil || len(bundle.ObservedContainerClasses) != 0 {
		t.Fatalf("observed_container_classes = %#v, want a non-nil empty array", bundle.ObservedContainerClasses)
	}
	scope := bundle.Provenance.APIScope
	if len(scope.Namespaces) != 0 || len(scope.Verbs) != 0 || len(scope.Resources) != 0 {
		t.Fatalf("api_scope = %+v, want empty arrays", scope)
	}
	if scope.Namespaces == nil || scope.Verbs == nil || scope.Resources == nil {
		t.Fatal("api_scope arrays must be non-nil")
	}
	if len(bundle.Provenance.Inputs) != 1 || bundle.Provenance.Inputs[0].Path != "findings.csv" {
		t.Fatalf("inputs = %+v", bundle.Provenance.Inputs)
	}
	if bundle.Provenance.Inputs[0].Hash != input.Source.Hash {
		t.Fatalf("input hash = %q, want %q", bundle.Provenance.Inputs[0].Hash, input.Source.Hash)
	}
}

func TestBuildDeterministicAndDetached(t *testing.T) {
	input := testInput(t, csvTwoRows, []normalize.Binding{
		testBinding(t, 0, contract.UID("pod-uid-1"), contract.ContainerRegular, contract.ContainerName("api")),
		testBinding(t, 1, contract.UID("pod-uid-1"), contract.ContainerRegular, contract.ContainerName("api")),
	})
	first, _ := buildForTest(t, input)
	second, _ := buildForTest(t, input)
	if envelopeOf(t, first) != envelopeOf(t, second) {
		t.Fatal("two builds of the same input differ")
	}

	wantEnvelope := envelopeOf(t, first)
	input.Normalized.Findings[0].Source.VulnerabilityID = "CVE-0000-0000"
	*input.Normalized.Findings[0].Binding.RawImageID = contract.RawImageID(testDigest("f"))
	*input.Normalized.Findings[0].Binding.ObservedAt = *testTimestamp(t, "2030-01-01T00:00:00Z")
	input.Normalized.Coverage.Rows.Accepted = 999
	*input.Normalized.Coverage.Rows.Total = 999
	input.Source.ObservedAt = testTimestamp(t, "2030-01-01T00:00:00Z")
	input.Run.ArgvSanitized[0] = "mutated"

	if got := envelopeOf(t, first); got != wantEnvelope {
		t.Fatal("the returned bundle changed when the caller mutated its input")
	}
}

func TestBuildHasNoDecisionFields(t *testing.T) {
	input := testInput(t, csvOneRow, []normalize.Binding{
		testBinding(t, 0, contract.UID("pod-uid-1"), contract.ContainerRegular, contract.ContainerName("api")),
	})
	bundle, _ := buildForTest(t, input)
	envelope := envelopeOf(t, bundle)

	for _, forbidden := range []string{"product_status", "exploitability", "risk_decision", "not_affected", "EXCEPCIONABLE"} {
		if strings.Contains(envelope, forbidden) {
			t.Fatalf("bundle carries decision vocabulary %q", forbidden)
		}
	}
	expected := []string{`"schema_version"`, `"subject"`, `"images"`, `"evidence"`, `"observed_container_classes"`, `"provenance"`}
	for _, key := range expected {
		if !strings.Contains(envelope, key) {
			t.Fatalf("bundle misses top-level key %s", key)
		}
	}
}

func TestBuildRejectsUnusableInput(t *testing.T) {
	cases := map[string]func(input *Input){
		"missing source path":      func(input *Input) { input.Source.Path = "" },
		"source hash not sha256":   func(input *Input) { input.Source.Hash = "sha256:short" },
		"missing source timestamp": func(input *Input) { input.Source.ObservedAt = nil },
		"missing collector":        func(input *Input) { input.Run.CollectorVersion = "" },
		"missing parser":           func(input *Input) { input.Run.ParserVersion = "" },
		"missing redaction policy": func(input *Input) { input.Run.RedactionPolicy = "" },
		"nil argv":                 func(input *Input) { input.Run.ArgvSanitized = nil },
		"zero normalized result":   func(input *Input) { input.Normalized = normalize.Result{} },
		"unknown completeness":     func(input *Input) { input.Normalized.Completeness = "invented" },
	}
	base := testInput(t, csvOneRow, []normalize.Binding{
		testBinding(t, 0, contract.UID("pod-uid-1"), contract.ContainerRegular, contract.ContainerName("api")),
	})
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			input := base
			input.Normalized = copyResult(base.Normalized)
			input.Run = copyRun(base.Run)
			mutate(&input)
			bundle, _, err := Build(input)
			if err == nil {
				t.Fatal("expected a fail-closed error, got a bundle")
			}
			if !reflect.DeepEqual(bundle, contract.Bundle{}) {
				t.Fatal("an unusable input produced a bundle value")
			}
		})
	}
}

func TestBuildRejectsIncoherentBinding(t *testing.T) {
	cases := map[string]func(input *Input){
		"resolution dropped": func(input *Input) {
			input.Normalized.Findings[0].Resolution = nil
		},
		"resolution without binding": func(input *Input) {
			input.Normalized.Findings[0].Resolution.Binding = nil
		},
		"unbound state with a binding": func(input *Input) {
			input.Normalized.Findings[0].State = normalize.NormalizationUnbound
		},
		"unknown state over a complete import": func(input *Input) {
			input.Normalized.Findings[0].State = normalize.NormalizationUnknown
		},
		"bound state with an unknown resolution": func(input *Input) {
			finding := &input.Normalized.Findings[0]
			resolution := *finding.Resolution
			resolution.State = identity.ResolutionUnknown
			finding.Resolution = &resolution
		},
		"divergent resolution observation": func(input *Input) {
			finding := &input.Normalized.Findings[0]
			resolution := *finding.Resolution
			divergent := *finding.Binding
			divergent.Locator = contract.SourceLocator("items[9].status.containerStatuses[0].imageID")
			resolution.Binding = &divergent
			finding.Resolution = &resolution
		},
		"key mismatch": func(input *Input) {
			finding := &input.Normalized.Findings[0]
			resolution := *finding.Resolution
			resolution.Key.ContainerName = contract.ContainerName("other")
			finding.Resolution = &resolution
		},
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			input := fixtureInput(t)
			mutate(&input)
			bundle, _, err := Build(input)
			if err == nil {
				t.Fatal("an incoherent normalized finding must be refused")
			}
			if !reflect.DeepEqual(bundle, contract.Bundle{}) {
				t.Fatal("a refused input produced a bundle value")
			}
		})
	}

	bound := fixtureInput(t)
	bound.Normalized.Completeness = contract.CompletenessPartial
	if _, _, err := Build(bound); err == nil {
		t.Fatal("a bound state over an incomplete import must be refused")
	}
}

func TestBuildRejectsUnknownResolutionEnumOverIncompleteImport(t *testing.T) {
	csv := testCSVHeader + csvRow("CVE-2024-1234") + "1.0,NOT-A-CVE,openssl,1.1.1k,fixed,registry.example,payments/api,release,high\n"
	input := testInput(t, csv, []normalize.Binding{
		testBinding(t, 0, contract.UID("pod-uid-1"), contract.ContainerRegular, contract.ContainerName("api")),
	})
	input.Normalized = copyResult(input.Normalized)
	if input.Normalized.Completeness != contract.CompletenessPartial {
		t.Fatalf("fixture completeness = %q, want a naturally partial import", input.Normalized.Completeness)
	}
	finding := &input.Normalized.Findings[0]
	resolution := *finding.Resolution
	resolution.State = identity.ResolutionState("invented")
	finding.Resolution = &resolution

	bundle, _, err := Build(input)
	if err == nil {
		t.Fatal("a resolution state outside the enum must be refused, even over an incomplete import")
	}
	if !reflect.DeepEqual(bundle, contract.Bundle{}) {
		t.Fatal("a refused input produced a bundle value")
	}
}

func fixtureInput(t *testing.T) Input {
	t.Helper()
	input := testInput(t, csvOneRow, []normalize.Binding{
		testBinding(t, 0, contract.UID("pod-uid-1"), contract.ContainerRegular, contract.ContainerName("api")),
	})
	input.Normalized = copyResult(input.Normalized)
	return input
}

func TestBuildRecordsOtherSubjectOmission(t *testing.T) {
	input := testInput(t, csvTwoRows, []normalize.Binding{
		testBinding(t, 0, contract.UID("pod-uid-1"), contract.ContainerRegular, contract.ContainerName("api")),
		testBinding(t, 1, contract.UID("pod-uid-2"), contract.ContainerRegular, contract.ContainerName("api")),
	})
	bundle, diagnostics := buildForTest(t, input)

	if bundle.Provenance.Completeness != contract.CompletenessComplete {
		t.Fatalf("completeness = %q, the subject partition is not a defect of this bundle", bundle.Provenance.Completeness)
	}
	if len(bundle.Provenance.Errors) != 0 || len(bundle.Provenance.Warnings) != 0 {
		t.Fatalf("partition changed the provenance claims: %+v", bundle.Provenance.Errors)
	}
	if len(diagnostics.Omissions) != 1 || diagnostics.Omissions[0].Reason != OmissionOtherSubject {
		t.Fatalf("omissions = %+v", diagnostics.Omissions)
	}
	if diagnostics.Omissions[0].FindingIndex != 1 {
		t.Fatalf("omitted index = %d, want the foreign finding", diagnostics.Omissions[0].FindingIndex)
	}
	if diagnostics.Omissions[0].Locator != input.Normalized.Findings[1].Source.Locator {
		t.Fatal("the omission must keep the row locator")
	}
	if strings.Contains(envelopeOf(t, bundle), "CVE-2024-5678") {
		t.Fatal("a foreign subject leaked into the bundle")
	}
}

func TestBuildConcurrentBuildsAgree(t *testing.T) {
	input := testInput(t, csvTwoRows, []normalize.Binding{
		testBinding(t, 0, contract.UID("pod-uid-1"), contract.ContainerRegular, contract.ContainerName("api")),
		testBinding(t, 1, contract.UID("pod-uid-1"), contract.ContainerRegular, contract.ContainerName("worker")),
	})
	frozen := input.Normalized

	const workers = 8
	results := make([]string, workers)
	var group sync.WaitGroup
	for worker := 0; worker < workers; worker++ {
		group.Add(1)
		go func(slot int) {
			defer group.Done()
			bundle, _, err := Build(input)
			if err != nil {
				results[slot] = "error: " + err.Error()
				return
			}
			encoded, encodeErr := canonical.CanonicalJSON(bundle)
			if encodeErr != nil {
				results[slot] = "error: " + encodeErr.Error()
				return
			}
			results[slot] = string(encoded)
		}(worker)
	}
	group.Wait()

	for slot, result := range results {
		if result != results[0] {
			t.Fatalf("worker %d disagrees with worker 0", slot)
		}
	}
	if !reflect.DeepEqual(frozen, input.Normalized) {
		t.Fatal("a concurrent build mutated the caller's input")
	}
}

func TestBuildPreviousBundleIsNotRewritten(t *testing.T) {
	previous := fixtureBundle(t, 1)
	before, err := Encode(previous)
	if err != nil {
		t.Fatalf("encode previous: %v", err)
	}

	csv := csvFromRows(
		csvRowFor("CVE-2024-1234", "payments/api", "release"),
		csvRowFor("CVE-2024-5678", "payments/api", "release"),
	)
	collided, _ := buildForTest(t, testInput(t, csv, []normalize.Binding{
		testBinding(t, 0, contract.UID("pod-uid-1"), contract.ContainerRegular, contract.ContainerName("api")),
		testBinding(t, 1, contract.UID("pod-uid-1"), contract.ContainerInit, contract.ContainerName("api")),
	}))
	if len(collided.Provenance.Warnings) == 0 {
		t.Fatal("the second bundle was expected to carry a collision")
	}

	after, err := Encode(previous)
	if err != nil {
		t.Fatalf("encode previous again: %v", err)
	}
	if string(after.Envelope) != string(before.Envelope) || after.Hash != before.Hash {
		t.Fatal("a later build rewrote a bundle that was already emitted")
	}
}
