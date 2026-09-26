package bundle

import (
	"strings"
	"testing"

	"github.com/d4rpell/Ariadne/internal/normalize"
	contract "github.com/d4rpell/Ariadne/pkg/evidence"
)

func csvFromRows(rows ...string) string {
	return testCSVHeader + strings.Join(rows, "")
}

func csvRowFor(cve, repository, tag string) string {
	return "1.0," + cve + ",openssl,1.1.1k,fixed,registry.example," + repository + "," + tag + ",high\n"
}

func TestBuildRequestedImagePerFinding(t *testing.T) {
	csv := csvFromRows(
		csvRowFor("CVE-2024-1234", "payments/api", "release"),
		csvRowFor("CVE-2024-1234", "payments/api", "canary"),
	)
	input := testInput(t, csv, []normalize.Binding{
		testBinding(t, 0, contract.UID("pod-uid-1"), contract.ContainerRegular, contract.ContainerName("api")),
		testBinding(t, 1, contract.UID("pod-uid-1"), contract.ContainerRegular, contract.ContainerName("api")),
	})
	bundle, _ := buildForTest(t, input)

	if len(bundle.Images) != 2 {
		t.Fatalf("images = %d, want one per finding", len(bundle.Images))
	}
	requested := map[string]bool{}
	for _, image := range bundle.Images {
		if image.RequestedImage == nil {
			t.Fatal("a finding lost its declared reference")
		}
		requested[string(*image.RequestedImage)] = true
	}
	for _, want := range []string{"registry.example/payments/api:release", "registry.example/payments/api:canary"} {
		if !requested[want] {
			t.Fatalf("missing requested reference %q", want)
		}
	}
	items := evidenceOfType(bundle.Evidence, "prisma_v1.requested_image")
	if len(items) != 2 {
		t.Fatalf("requested items = %d, want 2", len(items))
	}
	for _, item := range items {
		if item.Confidence != contract.ProvenanceDerived {
			t.Fatalf("composed reference confidence = %q, want derived", item.Confidence)
		}
		if item.Value == nil || HashValue(*item.Value) != *item.ValueHash {
			t.Fatal("composed reference hash does not cover its value")
		}
	}
	if items[0].Locator == items[1].Locator {
		t.Fatal("two rows must keep their own locator")
	}
}

func TestBuildRejectsNilRequestedImage(t *testing.T) {
	csv := csvFromRows(csvRowFor("CVE-2024-1234", "payments/api@sha256:aaa", "release"))
	input := testInput(t, csv, []normalize.Binding{
		testBinding(t, 0, contract.UID("pod-uid-1"), contract.ContainerRegular, contract.ContainerName("api")),
	})
	if input.Normalized.Findings[0].RequestedImage != nil {
		t.Fatal("the fixture was expected to be unrepresentable")
	}
	bundle, diagnostics := buildForTest(t, input)

	if len(bundle.Images) != 0 {
		t.Fatalf("images = %d, a blocked identity must not be projected", len(bundle.Images))
	}
	if items := evidenceOfType(bundle.Evidence, "prisma_v1.requested_image"); len(items) != 0 {
		t.Fatal("a blocked identity must not produce a composed item")
	}
	if items := evidenceOfType(bundle.Evidence, "prisma_v1.image_repository"); len(items) != 1 {
		t.Fatal("the declared columns of the row are still facts with their own provenance")
	}
	if len(diagnostics.Omissions) != 1 || diagnostics.Omissions[0].Reason != OmissionRequestedImage {
		t.Fatalf("omissions = %+v", diagnostics.Omissions)
	}
	assertErrorPresent(t, bundle, errRequestedImageBlocked.Error())
	if strings.Contains(envelopeOf(t, bundle), `"requested_image":null`) {
		t.Fatal("a prisma-v1 row must never be emitted as a legitimate null reference")
	}
	if bundle.Provenance.Completeness != contract.CompletenessPartial {
		t.Fatalf("completeness = %q, want partial", bundle.Provenance.Completeness)
	}
}

func TestBuildKeepsRequestedAndObservedSeparate(t *testing.T) {
	input := testInput(t, csvOneRow, []normalize.Binding{
		testBinding(t, 0, contract.UID("pod-uid-1"), contract.ContainerRegular, contract.ContainerName("api")),
	})
	bundle, _ := buildForTest(t, input)

	image := bundle.Images[0]
	if image.RequestedImage == nil || string(*image.RequestedImage) != "registry.example/payments/api:release" {
		t.Fatalf("requested = %v", image.RequestedImage)
	}
	if image.RawImageID == nil || !strings.Contains(string(*image.RawImageID), testDigest("a")) {
		t.Fatalf("raw = %v", image.RawImageID)
	}
	if image.NormalizedDigest == nil || string(*image.NormalizedDigest) != testDigest("a") {
		t.Fatalf("digest = %v", image.NormalizedDigest)
	}
	if string(*image.RequestedImage) == string(*image.RawImageID) {
		t.Fatal("requested and observed must never be conflated")
	}
}

func TestBuildCollisionPrecedesOtherOmissions(t *testing.T) {
	csv := csvFromRows(
		csvRowFor("CVE-2024-1234", "payments/api@sha256:aaa", "release"),
		csvRowFor("CVE-2024-5678", "payments/api", "release"),
	)
	input := testInput(t, csv, []normalize.Binding{
		testBinding(t, 0, contract.UID("pod-uid-1"), contract.ContainerRegular, contract.ContainerName("api")),
		testBinding(t, 1, contract.UID("pod-uid-1"), contract.ContainerInit, contract.ContainerName("api")),
	})
	bundle, diagnostics := buildForTest(t, input)

	if len(diagnostics.Omissions) != 2 {
		t.Fatalf("omissions = %+v", diagnostics.Omissions)
	}
	for _, omission := range diagnostics.Omissions {
		if omission.Reason != OmissionScopeCollision {
			t.Fatalf("reason = %q, want the collision to win over the other defect", omission.Reason)
		}
	}
	if len(bundle.Evidence) != 0 || len(bundle.Images) != 0 {
		t.Fatal("a collided key must not leak the half that was otherwise projectable")
	}
	assertErrorPresent(t, bundle, errScopeCollisionOmitted.Error())
	if strings.Contains(envelopeOf(t, bundle), errRequestedImageBlocked.Error()) {
		t.Fatal("the blocked-reference error must not replace the collision error")
	}
}

func TestBuildScopeCollisionKeepsOtherContainers(t *testing.T) {
	csv := csvFromRows(
		csvRowFor("CVE-2024-1234", "payments/api", "release"),
		csvRowFor("CVE-2024-5678", "payments/api", "release"),
		csvRowFor("CVE-2024-9999", "payments/worker", "release"),
	)
	input := testInput(t, csv, []normalize.Binding{
		testBinding(t, 0, contract.UID("pod-uid-1"), contract.ContainerRegular, contract.ContainerName("api")),
		testBinding(t, 1, contract.UID("pod-uid-1"), contract.ContainerInit, contract.ContainerName("api")),
		testBinding(t, 2, contract.UID("pod-uid-1"), contract.ContainerRegular, contract.ContainerName("worker")),
	})
	bundle, diagnostics := buildForTest(t, input)

	if diagnostics.CollisionCount != 1 || len(diagnostics.Omissions) != 2 {
		t.Fatalf("diagnostics = %+v", diagnostics)
	}
	if len(bundle.Images) != 1 || bundle.Images[0].ContainerName != contract.ContainerName("worker") {
		t.Fatalf("images = %+v", bundle.Images)
	}
	envelope := envelopeOf(t, bundle)
	if strings.Contains(envelope, "CVE-2024-1234") || strings.Contains(envelope, "CVE-2024-5678") {
		t.Fatal("evidence of the collided keys leaked")
	}
	if !strings.Contains(envelope, "CVE-2024-9999") {
		t.Fatal("the healthy container of the same subject was dropped")
	}
	if bundle.Provenance.Completeness != contract.CompletenessPartial {
		t.Fatalf("completeness = %q, want partial", bundle.Provenance.Completeness)
	}
}

func TestBuildThreeClassCollision(t *testing.T) {
	csv := csvFromRows(
		csvRowFor("CVE-2024-1234", "payments/api", "release"),
		csvRowFor("CVE-2024-5678", "payments/api", "release"),
		csvRowFor("CVE-2024-9999", "payments/api", "release"),
	)
	classes := []contract.ContainerClass{contract.ContainerRegular, contract.ContainerInit, contract.ContainerEphemeral}
	var orders [][]contract.ContainerClass
	for _, first := range classes {
		for _, second := range classes {
			for _, third := range classes {
				if first == second || second == third || first == third {
					continue
				}
				orders = append(orders, []contract.ContainerClass{first, second, third})
			}
		}
	}
	if len(orders) != 6 {
		t.Fatalf("permutations = %d, want the six orders of the enum", len(orders))
	}
	for _, classes := range orders {
		bindings := make([]normalize.Binding, 0, len(classes))
		for index, class := range classes {
			bindings = append(bindings, testBinding(t, index, contract.UID("pod-uid-1"), class, contract.ContainerName("api")))
		}
		bundle, diagnostics := buildForTest(t, testInput(t, csv, bindings))
		if diagnostics.CollisionCount != 1 || len(diagnostics.Omissions) != 3 {
			t.Fatalf("classes %v: diagnostics = %+v", classes, diagnostics)
		}
		warnings := bundle.Provenance.Warnings
		if len(warnings) != 1 {
			t.Fatalf("classes %v: warnings = %+v", classes, warnings)
		}
		if warnings[0].Message != "scope collision across container classes: regular, init, ephemeral" {
			t.Fatalf("message = %q", warnings[0].Message)
		}
		if warnings[0].Code != "scope_mismatch" || warnings[0].Class != contract.WarningContradictory {
			t.Fatalf("warning = %+v", warnings[0])
		}
	}
}

func TestBuildCollisionWarningsDoNotLeak(t *testing.T) {
	const marker = "SYNTHETIC_PRIVATE_MARKER"
	csv := csvFromRows(
		csvRowFor("CVE-2024-1234", "payments/"+marker, "release"),
		csvRowFor("CVE-2024-5678", "payments/"+marker, "release"),
	)
	input := testInput(t, csv, []normalize.Binding{
		testBinding(t, 0, contract.UID("pod-uid-1"), contract.ContainerRegular, contract.ContainerName(marker)),
		testBinding(t, 1, contract.UID("pod-uid-1"), contract.ContainerInit, contract.ContainerName(marker)),
	})
	bundle, _ := buildForTest(t, input)

	if strings.Contains(bundle.Provenance.Warnings[0].Message, marker) {
		t.Fatal("the collision message interpolated an input value")
	}
	if strings.Contains(envelopeOf(t, bundle), marker) {
		t.Fatal("the collided container name leaked into the envelope")
	}
}

func TestBuildDistinctCollisionWarningsRetained(t *testing.T) {
	csv := csvFromRows(
		csvRowFor("CVE-2024-1234", "payments/api", "release"),
		csvRowFor("CVE-2024-5678", "payments/api", "release"),
		csvRowFor("CVE-2024-9999", "payments/worker", "release"),
		csvRowFor("CVE-2024-0001", "payments/worker", "release"),
	)
	input := testInput(t, csv, []normalize.Binding{
		testBinding(t, 0, contract.UID("pod-uid-1"), contract.ContainerRegular, contract.ContainerName("api")),
		testBinding(t, 1, contract.UID("pod-uid-1"), contract.ContainerInit, contract.ContainerName("api")),
		testBinding(t, 2, contract.UID("pod-uid-1"), contract.ContainerRegular, contract.ContainerName("worker")),
		testBinding(t, 3, contract.UID("pod-uid-1"), contract.ContainerInit, contract.ContainerName("worker")),
	})
	bundle, diagnostics := buildForTest(t, input)

	if diagnostics.CollisionCount != 2 {
		t.Fatalf("collision count = %d", diagnostics.CollisionCount)
	}
	warnings := bundle.Provenance.Warnings
	if len(warnings) != 2 {
		t.Fatalf("warnings = %+v, two keys must keep two warnings even if identical", warnings)
	}
	if warnings[0] != warnings[1] {
		t.Fatalf("warnings differ: %+v", warnings)
	}
	occurrences := 0
	for _, message := range bundle.Provenance.Errors {
		if message == errScopeCollisionOmitted.Error() {
			occurrences++
		}
	}
	if occurrences != 2 {
		t.Fatalf("collision errors = %d, want 2", occurrences)
	}
}

func TestBuildPlatformCarrier(t *testing.T) {
	binding := testBinding(t, 0, contract.UID("pod-uid-1"), contract.ContainerRegular, contract.ContainerName("api"))
	binding.Image.PlatformArchitecture = "arm64"
	input := testInput(t, csvOneRow, []normalize.Binding{binding})
	bundle, _ := buildForTest(t, input)
	platform := bundle.Images[0].Platform
	if platform.Status != contract.PlatformKnown || platform.OS != "linux" || platform.Architecture != "arm64" {
		t.Fatalf("platform = %+v", platform)
	}
	items := evidenceOfType(bundle.Evidence, "container_status.platform.architecture")
	if len(items) != 1 || items[0].Value == nil || *items[0].Value != "arm64" {
		t.Fatalf("architecture items = %+v", items)
	}

	untagged := testInput(t, csvOneRow, []normalize.Binding{
		testTaggedBinding(t, 0, contract.UID("pod-uid-1"), contract.ContainerName("api")),
	})
	untaggedBundle, _ := buildForTest(t, untagged)
	if untaggedBundle.Images[0].Platform.Status != contract.PlatformUnknown ||
		untaggedBundle.Images[0].Platform.OS != "" || untaggedBundle.Images[0].Platform.Architecture != "" {
		t.Fatalf("unknown platform carried an observation: %+v", untaggedBundle.Images[0].Platform)
	}
	if items := evidenceOfType(untaggedBundle.Evidence, "container_status.platform.os"); len(items) != 0 {
		t.Fatal("an unknown platform must not produce platform items")
	}

	parsed := parseImport(t, csvOneRow)
	invalid := testBinding(t, 0, contract.UID("pod-uid-1"), contract.ContainerRegular, contract.ContainerName("api"))
	invalid.Image.PlatformOS = ""
	if _, err := normalize.Normalize(normalize.Input{Import: parsed.result, Bindings: []normalize.Binding{invalid}}); err == nil {
		t.Fatal("known platform without an observed carrier must be refused")
	}
}

func TestBuildIndexRemainsRaw(t *testing.T) {
	raw := contract.RawImageID("registry.example/payments/api@" + testDigest("b"))
	index := testTaggedBinding(t, 0, contract.UID("pod-uid-1"), contract.ContainerName("api"))
	index.Image.RawImageID = &raw

	input := testInput(t, csvOneRow, []normalize.Binding{index})
	bundle, _ := buildForTest(t, input)

	image := bundle.Images[0]
	if image.NormalizedDigest != nil {
		t.Fatal("a raw reference was promoted to a guaranteed digest")
	}
	if image.Platform.Status != contract.PlatformUnknown {
		t.Fatalf("platform = %+v, an index digest is never a platform manifest", image.Platform)
	}
	if image.RawImageID == nil || string(*image.RawImageID) != string(raw) {
		t.Fatalf("raw = %v", image.RawImageID)
	}
	if items := evidenceOfType(bundle.Evidence, "container_status.image_id"); len(items) != 1 {
		t.Fatalf("image_id items = %d", len(items))
	}
	if items := evidenceOfType(bundle.Evidence, "container_status.normalized_digest"); len(items) != 0 {
		t.Fatal("a non-guaranteed digest produced a digest item")
	}
}

func TestBuildDuplicateOccurrences(t *testing.T) {
	csv := csvFromRows(
		csvRowFor("CVE-2024-1234", "payments/api", "release"),
		csvRowFor("CVE-2024-1234", "payments/api", "release"),
	)
	input := testInput(t, csv, []normalize.Binding{
		testBinding(t, 0, contract.UID("pod-uid-1"), contract.ContainerRegular, contract.ContainerName("api")),
		testBinding(t, 1, contract.UID("pod-uid-1"), contract.ContainerRegular, contract.ContainerName("api")),
	})
	bundle, _ := buildForTest(t, input)

	items := evidenceOfType(bundle.Evidence, "prisma_v1.vulnerability_id")
	if len(items) != 2 {
		t.Fatalf("vulnerability items = %d, want both occurrences", len(items))
	}
	if items[0].Locator == items[1].Locator {
		t.Fatal("identical rows keep distinct locators")
	}
	if len(bundle.Images) != 2 {
		t.Fatalf("images = %d, duplicates are never collapsed", len(bundle.Images))
	}
}

func TestBuildDeclaredValueRules(t *testing.T) {
	header := "schema_version,vulnerability_id,package_name,installed_version,fix_status,image_registry,image_repository,path,severity,description\n"
	csv := header + "1.0,CVE-2024-1234,openssl,1.1.1k,fixed,registry.example,payments/api,=1+1,,\" padded \"\n"
	input := testInput(t, csv, []normalize.Binding{
		testBinding(t, 0, contract.UID("pod-uid-1"), contract.ContainerRegular, contract.ContainerName("api")),
	})
	bundle, _ := buildForTest(t, input)

	if items := evidenceOfType(bundle.Evidence, "prisma_v1.severity"); len(items) != 0 {
		t.Fatal("an empty optional means not informed, it is not an observation")
	}
	description := evidenceOfType(bundle.Evidence, "prisma_v1.description")
	if len(description) != 1 {
		t.Fatalf("description items = %d", len(description))
	}
	if description[0].Value != nil {
		t.Fatal("a value the wire cannot carry verbatim must not be emitted")
	}
	if description[0].ValueHash == nil || *description[0].ValueHash != HashValue(" padded ") {
		t.Fatalf("description hash = %v, want the hash of the exact bytes", description[0].ValueHash)
	}
	path := evidenceOfType(bundle.Evidence, "prisma_v1.path")
	if len(path) != 1 || path[0].Value == nil || *path[0].Value != "=1+1" {
		t.Fatalf("formula literal = %+v", path)
	}
	if path[0].ValueHash == nil || *path[0].ValueHash != HashValue("=1+1") {
		t.Fatal("the value hash must cover the literal value")
	}
}

func TestBuildMapsEveryDeclaredColumn(t *testing.T) {
	header := "schema_version,vulnerability_id,package_name,installed_version,fix_status,image_registry,image_repository,image_tag,package_type,package_id,path,severity,description,published_date,discovery_date\n"
	row := "1.0,CVE-2024-1234,openssl,1.1.1k,fixed,registry.example,payments/api,release,rpm,pkg-1,/usr/lib/openssl.so,high,a description,2024-01-02,2024-01-03\n"
	input := testInput(t, header+row, []normalize.Binding{
		testBinding(t, 0, contract.UID("pod-uid-1"), contract.ContainerRegular, contract.ContainerName("api")),
	})
	bundle, _ := buildForTest(t, input)

	expected := map[string]string{
		"prisma_v1.schema_version":    "1.0",
		"prisma_v1.vulnerability_id":  "CVE-2024-1234",
		"prisma_v1.package_name":      "openssl",
		"prisma_v1.installed_version": "1.1.1k",
		"prisma_v1.fix_status":        "fixed",
		"prisma_v1.image_registry":    "registry.example",
		"prisma_v1.image_repository":  "payments/api",
		"prisma_v1.image_tag":         "release",
		"prisma_v1.package_type":      "rpm",
		"prisma_v1.package_id":        "pkg-1",
		"prisma_v1.path":              "/usr/lib/openssl.so",
		"prisma_v1.severity":          "high",
		"prisma_v1.description":       "a description",
		"prisma_v1.published_date":    "2024-01-02",
		"prisma_v1.discovery_date":    "2024-01-03",
	}
	for itemType, value := range expected {
		items := evidenceOfType(bundle.Evidence, itemType)
		if len(items) != 1 {
			t.Fatalf("item %q count = %d, want one per informed column", itemType, len(items))
		}
		if items[0].Value == nil || *items[0].Value != value {
			t.Fatalf("item %q value = %v, want %q", itemType, items[0].Value, value)
		}
		if items[0].ValueHash == nil || *items[0].ValueHash != HashValue(value) {
			t.Fatalf("item %q does not hash its own value", itemType)
		}
	}
	// Fifteen declared columns, the composed reference and four observation facts.
	if len(bundle.Evidence) != len(expected)+5 {
		t.Fatalf("evidence = %d items, want %d", len(bundle.Evidence), len(expected)+5)
	}
}

func TestBuildMissingObservationTime(t *testing.T) {
	mutations := map[string]func(binding *normalize.Binding){
		"no timestamp": func(binding *normalize.Binding) { binding.Image.ObservedAt = nil },
		"no source":    func(binding *normalize.Binding) { binding.Image.SourceName = "" },
		"bad hash":     func(binding *normalize.Binding) { binding.Image.SourceHash = "sha256:short" },
		"no locator":   func(binding *normalize.Binding) { binding.Image.Locator = "" },
		"no digest": func(binding *normalize.Binding) {
			binding.Image.GuaranteedDigest = nil
			binding.Image.Platform = contract.PlatformUnknown
			binding.Image.PlatformOS = ""
			binding.Image.PlatformArchitecture = ""
		},
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			binding := testBinding(t, 0, contract.UID("pod-uid-1"), contract.ContainerRegular, contract.ContainerName("api"))
			mutate(&binding)
			bundle, diagnostics := buildForTest(t, testInput(t, csvOneRow, []normalize.Binding{binding}))

			if name == "no digest" {
				if bundle.Images[0].RawImageID == nil {
					t.Fatal("the raw reference is present and its provenance is complete")
				}
				return
			}
			image := bundle.Images[0]
			if image.RawImageID != nil || image.NormalizedDigest != nil {
				t.Fatal("observation facts were projected without complete provenance")
			}
			if image.RequestedImage == nil {
				t.Fatal("the declared reference still has CSV provenance")
			}
			if items := evidenceOfType(bundle.Evidence, "container_status.image_id"); len(items) != 0 {
				t.Fatal("an unproven observation produced an item")
			}
			if len(diagnostics.Omissions) != 1 || diagnostics.Omissions[0].Reason != OmissionMissingProvenance {
				t.Fatalf("omissions = %+v", diagnostics.Omissions)
			}
			assertErrorPresent(t, bundle, errObservationUnproven.Error())
			if bundle.Provenance.Completeness != contract.CompletenessPartial {
				t.Fatalf("completeness = %q, want partial", bundle.Provenance.Completeness)
			}
		})
	}
}

func assertErrorPresent(t *testing.T, bundle contract.Bundle, want string) {
	t.Helper()
	for _, message := range bundle.Provenance.Errors {
		if message == want {
			return
		}
	}
	t.Fatalf("error %q not found in %+v", want, bundle.Provenance.Errors)
}
