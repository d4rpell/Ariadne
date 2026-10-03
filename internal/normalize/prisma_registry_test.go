package normalize

import (
	"bytes"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/d4rpell/Ariadne/internal/ingest"
	"github.com/d4rpell/Ariadne/internal/schema"
)

// registryNormContext is the ADR-0029 §5 context for the registry JSON profile.
func registryNormContext() ingest.NativeContext {
	ctx := nativeTestContext()
	ctx.ReportKind = schema.NativeReportKindRegistry
	return ctx
}

func registrySourceOf(t *testing.T) ingest.NativeSource {
	t.Helper()
	src, err := ingest.ParsePrismaNative(strings.NewReader(`[{"type":"image","packages":[],"vulnerabilities":[]}]`),
		schema.NativeRegistryJSONSelector, schema.NativeRegistryInputVersion, schema.NativeRegistryJSONProfile, registryNormContext())
	if err != nil {
		t.Fatalf("parse failed: %v", err)
	}
	return src
}

func registryArtifacts(t *testing.T) NativeArtifacts {
	t.Helper()
	art, err := EncodePrismaNativeImport(registrySourceOf(t))
	if err != nil {
		t.Fatalf("encode failed: %v", err)
	}
	return art
}

func registrySliceHas(xs []string, want string) bool {
	for _, x := range xs {
		if x == want {
			return true
		}
	}
	return false
}

func registrySliceIndex(xs []string, want string) int {
	for i, x := range xs {
		if x == want {
			return i
		}
	}
	return -1
}

// TestPrismaRegistryLimitationsCatalogueAndSubset checks the 24-code catalogue
// order and the emitted subset of a minimal JSON registry source.
func TestPrismaRegistryLimitationsCatalogueAndSubset(t *testing.T) {
	cat := schema.NativeRegistryLimitations()
	wantCat := []string{
		"documentary_profile", "registry_profile", "csv_header_unverified",
		"registry_not_deployment", "origin_version_unknown",
		"origin_not_authenticated", "inventory_not_verified", "no_runtime_binding",
		"cvss_consistency_not_verified", "original_content_not_retained",
		"data_excluded", "fields_incomplete", "values_invalid",
		"values_uninterpretable", "capture_aborted", "capture_unknown",
		"scope_unknown", "selection_restricted", "page_scope_unverified",
		"scan_error_reported", "distro_coverage_missing", "temporal_conflict",
		"attribute_source_conflict", "declared_count_difference",
	}
	if !slices.Equal(cat, wantCat) {
		t.Fatalf("catalogue mismatch:\n got %v\nwant %v", cat, wantCat)
	}
	man, err := BuildNativeManifest(registrySourceOf(t), "sha256:"+strings.Repeat("0", 64), 1)
	if err != nil {
		t.Fatalf("manifest: %v", err)
	}
	if !registrySliceHas(man.Limitations, "registry_profile") || !registrySliceHas(man.Limitations, "registry_not_deployment") {
		t.Fatalf("registry limitations missing: %v", man.Limitations)
	}
	if registrySliceHas(man.Limitations, "csv_header_unverified") {
		t.Fatalf("csv_header_unverified must be inactive for a JSON source: %v", man.Limitations)
	}
	if registrySliceIndex(man.Limitations, "registry_profile") != 1 ||
		registrySliceIndex(man.Limitations, "registry_not_deployment") != 2 {
		t.Fatalf("emitted subset order wrong: %v", man.Limitations)
	}
	// The emitted array must be an in-order subsequence of the full catalogue.
	j := 0
	for _, c := range cat {
		if j < len(man.Limitations) && man.Limitations[j] == c {
			j++
		}
	}
	if j != len(man.Limitations) {
		t.Fatalf("emitted limitations are not an in-order subsequence of the catalogue: %v", man.Limitations)
	}
}

// TestPrismaRegistryProjectsIdenticallyViaSharedAdmission is the M13 oracle: the
// deployed and registry profiles project the same payload through the single
// shared admission, so their derived counts are identical (only the report
// class, formats and limitations differ).
func TestPrismaRegistryProjectsIdenticallyViaSharedAdmission(t *testing.T) {
	payload := `[{"type":"image","vulnerabilities":[{"cve":"CVE-2026-1","cvss":9.81},{"cve":"CVE-2026-2","cvss":7.5}]}]`
	deployed, err := ingest.ParsePrismaNative(strings.NewReader(payload),
		schema.NativeJSONSelector, schema.NativeInputVersion, schema.NativeJSONProfile, nativeTestContext())
	if err != nil {
		t.Fatalf("deployed parse: %v", err)
	}
	registry, err := ingest.ParsePrismaNative(strings.NewReader(payload),
		schema.NativeRegistryJSONSelector, schema.NativeRegistryInputVersion, schema.NativeRegistryJSONProfile, registryNormContext())
	if err != nil {
		t.Fatalf("registry parse: %v", err)
	}
	if !reflect.DeepEqual(deployed.Records, registry.Records) {
		t.Fatalf("projected records diverge:\ndeployed=%+v\nregistry=%+v", deployed.Records, registry.Records)
	}
	h := "sha256:" + strings.Repeat("0", 64)
	manD, err := BuildNativeManifest(deployed, h, 1)
	if err != nil {
		t.Fatalf("deployed manifest: %v", err)
	}
	manR, err := BuildNativeManifest(registry, h, 1)
	if err != nil {
		t.Fatalf("registry manifest: %v", err)
	}
	if manD.Counts != manR.Counts {
		t.Fatalf("projections diverge: deployed=%+v registry=%+v", manD.Counts, manR.Counts)
	}
}

// TestPrismaRegistryRuntimeBindingNotAttemptedWithDeploymentContext checks that
// conserved clusters/namespaces never produce a runtime binding.
func TestPrismaRegistryRuntimeBindingNotAttemptedWithDeploymentContext(t *testing.T) {
	src, err := ingest.ParsePrismaNative(
		strings.NewReader(`[{"type":"image","packages":[],"vulnerabilities":[],"clusters":["c1"],"namespaces":["ns1"]}]`),
		schema.NativeRegistryJSONSelector, schema.NativeRegistryInputVersion, schema.NativeRegistryJSONProfile, registryNormContext())
	if err != nil {
		t.Fatalf("parse failed: %v", err)
	}
	inv, err := InterpretPrismaNative(src, "sha256:"+strings.Repeat("0", 64), 1)
	if err != nil {
		t.Fatalf("interpret: %v", err)
	}
	if inv.RuntimeBinding != "not_attempted" {
		t.Fatalf("runtime binding = %q, want not_attempted even with clusters/namespaces", inv.RuntimeBinding)
	}
}

// TestPrismaRegistryRuntimeBindingNotAttempted checks the central invariant.
func TestPrismaRegistryRuntimeBindingNotAttempted(t *testing.T) {
	inv, err := InterpretPrismaNative(registrySourceOf(t), "sha256:"+strings.Repeat("0", 64), 1)
	if err != nil {
		t.Fatalf("interpret: %v", err)
	}
	if inv.RuntimeBinding != "not_attempted" {
		t.Fatalf("runtime binding = %q, want not_attempted", inv.RuntimeBinding)
	}
}

// TestPrismaRegistryLimitationsWithoutLosses checks that the global registry
// limitations never generate losses by themselves.
func TestPrismaRegistryLimitationsWithoutLosses(t *testing.T) {
	man, err := BuildNativeManifest(registrySourceOf(t), "sha256:"+strings.Repeat("0", 64), 1)
	if err != nil {
		t.Fatalf("manifest: %v", err)
	}
	if !registrySliceHas(man.Limitations, "registry_not_deployment") || !registrySliceHas(man.Limitations, "registry_profile") {
		t.Fatalf("registry limitations inactive: %v", man.Limitations)
	}
	if len(man.Losses) != 0 {
		t.Fatalf("global limitations must not generate losses: %v", man.Losses)
	}
}

// TestPrismaRegistryReplayEquivalence checks the 2.0 artifacts replay under the
// explicit registry selector/version.
func TestPrismaRegistryReplayEquivalence(t *testing.T) {
	art := registryArtifacts(t)
	inv, err := ReplayPrismaNative(
		bytes.NewReader(art.Source), bytes.NewReader(art.Manifest), bytes.NewReader(art.Digest),
		schema.NativeRegistrySourceFormat, schema.NativeRegistryInputVersion,
	)
	if err != nil {
		t.Fatalf("registry replay failed: %v", err)
	}
	if inv.RecordCount != 1 {
		t.Fatalf("inventory records = %d, want 1", inv.RecordCount)
	}
	if inv.RuntimeBinding != "not_attempted" {
		t.Fatalf("runtime binding = %q", inv.RuntimeBinding)
	}
}

// TestPrismaRegistryReplayRejectsMix checks that family crossings are rejected:
// an unknown selector, a deployed selector with the registry version, and the
// registry selector with a deployed version.
func TestPrismaRegistryReplayRejectsMix(t *testing.T) {
	art := registryArtifacts(t)
	if _, err := ReplayPrismaNative(
		bytes.NewReader(art.Source), bytes.NewReader(art.Manifest), bytes.NewReader(art.Digest),
		"prisma-native-nope", schema.NativeRegistryInputVersion,
	); err == nil || err.Code != ingest.NativeCodeUnsupportedSelector {
		t.Fatalf("unknown selector: err = %v, want %s", err, ingest.NativeCodeUnsupportedSelector)
	}
	if _, err := ReplayPrismaNative(
		bytes.NewReader(art.Source), bytes.NewReader(art.Manifest), bytes.NewReader(art.Digest),
		schema.NativeSourceFormat, schema.NativeRegistryInputVersion,
	); err == nil || err.Code != ingest.NativeCodeUnsupportedVersion {
		t.Fatalf("deployed selector with registry version: err = %v, want %s", err, ingest.NativeCodeUnsupportedVersion)
	}
	if _, err := ReplayPrismaNative(
		bytes.NewReader(art.Source), bytes.NewReader(art.Manifest), bytes.NewReader(art.Digest),
		schema.NativeRegistrySourceFormat, schema.NativeInputVersion,
	); err == nil || err.Code != ingest.NativeCodeUnsupportedVersion {
		t.Fatalf("registry selector with deployed version: err = %v, want %s", err, ingest.NativeCodeUnsupportedVersion)
	}
}
