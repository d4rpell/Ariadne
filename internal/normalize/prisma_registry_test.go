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

// TestPrismaRegistryManifestVectorIsDeployedWithDeclaredDeltas checks the
// registry manifest wire byte for byte: the deployed manifest with the declared
// family substitutions (format, version, profile fields, report_kind) plus the
// two mandatory global limitations inserted at their catalogue positions.
func TestPrismaRegistryManifestVectorIsDeployedWithDeclaredDeltas(t *testing.T) {
	payload := `[{"type":"image","packages":[],"vulnerabilities":[]}]`
	dep, err := ingest.ParsePrismaNative(strings.NewReader(payload),
		schema.NativeJSONSelector, schema.NativeInputVersion, schema.NativeJSONProfile, nativeTestContext())
	if err != nil {
		t.Fatalf("deployed parse: %v", err)
	}
	reg, err := ingest.ParsePrismaNative(strings.NewReader(payload),
		schema.NativeRegistryJSONSelector, schema.NativeRegistryInputVersion, schema.NativeRegistryJSONProfile, registryNormContext())
	if err != nil {
		t.Fatalf("registry parse: %v", err)
	}
	regBytes := ingest.EncodeNativeSource(reg)
	h := ingest.HashNativeSource(regBytes)
	n := uint64(len(regBytes))
	manD, err := BuildNativeManifest(dep, h, n)
	if err != nil {
		t.Fatalf("deployed manifest: %v", err)
	}
	manR, err := BuildNativeManifest(reg, h, n)
	if err != nil {
		t.Fatalf("registry manifest: %v", err)
	}
	got := string(ingest.EncodeNativeManifest(manR))
	want := string(ingest.EncodeNativeManifest(manD))
	for _, r := range [][2]string{
		{`"format":"` + schema.NativeManifestFormat + `"`, `"format":"` + schema.NativeRegistryManifestFormat + `"`},
		{`"version":"` + schema.NativeFormatVersion + `"`, `"version":"` + schema.NativeRegistryInputVersion + `"`},
		{`"selector":"` + schema.NativeJSONSelector + `"`, `"selector":"` + schema.NativeRegistryJSONSelector + `"`},
		{`"input_version":"` + schema.NativeInputVersion + `"`, `"input_version":"` + schema.NativeRegistryInputVersion + `"`},
		{`"name":"` + schema.NativeJSONProfile + `"`, `"name":"` + schema.NativeRegistryJSONProfile + `"`},
		{`"adapter_semantics":"` + schema.NativeAdapterSemantics + `"`, `"adapter_semantics":"` + schema.NativeRegistryAdapterSemantics + `"`},
		{`"limitations":["documentary_profile",`, `"limitations":["documentary_profile","registry_profile","registry_not_deployment",`},
	} {
		next := strings.Replace(want, r[0], r[1], 1)
		if next == want {
			t.Fatalf("substitution did not apply: %s", r[0])
		}
		want = next
	}
	if got != want {
		t.Fatalf("registry manifest is not the deployed one with declared deltas:\n got %s\nwant %s", got, want)
	}
	// The manifest is fully derived from the real registry source: its sidecar is
	// 72 bytes and covers the manifest bytes.
	sidecar := ingest.NativeManifestSidecar(ingest.HashNativeManifest([]byte(got)))
	if len(sidecar) != 72 {
		t.Fatalf("sidecar length = %d, want 72", len(sidecar))
	}
}

// TestPrismaRegistryReplayInventoryEquivalence checks that replay recomputes the
// same inventory (records, facts, diagnostics and coordinates) as the initial
// interpretation.
func TestPrismaRegistryReplayInventoryEquivalence(t *testing.T) {
	payload := `[{"type":"image","vulnerabilities":[{"cve":"CVE-2026-1","cvss":9.81},{"cve":"not-a-cve","cvss":1e0}]}]`
	src, err := ingest.ParsePrismaNative(strings.NewReader(payload),
		schema.NativeRegistryJSONSelector, schema.NativeRegistryInputVersion, schema.NativeRegistryJSONProfile, registryNormContext())
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	art, err := EncodePrismaNativeImport(src)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	initial, err := InterpretPrismaNative(src, ingest.HashNativeSource(art.Source), uint64(len(art.Source)))
	if err != nil {
		t.Fatalf("interpret: %v", err)
	}
	replayed, err := ReplayPrismaNative(
		bytes.NewReader(art.Source), bytes.NewReader(art.Manifest), bytes.NewReader(art.Digest),
		schema.NativeRegistrySourceFormat, schema.NativeRegistryInputVersion,
	)
	if err != nil {
		t.Fatalf("replay: %v", err)
	}
	if !reflect.DeepEqual(initial, replayed) {
		t.Fatalf("replay inventory differs from the initial interpretation")
	}
}

// TestPrismaRegistryReplayAnchors checks the replay diagnostics and their
// anchors for the digest and manifest_mismatch surfaces.
func TestPrismaRegistryReplayAnchors(t *testing.T) {
	art := registryArtifacts(t)

	t.Run("digest_mismatch", func(t *testing.T) {
		bad := append([]byte{}, art.Digest...)
		if bad[10] == '0' {
			bad[10] = '1'
		} else {
			bad[10] = '0'
		}
		_, err := ReplayPrismaNative(bytes.NewReader(art.Source), bytes.NewReader(art.Manifest), bytes.NewReader(bad),
			schema.NativeRegistrySourceFormat, schema.NativeRegistryInputVersion)
		if err == nil || err.Code != ingest.NativeCodeHashMismatch ||
			err.Phase != ingest.NativePhaseReplayVerification || err.OffsetSpace != ingest.NativeSpaceDigest || err.Offset != 0 {
			t.Fatalf("digest: err = %+v", err)
		}
	})

	t.Run("manifest_limitations_mismatch", func(t *testing.T) {
		// Drop a limitation and recompute the sidecar to reach the semantic check.
		edited := bytes.Replace(art.Manifest, []byte(`"registry_profile",`), []byte(``), 1)
		if bytes.Equal(edited, art.Manifest) {
			t.Fatal("edit did not apply")
		}
		digest := ingest.NativeManifestSidecar(ingest.HashNativeManifest(edited))
		wantOff, ok := ingest.NativeManifestMemberValueOffset(edited, "limitations")
		if !ok {
			t.Fatal("no limitations value offset")
		}
		_, err := ReplayPrismaNative(bytes.NewReader(art.Source), bytes.NewReader(edited), bytes.NewReader(digest),
			schema.NativeRegistrySourceFormat, schema.NativeRegistryInputVersion)
		if err == nil || err.Code != ingest.NativeCodeManifestMismatch ||
			err.Phase != ingest.NativePhaseReplayVerification || err.OffsetSpace != ingest.NativeSpaceManifest || err.Offset != wantOff {
			t.Fatalf("limitations: err = %+v, want manifest_mismatch at %d", err, wantOff)
		}
	})

	t.Run("source_hash_mismatch", func(t *testing.T) {
		// Flip a hex digit of the declared source_hash and recompute the sidecar so
		// the manifest stays canonical and only the hash diverges.
		marker := []byte(`"source_hash":"sha256:`)
		idx := bytes.Index(art.Manifest, marker)
		if idx < 0 {
			t.Fatal("no source_hash member")
		}
		edited := append([]byte{}, art.Manifest...)
		pos := idx + len(marker)
		if edited[pos] == '0' {
			edited[pos] = '1'
		} else {
			edited[pos] = '0'
		}
		digest := ingest.NativeManifestSidecar(ingest.HashNativeManifest(edited))
		wantOff, ok := ingest.NativeManifestMemberValueOffset(edited, "source_hash")
		if !ok {
			t.Fatal("no source_hash value offset")
		}
		_, err := ReplayPrismaNative(bytes.NewReader(art.Source), bytes.NewReader(edited), bytes.NewReader(digest),
			schema.NativeRegistrySourceFormat, schema.NativeRegistryInputVersion)
		if err == nil || err.Code != ingest.NativeCodeHashMismatch ||
			err.Phase != ingest.NativePhaseReplayVerification || err.OffsetSpace != ingest.NativeSpaceManifest || err.Offset != wantOff {
			t.Fatalf("source_hash: err = %+v, want hash_mismatch at %d", err, wantOff)
		}
	})
}

// TestPrismaRegistrySidecarBoundary checks the 72-byte sidecar length: 71 and 73
// are rejected, 72 (well formed) is admitted.
func TestPrismaRegistrySidecarBoundary(t *testing.T) {
	art := registryArtifacts(t)
	good := art.Digest
	if len(good) != 72 {
		t.Fatalf("sidecar length = %d, want 72", len(good))
	}
	for _, tc := range []struct {
		name  string
		bytes []byte
		ok    bool
	}{
		{"71", good[:71], false},
		{"72", good, true},
		{"73", append(append([]byte{}, good...), '\n'), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := ReplayPrismaNative(bytes.NewReader(art.Source), bytes.NewReader(art.Manifest), bytes.NewReader(tc.bytes),
				schema.NativeRegistrySourceFormat, schema.NativeRegistryInputVersion)
			if tc.ok && err != nil {
				t.Fatalf("72-byte sidecar rejected: %v", err)
			}
			if !tc.ok && err == nil {
				t.Fatalf("%s-byte sidecar admitted", tc.name)
			}
		})
	}
}
