package normalize

import (
	"bytes"
	"testing"

	"github.com/d4rpell/Ariadne/internal/ingest"
	"github.com/d4rpell/Ariadne/internal/schema"
)

// Incremento 5 de A2-08-F2: replay de la procedencia 1.1 (ADR-0028 §9.5, §9.10).
// Los artefactos 1.1 se reproducen con selector/versión explícitos; una mezcla
// de versión entre el artefacto y la solicitud se rechaza como versión no
// soportada.

// a208F2APIContext mirrors the connector acquisition context of §9.4.
func a208F2APIContext() ingest.NativeContext {
	f := false
	one := 1
	return ingest.NativeContext{
		OriginAlias:        "synthetic",
		SourceAlias:        "prisma-page-000001",
		DeclaredEdition:    "compute_self_hosted",
		DeclaredRelease:    "34.04.145",
		VersionBasis:       "operator_declared",
		ReportKind:         "deployed_images",
		AcquisitionKind:    schema.NativeAcquisitionKindAPI,
		AcquiredAt:         "2026-10-03T00:00:00Z",
		CaptureTermination: "finished",
		ScopeMode:          "unfiltered_declared",
		FilterStatus:       "none_declared",
		Compact:            &f,
		NormalizedSeverity: &f,
		Layers:             &f,
		FieldsMode:         "unrestricted_declared",
		SelectedFields:     []string{},
		PageMode:           "single_page_declared",
		PageOrdinal:        &one,
		PagesExpected:      &one,
		DataPolicyAck:      "prisma-native-offline-redaction-v1/1.0",
	}
}

func a208F2JSONProfile() ingest.NativeProfile {
	return ingest.NativeProfile{
		Selector:         schema.NativeJSONSelector,
		InputVersion:     schema.NativeInputVersion,
		Name:             schema.NativeJSONProfile,
		RedactionPolicy:  schema.NativeRedactionPolicy,
		AdapterSemantics: schema.NativeAdapterSemantics,
	}
}

// a208F2APIArtifacts builds the three 1.1 artifacts from a minimal page.
func a208F2APIArtifacts(t *testing.T) NativeArtifacts {
	t.Helper()
	draft, err := ingest.AdmitNativeJSON([]byte(`[{"type":"image","packages":[],"vulnerabilities":[]}]`), ingest.NativeAdmission{})
	if err != nil {
		t.Fatalf("admission failed: %v", err)
	}
	src := draft.Source(a208F2JSONProfile(), a208F2APIContext())
	src.Version = schema.NativeFormatVersionV11
	art, err := EncodePrismaNativeImport(src)
	if err != nil {
		t.Fatalf("encode failed: %v", err)
	}
	return art
}

// TestA208F2ReplayEquivalence asserts the 1.1 artifacts replay with the explicit
// 1.1 selector/version and recompute the same semantics.
func TestA208F2ReplayEquivalence(t *testing.T) {
	art := a208F2APIArtifacts(t)
	inv, err := ReplayPrismaNative(
		bytes.NewReader(art.Source), bytes.NewReader(art.Manifest), bytes.NewReader(art.Digest),
		schema.NativeSourceFormat, schema.NativeFormatVersionV11,
	)
	if err != nil {
		t.Fatalf("1.1 replay failed: %v", err)
	}
	if inv.RecordCount != 1 {
		t.Fatalf("inventory records = %d, want 1", inv.RecordCount)
	}
}

// TestA208F2ReplayRejectsVersionMix asserts a 1.1 artifact replayed as 1.0 (and
// the reverse) is rejected as an unsupported version.
func TestA208F2ReplayRejectsVersionMix(t *testing.T) {
	api := a208F2APIArtifacts(t)
	if _, err := ReplayPrismaNative(
		bytes.NewReader(api.Source), bytes.NewReader(api.Manifest), bytes.NewReader(api.Digest),
		schema.NativeSourceFormat, schema.NativeFormatVersion,
	); err == nil || err.Code != ingest.NativeCodeUnsupportedVersion {
		t.Fatalf("1.1 artifacts as 1.0: err = %v, want %s", err, ingest.NativeCodeUnsupportedVersion)
	}

	draft, err := ingest.AdmitNativeJSON([]byte(`[{"type":"image","packages":[],"vulnerabilities":[]}]`), ingest.NativeAdmission{})
	if err != nil {
		t.Fatalf("admission failed: %v", err)
	}
	offline, err := EncodePrismaNativeImport(draft.Source(a208F2JSONProfile(), nativeTestContext()))
	if err != nil {
		t.Fatalf("offline encode failed: %v", err)
	}
	if _, err := ReplayPrismaNative(
		bytes.NewReader(offline.Source), bytes.NewReader(offline.Manifest), bytes.NewReader(offline.Digest),
		schema.NativeSourceFormat, schema.NativeFormatVersionV11,
	); err == nil || err.Code != ingest.NativeCodeUnsupportedVersion {
		t.Fatalf("1.0 artifacts as 1.1: err = %v, want %s", err, ingest.NativeCodeUnsupportedVersion)
	}
}
