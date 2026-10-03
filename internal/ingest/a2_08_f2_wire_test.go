package ingest

import (
	"strings"
	"testing"

	"github.com/d4rpell/Ariadne/internal/schema"
)

// Incremento 5 de A2-08-F2: versionado explícito de la procedencia (ADR-0028
// §9.5). La versión 1.1 se reserva a compute_api del perfil JSON; la 1.0 conserva
// bytes y semántica y rechaza compute_api; se rechazan las mezclas de versión y
// perfil.

// a208F2APIContext is the F2 acquisition context of §9.4 with compute_api
// provenance and single_page_declared pagination.
func a208F2APIContext() NativeContext {
	f := false
	one := 1
	return NativeContext{
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

// a208F2APISource builds a valid 1.1 source for the selected JSON profile.
func a208F2APISource(t *testing.T) NativeSource {
	t.Helper()
	draft, err := AdmitNativeJSON([]byte(a208F2MinimalJSON), NativeAdmission{})
	if err != nil {
		t.Fatalf("admission failed: %v", err)
	}
	src := draft.Source(jsonProfile(), a208F2APIContext())
	src.Version = schema.NativeFormatVersionV11
	return src
}

// TestA208F2CanonicalAPISource asserts a 1.1 source validates and serializes the
// explicit 1.1 version while 1.0 keeps its version.
func TestA208F2CanonicalAPISource(t *testing.T) {
	src := a208F2APISource(t)
	if err := ValidateNativeSource(src); err != nil {
		t.Fatalf("1.1 API source rejected: %v", err)
	}
	got := string(EncodeNativeSource(src))
	if !strings.Contains(got, `"version":"1.1"`) {
		t.Fatalf("1.1 source lost its version: %s", got)
	}
	offline := minimalJSONSource()
	if off := string(EncodeNativeSource(offline)); !strings.Contains(off, `"version":"1.0"`) {
		t.Fatalf("1.0 source changed its version: %s", off)
	}
}

// TestA208F2ArtifactVersionMatrix covers the §9.5 negative matrix through the
// production validator.
func TestA208F2ArtifactVersionMatrix(t *testing.T) {
	api := a208F2APISource(t)
	offline := minimalJSONSource()

	asVersion := func(src NativeSource, v string) NativeSource { src.Version = v; return src }
	asKind := func(src NativeSource, k string) NativeSource { src.Context.AcquisitionKind = k; return src }

	cases := []struct {
		name string
		src  NativeSource
		ok   bool
	}{
		{"api_1_1", api, true},
		{"offline_1_0", offline, true},
		{"compute_api_1_0", asVersion(api, schema.NativeFormatVersion), false},
		{"export_1_1", asKind(asVersion(offline, schema.NativeFormatVersionV11), schema.NativeAcquisitionKindExport), false},
		{"synthetic_1_1", asKind(asVersion(offline, schema.NativeFormatVersionV11), schema.NativeAcquisitionKindSynthetic), false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidateNativeSource(tc.src)
			if tc.ok && err != nil {
				t.Fatalf("expected accepted, got %v", err)
			}
			if !tc.ok && err == nil {
				t.Fatal("expected rejected, got accepted")
			}
		})
	}
}

// TestA208F2CSVIsRejectedUnderV11 asserts the 1.1 provenance is reserved to the
// JSON profile: a CSV profile under 1.1 is an invalid artifact.
func TestA208F2CSVIsRejectedUnderV11(t *testing.T) {
	csv := minimalCSVSource()
	csv.Context.AcquisitionKind = schema.NativeAcquisitionKindAPI
	csv.Version = schema.NativeFormatVersionV11
	if err := ValidateNativeSource(csv); err == nil {
		t.Fatal("CSV source under version 1.1 was accepted")
	}
}
