package ingest

import (
	"bytes"
	"io"
	"strings"
	"testing"

	"github.com/d4rpell/Ariadne/internal/schema"
)

// registryTestContext is the ADR-0029 §5 context for the registry JSON profile.
func registryTestContext() NativeContext {
	ctx := validCtx()
	ctx.ReportKind = schema.NativeReportKindRegistry
	return ctx
}

const registryBody = `[{"type":"image","packages":[],"vulnerabilities":[]}]`

// TestPrismaRegistryContextAcceptsRegistryKind admits the registry report kind
// under the registry selector and version.
func TestPrismaRegistryContextAcceptsRegistryKind(t *testing.T) {
	src, err := ParsePrismaNative(strings.NewReader(registryBody),
		schema.NativeRegistryJSONSelector, schema.NativeRegistryInputVersion, schema.NativeRegistryJSONProfile, registryTestContext())
	if err != nil {
		t.Fatalf("registry context rejected: %v", err)
	}
	if src.Version != schema.NativeRegistryInputVersion {
		t.Fatalf("version = %q, want %q", src.Version, schema.NativeRegistryInputVersion)
	}
	if src.Profile.Selector != schema.NativeRegistryJSONSelector || src.Profile.Name != schema.NativeRegistryJSONProfile {
		t.Fatalf("profile = %+v", src.Profile)
	}
	if src.Profile.AdapterSemantics != schema.NativeRegistryAdapterSemantics {
		t.Fatalf("adapter semantics = %q", src.Profile.AdapterSemantics)
	}
}

// TestPrismaRegistryRejectsDeployedKind rejects a deployed report kind under the
// registry selector.
func TestPrismaRegistryRejectsDeployedKind(t *testing.T) {
	_, err := ParsePrismaNative(strings.NewReader(registryBody),
		schema.NativeRegistryJSONSelector, schema.NativeRegistryInputVersion, schema.NativeRegistryJSONProfile, validCtx())
	if err == nil || err.Code != NativeCodeInvalidContext {
		t.Fatalf("err = %v, want invalid_context", err)
	}
}

// TestPrismaRegistryArtifactVersionMatrix checks the closed selector/version/
// profile combinations of §4.7.
func TestPrismaRegistryArtifactVersionMatrix(t *testing.T) {
	cases := []struct {
		name, selector, version, profile string
		ctx                              NativeContext
		code                             string
	}{
		{"registry_with_deployed_version", schema.NativeRegistryJSONSelector, schema.NativeInputVersion, schema.NativeRegistryJSONProfile, registryTestContext(), NativeCodeUnsupportedVersion},
		{"deployed_with_registry_version", schema.NativeJSONSelector, schema.NativeRegistryInputVersion, schema.NativeJSONProfile, validCtx(), NativeCodeUnsupportedVersion},
		{"registry_bad_profile", schema.NativeRegistryJSONSelector, schema.NativeRegistryInputVersion, schema.NativeJSONProfile, registryTestContext(), NativeCodeUnsupportedProfile},
		{"registry_csv_reserved", schema.NativeRegistryCSVSelector, schema.NativeRegistryInputVersion, schema.NativeRegistryCSVProfile, registryTestContext(), NativeCodeUnsupportedSelector},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := ParsePrismaNative(strings.NewReader(registryBody), tc.selector, tc.version, tc.profile, tc.ctx)
			if err == nil || err.Code != tc.code {
				t.Fatalf("err = %v, want %s", err, tc.code)
			}
		})
	}
}

// TestPrismaRegistrySourceFormatAndVersion checks the wire literals of the
// registry family and that the produced DTO revalidates.
func TestPrismaRegistrySourceFormatAndVersion(t *testing.T) {
	src, err := ParsePrismaNative(strings.NewReader(registryBody),
		schema.NativeRegistryJSONSelector, schema.NativeRegistryInputVersion, schema.NativeRegistryJSONProfile, registryTestContext())
	if err != nil {
		t.Fatalf("parse failed: %v", err)
	}
	if err := ValidateNativeSource(src); err != nil {
		t.Fatalf("validate source: %v", err)
	}
	encoded := string(EncodeNativeSource(src))
	if !strings.Contains(encoded, `"format":"`+schema.NativeRegistrySourceFormat+`"`) {
		t.Fatalf("registry source format missing: %s", encoded)
	}
	if !strings.Contains(encoded, `"version":"`+schema.NativeRegistryInputVersion+`"`) {
		t.Fatalf("registry artifact version missing: %s", encoded)
	}
	if _, perr := ParseNativeSourceBytes([]byte(encoded)); perr != nil {
		t.Fatalf("registry source does not reparse: %v", perr)
	}
}

// TestPrismaRegistryNoConservationExpansion checks that labels/hosts and the
// image subtree stay excluded: their values never reach the sanitized source.
func TestPrismaRegistryNoConservationExpansion(t *testing.T) {
	body := `[{"type":"image","packages":[],"vulnerabilities":[],"labels":{"secret":"TOPSECRETVALUE"},` +
		`"hosts":["HOSTMARKER"],"image":{"secret":"IMAGEMARKER"}}]`
	src, err := ParsePrismaNative(strings.NewReader(body),
		schema.NativeRegistryJSONSelector, schema.NativeRegistryInputVersion, schema.NativeRegistryJSONProfile, registryTestContext())
	if err != nil {
		t.Fatalf("excluded members must be consumed, not rejected: %v", err)
	}
	encoded := string(EncodeNativeSource(src))
	for _, marker := range []string{"TOPSECRETVALUE", "HOSTMARKER", "IMAGEMARKER"} {
		if strings.Contains(encoded, marker) {
			t.Fatalf("excluded value %q leaked into the source", marker)
		}
	}
}

// TestPrismaRegistrySerializedContextRejectsDeploymentScope checks D-R1: a
// serialized context carrying an unknown deployment_scope key is rejected as
// invalid_artifact (closed schema) anchored at the start of that key, never as
// invalid_context.
func TestPrismaRegistrySerializedContextRejectsDeploymentScope(t *testing.T) {
	src, err := ParsePrismaNative(strings.NewReader(registryBody),
		schema.NativeRegistryJSONSelector, schema.NativeRegistryInputVersion, schema.NativeRegistryJSONProfile, registryTestContext())
	if err != nil {
		t.Fatalf("parse failed: %v", err)
	}
	encoded := EncodeNativeSource(src)
	for _, value := range []string{"null", `""`, "{}", "[]", `"x"`} {
		instrumented := `"deployment_scope":` + value + `,`
		tampered := bytes.Replace(encoded, []byte(`"origin_alias"`), []byte(instrumented+`"origin_alias"`), 1)
		if bytes.Equal(tampered, encoded) {
			t.Fatalf("tamper did not apply for value %q", value)
		}
		_, perr := ParseNativeSourceBytes(tampered)
		if perr == nil || perr.Code != NativeCodeInvalidArtifact ||
			perr.Phase != NativePhaseReplayAdmission || perr.OffsetSpace != NativeSpaceSource {
			t.Fatalf("value %q: err = %+v, want invalid_artifact/replay_admission/source", value, perr)
		}
		want := bytes.Index(tampered, []byte(`"deployment_scope"`))
		if perr.Offset != uint64(want) {
			t.Fatalf("value %q: offset = %d, want %d (start of the unknown key)", value, perr.Offset, want)
		}
	}
}

// TestPrismaRegistryRejectsFamilyVersionMismatch checks the bidirectional
// coherence profile/version (P1): a registry profile under the 1.0 version (or
// an empty version, which canonicalizes to 1.0) is rejected as invalid_artifact.
func TestPrismaRegistryRejectsFamilyVersionMismatch(t *testing.T) {
	src, err := ParsePrismaNative(strings.NewReader(registryBody),
		schema.NativeRegistryJSONSelector, schema.NativeRegistryInputVersion, schema.NativeRegistryJSONProfile, registryTestContext())
	if err != nil {
		t.Fatalf("parse failed: %v", err)
	}
	for _, tc := range []struct {
		name string
		mut  func(*NativeSource)
	}{
		{"registry_with_1_0", func(s *NativeSource) { s.Version = schema.NativeFormatVersion }},
		{"registry_with_empty_version", func(s *NativeSource) { s.Version = "" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			bad := src
			tc.mut(&bad)
			if err := ValidateNativeSource(bad); err == nil || err.Code != NativeCodeInvalidArtifact {
				t.Fatalf("err = %v, want invalid_artifact", err)
			}
		})
	}
	t.Run("registry_entry_rejects_deployed_args", func(t *testing.T) {
		_, err := ParsePrismaRegistryJSON(strings.NewReader(registryBody),
			schema.NativeJSONSelector, schema.NativeInputVersion, schema.NativeJSONProfile, validCtx())
		if err == nil || err.Code != NativeCodeUnsupportedSelector {
			t.Fatalf("err = %v, want unsupported_selector", err)
		}
		_, err = ParsePrismaRegistryJSON(strings.NewReader(registryBody),
			schema.NativeRegistryJSONSelector, schema.NativeInputVersion, schema.NativeRegistryJSONProfile, registryTestContext())
		if err == nil || err.Code != NativeCodeUnsupportedVersion {
			t.Fatalf("err = %v, want unsupported_version", err)
		}
		_, err = ParsePrismaRegistryJSON(strings.NewReader(registryBody),
			schema.NativeRegistryJSONSelector, schema.NativeRegistryInputVersion, schema.NativeJSONProfile, registryTestContext())
		if err == nil || err.Code != NativeCodeUnsupportedProfile {
			t.Fatalf("err = %v, want unsupported_profile", err)
		}
	})
}

// nativeCountingReader records how many times Read was called.
type nativeCountingReader struct{ calls int }

func (r *nativeCountingReader) Read([]byte) (int, error) { r.calls++; return 0, io.EOF }

// TestPrismaRegistryInvalidInputDoesNotConsumeReader checks that an invalid
// context, and the registry entry with wrong arguments, reject before reading.
func TestPrismaRegistryInvalidInputDoesNotConsumeReader(t *testing.T) {
	r := &nativeCountingReader{}
	if _, err := ParsePrismaNative(r, schema.NativeRegistryJSONSelector,
		schema.NativeRegistryInputVersion, schema.NativeRegistryJSONProfile, validCtx()); err == nil || err.Code != NativeCodeInvalidContext {
		t.Fatalf("err = %v, want invalid_context", err)
	}
	if r.calls != 0 {
		t.Fatalf("invalid context consumed the reader %d times", r.calls)
	}
	r2 := &nativeCountingReader{}
	if _, err := ParsePrismaRegistryJSON(r2, schema.NativeJSONSelector,
		schema.NativeInputVersion, schema.NativeJSONProfile, registryTestContext()); err == nil || err.Code != NativeCodeUnsupportedSelector {
		t.Fatalf("err = %v, want unsupported_selector", err)
	}
	if r2.calls != 0 {
		t.Fatalf("registry entry consumed the reader %d times", r2.calls)
	}
}
func TestPrismaRegistryManifestRejectsFamilyVersionMismatch(t *testing.T) {
	man := NativeManifest{
		SourceHash:    "sha256:" + strings.Repeat("0", 64),
		SourceBytes:   1,
		OriginalBytes: 1,
		Profile:       registryJSONProfile(),
		Limitations:   []string{"documentary_profile", "registry_profile", "registry_not_deployment"},
		Version:       schema.NativeRegistryInputVersion,
	}
	enc := EncodeNativeManifest(man)
	if _, _, err := ParseNativeManifestBytes(enc); err != nil {
		t.Fatalf("valid registry manifest rejected: %v", err)
	}
	tampered := bytes.Replace(enc, []byte(`"version":"`+schema.NativeRegistryInputVersion+`"`), []byte(`"version":"`+schema.NativeFormatVersion+`"`), 1)
	if bytes.Equal(tampered, enc) {
		t.Fatal("tamper did not apply")
	}
	if _, _, err := ParseNativeManifestBytes(tampered); err == nil || err.Code != NativeCodeInvalidArtifact {
		t.Fatalf("err = %v, want invalid_artifact", err)
	}
}
