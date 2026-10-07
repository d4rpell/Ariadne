package ingest

import (
	"bytes"
	"io"
	"strconv"
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

// TestPrismaRegistryVectorIsDeployedWithDeclaredDeltas checks the registry source
// wire byte for byte: it is exactly the deployed JSON source of ADR-0027 §11.12.1
// with the declared family substitutions (format, version, profile fields,
// report_kind). This is the registry 2.0 literal vector, adapted not copied.
func TestPrismaRegistryVectorIsDeployedWithDeclaredDeltas(t *testing.T) {
	payload := `[{"type":"image","packages":[],"vulnerabilities":[]}]`
	dep, err := ParsePrismaNative(strings.NewReader(payload),
		schema.NativeJSONSelector, schema.NativeInputVersion, schema.NativeJSONProfile, validCtx())
	if err != nil {
		t.Fatalf("deployed parse: %v", err)
	}
	depBytes := EncodeNativeSource(dep)
	if len(depBytes) != 1187 {
		t.Fatalf("deployed source length = %d, want the F1 §11.12.1 vector (1187)", len(depBytes))
	}
	reg, err := ParsePrismaNative(strings.NewReader(payload),
		schema.NativeRegistryJSONSelector, schema.NativeRegistryInputVersion, schema.NativeRegistryJSONProfile, registryTestContext())
	if err != nil {
		t.Fatalf("registry parse: %v", err)
	}
	got := string(EncodeNativeSource(reg))
	want := string(depBytes)
	for _, r := range [][2]string{
		{`"format":"` + schema.NativeSourceFormat + `"`, `"format":"` + schema.NativeRegistrySourceFormat + `"`},
		{`"version":"` + schema.NativeFormatVersion + `"`, `"version":"` + schema.NativeRegistryInputVersion + `"`},
		{`"selector":"` + schema.NativeJSONSelector + `"`, `"selector":"` + schema.NativeRegistryJSONSelector + `"`},
		{`"input_version":"` + schema.NativeInputVersion + `"`, `"input_version":"` + schema.NativeRegistryInputVersion + `"`},
		{`"name":"` + schema.NativeJSONProfile + `"`, `"name":"` + schema.NativeRegistryJSONProfile + `"`},
		{`"adapter_semantics":"` + schema.NativeAdapterSemantics + `"`, `"adapter_semantics":"` + schema.NativeRegistryAdapterSemantics + `"`},
		{`"report_kind":"` + schema.NativeReportKindDeployed + `"`, `"report_kind":"` + schema.NativeReportKindRegistry + `"`},
	} {
		next := strings.Replace(want, r[0], r[1], 1)
		if next == want {
			t.Fatalf("substitution did not apply: %s", r[0])
		}
		want = next
	}
	if got != want {
		t.Fatalf("registry source is not the deployed vector with declared deltas:\n got %s\nwant %s", got, want)
	}
	// Locked registry 2.0 literal vector, derived independently (deployed §11.12.1
	// vector + the documented deltas): 1209 bytes.
	if len(got) != 1209 {
		t.Fatalf("registry source length = %d, want 1209", len(got))
	}
	if h := HashNativeSource([]byte(got)); h != "sha256:e2a47182d4812e4566a1de737b1245ac5aae94f5636347e4c09473613b7adfe2" {
		t.Fatalf("registry source hash = %s, want sha256:e2a47182d4812e4566a1de737b1245ac5aae94f5636347e4c09473613b7adfe2", h)
	}
}

// TestPrismaRegistryObjectMemberBoundary checks the 128-member limit inside an
// excluded subtree (history): 127/128 admitted, 129 rejected.
func TestPrismaRegistryObjectMemberBoundary(t *testing.T) {
	build := func(n int) string {
		var b strings.Builder
		b.WriteString(`[{"type":"image","history":{`)
		for i := 0; i < n; i++ {
			if i > 0 {
				b.WriteByte(',')
			}
			b.WriteString(`"k`)
			b.WriteString(strconv.Itoa(i))
			b.WriteString(`":0`)
		}
		b.WriteString(`}}]`)
		return b.String()
	}
	for _, tc := range []struct {
		n  int
		ok bool
	}{{127, true}, {128, true}, {129, false}} {
		_, err := ParsePrismaNative(strings.NewReader(build(tc.n)),
			schema.NativeRegistryJSONSelector, schema.NativeRegistryInputVersion, schema.NativeRegistryJSONProfile, registryTestContext())
		if tc.ok && err != nil {
			t.Fatalf("n=%d rejected: %v", tc.n, err)
		}
		if !tc.ok && (err == nil || err.Code != NativeCodeMemberLimit) {
			t.Fatalf("n=%d: err = %v, want member_limit", tc.n, err)
		}
	}
}

// TestPrismaRegistryNativeSourceBudget pins the shared 64 MiB stream budget
// through the registry entry point: L-1 and L are admitted, L+1 is refused as
// source_limit during acquisition, before any examination of the document. The
// border is generated by streaming whitespace so no second 64 MiB copy is held.
func TestPrismaRegistryNativeSourceBudget(t *testing.T) {
	limit := schema.NativeMaxSourceBytes
	if limit != 64*1024*1024 {
		t.Fatalf("stream budget = %d, want the contract's 64 MiB", limit)
	}
	for _, size := range []int{limit - 1, limit} {
		src, err := ParsePrismaNative(a201PaddedSource(registryBody, size),
			schema.NativeRegistryJSONSelector, schema.NativeRegistryInputVersion, schema.NativeRegistryJSONProfile, registryTestContext())
		if err != nil {
			t.Fatalf("size %d rejected: %v", size, err)
		}
		if len(EncodeNativeSource(src)) == 0 {
			t.Fatalf("size %d: empty derived source", size)
		}
	}
	_, err := ParsePrismaNative(a201PaddedSource(registryBody, limit+1),
		schema.NativeRegistryJSONSelector, schema.NativeRegistryInputVersion, schema.NativeRegistryJSONProfile, registryTestContext())
	if err == nil || err.Code != NativeCodeSourceLimit || err.Phase != NativePhaseAcquisition || err.Offset != uint64(limit) {
		t.Fatalf("oversized registry source: err = %+v, want source_limit/acquisition at %d", err, limit)
	}
}
