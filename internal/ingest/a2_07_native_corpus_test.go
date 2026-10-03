package ingest

import (
	"strings"
	"testing"
)

// Corpus of ADR-0027 §14 for the native JSON/CSV adapters. All inputs are
// synthetic. These tests assert the closed structural rules, the budgets, the
// redaction frontier and the absence of invented associations.

func validCtx() NativeContext {
	f := false
	return NativeContext{
		OriginAlias: "synthetic", SourceAlias: "fixture",
		DeclaredEdition: "compute_self_hosted", DeclaredRelease: "34.04.145",
		VersionBasis: "operator_declared", ReportKind: "deployed_images",
		AcquisitionKind: "synthetic_fixture", AcquiredAt: "2026-10-02T00:00:00Z",
		CaptureTermination: "finished", ScopeMode: "unfiltered_declared",
		FilterStatus: "none_declared", Compact: &f, NormalizedSeverity: &f, Layers: &f,
		FieldsMode: "unrestricted_declared", SelectedFields: []string{},
		PageMode: "export_declared", DataPolicyAck: "prisma-native-offline-redaction-v1/1.0",
	}
}

// TestPrismaNativeContextConfig exercises the §5 validation before reading.
func TestPrismaNativeContextConfig(t *testing.T) {
	ok := validCtx()
	if _, err := ParsePrismaNative(strings.NewReader(`[]`), "prisma-native-images-json-v1", "1.0", "compute-sh-34.04.145-images-json", ok); err != nil {
		t.Fatalf("valid context rejected: %v", err)
	}
	cases := []struct {
		name string
		mut  func(*NativeContext)
		code string
	}{
		{"bad_alias", func(c *NativeContext) { c.OriginAlias = "bad alias" }, NativeCodeInvalidContext},
		{"unknown_release_mismatch", func(c *NativeContext) { c.DeclaredRelease = "unknown" }, NativeCodeInvalidContext},
		{"scope_alias_without_filter", func(c *NativeContext) { s := "x"; c.ScopeAlias = &s }, NativeCodeInvalidContext},
		{"bad_page", func(c *NativeContext) { n := 0; c.PageOrdinal = &n }, NativeCodeInvalidContext},
		{"bad_policy", func(c *NativeContext) { c.DataPolicyAck = "nope" }, NativeCodeRedactionPolicyMissing},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ctx := validCtx()
			tc.mut(&ctx)
			_, err := ParsePrismaNative(strings.NewReader(`[]`), "prisma-native-images-json-v1", "1.0", "compute-sh-34.04.145-images-json", ctx)
			if err == nil || err.Code != tc.code {
				t.Fatalf("err = %v, want %s", err, tc.code)
			}
		})
	}
	t.Run("unsupported_selector", func(t *testing.T) {
		_, err := ParsePrismaNative(strings.NewReader(`[]`), "nope", "1.0", "compute-sh-34.04.145-images-json", validCtx())
		if err == nil || err.Code != NativeCodeUnsupportedSelector {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("unsupported_version", func(t *testing.T) {
		_, err := ParsePrismaNative(strings.NewReader(`[]`), "prisma-native-images-json-v1", "2.0", "compute-sh-34.04.145-images-json", validCtx())
		if err == nil || err.Code != NativeCodeUnsupportedVersion {
			t.Fatalf("err = %v", err)
		}
	})
}

type nativeZeroReader struct{ n int }

func (r *nativeZeroReader) Read(p []byte) (int, error) {
	if r.n <= 0 {
		return 0, nil
	}
	r.n--
	return 0, nil
}

// TestPrismaNativeRead covers reader-level failures of §6.2.
func TestPrismaNativeRead(t *testing.T) {
	t.Run("nil", func(t *testing.T) {
		_, err := ParsePrismaNative(nil, "prisma-native-images-json-v1", "1.0", "compute-sh-34.04.145-images-json", validCtx())
		if err == nil || err.Code != NativeCodeNilReader {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("no_progress", func(t *testing.T) {
		_, err := ParsePrismaNative(&nativeZeroReader{n: 1000}, "prisma-native-images-json-v1", "1.0", "compute-sh-34.04.145-images-json", validCtx())
		if err == nil || err.Code != NativeCodeReadFailed {
			t.Fatalf("err = %v", err)
		}
	})
}

// TestPrismaNativeLimits covers the budgets of §6.2 at their boundaries.
func TestPrismaNativeLimits(t *testing.T) {
	parse := func(input string) *NativeError {
		_, err := ParsePrismaNative(strings.NewReader(input), "prisma-native-images-json-v1", "1.0", "compute-sh-34.04.145-images-json", validCtx())
		return err
	}
	t.Run("depth", func(t *testing.T) {
		var b strings.Builder
		b.WriteString(`[{"history":`)
		for i := 0; i < 40; i++ {
			b.WriteString(`{"a":`)
		}
		b.WriteString("1")
		for i := 0; i < 40; i++ {
			b.WriteString("}")
		}
		b.WriteString("}]")
		if err := parse(b.String()); err == nil || err.Code != NativeCodeDepthLimit {
			t.Fatalf("err = %v, want depth_limit", err)
		}
	})
	t.Run("key", func(t *testing.T) {
		input := `[{"history":{"` + strings.Repeat("k", 300) + `":1}}]`
		if err := parse(input); err == nil || err.Code != NativeCodeKeyLimit {
			t.Fatalf("err = %v, want key_limit", err)
		}
	})
	t.Run("string", func(t *testing.T) {
		input := `[{"distro":"` + strings.Repeat("a", 70000) + `"}]`
		if err := parse(input); err == nil || err.Code != NativeCodeStringLimit {
			t.Fatalf("err = %v, want string_limit", err)
		}
	})
	t.Run("number", func(t *testing.T) {
		input := `[{"vulnerabilities":[{"cvss":` + strings.Repeat("9", 200) + `}]}]`
		if err := parse(input); err == nil || err.Code != NativeCodeNumberLimit {
			t.Fatalf("err = %v, want number_limit", err)
		}
	})
	t.Run("decoded_string_limit", func(t *testing.T) {
		// severity is S128; 200 decoded bytes exceeds it.
		input := `[{"vulnerabilities":[{"severity":"` + strings.Repeat("a", 200) + `"}]}]`
		if err := parse(input); err == nil || err.Code != NativeCodeStringLimit {
			t.Fatalf("err = %v, want string_limit", err)
		}
	})
}

// TestPrismaNativeNoExcludedContent asserts the redaction frontier: values of
// excluded branches never reach the encoded source or the manifest.
func TestPrismaNativeNoExcludedContent(t *testing.T) {
	const marker = "SUPERSECRETMARKER"
	input := `[{"type":"image","history":{"secret":"` + marker + `"},"labels":"` + marker + `"}]`
	src, err := ParsePrismaNative(strings.NewReader(input), "prisma-native-images-json-v1", "1.0", "compute-sh-34.04.145-images-json", validCtx())
	if err != nil {
		t.Fatalf("parse failed: %v", err)
	}
	out := string(EncodeNativeSource(src))
	if strings.Contains(out, marker) {
		t.Fatalf("excluded content leaked into the source")
	}
}

// TestPrismaNativePresence asserts that absent, null, empty, zero and false are
// distinguishable in the projected data.
func TestPrismaNativePresence(t *testing.T) {
	input := `[{"type":"image","distro":"","osDistro":null,"isARM64":false,"scanID":0}]`
	src, err := ParsePrismaNative(strings.NewReader(input), "prisma-native-images-json-v1", "1.0", "compute-sh-34.04.145-images-json", validCtx())
	if err != nil {
		t.Fatalf("parse failed: %v", err)
	}
	obj := src.Records[0].Data.(NativeObject)
	byKey := map[string]NativeValue{}
	for i, k := range obj.Keys {
		byKey[k] = obj.Values[i]
	}
	if v, ok := byKey["distro"].(NativeString); !ok || v != "" {
		t.Fatalf("distro = %#v, want empty string", byKey["distro"])
	}
	if _, ok := byKey["osDistro"].(NativeNull); !ok {
		t.Fatalf("osDistro = %#v, want null", byKey["osDistro"])
	}
	if _, ok := byKey["scanID"].(NativeNumber); !ok {
		t.Fatalf("scanID = %#v, want number wrapper", byKey["scanID"])
	}
	if v, ok := byKey["isARM64"].(NativeBool); !ok || bool(v) {
		t.Fatalf("isARM64 = %#v, want false", byKey["isARM64"])
	}
	if _, ok := byKey["repository"]; ok {
		t.Fatalf("unexpected member present")
	}
}

// TestPrismaNativeNoRuntimePromotion asserts that repoDigests, tags and isARM64
// do not produce a guaranteed digest, platform or identity field.
func TestPrismaNativeNoRuntimePromotion(t *testing.T) {
	input := `[{"type":"image","repoDigests":["registry/app@sha256:` + strings.Repeat("a", 64) + `"],"tags":[{"digest":"sha256:` + strings.Repeat("b", 64) + `"}],"isARM64":false}]`
	src, err := ParsePrismaNative(strings.NewReader(input), "prisma-native-images-json-v1", "1.0", "compute-sh-34.04.145-images-json", validCtx())
	if err != nil {
		t.Fatalf("parse failed: %v", err)
	}
	out := string(EncodeNativeSource(src))
	if strings.Contains(out, "normalized_digest") || strings.Contains(out, "platform") {
		t.Fatalf("runtime promotion leaked into the source")
	}
}

// TestPrismaNativeOwnership asserts independent copies: mutating the caller
// context after parsing does not alter the produced source.
func TestPrismaNativeOwnership(t *testing.T) {
	ctx := validCtx()
	src, err := ParsePrismaNative(strings.NewReader(`[{"type":"image"}]`), "prisma-native-images-json-v1", "1.0", "compute-sh-34.04.145-images-json", ctx)
	if err != nil {
		t.Fatalf("parse failed: %v", err)
	}
	before := string(EncodeNativeSource(src))
	ctx.OriginAlias = "mutated"
	ctx.SelectedFields = append(ctx.SelectedFields, "x")
	after := string(EncodeNativeSource(src))
	if before != after {
		t.Fatalf("source changed after caller mutation")
	}
}
