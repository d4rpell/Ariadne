package normalize

import (
	"bytes"
	"strings"
	"testing"

	"github.com/d4rpell/Ariadne/internal/ingest"
	"github.com/d4rpell/Ariadne/internal/schema"
)

// nativeTestContext is the §11.12 context.
func nativeTestContext() ingest.NativeContext {
	f := false
	return ingest.NativeContext{
		OriginAlias:        "synthetic",
		SourceAlias:        "fixture",
		DeclaredEdition:    "compute_self_hosted",
		DeclaredRelease:    "34.04.145",
		VersionBasis:       "operator_declared",
		ReportKind:         "deployed_images",
		AcquisitionKind:    "synthetic_fixture",
		AcquiredAt:         "2026-10-02T00:00:00Z",
		CaptureTermination: "finished",
		ScopeMode:          "unfiltered_declared",
		FilterStatus:       "none_declared",
		Compact:            &f,
		NormalizedSeverity: &f,
		Layers:             &f,
		FieldsMode:         "unrestricted_declared",
		SelectedFields:     []string{},
		PageMode:           "export_declared",
		DataPolicyAck:      "prisma-native-offline-redaction-v1/1.0",
	}
}

// TestPrismaNativeManifestVectors asserts that the interpretation derives the
// exact manifest of §11.12 for both profiles: source length and hash, manifest
// length and sidecar digest, from the real native inputs.
func TestPrismaNativeManifestVectors(t *testing.T) {
	t.Run("json", func(t *testing.T) {
		input := `[{"type":"image","packages":[],"vulnerabilities":[]}]`
		src, err := ingest.ParsePrismaNative(strings.NewReader(input), schema.NativeJSONSelector, "1.0", schema.NativeJSONProfile, nativeTestContext())
		if err != nil {
			t.Fatalf("parse failed: %v", err)
		}
		art, err := EncodePrismaNativeImport(src)
		if err != nil {
			t.Fatalf("encode failed: %v", err)
		}
		if len(art.Source) != 1187 {
			t.Fatalf("source length = %d, want 1187", len(art.Source))
		}
		if h := ingest.HashNativeSource(art.Source); h != "sha256:25cb2426ee5cd817d410e554145042a0e010c121399e101e4bd4b9620fd19a15" {
			t.Fatalf("source hash = %s", h)
		}
		if len(art.Manifest) != 835 {
			t.Fatalf("manifest length = %d, want 835: %s", len(art.Manifest), art.Manifest)
		}
		want := "sha256:a8bbb3eb685e524789a08a32daceb7d72c112214b2f19462156658df48f04de0\n"
		if string(art.Digest) != want {
			t.Fatalf("digest = %q, want %q", art.Digest, want)
		}
	})
	t.Run("csv", func(t *testing.T) {
		hdr := strings.Join(schema.NativeCSVHeader(), ",")
		fields := make([]string, 39)
		fields[7] = "CVE-2026-1234"
		fields[16] = "0"
		input := hdr + "\n" + strings.Join(fields, ",")
		src, err := ingest.ParsePrismaNative(strings.NewReader(input), schema.NativeCSVSelector, "1.0", schema.NativeCSVProfile, nativeTestContext())
		if err != nil {
			t.Fatalf("parse failed: %v", err)
		}
		art, err := EncodePrismaNativeImport(src)
		if err != nil {
			t.Fatalf("encode failed: %v", err)
		}
		if len(art.Source) != 2021 {
			t.Fatalf("source length = %d, want 2021", len(art.Source))
		}
		if len(art.Manifest) != 2167 {
			t.Fatalf("manifest length = %d, want 2167: %s", len(art.Manifest), art.Manifest)
		}
		want := "sha256:7690cee3e48678c63ddf4af797756b500598f4d7f7770bd66e9aa7b3b147cdfd\n"
		if string(art.Digest) != want {
			t.Fatalf("digest = %q, want %q", art.Digest, want)
		}
	})
}

// nativeManifestOf parses a JSON native input and derives its manifest.
func nativeManifestOf(t *testing.T, input string) ingest.NativeManifest {
	t.Helper()
	src, err := ingest.ParsePrismaNative(strings.NewReader(input), schema.NativeJSONSelector, "1.0", schema.NativeJSONProfile, nativeTestContext())
	if err != nil {
		t.Fatalf("parse failed: %v", err)
	}
	man, err := BuildNativeManifest(src, "sha256:"+strings.Repeat("0", 64), 1)
	if err != nil {
		t.Fatalf("manifest failed: %v", err)
	}
	return man
}

func hasLimitation(man ingest.NativeManifest, code string) bool {
	for _, l := range man.Limitations {
		if l == code {
			return true
		}
	}
	return false
}

func lossFor(man ingest.NativeManifest, path, reason string) uint64 {
	for _, l := range man.Losses {
		if l.Path == path && l.Reason == reason {
			return l.Occurrences
		}
	}
	return 0
}

// TestPrismaNativeScalarRows covers the §12.5.3 rows for integers, CVSS score,
// vector and procedure pairs through the manifest they activate.
func TestPrismaNativeScalarRows(t *testing.T) {
	t.Run("cvss_invalid", func(t *testing.T) {
		man := nativeManifestOf(t, `[{"type":"image","vulnerabilities":[{"cve":"CVE-2026-1","cvss":9.81}]}]`)
		if !hasLimitation(man, "values_invalid") {
			t.Fatalf("values_invalid not activated: %v", man.Limitations)
		}
		if got := lossFor(man, "/records/[]/data/vulnerabilities/[]/cvss", "invalid_value"); got != 1 {
			t.Fatalf("cvss invalid_value = %d, want 1", got)
		}
	})
	t.Run("cvss_uninterpretable", func(t *testing.T) {
		man := nativeManifestOf(t, `[{"type":"image","vulnerabilities":[{"cvss":1e0}]}]`)
		if !hasLimitation(man, "values_uninterpretable") {
			t.Fatalf("values_uninterpretable not activated: %v", man.Limitations)
		}
		if got := lossFor(man, "/records/[]/data/vulnerabilities/[]/cvss", "semantics_unverified"); got != 1 {
			t.Fatalf("cvss semantics_unverified = %d, want 1", got)
		}
	})
	t.Run("cvss_valid_zero", func(t *testing.T) {
		man := nativeManifestOf(t, `[{"type":"image","vulnerabilities":[{"cve":"CVE-2026-1","cvss":0}]}]`)
		if hasLimitation(man, "values_invalid") {
			t.Fatalf("values_invalid wrongly activated: %v", man.Limitations)
		}
	})
	t.Run("vector_repeated_metric", func(t *testing.T) {
		man := nativeManifestOf(t, `[{"type":"image","vulnerabilities":[{"vecStr":"CVSS:3.1/AV:N/AV:L"}]}]`)
		if got := lossFor(man, "/records/[]/data/vulnerabilities/[]/vecStr", "invalid_value"); got != 1 {
			t.Fatalf("vecStr invalid_value = %d, want 1", got)
		}
	})
	t.Run("attribute_conflict", func(t *testing.T) {
		man := nativeManifestOf(t, `[{"type":"image","vulnerabilities":[{"vulnerabilityDataSources":[{"attribute":1,"source":2},{"attribute":1,"source":3}]}]}]`)
		if !hasLimitation(man, "attribute_source_conflict") {
			t.Fatalf("attribute_source_conflict not activated: %v", man.Limitations)
		}
		if got := lossFor(man, "/records/[]/data/vulnerabilities/[]/vulnerabilityDataSources", "semantics_unverified"); got != 1 {
			t.Fatalf("procedure conflict loss = %d, want 1", got)
		}
	})
	t.Run("declared_count_difference", func(t *testing.T) {
		man := nativeManifestOf(t, `[{"type":"image","vulnerabilities":[],"vulnerabilitiesCount":5}]`)
		if !hasLimitation(man, "declared_count_difference") {
			t.Fatalf("declared_count_difference not activated: %v", man.Limitations)
		}
	})
}

// TestPrismaNativeINT20States asserts the closed states of §7.1.1.
func TestPrismaNativeINT20States(t *testing.T) {
	cases := map[string]string{
		"0":                    "valid",
		"-0":                   "valid",
		"9223372036854775807":  "valid",
		"-9223372036854775808": "valid",
		"9223372036854775808":  "invalid",
		"18446744073709551615": "invalid",
		"1.0":                  "uninterpretable",
		"1e0":                  "uninterpretable",
	}
	for token, want := range cases {
		if got := interpretINT20(token).state; got != want {
			t.Fatalf("interpretINT20(%q) = %s, want %s", token, got, want)
		}
	}
}

// TestPrismaNativeScoreStates asserts the closed states of §8.2.
func TestPrismaNativeScoreStates(t *testing.T) {
	cases := map[string]string{
		"0":    "valid",
		"0.0":  "valid",
		"0.00": "valid",
		"9.8":  "valid",
		"9.80": "valid",
		"9.81": "invalid",
		"10.0": "valid",
		"10.1": "invalid",
		"-1":   "invalid",
		"1e0":  "uninterpretable",
	}
	for token, want := range cases {
		if got := interpretScore(token).state; got != want {
			t.Fatalf("interpretScore(%q) = %s, want %s", token, got, want)
		}
	}
}

// TestPrismaNativeReplay verifies the §11.10 replay: the produced artifacts
// replay cleanly, a tampered manifest is caught by the sidecar, and a
// non-canonical source is rejected as an invalid artifact.
func TestPrismaNativeReplay(t *testing.T) {
	input := `[{"type":"image","packages":[],"vulnerabilities":[]}]`
	src, err := ingest.ParsePrismaNative(strings.NewReader(input), schema.NativeJSONSelector, "1.0", schema.NativeJSONProfile, nativeTestContext())
	if err != nil {
		t.Fatalf("parse failed: %v", err)
	}
	art, aerr := EncodePrismaNativeImport(src)
	if aerr != nil {
		t.Fatalf("encode failed: %v", aerr)
	}
	inv, err := ReplayPrismaNative(bytes.NewReader(art.Source), bytes.NewReader(art.Manifest), bytes.NewReader(art.Digest), schema.NativeSourceFormat, schema.NativeFormatVersion)
	if err != nil {
		t.Fatalf("replay failed: %v", err)
	}
	fresh, ferr := InterpretPrismaNative(src, ingest.HashNativeSource(art.Source), uint64(len(art.Source)))
	if ferr != nil {
		t.Fatalf("interpret failed: %v", ferr)
	}
	if len(inv.Facts) != len(fresh.Facts) || len(inv.Diagnostics) != len(fresh.Diagnostics) {
		t.Fatalf("replay facts/diagnostics diverge: %d/%d vs %d/%d", len(inv.Facts), len(inv.Diagnostics), len(fresh.Facts), len(fresh.Diagnostics))
	}
	for i := range inv.Facts {
		if inv.Facts[i] != fresh.Facts[i] {
			t.Fatalf("fact %d differs: %+v vs %+v", i, inv.Facts[i], fresh.Facts[i])
		}
	}
	for i := range inv.Diagnostics {
		if inv.Diagnostics[i].Code != fresh.Diagnostics[i].Code || inv.Diagnostics[i].Offset != fresh.Diagnostics[i].Offset {
			t.Fatalf("diagnostic %d differs", i)
		}
	}

	t.Run("tampered_manifest", func(t *testing.T) {
		bad := append([]byte{}, art.Manifest...)
		bad[0] = '[' // corrupt the first byte
		if _, err := ReplayPrismaNative(bytes.NewReader(art.Source), bytes.NewReader(bad), bytes.NewReader(art.Digest), schema.NativeSourceFormat, schema.NativeFormatVersion); err == nil {
			t.Fatalf("tampered manifest accepted")
		}
	})
	t.Run("tampered_source", func(t *testing.T) {
		bad := append([]byte(" "), art.Source...) // non-canonical: leading space
		if _, err := ReplayPrismaNative(bytes.NewReader(bad), bytes.NewReader(art.Manifest), bytes.NewReader(art.Digest), schema.NativeSourceFormat, schema.NativeFormatVersion); err == nil {
			t.Fatalf("non-canonical source accepted")
		}
	})
}

// TestPrismaNativeReplayAnchors checks the §12.4.2 anchors of the replay
// verification diagnostics: a source_hash divergence is a hash_mismatch at the
// source_hash string start, and a member divergence is a manifest_mismatch at
// the first discrepant member's value, not at a whole-document first difference.
func TestPrismaNativeReplayAnchors(t *testing.T) {
	input := `[{"type":"image","packages":[],"vulnerabilities":[]}]`
	src, err := ingest.ParsePrismaNative(strings.NewReader(input), schema.NativeJSONSelector, "1.0", schema.NativeJSONProfile, nativeTestContext())
	if err != nil {
		t.Fatalf("parse failed: %v", err)
	}
	art, aerr := EncodePrismaNativeImport(src)
	if aerr != nil {
		t.Fatalf("encode failed: %v", aerr)
	}
	tamper := func(t *testing.T, mutate func(*ingest.NativeManifest)) ([]byte, []byte) {
		t.Helper()
		man, _, perr := ingest.ParseNativeManifestBytes(art.Manifest)
		if perr != nil {
			t.Fatalf("manifest parse failed: %v", perr)
		}
		mutate(&man)
		bad := ingest.EncodeNativeManifest(man)
		return bad, ingest.NativeManifestSidecar(ingest.HashNativeManifest(bad))
	}

	t.Run("source_hash", func(t *testing.T) {
		bad, digest := tamper(t, func(m *ingest.NativeManifest) {
			m.SourceHash = "sha256:" + strings.Repeat("0", 64)
		})
		_, rerr := ReplayPrismaNative(bytes.NewReader(art.Source), bytes.NewReader(bad), bytes.NewReader(digest), schema.NativeSourceFormat, schema.NativeFormatVersion)
		if rerr == nil || rerr.Code != ingest.NativeCodeHashMismatch {
			t.Fatalf("err = %v, want hash_mismatch", rerr)
		}
		if rerr.OffsetSpace != ingest.NativeSpaceManifest || rerr.Offset != 103 {
			t.Fatalf("anchor = %s/%d, want manifest/103", rerr.OffsetSpace, rerr.Offset)
		}
	})
	t.Run("manifest_member", func(t *testing.T) {
		bad, digest := tamper(t, func(m *ingest.NativeManifest) { m.OriginalBytes++ })
		want, ok := ingest.NativeManifestMemberValueOffset(bad, "original_bytes")
		if !ok {
			t.Fatalf("original_bytes anchor not found")
		}
		_, rerr := ReplayPrismaNative(bytes.NewReader(art.Source), bytes.NewReader(bad), bytes.NewReader(digest), schema.NativeSourceFormat, schema.NativeFormatVersion)
		if rerr == nil || rerr.Code != ingest.NativeCodeManifestMismatch {
			t.Fatalf("err = %v, want manifest_mismatch", rerr)
		}
		if rerr.OffsetSpace != ingest.NativeSpaceManifest || rerr.Offset != want {
			t.Fatalf("anchor = %s/%d, want manifest/%d", rerr.OffsetSpace, rerr.Offset, want)
		}
	})
}

// oversizedNativeJSONSource builds a valid but over-budget JSON source (one
// record whose envelope exceeds 16 MiB) to check the production derived-size
// failure mode.
func oversizedNativeJSONSource() ingest.NativeSource {
	vulns := ingest.NativeArray{}
	for i := 0; i < 3300; i++ {
		vulns.Items = append(vulns.Items, ingest.NativeObject{
			Keys: []string{"cve", "packageName", "vecStr"},
			Values: []ingest.NativeValue{
				ingest.NativeString("CVE-2026-1"),
				ingest.NativeString(strings.Repeat("a", 1024)),
				ingest.NativeString(strings.Repeat("b", 4096)),
			},
		})
	}
	data := ingest.NativeObject{
		Keys:   []string{"packages", "type", "vulnerabilities"},
		Values: []ingest.NativeValue{ingest.NativeArray{}, ingest.NativeString("image"), vulns},
	}
	return ingest.NativeSource{
		Profile: ingest.NativeProfile{
			Selector: schema.NativeJSONSelector, InputVersion: schema.NativeInputVersion,
			Name: schema.NativeJSONProfile, RedactionPolicy: schema.NativeRedactionPolicy,
			AdapterSemantics: schema.NativeAdapterSemantics,
		},
		Context: nativeTestContext(),
		Input:   ingest.NativeInput{SourceAlias: "fixture", NativeFormat: "json", OriginalBytes: 3},
		Records: []ingest.NativeRecord{{Ordinal: 0, OriginLocator: "json:/0", OriginStart: 1, OriginEnd: 2, Data: data}},
	}
}

// TestPrismaNativeDerivedRecordProductionLimit asserts that a record over the
// §11.9.1 derived size budget fails production with output_limit/projection, not
// with the replay-admission schema rejection.
func TestPrismaNativeDerivedRecordProductionLimit(t *testing.T) {
	src := oversizedNativeJSONSource()
	if ingest.NativeDerivedSizesWithinBudgets(src) {
		t.Fatalf("oversized source reported within budgets")
	}
	if _, err := EncodePrismaNativeImport(src); err == nil || err.Code != ingest.NativeCodeOutputLimit {
		t.Fatalf("err = %v, want output_limit", err)
	} else if err.Phase != ingest.NativePhaseProjection || err.OffsetSpace != ingest.NativeSpaceNone {
		t.Fatalf("phase/space = %s/%s, want projection/none", err.Phase, err.OffsetSpace)
	}
}

// TestPrismaNativeMalformedDTONoPanic asserts that a DTO with Keys/Values out of
// step is rejected with a typed error instead of panicking the measurement or
// the encoder.
func TestPrismaNativeMalformedDTONoPanic(t *testing.T) {
	src, err := ingest.ParsePrismaNative(strings.NewReader(`[{"type":"image","packages":[],"vulnerabilities":[]}]`), schema.NativeJSONSelector, "1.0", schema.NativeJSONProfile, nativeTestContext())
	if err != nil {
		t.Fatalf("parse failed: %v", err)
	}
	src.Records[0].Data = ingest.NativeObject{Keys: []string{"type"}, Values: nil}
	if _, err := EncodePrismaNativeImport(src); err == nil {
		t.Fatalf("malformed DTO accepted")
	}
}

// TestPrismaNativeTimeRows covers the §12.5.4 temporal rows and §9 semantics.
func TestPrismaNativeTimeRows(t *testing.T) {
	t.Run("scan_after_acquisition", func(t *testing.T) {
		man := nativeManifestOf(t, `[{"type":"image","scanTime":"2027-01-01T00:00:00Z"}]`)
		if !hasLimitation(man, "temporal_conflict") {
			t.Fatalf("temporal_conflict not activated: %v", man.Limitations)
		}
		if got := lossFor(man, "/records/[]/data/scanTime", "semantics_unverified"); got != 1 {
			t.Fatalf("scan_after_acquisition loss = %d, want 1", got)
		}
	})
	t.Run("discovered_invalid", func(t *testing.T) {
		man := nativeManifestOf(t, `[{"type":"image","vulnerabilities":[{"discovered":"2026-13-01T00:00:00Z"}]}]`)
		if !hasLimitation(man, "values_uninterpretable") {
			t.Fatalf("values_uninterpretable not activated: %v", man.Limitations)
		}
		if got := lossFor(man, "/records/[]/data/vulnerabilities/[]/discovered", "semantics_unverified"); got != 1 {
			t.Fatalf("discovered loss = %d, want 1", got)
		}
	})
	t.Run("unix_zero", func(t *testing.T) {
		man := nativeManifestOf(t, `[{"type":"image","vulnerabilities":[{"published":0}]}]`)
		if got := lossFor(man, "/records/[]/data/vulnerabilities/[]/published", "semantics_unverified"); got != 1 {
			t.Fatalf("published zero loss = %d, want 1", got)
		}
	})
	t.Run("csv_time_column", func(t *testing.T) {
		hdr := strings.Join(schema.NativeCSVHeader(), ",")
		fields := make([]string, 39)
		fields[26] = "2026-01-01" // Published
		input := hdr + "\n" + strings.Join(fields, ",")
		src, err := ingest.ParsePrismaNative(strings.NewReader(input), schema.NativeCSVSelector, "1.0", schema.NativeCSVProfile, nativeTestContext())
		if err != nil {
			t.Fatalf("parse failed: %v", err)
		}
		man, err := BuildNativeManifest(src, "sha256:"+strings.Repeat("0", 64), 1)
		if err != nil {
			t.Fatalf("manifest failed: %v", err)
		}
		if got := lossFor(man, "/records/[]/data/Published", "semantics_unverified"); got != 1 {
			t.Fatalf("CSV Published loss = %d, want 1", got)
		}
	})
}

// TestPrismaNativeDiagnosticVector checks the diagnostic expectations of
// §11.12.1 for the minimal JSON source: 23 field_absent, 2 field_empty and one
// no_runtime_binding, all anchored to the canonical source.
func TestPrismaNativeDiagnosticVector(t *testing.T) {
	input := `[{"type":"image","packages":[],"vulnerabilities":[]}]`
	src, err := ingest.ParsePrismaNative(strings.NewReader(input), schema.NativeJSONSelector, "1.0", schema.NativeJSONProfile, nativeTestContext())
	if err != nil {
		t.Fatalf("parse failed: %v", err)
	}
	sourceBytes := ingest.EncodeNativeSource(src)
	inv, ierr := InterpretPrismaNative(src, ingest.HashNativeSource(sourceBytes), uint64(len(sourceBytes)))
	if ierr != nil {
		t.Fatalf("interpret failed: %v", ierr)
	}
	counts := map[string]int{}
	for _, d := range inv.Diagnostics {
		counts[d.Code]++
	}
	if counts["field_absent"] != 23 {
		t.Fatalf("field_absent = %d, want 23", counts["field_absent"])
	}
	if counts["field_empty"] != 2 {
		t.Fatalf("field_empty = %d, want 2", counts["field_empty"])
	}
	if counts["no_runtime_binding"] != 1 {
		t.Fatalf("no_runtime_binding = %d, want 1", counts["no_runtime_binding"])
	}
}

// TestPrismaNativeInterpretationCoordinates reproduces the §12.4.4 example: two
// different 59-byte inputs produce the same 1204-byte canonical source and the
// same scalar_invalid diagnostic at source offset 1193.
func TestPrismaNativeInterpretationCoordinates(t *testing.T) {
	a := `[ {"vulnerabilities":[{"cve":"CVE-2026-1234","cvss":11}]} ]`
	b := `[ {"vulnerabilities":[{"cvss":11,"cve":"CVE-2026-1234"}]} ]`
	if len(a) != 59 || len(b) != 59 {
		t.Fatalf("input lengths = %d/%d, want 59/59", len(a), len(b))
	}
	srcA, err := ingest.ParsePrismaNative(strings.NewReader(a), schema.NativeJSONSelector, "1.0", schema.NativeJSONProfile, nativeTestContext())
	if err != nil {
		t.Fatalf("parse a failed: %v", err)
	}
	srcB, err := ingest.ParsePrismaNative(strings.NewReader(b), schema.NativeJSONSelector, "1.0", schema.NativeJSONProfile, nativeTestContext())
	if err != nil {
		t.Fatalf("parse b failed: %v", err)
	}
	bytesA := ingest.EncodeNativeSource(srcA)
	bytesB := ingest.EncodeNativeSource(srcB)
	if string(bytesA) != string(bytesB) {
		t.Fatalf("sources differ between the two 59-byte inputs")
	}
	if len(bytesA) != 1204 {
		t.Fatalf("canonical source length = %d, want 1204", len(bytesA))
	}
	inv, ierr := InterpretPrismaNative(srcA, ingest.HashNativeSource(bytesA), uint64(len(bytesA)))
	if ierr != nil {
		t.Fatalf("interpret failed: %v", ierr)
	}
	found := false
	for _, d := range inv.Diagnostics {
		if d.Code == "scalar_invalid" && d.Path != nil && *d.Path == "/records/0/data/vulnerabilities/0/cvss" {
			if d.Locator == nil || *d.Locator != "/records/0/data/vulnerabilities/0/cvss/number" {
				t.Fatalf("locator = %v", d.Locator)
			}
			if d.OffsetSpace != ingest.NativeSpaceSource || d.Offset != 1193 {
				t.Fatalf("offset = %s:%d, want source:1193", d.OffsetSpace, d.Offset)
			}
			found = true
		}
	}
	if !found {
		t.Fatalf("scalar_invalid diagnostic not found")
	}
}
