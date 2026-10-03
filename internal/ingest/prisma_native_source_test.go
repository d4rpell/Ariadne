package ingest

import (
	"strings"
	"testing"

	"github.com/d4rpell/Ariadne/internal/schema"
)

// Independent wire vectors of ADR-0027 §11.12. The expected bytes, lengths and
// hashes are literal oracle values computed with an independent Python
// implementation; they are not derived from this encoder.

func minimalNativeContext() NativeContext {
	f := false
	return NativeContext{
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

// minimalJSONSource builds the source of §11.12.1: one image object with only
// type, packages and vulnerabilities present.
func minimalJSONSource() NativeSource {
	return NativeSource{
		Profile: jsonProfile(),
		Context: minimalNativeContext(),
		Input:   NativeInput{SourceAlias: "fixture", NativeFormat: "json", OriginalBytes: 53},
		Records: []NativeRecord{{
			Ordinal:       0,
			OriginLocator: "json:/0",
			OriginStart:   1,
			OriginEnd:     52,
			Data: NativeObject{
				Keys: []string{"type", "packages", "vulnerabilities"},
				Values: []NativeValue{
					NativeString("image"),
					NativeArray{},
					NativeArray{},
				},
			},
		}},
	}
}

// minimalCSVSource builds the source of §11.12.2: one H39 row where only CVE ID
// and CVSS are non-empty.
func minimalCSVSource() NativeSource {
	values := map[string]NativeValue{"CVE ID": NativeString("CVE-2026-1234"), "CVSS": NativeString("0")}
	obj := NativeObject{}
	for _, col := range schema.NativeCSVColumns() {
		obj.Keys = append(obj.Keys, col.Name)
		if v, ok := values[col.Name]; ok {
			obj.Values = append(obj.Values, v)
			continue
		}
		if col.Disposition == schema.NativeExcludedValue {
			obj.Values = append(obj.Values, NativeRedacted{Kind: "empty"})
			continue
		}
		obj.Values = append(obj.Values, NativeString(""))
	}
	return NativeSource{
		Profile: csvProfile(),
		Context: minimalNativeContext(),
		Input:   NativeInput{SourceAlias: "fixture", NativeFormat: "csv", OriginalBytes: 441},
		Records: []NativeRecord{{
			Ordinal:       0,
			OriginLocator: "csv:record/1/bytes/389-441",
			OriginStart:   389,
			OriginEnd:     441,
			Data:          obj,
		}},
	}
}

// TestPrismaNativeIndependentWireVectors asserts that the canonical encoder
// reproduces the source vectors of §11.12 byte for byte, including length and
// hash. Any divergence fails the invariant that Ariadne's derived source is the
// one the contract fixes.
func TestPrismaNativeIndependentWireVectors(t *testing.T) {
	t.Run("json_source", func(t *testing.T) {
		got := EncodeNativeSource(minimalJSONSource())
		if len(got) != 1187 {
			t.Fatalf("json source length = %d, want 1187", len(got))
		}
		const want = "sha256:25cb2426ee5cd817d410e554145042a0e010c121399e101e4bd4b9620fd19a15"
		if hash := HashNativeSource(got); hash != want {
			t.Fatalf("json source hash = %s, want %s", hash, want)
		}
	})
	t.Run("csv_source", func(t *testing.T) {
		got := EncodeNativeSource(minimalCSVSource())
		if len(got) != 2021 {
			t.Fatalf("csv source length = %d, want 2021", len(got))
		}
		const want = "sha256:3fa05d28f01ccc0dfd07d952a6683ca5cc403c0da8574426dd2e1ea37bf42528"
		if hash := HashNativeSource(got); hash != want {
			t.Fatalf("csv source hash = %s, want %s", hash, want)
		}
	})
}

// TestPrismaNativeManifestWireVectors asserts the manifest serializer against
// the literal manifest values of §11.12 (length and sidecar digest). The
// interpretation that derives these counts, losses and limitations is a
// separate concern; here the manifest content is the contract's own oracle.
func TestPrismaNativeManifestWireVectors(t *testing.T) {
	t.Run("json_manifest", func(t *testing.T) {
		man := NativeManifest{
			SourceHash:    "sha256:25cb2426ee5cd817d410e554145042a0e010c121399e101e4bd4b9620fd19a15",
			SourceBytes:   1187,
			OriginalBytes: 53,
			Profile:       jsonProfile(),
			Counts:        NativeCounts{Records: 1},
			Losses:        []NativeLoss{},
			Limitations: []string{
				"documentary_profile", "origin_not_authenticated",
				"inventory_not_verified", "no_runtime_binding",
				"cvss_consistency_not_verified", "original_content_not_retained",
				"fields_incomplete",
			},
		}
		got := EncodeNativeManifest(man)
		if len(got) != 835 {
			t.Fatalf("json manifest length = %d, want 835", len(got))
		}
		sidecar := NativeManifestSidecar(HashNativeManifest(got))
		if len(sidecar) != 72 {
			t.Fatalf("sidecar length = %d, want 72", len(sidecar))
		}
		const want = "sha256:a8bbb3eb685e524789a08a32daceb7d72c112214b2f19462156658df48f04de0\n"
		if string(sidecar) != want {
			t.Fatalf("json sidecar = %q, want %q", sidecar, want)
		}
	})
	t.Run("csv_manifest", func(t *testing.T) {
		man := NativeManifest{
			SourceHash:    "sha256:3fa05d28f01ccc0dfd07d952a6683ca5cc403c0da8574426dd2e1ea37bf42528",
			SourceBytes:   2021,
			OriginalBytes: 441,
			Profile:       csvProfile(),
			Counts:        NativeCounts{Records: 1, FindingOccurrences: 1, CVEOccurrences: 1},
			Losses: []NativeLoss{
				{Path: "/records/[]/data", Reason: "semantics_unverified", Occurrences: 1},
				{Path: "/records/[]/data/Apps", Reason: "excluded_by_policy", Occurrences: 1},
				{Path: "/records/[]/data/Binaries", Reason: "excluded_by_policy", Occurrences: 1},
				{Path: "/records/[]/data/Cause", Reason: "excluded_by_policy", Occurrences: 1},
				{Path: "/records/[]/data/Collections", Reason: "excluded_by_policy", Occurrences: 1},
				{Path: "/records/[]/data/Containers", Reason: "excluded_by_policy", Occurrences: 1},
				{Path: "/records/[]/data/Custom Labels", Reason: "excluded_by_policy", Occurrences: 1},
				{Path: "/records/[]/data/Defender Hosts", Reason: "excluded_by_policy", Occurrences: 1},
				{Path: "/records/[]/data/Description", Reason: "excluded_by_policy", Occurrences: 1},
				{Path: "/records/[]/data/Grace Days", Reason: "excluded_by_policy", Occurrences: 1},
				{Path: "/records/[]/data/Hosts", Reason: "excluded_by_policy", Occurrences: 1},
				{Path: "/records/[]/data/Package License", Reason: "excluded_by_policy", Occurrences: 1},
				{Path: "/records/[]/data/Risk Factors", Reason: "excluded_by_policy", Occurrences: 1},
				{Path: "/records/[]/data/Vulnerability Link", Reason: "excluded_by_policy", Occurrences: 1},
				{Path: "/records/[]/data/Vulnerability Tags", Reason: "excluded_by_policy", Occurrences: 1},
			},
			Limitations: []string{
				"documentary_profile", "csv_header_unverified",
				"origin_not_authenticated", "inventory_not_verified",
				"no_runtime_binding", "cvss_consistency_not_verified",
				"original_content_not_retained", "data_excluded", "fields_incomplete",
			},
		}
		got := EncodeNativeManifest(man)
		if len(got) != 2167 {
			t.Fatalf("csv manifest length = %d, want 2167", len(got))
		}
		const want = "sha256:7690cee3e48678c63ddf4af797756b500598f4d7f7770bd66e9aa7b3b147cdfd\n"
		if string(NativeManifestSidecar(HashNativeManifest(got))) != want {
			t.Fatalf("csv sidecar = %q, want %q", NativeManifestSidecar(HashNativeManifest(got)), want)
		}
	})
}

// jsonSourceVector is the literal native-source.json of §11.12.1 (1187 bytes).
const jsonSourceVector = `{"format":"prisma-native-source-v1","version":"1.0","profile":{"selector":"prisma-native-images-json-v1","input_version":"1.0","name":"compute-sh-34.04.145-images-json","redaction_policy":"prisma-native-offline-redaction-v1/1.0","adapter_semantics":"prisma-native-offline/1.0"},"context":{"origin_alias":"synthetic","source_alias":"fixture","declared_edition":"compute_self_hosted","declared_release":"34.04.145","version_basis":"operator_declared","report_kind":"deployed_images","acquisition_kind":"synthetic_fixture","acquired_at":"2026-10-02T00:00:00Z","capture_termination":"finished","scope_mode":"unfiltered_declared","scope_alias":null,"filter_status":"none_declared","compact":false,"normalized_severity":false,"layers":false,"fields_mode":"unrestricted_declared","selected_fields":[],"page_mode":"export_declared","page_ordinal":null,"pages_expected":null,"data_policy_ack":"prisma-native-offline-redaction-v1/1.0"},"input":{"source_alias":"fixture","native_format":"json","original_bytes":53,"local_eof":true,"original_hash":null},"records":[{"ordinal":0,"origin_locator":"json:/0","origin_start":1,"origin_end":52,"data":{"packages":[],"type":"image","vulnerabilities":[]}}]}`

// TestPrismaNativeJSONReaderVector asserts that the JSON reader admits the
// §11.12.1 input and projects the exact byte-identical source of the contract:
// the reader, the projection and the serializer must agree with the independent
// oracle, not merely with each other.
func TestPrismaNativeJSONReaderVector(t *testing.T) {
	input := []byte(`[{"type":"image","packages":[],"vulnerabilities":[]}]`)
	if len(input) != 53 {
		t.Fatalf("input length = %d, want 53", len(input))
	}
	src, err := parsePrismaNativeJSON(input, minimalNativeContext())
	if err != nil {
		t.Fatalf("parse failed: %v", err)
	}
	got := string(EncodeNativeSource(src))
	if got != jsonSourceVector {
		t.Fatalf("source mismatch:\n got: %s\nwant: %s", got, jsonSourceVector)
	}
	if len(got) != 1187 {
		t.Fatalf("length = %d, want 1187", len(got))
	}
	const want = "sha256:25cb2426ee5cd817d410e554145042a0e010c121399e101e4bd4b9620fd19a15"
	if hash := HashNativeSource([]byte(got)); hash != want {
		t.Fatalf("hash = %s, want %s", hash, want)
	}
}

// TestPrismaNativeJSONAdmission covers the closed structural rules of §6.3-§6.4
// on the JSON reader: empty array, unknown key, duplicate key, non-image scope.
func TestPrismaNativeJSONAdmission(t *testing.T) {
	ctx := minimalNativeContext()
	cases := []struct {
		name  string
		input string
		code  string
		ok    bool
	}{
		{"empty_array", `[]`, "", true},
		{"single_object", `{"type":"image"}`, NativeCodeInvalidJSON, false},
		{"unknown_key", `[{"type":"image","nope":1}]`, NativeCodeFieldNotAllowed, false},
		{"duplicate_key", `[{"type":"image","type":"image"}]`, NativeCodeDuplicateKey, false},
		{"non_image_scope", `[{"type":"compliance"}]`, NativeCodeUnsupportedReportScope, false},
		{"empty_type_ok", `[{"type":""}]`, "", true},
		{"trailing_data", `[] []`, NativeCodeInvalidJSON, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := parsePrismaNativeJSON([]byte(tc.input), ctx)
			if tc.ok {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				return
			}
			if err == nil {
				t.Fatalf("expected error %s, got nil", tc.code)
			}
			if err.Code != tc.code {
				t.Fatalf("code = %s, want %s", err.Code, tc.code)
			}
		})
	}
}

// TestPrismaNativeJSONDiscardDuplicateKey asserts that duplicate keys are
// detected even inside a discarded (excluded) subtree.
func TestPrismaNativeJSONDiscardDuplicateKey(t *testing.T) {
	_, err := parsePrismaNativeJSON([]byte(`[{"history":{"a":1,"a":2}}]`), minimalNativeContext())
	if err == nil || err.Code != NativeCodeDuplicateKey {
		t.Fatalf("err = %v, want duplicate_key", err)
	}
}

// TestPrismaNativeJSONNULRejected asserts that a NUL escape is rejected even in
// a discarded subtree (§6.3: NUL is globally forbidden).
func TestPrismaNativeJSONNULRejected(t *testing.T) {
	_, err := parsePrismaNativeJSON([]byte(`[{"history":"a\u0000b"}]`), minimalNativeContext())
	if err == nil || err.Code != NativeCodeForbiddenText {
		t.Fatalf("err = %v, want forbidden_text", err)
	}
}

// TestPrismaNativeJSONExcludedWitness asserts the discard witness kinds of
// §11.3 for an excluded member: null, empty and value.
func TestPrismaNativeJSONExcludedWitness(t *testing.T) {
	src, err := parsePrismaNativeJSON([]byte(`[{"history":null,"image":{},"labels":"x"}]`), minimalNativeContext())
	if err != nil {
		t.Fatalf("parse failed: %v", err)
	}
	obj, ok := src.Records[0].Data.(NativeObject)
	if !ok {
		t.Fatalf("record data is not an object")
	}
	want := map[string]string{"history": "null", "image": "empty", "labels": "value"}
	for i, key := range obj.Keys {
		if kind, isRedacted := obj.Values[i].(NativeRedacted); isRedacted {
			if want[key] != kind.Kind {
				t.Fatalf("%s witness = %s, want %s", key, kind.Kind, want[key])
			}
			delete(want, key)
		}
	}
	if len(want) != 0 {
		t.Fatalf("witnesses not projected for %v", want)
	}
}

// csvSourceVector is the literal native-source.json of §11.12.2 (2021 bytes).
const csvSourceVector = `{"format":"prisma-native-source-v1","version":"1.0","profile":{"selector":"prisma-native-images-csv-v1","input_version":"1.0","name":"compute-sh-34.04.145-images-csv-h39-candidate","redaction_policy":"prisma-native-offline-redaction-v1/1.0","adapter_semantics":"prisma-native-offline/1.0"},"context":{"origin_alias":"synthetic","source_alias":"fixture","declared_edition":"compute_self_hosted","declared_release":"34.04.145","version_basis":"operator_declared","report_kind":"deployed_images","acquisition_kind":"synthetic_fixture","acquired_at":"2026-10-02T00:00:00Z","capture_termination":"finished","scope_mode":"unfiltered_declared","scope_alias":null,"filter_status":"none_declared","compact":false,"normalized_severity":false,"layers":false,"fields_mode":"unrestricted_declared","selected_fields":[],"page_mode":"export_declared","page_ordinal":null,"pages_expected":null,"data_policy_ack":"prisma-native-offline-redaction-v1/1.0"},"input":{"source_alias":"fixture","native_format":"csv","original_bytes":441,"local_eof":true,"original_hash":null},"records":[{"ordinal":0,"origin_locator":"csv:record/1/bytes/389-441","origin_start":389,"origin_end":441,"data":{"Apps":{"redacted":"empty"},"Binaries":{"redacted":"empty"},"CVE ID":"CVE-2026-1234","CVSS":"0","Cause":{"redacted":"empty"},"Clusters":"","Collections":{"redacted":"empty"},"Compliance":"","Containers":{"redacted":"empty"},"Custom Labels":{"redacted":"empty"},"Defender Hosts":{"redacted":"empty"},"Description":{"redacted":"empty"},"Digest":"","Discovered":"","Distro":"","Fix Date":"","Fix Status":"","Grace Days":{"redacted":"empty"},"Hosts":{"redacted":"empty"},"Id":"","Layer":"","Namespaces":"","PURL":"","Package License":{"redacted":"empty"},"Package Path":"","Package Version":"","Packages":"","Published":"","Registry":"","Repository":"","Result":"","Risk Factors":{"redacted":"empty"},"Severity":"","Source Package":"","Start Time":"","Tag":"","Type":"","Vulnerability Link":{"redacted":"empty"},"Vulnerability Tags":{"redacted":"empty"}}}]}`

// TestPrismaNativeCSVReaderVector asserts that the CSV reader admits the
// §11.12.2 input and projects the exact byte-identical source of the contract.
func TestPrismaNativeCSVReaderVector(t *testing.T) {
	hdr := strings.Join(schema.NativeCSVHeader(), ",")
	if len(hdr) != 388 {
		t.Fatalf("header length = %d, want 388", len(hdr))
	}
	fields := make([]string, 39)
	fields[7] = "CVE-2026-1234"
	fields[16] = "0"
	input := hdr + "\n" + strings.Join(fields, ",")
	if len(input) != 441 {
		t.Fatalf("input length = %d, want 441", len(input))
	}
	src, err := parsePrismaNativeCSV([]byte(input), minimalNativeContext())
	if err != nil {
		t.Fatalf("parse failed: %v", err)
	}
	got := string(EncodeNativeSource(src))
	if got != csvSourceVector {
		t.Fatalf("source mismatch:\n got: %s\nwant: %s", got, csvSourceVector)
	}
	if len(got) != 2021 {
		t.Fatalf("length = %d, want 2021", len(got))
	}
	const want = "sha256:3fa05d28f01ccc0dfd07d952a6683ca5cc403c0da8574426dd2e1ea37bf42528"
	if hash := HashNativeSource([]byte(got)); hash != want {
		t.Fatalf("hash = %s, want %s", hash, want)
	}
}

// TestPrismaNativeCSVAdmission covers the closed header and dialect rules of
// §4.4-§4.5 on the CSV reader.
func TestPrismaNativeCSVAdmission(t *testing.T) {
	ctx := minimalNativeContext()
	hdr := strings.Join(schema.NativeCSVHeader(), ",")
	row := strings.Repeat(",", 38)
	valid := hdr + "\n" + row
	cases := []struct {
		name  string
		input string
		code  string
		ok    bool
	}{
		{"header_only", hdr, "", true},
		{"lf_record", valid, "", true},
		{"crlf_record", hdr + "\r\n" + row, "", true},
		{"zero_bytes", "", NativeCodeInvalidHeader, false},
		{"missing_column", strings.Join(schema.NativeCSVHeader()[:38], ",") + "\n" + row, NativeCodeInvalidHeader, false},
		{"reordered", strings.Join(reorder(schema.NativeCSVHeader()), ",") + "\n" + row, NativeCodeInvalidHeader, false},
		{"typo_alias", strings.Replace(hdr, "Packages", "Pachakges", 1) + "\n" + row, NativeCodeInvalidHeader, false},
		{"wrong_width", hdr + "\n" + strings.Repeat(",", 37), NativeCodeFieldCount, false},
		{"blank_record", hdr + "\n\n", NativeCodeFieldCount, false},
		{"bare_cr", hdr + "\r" + row, NativeCodeInvalidCSV, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := parsePrismaNativeCSV([]byte(tc.input), ctx)
			if tc.ok {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				return
			}
			if err == nil {
				t.Fatalf("expected error %s, got nil", tc.code)
			}
			if err.Code != tc.code {
				t.Fatalf("code = %s, want %s", err.Code, tc.code)
			}
		})
	}
}

// TestPrismaNativeCSVQuotingDialect asserts "," inside quotes and "" escapes.
func TestPrismaNativeCSVQuotingDialect(t *testing.T) {
	hdr := strings.Join(schema.NativeCSVHeader(), ",")
	fields := make([]string, 39)
	fields[1] = `"a,b"`  // Repository: quoted comma stays one cell
	fields[2] = `"a""b"` // Tag: escaped quote
	input := hdr + "\n" + strings.Join(fields, ",")
	src, err := parsePrismaNativeCSV([]byte(input), minimalNativeContext())
	if err != nil {
		t.Fatalf("parse failed: %v", err)
	}
	obj := src.Records[0].Data.(NativeObject)
	byKey := map[string]NativeValue{}
	for i, k := range obj.Keys {
		byKey[k] = obj.Values[i]
	}
	if byKey["Repository"].(NativeString) != "a,b" {
		t.Fatalf("Repository = %q, want a,b", byKey["Repository"])
	}
	if byKey["Tag"].(NativeString) != `a"b` {
		t.Fatalf("Tag = %q, want a\"b", byKey["Tag"])
	}
}

// reorder swaps the first two header names to build a reordered header.
func reorder(in []string) []string {
	out := append([]string{}, in...)
	out[0], out[1] = out[1], out[0]
	return out
}
