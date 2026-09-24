package evidence

import (
	"bytes"
	"encoding/json"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestEnumAcceptsContractValues(t *testing.T) {
	values := []enumValue{
		ProvenanceObserved, ProvenanceDerived, ProvenanceUnavailable,
		ContainerRegular, ContainerInit, ContainerEphemeral,
		PlatformKnown, PlatformUnknown,
		CompletenessComplete, CompletenessPartial, CompletenessUnknown,
		ConsistencyPointObservation, ConsistencyNotAtomic,
		CoverageFindingsImport, CoverageContainerObservation,
		TerminationFinished, TerminationAborted, TerminationUnknown,
		WarningInformational, WarningContradictory,
		ProductAffected, ProductNotAffected, ProductFixed, ProductUnderInvestigation,
		ExploitabilityNotAssessed, ExploitabilityUnknown, ExploitabilityConditionsMet, ExploitabilityConditionsNotMet,
		RiskNotAssessed, RiskAccepted, RiskDeferred, RiskRejected,
	}
	for _, value := range values {
		if !value.Valid() {
			t.Errorf("%#v is part of the contract vocabulary and was rejected", value)
		}
	}
}

func TestEnumRejectsNonContractValues(t *testing.T) {
	values := []enumValue{
		ProvenanceKind(""), ProvenanceKind("unknown"), ProvenanceKind("assumed"),
		ContainerClass(""), ContainerClass("sidecar"),
		PlatformStatus(""), PlatformStatus("unresolved"),
		Completeness(""), Completeness("done"),
		Consistency(""), Consistency("atomic"),
		CoverageMethod(""), CoverageMethod("csv_import"), CoverageMethod("observation"),
		CoverageTermination(""), CoverageTermination("done"), CoverageTermination("partial"),
		WarningClass(""), WarningClass("critical"), WarningClass("error"),
		ProductStatus(""), ProductStatus("unknown"), ProductStatus("excepcionable"),
		Exploitability(""), Exploitability("exploitable"),
		RiskDecision(""), RiskDecision("exceptionable"),
	}
	for _, value := range values {
		if value.Valid() {
			t.Errorf("%#v is not part of a contract vocabulary and was accepted", value)
		}
	}
}

func TestParseRejectsEmptyAndUnpaddedValues(t *testing.T) {
	for _, value := range []string{"", "   ", " uid ", "\tuid"} {
		if _, err := ParseUID(value); err == nil {
			t.Errorf("ParseUID accepted %q", value)
		}
		if _, err := ParseDigest(value); err == nil {
			t.Errorf("ParseDigest accepted %q", value)
		}
		if _, err := ParsePURL(value); err == nil {
			t.Errorf("ParsePURL accepted %q", value)
		}
	}
}

func TestParseAcceptsExactValues(t *testing.T) {
	uid, err := ParseUID("pod-uid-1")
	if err != nil || uid != UID("pod-uid-1") {
		t.Fatalf("ParseUID: %v, %q", err, uid)
	}
	digest, err := ParseDigest("sha256:aaa")
	if err != nil || digest != Digest("sha256:aaa") {
		t.Fatalf("ParseDigest: %v, %q", err, digest)
	}
	purl, err := ParsePURL("pkg:rpm/redhat/openssl@3.0")
	if err != nil || purl != PURL("pkg:rpm/redhat/openssl@3.0") {
		t.Fatalf("ParsePURL: %v, %q", err, purl)
	}
}

func TestParseKeepsRawValuesWithoutNormalization(t *testing.T) {
	raw := "registry.example/app@sha256:aaa"
	digest, err := ParseDigest(raw)
	if err != nil {
		t.Fatalf("ParseDigest: %v", err)
	}
	if string(digest) != raw {
		t.Fatalf("ParseDigest modified the value: %q", digest)
	}
}

func TestNewTimestampNormalizesToUTC(t *testing.T) {
	if _, err := NewTimestamp(time.Time{}); err == nil {
		t.Fatal("NewTimestamp accepted the zero instant")
	}
	madrid := time.FixedZone("CEST", 2*60*60)
	local := time.Date(2026, 9, 23, 14, 0, 0, 0, madrid)
	utc := time.Date(2026, 9, 23, 12, 0, 0, 0, time.UTC)
	normalized, err := NewTimestamp(local)
	if err != nil {
		t.Fatalf("NewTimestamp: %v", err)
	}
	reference, err := NewTimestamp(utc)
	if err != nil {
		t.Fatalf("NewTimestamp: %v", err)
	}
	if !reflect.DeepEqual(normalized, reference) {
		t.Fatalf("equal instants with different offsets produced different timestamps: %#v and %#v", normalized, reference)
	}
	if normalized.Location() != time.UTC {
		t.Fatalf("timestamp kept a non UTC location: %v", normalized.Location())
	}
}

func TestSemanticRoundTrip(t *testing.T) {
	bundle := testBundle(t)
	encoded, err := json.Marshal(bundle)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var decoded Bundle
	if err := json.Unmarshal(encoded, &decoded); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if !reflect.DeepEqual(bundle, decoded) {
		t.Fatalf("round trip changed the bundle:\nwant %#v\ngot  %#v", bundle, decoded)
	}
}

// TestWireNamesAreSnakeCase checks the tags of the frozen wire. The canonical
// bytes, their ordering and the bundle hash are produced by internal/evidence.
func TestWireNamesAreSnakeCase(t *testing.T) {
	encoded, err := json.Marshal(testBundle(t))
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	for _, name := range []string{
		`"schema_version"`, `"cluster_alias"`, `"owner_chain"`, `"container_class"`, `"requested_image"`,
		`"normalized_digest"`, `"value_hash"`, `"observed_at"`, `"subject_uid"`, `"container_name"`,
		`"collector_version"`, `"ruleset"`, `"argv_sanitized"`, `"api_scope"`, `"wall_clock"`,
		`"coverage"`, `"termination"`, `"rows"`, `"completeness"`, `"redaction_policy"`, `"observed_container_classes"`,
	} {
		if !strings.Contains(string(encoded), name) {
			t.Errorf("the default encoding lost the wire name %s", name)
		}
	}
	if strings.Contains(string(encoded), `"SchemaVersion"`) || strings.Contains(string(encoded), `"Subject":`) {
		t.Fatal("a field is still encoded with its Go name instead of its wire name")
	}
}

// TestOptionalWireValuesAreNull covers ADR-0006 §2: the three optional values
// that the Go model keeps as non-pointer fields are emitted as null.
func TestOptionalWireValuesAreNull(t *testing.T) {
	subject := Subject{
		ClusterAlias: ClusterAlias("cluster-a"),
		Namespace:    Namespace("payments"),
		Kind:         "Pod",
		Name:         "payments-api-7f4d",
		UID:          UID("pod-uid-1"),
	}
	encoded, err := json.Marshal(subject)
	if err != nil {
		t.Fatalf("marshal subject: %v", err)
	}
	if !strings.Contains(string(encoded), `"owner_chain":null`) {
		t.Fatalf("an empty owner chain must be emitted as null: %s", encoded)
	}

	platform, err := json.Marshal(Platform{Status: PlatformUnknown})
	if err != nil {
		t.Fatalf("marshal platform: %v", err)
	}
	if string(platform) != `{"os":null,"architecture":null,"status":"unknown"}` {
		t.Fatalf("an unknown platform must emit null os and architecture: %s", platform)
	}

	ruleset, err := json.Marshal(RulesetRef{})
	if err != nil {
		t.Fatalf("marshal ruleset: %v", err)
	}
	if string(ruleset) != `null` {
		t.Fatalf("the zero ruleset must be emitted as null: %s", ruleset)
	}

	known, err := json.Marshal(Platform{OS: "linux", Architecture: "amd64", Status: PlatformKnown})
	if err != nil {
		t.Fatalf("marshal platform: %v", err)
	}
	if string(known) != `{"os":"linux","architecture":"amd64","status":"known"}` {
		t.Fatalf("a known platform must emit its observed values: %s", known)
	}
}

// TestWireDoesNotEscapeHTML freezes the escaping rule of ADR-0006 §4 for the
// marshalers of this package. The canonical bytes of a whole bundle come from
// internal/evidence, which configures the encoder the same way.
func TestWireDoesNotEscapeHTML(t *testing.T) {
	message := `a < b & c > d`
	encoded, err := OwnerChain(message).MarshalJSON()
	if err != nil {
		t.Fatalf("MarshalJSON: %v", err)
	}
	if string(encoded) != `"`+message+`"` {
		t.Fatalf("HTML characters were escaped: %s", encoded)
	}
}

// TestMarshalIsStable covers stability of the encoding. Canonical bytes and the
// hash live in internal/evidence.
func TestMarshalIsStable(t *testing.T) {
	bundle := testBundle(t)
	first, err := json.Marshal(bundle)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	second, err := json.Marshal(bundle)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if !bytes.Equal(first, second) {
		t.Fatal("marshalling the same bundle twice produced different bytes")
	}
}

// TestDecisionLayersDoNotShareVocabulary checks the type vocabularies only: the
// shape of an evaluation holding the three layers is out of scope for the bundle
// contract (ADR-0006 §9).
func TestDecisionLayersDoNotShareVocabulary(t *testing.T) {
	products := map[string]bool{
		string(ProductAffected): true, string(ProductNotAffected): true,
		string(ProductFixed): true, string(ProductUnderInvestigation): true,
	}
	exploitabilities := map[string]bool{
		string(ExploitabilityNotAssessed): true, string(ExploitabilityUnknown): true,
		string(ExploitabilityConditionsMet): true, string(ExploitabilityConditionsNotMet): true,
	}
	risks := map[string]bool{
		string(RiskNotAssessed): true, string(RiskAccepted): true,
		string(RiskDeferred): true, string(RiskRejected): true,
	}
	if len(products) != 4 || len(exploitabilities) != 4 || len(risks) != 4 {
		t.Fatal("a decision layer lost values, which collapses the three layers")
	}
	for value := range products {
		if exploitabilities[value] {
			t.Errorf("product status %q appears in the exploitability vocabulary", value)
		}
		if risks[value] {
			t.Errorf("product status %q appears in the risk decision vocabulary", value)
		}
	}
	// Layers 2 and 3 share only the unassessed placeholder; sharing any other
	// value would collapse exploitability into risk acceptance.
	shared := map[string]bool{}
	for value := range exploitabilities {
		if risks[value] {
			shared[value] = true
		}
	}
	if len(shared) != 1 || !shared["not_assessed"] {
		t.Fatalf("exploitability and risk decisions must share only the unassessed placeholder, got %v", shared)
	}
}

// TestContainerClassesAreDistinctValues checks the vocabulary; ADR-0006 §7
// fixes which of them are applicable per coverage method.
func TestContainerClassesAreDistinctValues(t *testing.T) {
	classes := []ContainerClass{ContainerRegular, ContainerInit, ContainerEphemeral}
	seen := map[ContainerClass]bool{}
	for _, class := range classes {
		if seen[class] {
			t.Fatalf("container class %q is duplicated", class)
		}
		seen[class] = true
	}
	if len(seen) != 3 {
		t.Fatal("regular, init and ephemeral containers must stay separate")
	}
}
