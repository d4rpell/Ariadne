package bundle

import (
	"encoding/json"
	"strings"
	"testing"

	canonical "github.com/d4rpell/Ariadne/internal/evidence"
	"github.com/d4rpell/Ariadne/internal/normalize"
	contract "github.com/d4rpell/Ariadne/pkg/evidence"
)

type recordingWriter struct {
	data      []byte
	failWith  error
	shortBy   int
	callCount int
}

func (w *recordingWriter) Write(data []byte) (int, error) {
	w.callCount++
	if w.failWith != nil {
		return 0, w.failWith
	}
	if w.shortBy > 0 && w.shortBy < len(data) {
		w.data = append(w.data, data[:len(data)-w.shortBy]...)
		return len(data) - w.shortBy, nil
	}
	w.data = append(w.data, data...)
	return len(data), nil
}

func fixtureBundle(t *testing.T, rows int) contract.Bundle {
	t.Helper()
	csv := csvFromRows(
		csvRowFor("CVE-2024-1234", "payments/api", "release"),
		csvRowFor("CVE-2024-5678", "payments/worker", "release"),
		csvRowFor("CVE-2024-9999", "payments/api", "canary"),
	)
	bindings := []normalize.Binding{
		testBinding(t, 0, contract.UID("pod-uid-1"), contract.ContainerRegular, contract.ContainerName("api")),
		testBinding(t, 1, contract.UID("pod-uid-1"), contract.ContainerRegular, contract.ContainerName("worker")),
		testBinding(t, 2, contract.UID("pod-uid-1"), contract.ContainerRegular, contract.ContainerName("api")),
	}
	input := testInput(t, csv, bindings[:rows])
	bundle, _ := buildForTest(t, input)
	return bundle
}

// cloneBundle detaches every slice and pointer a mutation could reach, so one
// subtest cannot corrupt the shared fixture.
func cloneBundle(bundle contract.Bundle) contract.Bundle {
	cloned := bundle
	cloned.Images = append([]contract.ImageIdentity{}, bundle.Images...)
	for index := range cloned.Images {
		image := cloned.Images[index]
		image.RequestedImage = copyPointer(image.RequestedImage)
		image.RawImageID = copyPointer(image.RawImageID)
		image.NormalizedDigest = copyPointer(image.NormalizedDigest)
		image.ObservedAt = copyPointer(image.ObservedAt)
		cloned.Images[index] = image
	}
	cloned.Evidence = append([]contract.EvidenceItem{}, bundle.Evidence...)
	for index := range cloned.Evidence {
		item := cloned.Evidence[index]
		item.Value = copyPointer(item.Value)
		item.ValueHash = copyPointer(item.ValueHash)
		item.ObservedAt = copyPointer(item.ObservedAt)
		item.Warnings = append([]contract.Warning{}, item.Warnings...)
		cloned.Evidence[index] = item
	}
	cloned.ObservedContainerClasses = append([]contract.ContainerClass{}, bundle.ObservedContainerClasses...)
	cloned.Provenance.ArgvSanitized = append([]string{}, bundle.Provenance.ArgvSanitized...)
	cloned.Provenance.Inputs = append([]contract.InputRef{}, bundle.Provenance.Inputs...)
	cloned.Provenance.APIScope = contract.APIScope{
		Namespaces: append([]contract.Namespace{}, bundle.Provenance.APIScope.Namespaces...),
		Verbs:      append([]string{}, bundle.Provenance.APIScope.Verbs...),
		Resources:  append([]string{}, bundle.Provenance.APIScope.Resources...),
	}
	cloned.Provenance.Warnings = append([]contract.Warning{}, bundle.Provenance.Warnings...)
	cloned.Provenance.Errors = append([]string{}, bundle.Provenance.Errors...)
	cloned.Provenance.StartedAt = copyPointer(bundle.Provenance.StartedAt)
	cloned.Provenance.EndedAt = copyPointer(bundle.Provenance.EndedAt)
	if bundle.Provenance.Coverage.Rows != nil {
		rows := *bundle.Provenance.Coverage.Rows
		if bundle.Provenance.Coverage.Rows.Total != nil {
			total := *bundle.Provenance.Coverage.Rows.Total
			rows.Total = &total
		}
		cloned.Provenance.Coverage.Rows = &rows
	}
	return cloned
}

func projectionSectionsOf(t *testing.T, document []byte) map[string]json.RawMessage {
	t.Helper()
	var sections map[string]json.RawMessage
	if err := json.Unmarshal(document, &sections); err != nil {
		t.Fatalf("decode document: %v", err)
	}
	return sections
}

func TestEncodeMatchesFrozenDocuments(t *testing.T) {
	bundle := fixtureBundle(t, 3)
	artifacts, err := Encode(bundle)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	envelope, err := canonical.CanonicalJSON(bundle)
	if err != nil {
		t.Fatalf("canonical json: %v", err)
	}
	hash, err := canonical.HashCanonicalJSON(bundle)
	if err != nil {
		t.Fatalf("canonical hash: %v", err)
	}
	if string(artifacts.Envelope) != string(envelope) {
		t.Fatal("the envelope artifact is not the frozen canonical envelope")
	}
	if artifacts.Hash != hash {
		t.Fatalf("hash = %q, want %q", artifacts.Hash, hash)
	}
	if computed := HashSource(artifacts.HashInput); string(computed) != artifacts.Hash {
		t.Fatal("the delivered digest does not cover the delivered projection")
	}
	for name, document := range map[string][]byte{"envelope": artifacts.Envelope, "projection": artifacts.HashInput} {
		if strings.HasPrefix(string(document), "\ufeff") {
			t.Fatalf("%s carries a BOM", name)
		}
		if strings.HasSuffix(string(document), "\n") {
			t.Fatalf("%s carries a trailing newline", name)
		}
	}
	if string(artifacts.HashInput) == string(artifacts.Envelope) {
		t.Fatal("the projection and the envelope must be different documents")
	}
	if !strings.HasPrefix(string(artifacts.HashInput), `{"schema_version":`) {
		t.Fatalf("projection starts with %q", string(artifacts.HashInput)[:20])
	}
}

func TestEncodeProjectionIsEnvelopeSelection(t *testing.T) {
	bundle := fixtureBundle(t, 2)
	artifacts, err := Encode(bundle)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	envelope := projectionSectionsOf(t, artifacts.Envelope)
	projection := projectionSectionsOf(t, artifacts.HashInput)

	for _, shared := range []string{"schema_version", "subject", "images", "evidence", "observed_container_classes"} {
		if string(projection[shared]) != string(envelope[shared]) {
			t.Fatalf("projection section %q differs from the envelope", shared)
		}
	}
	if len(projection) != 6 {
		t.Fatalf("projection keys = %d", len(projection))
	}
	run := projectionSectionsOf(t, projection["provenance"])
	envelopeRun := projectionSectionsOf(t, envelope["provenance"])
	covered := []string{"ruleset", "inputs", "api_scope", "coverage", "completeness", "consistency", "redaction_policy", "warnings", "errors"}
	if len(run) != len(covered) {
		t.Fatalf("projected provenance keys = %d, want %d", len(run), len(covered))
	}
	for _, key := range covered {
		if _, ok := run[key]; !ok {
			t.Fatalf("projected provenance misses %q", key)
		}
		if string(run[key]) != string(envelopeRun[key]) {
			t.Fatalf("projected %q differs from the envelope", key)
		}
	}
	for _, excluded := range []string{"collector_version", "parser_version", "argv_sanitized", "started_at", "ended_at", "budget"} {
		if _, ok := run[excluded]; ok {
			t.Fatalf("projected provenance carries excluded key %q", excluded)
		}
	}
	if string(run["ruleset"]) != "null" {
		t.Fatalf("ruleset = %s, want null for a findings import", run["ruleset"])
	}

	document := string(artifacts.HashInput)
	previous := -1
	for _, key := range []string{"schema_version", "subject", "images", "evidence", "observed_container_classes", "provenance"} {
		index := strings.Index(document, `"`+key+`"`)
		if index < 0 {
			t.Fatalf("key %q missing from the projection", key)
		}
		if index <= previous {
			t.Fatalf("top-level key %q is out of canonical order", key)
		}
		previous = index
	}
	provenance := document[strings.Index(document, `"provenance"`):]
	previous = -1
	for _, key := range covered {
		index := strings.Index(provenance, `"`+key+`"`)
		if index < 0 {
			t.Fatalf("key %q missing from the projected provenance", key)
		}
		if index <= previous {
			t.Fatalf("provenance key %q is out of canonical order", key)
		}
		previous = index
	}
}

func TestEncodeRulesetProjectionDropsVersion(t *testing.T) {
	bundle := fixtureBundle(t, 1)
	bundle.Provenance.Ruleset = contract.RulesetRef{Path: "rules/", Hash: contract.SourceHash(testDigest("d")), Version: "2026-09"}

	artifacts, err := Encode(bundle)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	expected := `"ruleset":{"path":"rules/","hash":"` + testDigest("d") + `"}`
	if !strings.Contains(string(artifacts.HashInput), expected) {
		t.Fatalf("projected ruleset = %s", string(artifacts.HashInput))
	}
	if strings.Contains(string(artifacts.HashInput), `"version"`) {
		t.Fatal("the operational ruleset version is covered by the hash")
	}
	if !strings.Contains(string(artifacts.Envelope), `"version":"2026-09"`) {
		t.Fatal("the envelope keeps the operational ruleset version")
	}

	changed := cloneBundle(bundle)
	changed.Provenance.Ruleset.Version = "2027-01"
	moved, err := Encode(changed)
	if err != nil {
		t.Fatalf("encode changed: %v", err)
	}
	if moved.Hash != artifacts.Hash {
		t.Fatal("changing only the ruleset version changed the hash")
	}
	if string(moved.Envelope) == string(artifacts.Envelope) {
		t.Fatal("the envelope must keep the operational metadata")
	}
}

func TestEncodeHashCoversClaimsAndExcludesMetadata(t *testing.T) {
	base := fixtureBundle(t, 2)
	baseArtifacts, err := Encode(base)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}

	excluded := map[string]func(bundle *contract.Bundle){
		"collector version": func(bundle *contract.Bundle) { bundle.Provenance.CollectorVersion = "9.9.9" },
		"parser version":    func(bundle *contract.Bundle) { bundle.Provenance.ParserVersion = "prisma-v1.9" },
		"argv order": func(bundle *contract.Bundle) {
			bundle.Provenance.ArgvSanitized = reverseCopy(bundle.Provenance.ArgvSanitized)
		},
		"started at": func(bundle *contract.Bundle) { bundle.Provenance.StartedAt = testTimestamp(t, "2026-09-26T08:00:00Z") },
		"budget":     func(bundle *contract.Bundle) { bundle.Provenance.Budget.Bytes = 999999 },
	}
	for name, mutate := range excluded {
		t.Run("excluded: "+name, func(t *testing.T) {
			changed := cloneBundle(base)
			mutate(&changed)
			artifacts, err := Encode(changed)
			if err != nil {
				t.Fatalf("encode: %v", err)
			}
			if artifacts.Hash != baseArtifacts.Hash {
				t.Fatalf("hash changed with operational metadata %q", name)
			}
			if string(artifacts.Envelope) == string(baseArtifacts.Envelope) {
				t.Fatalf("the envelope did not change for %q", name)
			}
		})
	}

	covered := map[string]func(bundle *contract.Bundle){
		"consistency": func(bundle *contract.Bundle) { bundle.Provenance.Consistency = contract.ConsistencyNotAtomic },
		"redaction":   func(bundle *contract.Bundle) { bundle.Provenance.RedactionPolicy = "default-v2" },
		"warning": func(bundle *contract.Bundle) {
			bundle.Provenance.Warnings = append(bundle.Provenance.Warnings, contract.Warning{Code: "tool_failure", Class: contract.WarningInformational, Message: "retried"})
		},
		"observed at": func(bundle *contract.Bundle) { bundle.Images[0].ObservedAt = testTimestamp(t, "2026-09-26T07:00:00Z") },
		"value hash": func(bundle *contract.Bundle) {
			hash := contract.ValueHash(testDigest("e"))
			bundle.Evidence[0].ValueHash = &hash
		},
		"image tag": func(bundle *contract.Bundle) {
			renamed := contract.RequestedImage("registry.example/payments/api:renamed")
			bundle.Images[0].RequestedImage = &renamed
		},
		"evidence value": func(bundle *contract.Bundle) {
			value := "changed"
			bundle.Evidence[0].Value = &value
			hash := HashValue(value)
			bundle.Evidence[0].ValueHash = &hash
		},
	}
	for name, mutate := range covered {
		t.Run("covered: "+name, func(t *testing.T) {
			changed := cloneBundle(base)
			mutate(&changed)
			artifacts, err := Encode(changed)
			if err != nil {
				t.Fatalf("encode: %v", err)
			}
			if artifacts.Hash == baseArtifacts.Hash {
				t.Fatalf("hash did not change with covered claim %q", name)
			}
		})
	}
}

func TestEncodePermutationInvariantPreservesDuplicates(t *testing.T) {
	bundle := fixtureBundle(t, 3)
	bundle.Provenance.Warnings = append(bundle.Provenance.Warnings,
		contract.Warning{Code: "redaction_applied", Class: contract.WarningInformational, Message: "policy applied"},
		contract.Warning{Code: "tool_failure", Class: contract.WarningInformational, Message: "retried"},
	)
	base, err := Encode(bundle)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}

	changed := cloneBundle(bundle)
	reverse(changed.Images)
	reverse(changed.Evidence)
	reverse(changed.Provenance.Warnings)
	reverse(changed.Provenance.Inputs)
	if len(changed.Evidence) != len(bundle.Evidence) {
		t.Fatal("permutation must not drop evidence")
	}
	permuted, err := Encode(changed)
	if err != nil {
		t.Fatalf("encode permuted: %v", err)
	}
	if string(permuted.Envelope) != string(base.Envelope) || permuted.Hash != base.Hash {
		t.Fatal("collection order changed the canonical bytes")
	}

	ordered := bundle
	ordered.Provenance.ArgvSanitized = reverseCopy(bundle.Provenance.ArgvSanitized)
	reordered, err := Encode(ordered)
	if err != nil {
		t.Fatalf("encode reordered argv: %v", err)
	}
	if reordered.Hash != base.Hash {
		t.Fatal("argv order must not change the hash")
	}
	if string(reordered.Envelope) == string(base.Envelope) {
		t.Fatal("argv order must be preserved in the envelope")
	}
	document := string(reordered.Envelope)
	reversedIndex := strings.Index(document, `"prisma-v1"`)
	originalIndex := strings.Index(document, `"import"`)
	if reversedIndex < 0 || originalIndex < 0 || reversedIndex > originalIndex {
		t.Fatal("argv_sanitized did not preserve the supplied order")
	}
}

func TestEncodeRejectsInvalidBundle(t *testing.T) {
	valid := fixtureBundle(t, 1)
	cases := map[string]func(bundle *contract.Bundle){
		"nil evidence":         func(bundle *contract.Bundle) { bundle.Evidence = nil },
		"nil images":           func(bundle *contract.Bundle) { bundle.Images = nil },
		"csv schema version":   func(bundle *contract.Bundle) { bundle.SchemaVersion = "1.0" },
		"unknown completeness": func(bundle *contract.Bundle) { bundle.Provenance.Completeness = "invented" },
		"nil warnings":         func(bundle *contract.Bundle) { bundle.Provenance.Warnings = nil },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			bundle := cloneBundle(valid)
			mutate(&bundle)
			artifacts, err := Encode(bundle)
			if err == nil {
				t.Fatal("an invalid bundle produced artifacts")
			}
			if artifacts.Envelope != nil || artifacts.HashInput != nil || artifacts.Hash != "" {
				t.Fatal("a failed encode returned bytes or a hash")
			}
		})
	}
}

func TestWritePrevalidatesAllArtifacts(t *testing.T) {
	invalid := fixtureBundle(t, 1)
	invalid.Evidence = nil
	envelope := &recordingWriter{}
	hashInput := &recordingWriter{}
	hash := &recordingWriter{}
	err := Write(invalid, Destinations{Envelope: envelope, HashInput: hashInput, Hash: hash})
	if err == nil {
		t.Fatal("an invalid bundle must not be transported")
	}
	if envelope.callCount != 0 || hashInput.callCount != 0 || hash.callCount != 0 {
		t.Fatal("an artifact was written for an invalid bundle")
	}
}

func TestWriteDeliversExactBytes(t *testing.T) {
	bundle := fixtureBundle(t, 1)
	artifacts, err := Encode(bundle)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	envelope := &recordingWriter{}
	hashInput := &recordingWriter{}
	hash := &recordingWriter{}
	if err := Write(bundle, Destinations{Envelope: envelope, HashInput: hashInput, Hash: hash}); err != nil {
		t.Fatalf("write: %v", err)
	}
	if string(envelope.data) != string(artifacts.Envelope) {
		t.Fatal("envelope bytes differ from the artifact")
	}
	if string(hashInput.data) != string(artifacts.HashInput) {
		t.Fatal("projection bytes differ from the artifact")
	}
	if string(hash.data) != artifacts.Hash+"\n" {
		t.Fatalf("hash sidecar = %q, want the digest plus one LF", hash.data)
	}
	if strings.Count(string(hash.data), "\n") != 1 {
		t.Fatal("the hash sidecar must carry exactly one LF")
	}
}

func TestWriteDetectsTransportFailure(t *testing.T) {
	bundle := fixtureBundle(t, 1)
	if err := Write(bundle, Destinations{Envelope: &recordingWriter{}, HashInput: &recordingWriter{}}); err == nil {
		t.Fatal("a missing destination must be refused")
	}

	failing := &recordingWriter{failWith: errTransportFailed}
	err := Write(bundle, Destinations{Envelope: &recordingWriter{}, HashInput: failing, Hash: &recordingWriter{}})
	if err == nil || !strings.Contains(err.Error(), "hash input") {
		t.Fatalf("transport failure = %v, want the failing artifact named", err)
	}
	if strings.Contains(err.Error(), errTransportFailed.Error()) == false {
		t.Fatalf("transport failure = %v, want the static reason", err)
	}

	short := &recordingWriter{shortBy: 1}
	err = Write(bundle, Destinations{Envelope: short, HashInput: &recordingWriter{}, Hash: &recordingWriter{}})
	if err == nil || !strings.Contains(err.Error(), "envelope") {
		t.Fatalf("short write = %v, want the affected artifact named", err)
	}
}

func TestWriteRejectsTypedNilDestination(t *testing.T) {
	bundle := fixtureBundle(t, 1)
	var typedNil *recordingWriter
	err := Write(bundle, Destinations{Envelope: typedNil, HashInput: &recordingWriter{}, Hash: &recordingWriter{}})
	if err == nil {
		t.Fatal("a typed nil destination must be refused instead of panicking")
	}
}

func TestWriteFailsOnHashSidecar(t *testing.T) {
	bundle := fixtureBundle(t, 1)
	envelope := &recordingWriter{}
	hashInput := &recordingWriter{}
	err := Write(bundle, Destinations{Envelope: envelope, HashInput: hashInput, Hash: &recordingWriter{failWith: errTransportFailed}})
	if err == nil || !strings.Contains(err.Error(), "hash") {
		t.Fatalf("hash sidecar failure = %v, want the failing artifact named", err)
	}
	// Transport is not atomic and does not claim to be: the earlier artifacts
	// may already be out, which is why the failure is reported as incomplete.
	if len(envelope.data) == 0 || len(hashInput.data) == 0 {
		t.Fatal("the fixture did not exercise a partial delivery")
	}
}

func reverse[T any](values []T) {
	for left, right := 0, len(values)-1; left < right; left, right = left+1, right-1 {
		values[left], values[right] = values[right], values[left]
	}
}

func reverseCopy[T any](values []T) []T {
	copied := append([]T{}, values...)
	reverse(copied)
	return copied
}
