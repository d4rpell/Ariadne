package collector

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/d4rpell/Ariadne/internal/bundle"
	contract "github.com/d4rpell/Ariadne/pkg/evidence"
)

// Golden cases of the A2-02 plan (handoff §4.8). Every case runs the real path
// acquisition -> projection -> admission -> normalization -> builder -> Encode
// -> Write over buffers, and every expectation is a file of
// internal/collector/testdata/a2_02 whose bytes are reproduced literally.

const a202GoldenRoot = "testdata/a2_02"

// a202GoldenCase is one scripted scenario of the golden corpus.
type a202GoldenCase struct {
	name string
	// responses are the scripted answers in request order.
	responses []a202RoundTrip
	// termination is the effective termination of the run.
	termination contract.CoverageTermination
	// config adjusts the synthetic configuration when the case needs it.
	config func(*Config)
}

// a202GoldenCases is the corpus of §4.8.
func a202GoldenCases(t *testing.T) []a202GoldenCase {
	t.Helper()
	complete := a202JSONResponse(a202Document(a202CompletePod("u1", "n1")))
	get := a202JSONResponse(a202Pod("u1", "n1"))
	page := a202JSONResponse(`{"apiVersion":"v1","kind":"PodList","metadata":{"resourceVersion":"7","continue":"token-2"},"items":[` + a202CompletePod("u1", "n1") + `]}`)
	page2 := a202JSONResponse(`{"apiVersion":"v1","kind":"PodList","metadata":{"resourceVersion":"7"},"items":[` + a202CompletePod("u2", "n2") + `]}`)
	getU1 := a202JSONResponse(a202Pod("u1", "n1"))
	getU2 := a202JSONResponse(a202Pod("u2", "n2"))
	return []a202GoldenCase{
		{name: "complete-three-categories", responses: []a202RoundTrip{complete, get, get}, termination: contract.TerminationFinished},
		{name: "omitted-categories", responses: []a202RoundTrip{a202JSONResponse(a202Document(a202IncompletePod("u1", "n1"))), get, get}, termination: contract.TerminationFinished},
		{name: "paginated-list", responses: []a202RoundTrip{page, page2, getU1, getU2, getU1, getU2}, termination: contract.TerminationFinished},
		{name: "failure-after-page", responses: []a202RoundTrip{page, a202RoundTrip{status: 403, body: "{}"}}, termination: contract.TerminationAborted},
		{name: "list-then-get-forbidden", responses: []a202RoundTrip{complete, a202RoundTrip{status: 403, body: "{}"}}, termination: contract.TerminationAborted},
		{name: "uid-replacement", responses: []a202RoundTrip{complete, a202JSONResponse(a202Pod("u2", "n1")), a202JSONResponse(a202Pod("u2", "n1"))}, termination: contract.TerminationFinished},
		{name: "f07-pattern", responses: []a202RoundTrip{
			complete,
			a202JSONResponse(a202F07Pod("registry.example/app:stable", a202ImageID)),
			a202JSONResponse(a202F07Pod("registry.example/app:stable", a202ImageID)),
		}, termination: contract.TerminationFinished},
		{name: "ephemeral-added", responses: []a202RoundTrip{
			complete,
			a202JSONResponse(a202EphemeralPod(a202ImageID, "")),
			a202JSONResponse(a202EphemeralPod(a202ImageID, "")),
		}, termination: contract.TerminationFinished},
		{name: "cross-class-collision", responses: []a202RoundTrip{a202JSONResponse(a202Document(a202CollisionPod("u1", "n1"))), a202JSONResponse(a202CollisionPod("u1", "n1")), a202JSONResponse(a202CollisionPod("u1", "n1"))}, termination: contract.TerminationFinished},
		{name: "all-images-collided", responses: []a202RoundTrip{a202JSONResponse(a202Document(a202AllCollidedPod("u1", "n1"))), a202JSONResponse(a202AllCollidedPod("u1", "n1")), a202JSONResponse(a202AllCollidedPod("u1", "n1"))}, termination: contract.TerminationFinished},
		{name: "empty-list", responses: []a202RoundTrip{a202JSONResponse(`{"apiVersion":"v1","kind":"PodList","metadata":{"resourceVersion":"7"},"items":[]}`)}, termination: contract.TerminationUnknown},
		{name: "abort-before-subject", responses: []a202RoundTrip{a202RoundTrip{status: 403, body: "{}"}}, termination: contract.TerminationUnknown},
	}
}

// TestA202CollectedGolden reproduces every golden case byte for byte.
func TestA202CollectedGolden(t *testing.T) {
	for _, testCase := range a202GoldenCases(t) {
		t.Run(testCase.name, func(t *testing.T) {
			config := a202Config(t)
			if testCase.config != nil {
				testCase.config(&config)
			}
			transport := newA202ScriptedTransport(testCase.responses...)
			clock := newA202Clock(t, a202StartMoment)
			clock.advance(time.Second)
			result, err := collectWithDependencies(context.Background(), config, transport, clock)
			switch testCase.termination {
			case contract.TerminationFinished:
				if err != nil {
					t.Fatalf("collect: %v", err)
				}
			case contract.TerminationAborted:
				if err == nil {
					t.Fatalf("the case declares an aborted run but collect returned no error")
				}
			case contract.TerminationUnknown:
				// An empty observation or a failure before any identity: the run
				// may end with or without an error, and the termination is what
				// the case pins.
			}
			if result.Acquisition.Termination != testCase.termination {
				t.Fatalf("termination = %q, want %q", result.Acquisition.Termination, testCase.termination)
			}
			// The sanitized sources of the case are reproduced literally.
			caseDir := filepath.Join(a202GoldenRoot, testCase.name)
			for _, capture := range result.Acquisition.Captures {
				path := filepath.Join(caseDir, "sources", capture.Alias)
				want, readErr := os.ReadFile(path)
				if readErr != nil {
					t.Fatalf("read golden source %s: %v", path, readErr)
				}
				if !bytes.Equal(want, capture.Bytes) {
					t.Fatalf("source %s differs from its golden", capture.Alias)
				}
			}
			// One triplet per bundle, selected by capture ordinal and item
			// index, exactly as the corpus organizes them.
			expected := a202GoldenBundles(t, testCase.name)
			if len(result.Bundles) != len(expected) {
				t.Fatalf("bundles = %d, golden triplets = %d", len(result.Bundles), len(expected))
			}
			for _, candidate := range result.Bundles {
				matched := false
				for _, golden := range expected {
					if golden.capture != candidate.CaptureOrdinal || golden.item != candidate.ItemIndex {
						continue
					}
					a202CheckGoldenBundle(t, candidate, golden)
					matched = true
				}
				if !matched {
					t.Fatalf("no golden triplet for capture %d item %d", candidate.CaptureOrdinal, candidate.ItemIndex)
				}
			}
		})
	}
}

// a202GoldenBundle identifies one triplet directory with the selection it
// encodes: the capture ordinal and the original item index.
type a202GoldenBundle struct {
	dir     string
	capture uint64
	item    int
}

// a202GoldenBundles lists the triplet directories of one case with their
// selection parsed from the path.
func a202GoldenBundles(t *testing.T, name string) []a202GoldenBundle {
	t.Helper()
	root := filepath.Join(a202GoldenRoot, name, "bundles")
	entries, err := os.ReadDir(root)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		t.Fatalf("read golden bundles of %s: %v", name, err)
	}
	bundles := []a202GoldenBundle{}
	for _, capture := range entries {
		if !capture.IsDir() {
			continue
		}
		captureOrdinal, ok := a202ParseDirectoryNumber(capture.Name(), "capture-")
		if !ok {
			t.Fatalf("unexpected capture directory %q", capture.Name())
		}
		subjects, err := os.ReadDir(filepath.Join(root, capture.Name()))
		if err != nil {
			t.Fatalf("read items of %s: %v", capture.Name(), err)
		}
		for _, subject := range subjects {
			if !subject.IsDir() {
				continue
			}
			itemIndex, ok := a202ParseDirectoryNumber(subject.Name(), "item-")
			if !ok {
				t.Fatalf("unexpected item directory %q", subject.Name())
			}
			bundles = append(bundles, a202GoldenBundle{
				dir:     filepath.Join(root, capture.Name(), subject.Name()),
				capture: captureOrdinal,
				item:    int(itemIndex),
			})
		}
	}
	return bundles
}

// a202ParseDirectoryNumber reads the decimal ordinal of one synthetic directory
// name with the given prefix.
func a202ParseDirectoryNumber(name, prefix string) (uint64, bool) {
	if !strings.HasPrefix(name, prefix) {
		return 0, false
	}
	digits := strings.TrimPrefix(name, prefix)
	if digits == "" {
		return 0, false
	}
	value := uint64(0)
	for index := 0; index < len(digits); index++ {
		if digits[index] < '0' || digits[index] > '9' {
			return 0, false
		}
		value = value*10 + uint64(digits[index]-'0')
	}
	return value, true
}

// a202CheckGoldenBundle compares one built bundle with its golden triplet and
// proves the hash with an independent oracle.
func a202CheckGoldenBundle(t *testing.T, candidate CollectedBundle, golden a202GoldenBundle) {
	t.Helper()
	artifacts, err := bundle.Encode(candidate.Bundle)
	if err != nil {
		t.Fatalf("encode bundle: %v", err)
	}
	envelopePath := filepath.Join(golden.dir, "bundle.json")
	hashInputPath := filepath.Join(golden.dir, "bundle.hash-input.json")
	digestPath := filepath.Join(golden.dir, "bundle.sha256")
	wantEnvelope, err := os.ReadFile(envelopePath)
	if err != nil {
		t.Fatalf("read golden envelope: %v", err)
	}
	wantHashInput, err := os.ReadFile(hashInputPath)
	if err != nil {
		t.Fatalf("read golden hash input: %v", err)
	}
	wantDigest, err := os.ReadFile(digestPath)
	if err != nil {
		t.Fatalf("read golden digest: %v", err)
	}
	if !bytes.Equal(artifacts.Envelope, wantEnvelope) {
		t.Fatalf("the envelope differs from %s", envelopePath)
	}
	if !bytes.Equal(artifacts.HashInput, wantHashInput) {
		t.Fatalf("the hash input differs from %s", hashInputPath)
	}
	// The digest file is ASCII "sha256:" + 64 hex + LF, and the value is the
	// independent SHA-256 of the projection, not of the envelope.
	wantText := "sha256:" + a202IndependentHashBytes(artifacts.HashInput) + string(rune(10))
	if string(wantDigest) != wantText {
		t.Fatalf("the digest file differs from the independent oracle")
	}
	// The envelope decodes back to the same bundle identity.
	decoded := contract.Bundle{}
	if err := json.Unmarshal(artifacts.Envelope, &decoded); err != nil {
		t.Fatalf("decode envelope: %v", err)
	}
	if decoded.Subject.UID != candidate.Bundle.Subject.UID {
		t.Fatal("the envelope does not carry the built subject")
	}
	// The writer path produces exactly the same bytes through its destinations:
	// the three artefacts of Write are compared byte to byte with the Encode
	// output and with the independent digest, not merely checked for emptiness.
	envelopeSpy := &a202GoldenWriter{}
	hashSpy := &a202GoldenWriter{}
	digestSpy := &a202GoldenWriter{}
	if err := bundle.Write(candidate.Bundle, bundle.Destinations{Envelope: envelopeSpy, HashInput: hashSpy, Hash: digestSpy}); err != nil {
		t.Fatalf("write: %v", err)
	}
	if !bytes.Equal(envelopeSpy.bytes(), artifacts.Envelope) {
		t.Fatal("Write delivered an envelope different from Encode")
	}
	if !bytes.Equal(hashSpy.bytes(), artifacts.HashInput) {
		t.Fatal("Write delivered a projection different from Encode")
	}
	if string(digestSpy.bytes()) != wantText {
		t.Fatal("Write delivered a digest different from the independent recalculation")
	}
}

// a202BuildOne builds one bundle from a single complete Pod through the full
// acquisition path, so the metadata cases of the operational hash start from a
// real projection.
func a202BuildOne(t *testing.T) (contract.Bundle, []byte) {
	t.Helper()
	config := a202Config(t)
	transport := newA202ScriptedTransport(
		a202JSONResponse(a202Document(a202CompletePod("u1", "n1"))),
		a202JSONResponse(a202Pod("u1", "n1")),
		a202JSONResponse(a202Pod("u1", "n1")),
	)
	clock := newA202Clock(t, a202StartMoment)
	clock.advance(time.Second)
	result, err := collectWithDependencies(context.Background(), config, transport, clock)
	if err != nil {
		t.Fatalf("collect: %v", err)
	}
	if len(result.Bundles) == 0 {
		t.Fatal("no bundle was produced")
	}
	artifacts, err := bundle.Encode(result.Bundles[0].Bundle)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	return result.Bundles[0].Bundle, artifacts.HashInput
}

// a202IndependentHashBytes is the raw hexadecimal oracle used by the golden
// digest check.
func a202IndependentHashBytes(data []byte) string {
	digest := sha256.Sum256(data)
	return hex.EncodeToString(digest[:])
}

// a202GoldenWriter records the bytes written to the destination triple.
type a202GoldenWriter struct{ chunks [][]byte }

func (writer *a202GoldenWriter) Write(chunk []byte) (int, error) {
	writer.chunks = append(writer.chunks, append([]byte{}, chunk...))
	return len(chunk), nil
}

// bytes joins every written chunk into the exact delivered value.
func (writer *a202GoldenWriter) bytes() []byte {
	joined := []byte{}
	for _, chunk := range writer.chunks {
		joined = append(joined, chunk...)
	}
	return joined
}

// TestA202SanitizedSourceGolden proves the source format contract: compact,
// fixed key order, no BOM and no trailing newline.
func TestA202SanitizedSourceGolden(t *testing.T) {
	for _, testCase := range a202GoldenCases(t) {
		t.Run(testCase.name, func(t *testing.T) {
			config := a202Config(t)
			if testCase.config != nil {
				testCase.config(&config)
			}
			transport := newA202ScriptedTransport(testCase.responses...)
			clock := newA202Clock(t, a202StartMoment)
			clock.advance(time.Second)
			result, _ := collectWithDependencies(context.Background(), config, transport, clock)
			for _, capture := range result.Acquisition.Captures {
				source := capture.Bytes
				if len(source) == 0 {
					t.Fatal("an admitted capture carries no bytes")
				}
				if bytes.HasPrefix(source, []byte{0xEF, 0xBB, 0xBF}) {
					t.Fatal("the source carries a BOM")
				}
				if bytes.HasSuffix(source, []byte("\n")) {
					t.Fatal("the source carries a trailing newline")
				}
				if !json.Valid(source) {
					t.Fatal("the source is not valid JSON")
				}
				if strings.Contains(string(source), `"continue"`) || strings.Contains(string(source), `"remainingItemCount"`) {
					t.Fatal("the source kept an operational list member")
				}
				if capture.Hash != bundle.HashSource(source) {
					t.Fatal("the source hash does not describe the source bytes")
				}
				if !strings.HasPrefix(string(capture.Hash), "sha256:") {
					t.Fatalf("hash = %q", capture.Hash)
				}
			}
		})
	}
}

// TestA202CollectedCanonicalProjection rebuilds the projection from the golden
// envelope with the test's own ordered structs and rehashes it independently:
// the oracle never trusts the stored projection nor delegates the section order
// to the production helper.
func TestA202CollectedCanonicalProjection(t *testing.T) {
	for _, testCase := range a202GoldenCases(t) {
		t.Run(testCase.name, func(t *testing.T) {
			for _, golden := range a202GoldenBundles(t, testCase.name) {
				envelope, err := os.ReadFile(filepath.Join(golden.dir, "bundle.json"))
				if err != nil {
					t.Fatalf("read envelope: %v", err)
				}
				decoded := contract.Bundle{}
				if err := json.Unmarshal(envelope, &decoded); err != nil {
					t.Fatalf("decode envelope: %v", err)
				}
				hashInput, err := os.ReadFile(filepath.Join(golden.dir, "bundle.hash-input.json"))
				if err != nil {
					t.Fatalf("read hash input: %v", err)
				}
				// The preimage is rebuilt from the envelope by this test's own
				// ordered structs: the delivered projection must be exactly the
				// document the envelope implies, section order included.
				rebuilt, err := a202RebuildHashProjection(envelope)
				if err != nil {
					t.Fatalf("rebuild the projection from the envelope: %v", err)
				}
				if !bytes.Equal(rebuilt, hashInput) {
					t.Fatalf("the delivered projection is not the reconstruction from the delivered envelope")
				}
				digest, err := os.ReadFile(filepath.Join(golden.dir, "bundle.sha256"))
				if err != nil {
					t.Fatalf("read digest: %v", err)
				}
				// The digest is the independent SHA-256 of the reconstructed
				// preimage, never a value read from the producer.
				want := "sha256:" + a202IndependentHashBytes(rebuilt) + string(rune(10))
				if string(digest) != want {
					t.Fatalf("the digest is not the independent hash of the reconstructed projection")
				}
				if decoded.SchemaVersion != "0.2" {
					t.Fatalf("schema version = %q", decoded.SchemaVersion)
				}
			}
		})
	}
}

// a202RebuildHashProjection reconstructs the ADR-0006 §1(a) projection from the
// canonical envelope with the test's own ordered structs: the section order and
// the ruleset reduction to path/hash are declared here, not read from the
// delivered artifact nor delegated to the production helper.
func a202RebuildHashProjection(envelope []byte) ([]byte, error) {
	type rulesetSections struct {
		Path json.RawMessage `json:"path"`
		Hash json.RawMessage `json:"hash"`
	}
	type projectedProvenance struct {
		Ruleset         json.RawMessage `json:"ruleset"`
		Inputs          json.RawMessage `json:"inputs"`
		APIScope        json.RawMessage `json:"api_scope"`
		Coverage        json.RawMessage `json:"coverage"`
		Completeness    json.RawMessage `json:"completeness"`
		Consistency     json.RawMessage `json:"consistency"`
		RedactionPolicy json.RawMessage `json:"redaction_policy"`
		Warnings        json.RawMessage `json:"warnings"`
		Errors          json.RawMessage `json:"errors"`
	}
	type projection struct {
		SchemaVersion            json.RawMessage     `json:"schema_version"`
		Subject                  json.RawMessage     `json:"subject"`
		Images                   json.RawMessage     `json:"images"`
		Evidence                 json.RawMessage     `json:"evidence"`
		ObservedContainerClasses json.RawMessage     `json:"observed_container_classes"`
		Provenance               projectedProvenance `json:"provenance"`
	}
	type envelopeSections struct {
		SchemaVersion            json.RawMessage `json:"schema_version"`
		Subject                  json.RawMessage `json:"subject"`
		Images                   json.RawMessage `json:"images"`
		Evidence                 json.RawMessage `json:"evidence"`
		ObservedContainerClasses json.RawMessage `json:"observed_container_classes"`
		Provenance               struct {
			Ruleset json.RawMessage `json:"ruleset"`
			projectedProvenance
		} `json:"provenance"`
	}

	var full envelopeSections
	if err := json.Unmarshal(envelope, &full); err != nil {
		return nil, err
	}
	rulesetJSON := json.RawMessage("null")
	if string(full.Provenance.Ruleset) != "null" && len(full.Provenance.Ruleset) != 0 {
		var sections rulesetSections
		if err := json.Unmarshal(full.Provenance.Ruleset, &sections); err != nil {
			return nil, err
		}
		built, err := json.Marshal(sections)
		if err != nil {
			return nil, err
		}
		rulesetJSON = built
	}
	document := projection{
		SchemaVersion:            full.SchemaVersion,
		Subject:                  full.Subject,
		Images:                   full.Images,
		Evidence:                 full.Evidence,
		ObservedContainerClasses: full.ObservedContainerClasses,
		Provenance: projectedProvenance{
			Ruleset:         rulesetJSON,
			Inputs:          full.Provenance.Inputs,
			APIScope:        full.Provenance.APIScope,
			Coverage:        full.Provenance.Coverage,
			Completeness:    full.Provenance.Completeness,
			Consistency:     full.Provenance.Consistency,
			RedactionPolicy: full.Provenance.RedactionPolicy,
			Warnings:        full.Provenance.Warnings,
			Errors:          full.Provenance.Errors,
		},
	}
	var buffer bytes.Buffer
	encoder := json.NewEncoder(&buffer)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(document); err != nil {
		return nil, err
	}
	return bytes.TrimSuffix(buffer.Bytes(), []byte("\n")), nil
}

// TestA202CollectedHash proves that the source hash covers all the admitted
// bytes and that the value hash covers the decoded value.
func TestA202CollectedHash(t *testing.T) {
	for _, testCase := range a202GoldenCases(t) {
		t.Run(testCase.name, func(t *testing.T) {
			config := a202Config(t)
			if testCase.config != nil {
				testCase.config(&config)
			}
			transport := newA202ScriptedTransport(testCase.responses...)
			clock := newA202Clock(t, a202StartMoment)
			clock.advance(time.Second)
			result, _ := collectWithDependencies(context.Background(), config, transport, clock)
			for _, candidate := range result.Bundles {
				for _, item := range candidate.Bundle.Evidence {
					if item.Value == nil {
						continue
					}
					want := "sha256:" + a202IndependentHashBytes([]byte(*item.Value))
					if item.ValueHash == nil || string(*item.ValueHash) != want {
						t.Fatalf("value hash is not the independent SHA-256 of the decoded value")
					}
				}
				for _, input := range candidate.Bundle.Provenance.Inputs {
					found := false
					for _, capture := range result.Acquisition.Captures {
						if capture.Alias == input.Path && capture.Hash == input.Hash {
							found = true
						}
					}
					if !found {
						t.Fatalf("input %s does not correspond to an admitted capture", input.Path)
					}
				}
			}
		})
	}
}

// TestA202CollectedDeterminism repeats one script with a fixed clock: the same
// input must produce the same bytes.
func TestA202CollectedDeterminism(t *testing.T) {
	for _, testCase := range a202GoldenCases(t) {
		t.Run(testCase.name, func(t *testing.T) {
			run := func() []contract.Bundle {
				config := a202Config(t)
				if testCase.config != nil {
					testCase.config(&config)
				}
				transport := newA202ScriptedTransport(testCase.responses...)
				clock := newA202Clock(t, a202StartMoment)
				clock.advance(time.Second)
				result, _ := collectWithDependencies(context.Background(), config, transport, clock)
				bundles := make([]contract.Bundle, 0, len(result.Bundles))
				for _, candidate := range result.Bundles {
					bundles = append(bundles, candidate.Bundle)
				}
				return bundles
			}
			first := run()
			second := run()
			if len(first) != len(second) {
				t.Fatalf("bundle counts differ between runs")
			}
			for index := range first {
				left, err := bundle.Encode(first[index])
				if err != nil {
					t.Fatalf("encode first: %v", err)
				}
				right, err := bundle.Encode(second[index])
				if err != nil {
					t.Fatalf("encode second: %v", err)
				}
				if !bytes.Equal(left.Envelope, right.Envelope) {
					t.Fatal("two identical runs produced different envelopes")
				}
				if !bytes.Equal(left.HashInput, right.HashInput) {
					t.Fatal("two identical runs produced different projections")
				}
			}
		})
	}
}

// TestA202OperationalMetadataHash varies each operational metadata field and
// proves which of them the projection hash covers: §1(a) of ADR-0006 excludes
// the versions, the run window and the budget, and protects the source, the
// observation instant, the api scope, the termination, the policy, the
// warnings and the errors.
func TestA202OperationalMetadataHash(t *testing.T) {
	// excluded cases keep the projection hash; protected cases change it.
	excluded := map[string]func(*contract.Bundle){
		"collector_version": func(built *contract.Bundle) { built.Provenance.CollectorVersion = "ariadne-collector/other" },
		"parser_version":    func(built *contract.Bundle) { built.Provenance.ParserVersion = "sanitized-podlist-v1/2.0" },
		"run_started_at": func(built *contract.Bundle) {
			shifted := *built.Provenance.StartedAt
			shifted.Time = shifted.Time.Add(-time.Hour)
			built.Provenance.StartedAt = &shifted
		},
		"run_ended_at": func(built *contract.Bundle) {
			shifted := *built.Provenance.EndedAt
			shifted.Time = shifted.Time.Add(time.Hour)
			built.Provenance.EndedAt = &shifted
		},
		"budget": func(built *contract.Bundle) { built.Provenance.Budget.Requests = 7 },
	}
	for name, mutate := range excluded {
		t.Run(name, func(t *testing.T) {
			built, before := a202BuildOne(t)
			mutate(&built)
			artifacts, err := bundle.Encode(built)
			if err != nil {
				t.Fatalf("encode: %v", err)
			}
			if !bytes.Equal(before, artifacts.HashInput) {
				t.Fatalf("%s changed the projection hash although it is excluded from it", name)
			}
		})
	}
	protected := map[string]struct {
		mutate func(*contract.Bundle)
		valid  bool
	}{
		"source": {func(built *contract.Bundle) {
			built.Evidence[0].Source = "capture-000002.json"
		}, true},
		"observed_at": {func(built *contract.Bundle) {
			shifted := *built.Evidence[0].ObservedAt
			shifted.Time = shifted.Time.Add(-time.Minute)
			built.Evidence[0].ObservedAt = &shifted
		}, true},
		"api_scope": {func(built *contract.Bundle) {
			built.Provenance.APIScope.Namespaces = []contract.Namespace{"other"}
		}, true},
		"termination": {func(built *contract.Bundle) {
			built.Provenance.Coverage.Termination = contract.TerminationAborted
			built.Provenance.Completeness = contract.CompletenessPartial
			built.Provenance.Errors = []string{"collector: forbidden"}
		}, true},
		"redaction_policy": {func(built *contract.Bundle) {
			built.Provenance.RedactionPolicy = "other-policy/1.0"
		}, true},
		"warnings": {func(built *contract.Bundle) {
			built.Provenance.Warnings = append(built.Provenance.Warnings, contract.Warning{
				Code:    "tool_failure",
				Class:   contract.WarningContradictory,
				Message: "collector acquisition did not complete",
			})
		}, true},
		"errors": {func(built *contract.Bundle) {
			built.Provenance.Completeness = contract.CompletenessPartial
			built.Provenance.Errors = append(built.Provenance.Errors, "ingest: sanitized-podlist-v1: byte/0: source contains rejected Pod items")
		}, true},
	}
	for name, testCase := range protected {
		t.Run(name, func(t *testing.T) {
			built, before := a202BuildOne(t)
			testCase.mutate(&built)
			artifacts, err := bundle.Encode(built)
			if testCase.valid && err != nil {
				t.Fatalf("encode: %v", err)
			}
			if testCase.valid && bytes.Equal(before, artifacts.HashInput) {
				t.Fatalf("%s did not change the projection hash although it is protected by it", name)
			}
		})
	}
}
