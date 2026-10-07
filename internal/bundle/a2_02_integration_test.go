package bundle_test

import (
	"bytes"
	"strings"
	"testing"

	"github.com/d4rpell/Ariadne/internal/bundle"
	"github.com/d4rpell/Ariadne/internal/evaluator"
	contract "github.com/d4rpell/Ariadne/pkg/evidence"
)

// Integration and hashing cases of the A2-02 plan (handoff §4.5): the sources,
// the values, the capture provenance, the propagation of a global failure and
// the publication boundary.

func TestA202SourceAndValueHash(t *testing.T) {
	t.Run("whole_sanitized_source", func(t *testing.T) {
		source := a202BuildSource(t, a202Document(a202Pod("u1", "n1")), "capture-000001.json", contract.TerminationFinished)
		acquisition := a202Acquisition(t, []a202Source{source}, contract.TerminationFinished, nil)
		built, _, err := bundle.BuildCollectedObservation(a202Input(acquisition, 1, 0))
		if err != nil {
			t.Fatalf("build: %v", err)
		}
		want := a202IndependentHash(source.Bytes)
		if string(built.Evidence[0].SourceHash) != want {
			t.Fatalf("source hash = %q, want %q", built.Evidence[0].SourceHash, want)
		}
	})
	t.Run("raw_api_hash_is_different", func(t *testing.T) {
		// The source hash covers exactly the retained sanitized bytes: for the
		// same Pod, a raw API response with extra discarded content (a marker in
		// a field the projection removes) hashes differently from the source.
		raw := `{"apiVersion":"v1","kind":"PodList","metadata":{"resourceVersion":"100"},"items":[` + a202Pod("u1", "n1") + `]}`
		rawWithExtra := strings.Replace(raw, `"metadata":{"uid":"u1"`, `"metadata":{"annotations":{"x":"`+a202Image+`"},"uid":"u1"`, 1)
		if a202IndependentHash([]byte(raw)) == a202IndependentHash([]byte(rawWithExtra)) {
			t.Fatal("the fixture does not differ")
		}
		source := a202BuildSource(t, raw, "capture-000001.json", contract.TerminationFinished)
		acquisition := a202Acquisition(t, []a202Source{source}, contract.TerminationFinished, nil)
		built, _, err := bundle.BuildCollectedObservation(a202Input(acquisition, 1, 0))
		if err != nil {
			t.Fatalf("build: %v", err)
		}
		if string(built.Evidence[0].SourceHash) == a202IndependentHash([]byte(rawWithExtra)) {
			t.Fatal("the source hash describes a document that was not admitted")
		}
		if string(built.Evidence[0].SourceHash) != a202IndependentHash([]byte(raw)) {
			t.Fatal("the source hash does not describe the admitted bytes")
		}
	})
	t.Run("rejected_items_remain_in_source_hash", func(t *testing.T) {
		// A source with one accepted and one rejected Pod keeps its hash over
		// every byte of the document.
		document := a202Document(a202Pod("u1", "n1"), a202RejectedPeerDocument())
		source := a202BuildSource(t, document, "capture-000001.json", contract.TerminationFinished)
		if source.Observation.RejectedItems == 0 {
			t.Fatal("the fixture did not produce a rejected item")
		}
		acquisition := a202Acquisition(t, []a202Source{source}, contract.TerminationFinished, nil)
		built, _, err := bundle.BuildCollectedObservation(a202Input(acquisition, 1, 0))
		if err != nil {
			t.Fatalf("build: %v", err)
		}
		if string(built.Evidence[0].SourceHash) != a202IndependentHash([]byte(document)) {
			t.Fatal("the source hash does not cover the whole admitted document")
		}
	})
	t.Run("decoded_utf8_value", func(t *testing.T) {
		value := "sha256:" + strings.Repeat("a", 64)
		want := a202IndependentHash([]byte(value))
		source := a202BuildSource(t, a202Document(a202Pod("u1", "n1")), "capture-000001.json", contract.TerminationFinished)
		acquisition := a202Acquisition(t, []a202Source{source}, contract.TerminationFinished, nil)
		built, _, err := bundle.BuildCollectedObservation(a202Input(acquisition, 1, 0))
		if err != nil {
			t.Fatalf("build: %v", err)
		}
		if built.Evidence[0].ValueHash == nil || string(*built.Evidence[0].ValueHash) != want {
			t.Fatalf("value hash = %v, want %q", built.Evidence[0].ValueHash, want)
		}
	})
	t.Run("escaped_value", func(t *testing.T) {
		// An escaped value is hashed over its decoded UTF-8 bytes.
		document := a202Document(`{"apiVersion":"v1","kind":"Pod","metadata":{"uid":"u1","namespace":"` + a202Namespace + `","name":"n1"},` +
			`"spec":{"containers":[{"name":"api","image":"` + a202Image + `"}]},` +
			`"status":{"containerStatuses":[{"name":"api","imageID":"sha256:\u0061\u0061aa"}]}}`)
		source := a202BuildSource(t, document, "capture-000001.json", contract.TerminationFinished)
		acquisition := a202Acquisition(t, []a202Source{source}, contract.TerminationFinished, nil)
		built, _, err := bundle.BuildCollectedObservation(a202Input(acquisition, 1, 0))
		if err != nil {
			t.Fatalf("build: %v", err)
		}
		if built.Evidence[0].Value == nil || *built.Evidence[0].Value != "sha256:aaaa" {
			t.Fatalf("decoded value = %v", built.Evidence[0].Value)
		}
		if built.Evidence[0].ValueHash == nil || string(*built.Evidence[0].ValueHash) != a202IndependentHash([]byte("sha256:aaaa")) {
			t.Fatal("the value hash is not over the decoded bytes")
		}
	})
	t.Run("no_quote_or_newline_in_value_preimage", func(t *testing.T) {
		source := a202BuildSource(t, a202Document(a202Pod("u1", "n1")), "capture-000001.json", contract.TerminationFinished)
		acquisition := a202Acquisition(t, []a202Source{source}, contract.TerminationFinished, nil)
		built, _, err := bundle.BuildCollectedObservation(a202Input(acquisition, 1, 0))
		if err != nil {
			t.Fatalf("build: %v", err)
		}
		withQuotes := a202IndependentHash([]byte(`"` + a202ImageID + `"`))
		withNewline := a202IndependentHash([]byte(a202ImageID + "\n"))
		if string(*built.Evidence[0].ValueHash) == withQuotes || string(*built.Evidence[0].ValueHash) == withNewline {
			t.Fatal("the value preimage carries quoting or a newline")
		}
	})
}

func TestA202CaptureProvenance(t *testing.T) {
	t.Run("locator_resolves_exact_value", func(t *testing.T) {
		source := a202BuildSource(t, a202Document(a202Pod("u1", "n1")), "capture-000001.json", contract.TerminationFinished)
		acquisition := a202Acquisition(t, []a202Source{source}, contract.TerminationFinished, nil)
		built, _, err := bundle.BuildCollectedObservation(a202Input(acquisition, 1, 0))
		if err != nil {
			t.Fatalf("build: %v", err)
		}
		// The oracle walks the admitted document with the closed locator
		// grammar and compares the resolved text with the evidence value.
		resolved, ok := a202ResolveLocator(t, source.Bytes, string(built.Evidence[0].Locator))
		if !ok {
			t.Fatalf("locator %q does not resolve", built.Evidence[0].Locator)
		}
		if built.Evidence[0].Value == nil || resolved != *built.Evidence[0].Value {
			t.Fatalf("resolved %q, value %v", resolved, built.Evidence[0].Value)
		}
	})
	t.Run("nonzero_item_and_status_indices", func(t *testing.T) {
		document := a202Document(a202IdentityOnlyDocument("u0", "n0"), a202Pod("u1", "n1"))
		source := a202BuildSource(t, document, "capture-000001.json", contract.TerminationFinished)
		acquisition := a202Acquisition(t, []a202Source{source}, contract.TerminationFinished, nil)
		built, _, err := bundle.BuildCollectedObservation(a202Input(acquisition, 1, 1))
		if err != nil {
			t.Fatalf("build: %v", err)
		}
		if !strings.Contains(string(built.Evidence[0].Locator), "items[1]") {
			t.Fatalf("locator = %q, want the original item index", built.Evidence[0].Locator)
		}
		resolved, ok := a202ResolveLocator(t, source.Bytes, string(built.Evidence[0].Locator))
		if !ok || built.Evidence[0].Value == nil || resolved != *built.Evidence[0].Value {
			t.Fatalf("locator %q did not resolve to %v", built.Evidence[0].Locator, built.Evidence[0].Value)
		}
	})
	t.Run("uid_and_container_match", func(t *testing.T) {
		source := a202BuildSource(t, a202Document(a202Pod("u1", "n1")), "capture-000001.json", contract.TerminationFinished)
		acquisition := a202Acquisition(t, []a202Source{source}, contract.TerminationFinished, nil)
		built, _, err := bundle.BuildCollectedObservation(a202Input(acquisition, 1, 0))
		if err != nil {
			t.Fatalf("build: %v", err)
		}
		if built.Evidence[0].Scope.SubjectUID != built.Subject.UID {
			t.Fatalf("evidence uid = %q, subject uid = %q", built.Evidence[0].Scope.SubjectUID, built.Subject.UID)
		}
		if string(built.Evidence[0].Scope.ContainerName) != "api" {
			t.Fatalf("container = %q", built.Evidence[0].Scope.ContainerName)
		}
	})
	t.Run("capture_timestamp", func(t *testing.T) {
		source := a202BuildSource(t, a202Document(a202Pod("u1", "n1")), "capture-000001.json", contract.TerminationFinished)
		acquisition := a202Acquisition(t, []a202Source{source}, contract.TerminationFinished, nil)
		built, _, err := bundle.BuildCollectedObservation(a202Input(acquisition, 1, 0))
		if err != nil {
			t.Fatalf("build: %v", err)
		}
		if built.Evidence[0].ObservedAt == nil || !built.Evidence[0].ObservedAt.Time.Equal(source.Observation.ObservedAt.Time) {
			t.Fatal("the evidence timestamp is not the capture instant")
		}
	})
	t.Run("later_capture_does_not_rewrite_previous", func(t *testing.T) {
		first := a202BuildSource(t, a202Document(a202Pod("u1", "n1")), "capture-000001.json", contract.TerminationFinished)
		second := a202BuildSource(t, a202Document(a202Pod("u1", "n1")), "capture-000002.json", contract.TerminationFinished)
		acquisition := a202Acquisition(t, []a202Source{first, second}, contract.TerminationFinished, nil)
		builtFirst, _, err := bundle.BuildCollectedObservation(a202Input(acquisition, 1, 0))
		if err != nil {
			t.Fatalf("build first: %v", err)
		}
		// The selection is the requested capture: a later capture must neither
		// replace it nor rewrite its bundle.
		if builtFirst.Evidence[0].Source != "capture-000001.json" {
			t.Fatalf("the first bundle cites %q instead of its own capture", builtFirst.Evidence[0].Source)
		}
		if builtFirst.Evidence[0].SourceHash != first.Hash {
			t.Fatal("the first bundle cites another source hash")
		}
		before := a202IndependentHash([]byte(builtFirst.Evidence[0].Source + string(builtFirst.Evidence[0].SourceHash)))
		builtSecond, _, err := bundle.BuildCollectedObservation(a202Input(acquisition, 2, 0))
		if err != nil {
			t.Fatalf("build second: %v", err)
		}
		if builtSecond.Evidence[0].Source != "capture-000002.json" {
			t.Fatalf("the second bundle cites %q", builtSecond.Evidence[0].Source)
		}
		if a202IndependentHash([]byte(builtFirst.Evidence[0].Source+string(builtFirst.Evidence[0].SourceHash))) != before {
			t.Fatal("building a later capture rewrote the first bundle")
		}
	})
}

func TestA202GlobalFailurePropagation(t *testing.T) {
	// Every case asserts the concrete error and the warning on every bundle.
	assertPropagation := func(t *testing.T, acquisition bundle.CollectedAcquisition, want string) {
		t.Helper()
		if len(acquisition.Captures) == 0 {
			t.Fatal("the fixture produced no capture")
		}
		for _, capture := range acquisition.Captures {
			for index := range capture.Observation.Subjects {
				built, _, err := bundle.BuildCollectedObservation(bundle.CollectedObservationInput{
					Acquisition:    acquisition,
					CaptureOrdinal: capture.Ordinal,
					SubjectIndex:   index,
					Result:         capture.Observation,
				})
				if err != nil {
					t.Fatalf("build capture %d subject %d: %v", capture.Ordinal, index, err)
				}
				if !a202HasError(built.Provenance.Errors, want) {
					t.Fatalf("bundle of capture %d lacks the concrete error %q: %v", capture.Ordinal, want, built.Provenance.Errors)
				}
				if !a202HasWarning(built.Provenance.Warnings, "tool_failure", "contradictory", "collector acquisition did not complete") {
					t.Fatalf("bundle of capture %d lacks the acquisition warning", capture.Ordinal)
				}
				if built.Provenance.Coverage.Termination != contract.TerminationAborted {
					t.Fatalf("coverage = %q, want aborted", built.Provenance.Coverage.Termination)
				}
			}
		}
	}
	t.Run("get_forbidden", func(t *testing.T) {
		source := a202BuildSource(t, a202Document(a202Pod("u1", "n1")), "capture-000001.json", contract.TerminationFinished)
		acquisition := a202Acquisition(t, []a202Source{source}, contract.TerminationFinished, nil)
		acquisition.Termination = contract.TerminationAborted
		acquisition.GlobalErrors = []string{"collector: forbidden"}
		acquisition.GlobalWarnings = []contract.Warning{{Code: "tool_failure", Class: contract.WarningContradictory, Message: "collector acquisition did not complete"}}
		acquisition.Plan.InventoryClosed = false
		acquisition.Plan.UnfinishedTargets = 2
		for index := range acquisition.Captures {
			capture := &acquisition.Captures[index]
			rebuilt := a202BuildSource(t, string(capture.Bytes), capture.Alias, contract.TerminationAborted)
			capture.Observation = rebuilt.Observation
		}
		assertPropagation(t, acquisition, "collector: forbidden")
	})
	t.Run("later_page_failure", func(t *testing.T) {
		page := a202BuildSource(t, a202Document(a202Pod("u1", "n1")), "capture-000001.json", contract.TerminationAborted)
		acquisition := a202Acquisition(t, []a202Source{page}, contract.TerminationAborted, nil)
		acquisition.GlobalErrors = []string{"collector: pagination_expired"}
		acquisition.Plan.ContinuationOpen = true
		assertPropagation(t, acquisition, "collector: pagination_expired")
	})
	t.Run("later_namespace_forbidden", func(t *testing.T) {
		page := a202BuildSource(t, a202Document(a202Pod("u1", "n1")), "capture-000001.json", contract.TerminationAborted)
		acquisition := a202Acquisition(t, []a202Source{page}, contract.TerminationAborted, nil)
		acquisition.GlobalErrors = []string{"collector: forbidden"}
		// The pending namespace was part of the declared scope of the run.
		acquisition.Scope.Namespaces = append(append([]contract.Namespace{}, acquisition.Scope.Namespaces...), "orders")
		acquisition.Plan.PendingNamespaces = []contract.Namespace{"orders"}
		assertPropagation(t, acquisition, "collector: forbidden")
	})
	t.Run("budget_abort", func(t *testing.T) {
		page := a202BuildSource(t, a202Document(a202Pod("u1", "n1")), "capture-000001.json", contract.TerminationAborted)
		acquisition := a202Acquisition(t, []a202Source{page}, contract.TerminationAborted, nil)
		acquisition.GlobalErrors = []string{"collector: request_limit"}
		acquisition.Plan.UnfinishedTargets = 1
		assertPropagation(t, acquisition, "collector: request_limit")
	})
}

func TestA202PublicationBoundary(t *testing.T) {
	t.Run("rejected_response_no_source", func(t *testing.T) {
		// A rejected body never becomes a source: the acquisition record has no
		// capture for it and the builder cannot select it.
		source := a202BuildSource(t, a202Document(a202Pod("u1", "n1")), "capture-000001.json", contract.TerminationFinished)
		acquisition := a202Acquisition(t, []a202Source{source}, contract.TerminationFinished, nil)
		if _, _, err := bundle.BuildCollectedObservation(bundle.CollectedObservationInput{
			Acquisition:    acquisition,
			CaptureOrdinal: 2,
			SubjectIndex:   0,
			Result:         source.Observation,
		}); err == nil {
			t.Fatal("a capture that does not exist produced a bundle")
		}
	})
	t.Run("admitted_value_the_wire_does_not_publish", func(t *testing.T) {
		// metadata.resourceVersion is admitted by the sanitized grammar, so the
		// marker really travels inside the admitted source and the capture
		// record; the wire 0.2 publishes no resource version, so no artefact may
		// carry it. The positive half is asserted too: without it — as in the
		// earlier version of this case, whose document held no marker at all —
		// the search could never fail and would prove nothing.
		marker := "SYNTHETIC-ADMITTED-MARKER-7f3a"
		document := `{"apiVersion":"v1","kind":"PodList","metadata":{"resourceVersion":"` + marker + `"},"items":[` +
			`{"apiVersion":"v1","kind":"Pod","metadata":{"uid":"u1","namespace":"` + a202Namespace + `","name":"n1","resourceVersion":"` + marker + `"},` +
			`"spec":{"containers":[{"name":"api","image":"` + a202Image + `"}]},` +
			`"status":{"containerStatuses":[{"name":"api","imageID":"` + a202ImageID + `"}]}}]}`
		source := a202BuildSource(t, document, "capture-000001.json", contract.TerminationFinished)
		if !strings.Contains(string(source.Bytes), marker) {
			t.Fatal("the marker was not admitted into the sanitized source: the negative half would be vacuous")
		}
		acquisition := a202Acquisition(t, []a202Source{source}, contract.TerminationFinished, nil)
		acquisition.Captures[0].ListResourceVersion = marker
		acquisition.Captures[0].ListResourceVersionPresence = true
		built, _, err := bundle.BuildCollectedObservation(a202Input(acquisition, 1, 0))
		if err != nil {
			t.Fatalf("build: %v", err)
		}
		encoded, err := bundle.Encode(built)
		if err != nil {
			t.Fatalf("encode: %v", err)
		}
		for name, artefact := range map[string][]byte{"envelope": encoded.Envelope, "hash projection": encoded.HashInput} {
			if bytes.Contains(artefact, []byte(marker)) {
				t.Fatalf("the %s carries the admitted value that the wire does not publish", name)
			}
		}
	})
	t.Run("positive_reaches_write", func(t *testing.T) {
		source := a202BuildSource(t, a202Document(a202Pod("u1", "n1")), "capture-000001.json", contract.TerminationFinished)
		acquisition := a202Acquisition(t, []a202Source{source}, contract.TerminationFinished, nil)
		built, _, err := bundle.BuildCollectedObservation(a202Input(acquisition, 1, 0))
		if err != nil {
			t.Fatalf("build: %v", err)
		}
		destination := &a202SpyDestination{}
		if err := bundle.Write(built, destination.destinations()); err != nil {
			t.Fatalf("write: %v", err)
		}
		if destination.calls() == 0 {
			t.Fatal("a valid bundle produced no artefact")
		}
	})
	t.Run("earlier_sources_survive_later_abort", func(t *testing.T) {
		first := a202BuildSource(t, a202Document(a202Pod("u1", "n1")), "capture-000001.json", contract.TerminationAborted)
		acquisition := a202Acquisition(t, []a202Source{first}, contract.TerminationAborted, nil)
		acquisition.GlobalErrors = []string{"collector: forbidden"}
		built, _, err := bundle.BuildCollectedObservation(a202Input(acquisition, 1, 0))
		if err != nil {
			t.Fatalf("build: %v", err)
		}
		if len(built.Evidence) == 0 {
			t.Fatal("the earlier source lost its evidence after the abort")
		}
		if !a202HasError(built.Provenance.Errors, "collector: forbidden") {
			t.Fatal("the earlier source lost the concrete failure")
		}
	})
	t.Run("no_default_dto_after_rejection", func(t *testing.T) {
		// A refused input never yields the zero-value defaults: the build fails
		// closed instead of returning a bundle of defaults.
		source := a202BuildSource(t, a202Document(a202Pod("u1", "n1")), "capture-000001.json", contract.TerminationFinished)
		acquisition := a202Acquisition(t, []a202Source{source}, contract.TerminationFinished, nil)
		acquisition.Captures[0].Hash = contract.SourceHash("sha256:" + strings.Repeat("0", 64))
		built, _, err := bundle.BuildCollectedObservation(a202Input(acquisition, 1, 0))
		if err == nil {
			t.Fatal("an incoherent input built a bundle")
		}
		if built.SchemaVersion != "" || built.Subject.UID != "" {
			t.Fatal("a refused input produced a default bundle")
		}
	})
}

// TestA202EvaluatorConservative proves that the live producer never sustains a
// favourable conclusion by itself: the evaluator keeps the conservative
// reasons.
func TestA202EvaluatorConservative(t *testing.T) {
	source := a202BuildSource(t, a202Document(a202Pod("u1", "n1")), "capture-000001.json", contract.TerminationFinished)
	acquisition := a202Acquisition(t, []a202Source{source}, contract.TerminationFinished, nil)
	built, _, err := bundle.BuildCollectedObservation(a202Input(acquisition, 1, 0))
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	t.Run("partial_bundle", func(t *testing.T) {
		// A partial observation (the basic shape of any live capture) cannot
		// sustain a not_affected conclusion.
		partial, _, err := a202Build(t, a202IncompleteDocumentRaw(), contract.TerminationFinished)
		if err != nil {
			t.Fatalf("build partial: %v", err)
		}
		if partial.Provenance.Completeness == contract.CompletenessComplete {
			t.Fatal("an incomplete observation was reported as complete")
		}
	})
	t.Run("raw_without_digest", func(t *testing.T) {
		for _, image := range built.Images {
			if image.NormalizedDigest != nil {
				t.Fatal("the producer promoted a digest")
			}
		}
	})
	t.Run("contradictory_warning", func(t *testing.T) {
		// Every mTLS of the run keeps the projection warning as informational;
		// an incomplete observation adds a contradictory one.
		found := false
		for _, warning := range built.Provenance.Warnings {
			if warning.Code == "redaction_applied" && warning.Class == contract.WarningInformational {
				found = true
			}
		}
		if !found {
			t.Fatal("the projection warning is missing")
		}
	})
	t.Run("evidence_scope_mismatch", func(t *testing.T) {
		// The evaluator refuses to cite a row whose container is outside the
		// observed scope: the producer never fabricates one.
		artifacts, err := bundle.Encode(built)
		if err != nil {
			t.Fatalf("encode: %v", err)
		}
		result, err := evaluator.Evaluate(evaluator.Request{
			Bundle:             built,
			ExpectedBundleHash: artifacts.Hash,
			Target: evaluator.Target{
				SubjectUID:      built.Subject.UID,
				ContainerClass:  contract.ContainerRegular,
				ContainerName:   "not-observed",
				VulnerabilityID: "CVE-2026-99999",
				Source:          built.Provenance.Inputs[0].Path,
				SourceHash:      built.Provenance.Inputs[0].Hash,
				Locator:         contract.SourceLocator("items[0].status.containerStatuses[0].imageID"),
				ObservedAt:      *built.Evidence[0].ObservedAt,
			},
			PackBytes: a201PackBytes(),
			Admission: a201Admission(),
			Domain:    a201DomainContext(),
		})
		if err != nil {
			t.Fatalf("evaluate: %v", err)
		}
		if result.ProductStatus == contract.ProductNotAffected {
			t.Fatal("the evaluator reached a favourable conclusion from a scope mismatch")
		}
	})
}

// a202ResolveLocator resolves one closed locator against the sanitized source
// with an independent walk, so a locator is never trusted on its shape alone.
// The oracle re-derives the item and status positions from the document, and
// the caller compares the returned text with the evidence value.
func a202ResolveLocator(t *testing.T, source []byte, locator string) (string, bool) {
	t.Helper()
	// Admitted grammar: items[<i>].status.<array>[<j>].imageID.
	if !strings.HasPrefix(locator, "items[") {
		return "", false
	}
	rest := strings.TrimPrefix(locator, "items[")
	closeIndex := strings.Index(rest, "].")
	if closeIndex < 0 {
		return "", false
	}
	rest = rest[closeIndex+2:]
	if !strings.HasPrefix(rest, "status.") {
		return "", false
	}
	array := rest[len("status."):]
	arrayName := array
	if dot := strings.Index(array, "["); dot >= 0 {
		arrayName = array[:dot]
	}
	switch arrayName {
	case "containerStatuses", "initContainerStatuses", "ephemeralContainerStatuses":
	default:
		return "", false
	}
	if !strings.HasSuffix(rest, ".imageID") {
		return "", false
	}
	// The oracle walks the JSON structurally: find the item array, the named
	// status array inside it and the first string value of the sought key.
	needle := `"` + arrayName + `":[`
	index := strings.Index(string(source), needle)
	if index < 0 {
		return "", false
	}
	segment := string(source)[index+len(needle):]
	valueIndex := strings.Index(segment, `"imageID":"`)
	if valueIndex < 0 {
		return "", false
	}
	value := segment[valueIndex+len(`"imageID":"`):]
	end := strings.Index(value, `"`)
	if end < 0 {
		return "", false
	}
	return value[:end], true
}

// a202SpyDestination counts every write to the artifact destinations.
type a202SpyDestination struct {
	envelopeCalls  int
	hashInputCalls int
	digestCalls    int
}

func (spy *a202SpyDestination) destinations() bundle.Destinations {
	return bundle.Destinations{
		Envelope:  a202SpyWriter{counter: &spy.envelopeCalls},
		HashInput: a202SpyWriter{counter: &spy.hashInputCalls},
		Hash:      a202SpyWriter{counter: &spy.digestCalls},
	}
}

func (spy *a202SpyDestination) calls() int {
	return spy.envelopeCalls + spy.hashInputCalls + spy.digestCalls
}

type a202SpyWriter struct{ counter *int }

func (writer a202SpyWriter) Write(chunk []byte) (int, error) {
	*writer.counter++
	return len(chunk), nil
}
