package bundle_test

import (
	"strings"
	"testing"
	"time"

	"github.com/d4rpell/Ariadne/internal/bundle"
	"github.com/d4rpell/Ariadne/internal/normalize"
	contract "github.com/d4rpell/Ariadne/pkg/evidence"
)

// Invalid-DTO cases of the A2-02 plan (handoff §4.2 row "DTO adulterado"): the
// builder revalidates the whole input and refuses an incoherent one with the
// zero bundle and the closed diagnostic.

func TestA202InvalidCollectedDTO(t *testing.T) {
	// a202ValidInput is the baseline of every corruption below.
	a202ValidInput := func(t *testing.T) bundle.CollectedObservationInput {
		t.Helper()
		source := a202BuildSource(t, a202Document(a202Pod("u1", "n1")), "capture-000001.json", contract.TerminationFinished)
		acquisition := a202Acquisition(t, []a202Source{source}, contract.TerminationFinished, nil)
		return a202Input(acquisition, 1, 0)
	}
	cases := map[string]func(*bundle.CollectedObservationInput){
		"source_hash": func(input *bundle.CollectedObservationInput) {
			input.Acquisition.Captures[0].Hash = contract.SourceHash("sha256:" + strings.Repeat("0", 64))
		},
		"source_bytes": func(input *bundle.CollectedObservationInput) {
			input.Acquisition.Captures[0].Bytes = []byte(`{"apiVersion":"v1","kind":"PodList","items":[]}`)
		},
		"subject": func(input *bundle.CollectedObservationInput) {
			input.SubjectIndex = 7
		},
		"subject_name_not_in_bytes": func(input *bundle.CollectedObservationInput) {
			// The DTO stays internally coherent, but its subject no longer
			// matches the admitted bytes: only the source-re-admission contrast
			// can prove the incoherence.
			copied := input.Result
			copied.Subjects = append([]normalize.ObservationSubject{}, input.Result.Subjects...)
			copied.Subjects[0].Name = "name-not-in-the-source"
			input.Result = copied
		},
		"capture": func(input *bundle.CollectedObservationInput) {
			input.CaptureOrdinal = 9
		},
		"operation": func(input *bundle.CollectedObservationInput) {
			input.Acquisition.Operations[0].Verb = "delete"
		},
		"timestamp": func(input *bundle.CollectedObservationInput) {
			// The started instant is after the ended one: the window is
			// incoherent and the input is refused.
			started := *input.Acquisition.EndedAt
			started.Time = started.Time.Add(time.Hour)
			input.Acquisition.StartedAt = &started
		},
		"termination": func(input *bundle.CollectedObservationInput) {
			input.Acquisition.Termination = contract.TerminationAborted
		},
		"scope": func(input *bundle.CollectedObservationInput) {
			input.Acquisition.Scope.Selector = "operator-export"
		},
		"comparison": func(input *bundle.CollectedObservationInput) {
			input.Acquisition.Comparisons = []bundle.CollectedComparison{{
				Code:     bundle.CodeObservationChanged,
				Previous: bundle.CollectedSubjectRef{CaptureOrdinal: 4, ItemIndex: 0},
				Current:  bundle.CollectedSubjectRef{CaptureOrdinal: 4, ItemIndex: 1},
			}}
		},
		"comparison_self": func(input *bundle.CollectedObservationInput) {
			// A comparison of one subject with itself cannot attest a difference.
			input.Acquisition.Comparisons = []bundle.CollectedComparison{{
				Code:     bundle.CodeObservationChanged,
				Previous: bundle.CollectedSubjectRef{CaptureOrdinal: 1, ItemIndex: 0},
				Current:  bundle.CollectedSubjectRef{CaptureOrdinal: 1, ItemIndex: 0},
			}}
		},
		"comparison_without_change": func(input *bundle.CollectedObservationInput) {
			// The two ends exist, but their projected content is identical: an
			// observation_changed over an unchanged observation is refused.
			ordinal := input.CaptureOrdinal
			input.Acquisition.Comparisons = []bundle.CollectedComparison{{
				Code:     bundle.CodeObservationChanged,
				Previous: bundle.CollectedSubjectRef{CaptureOrdinal: ordinal, ItemIndex: 0},
				Current:  bundle.CollectedSubjectRef{CaptureOrdinal: ordinal, ItemIndex: 0},
			}}
		},
		"comparison_stale_without_pattern": func(input *bundle.CollectedObservationInput) {
			// A stale_status_suspected without the bounded F07 pattern between
			// the referenced observations is refused.
			input.Acquisition.Comparisons = []bundle.CollectedComparison{{
				Code:     bundle.CodeStaleStatusSuspected,
				Previous: bundle.CollectedSubjectRef{CaptureOrdinal: 1, ItemIndex: 0},
				Current:  bundle.CollectedSubjectRef{CaptureOrdinal: 1, ItemIndex: 0},
			}}
		},
		"comparison_uid_changed_same_uid": func(input *bundle.CollectedObservationInput) {
			// A uid_changed whose two ends carry the same uid is refused: the
			// replacement it attests never happened.
			ordinal := input.CaptureOrdinal
			input.Acquisition.Comparisons = []bundle.CollectedComparison{{
				Code:     bundle.CodeUIDChanged,
				Previous: bundle.CollectedSubjectRef{CaptureOrdinal: ordinal, ItemIndex: 0},
				Current:  bundle.CollectedSubjectRef{CaptureOrdinal: ordinal, ItemIndex: 0},
			}}
		},
		"scope_namespace_not_allowed": func(input *bundle.CollectedObservationInput) {
			// An attempted namespace outside the declared allowlist is refused:
			// the record cannot claim permissions it never declared.
			input.Acquisition.Scope.Namespaces = []contract.Namespace{"other-ns"}
		},
		"operation_without_success": func(input *bundle.CollectedObservationInput) {
			// The capture cites an operation that never produced a 200: an
			// attempted request without a finished response cannot carry a source.
			for index := range input.Acquisition.Operations {
				if input.Acquisition.Operations[index].RequestOrdinal == input.CaptureOrdinal {
					input.Acquisition.Operations[index].State = bundle.OperationAttempted
					input.Acquisition.Operations[index].StatusCode = 0
				}
			}
		},
		"unknown_code": func(input *bundle.CollectedObservationInput) {
			ordinal := uint64(1)
			item := 0
			input.Acquisition.Diagnostics = []bundle.CollectionDiagnostic{{
				Code:           bundle.CollectionCode("synthetic_unknown"),
				RequestOrdinal: &ordinal,
				ItemIndex:      &item,
			}}
		},
		"free_text_locator": func(input *bundle.CollectedObservationInput) {
			input.Acquisition.Diagnostics = []bundle.CollectionDiagnostic{{
				Code:         bundle.CodeResponseInvalid,
				FieldLocator: "a free-text locator",
			}}
		},
		"arbitrary_origin": func(input *bundle.CollectedObservationInput) {
			// The alias must be the derived one: an arbitrary path is refused.
			input.Acquisition.Captures[0].Alias = "/tmp/synthetic.json"
		},
		"plain_source": func(input *bundle.CollectedObservationInput) {
			input.Acquisition.Captures[0].Alias = "sanitized-pods.json"
		},
		"operation_not_attempted": func(input *bundle.CollectedObservationInput) {
			input.Acquisition.Operations[0].State = bundle.OperationNotExecuted
		},
		"request_ordinal": func(input *bundle.CollectedObservationInput) {
			input.Acquisition.Operations[0].RequestOrdinal = 42
		},
		"accounting": func(input *bundle.CollectedObservationInput) {
			input.Acquisition.Stats.RequestsAttempted = 7
			input.Acquisition.Plan.RequestedOps = 7
		},
		"concurrency": func(input *bundle.CollectedObservationInput) {
			input.Acquisition.Stats.MaxConcurrency = 2
		},
		"collision_message_free_suffix": func(input *bundle.CollectedObservationInput) {
			// Free text appended after the admitted collision prefix must be
			// refused: the message is a program constant plus closed classes.
			input.Acquisition.GlobalWarnings = []contract.Warning{{
				Code:    "scope_mismatch",
				Class:   contract.WarningContradictory,
				Message: "scope collision across container classes: regular, MARCADOR_PRIVADO",
			}}
		},
		"collision_message_unknown_class": func(input *bundle.CollectedObservationInput) {
			input.Acquisition.GlobalWarnings = []contract.Warning{{
				Code:    "scope_mismatch",
				Class:   contract.WarningContradictory,
				Message: "scope collision across container classes: sidecar",
			}}
		},
		"collision_message_wrong_order": func(input *bundle.CollectedObservationInput) {
			// The classes are listed in the canonical enum order; the reversed
			// pair is not the message the producer emits.
			input.Acquisition.GlobalWarnings = []contract.Warning{{
				Code:    "scope_mismatch",
				Class:   contract.WarningContradictory,
				Message: "scope collision across container classes: init, regular",
			}}
		},
		"collision_message_empty_suffix": func(input *bundle.CollectedObservationInput) {
			input.Acquisition.GlobalWarnings = []contract.Warning{{
				Code:    "scope_mismatch",
				Class:   contract.WarningContradictory,
				Message: "scope collision across container classes: ",
			}}
		},
		"global_warning_free_text": func(input *bundle.CollectedObservationInput) {
			input.Acquisition.GlobalWarnings = []contract.Warning{{
				Code:    "uid_changed",
				Class:   contract.WarningContradictory,
				Message: "Pod UID changed between collection observations: MARCADOR_PRIVADO",
			}}
		},
		"global_error_free_text": func(input *bundle.CollectedObservationInput) {
			input.Acquisition.GlobalErrors = []string{"collector: response_invalid (MARCADOR_PRIVADO)"}
		},
	}
	for name, corrupt := range cases {
		t.Run(name, func(t *testing.T) {
			input := a202ValidInput(t)
			corrupt(&input)
			built, _, err := bundle.BuildCollectedObservation(input)
			if err == nil {
				t.Fatalf("an adulterated DTO produced a bundle: %+v", built.Provenance)
			}
			if err.Error() != "collector: projection_failed" {
				t.Fatalf("err = %q, want collector: projection_failed", err)
			}
			if len(built.Images) != 0 || len(built.Evidence) != 0 || built.SchemaVersion != "" {
				t.Fatal("a refused DTO produced a partial bundle")
			}
		})
	}
	t.Run("control_positive", func(t *testing.T) {
		// The baseline of the corruption matrix builds successfully: the
		// refusals above are caused by the corruption and not by the fixture.
		built, _, err := bundle.BuildCollectedObservation(a202ValidInput(t))
		if err != nil {
			t.Fatalf("the valid baseline failed: %v", err)
		}
		if built.Provenance.Completeness != contract.CompletenessComplete {
			t.Fatalf("completeness = %q", built.Provenance.Completeness)
		}
	})
	t.Run("valid_comparison_admitted", func(t *testing.T) {
		// The positive control of the comparison rules: two captures whose
		// projected content really differs, cited by an observation_changed and a
		// stale_status_suspected, are admitted and keep their warnings.
		first := a202BuildSource(t, a202Document(a202PodWithImageID("u1", "n1", a202ImageID)), "capture-000001.json", contract.TerminationFinished)
		second := a202BuildSource(t, a202Document(a202PodWithImageID("u1", "n1", "sha256:"+strings.Repeat("b", 64))), "capture-000002.json", contract.TerminationFinished)
		acquisition := a202Acquisition(t, []a202Source{first, second}, contract.TerminationFinished, nil)
		// The requested image is identical in the two captures, so the bounded
		// F07 pattern does not hold: only the content change is attested, and the
		// builder accepts it while refusing the stale claim.
		acquisition.Comparisons = []bundle.CollectedComparison{{
			Code:     bundle.CodeObservationChanged,
			Previous: bundle.CollectedSubjectRef{CaptureOrdinal: 1, ItemIndex: 0},
			Current:  bundle.CollectedSubjectRef{CaptureOrdinal: 2, ItemIndex: 0},
		}}
		built, _, err := bundle.BuildCollectedObservation(a202Input(acquisition, 1, 0))
		if err != nil {
			t.Fatalf("a real content change was refused: %v", err)
		}
		if !a202HasWarning(built.Provenance.Warnings, "source_conflict", "contradictory", "collection observations contain differing projected content") {
			t.Fatalf("the content change produced no source_conflict warning: %+v", built.Provenance.Warnings)
		}
	})
}

// TestA202ComparisonConditions isolates each comparison rule over two real
// captures of differing projected content: every refusal below is caused by the
// condition under test and not by an unrelated validation, so a mutation that
// removes the condition is detected.
func TestA202ComparisonConditions(t *testing.T) {
	first := a202BuildSource(t, a202Document(a202PodWithImageID("u1", "n1", a202ImageID)), "capture-000001.json", contract.TerminationFinished)
	second := a202BuildSource(t, a202Document(a202PodWithImageID("u1", "n1", "sha256:"+strings.Repeat("b", 64))), "capture-000002.json", contract.TerminationFinished)
	ref := func(capture uint64) bundle.CollectedSubjectRef {
		return bundle.CollectedSubjectRef{CaptureOrdinal: capture, ItemIndex: 0}
	}
	build := func(t *testing.T, acquisition bundle.CollectedAcquisition) error {
		t.Helper()
		_, _, err := bundle.BuildCollectedObservation(a202Input(acquisition, 1, 0))
		return err
	}
	t.Run("control_positive", func(t *testing.T) {
		// The ordered, same-subject pair with a real content change is admitted:
		// the refusals below are caused by each corruption, not by the fixture.
		admitted := a202Acquisition(t, []a202Source{first, second}, contract.TerminationFinished, nil)
		admitted.Comparisons = []bundle.CollectedComparison{{
			Code:     bundle.CodeObservationChanged,
			Previous: ref(1),
			Current:  ref(2),
		}}
		if err := build(t, admitted); err != nil {
			t.Fatalf("the ordered same-subject comparison was refused: %v", err)
		}
	})
	t.Run("observation_changed_requires_a_real_change", func(t *testing.T) {
		// Same subject twice across two captures with identical bytes: the two
		// ends exist and differ in capture, but the projected content does not
		// change, so the code is refused.
		same := a202BuildSource(t, a202Document(a202PodWithImageID("u1", "n1", a202ImageID)), "capture-000002.json", contract.TerminationFinished)
		identical := a202Acquisition(t, []a202Source{first, same}, contract.TerminationFinished, nil)
		identical.Comparisons = []bundle.CollectedComparison{{
			Code:     bundle.CodeObservationChanged,
			Previous: ref(1),
			Current:  ref(2),
		}}
		if _, _, err := bundle.BuildCollectedObservation(a202Input(identical, 1, 0)); err == nil || err.Error() != "collector: projection_failed" {
			t.Fatalf("an unchanged observation produced observation_changed: %v", err)
		}
	})
	t.Run("stale_requires_the_pattern", func(t *testing.T) {
		// The two captures differ in their status imageID only: the content
		// changed (so the earlier comparison rule passes) but the requested image
		// did not, so the F07 pattern does not hold and the stale claim is
		// refused.
		stale := a202Acquisition(t, []a202Source{first, second}, contract.TerminationFinished, nil)
		stale.Comparisons = []bundle.CollectedComparison{{
			Code:     bundle.CodeStaleStatusSuspected,
			Previous: ref(1),
			Current:  ref(2),
		}}
		if _, _, err := bundle.BuildCollectedObservation(a202Input(stale, 1, 0)); err == nil || err.Error() != "collector: projection_failed" {
			t.Fatalf("a stale claim without the pattern was admitted: %v", err)
		}
	})
	t.Run("uid_changed_requires_two_uids", func(t *testing.T) {
		// The two captures carry the same uid: a uid_changed between them is a
		// replacement that never happened and is refused.
		same := a202BuildSource(t, a202Document(a202PodWithImageID("u1", "n1", "sha256:"+strings.Repeat("b", 64))), "capture-000002.json", contract.TerminationFinished)
		replaced := a202Acquisition(t, []a202Source{first, same}, contract.TerminationFinished, nil)
		replaced.Comparisons = []bundle.CollectedComparison{{
			Code:     bundle.CodeUIDChanged,
			Previous: ref(1),
			Current:  ref(2),
		}}
		if _, _, err := bundle.BuildCollectedObservation(a202Input(replaced, 1, 0)); err == nil || err.Error() != "collector: projection_failed" {
			t.Fatalf("a uid_changed over one uid was admitted: %v", err)
		}
	})
	t.Run("observation_changed_requires_the_same_uid", func(t *testing.T) {
		// Two different subjects cannot attest an observation change of one
		// subject: the ends must share the UID.
		other := a202BuildSource(t, a202Document(a202PodWithImageID("u2", "n1", "sha256:"+strings.Repeat("b", 64))), "capture-000002.json", contract.TerminationFinished)
		acquisition := a202Acquisition(t, []a202Source{first, other}, contract.TerminationFinished, nil)
		acquisition.Comparisons = []bundle.CollectedComparison{{
			Code:     bundle.CodeObservationChanged,
			Previous: ref(1),
			Current:  ref(2),
		}}
		if err := build(t, acquisition); err == nil {
			t.Fatal("a comparison between different uids was admitted")
		}
	})
	t.Run("observation_changed_requires_the_order", func(t *testing.T) {
		// The comparison must cite the earlier capture as previous: a reversed
		// pair would claim a change that runs backwards in time.
		acquisition := a202Acquisition(t, []a202Source{first, second}, contract.TerminationFinished, nil)
		acquisition.Comparisons = []bundle.CollectedComparison{{
			Code:     bundle.CodeObservationChanged,
			Previous: ref(2),
			Current:  ref(1),
		}}
		if err := build(t, acquisition); err == nil {
			t.Fatal("a reversed-order comparison was admitted")
		}
	})
	t.Run("stale_requires_the_order", func(t *testing.T) {
		// The two captures really satisfy the bounded F07 pattern (the requested
		// image changed while the whole status tuple stayed identical): the ordered
		// claim is admitted, so the rejection of the reversed one can only be
		// caused by the required order of the two ends.
		staleBefore := a202BuildSource(t, a202Document(a202PodRequestedImage("u1", "n1", a202Image)), "capture-000001.json", contract.TerminationFinished)
		staleAfter := a202BuildSource(t, a202Document(a202PodRequestedImage("u1", "n1", "registry.example/app:second")), "capture-000002.json", contract.TerminationFinished)
		ordered := a202Acquisition(t, []a202Source{staleBefore, staleAfter}, contract.TerminationFinished, nil)
		ordered.Comparisons = []bundle.CollectedComparison{{
			Code:     bundle.CodeStaleStatusSuspected,
			Previous: ref(1),
			Current:  ref(2),
		}}
		if err := build(t, ordered); err != nil {
			t.Fatalf("the ordered F07 pair was refused, so the reversed claim proves nothing: %v", err)
		}
		reversed := a202Acquisition(t, []a202Source{staleBefore, staleAfter}, contract.TerminationFinished, nil)
		reversed.Comparisons = []bundle.CollectedComparison{{
			Code:     bundle.CodeStaleStatusSuspected,
			Previous: ref(2),
			Current:  ref(1),
		}}
		if err := build(t, reversed); err == nil {
			t.Fatal("a reversed-order stale pattern was admitted")
		}
	})
	t.Run("cited_capture_dto_adulterated", func(t *testing.T) {
		// The comparison cites a second capture whose DTO no longer matches its
		// retained bytes. The identity and the conditions of the comparison stay
		// intact (same uid and address, a real difference of the projected content
		// between the two ends), so only the re-admission of every cited capture
		// catches the adulteration, which the selected capture alone cannot see.
		acquisition := a202Acquisition(t, []a202Source{first, second}, contract.TerminationFinished, nil)
		copied := acquisition.Captures[1].Observation
		copied.Subjects = append([]normalize.ObservationSubject{}, copied.Subjects...)
		copied.Subjects[0].Containers = append([]normalize.ObservationContainer{}, copied.Subjects[0].Containers...)
		third := "sha256:" + strings.Repeat("c", 64)
		copied.Subjects[0].Containers[0].ImageID = &third
		acquisition.Captures[1].Observation = copied
		acquisition.Comparisons = []bundle.CollectedComparison{{
			Code:     bundle.CodeObservationChanged,
			Previous: ref(1),
			Current:  ref(2),
		}}
		if err := build(t, acquisition); err == nil {
			t.Fatal("a comparison sustained by an adulterated DTO was admitted")
		}
	})
	t.Run("cited_capture_hash_adulterated", func(t *testing.T) {
		// Only the hash of the second capture is altered, consistently in the
		// capture record and in the source header of its DTO: the retained bytes
		// are intact, every condition of the comparison holds and the selected
		// capture stays coherent. Re-hashing each cited capture is the only way to
		// stop the adulterated hash from reaching provenance.inputs.
		acquisition := a202Acquisition(t, []a202Source{first, second}, contract.TerminationFinished, nil)
		adulterated := contract.SourceHash("sha256:" + strings.Repeat("f", 64))
		acquisition.Captures[1].Hash = adulterated
		acquisition.Captures[1].Observation.Source.Hash = adulterated
		acquisition.Comparisons = []bundle.CollectedComparison{{
			Code:     bundle.CodeObservationChanged,
			Previous: ref(1),
			Current:  ref(2),
		}}
		if err := build(t, acquisition); err == nil {
			t.Fatal("a comparison sustained by an adulterated hash was admitted")
		}
	})
	t.Run("cited_capture_length_adulterated", func(t *testing.T) {
		// The byte count of the second capture is altered while its bytes and hash
		// stay intact: the recorded length no longer describes the retained bytes.
		acquisition := a202Acquisition(t, []a202Source{first, second}, contract.TerminationFinished, nil)
		acquisition.Captures[1].Observation.Source.ByteCount = uint64(len(acquisition.Captures[1].Bytes)) + 1
		acquisition.Comparisons = []bundle.CollectedComparison{{
			Code:     bundle.CodeObservationChanged,
			Previous: ref(1),
			Current:  ref(2),
		}}
		if err := build(t, acquisition); err == nil {
			t.Fatal("a comparison sustained by an altered length was admitted")
		}
	})
	t.Run("cited_capture_alias_adulterated", func(t *testing.T) {
		// The alias of the second capture is altered, so the record no longer names
		// the derived origin of its own bytes.
		acquisition := a202Acquisition(t, []a202Source{first, second}, contract.TerminationFinished, nil)
		acquisition.Captures[1].Alias = "capture-000009.json"
		acquisition.Captures[1].Observation.Source.Name = "capture-000009.json"
		acquisition.Comparisons = []bundle.CollectedComparison{{
			Code:     bundle.CodeObservationChanged,
			Previous: ref(1),
			Current:  ref(2),
		}}
		if err := build(t, acquisition); err == nil {
			t.Fatal("a comparison sustained by an altered alias was admitted")
		}
	})
	t.Run("cited_capture_bytes_re_admitted", func(t *testing.T) {
		// The bytes of the second capture are altered and its hash, source hash and
		// byte count are updated consistently: the record looks coherent and every
		// comparison condition still holds, so only re-admitting the cited bytes
		// proves that its DTO no longer describes them.
		acquisition := a202Acquisition(t, []a202Source{first, second}, contract.TerminationFinished, nil)
		altered := []byte(strings.Replace(string(acquisition.Captures[1].Bytes), "bbbb", "cccc", 1))
		if string(altered) == string(acquisition.Captures[1].Bytes) {
			t.Fatal("the synthetic alteration did not change the retained bytes")
		}
		acquisition.Captures[1].Bytes = altered
		acquisition.Captures[1].Hash = contract.SourceHash(a202IndependentHash(altered))
		acquisition.Captures[1].Observation.Source.Hash = acquisition.Captures[1].Hash
		acquisition.Captures[1].Observation.Source.ByteCount = uint64(len(altered))
		acquisition.Comparisons = []bundle.CollectedComparison{{
			Code:     bundle.CodeObservationChanged,
			Previous: ref(1),
			Current:  ref(2),
		}}
		if err := build(t, acquisition); err == nil {
			t.Fatal("a comparison sustained by bytes that do not admit its DTO was admitted")
		}
	})
}

// TestA202CollectedBuildOwnership is I-29/A-27: the builder owns its data and a
// later mutation of the input never changes an already built bundle.
func TestA202CollectedBuildOwnership(t *testing.T) {
	t.Run("source_bytes", func(t *testing.T) {
		source := a202BuildSource(t, a202Document(a202Pod("u1", "n1")), "capture-000001.json", contract.TerminationFinished)
		acquisition := a202Acquisition(t, []a202Source{source}, contract.TerminationFinished, nil)
		built, _, err := bundle.BuildCollectedObservation(a202Input(acquisition, 1, 0))
		if err != nil {
			t.Fatalf("build: %v", err)
		}
		before := built.Evidence[0].SourceHash
		// The caller mutates its own copy of the retained bytes and of the
		// normalized source: the built bundle must not change.
		acquisition.Captures[0].Bytes[0] = 'X'
		acquisition.Captures[0].Observation.Source.Hash = contract.SourceHash("sha256:" + strings.Repeat("f", 64))
		if built.Evidence[0].SourceHash != before {
			t.Fatal("the built bundle changed after the caller mutated its input")
		}
	})
	t.Run("timestamps", func(t *testing.T) {
		source := a202BuildSource(t, a202Document(a202Pod("u1", "n1")), "capture-000001.json", contract.TerminationFinished)
		acquisition := a202Acquisition(t, []a202Source{source}, contract.TerminationFinished, nil)
		built, _, err := bundle.BuildCollectedObservation(a202Input(acquisition, 1, 0))
		if err != nil {
			t.Fatalf("build: %v", err)
		}
		recorded := *built.Provenance.StartedAt
		recordedObserved := built.Evidence[0].ObservedAt.Time
		// Mutating the input instants after the build must not rewrite them.
		*acquisition.StartedAt = contract.Timestamp{}
		if acquisition.Captures[0].Observation.ObservedAt != nil {
			*acquisition.Captures[0].Observation.ObservedAt = contract.Timestamp{}
		}
		if !built.Provenance.StartedAt.Time.Equal(recorded.Time) {
			t.Fatal("the built timestamp changed after the caller mutated the input")
		}
		if !built.Evidence[0].ObservedAt.Time.Equal(recordedObserved) {
			t.Fatal("the built observation instant changed after the caller mutated the input")
		}
	})
	t.Run("built_bundle", func(t *testing.T) {
		source := a202BuildSource(t, a202Document(a202Pod("u1", "n1")), "capture-000001.json", contract.TerminationFinished)
		acquisition := a202Acquisition(t, []a202Source{source}, contract.TerminationFinished, nil)
		first, _, err := bundle.BuildCollectedObservation(a202Input(acquisition, 1, 0))
		if err != nil {
			t.Fatalf("build: %v", err)
		}
		// Mutating the returned bundle is the caller's right: a second build of
		// the same input must still produce the original content.
		first.Subject.Name = "mutated"
		second, _, err := bundle.BuildCollectedObservation(a202Input(acquisition, 1, 0))
		if err != nil {
			t.Fatalf("second build: %v", err)
		}
		if second.Subject.Name == "mutated" {
			t.Fatal("the second build observed the mutation of the first result")
		}
	})
	t.Run("diagnostic_pointers", func(t *testing.T) {
		// The normalized DTO carries a subject diagnostic; the builder copies it
		// into the provenance and a later mutation of the caller's value cannot
		// rewrite it.
		source := a202BuildSource(t, a202IncompleteDocumentRaw(), "capture-000001.json", contract.TerminationFinished)
		acquisition := a202Acquisition(t, []a202Source{source}, contract.TerminationFinished, nil)
		built, _, err := bundle.BuildCollectedObservation(a202Input(acquisition, 1, 0))
		if err != nil {
			t.Fatalf("build: %v", err)
		}
		if len(built.Provenance.Errors) == 0 {
			t.Fatal("the incompleteness error was lost")
		}
		before := append([]string{}, built.Provenance.Errors...)
		for index := range acquisition.Captures[0].Observation.GlobalDiagnostics {
			acquisition.Captures[0].Observation.GlobalDiagnostics[index].Offset = 999999
		}
		if len(built.Provenance.Errors) != len(before) {
			t.Fatal("a later mutation changed the built provenance")
		}
	})
}

// TestA202CollectedClockGap is the T03 correction: an operation left without a
// reading is admissible only as the artifact of a failing clock that the
// run-wide record makes visible — the run must be aborted and must carry the
// global clock_invalid error. A finished run can never present an unstamped
// operation, and an unexplained gap is refused.
func TestA202CollectedClockGap(t *testing.T) {
	// gapped builds one coherent capture plus the counted attempt whose sampling
	// failed: the exact shape of a reading that never arrived.
	gapped := func(t *testing.T, termination contract.CoverageTermination, globalErrors []string) bundle.CollectedObservationInput {
		t.Helper()
		source := a202BuildSource(t, a202Document(a202Pod("u1", "n1")), "capture-000001.json", termination)
		acquisition := a202Acquisition(t, []a202Source{source}, termination, globalErrors)
		acquisition.Operations = append(acquisition.Operations, bundle.CollectedOperation{
			Verb:           "list",
			Namespace:      a202Namespace,
			Page:           2,
			RequestOrdinal: 2,
			State:          bundle.OperationFailed,
			Diagnostic:     bundle.CodeClockInvalid,
		})
		acquisition.Stats.RequestsAttempted = 2
		acquisition.Stats.ResponsesFinished = 1
		acquisition.Stats.ResponsesFailed = 1
		acquisition.Plan.RequestedOps = 2
		return a202Input(acquisition, 1, 0)
	}
	build := func(t *testing.T, input bundle.CollectedObservationInput) error {
		t.Helper()
		_, _, err := bundle.BuildCollectedObservation(input)
		return err
	}
	t.Run("control_positive", func(t *testing.T) {
		// The gap is explained: the run is aborted and the global clock failure is
		// visible, so the coherent record is admitted.
		if err := build(t, gapped(t, contract.TerminationAborted, []string{"collector: clock_invalid"})); err != nil {
			t.Fatalf("the explained gap was refused: %v", err)
		}
	})
	t.Run("closing_gap_keeps_the_acquisition_cause", func(t *testing.T) {
		// The other producer shape: the start was really sampled, the response was
		// rejected (forbidden) and the closing sampling failed. The operation keeps
		// its acquisition cause and the gap stays explained by the visible clock
		// failure of the aborted run.
		input := gapped(t, contract.TerminationAborted, []string{"collector: clock_invalid"})
		started := *input.Acquisition.StartedAt
		input.Acquisition.Operations[1].StartedAt = &started
		input.Acquisition.Operations[1].Diagnostic = bundle.CodeForbidden
		if err := build(t, input); err != nil {
			t.Fatalf("the closing gap of a rejected response was refused: %v", err)
		}
	})
	t.Run("finished_run_without_errors_refuses_the_gap", func(t *testing.T) {
		// A finished run with no visible error can never present an operation
		// without instants: the gap has no admissible explanation.
		if err := build(t, gapped(t, contract.TerminationFinished, nil)); err == nil {
			t.Fatal("a finished run with an unstamped operation was admitted")
		}
	})
	t.Run("aborted_without_the_clock_diagnostic_refuses_the_gap", func(t *testing.T) {
		// An aborted run explains the gap only through the global clock failure:
		// another visible cause leaves the missing reading unexplained.
		if err := build(t, gapped(t, contract.TerminationAborted, []string{"collector: forbidden"})); err == nil {
			t.Fatal("an unexplained gap was admitted")
		}
	})
	t.Run("elapsed_without_an_end_is_refused", func(t *testing.T) {
		// The producer never publishes an elapsed time without its closing instant:
		// both are written by the same closing sample.
		input := gapped(t, contract.TerminationAborted, []string{"collector: clock_invalid"})
		started := *input.Acquisition.StartedAt
		input.Acquisition.Operations[1].StartedAt = &started
		input.Acquisition.Operations[1].Elapsed = time.Second
		if err := build(t, input); err == nil {
			t.Fatal("an elapsed time without its closing instant was admitted")
		}
	})
	t.Run("finished_operation_without_its_end_is_refused", func(t *testing.T) {
		// An operation that reached its end cannot lack the closing reading: the
		// gap belongs to a failed attempt, never to a finished one. The diagnostic
		// is a real acquisition cause, so only the state of the operation can
		// refuse this record.
		input := gapped(t, contract.TerminationAborted, []string{"collector: clock_invalid"})
		started := *input.Acquisition.StartedAt
		input.Acquisition.Operations[1].StartedAt = &started
		input.Acquisition.Operations[1].State = bundle.OperationFinished
		input.Acquisition.Operations[1].Diagnostic = bundle.CodeForbidden
		if err := build(t, input); err == nil {
			t.Fatal("a finished operation without its closing reading was admitted")
		}
	})
	t.Run("closing_gap_with_an_unknown_diagnostic_is_refused", func(t *testing.T) {
		// The preserved cause of a failed operation belongs to the closed catalog:
		// a code the acquisition could never classify leaves the failure of the
		// operation without a real cause.
		input := gapped(t, contract.TerminationAborted, []string{"collector: clock_invalid"})
		started := *input.Acquisition.StartedAt
		input.Acquisition.Operations[1].StartedAt = &started
		input.Acquisition.Operations[1].Diagnostic = bundle.CollectionCode("synthetic_unknown")
		if err := build(t, input); err == nil {
			t.Fatal("a closing gap with an unknown diagnostic was admitted")
		}
	})
	t.Run("closing_gap_with_an_empty_diagnostic_is_refused", func(t *testing.T) {
		// A failed operation always carries the cause it classified: an empty
		// diagnostic is not a cause.
		input := gapped(t, contract.TerminationAborted, []string{"collector: clock_invalid"})
		started := *input.Acquisition.StartedAt
		input.Acquisition.Operations[1].StartedAt = &started
		input.Acquisition.Operations[1].Diagnostic = ""
		if err := build(t, input); err == nil {
			t.Fatal("a closing gap with an empty diagnostic was admitted")
		}
	})
	t.Run("closing_gap_with_a_comparison_diagnostic_is_refused", func(t *testing.T) {
		// A comparison code describes a difference between observations, never a
		// failed request: it cannot be the preserved cause of the gap.
		input := gapped(t, contract.TerminationAborted, []string{"collector: clock_invalid"})
		started := *input.Acquisition.StartedAt
		input.Acquisition.Operations[1].StartedAt = &started
		input.Acquisition.Operations[1].Diagnostic = bundle.CodeObservationChanged
		if err := build(t, input); err == nil {
			t.Fatal("a closing gap with a comparison diagnostic was admitted")
		}
	})
	t.Run("closing_gap_with_a_pre_attempt_cause_is_refused", func(t *testing.T) {
		// The request guard aborts the run before the attempt is recorded: the
		// producer never writes this cause on a failed operation.
		input := gapped(t, contract.TerminationAborted, []string{"collector: clock_invalid"})
		started := *input.Acquisition.StartedAt
		input.Acquisition.Operations[1].StartedAt = &started
		input.Acquisition.Operations[1].Diagnostic = bundle.CodeRequestNotAllowed
		if err := build(t, input); err == nil {
			t.Fatal("a closing gap with a pre-attempt cause was admitted")
		}
	})
	t.Run("closing_gap_with_a_pre_attempt_budget_is_refused", func(t *testing.T) {
		// The request budget fires before the attempt is recorded as well: it is
		// a run-wide refusal, never the diagnostic of a failed operation.
		input := gapped(t, contract.TerminationAborted, []string{"collector: clock_invalid"})
		started := *input.Acquisition.StartedAt
		input.Acquisition.Operations[1].StartedAt = &started
		input.Acquisition.Operations[1].Diagnostic = bundle.CodeRequestLimit
		if err := build(t, input); err == nil {
			t.Fatal("a closing gap with a pre-attempt budget was admitted")
		}
	})
	t.Run("closing_gap_with_a_post_attempt_budget_is_refused", func(t *testing.T) {
		// The retained-source budget closes the run after the response was fully
		// admitted: its operation stays finished and carries no failure
		// diagnostic, so the code never labels a failed attempt.
		input := gapped(t, contract.TerminationAborted, []string{"collector: clock_invalid"})
		started := *input.Acquisition.StartedAt
		input.Acquisition.Operations[1].StartedAt = &started
		input.Acquisition.Operations[1].Diagnostic = bundle.CodeOutputLimit
		if err := build(t, input); err == nil {
			t.Fatal("a closing gap with a post-attempt budget was admitted")
		}
	})
}
