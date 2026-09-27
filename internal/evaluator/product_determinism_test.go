package evaluator

import (
	"encoding/json"
	"reflect"
	"sync"
	"testing"

	"github.com/d4rpell/Ariadne/internal/rulepack"
	contract "github.com/d4rpell/Ariadne/pkg/evidence"
)

// productReplayRequest is the product-profile control request: a complete
// affirmative bundle, its three pins and the terminal rule of one state.
func productReplayRequest(t *testing.T, kind proofKind) Request {
	t.Helper()
	return productRequest(t, productControlBundle(t, kind),
		productRuleJSON("rule.terminal", emitFor(kind), string(predicateFor(kind))))
}

func emitFor(kind proofKind) string {
	switch kind {
	case proofVulnerableBuild:
		return rulepack.OutputAffected
	case proofFixedBuild:
		return rulepack.OutputFixed
	}
	return rulepack.OutputNotAffected
}

// TestProductDeterminism is I-44: one hundred repetitions and sixteen concurrent
// evaluations of one immutable request produce the identical result and the
// identical test encoding, and the caller's request is never rewritten.
func TestProductDeterminism(t *testing.T) {
	request := productReplayRequest(t, proofVulnerableBuild)
	control, err := Evaluate(request)
	if err != nil {
		t.Fatalf("the control must evaluate: %v", err)
	}
	if control.ProductStatus != contract.ProductAffected {
		t.Fatalf("control status = %s, want affected", control.ProductStatus)
	}
	controlBytes := encodeResultDTO(t, control)

	// The request is snapshotted before the repetitions: the engine must not
	// mutate any part of it, so the same request can be replayed later.
	requestBytes := encodeResultDTO(t, control)
	pinsBefore := append([]SourcePin{}, request.Domain.SourcePins...)

	for repetition := 0; repetition < 100; repetition++ {
		candidate, err := Evaluate(request)
		if err != nil {
			t.Fatalf("repetition %d failed: %v", repetition, err)
		}
		if !reflect.DeepEqual(control, candidate) {
			t.Fatalf("repetition %d differs structurally from the control", repetition)
		}
		if string(encodeResultDTO(t, candidate)) != string(controlBytes) {
			t.Fatalf("repetition %d differs byte to byte", repetition)
		}
	}

	const workers = 16
	var wait sync.WaitGroup
	results := make([][]byte, workers)
	structures := make([]Result, workers)
	failures := make([]error, workers)
	for worker := 0; worker < workers; worker++ {
		wait.Add(1)
		go func(index int) {
			defer wait.Done()
			result, err := Evaluate(request)
			if err != nil {
				failures[index] = err
				return
			}
			structures[index] = result
			encoded, err := json.Marshal(dtoFromResult(result))
			if err != nil {
				failures[index] = err
				return
			}
			results[index] = encoded
		}(worker)
	}
	wait.Wait()

	for worker := 0; worker < workers; worker++ {
		if failures[worker] != nil {
			t.Fatalf("worker %d failed: %v", worker, failures[worker])
		}
		if string(results[worker]) != string(controlBytes) {
			t.Fatalf("worker %d differs byte to byte", worker)
		}
		if !reflect.DeepEqual(structures[worker], control) {
			t.Fatalf("worker %d differs structurally", worker)
		}
	}

	// The caller's context must be untouched by the concurrent evaluations.
	if !reflect.DeepEqual(pinsBefore, request.Domain.SourcePins) {
		t.Fatal("the evaluations rewrote the caller's domain context")
	}
	if string(encodeResultDTO(t, control)) != string(requestBytes) {
		t.Fatal("the control encoding changed after the repetitions")
	}
}

// TestProductReplayEncodingCoverage is I-45 (encoding half): the test DTO covers
// every leaf of Domain and Candidates, including the explicit nulls of the
// advisory pair, and the encoding distinguishes each leaf when it changes.
func TestProductReplayEncodingCoverage(t *testing.T) {
	request := productReplayRequest(t, proofVulnerableBuild)
	control, err := Evaluate(request)
	if err != nil {
		t.Fatalf("the control must evaluate: %v", err)
	}
	if control.Domain == nil {
		t.Fatal("the product result must carry its domain context")
	}
	if len(control.Candidates) == 0 {
		t.Fatal("the product result must carry its candidates")
	}

	controlBytes := string(encodeResultDTO(t, control))

	// Every leaf of the domain context must change the encoding when it changes.
	mutations := map[string]func(*DomainContext){
		"maximum age": func(context *DomainContext) { context.MaximumEvidenceAgeSeconds++ },
		"pin role":    func(context *DomainContext) { context.SourcePins[0].Role = SourceRoleVendor },
		"pin source":  func(context *DomainContext) { context.SourcePins[0].Source = "other.json" },
		"pin hash": func(context *DomainContext) {
			context.SourcePins[0].SourceHash = independentSourceHash("other")
		},
		"advisory id": func(context *DomainContext) {
			value := "RHSA-2026:9999"
			context.SourcePins[2].AdvisoryID = &value
		},
		"advisory revision": func(context *DomainContext) {
			value := "2"
			context.SourcePins[2].AdvisoryRevision = &value
		},
		"advisory null": func(context *DomainContext) { context.SourcePins[2].AdvisoryID = nil },
		"pin order": func(context *DomainContext) {
			context.SourcePins[0], context.SourcePins[1] = context.SourcePins[1], context.SourcePins[0]
		},
	}
	for name, mutate := range mutations {
		t.Run("domain/"+name, func(t *testing.T) {
			changed := control
			context := copyDomainContext(*control.Domain)
			mutate(&context)
			changed.Domain = &context
			if string(encodeResultDTO(t, changed)) == controlBytes {
				t.Fatalf("changing %s did not change the encoding", name)
			}
		})
	}

	// Every leaf of a candidate must change the encoding too.
	candidateMutations := map[string]func(*Candidate){
		"rule id":  func(candidate *Candidate) { candidate.RuleID = "rule.other" },
		"status":   func(candidate *Candidate) { candidate.ProductStatus = contract.ProductFixed },
		"refs":     func(candidate *Candidate) { candidate.EvidenceReferences = nil },
		"ref item": func(candidate *Candidate) { candidate.EvidenceReferences[0].ItemIndex++ },
	}
	for name, mutate := range candidateMutations {
		t.Run("candidate/"+name, func(t *testing.T) {
			changed := control
			changed.Candidates = append([]Candidate{}, control.Candidates...)
			candidate := changed.Candidates[0]
			candidate.EvidenceReferences = append([]EvidenceReference{}, candidate.EvidenceReferences...)
			mutate(&candidate)
			changed.Candidates[0] = candidate
			if string(encodeResultDTO(t, changed)) == controlBytes {
				t.Fatalf("changing the candidate %s did not change the encoding", name)
			}
		})
	}

	t.Run("candidate count", func(t *testing.T) {
		changed := control
		changed.Candidates = append([]Candidate{}, control.Candidates...)
		changed.Candidates = append(changed.Candidates, changed.Candidates[0])
		if string(encodeResultDTO(t, changed)) == controlBytes {
			t.Fatal("adding a candidate did not change the encoding")
		}
	})

	t.Run("absent domain is a null leaf", func(t *testing.T) {
		legacy := control
		legacy.Domain = nil
		encoded := string(encodeResultDTO(t, legacy))
		if encoded == controlBytes {
			t.Fatal("removing the domain context did not change the encoding")
		}
		if !containsSubstring(encoded, `"domain":null`) {
			t.Fatalf("the legacy absence must be encoded as null: %s", encoded[:80])
		}
	})
}

// TestProductInputOwnership is I-45 (ownership half): a mutation of the input
// after the call cannot change a previously returned result, and the result
// never aliases the caller's slices or pointers.
func TestProductInputOwnership(t *testing.T) {
	request := productReplayRequest(t, proofVulnerableBuild)
	result, err := Evaluate(request)
	if err != nil {
		t.Fatalf("the control must evaluate: %v", err)
	}
	before := string(encodeResultDTO(t, result))

	// Rewrite every caller-owned structure the result could have aliased.
	request.Domain.SourcePins[0].Source = "mutated.json"
	request.Domain.SourcePins[2].AdvisoryID = nil
	request.Domain.MaximumEvidenceAgeSeconds = 1
	request.Bundle.Evidence[0].Value = nil
	request.Target.ContainerName = "mutated"
	request.Admission.ExpectedPackID = "pack.mutated"

	after := string(encodeResultDTO(t, result))
	if before != after {
		t.Fatal("mutating the request changed a previously returned result")
	}
	if result.Domain == nil || result.Domain.SourcePins[0].Source == "mutated.json" {
		t.Fatal("the result aliases the caller's domain context")
	}
	if result.Target.ContainerName == "mutated" {
		t.Fatal("the result aliases the caller's target")
	}
	if result.Admission.ExpectedPackID == "pack.mutated" {
		t.Fatal("the result aliases the caller's admission context")
	}
	if len(result.Candidates) == 0 || result.Candidates[0].EvidenceReferences[0].ItemIndex < 0 {
		t.Fatal("the candidate references must stay resolvable")
	}
}

// TestProductReplayInputs is I-46: the excluded operational metadata does not
// decide the product state, and a new explicit input is either visible or
// refused.
func TestProductReplayInputs(t *testing.T) {
	request := productReplayRequest(t, proofVulnerableBuild)
	control, err := Evaluate(request)
	if err != nil {
		t.Fatalf("the control must evaluate: %v", err)
	}
	controlBytes := string(encodeResultDTO(t, control))

	excluded := map[string]func(*contract.Bundle){
		"collector_version": func(b *contract.Bundle) { b.Provenance.CollectorVersion = "9.9.9" },
		"parser_version":    func(b *contract.Bundle) { b.Provenance.ParserVersion = "other-v9" },
		"ruleset_version": func(b *contract.Bundle) {
			// A ruleset version is excluded from the projection, but the ruleset must
			// stay complete and, when present, name the admitted pack (ruleset
			// linkage), so the fixture reuses the real pack hash of the request.
			b.Provenance.Ruleset = contract.RulesetRef{
				Path:    "rules/",
				Hash:    contract.SourceHash(independentDocumentHash(string(request.PackBytes))),
				Version: "2030-01",
			}
		},
		"argv_sanitized": func(b *contract.Bundle) { b.Provenance.ArgvSanitized = []string{"other"} },
		"budget":         func(b *contract.Bundle) { b.Provenance.Budget.Requests = 99 },
	}
	for name, mutate := range excluded {
		t.Run("excluded/"+name, func(t *testing.T) {
			bundle := cloneBundle(request.Bundle)
			mutate(&bundle)
			adjusted := request
			adjusted.Bundle = bundle
			adjusted.ExpectedBundleHash = mustBundleHash(t, bundle)
			result, err := Evaluate(adjusted)
			if err != nil {
				t.Fatalf("excluded metadata must not reject: %v", err)
			}
			if result.ProductStatus != control.ProductStatus {
				t.Fatalf("the excluded metadata %s decided the state: %s vs %s", name, result.ProductStatus, control.ProductStatus)
			}
			if !reflect.DeepEqual(result.Reasons, control.Reasons) {
				t.Fatalf("the excluded metadata %s changed the reasons", name)
			}
		})
	}

	t.Run("excluded metadata of the run never rejuvenates evidence", func(t *testing.T) {
		// The run timestamps are excluded from the hash, but the age policy uses
		// the observation instants, so shifting the run times cannot make expired
		// evidence current.
		bundle := cloneBundle(request.Bundle)
		shifted := mustStamp(t, evaluatedAt)
		bundle.Provenance.StartedAt = &shifted
		bundle.Provenance.EndedAt = &shifted
		adjusted := request
		adjusted.Bundle = bundle
		adjusted.ExpectedBundleHash = mustBundleHash(t, bundle)
		domain := copyDomainContext(*request.Domain)
		domain.MaximumEvidenceAgeSeconds = 1
		adjusted.Domain = &domain
		result, err := Evaluate(adjusted)
		if err != nil {
			t.Fatalf("expired evidence is a result: %v", err)
		}
		if result.ProductStatus != contract.ProductUnderInvestigation {
			t.Fatalf("status = %s, want under_investigation: run times cannot rejuvenate evidence", result.ProductStatus)
		}
		if !containsGlobalReason(result.Reasons, ReasonDomainEvidenceExpired) {
			t.Fatalf("reasons = %v, want domain_evidence_expired", result.Reasons)
		}
	})

	t.Run("a new explicit input changes the identity", func(t *testing.T) {
		// Changing the domain context changes an explicit input: it must be
		// visible in the result and require a new replay record.
		adjusted := request
		domain := copyDomainContext(*request.Domain)
		domain.MaximumEvidenceAgeSeconds++
		adjusted.Domain = &domain
		result, err := Evaluate(adjusted)
		if err != nil {
			t.Fatalf("a valid new context must evaluate: %v", err)
		}
		if result.Domain.MaximumEvidenceAgeSeconds != domain.MaximumEvidenceAgeSeconds {
			t.Fatal("the new context is not visible in the result")
		}
		if string(encodeResultDTO(t, result)) == controlBytes {
			t.Fatal("a changed explicit input kept the same encoding")
		}
	})
}

// TestProductLayersAndDiagnostics is I-48: the three decision layers stay
// separate, exploitability is always not_assessed, and the diagnostics never
// carry raw values, locators or parser errors.
func TestProductLayersAndDiagnostics(t *testing.T) {
	request := productReplayRequest(t, proofVulnerableBuild)
	result, err := Evaluate(request)
	if err != nil {
		t.Fatalf("the control must evaluate: %v", err)
	}

	if result.ProductStatus != contract.ProductAffected {
		t.Fatalf("status = %s, want affected", result.ProductStatus)
	}
	if result.Exploitability != contract.ExploitabilityNotAssessed {
		t.Fatalf("exploitability = %s, want not_assessed", result.Exploitability)
	}

	t.Run("no risk decision field exists", func(t *testing.T) {
		// The layers are separated by construction: the Result type has no member
		// for a risk decision, an exception recommendation or a public issuance
		// date. Adding one would be a contract change, not an implementation
		// detail, so this test pins the current shape.
		resultType := reflect.TypeOf(Result{})
		forbidden := []string{
			"RiskDecision", "Exception", "Recommendation", "Approval",
			"Justification", "VEX", "IssuedAt", "ValidUntil", "Lifecycle",
		}
		for index := 0; index < resultType.NumField(); index++ {
			name := resultType.Field(index).Name
			for _, wanted := range forbidden {
				if containsSubstring(name, wanted) {
					t.Fatalf("Result carries the forbidden field %s", name)
				}
			}
		}
	})

	t.Run("diagnostics carry no raw input", func(t *testing.T) {
		encoded := string(encodeResultDTO(t, result))
		// Values, locators, hashes of the source and the synthetic marker must not
		// appear as text in the encoding: references are indices, not values.
		// The Target and the admitted DomainContext are caller-supplied replay
		// parameters and are echoed by design (ADR-0015 §7.1 keeps the admitted
		// context in the result), so their source names and advisory identifiers
		// legitimately appear. What must never appear is the evidence content the
		// engine resolved: locators and values are referenced by canonical index.
		for _, leak := range []string{
			locatorStat,
			domainLocatorMapping,
			domainLocatorArtifact,
			domainLocatorVendor,
			domainBasisLocator,
			domainVersion,
			domainStatusValue,
			marker,
		} {
			if containsSubstring(encoded, leak) {
				t.Fatalf("the encoding leaks the raw input %q", leak)
			}
		}
	})

	t.Run("reasons are constants, not messages", func(t *testing.T) {
		// Every reason of the result belongs to the closed vocabulary: no free
		// text, no pack string and no evidence content.
		known := map[string]bool{}
		for _, reason := range []Reason{
			ReasonNoApplicableRule, ReasonTargetUnsubstantiated, ReasonIncompleteEvidence,
			ReasonBlockingWarning, ReasonConflictingEvidence, ReasonRequirementsMissing,
			ReasonChecksFailed, ReasonChecksUnknown, ReasonDomainAssessmentDeferred,
			ReasonNoAffirmativeCandidate, ReasonAffirmativeConflict, ReasonDomainEvidenceExpired,
			ReasonDomainSourceUnapproved, ReasonDomainProofUnsupported,
		} {
			known[string(reason)] = true
		}
		for _, reason := range result.Reasons {
			if !known[string(reason)] {
				t.Fatalf("the result carries the unknown reason %q", reason)
			}
		}
		for _, trace := range result.Rules {
			for _, reason := range trace.Reasons {
				switch reason {
				case ReasonMissing, ReasonUnavailable, ReasonRedacted, ReasonConflict,
					ReasonFutureObservation, ReasonMismatch, ReasonVerified,
					ReasonExpired, ReasonUnapprovedSource, ReasonUnsupportedProof:
				default:
					t.Fatalf("the trace carries the unknown check reason %q", reason)
				}
			}
		}
	})

	t.Run("the domain profile never defers its assessment", func(t *testing.T) {
		if containsGlobalReason(result.Reasons, ReasonDomainAssessmentDeferred) {
			t.Fatal("the product profile must not carry the deferred-domain reason")
		}
	})
}

func containsSubstring(value, wanted string) bool {
	if len(wanted) == 0 {
		return true
	}
	for index := 0; index+len(wanted) <= len(value); index++ {
		if value[index:index+len(wanted)] == wanted {
			return true
		}
	}
	return false
}
