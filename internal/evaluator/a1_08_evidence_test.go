package evaluator

import (
	"reflect"
	"strings"
	"testing"
	"time"

	contract "github.com/d4rpell/Ariadne/pkg/evidence"
)

// a108ProductKinds are the three affirmative controls E02 must start from.
var a108ProductKinds = []proofKind{proofVulnerableBuild, proofFixedBuild, proofCodeExcludedBuild}

// a108ExpectedStatus maps each control proof onto the state it sustains.
func a108ExpectedStatus(kind proofKind) contract.ProductStatus {
	switch kind {
	case proofVulnerableBuild:
		return contract.ProductAffected
	case proofFixedBuild:
		return contract.ProductFixed
	}
	return contract.ProductNotAffected
}

// a108TerminalFor is the predicate that reads each control proof.
func a108TerminalFor(kind proofKind) string {
	return string(predicateFor(kind))
}

// a108AffirmativeRequest assembles the control request of one proof kind and
// asserts its control status, so no negative case can start from a broken
// fixture.
func a108AffirmativeRequest(t *testing.T, kind proofKind) (Request, Result) {
	t.Helper()
	request := productRequest(t, productControlBundle(t, kind),
		productRuleJSON("rule.terminal", emitFor(kind), a108TerminalFor(kind)))
	result, err := Evaluate(request)
	if err != nil {
		t.Fatalf("control %s must evaluate: %v", kind, err)
	}
	if result.ProductStatus != a108ExpectedStatus(kind) {
		t.Fatalf("control %s produced %s, want %s", kind, result.ProductStatus, a108ExpectedStatus(kind))
	}
	return request, result
}

// a108Rehash recomputes the bundle projection hash after a semantic change, so a
// negative case exercises the domain semantics instead of stopping at an
// integrity error.
func a108Rehash(t *testing.T, request Request) Request {
	t.Helper()
	rehashed := request
	rehashed.ExpectedBundleHash = mustBundleHash(t, rehashed.Bundle)
	return rehashed
}

// TestA108IncompleteEvidence covers E02 and I-01/I-10: every semantic negative
// starts from each affirmative control, the mutated bundle stays a valid wire
// value, and the outcome is always under_investigation with err == nil — never a
// structural rejection, which would prove nothing about incomplete evidence.
// Each case asserts its own reasons and the absence of an affirmative candidate.
func TestA108IncompleteEvidence(t *testing.T) {
	// a108Reason is the exact expectation of one negative case: the reason set
	// and whether an evaluated branch stays visible as a candidate.
	type a108Reason struct {
		reasons       []Reason
		withCandidate bool
	}
	for _, kind := range a108ProductKinds {
		t.Run(string(kind), func(t *testing.T) {
			controlRequest, _ := a108AffirmativeRequest(t, kind)

			cases := []struct {
				name   string
				mutate func(*Request)
				want   a108Reason
			}{
				{"evidence emptied", func(request *Request) {
					request.Bundle.Evidence = []contract.EvidenceItem{}
				}, a108Reason{reasons: []Reason{ReasonDomainSourceUnapproved, ReasonRequirementsMissing, ReasonTargetUnsubstantiated}}},
				{"mapping removed", func(request *Request) {
					request.Bundle.Evidence = withoutPrefix(request.Bundle.Evidence, "product_v1.mapping.")
				}, a108Reason{reasons: []Reason{ReasonDomainSourceUnapproved, ReasonRequirementsMissing}}},
				{"artifact removed", func(request *Request) {
					request.Bundle.Evidence = withoutPrefix(request.Bundle.Evidence, "product_v1.artifact.")
				}, a108Reason{reasons: []Reason{ReasonDomainSourceUnapproved, ReasonRequirementsMissing}}},
				{"vendor proof removed", func(request *Request) {
					request.Bundle.Evidence = withoutPrefix(request.Bundle.Evidence, "product_v1.vendor.")
				}, a108Reason{reasons: []Reason{ReasonDomainSourceUnapproved, ReasonRequirementsMissing}}},
				{"row removed", func(request *Request) {
					request.Bundle.Evidence = withoutPrefix(request.Bundle.Evidence, "prisma_v1.")
				}, a108Reason{reasons: []Reason{ReasonDomainSourceUnapproved, ReasonRequirementsMissing, ReasonTargetUnsubstantiated}}},
				{"observation removed", func(request *Request) {
					request.Bundle.Evidence = withoutPrefix(request.Bundle.Evidence, "container_status.")
				}, a108Reason{reasons: []Reason{ReasonDomainSourceUnapproved, ReasonRequirementsMissing, ReasonTargetUnsubstantiated}}},
				{"incomplete import declared", func(request *Request) {
					total := uint64(2)
					request.Bundle.Provenance.Completeness = contract.CompletenessPartial
					request.Bundle.Provenance.Coverage.Rows = &contract.CoverageRows{Total: &total, Accepted: 1, Rejected: 1}
					request.Bundle.Provenance.Errors = []string{"ingest: prisma-v1: record/2/bytes/40-90: invalid schema version"}
				}, a108Reason{reasons: []Reason{ReasonIncompleteEvidence, ReasonRequirementsMissing}}},
				{"unknown completeness declared", func(request *Request) {
					request.Bundle.Provenance.Completeness = contract.CompletenessUnknown
					request.Bundle.Provenance.Errors = []string{"ingest: prisma-v1: byte/10: invalid CSV structure"}
				}, a108Reason{reasons: []Reason{ReasonIncompleteEvidence, ReasonRequirementsMissing}}},
				{"abort recorded as error", func(request *Request) {
					request.Bundle.Provenance.Completeness = contract.CompletenessPartial
					request.Bundle.Provenance.Coverage.Termination = contract.TerminationAborted
					request.Bundle.Provenance.Coverage.Rows.Total = nil
					request.Bundle.Provenance.Errors = []string{"ingest: prisma-v1: byte/10: invalid CSV structure"}
				}, a108Reason{reasons: []Reason{ReasonIncompleteEvidence, ReasonRequirementsMissing}}},
				{"blocking warning present", func(request *Request) {
					request.Bundle.Provenance.Warnings = []contract.Warning{{
						Code:    "unknown_code_from_a_future_source",
						Class:   contract.WarningContradictory,
						Message: "synthetic blocking warning",
					}}
				}, a108Reason{reasons: []Reason{ReasonBlockingWarning}, withCandidate: true}},
				{"mapping item declared unavailable", func(request *Request) {
					// ADR-0006 §2: an unavailable item keeps its observed_at and
					// abandons its value; the wire stays valid and the record can no
					// longer be completed from it.
					for index := range request.Bundle.Evidence {
						item := &request.Bundle.Evidence[index]
						if item.Type != "product_v1.mapping.package_name" {
							continue
						}
						item.Confidence = contract.ProvenanceUnavailable
						item.Value = nil
						item.ValueHash = nil
					}
				}, a108Reason{reasons: []Reason{ReasonDomainProofUnsupported, ReasonDomainSourceUnapproved, ReasonRequirementsMissing}}},
				{"value omitted but hash kept", func(request *Request) {
					target := &request.Bundle.Evidence[0]
					for index := range request.Bundle.Evidence {
						if request.Bundle.Evidence[index].Type == "prisma_v1.package_name" {
							target = &request.Bundle.Evidence[index]
						}
					}
					target.Value = nil
				}, a108Reason{reasons: []Reason{ReasonDomainSourceUnapproved, ReasonRequirementsMissing}}},
			}
			for _, tc := range cases {
				t.Run(tc.name, func(t *testing.T) {
					request := controlRequest
					request.Bundle = cloneBundle(controlRequest.Bundle)
					tc.mutate(&request)
					request = a108Rehash(t, request)

					result, err := Evaluate(request)
					if err != nil {
						// A structural rejection would not exercise incomplete
						// evidence at all: the mutated bundle must stay valid.
						t.Fatalf("%s: unexpected rejection of a valid incomplete bundle: %v", tc.name, err)
					}
					if result.ProductStatus != contract.ProductUnderInvestigation {
						t.Fatalf("%s: status = %s, want under_investigation", tc.name, result.ProductStatus)
					}
					if result.Exploitability != contract.ExploitabilityNotAssessed {
						t.Fatalf("%s: exploitability = %s, want not_assessed", tc.name, result.Exploitability)
					}
					if !reflect.DeepEqual(result.Reasons, tc.want.reasons) {
						t.Fatalf("%s: reasons = %v, want %v", tc.name, result.Reasons, tc.want.reasons)
					}
					if tc.want.withCandidate {
						if len(result.Candidates) == 0 {
							t.Fatalf("%s: the evaluated branch must stay visible", tc.name)
						}
						return
					}
					if len(result.Candidates) != 0 {
						t.Fatalf("%s: an inconclusive result must carry no affirmative candidate", tc.name)
					}
				})
			}
		})
	}

	t.Run("readiness profile is always inconclusive", func(t *testing.T) {
		result := evaluate(t, baseRequest(t))
		if result.ProductStatus != contract.ProductUnderInvestigation {
			t.Fatalf("readiness status = %s, want under_investigation", result.ProductStatus)
		}
		if len(result.Candidates) != 0 {
			t.Fatal("the readiness profile must not emit candidates")
		}
	})
}

// withoutPrefix removes every evidence item whose type starts with the prefix.
func withoutPrefix(items []contract.EvidenceItem, prefix string) []contract.EvidenceItem {
	kept := make([]contract.EvidenceItem, 0, len(items))
	for _, item := range items {
		if strings.HasPrefix(item.Type, prefix) {
			continue
		}
		kept = append(kept, item)
	}
	return kept
}

// TestA108RequiredLinks covers E03: removing one required link of the chain
// never leaves an affirmative status, and a missing requirement leaves the rule
// in missing_evidence with no invented checks.
func TestA108RequiredLinks(t *testing.T) {
	linkPrefixes := []struct {
		name   string
		prefix string
	}{
		{"mapping", "product_v1.mapping."},
		{"artifact", "product_v1.artifact."},
		{"vendor proof", "product_v1.vendor."},
		{"vulnerability id", "prisma_v1.vulnerability_id"},
		{"package name", "prisma_v1.package_name"},
		{"image id", TypeImageID},
		{"normalized digest", TypeNormalizedDigest},
	}
	for _, link := range linkPrefixes {
		t.Run(link.name, func(t *testing.T) {
			request, _ := a108AffirmativeRequest(t, proofVulnerableBuild)
			request.Bundle = cloneBundle(request.Bundle)
			request.Bundle.Evidence = withoutPrefix(request.Bundle.Evidence, link.prefix)
			request = a108Rehash(t, request)

			result, err := Evaluate(request)
			if err != nil {
				t.Fatalf("removing %s from a valid bundle is uncertainty, not a rejection: %v", link.name, err)
			}
			if result.ProductStatus != contract.ProductUnderInvestigation {
				t.Fatalf("status = %s, want under_investigation", result.ProductStatus)
			}
			if !containsGlobalReason(result.Reasons, ReasonRequirementsMissing) {
				t.Fatalf("removing %s: reasons = %v, want requirements_missing", link.name, result.Reasons)
			}
			// A missing requirement leaves the rule in missing_evidence; the
			// trace never invents a check that was not run.
			for _, trace := range result.Rules {
				if trace.State == RuleMissingEvidence && len(trace.Checks) != 0 {
					t.Fatalf("rule %s is missing_evidence but carries %d checks", trace.RuleID, len(trace.Checks))
				}
				if trace.State == RuleChecked {
					for _, check := range trace.Checks {
						if check.Outcome == OutcomePass && len(check.Reasons) == 0 {
							t.Fatalf("check %s passed with no reason", check.CheckID)
						}
					}
				}
			}
		})
	}

	t.Run("a missing requirement never invents an executed check", func(t *testing.T) {
		bundle := productBundle(t, mappingItems(t, baseSubject(t), containerA)...)
		request := productRequest(t, bundle,
			productRuleJSON("rule.terminal", emitFor(proofVulnerableBuild), a108TerminalFor(proofVulnerableBuild)))
		result, err := Evaluate(request)
		if err != nil {
			t.Fatalf("a bundle without domain proof is uncertainty, not a rejection: %v", err)
		}
		if result.ProductStatus != contract.ProductUnderInvestigation {
			t.Fatalf("status = %s, want under_investigation", result.ProductStatus)
		}
		missing := 0
		for _, trace := range result.Rules {
			if trace.State == RuleMissingEvidence {
				missing++
				if len(trace.Checks) != 0 {
					t.Fatalf("missing_evidence trace carries checks: %+v", trace.Checks)
				}
				if len(trace.MissingRequirements) == 0 {
					t.Fatal("a missing_evidence rule must name its missing requirements")
				}
			}
		}
		if missing == 0 {
			t.Fatal("the rule must be reported as missing_evidence")
		}
	})
}

// TestA108ProvenanceIsolation covers E04: separating each component of the
// provenance tuple prevents a record from being completed from another locator,
// timestamp or source.
func TestA108ProvenanceIsolation(t *testing.T) {
	t.Run("a mapping item split off its group does not complete the record", func(t *testing.T) {
		request, _ := a108AffirmativeRequest(t, proofVulnerableBuild)
		request.Bundle = cloneBundle(request.Bundle)
		// Exactly one mapping item moves to a foreign locator: the record is now
		// incomplete on its own provenance tuple, and the remaining items must not
		// complete it from another locator.
		for index := range request.Bundle.Evidence {
			if request.Bundle.Evidence[index].Type == "product_v1.mapping.method" {
				request.Bundle.Evidence[index].Locator = contract.SourceLocator("records/mapping/9")
				break
			}
		}
		request = a108Rehash(t, request)
		result, err := Evaluate(request)
		if err != nil {
			t.Fatalf("a valid bundle missing one provenance link is uncertainty, not a rejection: %v", err)
		}
		if result.ProductStatus != contract.ProductUnderInvestigation {
			t.Fatalf("status = %s, want under_investigation", result.ProductStatus)
		}
		// The observable of the split provenance is not only the status: the
		// unsupported proof and the unapproved source are the reasons the record
		// cannot be completed, and losing them would hide the cause.
		if want := []Reason{ReasonDomainProofUnsupported, ReasonDomainSourceUnapproved, ReasonRequirementsMissing}; !reflect.DeepEqual(result.Reasons, want) {
			t.Fatalf("a split mapping: reasons = %v, want %v", result.Reasons, want)
		}
	})

	t.Run("a mapping item with a foreign source hash does not complete the record", func(t *testing.T) {
		request, _ := a108AffirmativeRequest(t, proofVulnerableBuild)
		request.Bundle = cloneBundle(request.Bundle)
		for index := range request.Bundle.Evidence {
			if request.Bundle.Evidence[index].Type == "product_v1.mapping.method" {
				request.Bundle.Evidence[index].SourceHash = contract.SourceHash(independentDocumentHash("another mapping source"))
				break
			}
		}
		request = a108Rehash(t, request)
		result, err := Evaluate(request)
		if err != nil {
			t.Fatalf("a valid bundle missing one provenance link is uncertainty, not a rejection: %v", err)
		}
		if result.ProductStatus != contract.ProductUnderInvestigation {
			t.Fatalf("status = %s, want under_investigation", result.ProductStatus)
		}
		if want := []Reason{ReasonDomainProofUnsupported, ReasonDomainSourceUnapproved, ReasonRequirementsMissing}; !reflect.DeepEqual(result.Reasons, want) {
			t.Fatalf("a foreign source hash: reasons = %v, want %v", result.Reasons, want)
		}
	})

	t.Run("a mapping item with a foreign timestamp does not complete the record", func(t *testing.T) {
		request, _ := a108AffirmativeRequest(t, proofVulnerableBuild)
		request.Bundle = cloneBundle(request.Bundle)
		other := mustStamp(t, sourceObservedAt.Add(-24*time.Hour))
		for index := range request.Bundle.Evidence {
			if request.Bundle.Evidence[index].Type == "product_v1.mapping.method" {
				request.Bundle.Evidence[index].ObservedAt = &other
				break
			}
		}
		request = a108Rehash(t, request)
		result, err := Evaluate(request)
		if err != nil {
			t.Fatalf("a valid bundle missing one provenance link is uncertainty, not a rejection: %v", err)
		}
		if result.ProductStatus != contract.ProductUnderInvestigation {
			t.Fatalf("status = %s, want under_investigation", result.ProductStatus)
		}
		if want := []Reason{ReasonDomainProofUnsupported, ReasonDomainSourceUnapproved, ReasonRequirementsMissing}; !reflect.DeepEqual(result.Reasons, want) {
			t.Fatalf("a foreign timestamp: reasons = %v, want %v", result.Reasons, want)
		}
	})

	t.Run("a vendor proof from another revision does not complete the record", func(t *testing.T) {
		request, _ := a108AffirmativeRequest(t, proofVulnerableBuild)
		request.Bundle = cloneBundle(request.Bundle)
		for index := range request.Bundle.Evidence {
			if request.Bundle.Evidence[index].Type == "product_v1.vendor.advisory_revision" {
				replaceValue(&request.Bundle.Evidence[index], "9")
			}
		}
		request = a108Rehash(t, request)
		result, err := Evaluate(request)
		if err != nil {
			t.Fatalf("a valid bundle missing one provenance link is uncertainty, not a rejection: %v", err)
		}
		if result.ProductStatus != contract.ProductUnderInvestigation {
			t.Fatalf("status = %s, want under_investigation", result.ProductStatus)
		}
		// A revision the mapping does not name leaves the source unapproved and the
		// requirements unsatisfied; both reasons must be visible, not just the
		// inconclusive status.
		if want := []Reason{ReasonDomainSourceUnapproved, ReasonRequirementsMissing}; !reflect.DeepEqual(result.Reasons, want) {
			t.Fatalf("a foreign revision: reasons = %v, want %v", result.Reasons, want)
		}
	})
}

// TestA108DigestReplay covers E10 and I-13 (partial): two bundles with different
// digests keep their references bound to their own bundle, and a replay of the
// previous one is not transferable.
func TestA108DigestReplay(t *testing.T) {
	t.Run("references stay bound to their own bundle", func(t *testing.T) {
		first, _ := a108AffirmativeRequest(t, proofVulnerableBuild)
		second := first
		second.Bundle = cloneBundle(first.Bundle)
		// Change the image digest, which changes the projection hash, and re-hash.
		for index := range second.Bundle.Evidence {
			if second.Bundle.Evidence[index].Type == TypeNormalizedDigest {
				// Keep the file coherent: the digest is a different valid hex.
				replaceValue(&second.Bundle.Evidence[index], "sha256:"+strings.Repeat("c", 64))
			}
		}
		second = a108Rehash(t, second)
		if first.ExpectedBundleHash == second.ExpectedBundleHash {
			t.Fatal("the two bundles must have different projection hashes")
		}

		firstResult := evaluate(t, first)
		if firstResult.BundleHash != first.ExpectedBundleHash {
			t.Fatalf("result hash = %q, want the evaluated bundle hash", firstResult.BundleHash)
		}

		// Replaying the first bundle against the second bundle's hash must be
		// rejected: the reference is not transferable.
		transferred := first
		transferred.ExpectedBundleHash = second.ExpectedBundleHash
		result, err := Evaluate(transferred)
		if err == nil {
			t.Fatalf("a replay against a foreign bundle hash must be rejected, got %+v", result)
		}
		if !reflect.DeepEqual(result, Result{}) {
			t.Fatal("a rejected replay must not return a partial result")
		}
	})

	t.Run("a changed digest is detected against the expected hash", func(t *testing.T) {
		request, _ := a108AffirmativeRequest(t, proofVulnerableBuild)
		changed := request
		changed.Bundle = cloneBundle(request.Bundle)
		for index := range changed.Bundle.Evidence {
			if changed.Bundle.Evidence[index].Type == TypeNormalizedDigest {
				replaceValue(&changed.Bundle.Evidence[index], "sha256:"+strings.Repeat("e", 64))
			}
		}
		// No rehash: the declared expectation is now stale.
		result, err := Evaluate(changed)
		if err == nil {
			t.Fatalf("a stale expected hash must be rejected, got %+v", result)
		}
		if !reflect.DeepEqual(result, Result{}) {
			t.Fatal("a rejected bundle hash must not return a partial result")
		}
	})
}
