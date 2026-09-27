package evaluator

import (
	"sort"

	"github.com/d4rpell/Ariadne/internal/rulepack"
	contract "github.com/d4rpell/Ariadne/pkg/evidence"
)

// runDomainCheck executes one of the five domain predicates of ADR-0015 §8.3.
// The dispatch is closed and takes no parameters: the pack cannot select a
// source, a branch or an order.
func runDomainCheck(check rulepack.Check, facts *factSet, domain *domainAssessment) CheckTrace {
	trace := CheckTrace{
		CheckID:            check.CheckID,
		Reasons:            []CheckReason{},
		EvidenceReferences: []EvidenceReference{},
	}
	outcome := domainOutcome{value: OutcomeUnknown, reasons: []CheckReason{ReasonMissing}}
	switch check.Predicate {
	case rulepack.PredicateRedhatProductMapped:
		outcome = mappedOutcome(domain)
	case rulepack.PredicateRedhatArtifactBound:
		outcome = boundOutcome(domain)
	case rulepack.PredicateRedhatBuildAffected:
		outcome = terminalOutcome(domain, proofVulnerableBuild)
	case rulepack.PredicateRedhatBuildFixed:
		outcome = terminalOutcome(domain, proofFixedBuild)
	case rulepack.PredicateRedhatCodeExcluded:
		outcome = terminalOutcome(domain, proofCodeExcludedBuild)
	}
	trace.Outcome = outcome.value
	trace.Reasons = orderReasons(outcome.reasons)
	trace.EvidenceReferences = facts.storeCheckReferences(sortReferences(outcome.refs))
	return trace
}

// mappedOutcome is the auxiliary predicate: mapping unique and traceable. It
// never produces fail; absence or ambiguity is unknown.
func mappedOutcome(domain *domainAssessment) domainOutcome {
	if domain.mappingOK && domain.mapping != nil {
		return domainOutcome{value: OutcomePass, reasons: []CheckReason{ReasonVerified}, refs: domain.mapping.refs}
	}
	reasons := domain.blockerReasonsFor(ReasonMissing, ReasonConflict, ReasonUnsupportedProof)
	return domainOutcome{value: OutcomeUnknown, reasons: reasons, refs: domain.refsFor(reasons)}
}

// boundOutcome is the auxiliary predicate: exact build bound to the observed
// manifest, product and platform. It never produces fail.
func boundOutcome(domain *domainAssessment) domainOutcome {
	if domain.mappingOK && domain.artifactOK && domain.artifact != nil {
		refs := append(append([]EvidenceReference{}, domain.mapping.refs...), domain.artifact.refs...)
		return domainOutcome{value: OutcomePass, reasons: []CheckReason{ReasonVerified}, refs: sortReferences(refs)}
	}
	reasons := domain.blockerReasonsFor(ReasonMissing, ReasonMismatch, ReasonConflict, ReasonUnsupportedProof)
	return domainOutcome{value: OutcomeUnknown, reasons: reasons, refs: domain.refsFor(reasons)}
}

// terminalOutcome is one terminal predicate of ADR-0015 §8.3: pass with a valid
// applicable proof of its variant, fail only when the applicable set is complete,
// interpretable and current and no proof of that variant exists, unknown in any
// other case.
func terminalOutcome(domain *domainAssessment, kind proofKind) domainOutcome {
	if domain.hasProofKind(kind) {
		refs := domain.refsOfKind(kind)
		return domainOutcome{value: OutcomePass, reasons: []CheckReason{ReasonVerified}, refs: refs}
	}
	if domain.complete() {
		// Every applicable proof is usable and none is of this variant: the
		// terminal fails, which retires only this candidate.
		return domainOutcome{value: OutcomeFail, reasons: []CheckReason{ReasonMismatch}, refs: domain.globalRefs}
	}
	reasons := domain.blockerReasonsFor(
		ReasonMissing, ReasonMismatch, ReasonConflict, ReasonFutureObservation,
		ReasonExpired, ReasonUnapprovedSource, ReasonUnsupportedProof, ReasonUnavailable, ReasonRedacted,
	)
	if len(reasons) == 0 {
		reasons = []CheckReason{ReasonMissing}
	}
	return domainOutcome{value: OutcomeUnknown, reasons: reasons, refs: domain.refsFor(reasons)}
}

// blockerReasonsFor lists, in deterministic order, which of the wanted reasons
// are actually blocking the chain.
func (assessment *domainAssessment) blockerReasonsFor(wanted ...CheckReason) []CheckReason {
	var reasons []CheckReason
	for _, reason := range wanted {
		if assessment.blocked[reason] || assessment.hasUnknownFor(reason) {
			reasons = append(reasons, reason)
		}
	}
	return reasons
}

// hasUnknownFor maps the unknown-names blocker onto the unsupported_proof reason
// without inventing a second storage.
func (assessment *domainAssessment) hasUnknownFor(reason CheckReason) bool {
	return reason == ReasonUnsupportedProof && len(assessment.unknownDomain) > 0
}

// refsFor collects the references of the given blockers plus the unknown domain
// names, in canonical index order.
func (assessment *domainAssessment) refsFor(reasons []CheckReason) []EvidenceReference {
	var refs []EvidenceReference
	for _, reason := range reasons {
		refs = append(refs, assessment.blockers[reason]...)
		if reason == ReasonUnsupportedProof {
			refs = append(refs, assessment.unknownDomain...)
		}
	}
	sort.Slice(refs, func(i, j int) bool { return refs[i].ItemIndex < refs[j].ItemIndex })
	return refs
}

// refsOfKind returns the references of the valid proofs of one variant.
func (assessment *domainAssessment) refsOfKind(kind proofKind) []EvidenceReference {
	var refs []EvidenceReference
	for _, proof := range assessment.proofs {
		if proof.kind == kind {
			refs = append(refs, proof.refs...)
		}
	}
	sort.Slice(refs, func(i, j int) bool { return refs[i].ItemIndex < refs[j].ItemIndex })
	return refs
}

// domainRequirementOutcome resolves one of the four domain requirements of
// ADR-0015 §8.1: satisfied means the operand is present, interpretable and
// conforms to its conditions; anything else is a missing requirement, never an
// executed check.
func domainRequirementOutcome(requirement rulepack.Requirement, domain *domainAssessment, resolver *resolver) requirementOutcome {
	switch requirement {
	case rulepack.RequirementDomainMapping:
		if domain.mappingOK && domain.mapping != nil {
			return requirementOutcome{
				satisfied:  true,
				reasons:    []CheckReason{ReasonVerified},
				refs:       domain.mapping.refs,
				candidates: len(domain.mapping.refs),
			}
		}
		return unknownOutcome(len(domain.globalRefs), domain.reasonsForMissing()...)
	case rulepack.RequirementDomainArtifact:
		if domain.artifactOK && domain.artifact != nil {
			return requirementOutcome{
				satisfied:  true,
				reasons:    []CheckReason{ReasonVerified},
				refs:       domain.artifact.refs,
				candidates: len(domain.artifact.refs),
			}
		}
		return unknownOutcome(len(domain.globalRefs), domain.reasonsForMissing()...)
	case rulepack.RequirementDomainVendorProof:
		// ADR-0015 §8.1: at least one applicable proof and a complete,
		// interpretable set, with no candidate outside the pins. A conflict
		// between valid proofs keeps the requirement satisfied: the set is
		// complete and the global blocker reports the conflict.
		if domain.vendorProofSetComplete() {
			return requirementOutcome{
				satisfied:  true,
				reasons:    []CheckReason{ReasonVerified},
				refs:       domain.allProofRefs(),
				candidates: len(domain.globalRefs),
			}
		}
		return unknownOutcome(len(domain.globalRefs), domain.reasonsForMissing()...)
	case rulepack.RequirementDomainCurrent:
		if domain.current {
			return requirementOutcome{
				satisfied:  true,
				reasons:    []CheckReason{ReasonVerified},
				candidates: len(domain.globalRefs),
			}
		}
		refs := domain.refsFor(domain.blockerReasonsFor(ReasonExpired, ReasonFutureObservation))
		return requirementOutcome{
			satisfied:  false,
			reasons:    orderReasons(domain.blockerReasonsFor(ReasonExpired, ReasonFutureObservation)),
			refs:       refs,
			candidates: len(domain.globalRefs),
		}
	}
	return unknownOutcome(0, ReasonMissing)
}

// vendorProofSetComplete reports whether the applicable proof set satisfies
// ADR-0015 §8.1: at least one applicable proof, no uninterpretable group and no
// candidate outside the authorized pins.
func (assessment *domainAssessment) vendorProofSetComplete() bool {
	if len(assessment.proofs) == 0 {
		return false
	}
	// A name this vocabulary cannot interpret leaves the set uninterpretable even
	// when nothing else is blocking: an unknown record of the reserved namespace
	// may be the very proof the chain is missing (ADR-0015 §5.1).
	if len(assessment.unknownDomain) > 0 {
		return false
	}
	// Any blocker of the chain leaves the requirement unsatisfied too: the set is
	// not interpretable or not authorized. A conflict between valid proofs is not
	// a blocker of this kind and stays out of this decision, because the set is
	// complete and the global blocker reports the conflict.
	for reason := range assessment.blocked {
		switch reason {
		case ReasonUnapprovedSource, ReasonUnsupportedProof, ReasonMissing, ReasonMismatch,
			ReasonConflict, ReasonExpired, ReasonFutureObservation, ReasonUnavailable, ReasonRedacted:
			return false
		}
	}
	return true
}

// reasonsForMissing is the ordered blocker set that makes a domain requirement
// unsatisfied, falling back to the plain missing reason.
func (assessment *domainAssessment) reasonsForMissing() []CheckReason {
	reasons := assessment.blockerReasonsFor(
		ReasonMissing, ReasonMismatch, ReasonConflict, ReasonFutureObservation,
		ReasonExpired, ReasonUnapprovedSource, ReasonUnsupportedProof, ReasonUnavailable, ReasonRedacted,
	)
	if len(reasons) == 0 {
		return []CheckReason{ReasonMissing}
	}
	return reasons
}

func (assessment *domainAssessment) allProofRefs() []EvidenceReference {
	var refs []EvidenceReference
	for _, proof := range assessment.proofs {
		refs = append(refs, proof.refs...)
	}
	return refs
}

// globalDomainReasons maps the blockers of the global inspection onto the global
// reasons of ADR-0015 §10. They are accumulated even when several blockers
// coincide.
func (assessment *domainAssessment) globalDomainReasons() []Reason {
	var reasons []Reason
	add := func(condition bool, reason Reason) {
		if condition {
			reasons = append(reasons, reason)
		}
	}
	add(assessment.blocked[ReasonExpired] || assessment.blocked[ReasonFutureObservation], ReasonDomainEvidenceExpired)
	add(assessment.blocked[ReasonUnapprovedSource], ReasonDomainSourceUnapproved)
	add(len(assessment.unknownDomain) > 0 || assessment.blocked[ReasonUnsupportedProof], ReasonDomainProofUnsupported)
	add(len(assessment.sustainedStates()) > 1, ReasonAffirmativeConflict)
	return reasons
}

// sustainedStatus is the state sustained by the valid proofs, or
// under_investigation when there is no single one.
func (assessment *domainAssessment) sustainedStatus() (contract.ProductStatus, bool) {
	states := assessment.sustainedStates()
	if len(states) != 1 {
		return contract.ProductUnderInvestigation, false
	}
	return states[0].status, true
}
