package evaluator

import (
	"sort"

	contract "github.com/d4rpell/Ariadne/pkg/evidence"
)

// productResolution carries everything the product profile needs to decide the
// published state and its reasons (ADR-0015 §9, table of §9).
type productResolution struct {
	candidates            []Candidate
	domain                domainAssessment
	affirmativeUncertain  bool
	blocking              bool
	conflict              bool
	requirementsMissing   bool
	checksFailed          bool
	checksUnknown         bool
	noApplicableRule      bool
	targetUnsubstantiated bool
	incompleteEvidence    bool
	globalDomain          []Reason
}

// resolveProductStatus applies the ratified table of ADR-0015 §9. It never
// resolves a conflict by order, majority or recency: two sustained states block,
// and a candidate is published only when a single state is sustained by a
// concordant proof and no global blocker exists.
func resolveProductStatus(resolution productResolution) (contract.ProductStatus, []Reason) {
	var reasons []Reason
	add := func(condition bool, reason Reason) {
		if condition {
			reasons = append(reasons, reason)
		}
	}

	states := resolution.domain.sustainedStates()
	candidateStates := candidateStateSet(resolution.candidates)

	conflictingStates := len(states) > 1 || len(candidateStates) > 1
	if len(states) > 1 && len(candidateStates) <= 1 {
		// Proofs of two branches sustain incompatible states even when the pack
		// only declares one terminal.
		conflictingStates = true
	}
	if len(candidateStates) > 1 {
		conflictingStates = true
	}
	if len(states) == 1 && len(candidateStates) == 1 && states[0].status != candidateStates[0] {
		// A rule candidate contradicting the sustained proof set is a conflict,
		// not a preference.
		conflictingStates = true
	}

	blocked := resolution.blocking || resolution.conflict || conflictingStates ||
		resolution.affirmativeUncertain || len(resolution.domain.blocked) > 0 ||
		len(resolution.domain.unknownDomain) > 0 || !resolution.domain.current

	add(resolution.noApplicableRule, ReasonNoApplicableRule)
	add(resolution.targetUnsubstantiated, ReasonTargetUnsubstantiated)
	add(resolution.incompleteEvidence, ReasonIncompleteEvidence)
	add(resolution.blocking, ReasonBlockingWarning)
	add(resolution.conflict || conflictingStates, ReasonConflictingEvidence)
	add(resolution.requirementsMissing, ReasonRequirementsMissing)
	add(resolution.checksFailed, ReasonChecksFailed)
	add(resolution.checksUnknown, ReasonChecksUnknown)
	for _, reason := range resolution.globalDomain {
		add(true, reason)
	}
	if conflictingStates {
		add(true, ReasonAffirmativeConflict)
	}

	// Publication requires a rule candidate: the sustained states exist to
	// detect conflicts, never to publish a branch the pack did not declare. A
	// lone sustained state without a candidate is still 'no affirmative
	// candidate' in the table of §9.
	status := contract.ProductUnderInvestigation
	switch {
	case blocked:
		status = contract.ProductUnderInvestigation
	case len(resolution.candidates) == 0:
		add(true, ReasonNoAffirmativeCandidate)
		status = contract.ProductUnderInvestigation
	default:
		status = resolution.candidates[0].ProductStatus
	}

	reasons = orderGlobalReasons(reasons)
	return status, reasons
}

// candidateStateSet returns the distinct states of the affirmative candidates,
// ordered for determinism.
func candidateStateSet(candidates []Candidate) []contract.ProductStatus {
	seen := make(map[contract.ProductStatus]bool)
	var states []contract.ProductStatus
	for _, candidate := range candidates {
		if seen[candidate.ProductStatus] {
			continue
		}
		seen[candidate.ProductStatus] = true
		states = append(states, candidate.ProductStatus)
	}
	sort.Slice(states, func(i, j int) bool { return states[i] < states[j] })
	return states
}

func orderGlobalReasons(reasons []Reason) []Reason {
	if len(reasons) == 0 {
		return nil
	}
	ordered := append([]Reason{}, reasons...)
	sort.Slice(ordered, func(i, j int) bool { return ordered[i] < ordered[j] })
	unique := ordered[:1]
	for _, reason := range ordered[1:] {
		if reason != unique[len(unique)-1] {
			unique = append(unique, reason)
		}
	}
	return unique
}
