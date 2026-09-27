package evaluator

import (
	"github.com/d4rpell/Ariadne/internal/rulepack"
)

// checkRequirements is the execution-side mapping from a check to the
// requirements it reads. It mirrors the mandatory requirements rulepack
// validates against a pack, and a test asserts both agree for every predicate.
func checkRequirements(check rulepack.Check) []rulepack.Requirement {
	switch check.Predicate {
	case rulepack.PredicateFindingFieldPresent, rulepack.PredicateFindingFieldEquals:
		return []rulepack.Requirement{rulepack.FindingRequirement(rulepack.FieldID(check.Params.Field))}
	case rulepack.PredicateImageDigestBound:
		return []rulepack.Requirement{rulepack.RequirementImageBoundDigest}
	case rulepack.PredicateImagePlatformKnown:
		return []rulepack.Requirement{rulepack.RequirementImageBoundDigest, rulepack.RequirementImageKnownPlatform}
	case rulepack.PredicateRedhatProductMapped:
		return []rulepack.Requirement{
			rulepack.FindingRequirement(rulepack.FieldPackageType),
			rulepack.FindingRequirement(rulepack.FieldPackageName),
			rulepack.FindingRequirement(rulepack.FieldPackageID),
			rulepack.RequirementDomainMapping,
		}
	case rulepack.PredicateRedhatArtifactBound:
		return []rulepack.Requirement{
			rulepack.FindingRequirement(rulepack.FieldPackageType),
			rulepack.FindingRequirement(rulepack.FieldPackageName),
			rulepack.FindingRequirement(rulepack.FieldPackageID),
			rulepack.RequirementImageBoundDigest,
			rulepack.RequirementImageKnownPlatform,
			rulepack.RequirementDomainMapping,
			rulepack.RequirementDomainArtifact,
		}
	case rulepack.PredicateRedhatBuildAffected, rulepack.PredicateRedhatBuildFixed,
		rulepack.PredicateRedhatCodeExcluded:
		return []rulepack.Requirement{
			rulepack.FindingRequirement(rulepack.FieldPackageType),
			rulepack.FindingRequirement(rulepack.FieldPackageName),
			rulepack.FindingRequirement(rulepack.FieldPackageID),
			rulepack.RequirementImageBoundDigest,
			rulepack.RequirementImageKnownPlatform,
			rulepack.RequirementDomainMapping,
			rulepack.RequirementDomainArtifact,
			rulepack.RequirementDomainVendorProof,
			rulepack.RequirementDomainCurrent,
		}
	}
	return nil
}

// runCheck executes one closed predicate over requirements that are already
// resolved and satisfied. A check never discovers evidence of its own: it reads
// an outcome and compares values. Outcomes are pass, fail or unknown, and a
// failing or unknown check never leaves the initial profile. The five domain
// predicates are dispatched to their own module.
func runCheck(check rulepack.Check, facts *factSet) CheckTrace {
	switch check.Predicate {
	case rulepack.PredicateRedhatProductMapped, rulepack.PredicateRedhatArtifactBound,
		rulepack.PredicateRedhatBuildAffected, rulepack.PredicateRedhatBuildFixed,
		rulepack.PredicateRedhatCodeExcluded:
		return runDomainCheck(check, facts, facts.domain)
	}
	trace := CheckTrace{
		CheckID:            check.CheckID,
		Reasons:            []CheckReason{},
		EvidenceReferences: []EvidenceReference{},
	}
	switch check.Predicate {
	case rulepack.PredicateFindingFieldPresent:
		outcome := facts.resolve(rulepack.FindingRequirement(rulepack.FieldID(check.Params.Field)))
		if !outcome.satisfied {
			trace.Outcome = OutcomeUnknown
			trace.Reasons = outcome.reasons
			return trace
		}
		trace.Outcome = OutcomePass
		trace.Reasons = []CheckReason{ReasonVerified}
		trace.EvidenceReferences = facts.storeCheckReferences(outcome.refs)
		return trace

	case rulepack.PredicateFindingFieldEquals:
		outcome := facts.resolve(rulepack.FindingRequirement(rulepack.FieldID(check.Params.Field)))
		if !outcome.satisfied {
			trace.Outcome = OutcomeUnknown
			trace.Reasons = outcome.reasons
			return trace
		}
		trace.EvidenceReferences = facts.storeCheckReferences(outcome.refs)
		if outcome.value != nil && *outcome.value == check.Params.Value {
			trace.Outcome = OutcomePass
			trace.Reasons = []CheckReason{ReasonVerified}
			return trace
		}
		// The comparison is an exact UTF-8 comparison and metacharacters are
		// data: a difference is a fail, never an error and never a coercion.
		trace.Outcome = OutcomeFail
		trace.Reasons = []CheckReason{ReasonMismatch}
		return trace

	case rulepack.PredicateImageDigestBound:
		outcome := facts.resolve(rulepack.RequirementImageBoundDigest)
		if !outcome.satisfied {
			trace.Outcome = OutcomeUnknown
			trace.Reasons = outcome.reasons
			return trace
		}
		trace.Outcome = OutcomePass
		trace.Reasons = []CheckReason{ReasonVerified}
		trace.EvidenceReferences = facts.storeCheckReferences(outcome.refs)
		return trace

	case rulepack.PredicateImagePlatformKnown:
		bound := facts.resolve(rulepack.RequirementImageBoundDigest)
		if !bound.satisfied {
			trace.Outcome = OutcomeUnknown
			trace.Reasons = bound.reasons
			return trace
		}
		outcome := facts.resolve(rulepack.RequirementImageKnownPlatform)
		if !outcome.satisfied || outcome.platform == nil {
			trace.Outcome = OutcomeUnknown
			trace.Reasons = outcome.reasons
			// Declared unreachable and therefore not isolable by a mutation: a check
			// only runs when every requirement of its rule is satisfied, and this
			// predicate must declare image.bound_digest and image.known_platform, so
			// an unsatisfied platform requirement leaves the rule missing_evidence
			// before any check runs. The reservation is kept for a future profile
			// that relaxes that rule, and its mutation stays green on purpose.
			trace.EvidenceReferences = facts.storeCheckReferences(outcome.refs)
			return trace
		}
		trace.EvidenceReferences = facts.storeCheckReferences(outcome.refs)
		if outcome.platform.OS == check.Params.OS && outcome.platform.Architecture == check.Params.Architecture {
			trace.Outcome = OutcomePass
			trace.Reasons = []CheckReason{ReasonVerified}
			return trace
		}
		trace.Outcome = OutcomeFail
		trace.Reasons = []CheckReason{ReasonMismatch}
		return trace
	}

	trace.Outcome = OutcomeUnknown
	trace.Reasons = []CheckReason{ReasonMissing}
	return trace
}
