package normalize

import (
	contract "github.com/d4rpell/Ariadne/pkg/evidence"
)

// Coverage precedence of ADR-0025 A.7.4 and A.8.4. This file computes the
// per-subject completeness from the admitted capture termination, the observed
// categories and the verified progress. The rule is absolute: an unknown
// capture termination always yields unknown completeness, and no collision or
// other defect may promote it.

// ObservationProgress is the verified progress of one subject: an observed
// category or an inventoried image. Knowing the UID is not progress.
type ObservationProgress struct {
	CategoryObserved bool
	ImageInventoried bool
}

// ProgressOf derives the progress of one subject from its own observations.
func ProgressOf(subject ObservationSubject) ObservationProgress {
	progress := ObservationProgress{}
	for _, observed := range subject.CategoriesObserved {
		if observed {
			progress.CategoryObserved = true
		}
	}
	for _, container := range subject.Containers {
		if container.ImageID != nil && *container.ImageID != "" {
			progress.ImageInventoried = true
		}
	}
	return progress
}

// CompletenessFor applies the precedence of A.7.4 for one subject. hasDefect
// reports collisions, rejected peers, unassociated statuses or projection
// omissions; it can only lower "complete" to "partial", never raise an unknown
// termination.
func CompletenessFor(termination contract.CoverageTermination, subject ObservationSubject, hasDefect bool) contract.Completeness {
	progress := ProgressOf(subject)
	verifiable := progress.CategoryObserved || progress.ImageInventoried

	switch termination {
	case contract.TerminationUnknown:
		return contract.CompletenessUnknown
	case contract.TerminationAborted:
		if verifiable {
			return contract.CompletenessPartial
		}
		return contract.CompletenessUnknown
	case contract.TerminationFinished:
		if !verifiable {
			return contract.CompletenessUnknown
		}
		if hasDefect {
			return contract.CompletenessPartial
		}
		if AllCategoriesComplete(subject) {
			return contract.CompletenessComplete
		}
		return contract.CompletenessPartial
	default:
		return contract.CompletenessUnknown
	}
}

// AllCategoriesComplete reports whether the three container categories were
// explicitly observed with complete associations, the only shape that can
// sustain a complete observation.
func AllCategoriesComplete(subject ObservationSubject) bool {
	for _, class := range []contract.ContainerClass{
		contract.ContainerRegular, contract.ContainerInit, contract.ContainerEphemeral,
	} {
		if !subject.CategoriesComplete[class] {
			return false
		}
	}
	return true
}

// SubjectHasDefect reports whether a subject carries a defect that forbids
// "complete": a context conflict, a scope collision, or any preserved
// diagnostic of incompleteness. Every diagnostic the producer kept states that
// the observation is not whole — an unobserved category, a missing container
// status, a requested reference the export did not carry or a rejected peer —
// so a subject with errors can never be reported as complete.
func SubjectHasDefect(subject ObservationSubject) bool {
	if subject.ContextConflict {
		return true
	}
	if len(subject.CollidedClasses) > 0 {
		return true
	}
	return len(subject.Diagnostics) > 0
}
