package report

import (
	"fmt"
	"testing"
	"time"

	"github.com/d4rpell/Ariadne/internal/evaluator"
	"github.com/d4rpell/Ariadne/internal/rulepack"
)

func pointer(value string) *string { return &value }

// detachedString copies the value an optional string points to, so a snapshot
// cannot be changed through the pointer the original still holds.
func detachedString(value *string) *string {
	if value == nil {
		return nil
	}
	copied := *value
	return &copied
}

func itoa(value int) string { return fmt.Sprintf("%d", value) }

// timeAt builds one canonical UTC instant in the given year. It is used to probe
// the year range the presentation grammar admits, which no fixture carries.
func timeAt(year int) time.Time {
	return time.Date(year, time.January, 2, 3, 4, 5, 6, time.UTC)
}

// cloneResult detaches a Result from the caller so a mutation of the copy
// cannot be observed through the original, mirroring the clone the tests need to
// compare states.
func cloneResult(t *testing.T, result evaluator.Result) evaluator.Result {
	t.Helper()
	cloned := result
	cloned.Reasons = append([]evaluator.Reason{}, result.Reasons...)
	cloned.EvidenceReferences = append([]evaluator.EvidenceReference{}, result.EvidenceReferences...)
	cloned.WarningReferences = append([]evaluator.WarningReference{}, result.WarningReferences...)
	cloned.Rules = make([]evaluator.RuleTrace, len(result.Rules))
	for index, trace := range result.Rules {
		copied := trace
		copied.MissingRequirements = append([]rulepack.Requirement{}, trace.MissingRequirements...)
		copied.Reasons = append([]evaluator.CheckReason{}, trace.Reasons...)
		copied.EvidenceReferences = append([]evaluator.EvidenceReference{}, trace.EvidenceReferences...)
		copied.Checks = make([]evaluator.CheckTrace, len(trace.Checks))
		for checkIndex, check := range trace.Checks {
			checkCopy := check
			checkCopy.Reasons = append([]evaluator.CheckReason{}, check.Reasons...)
			checkCopy.EvidenceReferences = append([]evaluator.EvidenceReference{}, check.EvidenceReferences...)
			copied.Checks[checkIndex] = checkCopy
		}
		cloned.Rules[index] = copied
	}
	cloned.Candidates = make([]evaluator.Candidate, len(result.Candidates))
	for index, candidate := range result.Candidates {
		copied := candidate
		copied.EvidenceReferences = append([]evaluator.EvidenceReference{}, candidate.EvidenceReferences...)
		cloned.Candidates[index] = copied
	}
	if result.Domain != nil {
		domain := *result.Domain
		domain.SourcePins = make([]evaluator.SourcePin, len(result.Domain.SourcePins))
		for index, pin := range result.Domain.SourcePins {
			copied := pin
			// The optional strings are copied through their own pointers. Sharing
			// them would make an equality check blind to a modification of the
			// pointed-to value, which is exactly the alias this helper has to rule
			// out.
			copied.AdvisoryID = detachedString(pin.AdvisoryID)
			copied.AdvisoryRevision = detachedString(pin.AdvisoryRevision)
			domain.SourcePins[index] = copied
		}
		cloned.Domain = &domain
	}
	if previous := result.Admission.Previous; previous != nil {
		copied := *previous
		cloned.Admission.Previous = &copied
	}
	return cloned
}

// sameResult compares the fields the encoders could have modified.
func sameResult(left, right evaluator.Result) bool {
	if left.Target != right.Target ||
		left.ProductStatus != right.ProductStatus ||
		left.Exploitability != right.Exploitability ||
		len(left.Reasons) != len(right.Reasons) ||
		len(left.Rules) != len(right.Rules) ||
		len(left.Candidates) != len(right.Candidates) ||
		len(left.EvidenceReferences) != len(right.EvidenceReferences) ||
		len(left.WarningReferences) != len(right.WarningReferences) {
		return false
	}
	for index := range left.Reasons {
		if left.Reasons[index] != right.Reasons[index] {
			return false
		}
	}
	for index := range left.EvidenceReferences {
		if left.EvidenceReferences[index] != right.EvidenceReferences[index] {
			return false
		}
	}
	for index := range left.WarningReferences {
		if left.WarningReferences[index] != right.WarningReferences[index] {
			return false
		}
	}
	for index := range left.Rules {
		leftRule, rightRule := left.Rules[index], right.Rules[index]
		if leftRule.RuleID != rightRule.RuleID || leftRule.State != rightRule.State {
			return false
		}
		if len(leftRule.Checks) != len(rightRule.Checks) ||
			len(leftRule.MissingRequirements) != len(rightRule.MissingRequirements) {
			return false
		}
	}
	for index := range left.Candidates {
		if left.Candidates[index].RuleID != right.Candidates[index].RuleID ||
			left.Candidates[index].ProductStatus != right.Candidates[index].ProductStatus {
			return false
		}
	}
	return true
}
