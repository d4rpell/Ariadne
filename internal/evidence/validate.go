package evidence

import (
	"errors"
	"fmt"

	contract "github.com/d4rpell/Ariadne/pkg/evidence"
)

// ValidateConclusion guards layer 1 of the decision model for a conclusion scoped
// to one subject and container. Evidence that is incomplete, unavailable, out of
// scope or carrying a blocking warning can never yield not_affected: the negative
// that is not observed stays under_investigation.
func ValidateConclusion(status contract.ProductStatus, subject contract.Subject, container contract.ContainerName, items []contract.EvidenceItem) error {
	if !status.Valid() {
		return errors.New("internal/evidence: product status is not a known value")
	}
	if status != contract.ProductNotAffected {
		return nil
	}
	affirmative := 0
	for index, item := range items {
		if err := contract.ValidateEvidenceItem(item, subject); err != nil {
			return fmt.Errorf("evidence[%d]: %w", index, err)
		}
		if err := contract.ValidateScope(item.Scope, subject.UID, container); err != nil {
			return fmt.Errorf("evidence[%d]: %w", index, err)
		}
		// A contradictory warning blocks the negative conclusion. A code this
		// schema version does not define is uninterpretable, so it blocks too.
		for _, warning := range item.Warnings {
			if warning.Class == contract.WarningContradictory || !warning.CodeKnown() {
				return fmt.Errorf("evidence[%d]: warning %q blocks a not_affected conclusion", index, warning.Code)
			}
		}
		if item.Confidence == contract.ProvenanceUnavailable {
			return fmt.Errorf("evidence[%d]: unavailable evidence blocks a not_affected conclusion", index)
		}
		if item.ValueHash == nil {
			return fmt.Errorf("evidence[%d]: affirmative evidence requires a value hash", index)
		}
		affirmative++
	}
	if affirmative == 0 {
		return errors.New("internal/evidence: not_affected requires affirmative evidence scoped to the subject")
	}
	return nil
}
