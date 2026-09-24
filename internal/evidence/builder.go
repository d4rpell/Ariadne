package evidence

import (
	contract "github.com/d4rpell/Ariadne/pkg/evidence"
)

// NewBundle is the fail-closed entry point for a bundle: nothing that fails the
// contract reaches a caller as a value.
func NewBundle(bundle contract.Bundle) (contract.Bundle, error) {
	if err := contract.ValidateBundle(bundle); err != nil {
		return contract.Bundle{}, err
	}
	return bundle, nil
}

func NewEvidenceItem(subject contract.Subject, item contract.EvidenceItem) (contract.EvidenceItem, error) {
	if err := contract.ValidateEvidenceItem(item, subject); err != nil {
		return contract.EvidenceItem{}, err
	}
	return item, nil
}
