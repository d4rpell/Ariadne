package evaluator

import (
	"github.com/d4rpell/Ariadne/internal/rulepack"
	contract "github.com/d4rpell/Ariadne/pkg/evidence"
)

// checkContextForm applies ADR-0018 §4: every supplied DomainContext is counted
// and validated in form, and the recognized profile decides whether it is
// required or forbidden. An indeterminate classification owes nothing: the real
// error of the phase that actually fails is preserved.
func checkContextForm(request Request, recognition rulepack.Recognition) error {
	if request.Domain == nil {
		if recognition.RequiresDomainContext() {
			return contextProblem(-1)
		}
		return nil
	}
	if recognition.ForbidsDomainContext() {
		return contextProblem(-1)
	}
	return validateDomainContext(*request.Domain)
}

// checkValueHashes revalidates the value hash of every recognized fact that
// carries a value. A present value whose hash does not match is an integrity
// rejection, never unknown evidence that could still be used.
//
// The recognized domain types are verified only when the strict classification
// says the profile is the product one: the integrity of domain values belongs to
// the bundle phase, before pack admission, so it cannot depend on an admitted
// pack (ADR-0015 §5.2/§7.3, ADR-0018 §4). Readiness keeps its previous
// recognition and is never hardened.
func checkValueHashes(bundle contract.Bundle, recognition rulepack.Recognition) error {
	domainTypes := recognition == rulepack.RecognizedProduct
	for index, item := range bundle.Evidence {
		if item.Value == nil {
			continue
		}
		switch {
		case recognizedType(item.Type):
			// The legacy catalog keeps its exact verification.
		case domainTypes && isDomainType(item.Type):
			// A registered domain name is verified here, in the bundle phase. An
			// unknown name inside the reserved prefix is not: it blocks an
			// affirmation later, and inventing a value-hash rule for it would
			// harden the wire carrier.
			if _, _, ok := recognizeDomainType(item.Type); !ok {
				continue
			}
		default:
			continue
		}
		if item.ValueHash == nil || string(*item.ValueHash) != hashValue(*item.Value) {
			return problem(CodeValueHashMismatch, index)
		}
	}
	return nil
}
