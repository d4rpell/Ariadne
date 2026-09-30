package bundle

import (
	"github.com/d4rpell/Ariadne/internal/ingest"
	"github.com/d4rpell/Ariadne/internal/normalize"
	contract "github.com/d4rpell/Ariadne/pkg/evidence"
)

// BuildObservation projects one normalized observation subject onto a bundle
// (ADR-0025 A.9, A.11). The caller keeps the diagnostics; err == nil means the
// bundle is valid, never that the capture was complete and never that a
// conclusion is favourable. An unusable input yields no bundle at all.
func BuildObservation(input ObservationInput) (contract.Bundle, ObservationDiagnostics, error) {
	if err := validateObservationInput(input); err != nil {
		return contract.Bundle{}, ObservationDiagnostics{}, err
	}
	subject := input.Result.Subjects[input.SubjectIndex]
	// The obsderved instant is copied once: neither the caller nor a later
	// mutation of the input can rewrite the bytes of this bundle.
	observedAt := copyPointer(input.ObservedAt)
	diagnostics := ObservationDiagnostics{Omitted: []ObservationOmission{}}

	images, omitted := observationImages(subject, input.Result, observedAt)
	diagnostics.Omitted = omitted

	// Collisions omit every observation of the collided key; the rest of the
	// subject is preserved and the result is partial, never complete.
	collisionClasses := [][]contract.ContainerClass{}
	for name := range subject.CollidedClasses {
		collisionClasses = append(collisionClasses, subject.CollidedClasses[name])
	}
	conflicts := normalize.ConflictingUIDs(input.Result)[input.SubjectIndex]
	rejectedPeers := input.Result.RejectedItems > 0
	defect := normalize.SubjectHasDefect(subject) || conflicts || rejectedPeers
	completeness := normalize.CompletenessFor(input.Result.Termination, subject, defect)

	evidence := []contract.EvidenceItem{}
	observedClasses := observedClassList(subject)
	evidence = append(evidence, observationEvidence(subject, input.Result, observedAt)...)

	warnings, err := observationWarnings(subject, conflicts, collisionClasses, completeness != contract.CompletenessComplete)
	if err != nil {
		return contract.Bundle{}, diagnostics, err
	}
	preserved := observationDiagnosticCodes(subject, input.Result.GlobalDiagnostics)
	errors := observationErrors(subject, input.Result.GlobalDiagnostics, rejectedPeers, preserved)
	errors = append(errors, observationIncompletenessErrors(subject, preserved, input.Result.Termination, completeness)...)
	if len(diagnostics.Omitted) > 0 {
		errors = append(errors, errScopeCollisionOmitted.Error())
	}

	bundle := contract.Bundle{
		SchemaVersion: contract.SchemaVersionSupported,
		Subject: contract.Subject{
			ClusterAlias: input.Result.ClusterAlias,
			Namespace:    subject.Namespace,
			Kind:         "Pod",
			Name:         subject.Name,
			UID:          subject.UID,
			// ownerReferences are context, not a resolved owner chain: no chain is
			// invented from a list of references (A.9.1).
			OwnerChain: "",
		},
		Images:                   images,
		Evidence:                 evidence,
		ObservedContainerClasses: observedClasses,
		Provenance:               observationProvenance(input, subject, warnings, errors, completeness),
	}

	validated, err := validateObservationBundle(bundle)
	if err != nil {
		return contract.Bundle{}, diagnostics, err
	}
	return validated, diagnostics, nil
}

// observationIncompletenessErrors reports the causes of an incomplete result.
// ADR-0025 A.7.4 requires every incomplete result to keep visible errors: the
// termination and the unobserved categories are stated with their closed
// diagnostic codes. A cause the producer already preserved is not repeated: this
// layer only states what the preserved diagnostics do not.
func observationIncompletenessErrors(subject normalize.ObservationSubject, preserved map[string]bool, termination contract.CoverageTermination, completeness contract.Completeness) []string {
	if completeness == contract.CompletenessComplete {
		return nil
	}
	messages := []string{}
	add := func(code string) {
		if preserved[code] {
			return
		}
		messages = append(messages, podListDiagnosticText(code, 0, ""))
	}
	switch termination {
	case contract.TerminationAborted:
		add("capture_aborted")
	case contract.TerminationUnknown:
		add("capture_unknown")
	}
	for _, class := range []contract.ContainerClass{
		contract.ContainerRegular, contract.ContainerInit, contract.ContainerEphemeral,
	} {
		if !subject.CategoriesObserved[class] {
			add("category_unobserved")
			continue
		}
		if !subject.CategoriesComplete[class] {
			add("status_unobserved")
		}
	}
	return messages
}

// observationDiagnosticCodes collects the codes of every diagnostic the producer
// preserved, so the fallback of this layer never repeats one.
func observationDiagnosticCodes(subject normalize.ObservationSubject, global []normalize.ObservationDiagnostic) map[string]bool {
	codes := map[string]bool{}
	for _, diagnostic := range global {
		codes[diagnostic.Code] = true
	}
	for _, diagnostic := range subject.Diagnostics {
		codes[diagnostic.Code] = true
	}
	return codes
}

// observedClassList returns the observed container classes of one subject in
// canonical enum order, without duplicates.
func observedClassList(subject normalize.ObservationSubject) []contract.ContainerClass {
	classes := []contract.ContainerClass{}
	for _, class := range []contract.ContainerClass{
		contract.ContainerRegular, contract.ContainerInit, contract.ContainerEphemeral,
	} {
		if subject.CategoriesObserved[class] {
			classes = append(classes, class)
		}
	}
	return classes
}

// podListDiagnosticText renders one local diagnostic with the fixed adapter
// format. The message comes from the closed catalog of the ingest package.
func podListDiagnosticText(code string, offset uint64, locator string) string {
	if !ingest.PodListCodeKnown(code) {
		// A code outside the closed catalog has no message and no reliable
		// anchor: it is rendered as invalid_input at byte zero, and the supplied
		// text is never printed.
		code = string(ingest.PodListCodeInvalidInput)
		offset = 0
		locator = ""
	}
	if !ingest.PodListLocatorValid(locator) {
		// A locator is a path inside the admitted document, never free text.
		locator = ""
	}
	message := ingest.PodListMessage(ingest.PodListDiagnosticCode(code))
	text := "ingest: sanitized-podlist-v1: byte/" + itoaForBundle(int(offset)) + ": " + message
	if locator != "" {
		text += " at " + locator
	}
	return text
}
