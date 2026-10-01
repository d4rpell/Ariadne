package bundle

import (
	"github.com/d4rpell/Ariadne/internal/normalize"
	contract "github.com/d4rpell/Ariadne/pkg/evidence"
)

// BuildCollectedObservation projects one subject of one capture of a live
// acquisition onto a bundle (ADR-0026 A.7.3, A.9, A.11). It is a separate
// entry point from BuildObservation: the origin of a live capture is the
// collector that really executed the requests, and no export label is reused.
// The input is validated as a whole before a single byte is built; an
// incoherent DTO yields the zero bundle and the closed diagnostic
// projection_failed, never a repaired value.
func BuildCollectedObservation(input CollectedObservationInput) (contract.Bundle, ObservationDiagnostics, error) {
	if err := validateCollectedInput(input); err != nil {
		return contract.Bundle{}, ObservationDiagnostics{}, collectedFailure()
	}
	capture, err := collectedCaptureOf(input.Acquisition, input.CaptureOrdinal)
	if err != nil {
		return contract.Bundle{}, ObservationDiagnostics{}, collectedFailure()
	}
	subject := input.Result.Subjects[input.SubjectIndex]
	observedAt := copyPointer(input.Result.ObservedAt)
	diagnostics := ObservationDiagnostics{Omitted: []ObservationOmission{}}

	images, omitted := observationImages(subject, input.Result, observedAt)
	diagnostics.Omitted = omitted

	// The completeness of a live capture adds the defects of the acquisition
	// itself: a run that aborted, a plan that stayed open or a collision of this
	// subject can only keep "complete" away, never promote an unknown
	// termination.
	conflicts := normalize.ConflictingUIDs(input.Result)[input.SubjectIndex]
	defect := normalize.SubjectHasDefect(subject) || conflicts ||
		input.Result.RejectedItems > 0 || captureContaminated(input.Acquisition, capture) ||
		acquisitionContaminated(input.Acquisition)
	completeness := normalize.CompletenessFor(input.Acquisition.Termination, subject, defect)

	evidence := []contract.EvidenceItem{}
	evidence = append(evidence, observationEvidence(subject, input.Result, observedAt)...)

	bundle := contract.Bundle{
		SchemaVersion: contract.SchemaVersionSupported,
		Subject: contract.Subject{
			ClusterAlias: input.Result.ClusterAlias,
			Namespace:    subject.Namespace,
			Kind:         "Pod",
			Name:         subject.Name,
			UID:          subject.UID,
			// The admitted owner references stay context: no chain is invented.
			OwnerChain: "",
		},
		Images:                   images,
		Evidence:                 evidence,
		ObservedContainerClasses: observedClassList(subject),
		Provenance:               collectedProvenance(input, capture, completeness, len(omitted) > 0),
	}

	validated, err := validateObservationBundle(bundle)
	if err != nil {
		return contract.Bundle{}, diagnostics, err
	}
	return validated, diagnostics, nil
}

// acquisitionContaminatingCode reports whether one diagnostic code negates an
// integrity fact of the run, so no bundle of the run can claim completeness
// while it is present.
func acquisitionContaminatingCode(code CollectionCode) bool {
	switch code {
	case CodeResourceVersionMiss, CodePodRejected, CodeIdentityConflict,
		CodePaginationInvalid, CodeScopeMismatch, CodeObservationChanged,
		CodeUIDChanged, CodeRedactionFailed, CodeProjectionFailed:
		return true
	}
	return false
}

// acquisitionContaminated reports whether the acquisition record itself forbids
// "complete" for every bundle of the run: a diagnostic that negates an
// integrity fact of the sequence (a missing list resourceVersion, a rejected
// Pod, an identity or pagination conflict) is a defect of the observation, not
// a note that can disappear from the bundle.
func acquisitionContaminated(acquisition CollectedAcquisition) bool {
	for _, diagnostic := range acquisition.Diagnostics {
		if acquisitionContaminatingCode(diagnostic.Code) {
			return true
		}
	}
	return false
}

// capturedSubjectProblems reports whether one capture carries a diagnostic
// that negates the integrity of its own observation.
func capturedSubjectProblems(acquisition CollectedAcquisition, capture CollectedCapture) bool {
	for _, diagnostic := range acquisition.Diagnostics {
		if diagnostic.CaptureOrdinal != nil && *diagnostic.CaptureOrdinal == capture.Ordinal {
			return true
		}
	}
	return false
}

// captureContaminated reports whether the acquisition record forbids presenting
// this capture as complete: any run-wide failure, an open plan, a failed or
// missing operation of this capture, or a capture that was not admitted whole.
func captureContaminated(acquisition CollectedAcquisition, capture CollectedCapture) bool {
	if len(acquisition.GlobalErrors) != 0 {
		return true
	}
	if acquisition.Termination != contract.TerminationFinished {
		return true
	}
	if acquisition.Plan.ContinuationOpen || !acquisition.Plan.InventoryClosed ||
		acquisition.Plan.UnfinishedTargets != 0 || len(acquisition.Plan.PendingNamespaces) != 0 {
		return true
	}
	if capturedSubjectProblems(acquisition, capture) {
		return true
	}
	attempted := false
	for _, operation := range acquisition.Operations {
		if operation.RequestOrdinal != capture.RequestOrdinal {
			continue
		}
		attempted = true
		if operation.State != OperationFinished {
			return true
		}
	}
	return !attempted
}
