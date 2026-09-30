package ingest

import (
	"io"

	contract "github.com/d4rpell/Ariadne/pkg/evidence"
)

// ParseSanitizedPodList implements the explicit entry point of ADR-0025 A.11 for
// the sanitized-podlist-v1/1.0 profile. The mandatory sequence of A.5.3 is
// preserved: validate the context, acquire one bounded source to a confirmed
// EOF, run the strict reader with the allowlist and the budgets, hash every
// original byte only after that examination, and only then decode and validate
// the Pods. The selector is never inferred from the reader, the file name or its
// extension.
//
// A fatal failure returns no source, no hash and no publicable observation: the
// processing is transactional with respect to the admission of the source. An
// admitted source may still contain rejected Pods and incomplete observations,
// which stay visible in the result and, later, in every bundle of that source.
func ParseSanitizedPodList(reader io.Reader, context PodListContext) (PodListResult, error) {
	if problem := validatePodListContext(context); problem != nil {
		// The failure belongs to the caller's context: nothing was read and the
		// local processing was never started.
		return PodListResult{Context: context}, problem
	}
	data, problem := acquirePodListSource(reader)
	if problem != nil {
		return PodListResult{Context: context, LocalAborted: true}, problem
	}
	document, problem := newPodListScanner(data).scanDocument()
	if problem != nil {
		return PodListResult{Context: context, LocalAborted: true}, problem
	}

	result := PodListResult{Context: context}
	total := uint64(len(document.Items))
	result.TotalItems = &total

	outcomes := make([]podListOutcome, 0, len(document.Items))
	for index, element := range document.Items {
		outcome := validatePodListElement(element, index, context.Namespace)
		outcome.itemIndex = index
		outcomes = append(outcomes, outcome)
	}

	// Only an admitted source gets a publicable hash, and the hash covers every
	// original byte, including whitespace and the rejected items.
	result.Source = &PodListSource{
		Name:      context.SourceName,
		Hash:      hashPodListSource(data),
		ByteCount: uint64(len(data)),
	}

	// A usable UID repeated across the source invalidates every one of its
	// occurrences, including the first and the ones already rejected for another
	// defect, and replaces their primary reason.
	uidCounts := map[string]uint64{}
	for _, outcome := range outcomes {
		if outcome.uidUsable {
			uidCounts[outcome.uid]++
		}
	}
	nameOffsets := make([]uint64, 0, len(outcomes))
	for index, outcome := range outcomes {
		switch {
		case outcome.uidUsable && uidCounts[outcome.uid] > 1:
			result.Rejections = append(result.Rejections, PodListRejection{
				ItemIndex: index,
				Offset:    outcome.uidOffset,
				Code:      PodListCodeDuplicateUID,
			})
			result.Rejected++
		case !outcome.accepted:
			result.Rejections = append(result.Rejections, PodListRejection{
				ItemIndex: index,
				Offset:    outcome.offset,
				Code:      outcome.code,
			})
			result.Rejected++
		default:
			result.Subjects = append(result.Subjects, outcome.subject)
			nameOffsets = append(nameOffsets, outcome.nameOffset)
			result.Accepted++
		}
	}

	result.Diagnostics = podListSourceDiagnostics(context, document, result.Rejected)
	podListApplyConflicts(&result, nameOffsets)
	return result, nil
}

// podListSourceDiagnostics are the source-level diagnostics of an admitted
// capture: the declared termination and the visible rejections.
func podListSourceDiagnostics(context PodListContext, document *podListDocument, rejected uint64) []PodListDiagnostic {
	diagnostics := []PodListDiagnostic{}
	switch context.CaptureTermination {
	case contract.TerminationAborted:
		diagnostics = append(diagnostics, PodListDiagnostic{Code: PodListCodeCaptureAborted, ByteOffset: document.RootOffset})
	case contract.TerminationUnknown:
		diagnostics = append(diagnostics, PodListDiagnostic{Code: PodListCodeCaptureUnknown, ByteOffset: document.RootOffset})
	}
	if rejected > 0 {
		diagnostics = append(diagnostics, PodListDiagnostic{Code: PodListCodeSourceItemsRejected, ByteOffset: document.ItemsOffset})
	}
	return diagnostics
}

// podListApplyConflicts marks every subject that shares a namespace/name pair
// with a different UID. Both occurrences stay separate subjects and both carry
// the conflict: the order of the array is never read as chronology, and no
// subject is chosen or merged.
func podListApplyConflicts(result *PodListResult, nameOffsets []uint64) {
	type occurrence struct {
		uids map[string]bool
	}
	byName := map[string]*occurrence{}
	for _, subject := range result.Subjects {
		key := string(subject.Namespace) + "\x00" + subject.Name
		entry, known := byName[key]
		if !known {
			entry = &occurrence{uids: map[string]bool{}}
			byName[key] = entry
		}
		entry.uids[subject.UID] = true
	}
	for index := range result.Subjects {
		subject := &result.Subjects[index]
		key := string(subject.Namespace) + "\x00" + subject.Name
		if len(byName[key].uids) < 2 {
			continue
		}
		subject.Diagnostics = append(subject.Diagnostics, PodListDiagnostic{
			Code:       PodListCodeSubjectContextConflict,
			ByteOffset: nameOffsets[index],
		})
	}
}
