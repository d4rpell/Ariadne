package collector

import (
	"sort"

	"github.com/d4rpell/Ariadne/internal/bundle"
	"github.com/d4rpell/Ariadne/internal/normalize"
	contract "github.com/d4rpell/Ariadne/pkg/evidence"
)

// Temporal comparisons (ADR-0026 A.8.3). Only captures of the same run are
// compared, every reference is preserved and the results never rewrite the
// bytes or the observations of the captures they compare.

// compareCaptures produces the deterministic comparisons of one run. It never
// chooses a winning version: a difference is reported, not resolved.
func compareCaptures(captures []bundle.CollectedCapture) ([]bundle.CollectedComparison, []bundle.CollectionDiagnostic, error) {
	comparisons := []bundle.CollectedComparison{}
	diagnostics := []bundle.CollectionDiagnostic{}

	// Index the subjects by uid, keeping every occurrence in capture order.
	type located struct {
		capture uint64
		item    int
		subject normalize.ObservationSubject
	}
	// earliestOccurrence returns the occurrence with the lowest capture ordinal,
	// with the item index as a deterministic tie-break.
	earliestOccurrence := func(occurrences []located) located {
		best := occurrences[0]
		for _, candidate := range occurrences[1:] {
			if candidate.capture < best.capture ||
				(candidate.capture == best.capture && candidate.item < best.item) {
				best = candidate
			}
		}
		return best
	}
	byUID := map[contract.UID][]located{}
	for _, capture := range captures {
		for _, subject := range capture.Observation.Subjects {
			byUID[subject.UID] = append(byUID[subject.UID], located{
				capture: capture.Ordinal,
				item:    subject.ItemIndex,
				subject: subject,
			})
		}
	}
	// A replacement is a namespace/name whose uid changed between captures: the
	// two subjects stay separate, the change is visible, and the comparison
	// references the two real subjects of the two distinct uids, never the same
	// subject as both ends.
	byAddress := map[string][]located{}
	for _, capture := range captures {
		for _, subject := range capture.Observation.Subjects {
			address := string(subject.Namespace) + "/" + subject.Name
			byAddress[address] = append(byAddress[address], located{
				capture: capture.Ordinal,
				item:    subject.ItemIndex,
				subject: subject,
			})
		}
	}
	for _, occurrences := range byAddress {
		byReplacementUID := map[contract.UID][]located{}
		for _, occurrence := range occurrences {
			byReplacementUID[occurrence.subject.UID] = append(byReplacementUID[occurrence.subject.UID], occurrence)
		}
		if len(byReplacementUID) < 2 {
			continue
		}
		uids := make([]string, 0, len(byReplacementUID))
		for uid := range byReplacementUID {
			uids = append(uids, string(uid))
		}
		sort.Strings(uids)
		for index := 0; index+1 < len(uids); index++ {
			previous := earliestOccurrence(byReplacementUID[contract.UID(uids[index])])
			current := earliestOccurrence(byReplacementUID[contract.UID(uids[index+1])])
			if previous.capture > current.capture {
				previous, current = current, previous
			}
			comparisons = append(comparisons, bundle.CollectedComparison{
				Code:     bundle.CodeUIDChanged,
				Previous: bundle.CollectedSubjectRef{CaptureOrdinal: previous.capture, ItemIndex: previous.item},
				Current:  bundle.CollectedSubjectRef{CaptureOrdinal: current.capture, ItemIndex: current.item},
			})
		}
	}
	for uid, occurrences := range byUID {
		_ = uid
		if len(occurrences) < 2 {
			continue
		}
		sort.Slice(occurrences, func(i, j int) bool {
			return occurrences[i].capture < occurrences[j].capture
		})
		for index := 1; index < len(occurrences); index++ {
			previous := occurrences[index-1]
			current := occurrences[index]
			previousSignature := normalize.ContentSignature(previous.subject)
			currentSignature := normalize.ContentSignature(current.subject)
			if previousSignature == currentSignature {
				continue
			}
			comparisons = append(comparisons, bundle.CollectedComparison{
				Code:     bundle.CodeObservationChanged,
				Previous: bundle.CollectedSubjectRef{CaptureOrdinal: previous.capture, ItemIndex: previous.item},
				Current:  bundle.CollectedSubjectRef{CaptureOrdinal: current.capture, ItemIndex: current.item},
			})
			if normalize.StaleStatusPattern(previous.subject, current.subject) {
				comparisons = append(comparisons, bundle.CollectedComparison{
					Code:     bundle.CodeStaleStatusSuspected,
					Previous: bundle.CollectedSubjectRef{CaptureOrdinal: previous.capture, ItemIndex: previous.item},
					Current:  bundle.CollectedSubjectRef{CaptureOrdinal: current.capture, ItemIndex: current.item},
				})
			}
		}
	}
	sort.Slice(comparisons, func(i, j int) bool {
		if comparisons[i].Code != comparisons[j].Code {
			return comparisons[i].Code < comparisons[j].Code
		}
		if comparisons[i].Previous.CaptureOrdinal != comparisons[j].Previous.CaptureOrdinal {
			return comparisons[i].Previous.CaptureOrdinal < comparisons[j].Previous.CaptureOrdinal
		}
		return comparisons[i].Previous.ItemIndex < comparisons[j].Previous.ItemIndex
	})
	return comparisons, diagnostics, nil
}
