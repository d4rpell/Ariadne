package report

import (
	"sort"
	"strings"

	"github.com/d4rpell/Ariadne/internal/evaluator"
	contract "github.com/d4rpell/Ariadne/pkg/evidence"
)

// resolveCatalogs builds the two catalogs exclusively from the references the
// Result carries and the canonical bundle they name. The evidence array is
// concatenated in the ratified order — global references, then candidates, then
// each rule with its own checks, then the items cited only by warnings — and
// stably sorted by index; every occurrence is preserved and no item outside the
// references is added.
func resolveCatalogs(result evaluator.Result, bundle contract.Bundle) ([]ResolvedEvidenceDTO, []ResolvedWarningDTO, error) {
	references := collectReferences(result)
	evidence := make([]ResolvedEvidenceDTO, 0, len(references))
	for _, reference := range references {
		if reference.ItemIndex < 0 || reference.ItemIndex >= len(bundle.Evidence) {
			return nil, nil, problem(CodeInvalidReference)
		}
		item := bundle.Evidence[reference.ItemIndex]
		if item.Scope.SubjectUID != result.Target.SubjectUID || item.Scope.ContainerName != result.Target.ContainerName {
			// A citation of another subject is a contract error, never a silent
			// presentation of foreign evidence.
			return nil, nil, problem(CodeInvalidReference)
		}
		evidence = append(evidence, ResolvedEvidenceDTO{
			Reference:  ReferenceDTO{ItemIndex: reference.ItemIndex},
			Type:       item.Type,
			Source:     item.Source,
			SourceHash: string(item.SourceHash),
			Locator:    string(item.Locator),
			ObservedAt: formatTimestamp(*item.ObservedAt),
			Confidence: string(item.Confidence),
			Scope: ScopeDTO{
				SubjectUID:    string(item.Scope.SubjectUID),
				ContainerName: string(item.Scope.ContainerName),
			},
		})
	}
	sort.SliceStable(evidence, func(left, right int) bool {
		return evidence[left].Reference.ItemIndex < evidence[right].Reference.ItemIndex
	})

	warnings := make([]ResolvedWarningDTO, 0, len(result.WarningReferences))
	for _, reference := range result.WarningReferences {
		resolved, err := resolveWarning(reference, bundle)
		if err != nil {
			return nil, nil, err
		}
		warnings = append(warnings, resolved)
	}
	// The ratified catalog order of F0 §5 is (origin, evidence_index,
	// warning_index), compared as UTF-8 text and numbers. Occurrences are
	// preserved: equal warnings from two traces stay as two rows, and no index
	// is renumbered.
	sort.SliceStable(warnings, func(left, right int) bool {
		return compareWarningReferences(warnings[left].Reference, warnings[right].Reference) < 0
	})
	return evidence, warnings, nil
}

func compareWarningReferences(a, b WarningRefDTO) int {
	if result := strings.Compare(a.Origin, b.Origin); result != 0 {
		return result
	}
	if a.EvidenceIndex != b.EvidenceIndex {
		if a.EvidenceIndex < b.EvidenceIndex {
			return -1
		}
		return 1
	}
	switch {
	case a.WarningIndex < b.WarningIndex:
		return -1
	case a.WarningIndex > b.WarningIndex:
		return 1
	}
	return 0
}

// collectReferences concatenates every reference occurrence in the ratified
// order. Duplicates are kept: an item cited by two traces and by a warning has
// three rows.
func collectReferences(result evaluator.Result) []evaluator.EvidenceReference {
	references := make([]evaluator.EvidenceReference, 0, len(result.EvidenceReferences))
	references = append(references, result.EvidenceReferences...)
	for _, candidate := range result.Candidates {
		references = append(references, candidate.EvidenceReferences...)
	}
	for _, rule := range result.Rules {
		references = append(references, rule.EvidenceReferences...)
		for _, check := range rule.Checks {
			references = append(references, check.EvidenceReferences...)
		}
	}
	for _, warning := range result.WarningReferences {
		if warning.Origin == evaluator.WarningFromEvidence {
			references = append(references, evaluator.EvidenceReference{ItemIndex: warning.EvidenceIndex})
		}
	}
	return references
}

// resolveWarning locates one warning in the canonical arrays. Provenance
// warnings point at the run provenance and never generate an evidence row.
func resolveWarning(reference evaluator.WarningReference, bundle contract.Bundle) (ResolvedWarningDTO, error) {
	var warning contract.Warning
	switch reference.Origin {
	case evaluator.WarningFromProvenance:
		if reference.EvidenceIndex != -1 || reference.WarningIndex < 0 || reference.WarningIndex >= len(bundle.Provenance.Warnings) {
			return ResolvedWarningDTO{}, problem(CodeInvalidReference)
		}
		warning = bundle.Provenance.Warnings[reference.WarningIndex]
	case evaluator.WarningFromEvidence:
		if reference.EvidenceIndex < 0 || reference.EvidenceIndex >= len(bundle.Evidence) {
			return ResolvedWarningDTO{}, problem(CodeInvalidReference)
		}
		item := bundle.Evidence[reference.EvidenceIndex]
		if reference.WarningIndex < 0 || reference.WarningIndex >= len(item.Warnings) {
			return ResolvedWarningDTO{}, problem(CodeInvalidReference)
		}
		warning = item.Warnings[reference.WarningIndex]
	default:
		return ResolvedWarningDTO{}, problem(CodeInvalidReference)
	}
	// The message is omitted by presentation policy, for every warning and with
	// no exception: its free text is not something this contract controls.
	return ResolvedWarningDTO{
		Reference: WarningRefDTO{
			Origin:        string(reference.Origin),
			EvidenceIndex: reference.EvidenceIndex,
			WarningIndex:  reference.WarningIndex,
		},
		Code:    warning.Code,
		Class:   string(warning.Class),
		Message: nil,
	}, nil
}
