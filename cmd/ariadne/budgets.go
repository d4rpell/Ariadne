package main

import (
	"github.com/d4rpell/Ariadne/internal/evaluator"
	contract "github.com/d4rpell/Ariadne/pkg/evidence"
)

// Preflight of the four model budgets of ADR-0013 §5.4 (ADR-0023 §4.2). The
// adapter applies them to the decoded model *before* validation, copying,
// sorting or re-encoding, so an oversized document cannot reach the canonical
// encoder. The inventory mirrors internal/evaluator/input.go measureBundle field
// by field: same four budgets, same units, same early stop, no new limit and no
// change to the evaluator's API or precedence. Raw-file bounds are a different
// layer and never substitute for these.

type budgetState struct {
	items    uint64
	images   uint64
	elements uint64
	bytes    uint64
	over     bool
}

func (state *budgetState) addCount(value *uint64, count int, limit uint64) {
	if state.over || count <= 0 {
		return
	}
	*value += uint64(count)
	if *value > limit {
		state.over = true
	}
}

func (state *budgetState) addString(value string) {
	if state.over {
		return
	}
	state.bytes += uint64(len(value))
	if state.bytes > evaluator.MaxBundleStringBytes {
		state.over = true
	}
}

func (state *budgetState) addOptional(value *string) {
	if value == nil {
		return
	}
	state.addString(*value)
}

func (state *budgetState) addWarning(warning contract.Warning) {
	state.addString(warning.Code)
	state.addString(string(warning.Class))
	state.addString(warning.Message)
}

// measureForCLI returns true when the decoded bundle stays inside every budget.
// Cardinalities are checked first and the walk stops at the first excess: a
// bundle that already fails a count budget is never walked for its strings.
func measureForCLI(bundle contract.Bundle) bool {
	state := budgetState{}

	state.addCount(&state.items, len(bundle.Evidence), evaluator.MaxEvidenceItems)
	state.addCount(&state.images, len(bundle.Images), evaluator.MaxImages)

	state.addCount(&state.elements, len(bundle.Images), evaluator.MaxCollectionElements)
	state.addCount(&state.elements, len(bundle.Evidence), evaluator.MaxCollectionElements)
	state.addCount(&state.elements, len(bundle.ObservedContainerClasses), evaluator.MaxCollectionElements)
	state.addCount(&state.elements, len(bundle.Provenance.ArgvSanitized), evaluator.MaxCollectionElements)
	state.addCount(&state.elements, len(bundle.Provenance.Inputs), evaluator.MaxCollectionElements)
	state.addCount(&state.elements, len(bundle.Provenance.APIScope.Namespaces), evaluator.MaxCollectionElements)
	state.addCount(&state.elements, len(bundle.Provenance.APIScope.Verbs), evaluator.MaxCollectionElements)
	state.addCount(&state.elements, len(bundle.Provenance.APIScope.Resources), evaluator.MaxCollectionElements)
	state.addCount(&state.elements, len(bundle.Provenance.Warnings), evaluator.MaxCollectionElements)
	state.addCount(&state.elements, len(bundle.Provenance.Errors), evaluator.MaxCollectionElements)
	for _, item := range bundle.Evidence {
		if state.over {
			break
		}
		state.addCount(&state.elements, len(item.Warnings), evaluator.MaxCollectionElements)
	}
	if state.over {
		return false
	}

	state.addString(bundle.SchemaVersion)
	state.addString(string(bundle.Subject.ClusterAlias))
	state.addString(string(bundle.Subject.Namespace))
	state.addString(bundle.Subject.Kind)
	state.addString(bundle.Subject.Name)
	state.addString(string(bundle.Subject.UID))
	state.addString(string(bundle.Subject.OwnerChain))
	for _, class := range bundle.ObservedContainerClasses {
		if state.over {
			break
		}
		state.addString(string(class))
	}
	for _, image := range bundle.Images {
		if state.over {
			break
		}
		state.addString(string(image.ContainerClass))
		state.addString(string(image.ContainerName))
		state.addOptional((*string)(image.RequestedImage))
		state.addOptional((*string)(image.RawImageID))
		state.addOptional((*string)(image.NormalizedDigest))
		state.addString(image.Platform.OS)
		state.addString(image.Platform.Architecture)
		state.addString(string(image.Platform.Status))
	}
	for _, item := range bundle.Evidence {
		if state.over {
			break
		}
		state.addString(item.Type)
		state.addString(item.Source)
		state.addString(string(item.SourceHash))
		state.addString(string(item.Locator))
		state.addOptional(item.Value)
		state.addOptional((*string)(item.ValueHash))
		state.addString(string(item.Confidence))
		state.addString(string(item.Scope.SubjectUID))
		state.addString(string(item.Scope.ContainerName))
		for _, warning := range item.Warnings {
			if state.over {
				break
			}
			state.addWarning(warning)
		}
	}
	state.addString(bundle.Provenance.CollectorVersion)
	state.addString(bundle.Provenance.ParserVersion)
	state.addString(bundle.Provenance.Ruleset.Path)
	state.addString(string(bundle.Provenance.Ruleset.Hash))
	state.addString(bundle.Provenance.Ruleset.Version)
	for _, argument := range bundle.Provenance.ArgvSanitized {
		if state.over {
			break
		}
		state.addString(argument)
	}
	for _, input := range bundle.Provenance.Inputs {
		if state.over {
			break
		}
		state.addString(input.Path)
		state.addString(string(input.Hash))
	}
	for _, namespace := range bundle.Provenance.APIScope.Namespaces {
		if state.over {
			break
		}
		state.addString(string(namespace))
	}
	for _, verb := range bundle.Provenance.APIScope.Verbs {
		if state.over {
			break
		}
		state.addString(verb)
	}
	for _, resource := range bundle.Provenance.APIScope.Resources {
		if state.over {
			break
		}
		state.addString(resource)
	}
	state.addString(bundle.Provenance.Budget.WallClock)
	state.addString(string(bundle.Provenance.Coverage.Method))
	state.addString(string(bundle.Provenance.Coverage.Termination))
	state.addString(string(bundle.Provenance.Completeness))
	state.addString(string(bundle.Provenance.Consistency))
	state.addString(bundle.Provenance.RedactionPolicy)
	for _, warning := range bundle.Provenance.Warnings {
		if state.over {
			break
		}
		state.addWarning(warning)
	}
	for _, message := range bundle.Provenance.Errors {
		if state.over {
			break
		}
		state.addString(message)
	}
	return !state.over
}
