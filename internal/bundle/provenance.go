package bundle

import (
	"strings"

	"github.com/d4rpell/Ariadne/internal/identity"
	"github.com/d4rpell/Ariadne/internal/normalize"
	contract "github.com/d4rpell/Ariadne/pkg/evidence"
)

// containerClassOrder is the canonical enum order of ADR-0006; the collision
// message lists the affected classes in this order, never in appearance order
// and never lexicographically.
var containerClassOrder = []contract.ContainerClass{
	contract.ContainerRegular,
	contract.ContainerInit,
	contract.ContainerEphemeral,
}

// scopeCollisionWarning builds the visible warning of one collided key. The
// text is a program constant plus validated enum literals: no uid, container
// name, locator or any other input value is interpolated (ADR-0010 §2).
func scopeCollisionWarning(classes []contract.ContainerClass) (contract.Warning, error) {
	ordered, err := orderedClasses(classes)
	if err != nil {
		return contract.Warning{}, err
	}
	return contract.Warning{
		Code:    "scope_mismatch",
		Class:   contract.WarningContradictory,
		Message: "scope collision across container classes: " + strings.Join(ordered, ", "),
	}, nil
}

func orderedClasses(classes []contract.ContainerClass) ([]string, error) {
	present := make(map[contract.ContainerClass]bool, len(classes))
	for _, class := range classes {
		if !class.Valid() {
			return nil, errCollisionClassUnknown
		}
		present[class] = true
	}
	ordered := make([]string, 0, len(present))
	for _, class := range containerClassOrder {
		if present[class] {
			ordered = append(ordered, string(class))
		}
	}
	return ordered, nil
}

// importErrors translates the preserved ingest diagnostics into the sanitized
// error strings of provenance. The formatters are the existing ones: the
// allowlisted reason and the stream locator, never a raw reader error or an
// input value.
func importErrors(diagnostics normalize.Diagnostics) []string {
	messages := make([]string, 0, len(diagnostics.Rejections)+1)
	for _, rejection := range diagnostics.Rejections {
		messages = append(messages, rejection.String())
	}
	if diagnostics.StructuralError != nil {
		messages = append(messages, diagnostics.StructuralError.Error())
	}
	return messages
}

// observationProvenanceComplete reports whether a binding carries a source, a
// source hash, a locator and an observation timestamp that the wire accepts.
// Only then can its facts become evidence items.
func observationProvenanceComplete(binding identity.ImageBinding) bool {
	return identifierOK(binding.SourceName) &&
		isSha256(string(binding.SourceHash)) &&
		identifierOK(string(binding.Locator)) &&
		timestampOK(binding.ObservedAt)
}

// buildProvenance assembles the run provenance. The coverage and completeness
// of the import are preserved; a projection defect adds a visible error and
// therefore makes the bundle partial, never complete with evidence missing
// (ADR-0012 §3).
func buildProvenance(run RunContext, normalized normalize.Result, source ImportSource, collisionWarnings []contract.Warning, messages []string) contract.RunProvenance {
	completeness := normalized.Completeness
	if len(messages) > 0 && completeness == contract.CompletenessComplete {
		completeness = contract.CompletenessPartial
	}
	warnings := make([]contract.Warning, 0, len(run.Warnings)+len(collisionWarnings))
	warnings = append(warnings, run.Warnings...)
	warnings = append(warnings, collisionWarnings...)
	errors := make([]string, 0, len(messages))
	errors = append(errors, messages...)
	return contract.RunProvenance{
		CollectorVersion: run.CollectorVersion,
		ParserVersion:    run.ParserVersion,
		Ruleset:          contract.RulesetRef{},
		ArgvSanitized:    run.ArgvSanitized,
		Inputs:           []contract.InputRef{{Path: source.Path, Hash: source.Hash}},
		APIScope: contract.APIScope{
			Namespaces: []contract.Namespace{},
			Verbs:      []string{},
			Resources:  []string{},
		},
		StartedAt:       run.StartedAt,
		EndedAt:         run.EndedAt,
		Budget:          run.Budget,
		Coverage:        copyCoverage(normalized.Coverage),
		Completeness:    completeness,
		Consistency:     run.Consistency,
		RedactionPolicy: run.RedactionPolicy,
		Warnings:        warnings,
		Errors:          errors,
	}
}
