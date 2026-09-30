package bundle

import (
	"github.com/d4rpell/Ariadne/internal/normalize"
	contract "github.com/d4rpell/Ariadne/pkg/evidence"
)

// Observation provenance of ADR-0025 A.9.4: the run metadata is fixed and
// honest. No permissions exercised, no argv, no remote metrics and no ruleset
// are invented; the coverage method is container_observation with rows null,
// and every rejection of the source stays visible as an error.

// observationProvenance assembles the run provenance of one subject.
func observationProvenance(input ObservationInput, subject normalize.ObservationSubject, warnings []contract.Warning, errors []string, completeness contract.Completeness) contract.RunProvenance {
	return contract.RunProvenance{
		CollectorVersion: observationCollectorLabel,
		ParserVersion:    input.ParserVersion,
		Ruleset:          contract.RulesetRef{},
		ArgvSanitized:    []string{},
		Inputs: []contract.InputRef{{
			Path: input.Result.Source.Name,
			Hash: input.Result.Source.Hash,
		}},
		APIScope: contract.APIScope{
			Namespaces: []contract.Namespace{input.Result.Namespace},
			// The adapter neither executed nor verified an API call.
			Verbs: []string{},
			// The object of the observation, never an exercised permission.
			Resources: []string{"pods"},
		},
		StartedAt: copyPointer(input.StartedAt),
		EndedAt:   copyPointer(input.EndedAt),
		Budget:    input.Budget,
		Coverage: contract.Coverage{
			Method:      contract.CoverageContainerObservation,
			Termination: input.Result.Termination,
			Rows:        nil,
		},
		Completeness:    completeness,
		Consistency:     contract.ConsistencyNotAtomic,
		RedactionPolicy: sanitizedPodListRedactionPolicy,
		Warnings:        warnings,
		Errors:          errors,
	}
}

// sanitizedPodListRedactionPolicy is the only policy this adapter acknowledges.
// It is a program constant, never an input value.
const sanitizedPodListRedactionPolicy = "sanitized-podlist-v1/1.0"

// observationCollectorLabel is the fixed collector identification of A.9.4: the
// adapter never executed a collector, so no caller-supplied label is published
// as if it had.
const observationCollectorLabel = "operator-export"

// observationWarnings assembles the wire warnings of one subject. Only the
// existing codes are used, and the general incompleteness warning is emitted
// whenever the result is not complete.
func observationWarnings(subject normalize.ObservationSubject, conflicts bool, collisionClasses [][]contract.ContainerClass, incomplete bool) ([]contract.Warning, error) {
	warnings := []contract.Warning{}
	if incomplete {
		warnings = append(warnings, contract.Warning{
			Code:    "partial_observation",
			Class:   contract.WarningContradictory,
			Message: "container observation is incomplete",
		})
	}
	if conflicts {
		warnings = append(warnings, contract.Warning{
			Code:    "source_conflict",
			Class:   contract.WarningContradictory,
			Message: "source contains conflicting Pod identity context",
		})
	}
	warnings = append(warnings, contract.Warning{
		Code:    "redaction_applied",
		Class:   contract.WarningInformational,
		Message: "input was supplied under the sanitized PodList policy",
	})
	for _, classes := range collisionClasses {
		collision, err := observationCollisionWarning(classes)
		if err != nil {
			return nil, err
		}
		warnings = append(warnings, collision)
	}
	return warnings, nil
}

// observationErrors translates the preserved diagnostics into sanitized error
// strings. The formatters are the existing ones: the allowlisted code and the
// verified offset, never a raw error or an input value. A rejection the producer
// already stated as a diagnostic is not repeated here.
func observationErrors(subject normalize.ObservationSubject, global []normalize.ObservationDiagnostic, rejected bool, preserved map[string]bool) []string {
	messages := []string{}
	for _, diagnostic := range global {
		messages = append(messages, formatObservationDiagnostic(diagnostic))
	}
	for _, diagnostic := range subject.Diagnostics {
		messages = append(messages, formatObservationDiagnostic(diagnostic))
	}
	if rejected && !preserved["source_items_rejected"] {
		messages = append(messages, "ingest: sanitized-podlist-v1: byte/0: source contains rejected Pod items")
	}
	return messages
}

func formatObservationDiagnostic(diagnostic normalize.ObservationDiagnostic) string {
	return podListDiagnosticText(diagnostic.Code, diagnostic.Offset, diagnostic.Locator)
}
