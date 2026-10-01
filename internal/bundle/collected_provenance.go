package bundle

import (
	"sort"

	"github.com/d4rpell/Ariadne/internal/normalize"
	contract "github.com/d4rpell/Ariadne/pkg/evidence"
)

// Provenance of the live collector (ADR-0026 A.7.5). Every claim is derived
// from the acquisition record the collector really produced: the installed
// implementation, the parser it really used, the inputs of the capture, the
// namespaces and verbs really attempted and the effective termination. Nothing
// is copied from the caller and no permission is invented.

const (
	// collectedSelector identifies the acquisition profile of this builder.
	collectedSelector = "k8s-pod-read-v1"
	// collectedVersion is the only supported version of that profile.
	collectedVersion = "1.0"
	// collectedRedactionPolicy is the policy stamped on every provenance.
	collectedRedactionPolicy = "k8s-pod-read-v1/1.0"
	// collectedCollectorVersion identifies this implementation of the profile.
	collectedCollectorVersion = "ariadne-collector/k8s-pod-read-v1"
	// collectedParserVersion identifies the parser really used to admit the
	// sanitized source: the A2-01 sanitized PodList reader.
	collectedParserVersion = "sanitized-podlist-v1/1.0"

	// collectedBudgetWallClock is the declared wall-clock bound of the run.
	collectedBudgetWallClock = "5m"
	// collectedBudgetRequests is the declared request bound.
	collectedBudgetRequests = 1024
	// collectedBudgetObjects is the declared object bound.
	collectedBudgetObjects = 1024
	// collectedBudgetBytes is the declared accumulated byte bound.
	collectedBudgetBytes = 67108864
)

// collectedProvenance assembles the provenance of one subject of one capture.
// Every failure of the run reaches every affected bundle: the concrete global
// error is preserved together with the termination, so selecting one subject
// never erases a failure of the acquisition.
func collectedProvenance(input CollectedObservationInput, capture CollectedCapture, completeness contract.Completeness, omitted bool) contract.RunProvenance {
	acquisition := input.Acquisition
	subject := input.Result.Subjects[input.SubjectIndex]

	inputs := []contract.InputRef{{
		Path: capture.Alias,
		Hash: capture.Hash,
	}}
	sources := map[uint64]bool{capture.Ordinal: true}
	comparisonByOrdinal := map[uint64]CollectedCapture{}
	for _, candidate := range acquisition.Captures {
		comparisonByOrdinal[candidate.Ordinal] = candidate
	}
	for _, comparison := range acquisition.Comparisons {
		// Only the comparisons that concern the selected subject cite their
		// sources: a difference observed elsewhere in the run is not an input of
		// this bundle.
		if !comparisonReferences(comparison, capture.Ordinal, subject.ItemIndex) {
			continue
		}
		for _, reference := range []CollectedSubjectRef{comparison.Previous, comparison.Current} {
			if sources[reference.CaptureOrdinal] {
				continue
			}
			// A comparison input is only cited when it exists as a capture: the
			// record never names a source it does not carry.
			if candidate, known := comparisonByOrdinal[reference.CaptureOrdinal]; known {
				sources[reference.CaptureOrdinal] = true
				inputs = append(inputs, contract.InputRef{Path: candidate.Alias, Hash: candidate.Hash})
			}
		}
	}

	namespaces := []contract.Namespace{}
	seenNamespaces := map[contract.Namespace]bool{}
	verbs := []string{}
	seenVerbs := map[string]bool{}
	sawPods := false
	for _, operation := range acquisition.Operations {
		switch operation.State {
		case OperationAttempted, OperationFinished, OperationFailed:
		default:
			continue
		}
		if !seenNamespaces[operation.Namespace] {
			seenNamespaces[operation.Namespace] = true
			namespaces = append(namespaces, operation.Namespace)
		}
		if !seenVerbs[operation.Verb] {
			seenVerbs[operation.Verb] = true
			verbs = append(verbs, operation.Verb)
		}
		sawPods = true
	}
	sort.Slice(namespaces, func(i, j int) bool { return namespaces[i] < namespaces[j] })
	sort.Strings(verbs)
	resources := []string{}
	if sawPods {
		resources = append(resources, "pods")
	}

	// The errors of one subject: the concrete run-wide failures first, then the
	// preserved diagnostics of the admitted source, the diagnostics of the
	// acquisition that concern this subject or its run, the omissions caused by
	// an incomplete result and the collision of this subject. The formatters are
	// the existing ones; no raw error text reaches this list.
	preserved := observationDiagnosticCodes(subject, input.Result.GlobalDiagnostics)
	errors := append([]string{}, acquisition.GlobalErrors...)
	errors = append(errors, observationErrors(subject, input.Result.GlobalDiagnostics, input.Result.RejectedItems > 0, preserved)...)
	errors = append(errors, collectedDiagnosticErrors(acquisition, capture)...)
	errors = append(errors, observationIncompletenessErrors(subject, preserved, acquisition.Termination, completeness)...)
	if omitted {
		errors = append(errors, errScopeCollisionOmitted.Error())
	}

	return contract.RunProvenance{
		CollectorVersion: collectedCollectorVersion,
		ParserVersion:    collectedParserVersion,
		Ruleset:          contract.RulesetRef{},
		ArgvSanitized:    []string{},
		Inputs:           inputs,
		APIScope: contract.APIScope{
			Namespaces: namespaces,
			Verbs:      verbs,
			Resources:  resources,
		},
		StartedAt: copyPointer(acquisition.StartedAt),
		EndedAt:   copyPointer(acquisition.EndedAt),
		Budget: contract.Budget{
			WallClock: collectedBudgetWallClock,
			Requests:  collectedBudgetRequests,
			Objects:   collectedBudgetObjects,
			Bytes:     collectedBudgetBytes,
		},
		Coverage: contract.Coverage{
			Method:      contract.CoverageContainerObservation,
			Termination: acquisition.Termination,
			Rows:        nil,
		},
		Completeness:    completeness,
		Consistency:     contract.ConsistencyNotAtomic,
		RedactionPolicy: collectedRedactionPolicy,
		Warnings:        collectedSubjectWarnings(subject, completeness, acquisition.GlobalWarnings, acquisition.Comparisons, capture),
		Errors:          errors,
	}
}

// collectedDiagnosticErrors projects the acquisition diagnostics that concern
// one subject or the whole run into the closed error vocabulary of the bundle.
// The message of a code is always "collector: <code>": the cause of a degraded
// integrity fact (a missing list resourceVersion, a rejected Pod) is preserved
// in the expedient instead of disappearing behind the completeness verdict.
//
// A diagnostic of another capture is copied only when its code contaminates the
// run as a whole (the same codes that forbid "complete" for every bundle): the
// degradation it causes is visible in this bundle, so its cause must be too. A
// diagnostic of another capture that affects nobody else stays out.
func collectedDiagnosticErrors(acquisition CollectedAcquisition, capture CollectedCapture) []string {
	errors := []string{}
	for _, diagnostic := range acquisition.Diagnostics {
		own := diagnostic.CaptureOrdinal == nil || *diagnostic.CaptureOrdinal == capture.Ordinal
		if !own && !acquisitionContaminatingCode(diagnostic.Code) {
			continue
		}
		message := CollectionMessage(diagnostic.Code)
		if message == "" {
			continue
		}
		present := false
		for _, existing := range errors {
			if existing == message {
				present = true
				break
			}
		}
		if !present {
			errors = append(errors, message)
		}
	}
	return errors
}

// comparisonReferences reports whether one comparison concerns the subject
// identified by a capture ordinal and an original item index.
func comparisonReferences(comparison CollectedComparison, captureOrdinal uint64, itemIndex int) bool {
	for _, reference := range []CollectedSubjectRef{comparison.Previous, comparison.Current} {
		if reference.CaptureOrdinal == captureOrdinal && reference.ItemIndex == itemIndex {
			return true
		}
	}
	return false
}

// collectedComparisonWarnings renders the wire warnings that the comparisons of
// this subject produce. The codes, classes and messages are the frozen
// vocabulary of wire 0.2; a comparison that does not reference this subject
// never becomes its warning.
func collectedComparisonWarnings(comparisons []CollectedComparison, capture CollectedCapture, itemIndex int) []contract.Warning {
	warnings := []contract.Warning{}
	seen := map[string]bool{}
	for _, comparison := range comparisons {
		references := false
		for _, reference := range []CollectedSubjectRef{comparison.Previous, comparison.Current} {
			if reference.CaptureOrdinal == capture.Ordinal && reference.ItemIndex == itemIndex {
				references = true
			}
		}
		if !references {
			continue
		}
		var warning contract.Warning
		switch comparison.Code {
		case CodeUIDChanged:
			warning = contract.Warning{
				Code:    "uid_changed",
				Class:   contract.WarningContradictory,
				Message: "Pod UID changed between collection observations",
			}
		case CodeObservationChanged:
			warning = contract.Warning{
				Code:    "source_conflict",
				Class:   contract.WarningContradictory,
				Message: "collection observations contain differing projected content",
			}
		case CodeStaleStatusSuspected:
			warning = contract.Warning{
				Code:    "stale_observation",
				Class:   contract.WarningContradictory,
				Message: "status freshness could not be established after a spec change",
			}
		default:
			continue
		}
		if seen[warning.Code] {
			continue
		}
		seen[warning.Code] = true
		warnings = append(warnings, warning)
	}
	return warnings
}

// collectedSubjectWarnings renders the wire warnings of one subject of a live
// acquisition: the incompleteness warning, the run-wide failures, the
// projection warning of the collector, the warnings of its comparisons and the
// collision warnings of the admitted observation. Codes, classes and messages
// are the frozen vocabulary of wire 0.2.
func collectedSubjectWarnings(subject normalize.ObservationSubject, completeness contract.Completeness, global []contract.Warning, comparisons []CollectedComparison, capture CollectedCapture) []contract.Warning {
	warnings := []contract.Warning{}
	if completeness != contract.CompletenessComplete {
		warnings = append(warnings, contract.Warning{
			Code:    "partial_observation",
			Class:   contract.WarningContradictory,
			Message: "container observation is incomplete",
		})
	}
	for _, warning := range global {
		// A run-wide warning is kept once: the incompleteness warning above may
		// already state the same fact.
		if warning.Code == "partial_observation" && len(warnings) > 0 && warnings[0].Code == "partial_observation" {
			continue
		}
		warnings = append(warnings, warning)
	}
	warnings = append(warnings, collectedComparisonWarnings(comparisons, capture, subject.ItemIndex)...)
	warnings = append(warnings, contract.Warning{
		Code:    "redaction_applied",
		Class:   contract.WarningInformational,
		Message: "collector applied the admitted Pod field projection",
	})
	collisionClasses := [][]contract.ContainerClass{}
	for name := range subject.CollidedClasses {
		if !identifierOK(name) {
			continue
		}
		collisionClasses = append(collisionClasses, subject.CollidedClasses[name])
	}
	sort.Slice(collisionClasses, func(i, j int) bool {
		return classesText(collisionClasses[i]) < classesText(collisionClasses[j])
	})
	for _, classes := range collisionClasses {
		warning, err := observationCollisionWarning(classes)
		if err != nil {
			continue
		}
		warnings = append(warnings, warning)
	}
	return warnings
}

// classesText renders one class list as a deterministic sort key. Every value
// is an enum literal of the wire; nothing else is ever published.
func classesText(classes []contract.ContainerClass) string {
	text := ""
	for _, class := range classes {
		text += string(class) + ","
	}
	return text
}
