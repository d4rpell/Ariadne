package bundle

import (
	"errors"
	"fmt"

	canonical "github.com/d4rpell/Ariadne/internal/evidence"
	"github.com/d4rpell/Ariadne/internal/ingest"
	"github.com/d4rpell/Ariadne/internal/normalize"
	contract "github.com/d4rpell/Ariadne/pkg/evidence"
)

// Observation projection validation (ADR-0025 A.9, A.11.2): BuildObservation
// revalidates the normalized DTO before emitting bytes, so an incoherent
// intermediate value can never become evidence. A defect is a static error and
// an empty bundle; it is never repaired with defaults.

var (
	errObservationSubjectIndex = errors.New("bundle: observation subject index is out of range")
	errObservationSource       = errors.New("bundle: observation source is not a sha256 digest")
	errObservationNamespace    = errors.New("bundle: observation namespace is required")
	errObservationTime         = errors.New("bundle: observation time is required")
	errObservationCollector    = errors.New("bundle: collector label is required")
	errObservationParser       = errors.New("bundle: parser version is required")
	errObservationCoverage     = errors.New("bundle: observation coverage method is not container observation")
	errObservationTermination  = errors.New("bundle: capture termination is not declared")
	errObservationSubject      = errors.New("bundle: observation subject is not coherent")
	errObservationContainer    = errors.New("bundle: observation container is not coherent")
	errObservationCollision    = errors.New("bundle: observation scope collision is not coherent")
	errObservationDiagnostic   = errors.New("bundle: observation diagnostic is not coherent with the admitted source")
	errObservationAccounting   = errors.New("bundle: observation accounting is not coherent")
)

// observationContainerKey is the identity tuple of one container inside a
// subject. Names are compared as given: never trimmed, never merged.
type observationContainerKey struct {
	Class contract.ContainerClass
	Name  contract.ContainerName
}

func validateObservationInput(input ObservationInput) error {
	if !isSha256(string(input.Result.Source.Hash)) {
		return errObservationSource
	}
	if !identifierOK(input.Result.Source.Name) {
		return errObservationCollector
	}
	if input.CollectorLabel != "" && input.CollectorLabel != observationCollectorLabel {
		// The collector identification is fixed by the contract: a caller cannot
		// present a different one as provenance.
		return errObservationCollector
	}
	if !identifierOK(input.ParserVersion) {
		return errObservationParser
	}
	if !identifierOK(string(input.Result.Namespace)) {
		return errObservationNamespace
	}
	if !identifierOK(string(input.Result.ClusterAlias)) {
		return errObservationNamespace
	}
	// The accounting of the run is revalidated at this frontier too: the accepted
	// subjects plus the rejected items are the known total, and the subtraction is
	// checked without overflow.
	if input.Result.TotalItems < input.Result.RejectedItems ||
		uint64(len(input.Result.Subjects)) != input.Result.TotalItems-input.Result.RejectedItems {
		return errObservationAccounting
	}
	if !timestampOK(input.ObservedAt) {
		return errObservationTime
	}
	if input.Result.ObservedAt == nil || !input.ObservedAt.Time.Equal(input.Result.ObservedAt.Time) {
		// The observation time is the one the export declared; it is never
		// replaced by another instant supplied by the caller.
		return errObservationTime
	}
	if !input.Result.Termination.Valid() {
		return errObservationTermination
	}
	if input.SubjectIndex < 0 || input.SubjectIndex >= len(input.Result.Subjects) {
		return errObservationSubjectIndex
	}
	// The preserved diagnostics are part of the projection: an unknown code, a
	// locator outside the closed grammar or an offset beyond the admitted source
	// would publish text or a position that never existed. They are refused here
	// instead of being repaired.
	if err := validateObservationDiagnostics(input.Result); err != nil {
		return err
	}
	subject := input.Result.Subjects[input.SubjectIndex]
	if !identifierOK(string(subject.UID)) || string(subject.Namespace) != string(input.Result.Namespace) {
		return errObservationSubject
	}
	if !identifierOK(subject.Name) {
		return errObservationSubject
	}
	if subject.ItemIndex < 0 || subject.EndByte < subject.StartByte {
		return errObservationSubject
	}
	// A category cannot be complete without being observed, and it cannot be
	// complete when one of its own containers has no status: the DTO would claim
	// an association the containers deny.
	for _, class := range []contract.ContainerClass{
		contract.ContainerRegular, contract.ContainerInit, contract.ContainerEphemeral,
	} {
		if !subject.CategoriesComplete[class] {
			continue
		}
		if !subject.CategoriesObserved[class] {
			return errObservationSubject
		}
		for _, container := range subject.Containers {
			if container.Class == class && !container.StatusPresent {
				return errObservationSubject
			}
		}
	}
	seen := map[observationContainerKey]bool{}
	for _, container := range subject.Containers {
		if !container.Class.Valid() || !identifierOK(container.Name) {
			return errObservationContainer
		}
		// Presence, value and original position must agree: an observation that
		// carries a status value without a status, or without its own index,
		// would render a locator that never existed in the document.
		if container.SpecPresent != (container.SpecIndex >= 0) {
			return errObservationContainer
		}
		if container.StatusPresent != (container.StatusIndex >= 0) {
			return errObservationContainer
		}
		if (container.Image != nil || container.ImageID != nil || container.StatusImage != nil ||
			container.Ready != nil || container.RestartCount != nil || container.State != "") && !container.SpecPresent && !container.StatusPresent {
			return errObservationContainer
		}
		if (container.ImageID != nil || container.StatusImage != nil || container.Ready != nil ||
			container.RestartCount != nil) && !container.StatusPresent {
			return errObservationContainer
		}
		if container.Image != nil && !container.SpecPresent {
			return errObservationContainer
		}
		key := observationContainerKey{Class: container.Class, Name: contract.ContainerName(container.Name)}
		if seen[key] {
			return errObservationContainer
		}
		seen[key] = true
	}
	// The collided-name table must match the containers actually present, and it
	// is rebuilt here from them: a DTO that hides a collision would project two
	// observations whose wire scope is identical, and the wire validator cannot
	// see that. Equality is exact, including every class and the canonical order.
	expected := map[string][]contract.ContainerClass{}
	classesByName := map[string]map[contract.ContainerClass]bool{}
	for _, container := range subject.Containers {
		if classesByName[container.Name] == nil {
			classesByName[container.Name] = map[contract.ContainerClass]bool{}
		}
		classesByName[container.Name][container.Class] = true
	}
	for name, classes := range classesByName {
		if len(classes) < 2 {
			continue
		}
		expected[name] = orderedContainerClasses(classes)
	}
	if len(expected) != len(subject.CollidedClasses) {
		return errObservationCollision
	}
	for name, classes := range expected {
		declared, present := subject.CollidedClasses[name]
		if !present || !identifierOK(name) || !sameClasses(declared, classes) {
			return errObservationCollision
		}
	}
	return nil
}

// sameClasses compares two class lists exactly, order included.
func sameClasses(left, right []contract.ContainerClass) bool {
	if len(left) != len(right) {
		return false
	}
	for index, class := range left {
		if right[index] != class {
			return false
		}
	}
	return true
}

// orderedContainerClasses returns one container class set in the canonical
// order of the profile: regular, init, ephemeral.
func orderedContainerClasses(classes map[contract.ContainerClass]bool) []contract.ContainerClass {
	ordered := make([]contract.ContainerClass, 0, len(classes))
	for _, class := range containerClassOrder {
		if classes[class] {
			ordered = append(ordered, class)
		}
	}
	return ordered
}

// observationCollided reports whether one container key is omitted by a
// collision.
func observationCollided(subject normalize.ObservationSubject, class contract.ContainerClass, name string) bool {
	classes, collided := subject.CollidedClasses[name]
	if !collided {
		return false
	}
	for _, candidate := range classes {
		if candidate == class {
			return true
		}
	}
	return false
}

// observationCollisionWarning builds the visible collision warning. The message
// is a program constant plus validated enum literals: no uid, container name or
// locator is interpolated (ADR-0025 A.8.4).
func observationCollisionWarning(classes []contract.ContainerClass) (contract.Warning, error) {
	ordered, err := orderedClasses(classes)
	if err != nil {
		return contract.Warning{}, err
	}
	return contract.Warning{
		Code:    "scope_mismatch",
		Class:   contract.WarningContradictory,
		Message: "scope collision across container classes: " + joinComma(ordered),
	}, nil
}

func joinComma(values []string) string {
	joined := ""
	for index, value := range values {
		if index > 0 {
			joined += ", "
		}
		joined += value
	}
	return joined
}

// observationRequestedLiteral keeps the declared reference exactly as the
// source carried it: no composition, no tag or digest repair. A value that the
// wire cannot carry verbatim is still recorded by hash but left out of the
// evidence value, exactly like the CSV path (ADR-0012 §1).
func observationRequestedLiteral(value string) string {
	return value
}

// observationValuePreimage is the exact preimage of a value hash: the UTF-8
// bytes of the decoded value, with no quoting and no added newline.
func observationValuePreimage(value string) []byte {
	return []byte(value)
}

// observationLocatorOf renders the exact locator of one observed field, as the
// normalize stage computed it from the original document positions.
func observationLocatorOf(binding normalize.ObservationBinding) string {
	return string(binding.Locator)
}

// validateObservationBundle runs the canonical validation of the assembled
// bundle. The wire rules are the existing ones; this adapter adds no exception.
func validateObservationBundle(bundle contract.Bundle) (contract.Bundle, error) {
	return canonical.NewBundle(bundle)
}

// formatObservationError attaches the static diagnostic to a bundle error
// without ever including an input value.
func formatObservationError(base error, detail string) error {
	if detail == "" {
		return base
	}
	return fmt.Errorf("%w: %s", base, detail)
}

// validateObservationDiagnostics refuses the diagnostics of one normalized run
// that cannot belong to an admitted source: a code outside the closed catalog, a
// locator that is not a path of the admitted document, or an offset past the
// last byte of that source.
func validateObservationDiagnostics(result normalize.ObservationResult) error {
	check := func(code string, offset uint64, locator string) error {
		if !ingest.PodListCodeKnown(code) {
			return errObservationDiagnostic
		}
		if !ingest.PodListLocatorValid(locator) {
			return errObservationDiagnostic
		}
		if offset > result.Source.ByteCount {
			return errObservationDiagnostic
		}
		// An anchor is the first byte of a token, so it lies strictly inside the
		// source. The only exception is invalid_json, whose anchor is the total
		// number of bytes received when the input ends inside a structure or an
		// escape; every other code, invalid_surrogate included, anchors on a byte
		// that exists.
		if offset >= result.Source.ByteCount && code != "invalid_json" {
			return errObservationDiagnostic
		}
		return nil
	}
	for _, diagnostic := range result.GlobalDiagnostics {
		if err := check(diagnostic.Code, diagnostic.Offset, diagnostic.Locator); err != nil {
			return err
		}
	}
	for _, subject := range result.Subjects {
		// A declared interval must be coherent with the admitted source; a DTO that
		// carries none is not contradicting itself, so the check applies only when
		// the producer declared the interval.
		if subject.StartByte != 0 || subject.EndByte != 0 {
			// EndByte is the last byte of the interval, inclusive, so it can never
			// be the first byte past the source.
			if subject.StartByte >= subject.EndByte || subject.EndByte >= result.Source.ByteCount {
				return errObservationSubject
			}
		}
		for _, diagnostic := range subject.Diagnostics {
			if err := check(diagnostic.Code, diagnostic.Offset, diagnostic.Locator); err != nil {
				return err
			}
			// A diagnostic of a subject is anchored inside that subject's own
			// interval whenever the producer declared it.
			if subject.EndByte != 0 || subject.StartByte != 0 {
				if diagnostic.Offset < subject.StartByte || diagnostic.Offset > subject.EndByte {
					return errObservationDiagnostic
				}
			}
		}
	}
	return nil
}
