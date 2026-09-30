package bundle

import (
	"github.com/d4rpell/Ariadne/internal/normalize"
	contract "github.com/d4rpell/Ariadne/pkg/evidence"
)

// BuildObservation builds one bundle of one observation subject (ADR-0025
// A.9/A.11). It is a separate entry point from Build: an observation run is
// not a findings import, and no normalize.Result is fabricated to reuse that
// path.

// ObservationInput is everything BuildObservation consumes: the whole
// normalized observation run, the subject to build and the operational context
// the caller declares.
type ObservationInput struct {
	Result         normalize.ObservationResult
	SubjectIndex   int
	CollectorLabel string
	ParserVersion  string
	ObservedAt     *contract.Timestamp
	Budget         contract.Budget
	StartedAt      *contract.Timestamp
	EndedAt        *contract.Timestamp
}

// ObservationDiagnostics carries the preserved diagnostics and omissions of
// one observation build. It is never serialized as a bundle extension.
type ObservationDiagnostics struct {
	// Omitted lists the container keys left out of the projection, each with a
	// static reason.
	Omitted []ObservationOmission
}

// ObservationOmissionReason is the static vocabulary of observation omissions.
type ObservationOmissionReason string

const (
	// OmissionCollision is a collided scope omitted by ADR-0010 §2.
	OmissionCollision ObservationOmissionReason = "scope_collision"
)

// ObservationOmission reports one omitted container key with a static reason.
// It never carries the container name of a collided key or any input value
// beyond the identity that is already public in the bundle vocabulary.
type ObservationOmission struct {
	Key    observationKey
	Reason ObservationOmissionReason
	// Locator is the internal path of the observation that was omitted. It is
	// kept so the omission can be traced to its origin; no public evidence
	// reference is fabricated for an item that was never emitted (A.9.5).
	Locator contract.SourceLocator
}

type observationKey struct {
	ContainerClass contract.ContainerClass
	ContainerName  contract.ContainerName
}
