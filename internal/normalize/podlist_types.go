package normalize

import (
	"github.com/d4rpell/Ariadne/internal/identity"
	"github.com/d4rpell/Ariadne/internal/ingest"
	contract "github.com/d4rpell/Ariadne/pkg/evidence"
)

// The sanitized PodList adapter (ADR-0025) normalizes one admitted PodList
// parse into per-subject observations. This file does not reuse Normalize or
// the findings-import types: an observation run is a separate method with its
// own carriers, and it never fabricates a finding.

// ObservationDiagnostic is one preserved local diagnostic of the adapter,
// carried with the normalization result so provenance can report it.
type ObservationDiagnostic struct {
	Code      string
	Offset    uint64
	ItemIndex *int
	Locator   string
}

// ObservationContainer is one container identity of a subject with its spec
// declaration and, when observed, its status. Presence is explicit so a
// missing status is never confused with an observed empty one. SpecIndex and
// StatusIndex are the original positions in their own source arrays, used to
// render exact locators.
type ObservationContainer struct {
	Class contract.ContainerClass
	Name  string

	SpecIndex   int
	StatusIndex int

	SpecPresent bool
	Image       *string
	// ImagePresence keeps absence and emptiness apart: an omitted reference and
	// an empty one are different observations (A.7.3, A.9.3).
	ImagePresence ingest.PodPresence

	StatusPresent bool
	ImageID       *string
	StatusImage   *string
	Ready         *bool
	State         string
	RestartCount  *int64
	// ImageIDPresence, StatusImagePresence and StatePresence keep the same
	// distinction for the status fields and for an omitted state object.
	ImageIDPresence     ingest.PodPresence
	StatusImagePresence ingest.PodPresence
	StatePresence       ingest.PodPresence

	SpecOffset    uint64
	ImageOffset   uint64
	ImageIDOffset uint64
}

// ObservationSubject is one accepted Pod of the source with its containers and
// the coverage facts of its own categories. No bundle identity is fabricated
// here: the caller chooses the subject to build.
type ObservationSubject struct {
	ItemIndex int
	StartByte uint64
	EndByte   uint64

	UID       contract.UID
	Namespace contract.Namespace
	Name      string

	ResourceVersion         string
	ResourceVersionPresence ingest.PodPresence
	OwnerReferences         []ObservationOwnerReference

	Containers []ObservationContainer

	// CategoriesObserved records which spec categories were explicitly present.
	CategoriesObserved map[contract.ContainerClass]bool
	// CategoriesComplete records which categories had both spec and status
	// arrays explicitly present and fully associated.
	CategoriesComplete map[contract.ContainerClass]bool

	ContextConflict bool
	CollidedClasses map[string][]contract.ContainerClass
	Diagnostics     []ObservationDiagnostic
}

// ObservationOwnerReference is an admitted owner reference kept as context.
// It is never resolved nor encoded as an owner chain.
type ObservationOwnerReference struct {
	APIVersion string
	Kind       string
	Name       string
	UID        string
	Controller *bool
	BlockOwner *bool
	Offset     uint64
}

// ObservationSource is the admitted source of one observation run.
type ObservationSource struct {
	Name      string
	Hash      contract.SourceHash
	ByteCount uint64
}

// ObservationResult is the normalization of one admitted PodList parse.
type ObservationResult struct {
	Source            ObservationSource
	Namespace         contract.Namespace
	ClusterAlias      contract.ClusterAlias
	ObservedAt        *contract.Timestamp
	Termination       contract.CoverageTermination
	Subjects          []ObservationSubject
	RejectedItems     uint64
	TotalItems        uint64
	GlobalDiagnostics []ObservationDiagnostic
}

// ObservationBinding is the explicit identity binding of one container of one
// subject. It carries only admitted facts: requested reference, observed raw
// image ID and the observation time. GuaranteedDigest is never set by this
// adapter (ADR-0025 A.8.3).
type ObservationBinding struct {
	Key            identity.ContainerKey
	RequestedImage *contract.RequestedImage
	RawImageID     *contract.RawImageID
	ObservedAt     *contract.Timestamp
	SourceName     string
	SourceHash     contract.SourceHash
	Locator        contract.SourceLocator
}
