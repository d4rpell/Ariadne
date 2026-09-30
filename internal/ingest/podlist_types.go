package ingest

import (
	"time"

	contract "github.com/d4rpell/Ariadne/pkg/evidence"
)

// PodListContext is the explicit observation context required by
// ParseSanitizedPodList (ADR-0025 A.6). Every field must be supplied by the
// caller: no clock, mtime, resourceVersion or Kubernetes timestamp is read.
type PodListContext struct {
	Selector           string
	Version            string
	RedactionPolicy    string
	SourceName         string
	ClusterAlias       string
	Namespace          string
	ObservedAt         time.Time
	CaptureTermination contract.CoverageTermination
}

// PodPresence records whether an optional field was present and, when present,
// whether it was empty. A zero value never stands in for an absent field.
type PodPresence uint8

const (
	PresenceAbsent PodPresence = iota
	PresenceEmpty
	PresenceValue
)

// PodOptionalString is one optional string field with explicit presence.
type PodOptionalString struct {
	Present PodPresence
	Value   string
}

// PodOptionalBool is one optional boolean field with explicit presence.
type PodOptionalBool struct {
	Present PodPresence
	Value   bool
}

// PodOptionalInt is one optional integer field with explicit presence.
type PodOptionalInt struct {
	Present PodPresence
	Value   int64
}

// PodOwnerReference is one admitted owner reference, kept as context only: it
// is never resolved, followed or encoded as an owner chain.
type PodOwnerReference struct {
	APIVersion         string
	Kind               string
	Name               string
	UID                string
	OwnerController    PodOptionalBool
	BlockOwnerDeletion PodOptionalBool
	Offset             uint64
}

// PodContainerSpec is one admitted spec container declaration.
type PodContainerSpec struct {
	Class    contract.ContainerClass
	Name     string
	Image    PodOptionalString
	Offset   uint64
	ImageOff uint64
}

// PodContainerState is the admitted state category of one container status.
type PodContainerState struct {
	Category string // "", "waiting", "running", "terminated"
	Offset   uint64
}

// PodContainerStatus is one admitted container status observation.
type PodContainerStatus struct {
	Class   contract.ContainerClass
	Name    string
	ImageID PodOptionalString
	Image   PodOptionalString
	Ready   PodOptionalBool
	State   PodContainerState
	// StatePresent distinguishes an omitted state object from the empty one:
	// both carry no category, and only their presence tells them apart.
	StatePresent bool
	Restart      PodOptionalInt
	Offset       uint64
	ImageIDOff   uint64
}

// PodSubject is one accepted Pod item with its original position, byte interval
// and admitted observations. Presence of each category is explicit: an omitted
// array is not an observed empty one.
type PodSubject struct {
	ItemIndex int
	StartByte uint64
	EndByte   uint64

	UID             string
	Namespace       string
	Name            string
	ResourceVersion PodOptionalString
	OwnerReferences []PodOwnerReference

	SpecPresent map[contract.ContainerClass]bool
	Statuses    map[contract.ContainerClass]bool

	SpecContainers   map[contract.ContainerClass][]PodContainerSpec
	StatusContainers map[contract.ContainerClass][]PodContainerStatus

	Diagnostics []PodListDiagnostic
}

// PodListSource is the admitted source of one parse: alias, complete bytes hash
// and size. The raw buffer is never exposed.
type PodListSource struct {
	Name      string
	Hash      contract.SourceHash
	ByteCount uint64
}

// PodListResult is the outcome of one ParseSanitizedPodList call. A fatal
// failure leaves Source nil and no publicable observations: a prefix is never
// published as admitted.
type PodListResult struct {
	Context      PodListContext
	Source       *PodListSource
	Subjects     []PodSubject
	Rejections   []PodListRejection
	TotalItems   *uint64
	Accepted     uint64
	Rejected     uint64
	Diagnostics  []PodListDiagnostic
	LocalAborted bool
}

// PodListAccepted reports whether the source itself was admitted. Only then can
// downstream stages propose observations.
func (r PodListResult) PodListAccepted() bool {
	return r.Source != nil
}
