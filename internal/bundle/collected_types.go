package bundle

import (
	"time"

	"github.com/d4rpell/Ariadne/internal/normalize"
	contract "github.com/d4rpell/Ariadne/pkg/evidence"
)

// Live-collection carriers (ADR-0026 A.7, A.8). The optional collector reports
// what it attempted, what it admitted and what it compared, using only the
// existing wire vocabulary. These types are shared with internal/collector; the
// dependency direction is collector -> bundle and never the reverse.

// CollectedScope is the non-secret scope of one acquisition run.
type CollectedScope struct {
	Selector        string
	Version         string
	RedactionPolicy string
	ClusterAlias    contract.ClusterAlias
	Namespaces      []contract.Namespace
}

// CollectedTarget is one inventoried Pod addressed for re-reads. Namespace and
// name are directions for the API, never the association key.
type CollectedTarget struct {
	UID            contract.UID
	Namespace      contract.Namespace
	Name           string
	CaptureOrdinal uint64
	ItemIndex      int
}

// CollectedOperationState is the closed execution state of one planned request.
type CollectedOperationState string

const (
	OperationPending     CollectedOperationState = "pending"
	OperationAttempted   CollectedOperationState = "attempted"
	OperationFinished    CollectedOperationState = "finished"
	OperationFailed      CollectedOperationState = "failed"
	OperationNotExecuted CollectedOperationState = "not_executed"
)

// CollectedOperation is one request of the acquisition plan with the facts the
// machine actually witnessed. No credential, URL, query token or raw error
// survives here.
type CollectedOperation struct {
	Verb           string // "list" or "get"
	Namespace      contract.Namespace
	Name           string // only for get
	Page           uint64
	Round          uint8
	RequestOrdinal uint64
	State          CollectedOperationState
	StatusCode     int
	StartedAt      *contract.Timestamp
	EndedAt        *contract.Timestamp
	Elapsed        time.Duration
	BytesRead      uint64
	Diagnostic     CollectionCode
}

// CollectedItem is the identity an item of one projected response carried,
// whether or not the admission stage accepted it. It exists so a uid repeated
// anywhere in the initial inventory invalidates every one of its occurrences:
// a rejected Pod cannot hide a duplicate.
type CollectedItem struct {
	UID       contract.UID
	Namespace contract.Namespace
	Name      string
}

// CollectedCapture is one complete admitted response projected to the sanitized
// grammar, plus the normalized observation of that exact source.
type CollectedCapture struct {
	Ordinal        uint64
	RequestOrdinal uint64
	// Verb is the operation of this capture: "list" or "get".
	Verb        string
	Alias       string
	Bytes       []byte
	Hash        contract.SourceHash
	Observation normalize.ObservationResult
	// Items are the projected identities of the response, in document order.
	Items []CollectedItem
	// ListResourceVersion carries the opaque list metadata resourceVersion with
	// its explicit presence: absence is never written as an empty value.
	ListResourceVersion         string
	ListResourceVersionPresence bool
	// ContinuationPending records that the source this capture belongs to had a
	// continuation at admit time; the token itself is never retained.
	ContinuationPending bool
}

// CollectedSubjectRef points at one subject of one capture by its original item
// position. It never confuses the item index with a subject index.
type CollectedSubjectRef struct {
	CaptureOrdinal uint64
	ItemIndex      int
}

// CollectedComparison is one deterministic comparison between two captures.
type CollectedComparison struct {
	Code     CollectionCode
	Previous CollectedSubjectRef
	Current  CollectedSubjectRef
	// ContainerClass and ContainerName are set only for per-container
	// comparisons; they are validated enum and identifier text, never free text.
	ContainerClass string
	ContainerName  string
}

// CollectedBudgetStats counts what the run really consumed.
type CollectedBudgetStats struct {
	RequestsAttempted   uint64
	ResponsesFinished   uint64
	ResponsesFailed     uint64
	BytesRead           uint64
	PodOccurrences      uint64
	InitialUIDs         uint64
	RetainedSourceBytes uint64
	MaxConcurrency      uint64
	Elapsed             time.Duration
}

// CollectedPlan declares what the run set out to do and what remains open. A
// pending page of unknown size is never presented as a known number of future
// pages: PagesKnown is false while a continuation stayed open.
type CollectedPlan struct {
	ListedNamespaces        []contract.Namespace
	PendingNamespaces       []contract.Namespace
	Targets                 []CollectedTarget
	PlannedReReadsPerTarget uint8
	UnfinishedTargets       uint64
	RequestedOps            uint64
	NotExecutedOps          uint64
	ContinuationOpen        bool
	PagesKnown              bool
	InventoryClosed         bool
}

// CollectedAcquisition is the publishable record of one acquisition run.
type CollectedAcquisition struct {
	Scope       CollectedScope
	Plan        CollectedPlan
	Operations  []CollectedOperation
	Captures    []CollectedCapture
	Comparisons []CollectedComparison
	Diagnostics []CollectionDiagnostic
	Stats       CollectedBudgetStats
	StartedAt   *contract.Timestamp
	EndedAt     *contract.Timestamp
	Termination contract.CoverageTermination
	// GlobalErrors are the run-wide failures that every affected bundle keeps.
	GlobalErrors []string
	// GlobalWarnings are the wire-visible warnings every bundle keeps.
	GlobalWarnings []contract.Warning
}

// CollectedObservationInput is everything BuildCollectedObservation consumes:
// the whole acquisition record and the selection of one subject. The observed
// instant, the run window and the budget are derived from the acquisition
// record itself; they are never a second, caller-supplied source of truth.
type CollectedObservationInput struct {
	Acquisition    CollectedAcquisition
	CaptureOrdinal uint64
	// SubjectIndex is the position of the subject inside the accepted subjects
	// of the capture; ItemIndex, the original position of the item, is the
	// carrier of CollectedSubjectRef and is never confused with it.
	SubjectIndex int
	Result       normalize.ObservationResult
}
