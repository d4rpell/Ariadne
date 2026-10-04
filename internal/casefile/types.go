// Package casefile keeps explicit human risk decisions as append-only records
// (ADR-0030, task A3-01). The library is a pure, offline, deterministic data
// type: it opens no paths, uses no network, reads no clock and executes
// nothing. Every instant comes from the caller; every decision is declared by
// the caller and never derived.
//
// The vocabulary is exactly accepted, deferred and rejected. The absence of a
// decision is the absence of a record, never a record of its own. Expiry and
// supersession carry as declared data only: this package implements no
// lifecycle, no current-decision view and no exception recommendation.
package casefile

// Format identifiers of the artifact family. Only the exact combination of
// format and version below is admitted: no autodetection, no prefix match and
// no implicit acceptance of future versions.
const (
	BookFormat    = "casefile-book-v1"
	RecordFormat  = "casefile-decision-v1"
	FormatVersion = "1.0"
)

// Budgets of the profile (ADR-0030 §5.1). They are constants of the profile,
// never arguments; every guard fires before the buffer grows.
const (
	MaxRecords              = 1024
	MaxBookBytes            = 16777216
	MaxRecordBytes          = 131072
	MaxActorBytes           = 256
	MaxRationaleBytes       = 8192
	MaxControls             = 32
	MaxControlBytes         = 1024
	MaxSubjectUIDBytes      = 1024
	MaxContainerNameBytes   = 1024
	MaxVulnerabilityIDBytes = 256
	MaxStringTokenBytes     = 49154
	MaxDepth                = 4
)

// Decision is the closed risk-decision vocabulary of layer 3. The zero value is
// invalid by construction: there is no implicit or default decision.
type Decision string

const (
	DecisionAccepted Decision = "accepted"
	DecisionDeferred Decision = "deferred"
	DecisionRejected Decision = "rejected"
)

// ContainerClass reproduces the repository vocabulary without importing any
// evaluation package. There is no sidecar class.
type ContainerClass string

const (
	ContainerRegular   ContainerClass = "regular"
	ContainerInit      ContainerClass = "init"
	ContainerEphemeral ContainerClass = "ephemeral"
)

// Scope links one declared decision to one subject, container and
// vulnerability. Identity is conserved verbatim and never inferred, replaced
// or normalized. The hashes are caller-supplied references: their syntax is
// checked, their existence and meaning are not.
type Scope struct {
	BundleHash        string
	SubjectUID        string
	ContainerName     string
	ContainerClass    ContainerClass
	VulnerabilityID   string
	ResultFingerprint *string
}

// DecisionInput is one declared human decision. Owner and approver are
// declared actors, not authenticated identities; controls are declared, not
// verified. ExpiresAt and Supersedes are historical data: their presence
// produces no state change in this package.
type DecisionInput struct {
	RiskDecision Decision
	Owner        string
	Approver     string
	Rationale    string
	Scope        Scope
	Controls     []string
	DecidedAt    string
	ExpiresAt    *string
	Supersedes   *string
}

// Record is one appended decision with its chain membership. Hash covers the
// thirteen canonical fields of the preimage, never itself. PreviousHash is nil
// only for the first record of a book.
type Record struct {
	Format       string
	Version      string
	Sequence     uint64
	PreviousHash *string
	Decision     DecisionInput
	Hash         string
}

// Book is an immutable append-only ledger. The zero value is invalid: NewBook
// builds the empty, valid book. No slice, map or pointer of a Book escapes the
// package without a deep copy.
type Book struct {
	initialized bool
	records     []Record
	bytes       int
}
