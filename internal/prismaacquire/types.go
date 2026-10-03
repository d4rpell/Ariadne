package prismaacquire

import (
	"time"

	"github.com/d4rpell/Ariadne/internal/normalize"
)

// Scope modes of ADR-0028 §4.4. Exactly two modes are admitted.
const (
	ScopeSingleTenant  = "single_tenant_declared"
	ScopeProjectSelect = "project_selected"
)

// Authentication modes of ADR-0028 §5.1. Exactly two modes are admitted.
const (
	AuthBearerSupplied   = "bearer_supplied"
	AuthPasswordExchange = "password_exchange"
)

// AcquisitionConfig is the closed configuration of §4.2. Pagination, format,
// compression, retry, filter and budget options are not configurable; a missing
// required value is an error and never completed from the environment.
type AcquisitionConfig struct {
	// Selection.
	Selector string
	Version  string
	Profile  string

	// Sanitized identification.
	OriginAlias string

	// Documentary declaration.
	Edition string
	Release string

	// Connection (§6.1–§6.3). CA is explicit trust material held in memory.
	Endpoint string
	CA       []byte

	// Scope (§4.4).
	ScopeMode  string
	Project    string  // real project id; used only for the request, never persisted
	ScopeAlias *string // sanitized scope alias; required only for project_selected

	// Authentication (§5) and the opaque credential reference (§4.3).
	AuthMode      string
	CredentialRef string

	// Data policy acknowledgement required by F1.
	DataPolicyAck string

	// Optional known token expiry (§5.3); nil means unknown, not "never".
	TokenExpiresAt *time.Time
}

// Credential is a credential already resolved in memory by the caller. The
// connector never opens a credential path, reads the environment or invokes an
// external resolver (§4.1).
type Credential struct {
	Reference string // opaque, must match AcquisitionConfig.CredentialRef
	Token     string // bearer_supplied
	Username  string // password_exchange
	Password  string // password_exchange
}

// Termination, sequence-completeness, coverage, consistency and runtime-binding
// literals of §10.2. They are separate dimensions and are never collapsed.
const (
	TerminationFinished = "finished"
	TerminationAborted  = "aborted"
	TerminationUnknown  = "unknown"

	SequenceComplete = "complete"
	SequencePartial  = "partial"
	SequenceUnknown  = "unknown"

	InventoryCoverageUnknown   = "unknown"
	ConsistencyNotAtomic       = "not_atomic"
	RuntimeBindingNotAttempted = "not_attempted"
)

// AttemptCounters reports the budgets an acquisition consumed (§7.4–§7.9).
type AttemptCounters struct {
	Total     int
	Auth      int
	ImageGET  int
	BodyBytes uint64
	Images    uint64
	Findings  uint64
	Packages  uint64
	Tokens    uint64
}

// PageResult is one admitted page delivered in memory (§9.1, §10.1). The
// artifacts and the native inventory are the only data of the page; no original
// body, credential or transport metadata is retained.
type PageResult struct {
	Ordinal     int
	Offset      int
	SourceAlias string
	AcquiredAt  string
	Artifacts   normalize.NativeArtifacts
	Inventory   normalize.NativeInventory
}

// AcquisitionResult is the typed, in-memory result of §10.1. It expresses the
// four independent dimensions, the consumed counters, the admitted pages and
// the acquisition diagnostics. It is not a new persistent format.
type AcquisitionResult struct {
	Selector             string
	Version              string
	Profile              string
	OriginAlias          string
	ScopeAlias           *string
	AuthMode             string
	Termination          string
	SequenceCompleteness string
	InventoryCoverage    string
	Consistency          string
	RuntimeBinding       string
	Attempts             AttemptCounters
	Pages                []PageResult
	Diagnostics          []*AcquisitionError
}
