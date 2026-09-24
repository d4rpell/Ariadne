package evidence

import (
	"errors"
	"time"
)

// These types are the Go model of the evidence contract. ADR-0006 (ratified
// 2026-09-24) fixes the wire: the tags below are normative, the declared field
// order is the canonical key order, and the canonical bytes are produced by
// internal/evidence after validation. Values that are optional on the wire but
// not pointers here (owner_chain, platform.os/architecture, ruleset) are emitted
// as null by the MarshalJSON methods in json.go.

type UID string

type Digest string

type PURL string

type ContainerName string

type Namespace string

type ClusterAlias string

type OwnerChain string

type RequestedImage string

type RawImageID string

type NormalizedDigest string

type SourceLocator string

type SourceHash string

type ValueHash string

type ProvenanceKind string

const (
	ProvenanceObserved    ProvenanceKind = "observed"
	ProvenanceDerived     ProvenanceKind = "derived"
	ProvenanceUnavailable ProvenanceKind = "unavailable"
)

func (k ProvenanceKind) Valid() bool {
	switch k {
	case ProvenanceObserved, ProvenanceDerived, ProvenanceUnavailable:
		return true
	}
	return false
}

type ContainerClass string

const (
	ContainerRegular   ContainerClass = "regular"
	ContainerInit      ContainerClass = "init"
	ContainerEphemeral ContainerClass = "ephemeral"
)

func (c ContainerClass) Valid() bool {
	switch c {
	case ContainerRegular, ContainerInit, ContainerEphemeral:
		return true
	}
	return false
}

type PlatformStatus string

const (
	PlatformKnown   PlatformStatus = "known"
	PlatformUnknown PlatformStatus = "unknown"
)

func (s PlatformStatus) Valid() bool {
	switch s {
	case PlatformKnown, PlatformUnknown:
		return true
	}
	return false
}

type Completeness string

const (
	CompletenessComplete Completeness = "complete"
	CompletenessPartial  Completeness = "partial"
	CompletenessUnknown  Completeness = "unknown"
)

func (c Completeness) Valid() bool {
	switch c {
	case CompletenessComplete, CompletenessPartial, CompletenessUnknown:
		return true
	}
	return false
}

type Consistency string

const (
	ConsistencyPointObservation Consistency = "point-observation"
	ConsistencyNotAtomic        Consistency = "not-atomic"
)

func (c Consistency) Valid() bool {
	switch c {
	case ConsistencyPointObservation, ConsistencyNotAtomic:
		return true
	}
	return false
}

// CoverageMethod fixes how a run declared its scope before processing input. It
// is never inferred from argv, file names or the API scope.
type CoverageMethod string

const (
	CoverageFindingsImport       CoverageMethod = "findings_import"
	CoverageContainerObservation CoverageMethod = "container_observation"
)

func (m CoverageMethod) Valid() bool {
	switch m {
	case CoverageFindingsImport, CoverageContainerObservation:
		return true
	}
	return false
}

type CoverageTermination string

const (
	TerminationFinished CoverageTermination = "finished"
	TerminationAborted  CoverageTermination = "aborted"
	TerminationUnknown  CoverageTermination = "unknown"
)

func (t CoverageTermination) Valid() bool {
	switch t {
	case TerminationFinished, TerminationAborted, TerminationUnknown:
		return true
	}
	return false
}

type WarningClass string

const (
	WarningInformational WarningClass = "informational"
	WarningContradictory WarningClass = "contradictory"
)

func (c WarningClass) Valid() bool {
	switch c {
	case WarningInformational, WarningContradictory:
		return true
	}
	return false
}

type Warning struct {
	Code    string       `json:"code"`
	Class   WarningClass `json:"class"`
	Message string       `json:"message"`
}

// knownWarningCodes is the code set of schema version 0.1. A reader that meets a
// code outside this set keeps the warning and treats it as uninterpretable.
var knownWarningCodes = map[string]struct{}{
	"uid_changed":         {},
	"scope_mismatch":      {},
	"partial_observation": {},
	"stale_observation":   {},
	"source_conflict":     {},
	"redaction_applied":   {},
	"tool_failure":        {},
}

// CodeKnown reports whether this schema version defines what the code means. An
// unknown code cannot support a not_affected conclusion.
func (w Warning) CodeKnown() bool {
	_, known := knownWarningCodes[w.Code]
	return known
}

// ProductStatus is layer 1 of the decision model. "unknown" is not a member of
// this vocabulary: it is re-opened as ProductUnderInvestigation when a conclusion
// has to be exported.
type ProductStatus string

const (
	ProductAffected           ProductStatus = "affected"
	ProductNotAffected        ProductStatus = "not_affected"
	ProductFixed              ProductStatus = "fixed"
	ProductUnderInvestigation ProductStatus = "under_investigation"
)

func (s ProductStatus) Valid() bool {
	switch s {
	case ProductAffected, ProductNotAffected, ProductFixed, ProductUnderInvestigation:
		return true
	}
	return false
}

type Exploitability string

const (
	ExploitabilityNotAssessed      Exploitability = "not_assessed"
	ExploitabilityUnknown          Exploitability = "unknown"
	ExploitabilityConditionsMet    Exploitability = "conditions_met"
	ExploitabilityConditionsNotMet Exploitability = "conditions_not_met"
)

func (e Exploitability) Valid() bool {
	switch e {
	case ExploitabilityNotAssessed, ExploitabilityUnknown, ExploitabilityConditionsMet, ExploitabilityConditionsNotMet:
		return true
	}
	return false
}

type RiskDecision string

const (
	RiskNotAssessed RiskDecision = "not_assessed"
	RiskAccepted    RiskDecision = "accepted"
	RiskDeferred    RiskDecision = "deferred"
	RiskRejected    RiskDecision = "rejected"
)

func (r RiskDecision) Valid() bool {
	switch r {
	case RiskNotAssessed, RiskAccepted, RiskDeferred, RiskRejected:
		return true
	}
	return false
}

// Timestamp holds an instant in canonical UTC form. It is never generated while
// serializing.
type Timestamp struct {
	time.Time
}

func NewTimestamp(value time.Time) (Timestamp, error) {
	if value.IsZero() {
		return Timestamp{}, errors.New("evidence: timestamp is zero")
	}
	return Timestamp{Time: value.UTC()}, nil
}

// ParseDigest checks presence only. Proving that a digest is unambiguous is the
// parser's responsibility, never this function's.
func ParseDigest(value string) (Digest, error) {
	parsed, err := parseRequired("digest", value)
	if err != nil {
		return "", err
	}
	return Digest(parsed), nil
}

func ParseUID(value string) (UID, error) {
	parsed, err := parseRequired("uid", value)
	if err != nil {
		return "", err
	}
	return UID(parsed), nil
}

// ParsePURL keeps the value as given: no PURL normalization or equivalence
// semantics are applied at this layer.
func ParsePURL(value string) (PURL, error) {
	parsed, err := parseRequired("purl", value)
	if err != nil {
		return "", err
	}
	return PURL(parsed), nil
}

type Subject struct {
	ClusterAlias ClusterAlias `json:"cluster_alias"`
	Namespace    Namespace    `json:"namespace"`
	Kind         string       `json:"kind"`
	Name         string       `json:"name"`
	UID          UID          `json:"uid"`
	OwnerChain   OwnerChain   `json:"owner_chain"`
}

type Platform struct {
	OS           string         `json:"os"`
	Architecture string         `json:"architecture"`
	Status       PlatformStatus `json:"status"`
}

type ImageIdentity struct {
	ContainerClass   ContainerClass    `json:"container_class"`
	ContainerName    ContainerName     `json:"container_name"`
	RequestedImage   *RequestedImage   `json:"requested_image"`
	RawImageID       *RawImageID       `json:"raw_image_id"`
	NormalizedDigest *NormalizedDigest `json:"normalized_digest"`
	Platform         Platform          `json:"platform"`
	ObservedAt       *Timestamp        `json:"observed_at"`
}

type Scope struct {
	SubjectUID    UID           `json:"subject_uid"`
	ContainerName ContainerName `json:"container_name"`
}

type EvidenceItem struct {
	Type       string         `json:"type"`
	Source     string         `json:"source"`
	SourceHash SourceHash     `json:"source_hash"`
	Locator    SourceLocator  `json:"locator"`
	Value      *string        `json:"value"`
	ValueHash  *ValueHash     `json:"value_hash"`
	ObservedAt *Timestamp     `json:"observed_at"`
	Confidence ProvenanceKind `json:"confidence"`
	Scope      Scope          `json:"scope"`
	Warnings   []Warning      `json:"warnings"`
}

type InputRef struct {
	Path string     `json:"path"`
	Hash SourceHash `json:"hash"`
}

type RulesetRef struct {
	Path    string     `json:"path"`
	Hash    SourceHash `json:"hash"`
	Version string     `json:"version"`
}

type APIScope struct {
	Namespaces []Namespace `json:"namespaces"`
	Verbs      []string    `json:"verbs"`
	Resources  []string    `json:"resources"`
}

type Budget struct {
	WallClock string `json:"wall_clock"`
	Requests  uint64 `json:"requests"`
	Objects   uint64 `json:"objects"`
	Bytes     uint64 `json:"bytes"`
}

// CoverageRows counts records of a findings import: logical CSV records, not
// physical lines. Total is null while the file size is still unknown.
type CoverageRows struct {
	Total    *uint64 `json:"total"`
	Accepted uint64  `json:"accepted"`
	Rejected uint64  `json:"rejected"`
}

// Coverage declares the scope of the run. Rows is null for a container
// observation and required for a findings import.
type Coverage struct {
	Method      CoverageMethod      `json:"method"`
	Termination CoverageTermination `json:"termination"`
	Rows        *CoverageRows       `json:"rows"`
}

type RunProvenance struct {
	CollectorVersion string       `json:"collector_version"`
	ParserVersion    string       `json:"parser_version"`
	Ruleset          RulesetRef   `json:"ruleset"`
	ArgvSanitized    []string     `json:"argv_sanitized"`
	Inputs           []InputRef   `json:"inputs"`
	APIScope         APIScope     `json:"api_scope"`
	StartedAt        *Timestamp   `json:"started_at"`
	EndedAt          *Timestamp   `json:"ended_at"`
	Budget           Budget       `json:"budget"`
	Coverage         Coverage     `json:"coverage"`
	Completeness     Completeness `json:"completeness"`
	Consistency      Consistency  `json:"consistency"`
	RedactionPolicy  string       `json:"redaction_policy"`
	Warnings         []Warning    `json:"warnings"`
	Errors           []string     `json:"errors"`
}

type Bundle struct {
	SchemaVersion            string           `json:"schema_version"`
	Subject                  Subject          `json:"subject"`
	Images                   []ImageIdentity  `json:"images"`
	Evidence                 []EvidenceItem   `json:"evidence"`
	ObservedContainerClasses []ContainerClass `json:"observed_container_classes"`
	Provenance               RunProvenance    `json:"provenance"`
}
