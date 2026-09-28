package report

import (
	"time"

	"github.com/d4rpell/Ariadne/internal/rulepack"
	contract "github.com/d4rpell/Ariadne/pkg/evidence"
)

// Profile is the closed set of evaluation profiles this contract presents.
type Profile string

const (
	ProfileReadiness Profile = "evidence-readiness-v1"
	ProfileProduct   Profile = "product-evidence-v1"
)

func (p Profile) valid() bool {
	return p == ProfileReadiness || p == ProfileProduct
}

// SourceRole is the closed set of domain source roles.
type SourceRole string

func (r SourceRole) valid() bool {
	switch r {
	case "mapping", "artifact", "vendor":
		return true
	}
	return false
}

// ResultDTO is the closed projection of evaluator.Result. Every key is
// mandatory and appears in this declared order; there is no omitempty, and the
// risk decision is always the explicit null that states its absence.
type ResultDTO struct {
	EngineVersion      string          `json:"engine_version"`
	ProfileVersion     Profile         `json:"profile_version"`
	BundleHash         string          `json:"bundle_hash"`
	PackID             string          `json:"pack_id"`
	PackVersion        int64           `json:"pack_version"`
	PackHash           string          `json:"pack_hash"`
	Target             TargetDTO       `json:"target"`
	Admission          AdmissionDTO    `json:"admission"`
	Domain             *DomainDTO      `json:"domain"`
	ProductStatus      string          `json:"product_status"`
	Exploitability     string          `json:"exploitability"`
	RiskDecision       *struct{}       `json:"risk_decision"`
	Reasons            []string        `json:"reasons"`
	Rules              []RuleTraceDTO  `json:"rules"`
	Candidates         []CandidateDTO  `json:"candidates"`
	EvidenceReferences []ReferenceDTO  `json:"evidence_references"`
	WarningReferences  []WarningRefDTO `json:"warning_references"`
}

// TargetDTO is the exact finding and row the evaluation was scoped to.
type TargetDTO struct {
	SubjectUID      string `json:"subject_uid"`
	ContainerClass  string `json:"container_class"`
	ContainerName   string `json:"container_name"`
	VulnerabilityID string `json:"vulnerability_id"`
	Source          string `json:"source"`
	SourceHash      string `json:"source_hash"`
	Locator         string `json:"locator"`
	ObservedAt      string `json:"observed_at"`
}

// AdmissionDTO is the replay parameter and the version policy of the run. It is
// not an issuance date.
type AdmissionDTO struct {
	EvaluatedAt      string       `json:"evaluated_at"`
	ExpectedPackID   string       `json:"expected_pack_id"`
	ExpectedPackHash string       `json:"expected_pack_hash"`
	MinimumVersion   int64        `json:"minimum_version"`
	Previous         *PreviousDTO `json:"previous"`
}

// PreviousDTO is the version/hash pair the caller had already admitted.
type PreviousDTO struct {
	Version int64  `json:"version"`
	Hash    string `json:"hash"`
}

// DomainDTO is the caller policy of the product profile, sorted by the tuple of
// ADR-0015 §7.1 (the evaluator returns it that way).
type DomainDTO struct {
	MaximumEvidenceAgeSeconds int64          `json:"maximum_evidence_age_seconds"`
	SourcePins                []SourcePinDTO `json:"source_pins"`
}

// SourcePinDTO is one authorized source. Advisory members are explicit nulls for
// mapping and artifact, and present strings for vendor.
type SourcePinDTO struct {
	Role             string  `json:"role"`
	Source           string  `json:"source"`
	SourceHash       string  `json:"source_hash"`
	AdvisoryID       *string `json:"advisory_id"`
	AdvisoryRevision *string `json:"advisory_revision"`
}

// ReferenceDTO points at one item of the canonical evidence array.
type ReferenceDTO struct {
	ItemIndex int `json:"item_index"`
}

// WarningRefDTO points at one warning of the canonical arrays. Provenance
// warnings carry evidence_index -1.
type WarningRefDTO struct {
	Origin        string `json:"origin"`
	EvidenceIndex int    `json:"evidence_index"`
	WarningIndex  int    `json:"warning_index"`
}

// CheckTraceDTO is the trace of one executed check.
type CheckTraceDTO struct {
	CheckID            string         `json:"check_id"`
	Outcome            string         `json:"outcome"`
	Reasons            []string       `json:"reasons"`
	EvidenceReferences []ReferenceDTO `json:"evidence_references"`
}

// RuleTraceDTO is the trace of one rule.
type RuleTraceDTO struct {
	RuleID              string          `json:"rule_id"`
	State               string          `json:"state"`
	MissingRequirements []string        `json:"missing_requirements"`
	Checks              []CheckTraceDTO `json:"checks"`
	Reasons             []string        `json:"reasons"`
	EvidenceReferences  []ReferenceDTO  `json:"evidence_references"`
}

// CandidateDTO is one sustained affirmative branch: never the selected first,
// last or most favourable one.
type CandidateDTO struct {
	RuleID             string         `json:"rule_id"`
	ProductStatus      string         `json:"product_status"`
	EvidenceReferences []ReferenceDTO `json:"evidence_references"`
}

// ScopeDTO is the item scope, always subject plus container.
type ScopeDTO struct {
	SubjectUID    string `json:"subject_uid"`
	ContainerName string `json:"container_name"`
}

// ResolvedEvidenceDTO is one citation resolved from the canonical bundle. It
// carries no value: the message of what was observed stays in the bundle, under
// its own access policy.
type ResolvedEvidenceDTO struct {
	Reference  ReferenceDTO `json:"reference"`
	Type       string       `json:"type"`
	Source     string       `json:"source"`
	SourceHash string       `json:"source_hash"`
	Locator    string       `json:"locator"`
	ObservedAt string       `json:"observed_at"`
	Confidence string       `json:"confidence"`
	Scope      ScopeDTO     `json:"scope"`
}

// ResolvedWarningDTO is one warning of the catalog. The message is always the
// explicit null that states it was omitted by presentation, never that the
// evidence carries no message.
type ResolvedWarningDTO struct {
	Reference WarningRefDTO `json:"reference"`
	Code      string        `json:"code"`
	Class     string        `json:"class"`
	Message   *string       `json:"message"`
}

// completeReportDTO is the final envelope: the result core plus the two resolved
// catalogs, in the declared key order.
type completeReportDTO struct {
	Result          ResultDTO             `json:"result"`
	EvidenceCatalog []ResolvedEvidenceDTO `json:"evidence_catalog"`
	WarningCatalog  []ResolvedWarningDTO  `json:"warning_catalog"`
}

// Report is a validated presentation. Its state is private and the zero value is
// invalid: only Build produces a usable one, so the encoders can never render a
// partially constructed projection.
type Report struct {
	ok       bool
	result   ResultDTO
	evidence []ResolvedEvidenceDTO
	warnings []ResolvedWarningDTO
}

// Valid reports whether this value came from a successful Build.
func (r Report) Valid() bool { return r.ok }

// envelope returns the complete document of this report.
func (r Report) envelope() completeReportDTO {
	return completeReportDTO{
		Result:          r.result,
		EvidenceCatalog: r.evidence,
		WarningCatalog:  r.warnings,
	}
}

// formatTimestamp is the presentation grammar of every instant: canonical UTC
// with nanosecond precision and the Z offset.
func formatTimestamp(value contract.Timestamp) string {
	return value.UTC().Format(time.RFC3339Nano)
}

// isRequirementName reports whether a name belongs to the closed requirement
// vocabulary. It is a form check of this renderer: which profile may declare
// which requirement is decided by the pack admission, never here.
func isRequirementName(value string) bool {
	switch rulepack.Requirement(value) {
	case rulepack.RequirementBundleComplete, rulepack.RequirementFindingRow,
		rulepack.RequirementImageBoundDigest, rulepack.RequirementImageKnownPlatform,
		rulepack.RequirementDomainMapping, rulepack.RequirementDomainArtifact,
		rulepack.RequirementDomainVendorProof, rulepack.RequirementDomainCurrent:
		return true
	}
	const prefix = "finding."
	if len(value) > len(prefix) && value[:len(prefix)] == prefix {
		return rulepack.FieldID(value[len(prefix):]).Valid()
	}
	return false
}
