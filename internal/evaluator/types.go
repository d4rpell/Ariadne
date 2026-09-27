package evaluator

import (
	"github.com/d4rpell/Ariadne/internal/rulepack"
	contract "github.com/d4rpell/Ariadne/pkg/evidence"
)

// Engine and profile identify the semantics of one result. A change of either
// changes the replay identity of every evaluation.
const (
	EngineVersion  = "0.1.0"
	ProfileVersion = rulepack.SupportedProfile
)

// Target is the exact finding one evaluation is scoped to: the container
// identity, the vulnerability and the row reference that substantiates it. It is
// never discovered by the engine and never inferred from the bundle.
type Target struct {
	SubjectUID      contract.UID
	ContainerClass  contract.ContainerClass
	ContainerName   contract.ContainerName
	VulnerabilityID string
	Source          string
	SourceHash      contract.SourceHash
	Locator         contract.SourceLocator
	ObservedAt      contract.Timestamp
}

// Request is everything one evaluation consumes, in memory: the canonical
// bundle, the hash of its projection, the target, the exact pack bytes and the
// admission policy. No path is opened and no callback, reader or plugin is
// accepted. Domain is the explicit policy of the product profile; a nil pointer
// distinguishes the legacy absence, which is not a zero TTL.
type Request struct {
	Bundle             contract.Bundle
	ExpectedBundleHash string
	Target             Target
	PackBytes          []byte
	Admission          rulepack.AdmissionContext
	Domain             *DomainContext
}

// RuleState is the state of one rule trace.
type RuleState string

const (
	RuleNotApplicable   RuleState = "not_applicable"
	RuleMissingEvidence RuleState = "missing_evidence"
	RuleChecked         RuleState = "checked"
)

// CheckOutcome is the three-valued outcome of one check.
type CheckOutcome string

const (
	OutcomePass    CheckOutcome = "pass"
	OutcomeFail    CheckOutcome = "fail"
	OutcomeUnknown CheckOutcome = "unknown"
)

// CheckReason is the closed reason vocabulary. Reasons are engine constants:
// never strings taken from a pack or from evidence content.
type CheckReason string

const (
	ReasonMissing           CheckReason = "missing"
	ReasonUnavailable       CheckReason = "unavailable"
	ReasonRedacted          CheckReason = "redacted"
	ReasonConflict          CheckReason = "conflict"
	ReasonFutureObservation CheckReason = "future_observation"
	ReasonMismatch          CheckReason = "mismatch"
	ReasonVerified          CheckReason = "verified"
	// Domain reasons of ADR-0015 §10. They are engine constants, never strings
	// taken from a pack or from evidence content.
	ReasonExpired          CheckReason = "expired"
	ReasonUnapprovedSource CheckReason = "unapproved_source"
	ReasonUnsupportedProof CheckReason = "unsupported_proof"
)

// Reason is the closed vocabulary of global evaluation reasons.
type Reason string

const (
	ReasonNoApplicableRule         Reason = "no_applicable_rule"
	ReasonTargetUnsubstantiated    Reason = "target_unsubstantiated"
	ReasonIncompleteEvidence       Reason = "incomplete_evidence"
	ReasonBlockingWarning          Reason = "blocking_warning"
	ReasonConflictingEvidence      Reason = "conflicting_evidence"
	ReasonRequirementsMissing      Reason = "requirements_missing"
	ReasonChecksFailed             Reason = "checks_failed"
	ReasonChecksUnknown            Reason = "checks_unknown"
	ReasonDomainAssessmentDeferred Reason = "domain_assessment_deferred"
	// Global reasons of the product profile (ADR-0015 §10). The deferred-domain
	// reason belongs to the legacy profile only; it is not required in the new
	// one and never replaces a concrete domain reason.
	ReasonNoAffirmativeCandidate Reason = "no_affirmative_candidate"
	ReasonAffirmativeConflict    Reason = "affirmative_conflict"
	ReasonDomainEvidenceExpired  Reason = "domain_evidence_expired"
	ReasonDomainSourceUnapproved Reason = "domain_source_unapproved"
	ReasonDomainProofUnsupported Reason = "domain_proof_unsupported"
)

// EvidenceReference points at one item of the canonical evidence array of the
// bundle identified by Result.BundleHash. Every duplicate occurrence is kept.
type EvidenceReference struct {
	ItemIndex int
}

// WarningOrigin distinguishes provenance warnings from item warnings.
type WarningOrigin string

const (
	WarningFromProvenance WarningOrigin = "provenance"
	WarningFromEvidence   WarningOrigin = "evidence"
)

// WarningReference points at one warning in the canonical arrays. Provenance
// warnings use EvidenceIndex -1.
type WarningReference struct {
	Origin        WarningOrigin
	EvidenceIndex int
	WarningIndex  int
}

// CheckTrace is the trace of one executed check.
type CheckTrace struct {
	CheckID            string
	Outcome            CheckOutcome
	Reasons            []CheckReason
	EvidenceReferences []EvidenceReference
}

// RuleTrace is the trace of one rule. MissingRequirements is ordered; Checks are
// ordered by ASCII check id and every one of them runs when the rule is checked.
type RuleTrace struct {
	RuleID              string
	State               RuleState
	MissingRequirements []rulepack.Requirement
	Checks              []CheckTrace
	Reasons             []CheckReason
	EvidenceReferences  []EvidenceReference
}

// Candidate is one affirmative rule candidate of the product profile: the rule
// that sustained it, the state it emits and the evidence it rests on.
type Candidate struct {
	RuleID             string
	ProductStatus      contract.ProductStatus
	EvidenceReferences []EvidenceReference
}

// Result is the internal, reproducible outcome of one evaluation. It carries no
// risk decision, no exception recommendation, no VEX justification and no
// public issuance date: evaluated_at is a replay parameter, not a declaration
// date. Evidence and warning references are resolved against the bundle; no
// evidence value is copied into this structure. Domain and Candidates exist only
// for the product profile.
type Result struct {
	EngineVersion      string
	ProfileVersion     string
	BundleHash         string
	PackID             string
	PackVersion        int64
	PackHash           string
	Target             Target
	Admission          rulepack.AdmissionContext
	Domain             *DomainContext
	ProductStatus      contract.ProductStatus
	Exploitability     contract.Exploitability
	Reasons            []Reason
	Rules              []RuleTrace
	Candidates         []Candidate
	EvidenceReferences []EvidenceReference
	WarningReferences  []WarningReference
}
