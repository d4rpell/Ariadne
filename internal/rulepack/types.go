package rulepack

import (
	contract "github.com/d4rpell/Ariadne/pkg/evidence"
)

// Schema and profile identity of this reader. A pack that declares anything else
// is unsupported: there is no implicit migration, no ignored extension and no
// downgrade to an earlier profile.
const (
	SupportedSchemaVersion = "0.1"
	SupportedProfile       = "evidence-readiness-v1"
)

// OutputUnderInvestigation is the only state a rule of this profile may emit or
// leave as its missing-evidence outcome (ADR-0013 §7).
const OutputUnderInvestigation = "under_investigation"

// Shape, count and byte limits of ADR-0013 §5.4.
const (
	MaxPackBytes     = 1 << 20
	MaxJSONDepth     = 8
	MaxJSONTokens    = 20000
	MaxStringBytes   = 256
	MaxRules         = 128
	MaxRequires      = 32
	MaxChecksPerRule = 32
	MaxChecksTotal   = 4096
	MaxIDBytes       = 64
	MaxVersion       = 1<<53 - 1
)

// FieldID is the closed set of finding columns a rule may select on. A field
// outside this set is not an operand, however present it may be in a bundle.
type FieldID string

const (
	FieldVulnerabilityID  FieldID = "vulnerability_id"
	FieldPackageName      FieldID = "package_name"
	FieldInstalledVersion FieldID = "installed_version"
	FieldPackageType      FieldID = "package_type"
	FieldPackageID        FieldID = "package_id"
	FieldFixStatus        FieldID = "fix_status"
)

func (f FieldID) Valid() bool {
	switch f {
	case FieldVulnerabilityID, FieldPackageName, FieldInstalledVersion,
		FieldPackageType, FieldPackageID, FieldFixStatus:
		return true
	}
	return false
}

// Requirement is the closed requirement vocabulary. Predicates add mandatory
// requirements that a pack cannot omit.
type Requirement string

const (
	RequirementBundleComplete     Requirement = "bundle.complete"
	RequirementFindingRow         Requirement = "finding.row"
	RequirementImageBoundDigest   Requirement = "image.bound_digest"
	RequirementImageKnownPlatform Requirement = "image.known_platform"
)

// FindingRequirement is the requirement that evidences one finding field.
func FindingRequirement(field FieldID) Requirement {
	return Requirement("finding." + string(field))
}

// PredicateID is the closed predicate vocabulary of this profile.
type PredicateID string

const (
	PredicateFindingFieldPresent PredicateID = "finding_field_present"
	PredicateFindingFieldEquals  PredicateID = "finding_field_equals"
	PredicateImageDigestBound    PredicateID = "image_digest_bound"
	PredicateImagePlatformKnown  PredicateID = "image_platform_known"
)

// Params is the typed parameter shape of one check. Which members are present is
// part of the contract, so presence is tracked explicitly instead of relying on
// zero values or on a map.
type Params struct {
	Field           string
	FieldSet        bool
	Value           string
	ValueSet        bool
	OS              string
	OSSet           bool
	Architecture    string
	ArchitectureSet bool
}

type Check struct {
	CheckID   string
	Predicate PredicateID
	Params    Params
}

type Selector struct {
	CoverageMethod  contract.CoverageMethod
	VulnerabilityID string
}

type Rule struct {
	RuleID            string
	Selector          Selector
	Requires          []Requirement
	Checks            []Check
	OnMissingEvidence string
	Emit              string
}

// Pack is a decoded and domain-validated pack. Decode proves shape and domain,
// never identity: hash, pin, version policy and validity are the concerns of
// Admit.
type Pack struct {
	SchemaVersion string
	Profile       string
	PackID        string
	Version       int64
	ValidFrom     contract.Timestamp
	ExpiresAt     contract.Timestamp
	Rules         []Rule
}

// PreviousVersion is a version/hash pair the caller already admitted for the
// same pack id. It is caller policy, not durable history.
type PreviousVersion struct {
	Version int64
	Hash    string
}

// AdmissionContext is the caller-supplied admission policy: the explicit instant
// of evaluation, the pinned pack identity and the version policy. Nil Previous
// is the explicit bootstrap case.
type AdmissionContext struct {
	EvaluatedAt      contract.Timestamp
	ExpectedPackID   string
	ExpectedPackHash string
	MinimumVersion   int64
	Previous         *PreviousVersion
}

// AdmittedPack is the result of a successful admission. Its state is private and
// the zero value is invalid, so an admitted pack can only come from Admit.
type AdmittedPack struct {
	pack Pack
	hash string
	ok   bool
}

// Valid reports whether this value came from a successful admission.
func (admitted AdmittedPack) Valid() bool { return admitted.ok }

// Hash is the sha256 digest of the exact admitted bytes.
func (admitted AdmittedPack) Hash() string { return admitted.hash }

// PackID is the admitted pack identity.
func (admitted AdmittedPack) PackID() string { return admitted.pack.PackID }

// Version is the admitted pack version.
func (admitted AdmittedPack) Version() int64 { return admitted.pack.Version }

// Pack returns a copy of the admitted pack. The copy detaches slices so a caller
// cannot rewrite what admission validated.
func (admitted AdmittedPack) Pack() Pack { return copyPack(admitted.pack) }

func copyPack(pack Pack) Pack {
	copied := pack
	copied.Rules = make([]Rule, len(pack.Rules))
	for index, rule := range pack.Rules {
		copied.Rules[index] = copyRule(rule)
	}
	return copied
}

func copyRule(rule Rule) Rule {
	copied := rule
	copied.Requires = append([]Requirement{}, rule.Requires...)
	copied.Checks = make([]Check, len(rule.Checks))
	copy(copied.Checks, rule.Checks)
	return copied
}
