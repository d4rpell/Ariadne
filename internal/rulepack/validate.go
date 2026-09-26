package rulepack

import (
	"strings"
	"unicode"
)

// validate applies the closed domain rules of ADR-0013 §5.1 and §6. Unknown
// schema, profile, predicate, requirement, field or output is unsupported; a
// known vocabulary member used with the wrong shape is invalid.
func (pack Pack) validate() error {
	if pack.SchemaVersion != SupportedSchemaVersion {
		return problem(CodeUnsupportedPack, -1)
	}
	if pack.Profile != SupportedProfile {
		return problem(CodeUnsupportedPack, -1)
	}
	if !validID(pack.PackID) {
		return invalidProblem(-1)
	}
	if pack.Version < 1 || pack.Version > MaxVersion {
		return invalidProblem(-1)
	}
	if !pack.ValidFrom.Time.Before(pack.ExpiresAt.Time) {
		return invalidProblem(-1)
	}
	if len(pack.Rules) < 1 || len(pack.Rules) > MaxRules {
		return invalidProblem(-1)
	}

	seenRules := make(map[string]bool, len(pack.Rules))
	totalChecks := 0
	for index, rule := range pack.Rules {
		if err := rule.validate(index); err != nil {
			return err
		}
		if seenRules[rule.RuleID] {
			return invalidProblem(index)
		}
		seenRules[rule.RuleID] = true
		totalChecks += len(rule.Checks)
	}
	if totalChecks > MaxChecksTotal {
		return limitProblem()
	}
	return nil
}

func (rule Rule) validate(index int) error {
	if !validID(rule.RuleID) {
		return invalidProblem(index)
	}
	if !rule.Selector.CoverageMethod.Valid() {
		return invalidProblem(index)
	}
	if !validCVE(rule.Selector.VulnerabilityID) {
		return invalidProblem(index)
	}
	if len(rule.Requires) < 1 || len(rule.Requires) > MaxRequires {
		return invalidProblem(index)
	}
	declared := make(map[Requirement]bool, len(rule.Requires))
	for _, requirement := range rule.Requires {
		if !requirementValid(requirement) {
			return problem(CodeUnsupportedPack, index)
		}
		if declared[requirement] {
			return invalidProblem(index)
		}
		declared[requirement] = true
	}
	// Every rule of this profile rests on a complete method-specific capture and
	// on the finding row of its target.
	if !declared[RequirementBundleComplete] || !declared[RequirementFindingRow] {
		return invalidProblem(index)
	}

	if len(rule.Checks) < 1 || len(rule.Checks) > MaxChecksPerRule {
		return invalidProblem(index)
	}
	seenChecks := make(map[string]bool, len(rule.Checks))
	for _, check := range rule.Checks {
		if err := check.validate(index); err != nil {
			return err
		}
		if seenChecks[check.CheckID] {
			return invalidProblem(index)
		}
		seenChecks[check.CheckID] = true
		// A predicate's mandatory requirements cannot be omitted by the pack.
		for _, required := range mandatoryRequirements(check) {
			if !declared[required] {
				return invalidProblem(index)
			}
		}
	}

	if rule.OnMissingEvidence != OutputUnderInvestigation {
		return problem(CodeUnsupportedPack, index)
	}
	if rule.Emit != OutputUnderInvestigation {
		return problem(CodeUnsupportedPack, index)
	}
	return nil
}

func (check Check) validate(index int) error {
	if !validID(check.CheckID) {
		return invalidProblem(index)
	}
	switch check.Predicate {
	case PredicateFindingFieldPresent:
		if !check.Params.FieldSet || check.Params.ValueSet || check.Params.OSSet || check.Params.ArchitectureSet {
			return invalidProblem(index)
		}
		if !FieldID(check.Params.Field).Valid() {
			return problem(CodeUnsupportedPack, index)
		}
	case PredicateFindingFieldEquals:
		if !check.Params.FieldSet || !check.Params.ValueSet || check.Params.OSSet || check.Params.ArchitectureSet {
			return invalidProblem(index)
		}
		if !FieldID(check.Params.Field).Valid() {
			return problem(CodeUnsupportedPack, index)
		}
		if !validParamString(check.Params.Value) {
			return invalidProblem(index)
		}
		if FieldID(check.Params.Field) == FieldVulnerabilityID && !validCVE(check.Params.Value) {
			return invalidProblem(index)
		}
	case PredicateImageDigestBound:
		if check.Params.FieldSet || check.Params.ValueSet || check.Params.OSSet || check.Params.ArchitectureSet {
			return invalidProblem(index)
		}
	case PredicateImagePlatformKnown:
		if check.Params.FieldSet || check.Params.ValueSet || !check.Params.OSSet || !check.Params.ArchitectureSet {
			return invalidProblem(index)
		}
		if !validParamString(check.Params.OS) || !validParamString(check.Params.Architecture) {
			return invalidProblem(index)
		}
	default:
		return problem(CodeUnsupportedPack, index)
	}
	return nil
}

func mandatoryRequirements(check Check) []Requirement {
	switch check.Predicate {
	case PredicateFindingFieldPresent, PredicateFindingFieldEquals:
		return []Requirement{FindingRequirement(FieldID(check.Params.Field))}
	case PredicateImageDigestBound:
		return []Requirement{RequirementImageBoundDigest}
	case PredicateImagePlatformKnown:
		return []Requirement{RequirementImageBoundDigest, RequirementImageKnownPlatform}
	}
	return nil
}

func requirementValid(requirement Requirement) bool {
	switch requirement {
	case RequirementBundleComplete, RequirementFindingRow,
		RequirementImageBoundDigest, RequirementImageKnownPlatform:
		return true
	}
	const prefix = "finding."
	if strings.HasPrefix(string(requirement), prefix) {
		return FieldID(strings.TrimPrefix(string(requirement), prefix)).Valid()
	}
	return false
}

// validID is the identifier grammar: 1–64 ASCII bytes, first letter a–z, the
// rest lowercase letters, digits, dot, underscore or hyphen.
func validID(value string) bool {
	if len(value) == 0 || len(value) > MaxIDBytes {
		return false
	}
	if value[0] < 'a' || value[0] > 'z' {
		return false
	}
	for index := 1; index < len(value); index++ {
		c := value[index]
		switch {
		case c >= 'a' && c <= 'z', c >= '0' && c <= '9', c == '.', c == '_', c == '-':
		default:
			return false
		}
	}
	return true
}

// validCVE is the grammar already ratified for prisma-v1:
// CVE-<4 digits>-<4 or more digits>.
func validCVE(value string) bool {
	const prefix = "CVE-"
	if !strings.HasPrefix(value, prefix) {
		return false
	}
	rest := value[len(prefix):]
	if len(rest) < 9 || rest[4] != '-' {
		return false
	}
	for index := 0; index < len(rest); index++ {
		if index == 4 {
			continue
		}
		if rest[index] < '0' || rest[index] > '9' {
			return false
		}
	}
	return true
}

// validParamString is the parameter string rule of ADR-0013 §6: 1–256 UTF-8
// bytes, no control or format characters and no surrounding whitespace.
func validParamString(value string) bool {
	if len(value) == 0 || len(value) > MaxStringBytes {
		return false
	}
	if strings.TrimSpace(value) != value {
		return false
	}
	for _, r := range value {
		if controlOrFormat(r) {
			return false
		}
	}
	return true
}

// controlOrFormat mirrors the project's inadmissible text: C0 controls, DEL, C1
// controls and Unicode format characters.
func controlOrFormat(r rune) bool {
	return r < 0x20 || r == 0x7F || (r >= 0x80 && r <= 0x9F) || unicode.Is(unicode.Cf, r)
}
