package report

import (
	"encoding/json"
	"time"
	"unicode/utf8"

	"github.com/d4rpell/Ariadne/internal/evaluator"
	canonical "github.com/d4rpell/Ariadne/internal/evidence"
	"github.com/d4rpell/Ariadne/internal/rulepack"
	contract "github.com/d4rpell/Ariadne/pkg/evidence"
)

// Build validates the form of one evaluation result, canonicalizes the bundle
// its hash names and resolves the two catalogs. The phase order is the one
// ratified in ADR-0022 §D3: result form, bundle, hash contrast, references and
// scope.
//
// Build checks form only. It cannot and does not claim that Evaluate ran, that a
// fabricated conclusion is substantiated, or that the identifiers and citations
// are authorized for any recipient: those are properties of the producer and of
// the caller who holds the case.
func Build(result evaluator.Result, bundle contract.Bundle) (Report, error) {
	if err := validateResultForm(result); err != nil {
		return Report{}, err
	}
	ordered, err := canonicalBundle(bundle)
	if err != nil {
		return Report{}, problem(CodeInvalidBundle)
	}
	hash, err := canonical.HashCanonicalJSON(bundle)
	if err != nil {
		return Report{}, problem(CodeInvalidBundle)
	}
	if hash != result.BundleHash {
		return Report{}, problem(CodeBundleHashMismatch)
	}
	evidence, warnings, err := resolveCatalogs(result, ordered)
	if err != nil {
		return Report{}, err
	}
	return Report{
		ok:       true,
		result:   projectResult(result),
		evidence: evidence,
		warnings: warnings,
	}, nil
}

// canonicalBundle returns the canonical copy whose collections follow the order
// the evaluator's references were resolved against. It is the same projection
// internal/evidence produces; this package re-derives it instead of adding an
// exported API to a protected package.
func canonicalBundle(input contract.Bundle) (contract.Bundle, error) {
	encoded, err := canonical.CanonicalJSON(input)
	if err != nil {
		return contract.Bundle{}, err
	}
	var ordered contract.Bundle
	if err := json.Unmarshal(encoded, &ordered); err != nil {
		return contract.Bundle{}, err
	}
	return ordered, nil
}

// validateResultForm checks the closed vocabulary, the timestamps, the profile
// combinations and the sign of the references. Every failure is invalid_result:
// a result that could not have come from this evaluator has no presentation.
func validateResultForm(result evaluator.Result) error {
	if !boundedString(result.EngineVersion) || !boundedString(result.PackID) {
		return problem(CodeInvalidResult)
	}
	profile := Profile(result.ProfileVersion)
	if !profile.valid() {
		return problem(CodeInvalidResult)
	}
	if !isSha256(result.BundleHash) || !isSha256(result.PackHash) {
		return problem(CodeInvalidResult)
	}
	if result.PackVersion < 1 || result.PackVersion > rulepack.MaxVersion {
		return problem(CodeInvalidResult)
	}
	if err := validateTargetForm(result.Target); err != nil {
		return problem(CodeInvalidResult)
	}
	if err := validateAdmissionForm(result.Admission); err != nil {
		return problem(CodeInvalidResult)
	}
	if err := validateDomainPresence(profile, result.Domain); err != nil {
		return err
	}
	if err := validateStatusForm(profile, result); err != nil {
		return err
	}
	for _, reason := range result.Reasons {
		if !globalReasonValid(string(reason)) {
			return problem(CodeInvalidResult)
		}
	}
	for _, trace := range result.Rules {
		if err := validateRuleTraceForm(trace); err != nil {
			return problem(CodeInvalidResult)
		}
	}
	for _, candidate := range result.Candidates {
		if err := validateCandidateForm(profile, candidate); err != nil {
			return problem(CodeInvalidResult)
		}
	}
	for _, reference := range result.EvidenceReferences {
		if reference.ItemIndex < 0 {
			return problem(CodeInvalidResult)
		}
	}
	for _, reference := range result.WarningReferences {
		if !warningOriginValid(reference.Origin) || reference.WarningIndex < 0 {
			return problem(CodeInvalidResult)
		}
		if reference.Origin == evaluator.WarningFromProvenance {
			if reference.EvidenceIndex != -1 {
				return problem(CodeInvalidResult)
			}
			continue
		}
		if reference.EvidenceIndex < 0 {
			return problem(CodeInvalidResult)
		}
	}
	return nil
}

func validateTargetForm(target evaluator.Target) error {
	if !boundedString(string(target.SubjectUID)) || !boundedString(string(target.ContainerName)) ||
		!boundedString(target.VulnerabilityID) || !boundedString(target.Source) ||
		!boundedString(string(target.Locator)) {
		return problem(CodeInvalidResult)
	}
	if !target.ContainerClass.Valid() {
		return problem(CodeInvalidResult)
	}
	if !isSha256(string(target.SourceHash)) {
		return problem(CodeInvalidResult)
	}
	if !canonicalInstant(target.ObservedAt) {
		return problem(CodeInvalidResult)
	}
	return nil
}

func validateAdmissionForm(admission rulepack.AdmissionContext) error {
	if !canonicalInstant(admission.EvaluatedAt) || !boundedString(admission.ExpectedPackID) {
		return problem(CodeInvalidResult)
	}
	if !isSha256(admission.ExpectedPackHash) {
		return problem(CodeInvalidResult)
	}
	if admission.MinimumVersion < 1 || admission.MinimumVersion > rulepack.MaxVersion {
		return problem(CodeInvalidResult)
	}
	if previous := admission.Previous; previous != nil {
		if previous.Version < 1 || previous.Version > rulepack.MaxVersion || !isSha256(previous.Hash) {
			return problem(CodeInvalidResult)
		}
	}
	return nil
}

// validateDomainPresence enforces the profile combination the engine produces:
// the domain context exists exactly in the product profile.
func validateDomainPresence(profile Profile, domain *evaluator.DomainContext) error {
	if profile == ProfileReadiness {
		if domain != nil {
			return problem(CodeInvalidResult)
		}
		return nil
	}
	if domain == nil {
		return problem(CodeInvalidResult)
	}
	if domain.MaximumEvidenceAgeSeconds < 1 || domain.MaximumEvidenceAgeSeconds > evaluator.MaxDomainEvidenceAgeSeconds {
		return problem(CodeInvalidResult)
	}
	if len(domain.SourcePins) < 1 || len(domain.SourcePins) > evaluator.MaxSourcePins {
		return problem(CodeInvalidResult)
	}
	for _, pin := range domain.SourcePins {
		if !pinFormValid(pin) {
			return problem(CodeInvalidResult)
		}
	}
	return nil
}

func pinFormValid(pin evaluator.SourcePin) bool {
	if !boundedString(pin.Source) || !isSha256(string(pin.SourceHash)) {
		return false
	}
	switch pin.Role {
	case evaluator.SourceRoleMapping, evaluator.SourceRoleArtifact:
		return pin.AdvisoryID == nil && pin.AdvisoryRevision == nil
	case evaluator.SourceRoleVendor:
		return pin.AdvisoryID != nil && pin.AdvisoryRevision != nil &&
			boundedString(*pin.AdvisoryID) && boundedString(*pin.AdvisoryRevision)
	}
	return false
}

// validateStatusForm enforces the status each profile can emit. The conservative
// profile never concludes affirmatively; the product profile emits the four
// states, still with no risk decision.
func validateStatusForm(profile Profile, result evaluator.Result) error {
	switch result.ProductStatus {
	case contract.ProductUnderInvestigation:
	case contract.ProductAffected, contract.ProductNotAffected, contract.ProductFixed:
		if profile != ProfileProduct {
			return problem(CodeInvalidResult)
		}
	default:
		return problem(CodeInvalidResult)
	}
	// Both implemented profiles leave exploitability unassessed; a fabricated
	// combination is not form.
	if result.Exploitability != contract.ExploitabilityNotAssessed {
		return problem(CodeInvalidResult)
	}
	return nil
}

func validateRuleTraceForm(trace evaluator.RuleTrace) error {
	if !boundedString(trace.RuleID) {
		return problem(CodeInvalidResult)
	}
	switch trace.State {
	case evaluator.RuleNotApplicable, evaluator.RuleMissingEvidence, evaluator.RuleChecked:
	default:
		return problem(CodeInvalidResult)
	}
	for _, requirement := range trace.MissingRequirements {
		if !isRequirementName(string(requirement)) {
			return problem(CodeInvalidResult)
		}
	}
	for _, reason := range trace.Reasons {
		if !checkReasonValid(reason) {
			return problem(CodeInvalidResult)
		}
	}
	if err := validateReferencesSign(trace.EvidenceReferences); err != nil {
		return err
	}
	for _, check := range trace.Checks {
		if !boundedString(check.CheckID) || !checkOutcomeValid(check.Outcome) {
			return problem(CodeInvalidResult)
		}
		for _, reason := range check.Reasons {
			if !checkReasonValid(reason) {
				return problem(CodeInvalidResult)
			}
		}
		if err := validateReferencesSign(check.EvidenceReferences); err != nil {
			return err
		}
	}
	return nil
}

func validateCandidateForm(profile Profile, candidate evaluator.Candidate) error {
	if !boundedString(candidate.RuleID) {
		return problem(CodeInvalidResult)
	}
	if profile != ProfileProduct {
		return problem(CodeInvalidResult)
	}
	switch candidate.ProductStatus {
	case contract.ProductAffected, contract.ProductNotAffected, contract.ProductFixed:
	default:
		return problem(CodeInvalidResult)
	}
	return validateReferencesSign(candidate.EvidenceReferences)
}

func validateReferencesSign(references []evaluator.EvidenceReference) error {
	for _, reference := range references {
		if reference.ItemIndex < 0 {
			return problem(CodeInvalidResult)
		}
	}
	return nil
}

func checkOutcomeValid(outcome evaluator.CheckOutcome) bool {
	switch outcome {
	case evaluator.OutcomePass, evaluator.OutcomeFail, evaluator.OutcomeUnknown:
		return true
	}
	return false
}

func checkReasonValid(reason evaluator.CheckReason) bool {
	switch reason {
	case evaluator.ReasonMissing, evaluator.ReasonUnavailable, evaluator.ReasonRedacted,
		evaluator.ReasonConflict, evaluator.ReasonFutureObservation, evaluator.ReasonMismatch,
		evaluator.ReasonVerified, evaluator.ReasonExpired, evaluator.ReasonUnapprovedSource,
		evaluator.ReasonUnsupportedProof:
		return true
	}
	return false
}

func globalReasonValid(reason string) bool {
	switch evaluator.Reason(reason) {
	case evaluator.ReasonNoApplicableRule, evaluator.ReasonTargetUnsubstantiated,
		evaluator.ReasonIncompleteEvidence, evaluator.ReasonBlockingWarning,
		evaluator.ReasonConflictingEvidence, evaluator.ReasonRequirementsMissing,
		evaluator.ReasonChecksFailed, evaluator.ReasonChecksUnknown,
		evaluator.ReasonDomainAssessmentDeferred, evaluator.ReasonNoAffirmativeCandidate,
		evaluator.ReasonAffirmativeConflict, evaluator.ReasonDomainEvidenceExpired,
		evaluator.ReasonDomainSourceUnapproved, evaluator.ReasonDomainProofUnsupported:
		return true
	}
	return false
}

func warningOriginValid(origin evaluator.WarningOrigin) bool {
	switch origin {
	case evaluator.WarningFromProvenance, evaluator.WarningFromEvidence:
		return true
	}
	return false
}

// canonicalInstant accepts the instants this presentation can express: a
// non-zero UTC timestamp whose year is representable by the ratified
// RFC3339Nano grammar (years 0000-9999). It reads no clock. The identity
// comparison is the same rule the wire validator applies; a name comparison
// would accept a fixed zone merely named "UTC" whose offset is not zero, and an
// unbounded year would render as text the grammar does not admit.
func canonicalInstant(value contract.Timestamp) bool {
	if value.IsZero() || value.Location() != time.UTC {
		return false
	}
	if year := value.Year(); year < 0 || year > 9999 {
		return false
	}
	return true
}

func boundedString(value string) bool {
	return value != "" && len(value) <= evaluator.MaxTargetStringBytes && utf8.ValidString(value)
}

// projectResult copies the result field by field. Every collection is
// normalized to an array, never null, and no value of any evidence item is
// copied: only the references are.
func projectResult(result evaluator.Result) ResultDTO {
	dto := ResultDTO{
		EngineVersion:  result.EngineVersion,
		ProfileVersion: Profile(result.ProfileVersion),
		BundleHash:     result.BundleHash,
		PackID:         result.PackID,
		PackVersion:    result.PackVersion,
		PackHash:       result.PackHash,
		Target: TargetDTO{
			SubjectUID:      string(result.Target.SubjectUID),
			ContainerClass:  string(result.Target.ContainerClass),
			ContainerName:   string(result.Target.ContainerName),
			VulnerabilityID: result.Target.VulnerabilityID,
			Source:          result.Target.Source,
			SourceHash:      string(result.Target.SourceHash),
			Locator:         string(result.Target.Locator),
			ObservedAt:      formatTimestamp(result.Target.ObservedAt),
		},
		Admission: AdmissionDTO{
			EvaluatedAt:      formatTimestamp(result.Admission.EvaluatedAt),
			ExpectedPackID:   result.Admission.ExpectedPackID,
			ExpectedPackHash: result.Admission.ExpectedPackHash,
			MinimumVersion:   result.Admission.MinimumVersion,
			Previous:         previousDTO(result.Admission.Previous),
		},
		Domain:         domainDTO(result.Domain),
		ProductStatus:  string(result.ProductStatus),
		Exploitability: string(result.Exploitability),
		Reasons:        reasonList(result.Reasons),
		Rules:          ruleList(result.Rules),
		Candidates:     candidateList(result.Candidates),
	}
	dto.EvidenceReferences = referenceList(result.EvidenceReferences)
	dto.WarningReferences = warningReferenceList(result.WarningReferences)
	return dto
}

func previousDTO(previous *rulepack.PreviousVersion) *PreviousDTO {
	if previous == nil {
		return nil
	}
	return &PreviousDTO{Version: previous.Version, Hash: previous.Hash}
}

func domainDTO(domain *evaluator.DomainContext) *DomainDTO {
	if domain == nil {
		return nil
	}
	pins := make([]SourcePinDTO, 0, len(domain.SourcePins))
	for _, pin := range domain.SourcePins {
		pins = append(pins, SourcePinDTO{
			Role:             string(pin.Role),
			Source:           pin.Source,
			SourceHash:       string(pin.SourceHash),
			AdvisoryID:       copyString(pin.AdvisoryID),
			AdvisoryRevision: copyString(pin.AdvisoryRevision),
		})
	}
	return &DomainDTO{MaximumEvidenceAgeSeconds: domain.MaximumEvidenceAgeSeconds, SourcePins: pins}
}

func copyString(value *string) *string {
	if value == nil {
		return nil
	}
	copied := *value
	return &copied
}

func reasonList(reasons []evaluator.Reason) []string {
	list := make([]string, 0, len(reasons))
	for _, reason := range reasons {
		list = append(list, string(reason))
	}
	return list
}

func ruleList(traces []evaluator.RuleTrace) []RuleTraceDTO {
	list := make([]RuleTraceDTO, 0, len(traces))
	for _, trace := range traces {
		list = append(list, RuleTraceDTO{
			RuleID:              trace.RuleID,
			State:               string(trace.State),
			MissingRequirements: requirementList(trace.MissingRequirements),
			Checks:              checkList(trace.Checks),
			Reasons:             checkReasonList(trace.Reasons),
			EvidenceReferences:  referenceList(trace.EvidenceReferences),
		})
	}
	return list
}

func requirementList(requirements []rulepack.Requirement) []string {
	list := make([]string, 0, len(requirements))
	for _, requirement := range requirements {
		list = append(list, string(requirement))
	}
	return list
}

func checkList(checks []evaluator.CheckTrace) []CheckTraceDTO {
	list := make([]CheckTraceDTO, 0, len(checks))
	for _, check := range checks {
		list = append(list, CheckTraceDTO{
			CheckID:            check.CheckID,
			Outcome:            string(check.Outcome),
			Reasons:            checkReasonList(check.Reasons),
			EvidenceReferences: referenceList(check.EvidenceReferences),
		})
	}
	return list
}

func checkReasonList(reasons []evaluator.CheckReason) []string {
	list := make([]string, 0, len(reasons))
	for _, reason := range reasons {
		list = append(list, string(reason))
	}
	return list
}

func candidateList(candidates []evaluator.Candidate) []CandidateDTO {
	list := make([]CandidateDTO, 0, len(candidates))
	for _, candidate := range candidates {
		list = append(list, CandidateDTO{
			RuleID:             candidate.RuleID,
			ProductStatus:      string(candidate.ProductStatus),
			EvidenceReferences: referenceList(candidate.EvidenceReferences),
		})
	}
	return list
}

func referenceList(references []evaluator.EvidenceReference) []ReferenceDTO {
	list := make([]ReferenceDTO, 0, len(references))
	for _, reference := range references {
		list = append(list, ReferenceDTO{ItemIndex: reference.ItemIndex})
	}
	return list
}

func warningReferenceList(references []evaluator.WarningReference) []WarningRefDTO {
	list := make([]WarningRefDTO, 0, len(references))
	for _, reference := range references {
		list = append(list, WarningRefDTO{
			Origin:        string(reference.Origin),
			EvidenceIndex: reference.EvidenceIndex,
			WarningIndex:  reference.WarningIndex,
		})
	}
	return list
}
