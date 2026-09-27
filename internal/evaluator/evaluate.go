package evaluator

import (
	"sort"

	"github.com/d4rpell/Ariadne/internal/rulepack"
	contract "github.com/d4rpell/Ariadne/pkg/evidence"
)

// factSet resolves requirements lazily and remembers each outcome, so a pack
// cannot multiply work by repeating requirements.
type factSet struct {
	resolver *resolver
	domain   *domainAssessment
	resolved map[rulepack.Requirement]requirementOutcome
}

func newFactSet(resolver *resolver, domain *domainAssessment) *factSet {
	return &factSet{
		resolver: resolver,
		domain:   domain,
		resolved: make(map[rulepack.Requirement]requirementOutcome),
	}
}

// storeCheckReferences admits the occurrence one check trace stores. A repeated
// check repeats its references in the Result, so it is admitted again instead of
// sharing the memoized slice without charge.
func (facts *factSet) storeCheckReferences(refs []EvidenceReference) []EvidenceReference {
	if !facts.resolver.budget.admit(len(refs)) {
		return []EvidenceReference{}
	}
	return refs
}

func (facts *factSet) resolve(requirement rulepack.Requirement) requirementOutcome {
	if outcome, ok := facts.resolved[requirement]; ok {
		return outcome
	}
	var outcome requirementOutcome
	switch requirement {
	case rulepack.RequirementDomainMapping, rulepack.RequirementDomainArtifact,
		rulepack.RequirementDomainVendorProof, rulepack.RequirementDomainCurrent:
		outcome = domainRequirementOutcome(requirement, facts.domain, facts.resolver)
	default:
		outcome = facts.resolver.outcome(requirement)
	}
	facts.resolved[requirement] = outcome
	return outcome
}

// Evaluate is the whole engine: limits, request form, bundle integrity, pack
// admission, ruleset linkage, work budget and rule execution. A returned error
// rejects the evaluation and the result is the zero value, never a partial one.
//
// The phases are the ratified order of ADR-0018 §4 and ADR-0015 §7.3: limits;
// context and target form; bundle validity, projection hash and value integrity;
// pack presence and hash; pack syntax, schema and profile (vocabulary first, then
// the profile/version cross); identity and anti-downgrade; validity; ruleset
// linkage; work budget and result.
func Evaluate(request Request) (Result, error) {
	// 1. Limits of every input, context included whether or not a profile will
	// end up requiring it.
	if err := checkInputLimits(request); err != nil {
		return Result{}, err
	}
	// 2. Form of the caller-supplied context and target, before any bundle
	// interpretation. The profile is recognized strictly and without admission,
	// because the context contract depends on it and the context phase precedes
	// pack admission (ADR-0018 §3/§4).
	recognition := rulepack.RecognizeProfile(request.PackBytes)
	if err := checkContextForm(request, recognition); err != nil {
		return Result{}, err
	}
	if err := request.Admission.Validate(); err != nil {
		return Result{}, err
	}
	if err := checkTargetForm(request); err != nil {
		return Result{}, err
	}
	// 3. Bundle validity, projection hash, canonical copy and value integrity.
	if err := contract.ValidateBundle(request.Bundle); err != nil {
		return Result{}, problem(CodeInvalidBundle, -1)
	}
	bundleHash, err := projectionHash(request.Bundle)
	if err != nil {
		return Result{}, err
	}
	if !isSha256(request.ExpectedBundleHash) || bundleHash != request.ExpectedBundleHash {
		return Result{}, problem(CodeBundleHashMismatch, -1)
	}
	canonicalBundle, err := canonicalCopy(request.Bundle)
	if err != nil {
		return Result{}, err
	}
	// Domain value integrity belongs to the bundle phase: the classification
	// decides which types are verified, and the pack is not admitted yet.
	if err := checkValueHashes(canonicalBundle, recognition); err != nil {
		return Result{}, err
	}
	// 4. Pack admission: presence, bytes, schema, identity, version and validity,
	// plus the profile/version cross inside the schema phase.
	admitted, err := rulepack.AdmitForBundle(request.PackBytes, request.Admission, canonicalBundle.SchemaVersion)
	if err != nil {
		return Result{}, err
	}
	pack := admitted.Pack()
	product := pack.Profile == rulepack.ProductEvidenceProfile
	// 5. Ruleset linkage: a bundle may name a ruleset, and then it must name the
	// admitted pack. Its path and version are inert references.
	if ruleset := canonicalBundle.Provenance.Ruleset; ruleset != (contract.RulesetRef{}) {
		if string(ruleset.Hash) != admitted.Hash() {
			return Result{}, problem(CodeRulesetMismatch, -1)
		}
	}

	budget := &referenceBudget{}
	resolver := newResolver(canonicalBundle, request.Target, request.Admission.EvaluatedAt.Time, budget)

	var domain domainAssessment
	if product {
		domain = assessDomain(resolver, *request.Domain)
	}

	facts := newFactSet(resolver, &domain)

	rules := sortedRules(pack.Rules)
	matched := 0
	candidates := 0
	for _, rule := range rules {
		if !selectorMatches(rule, canonicalBundle.Provenance.Coverage.Method, request.Target.VulnerabilityID) {
			continue
		}
		matched++
		for _, requirement := range rule.Requires {
			candidates += facts.resolve(requirement).candidates
		}
		for _, check := range rule.Checks {
			for _, requirement := range checkRequirements(check) {
				candidates += facts.resolve(requirement).candidates
			}
		}
	}
	// The global inspection is work too, even when no rule is applicable.
	if product {
		candidates += len(domain.globalRefs)
	}
	// 6. Work budget, computed before any check executes and independent of the
	// host or of the input order.
	if candidates > MaxCandidateBudget {
		return Result{}, problem(CodeEvaluationLimit, -1)
	}

	// The two requirements that decide whether the target is substantiated at all
	// are resolved even when no rule matches, because the reasons report it.
	rowOutcome := facts.resolve(rulepack.RequirementFindingRow)
	imageOutcome := facts.resolve(rulepack.RequirementImageBoundDigest)
	completeOutcome := facts.resolve(rulepack.RequirementBundleComplete)

	// The budget bounds storage itself: warning references and every repetition
	// of an evidence reference are admitted before they are appended, so no
	// collection ever grows past the limit.
	warningReferences, blocking := warningState(canonicalBundle, request.Target, budget)
	if budget.over {
		return Result{}, problem(CodeEvaluationLimit, -1)
	}

	traces := make([]RuleTrace, 0, len(rules))
	affirmativeCandidates := make([]Candidate, 0)
	conflict := false
	requirementsMissing := false
	checksFailed := false
	checksUnknown := false
	affirmativeUncertain := false
	for _, rule := range rules {
		trace, err := traceRule(rule, canonicalBundle.Provenance.Coverage.Method, request.Target.VulnerabilityID, facts)
		if err != nil {
			return Result{}, err
		}
		if budget.over {
			return Result{}, problem(CodeEvaluationLimit, -1)
		}
		traces = append(traces, trace)
		affirmative := product && rule.Emit != rulepack.OutputUnderInvestigation
		switch trace.State {
		case RuleMissingEvidence:
			requirementsMissing = true
			if affirmative {
				affirmativeUncertain = true
			}
		case RuleChecked:
			allPass := len(trace.Checks) > 0
			for _, check := range trace.Checks {
				switch check.Outcome {
				case OutcomeFail:
					checksFailed = true
					allPass = false
				case OutcomeUnknown:
					checksUnknown = true
					allPass = false
					if affirmative {
						affirmativeUncertain = true
					}
				}
			}
			if affirmative && allPass {
				candidate := Candidate{
					RuleID:             rule.RuleID,
					ProductStatus:      contract.ProductStatus(rule.Emit),
					EvidenceReferences: append([]EvidenceReference{}, trace.EvidenceReferences...),
				}
				if !budget.admit(len(candidate.EvidenceReferences)) {
					return Result{}, problem(CodeEvaluationLimit, -1)
				}
				affirmativeCandidates = append(affirmativeCandidates, candidate)
			}
		}
		for _, reason := range trace.Reasons {
			if reason == ReasonConflict {
				conflict = true
			}
		}
		if containsReason(rowOutcome.reasons, ReasonConflict) || containsReason(imageOutcome.reasons, ReasonConflict) {
			conflict = true
		}
	}

	evidenceReferences := collectReferences(traces, budget)
	if budget.over {
		return Result{}, problem(CodeEvaluationLimit, -1)
	}
	// The global domain inspection is part of the result whether or not a rule
	// selected it: a pack cannot hide the records it chose not to evaluate by
	// declaring no applicable rule. Every occurrence is charged to the budget.
	if product {
		if !budget.admit(len(domain.globalRefs)) {
			return Result{}, problem(CodeEvaluationLimit, -1)
		}
		evidenceReferences = append(evidenceReferences, domain.globalRefs...)
		sortReferencesInPlace(evidenceReferences)
	}

	// The admission context is copied, including its pointer member, so a caller
	// cannot rewrite a returned result through its own state.
	admission := request.Admission
	if previous := request.Admission.Previous; previous != nil {
		copied := *previous
		admission.Previous = &copied
	}

	var domainPointer *DomainContext
	if product {
		copied := copyDomainContext(*request.Domain)
		copied.SourcePins = sortedDomainPins(copied.SourcePins)
		domainPointer = &copied
	}

	status := contract.ProductUnderInvestigation
	exploitability := contract.ExploitabilityNotAssessed
	var reasons []Reason

	if product {
		globalDomain := domain.globalDomainReasons()
		for _, reason := range globalDomain {
			if reason == ReasonAffirmativeConflict {
				conflict = true
			}
		}
		status, reasons = resolveProductStatus(productResolution{
			candidates:            affirmativeCandidates,
			domain:                domain,
			affirmativeUncertain:  affirmativeUncertain,
			blocking:              blocking,
			conflict:              conflict,
			requirementsMissing:   requirementsMissing,
			checksFailed:          checksFailed,
			checksUnknown:         checksUnknown,
			noApplicableRule:      matched == 0,
			targetUnsubstantiated: !rowOutcome.satisfied || !imageOutcome.satisfied,
			incompleteEvidence:    !completeOutcome.satisfied,
			globalDomain:          globalDomain,
		})
	} else {
		reasons = globalReasons(globalState{
			noApplicableRule:      matched == 0,
			targetUnsubstantiated: !rowOutcome.satisfied || !imageOutcome.satisfied,
			incompleteEvidence:    !completeOutcome.satisfied,
			blockingWarning:       blocking,
			conflicting:           conflict,
			requirementsMissing:   requirementsMissing,
			checksFailed:          checksFailed,
			checksUnknown:         checksUnknown,
		})
	}

	return Result{
		EngineVersion:      EngineVersion,
		ProfileVersion:     pack.Profile,
		BundleHash:         bundleHash,
		PackID:             admitted.PackID(),
		PackVersion:        admitted.Version(),
		PackHash:           admitted.Hash(),
		Target:             request.Target,
		Admission:          admission,
		Domain:             domainPointer,
		ProductStatus:      status,
		Exploitability:     exploitability,
		Reasons:            reasons,
		Rules:              traces,
		Candidates:         affirmativeCandidates,
		EvidenceReferences: evidenceReferences,
		WarningReferences:  warningReferences,
	}, nil
}

func sortedRules(rules []rulepack.Rule) []rulepack.Rule {
	ordered := append([]rulepack.Rule{}, rules...)
	sort.Slice(ordered, func(i, j int) bool { return ordered[i].RuleID < ordered[j].RuleID })
	return ordered
}

func selectorMatches(rule rulepack.Rule, method contract.CoverageMethod, vulnerability string) bool {
	return rule.Selector.CoverageMethod == method && rule.Selector.VulnerabilityID == vulnerability
}

// traceRule executes one rule without short-circuiting: when every requirement is
// satisfied all checks run, and each check keeps its own outcome.
func traceRule(rule rulepack.Rule, method contract.CoverageMethod, vulnerability string, facts *factSet) (RuleTrace, error) {
	trace := RuleTrace{
		RuleID:              rule.RuleID,
		MissingRequirements: []rulepack.Requirement{},
		Checks:              []CheckTrace{},
		Reasons:             []CheckReason{},
		EvidenceReferences:  []EvidenceReference{},
	}
	if !selectorMatches(rule, method, vulnerability) {
		trace.State = RuleNotApplicable
		return trace, nil
	}

	missing := false
	var reasons []CheckReason
	var refs []EvidenceReference
	for _, requirement := range rule.Requires {
		outcome := facts.resolve(requirement)
		if !outcome.satisfied {
			missing = true
			trace.MissingRequirements = append(trace.MissingRequirements, requirement)
		}
		reasons = append(reasons, outcome.reasons...)
		refs = facts.resolver.copyReferences(refs, outcome.refs)
	}
	if missing {
		trace.State = RuleMissingEvidence
		// The missing requirements are ordered, so the trace does not depend on
		// the order the pack declared them.
		sort.Slice(trace.MissingRequirements, func(i, j int) bool {
			return trace.MissingRequirements[i] < trace.MissingRequirements[j]
		})
		trace.Reasons = orderReasons(reasons)
		trace.EvidenceReferences = sortReferences(refs)
		return trace, nil
	}

	trace.State = RuleChecked
	checks := append([]rulepack.Check{}, rule.Checks...)
	sort.Slice(checks, func(i, j int) bool { return checks[i].CheckID < checks[j].CheckID })
	for _, check := range checks {
		checkTrace := runCheck(check, facts)
		trace.Checks = append(trace.Checks, checkTrace)
		reasons = append(reasons, checkTrace.Reasons...)
		refs = facts.resolver.copyReferences(refs, checkTrace.EvidenceReferences)
	}
	trace.Reasons = orderReasons(reasons)
	trace.EvidenceReferences = sortReferences(refs)
	return trace, nil
}

func collectReferences(traces []RuleTrace, budget *referenceBudget) []EvidenceReference {
	var refs []EvidenceReference
	for _, trace := range traces {
		if !budget.admit(len(trace.EvidenceReferences)) {
			break
		}
		refs = append(refs, trace.EvidenceReferences...)
	}
	return sortReferences(refs)
}

// warningState inspects every warning of the provenance and of the target scope,
// whether or not a rule selected that item, and returns their canonical
// references plus whether any of them blocks conclusions.
func warningState(bundle contract.Bundle, target Target, budget *referenceBudget) ([]WarningReference, bool) {
	// The taxonomy is decided for every warning, because it is a semantic fact;
	// only the references are bounded by the budget, so the returned collection
	// never grows past the limit.
	var references []WarningReference
	blocking := false
	for index, warning := range bundle.Provenance.Warnings {
		if budget.admit(1) {
			references = append(references, WarningReference{
				Origin:        WarningFromProvenance,
				EvidenceIndex: -1,
				WarningIndex:  index,
			})
		}
		if blocks(warning) {
			blocking = true
		}
	}
	for itemIndex, item := range bundle.Evidence {
		if item.Scope.SubjectUID != target.SubjectUID || item.Scope.ContainerName != target.ContainerName {
			continue
		}
		for warningIndex, warning := range item.Warnings {
			if budget.admit(1) {
				references = append(references, WarningReference{
					Origin:        WarningFromEvidence,
					EvidenceIndex: itemIndex,
					WarningIndex:  warningIndex,
				})
			}
			if blocks(warning) {
				blocking = true
			}
		}
	}
	return references, blocking
}

// blocks is the taxonomy of ADR-0006 §8: a contradictory warning or a code this
// schema version does not define blocks a favourable conclusion.
func blocks(warning contract.Warning) bool {
	return warning.Class == contract.WarningContradictory || !warning.CodeKnown()
}

func containsReason(reasons []CheckReason, wanted CheckReason) bool {
	for _, reason := range reasons {
		if reason == wanted {
			return true
		}
	}
	return false
}

type globalState struct {
	noApplicableRule      bool
	targetUnsubstantiated bool
	incompleteEvidence    bool
	blockingWarning       bool
	conflicting           bool
	requirementsMissing   bool
	checksFailed          bool
	checksUnknown         bool
}

func globalReasons(state globalState) []Reason {
	var reasons []Reason
	add := func(condition bool, reason Reason) {
		if condition {
			reasons = append(reasons, reason)
		}
	}
	add(state.noApplicableRule, ReasonNoApplicableRule)
	add(state.targetUnsubstantiated, ReasonTargetUnsubstantiated)
	add(state.incompleteEvidence, ReasonIncompleteEvidence)
	add(state.blockingWarning, ReasonBlockingWarning)
	add(state.conflicting, ReasonConflictingEvidence)
	add(state.requirementsMissing, ReasonRequirementsMissing)
	add(state.checksFailed, ReasonChecksFailed)
	add(state.checksUnknown, ReasonChecksUnknown)
	// This profile never assesses the domain: the reason is always present.
	reasons = append(reasons, ReasonDomainAssessmentDeferred)
	sort.Slice(reasons, func(i, j int) bool { return reasons[i] < reasons[j] })
	return reasons
}
