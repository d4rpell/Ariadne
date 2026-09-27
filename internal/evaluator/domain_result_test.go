package evaluator

import (
	"reflect"
	"testing"

	"github.com/d4rpell/Ariadne/internal/rulepack"
	contract "github.com/d4rpell/Ariadne/pkg/evidence"
)

// TestProductAffirmativeControls is I-37: the three independent positive
// controls, and a partial exclusion that blocks instead of concluding.
func TestProductAffirmativeControls(t *testing.T) {
	cases := []struct {
		name   string
		kind   proofKind
		emit   string
		status contract.ProductStatus
	}{
		{"affected", proofVulnerableBuild, rulepack.OutputAffected, contract.ProductAffected},
		{"fixed", proofFixedBuild, rulepack.OutputFixed, contract.ProductFixed},
		{"not affected", proofCodeExcludedBuild, rulepack.OutputNotAffected, contract.ProductNotAffected},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			bundle := productControlBundle(t, testCase.kind)
			request := productRequest(t, bundle,
				productRuleJSON("rule.terminal", testCase.emit, string(predicateFor(testCase.kind))))
			result, err := Evaluate(request)
			if err != nil {
				t.Fatalf("the control must evaluate: %v", err)
			}
			if result.ProductStatus != testCase.status {
				t.Fatalf("status = %s, want %s (reasons %v)", result.ProductStatus, testCase.status, result.Reasons)
			}
			if len(result.Candidates) != 1 {
				t.Fatalf("candidates = %d, want 1", len(result.Candidates))
			}
			if result.Candidates[0].ProductStatus != testCase.status {
				t.Fatalf("candidate status = %s, want %s", result.Candidates[0].ProductStatus, testCase.status)
			}
			if result.Exploitability != contract.ExploitabilityNotAssessed {
				t.Fatalf("exploitability = %s, want not_assessed", result.Exploitability)
			}
		})
	}

	t.Run("a patch is fixed, never not_affected", func(t *testing.T) {
		bundle := productControlBundle(t, proofFixedBuild)
		request := productRequest(t, bundle,
			productRuleJSON("rule.excluded", rulepack.OutputNotAffected, "redhat_build_code_excluded"))
		result, err := Evaluate(request)
		if err != nil {
			t.Fatalf("the control must evaluate: %v", err)
		}
		if result.ProductStatus != contract.ProductUnderInvestigation {
			t.Fatalf("status = %s, want under_investigation: a fix is not an exclusion", result.ProductStatus)
		}
	})

	t.Run("partial exclusion blocks", func(t *testing.T) {
		subject := baseSubject(t)
		bundle := productBundle(t, mappingItems(t, subject, containerA)...)
		bundle.Evidence = append(bundle.Evidence, artifactItems(t, subject, containerA)...)
		proof := vendorItems(t, subject, containerA, proofCodeExcludedBuild)
		for index := range proof {
			if proof[index].Type == "product_v1.vendor.exclusion_coverage" {
				replaceValue(&proof[index], "some_vulnerable_code")
			}
		}
		bundle.Evidence = append(bundle.Evidence, proof...)
		request := productRequest(t, bundle,
			productRuleJSON("rule.excluded", rulepack.OutputNotAffected, "redhat_build_code_excluded"))
		result, err := Evaluate(request)
		if err != nil {
			t.Fatalf("a partial exclusion is uncertainty, not a rejection: %v", err)
		}
		if result.ProductStatus != contract.ProductUnderInvestigation {
			t.Fatalf("status = %s, want under_investigation", result.ProductStatus)
		}
	})
}

func predicateFor(kind proofKind) rulepack.PredicateID {
	switch kind {
	case proofVulnerableBuild:
		return rulepack.PredicateRedhatBuildAffected
	case proofFixedBuild:
		return rulepack.PredicateRedhatBuildFixed
	}
	return rulepack.PredicateRedhatCodeExcluded
}

// TestProductConflictAllPairs is I-38: every incompatible pair blocks with
// affirmative_conflict, preserving all branches, and never resolves by order,
// majority or recency.
func TestProductConflictAllPairs(t *testing.T) {
	subject := baseSubject(t)
	pairs := []struct {
		name  string
		left  proofKind
		right proofKind
	}{
		{"affected vs fixed", proofVulnerableBuild, proofFixedBuild},
		{"affected vs not_affected", proofVulnerableBuild, proofCodeExcludedBuild},
		{"fixed vs not_affected", proofFixedBuild, proofCodeExcludedBuild},
	}
	for _, pair := range pairs {
		t.Run(pair.name, func(t *testing.T) {
			bundle := productBundle(t, mappingItems(t, subject, containerA)...)
			bundle.Evidence = append(bundle.Evidence, artifactItems(t, subject, containerA)...)
			left := vendorItems(t, subject, containerA, pair.left)
			right := vendorItems(t, subject, containerA, pair.right)
			for index := range right {
				right[index].Locator = "records/proof/1"
			}
			bundle.Evidence = append(bundle.Evidence, left...)
			bundle.Evidence = append(bundle.Evidence, right...)

			request := productRequest(t, bundle)
			// Both sources must be authorized: the second group lives in the same
			// source file, so the existing vendor pin already covers it.
			result, err := Evaluate(request)
			if err != nil {
				t.Fatalf("a conflict is a result, not an error: %v", err)
			}
			if result.ProductStatus != contract.ProductUnderInvestigation {
				t.Fatalf("status = %s, want under_investigation", result.ProductStatus)
			}
			if !containsGlobalReason(result.Reasons, ReasonAffirmativeConflict) {
				t.Fatalf("reasons = %v, want affirmative_conflict", result.Reasons)
			}
			if !containsGlobalReason(result.Reasons, ReasonConflictingEvidence) {
				t.Fatalf("reasons = %v, want conflicting_evidence", result.Reasons)
			}
			if len(result.EvidenceReferences) == 0 {
				t.Fatal("a conflict must preserve the references of both branches")
			}
		})
	}

	t.Run("order and permutation do not change the outcome", func(t *testing.T) {
		build := func(reverse bool) contract.Bundle {
			bundle := productBundle(t, mappingItems(t, subject, containerA)...)
			bundle.Evidence = append(bundle.Evidence, artifactItems(t, subject, containerA)...)
			left := vendorItems(t, subject, containerA, proofVulnerableBuild)
			right := vendorItems(t, subject, containerA, proofFixedBuild)
			for index := range right {
				right[index].Locator = "records/proof/1"
			}
			if reverse {
				bundle.Evidence = append(bundle.Evidence, right...)
				bundle.Evidence = append(bundle.Evidence, left...)
				return bundle
			}
			bundle.Evidence = append(bundle.Evidence, left...)
			bundle.Evidence = append(bundle.Evidence, right...)
			return bundle
		}
		first, err := Evaluate(productRequest(t, build(false)))
		if err != nil {
			t.Fatalf("control: %v", err)
		}
		second, err := Evaluate(productRequest(t, build(true)))
		if err != nil {
			t.Fatalf("permuted: %v", err)
		}
		if first.ProductStatus != second.ProductStatus {
			t.Fatal("the declared order changed the state")
		}
		if !reflect.DeepEqual(first.Reasons, second.Reasons) {
			t.Fatalf("the declared order changed the reasons: %v vs %v", first.Reasons, second.Reasons)
		}
	})

	t.Run("majority does not resolve a conflict", func(t *testing.T) {
		bundle := productBundle(t, mappingItems(t, subject, containerA)...)
		bundle.Evidence = append(bundle.Evidence, artifactItems(t, subject, containerA)...)
		first := vendorItems(t, subject, containerA, proofVulnerableBuild)
		second := vendorItems(t, subject, containerA, proofVulnerableBuild)
		third := vendorItems(t, subject, containerA, proofFixedBuild)
		for index := range second {
			second[index].Locator = "records/proof/1"
		}
		for index := range third {
			third[index].Locator = "records/proof/2"
		}
		bundle.Evidence = append(bundle.Evidence, first...)
		bundle.Evidence = append(bundle.Evidence, second...)
		bundle.Evidence = append(bundle.Evidence, third...)
		result, err := Evaluate(productRequest(t, bundle))
		if err != nil {
			t.Fatalf("control: %v", err)
		}
		if result.ProductStatus != contract.ProductUnderInvestigation {
			t.Fatalf("status = %s, want under_investigation: two against one is not a vote", result.ProductStatus)
		}
	})
}

// TestProductConflictWithoutOpposingRule is I-39: the opposite branch is detected
// even when the pack declares no terminal for it, and a pack without applicable
// rules keeps the global inspection.
func TestProductConflictWithoutOpposingRule(t *testing.T) {
	subject := baseSubject(t)

	t.Run("opposite proof without its rule", func(t *testing.T) {
		bundle := productBundle(t, mappingItems(t, subject, containerA)...)
		bundle.Evidence = append(bundle.Evidence, artifactItems(t, subject, containerA)...)
		// Only a fixed_build proof exists, but the pack only declares the affected
		// terminal. The sustained fixed state must still block the affected claim.
		bundle.Evidence = append(bundle.Evidence, vendorItems(t, subject, containerA, proofFixedBuild)...)
		request := productRequest(t, bundle,
			productRuleJSON("rule.affected", rulepack.OutputAffected, "redhat_build_affected"))
		result, err := Evaluate(request)
		if err != nil {
			t.Fatalf("control: %v", err)
		}
		if result.ProductStatus != contract.ProductUnderInvestigation {
			t.Fatalf("status = %s, want under_investigation: a fail of affected is not an affected claim", result.ProductStatus)
		}
		if len(result.EvidenceReferences) == 0 {
			t.Fatal("the opposite branch must stay referenced")
		}
		// The affected terminal ran and failed because the foreign exact proof was
		// inspected: the chain was complete, so the retirement is a check result,
		// never a missing requirement. An implementation that inspected only the
		// variants named by the pack would report missing evidence here.
		if !containsGlobalReason(result.Reasons, ReasonChecksFailed) {
			t.Fatalf("reasons = %v, want checks_failed: the foreign proof retires the branch", result.Reasons)
		}
		if containsGlobalReason(result.Reasons, ReasonRequirementsMissing) {
			t.Fatalf("reasons = %v: the chain is complete, no requirement is missing", result.Reasons)
		}
	})

	t.Run("incompatible proof without its rule still blocks", func(t *testing.T) {
		// Both proofs exist and only the affected rule is declared: the opposite
		// branch is inspected anyway, so the conflict is visible and no state is
		// published.
		bundle := productBundle(t, mappingItems(t, subject, containerA)...)
		bundle.Evidence = append(bundle.Evidence, artifactItems(t, subject, containerA)...)
		bundle.Evidence = append(bundle.Evidence, vendorItems(t, subject, containerA, proofVulnerableBuild)...)
		fixed := vendorItems(t, subject, containerA, proofFixedBuild)
		for index := range fixed {
			fixed[index].Locator = "records/proof/1"
		}
		bundle.Evidence = append(bundle.Evidence, fixed...)
		request := productRequest(t, bundle,
			productRuleJSON("rule.affected", rulepack.OutputAffected, "redhat_build_affected"))
		result, err := Evaluate(request)
		if err != nil {
			t.Fatalf("control: %v", err)
		}
		if result.ProductStatus != contract.ProductUnderInvestigation {
			t.Fatalf("status = %s, want under_investigation: the opposite proof must be inspected", result.ProductStatus)
		}
		if !containsGlobalReason(result.Reasons, ReasonAffirmativeConflict) {
			t.Fatalf("reasons = %v, want affirmative_conflict", result.Reasons)
		}
		// The candidate is retained for inspection, never published as a state:
		// the conflict blocks the publication, not the trace.
		for _, candidate := range result.Candidates {
			if candidate.ProductStatus == contract.ProductUnderInvestigation {
				t.Fatalf("a retained candidate must carry its sustained state: %+v", candidate)
			}
		}
	})

	t.Run("no applicable rule keeps the global inspection", func(t *testing.T) {
		bundle := productBundle(t, mappingItems(t, subject, containerA)...)
		bundle.Evidence = append(bundle.Evidence, artifactItems(t, subject, containerA)...)
		bundle.Evidence = append(bundle.Evidence, vendorItems(t, subject, containerA, proofVulnerableBuild)...)
		// The rule selects another CVE, so nothing applies.
		other := productRuleJSON("rule.other", rulepack.OutputAffected, "redhat_build_affected")
		other = replaceRuleCVE(other, cveOther)
		result, err := Evaluate(productRequest(t, bundle, other))
		if err != nil {
			t.Fatalf("control: %v", err)
		}
		if !containsGlobalReason(result.Reasons, ReasonNoApplicableRule) {
			t.Fatalf("reasons = %v, want no_applicable_rule", result.Reasons)
		}
	})
}

func replaceRuleCVE(document, cve string) string {
	return replaceAll(document, cveA, cve)
}

// replaceAll replaces every occurrence. It must not be called with an after
// that contains before: the replacement would be replaced again forever.
func replaceAll(document, before, after string) string {
	for {
		index := indexOf(document, before)
		if index < 0 {
			return document
		}
		document = document[:index] + after + document[index+len(before):]
	}
}

func indexOf(document, wanted string) int {
	for index := 0; index+len(wanted) <= len(document); index++ {
		if document[index:index+len(wanted)] == wanted {
			return index
		}
	}
	return -1
}

// TestProductWarningsGlobal is I-40: contradictory and unknown warnings block
// even outside the selected items, and a known informational warning does not.
func TestProductWarningsGlobal(t *testing.T) {
	t.Run("contradictory warning on an unused item", func(t *testing.T) {
		bundle := productControlBundle(t, proofVulnerableBuild)
		// The warning sits on the declared row item, which no domain rule selects.
		bundle.Evidence[0].Warnings = []contract.Warning{{
			Code: "uid_changed", Class: contract.WarningContradictory, Message: "the pod uid changed",
		}}
		result, err := Evaluate(productRequest(t, bundle))
		if err != nil {
			t.Fatalf("control: %v", err)
		}
		if result.ProductStatus != contract.ProductUnderInvestigation {
			t.Fatalf("status = %s, want under_investigation", result.ProductStatus)
		}
		if !containsGlobalReason(result.Reasons, ReasonBlockingWarning) {
			t.Fatalf("reasons = %v, want blocking_warning", result.Reasons)
		}
	})

	t.Run("provenance warning blocks too", func(t *testing.T) {
		bundle := productControlBundle(t, proofVulnerableBuild)
		bundle.Provenance.Warnings = []contract.Warning{
			{Code: "scope_mismatch", Class: contract.WarningContradictory, Message: "another scope was read"},
			{Code: "tool_failure", Class: contract.WarningInformational, Message: "the collector retried the request"},
		}
		result, err := Evaluate(productRequest(t, bundle))
		if err != nil {
			t.Fatalf("control: %v", err)
		}
		if !containsGlobalReason(result.Reasons, ReasonBlockingWarning) {
			t.Fatalf("reasons = %v, want blocking_warning", result.Reasons)
		}
		// Both provenance warnings are occurrences of the result: neither may be
		// deduplicated away nor replaced by the other.
		present := map[int]bool{}
		for _, reference := range result.WarningReferences {
			if reference.Origin != WarningFromProvenance {
				continue
			}
			if reference.EvidenceIndex != -1 {
				t.Fatalf("a provenance warning must use evidence index -1: %+v", reference)
			}
			present[reference.WarningIndex] = true
		}
		for index := range bundle.Provenance.Warnings {
			if !present[index] {
				t.Fatalf("the provenance warning %d was not reported: %+v", index, result.WarningReferences)
			}
		}
	})

	t.Run("unknown code blocks", func(t *testing.T) {
		bundle := productControlBundle(t, proofVulnerableBuild)
		bundle.Evidence[0].Warnings = []contract.Warning{{
			Code: "future_code", Class: contract.WarningInformational, Message: "uninterpretable",
		}}
		result, err := Evaluate(productRequest(t, bundle))
		if err != nil {
			t.Fatalf("control: %v", err)
		}
		if !containsGlobalReason(result.Reasons, ReasonBlockingWarning) {
			t.Fatalf("reasons = %v, want blocking_warning", result.Reasons)
		}
	})

	t.Run("known informational does not block", func(t *testing.T) {
		bundle := productControlBundle(t, proofVulnerableBuild)
		bundle.Evidence[0].Warnings = []contract.Warning{{
			Code: "redaction_applied", Class: contract.WarningInformational, Message: "the value was redacted",
		}}
		result, err := Evaluate(productRequest(t, bundle))
		if err != nil {
			t.Fatalf("control: %v", err)
		}
		if result.ProductStatus != contract.ProductAffected {
			t.Fatalf("status = %s, want affected: an informational warning does not block", result.ProductStatus)
		}
	})

	t.Run("every occurrence of a repeated warning is reported", func(t *testing.T) {
		// The same warning twice on different items is two occurrences, not one:
		// a deduplication by code or message would hide the second one from the
		// explanation even though both are part of the bundle.
		bundle := productControlBundle(t, proofVulnerableBuild)
		warning := contract.Warning{Code: "source_conflict", Class: contract.WarningContradictory, Message: "the sources disagree"}
		bundle.Evidence[0].Warnings = []contract.Warning{warning}
		bundle.Evidence[1].Warnings = []contract.Warning{warning}
		result, err := Evaluate(productRequest(t, bundle))
		if err != nil {
			t.Fatalf("control: %v", err)
		}
		canonical := mustCanonical(t, bundle)
		seen := map[WarningReference]bool{}
		for _, reference := range result.WarningReferences {
			seen[reference] = true
		}
		for index, item := range canonical.Evidence {
			for warningIndex := range item.Warnings {
				wanted := WarningReference{Origin: WarningFromEvidence, EvidenceIndex: index, WarningIndex: warningIndex}
				if !seen[wanted] {
					t.Fatalf("the warning occurrence on item %d was not reported: %+v", index, result.WarningReferences)
				}
			}
		}
	})
}

// TestProductRuleCombination is I-41: a missing or unknown affirmative rule
// blocks another favourable one, and a failing scanner restriction only retires
// its own candidate.
func TestProductRuleCombination(t *testing.T) {
	t.Run("missing affirmative rule blocks another", func(t *testing.T) {
		bundle := productControlBundle(t, proofVulnerableBuild)
		// The second affirmative rule selects the same CVE and demands the
		// installed_version field, whose item is removed: it stays missing_evidence
		// and its uncertainty must block the favourable first rule.
		kept := make([]contract.EvidenceItem, 0, len(bundle.Evidence))
		for _, item := range bundle.Evidence {
			if item.Type == "prisma_v1.installed_version" {
				continue
			}
			kept = append(kept, item)
		}
		bundle.Evidence = kept
		second := productRuleJSON("rule.second", rulepack.OutputFixed, "redhat_build_fixed")
		second = addRequirement(second, `"finding.installed_version"`)
		result, err := Evaluate(productRequest(t, bundle,
			productRuleJSON("rule.first", rulepack.OutputAffected, "redhat_build_affected"), second))
		if err != nil {
			t.Fatalf("control: %v", err)
		}
		if result.ProductStatus != contract.ProductUnderInvestigation {
			t.Fatalf("status = %s, want under_investigation: an uncertain affirmative rule blocks", result.ProductStatus)
		}
	})

	t.Run("a failing restriction retires only its candidate", func(t *testing.T) {
		bundle := productControlBundle(t, proofVulnerableBuild)
		// A rule whose scanner restriction fails cannot sustain a candidate, but
		// it does not contradict the affected proof either.
		restricted := productRuleJSON("rule.restricted", rulepack.OutputAffected, "redhat_build_affected")
		restricted = addRequirement(restricted, `"finding.fix_status"`)
		restricted = addCheck(restricted,
			`{"check_id":"check.fix_status","predicate":"finding_field_equals","params":{"field":"fix_status","value":"not-fixed"}}`)
		result, err := Evaluate(productRequest(t, bundle,
			productRuleJSON("rule.plain", rulepack.OutputAffected, "redhat_build_affected"), restricted))
		if err != nil {
			t.Fatalf("control: %v", err)
		}
		if result.ProductStatus != contract.ProductAffected {
			t.Fatalf("status = %s, want affected (reasons %v)", result.ProductStatus, result.Reasons)
		}
	})
}

func addRequirement(document, requirement string) string {
	const anchor = `"domain.current"`
	index := indexOf(document, anchor)
	if index < 0 {
		return document
	}
	end := index + len(anchor)
	return document[:end] + "," + requirement + document[end:]
}

func addCheck(document, check string) string {
	index := indexOf(document, `"checks":[`)
	if index < 0 {
		return document
	}
	start := index + len(`"checks":[`)
	return document[:start] + check + "," + document[start:]
}

// TestProductReferencesAndReasons is I-42: the references are canonical and
// complete, retained candidates keep their references, and the reason vocabulary
// stays closed.
func TestProductReferencesAndReasons(t *testing.T) {
	subject := baseSubject(t)

	t.Run("references resolve and are canonical", func(t *testing.T) {
		bundle := productControlBundle(t, proofVulnerableBuild)
		result, err := Evaluate(productRequest(t, bundle))
		if err != nil {
			t.Fatalf("control: %v", err)
		}
		if len(result.EvidenceReferences) == 0 {
			t.Fatal("an affirmative conclusion must reference its support")
		}
		previous := -1
		for _, reference := range result.EvidenceReferences {
			if reference.ItemIndex < previous {
				t.Fatal("references are not in canonical index order")
			}
			if reference.ItemIndex < 0 || reference.ItemIndex >= len(bundle.Evidence) {
				t.Fatalf("reference %d does not resolve", reference.ItemIndex)
			}
			previous = reference.ItemIndex
		}
		// Every reference resolves to an item of the target scope.
		for _, reference := range result.EvidenceReferences {
			item := bundle.Evidence[reference.ItemIndex]
			if item.Scope.SubjectUID != result.Target.SubjectUID || item.Scope.ContainerName != result.Target.ContainerName {
				t.Fatalf("reference %d points outside the target scope", reference.ItemIndex)
			}
		}
	})

	t.Run("retained candidates keep their references on conflict", func(t *testing.T) {
		bundle := productBundle(t, mappingItems(t, subject, containerA)...)
		bundle.Evidence = append(bundle.Evidence, artifactItems(t, subject, containerA)...)
		left := vendorItems(t, subject, containerA, proofVulnerableBuild)
		right := vendorItems(t, subject, containerA, proofFixedBuild)
		for index := range right {
			right[index].Locator = "records/proof/1"
		}
		bundle.Evidence = append(bundle.Evidence, left...)
		bundle.Evidence = append(bundle.Evidence, right...)
		// A domain record of another vulnerability is not a candidate of this
		// target and no requirement selects it, so only the global inspection can
		// reference it. It stays in the fixture on purpose: the conflict path must
		// not drop the records the rules did not read.
		foreign := mappingItems(t, subject, containerA)
		for index := range foreign {
			foreign[index].Locator = "records/mapping/foreign"
			if foreign[index].Type == "product_v1.mapping.vulnerability_id" {
				replaceValue(&foreign[index], cveOther)
			}
		}
		bundle.Evidence = append(bundle.Evidence, foreign...)
		result, err := Evaluate(productRequest(t, bundle))
		if err != nil {
			t.Fatalf("control: %v", err)
		}
		if !containsGlobalReason(result.Reasons, ReasonAffirmativeConflict) {
			t.Fatalf("reasons = %v, want affirmative_conflict", result.Reasons)
		}
		// The global references must cover both proof groups and the foreign
		// record, so every branch and every inspected record is resolvable from
		// the result. The oracle walks the canonical array, the only one the
		// indices refer to, and demands every domain item of the target scope.
		canonical := mustCanonical(t, bundle)
		covered := map[int]bool{}
		for _, reference := range result.EvidenceReferences {
			if reference.ItemIndex < 0 || reference.ItemIndex >= len(canonical.Evidence) {
				t.Fatalf("the reference %d does not resolve in the canonical array", reference.ItemIndex)
			}
			covered[reference.ItemIndex] = true
		}
		groupItems := 0
		for index, item := range canonical.Evidence {
			if !isDomainType(item.Type) {
				continue
			}
			groupItems++
			if !covered[index] {
				t.Fatalf("the domain item %d (%s) is not referenced in the conflict result", index, item.Type)
			}
		}
		if groupItems == 0 {
			t.Fatal("the fixture must carry domain items")
		}
	})

	t.Run("reason vocabulary is closed", func(t *testing.T) {
		known := map[Reason]bool{}
		for _, reason := range []Reason{
			ReasonNoApplicableRule, ReasonTargetUnsubstantiated, ReasonIncompleteEvidence,
			ReasonBlockingWarning, ReasonConflictingEvidence, ReasonRequirementsMissing,
			ReasonChecksFailed, ReasonChecksUnknown, ReasonDomainAssessmentDeferred,
			ReasonNoAffirmativeCandidate, ReasonAffirmativeConflict, ReasonDomainEvidenceExpired,
			ReasonDomainSourceUnapproved, ReasonDomainProofUnsupported,
		} {
			known[reason] = true
		}
		bundle := productControlBundle(t, proofVulnerableBuild)
		result, err := Evaluate(productRequest(t, bundle))
		if err != nil {
			t.Fatalf("control: %v", err)
		}
		for _, reason := range result.Reasons {
			if !known[reason] {
				t.Fatalf("the result carries an unknown reason %q", reason)
			}
		}
		// The deferred-domain reason is not part of the product profile.
		if containsGlobalReason(result.Reasons, ReasonDomainAssessmentDeferred) {
			t.Fatal("the product profile must not defer its domain assessment")
		}
	})
}

// TestProductEvaluationBudgets is I-43: the reference budget counts globals,
// candidates, warning references and every repetition, and exhausting it rejects
// with evaluation_limit and a zero result instead of truncating the explanation.
func TestProductEvaluationBudgets(t *testing.T) {
	t.Run("the reference budget rejects when exhausted", func(t *testing.T) {
		// Thousands of equivalent mapping records are pertinent candidates: their
		// repetitions across requirements, traces and the global inspection exceed
		// the reference budget, so the evaluation must reject instead of dropping a
		// branch.
		bundle := crowdedDomainBundle(t, 3000)
		request := productRequest(t, bundle)

		// Which budget fires is measured, not assumed: the bundle limits pass and
		// the candidate budget stays below its own limit, so the only remaining
		// output budget is the reference one.
		usage := measureBundle(bundle, ratifiedBundleLimits())
		if usage.rejected() {
			t.Fatalf("the fixture must not exceed the bundle limits: %+v", usage)
		}
		if charged := candidateBudgetCharged(t, request); charged > MaxCandidateBudget {
			t.Fatalf("the fixture charges %d candidates, over their own budget", charged)
		}

		result, err := Evaluate(request)
		wantCode(t, err, CodeEvaluationLimit)
		if !reflect.DeepEqual(result, Result{}) {
			t.Fatal("an exhausted budget must not return a partial result")
		}
	})

	t.Run("a result inside the budget counts every occurrence", func(t *testing.T) {
		bundle := productControlBundle(t, proofVulnerableBuild)
		request := productRequest(t, bundle)
		result, err := Evaluate(request)
		if err != nil {
			t.Fatalf("control: %v", err)
		}
		count := referenceCount(result)
		if count == 0 {
			t.Fatal("the control must carry references")
		}
		if count > MaxResultReferences {
			t.Fatalf("the result stores %d occurrences, over the budget %d", count, MaxResultReferences)
		}
		if len(result.WarningReferences) != len(bundle.Provenance.Warnings) {
			t.Fatalf("warning references = %d, want %d", len(result.WarningReferences), len(bundle.Provenance.Warnings))
		}
	})

	t.Run("candidate references are charged", func(t *testing.T) {
		bundle := productControlBundle(t, proofVulnerableBuild)
		result, err := Evaluate(productRequest(t, bundle))
		if err != nil {
			t.Fatalf("control: %v", err)
		}
		if len(result.Candidates) != 1 {
			t.Fatalf("candidates = %d, want 1", len(result.Candidates))
		}
		if len(result.Candidates[0].EvidenceReferences) == 0 {
			t.Fatal("a candidate must carry its references")
		}
		// The counter the test uses must include the candidate occurrences: with
		// them removed the total has to change, or the bound would not see them.
		if len(result.Candidates[0].EvidenceReferences) == 0 {
			t.Fatal("the fixture must charge candidate references")
		}
		stripped := result
		stripped.Candidates = nil
		if referenceCount(result) == referenceCount(stripped) {
			t.Fatal("the test counter does not charge the candidate references")
		}
	})

	t.Run("the global inspection is charged even without candidates of its own", func(t *testing.T) {
		// Records of another vulnerability are never candidates of this target,
		// so nothing but the global inspection charges them. The boundary was
		// measured: at 7100 copies the result is stored, at 7135 the occurrences
		// exceed the reference budget and the evaluation rejects with a zero
		// result. An implementation that stops charging the global references
		// would admit the larger request.
		base := productControlBundle(t, proofVulnerableBuild)
		inside := foreignDomainBundle(t, base, 7100)
		request := productRequest(t, inside, productRuleJSON("rule.affected", rulepack.OutputAffected, "redhat_build_affected"))
		result, err := Evaluate(request)
		if err != nil {
			t.Fatalf("the fixture inside the budget must evaluate: %v", err)
		}
		if len(result.Candidates) != 1 {
			t.Fatalf("candidates = %d, want 1", len(result.Candidates))
		}
		if usage := measureBundle(inside, ratifiedBundleLimits()); usage.rejected() {
			t.Fatalf("the inside fixture must not exceed the bundle limits: %+v", usage)
		}

		over := foreignDomainBundle(t, base, 7135)
		request = productRequest(t, over, productRuleJSON("rule.affected", rulepack.OutputAffected, "redhat_build_affected"))
		result, err = Evaluate(request)
		wantCode(t, err, CodeEvaluationLimit)
		if !reflect.DeepEqual(result, Result{}) {
			t.Fatal("an exhausted reference budget must not return a partial result")
		}
	})
}

// foreignDomainBundle returns the control bundle plus complete mapping records
// of another vulnerability, each under its own locator: they are never
// candidates of the target, so only the global inspection references them.
func foreignDomainBundle(t *testing.T, base contract.Bundle, copies int) contract.Bundle {
	t.Helper()
	subject := baseSubject(t)
	bundle := cloneBundle(base)
	for copy := 0; copy < copies; copy++ {
		foreign := mappingItems(t, subject, containerA)
		for index := range foreign {
			foreign[index].Locator = contract.SourceLocator("records/foreign/" + suffixOf(copy))
			if foreign[index].Type == "product_v1.mapping.vulnerability_id" {
				replaceValue(&foreign[index], cveOther)
			}
		}
		bundle.Evidence = append(bundle.Evidence, foreign...)
	}
	return bundle
}

// candidateBudgetCharged measures, outside the engine, the work the rules of a
// request demand: every requirement of every matching rule and of every check,
// counted the way the work budget counts them.
func candidateBudgetCharged(t *testing.T, request Request) int {
	t.Helper()
	canonical, err := canonicalCopy(request.Bundle)
	if err != nil {
		t.Fatalf("canonical copy: %v", err)
	}
	budget := &referenceBudget{}
	resolver := newResolver(canonical, baseTarget(t), evaluatedAt, budget)
	domain := assessDomain(resolver, *request.Domain)
	facts := newFactSet(resolver, &domain)
	rule := firstRuleOf(t, request)
	charged := 0
	for _, requirement := range rule.Requires {
		charged += facts.resolve(requirement).candidates
	}
	for _, check := range rule.Checks {
		for _, requirement := range checkRequirements(check) {
			charged += facts.resolve(requirement).candidates
		}
	}
	// The global inspection is work too, and the engine charges it: the control
	// has to count it or it understates the fixture.
	return charged + len(domain.globalRefs)
}
