package evaluator

import (
	"strings"
	"testing"

	"github.com/d4rpell/Ariadne/internal/rulepack"
	contract "github.com/d4rpell/Ariadne/pkg/evidence"
)

// Regression tests of the findings of the independent review of F4a. Each test
// fails on the code as reviewed and passes after the correction.

// TestDomainFieldConfidenceIsContractual is the regression of P1-1: every
// occurrence of every field must carry the confidence of its family, not only
// the method field.
func TestDomainFieldConfidenceIsContractual(t *testing.T) {
	subject := baseSubject(t)

	// Every field of every family, one at a time: the record must stop being
	// interpretable when the confidence of any field changes.
	cases := []struct {
		name   string
		items  func() []contract.EvidenceItem
		fields []string
	}{
		{
			"mapping",
			func() []contract.EvidenceItem { return mappingItems(t, subject, containerA) },
			[]string{
				"product_v1.mapping.method", "product_v1.mapping.coverage",
				"product_v1.mapping.vulnerability_id", "product_v1.mapping.component_id",
				"product_v1.mapping.package_name", "product_v1.mapping.package_arch",
			},
		},
		{
			"artifact",
			func() []contract.EvidenceItem { return artifactItems(t, subject, containerA) },
			[]string{
				"product_v1.artifact.method", "product_v1.artifact.artifact_digest",
				"product_v1.artifact.epoch", "product_v1.artifact.version",
				"product_v1.artifact.package_release", "product_v1.artifact.digest_kind",
			},
		},
		{
			"vendor",
			func() []contract.EvidenceItem {
				return vendorItems(t, subject, containerA, proofVulnerableBuild)
			},
			[]string{
				"product_v1.vendor.method", "product_v1.vendor.proof_kind",
				"product_v1.vendor.applicability", "product_v1.vendor.vulnerable_code_id",
				"product_v1.vendor.basis_id", "product_v1.vendor.source_status_value",
			},
		},
	}
	for _, testCase := range cases {
		for _, field := range testCase.fields {
			t.Run(testCase.name+"/"+field, func(t *testing.T) {
				items := testCase.items()
				changed := false
				for index := range items {
					if items[index].Type != field {
						continue
					}
					// A wrong confidence with an intact value and hash: the
					// decoder must refuse the record on the confidence alone.
					items[index].Confidence = wrongConfidenceFor(items[index].Confidence)
					changed = true
				}
				if !changed {
					t.Fatalf("the fixture does not carry %s", field)
				}
				index := indexDomainRecords(bundleWith(items), baseTarget(t))
				decoded := decodeDomainRecords(index)
				if interpreted(decoded, testCase.name) != 0 {
					t.Fatalf("a %s record with a wrong confidence in %s was interpreted", testCase.name, field)
				}
			})
		}
	}

	t.Run("duplicated occurrence with a wrong confidence", func(t *testing.T) {
		items := mappingItems(t, subject, containerA)
		duplicate := mappingItems(t, subject, containerA)
		for index := range duplicate {
			if duplicate[index].Type != "product_v1.mapping.component_id" {
				continue
			}
			duplicate[index].Confidence = contract.ProvenanceObserved
		}
		// The duplicate shares the provenance tuple, so it lands in the same
		// record: the wrong confidence in the second occurrence must destroy it.
		index := indexDomainRecords(bundleWith(append(items, duplicate...)), baseTarget(t))
		if len(decodeDomainRecords(index).mappings) != 0 {
			t.Fatal("a duplicated field with a wrong confidence must invalidate the record")
		}
	})

	t.Run("control records stay interpretable", func(t *testing.T) {
		index := indexDomainRecords(productControlBundle(t, proofVulnerableBuild), baseTarget(t))
		decoded := decodeDomainRecords(index)
		if len(decoded.mappings) != 1 || len(decoded.artifacts) != 1 || len(decoded.vendors) != 1 {
			t.Fatalf("the control must decode: %d/%d/%d", len(decoded.mappings), len(decoded.artifacts), len(decoded.vendors))
		}
	})
}

func wrongConfidenceFor(current contract.ProvenanceKind) contract.ProvenanceKind {
	if current == contract.ProvenanceObserved {
		return contract.ProvenanceDerived
	}
	return contract.ProvenanceObserved
}

func bundleWith(items []contract.EvidenceItem) contract.Bundle {
	bundle := contract.Bundle{
		SchemaVersion:            rulepack.ProductBundleSchemaVersion,
		Subject:                  contract.Subject{UID: uidA, ClusterAlias: clusterA, Namespace: namespaceA, Kind: "Pod", Name: podNameA},
		Images:                   []contract.ImageIdentity{},
		Evidence:                 items,
		ObservedContainerClasses: []contract.ContainerClass{},
		Provenance: contract.RunProvenance{
			CollectorVersion: "0.1.0",
			ParserVersion:    "prisma-v1.0",
			ArgvSanitized:    []string{"import", sourceCSV},
			Inputs:           []contract.InputRef{{Path: sourceCSV, Hash: contract.SourceHash(sourceHashCSV)}},
			APIScope:         contract.APIScope{Namespaces: []contract.Namespace{}, Verbs: []string{}, Resources: []string{}},
			Coverage:         contract.Coverage{Method: contract.CoverageFindingsImport, Termination: contract.TerminationFinished, Rows: &contract.CoverageRows{Total: uint64Pointer(1), Accepted: 1, Rejected: 0}},
			Completeness:     contract.CompletenessComplete,
			Consistency:      contract.ConsistencyPointObservation,
			RedactionPolicy:  "default-v1",
			Warnings:         []contract.Warning{},
			Errors:           []string{},
		},
	}
	return bundle
}

func uint64Pointer(value uint64) *uint64 { return &value }

func interpreted(decoded domainRecords, family string) int {
	switch family {
	case "mapping":
		return len(decoded.mappings)
	case "artifact":
		return len(decoded.artifacts)
	case "vendor":
		return len(decoded.vendors)
	}
	return 0
}

// TestDomainScalarRule is the regression of P1-2: the domain scalars are 1-256
// UTF-8 bytes without controls and without surrounding whitespace, and the pins
// obey the same rule.
func TestDomainScalarRule(t *testing.T) {
	subject := baseSubject(t)

	t.Run("locator over the scalar length", func(t *testing.T) {
		items := mappingItems(t, baseSubject(t), containerA)
		for index := range items {
			items[index].Locator = contract.SourceLocator("records/" + strings.Repeat("a", rulepack.MaxStringBytes))
		}
		index := indexDomainRecords(bundleWith(items), baseTarget(t))
		if len(decodeDomainRecords(index).mappings) != 0 {
			t.Fatal("a locator over the scalar length must not be interpretable")
		}
	})

	t.Run("locator with an interior control", func(t *testing.T) {
		items := mappingItems(t, baseSubject(t), containerA)
		for index := range items {
			items[index].Locator = contract.SourceLocator("records/mapping\x01/0")
		}
		index := indexDomainRecords(bundleWith(items), baseTarget(t))
		if len(decodeDomainRecords(index).mappings) != 0 {
			t.Fatal("a locator with an interior control must not be interpretable")
		}
	})

	t.Run("source with an interior control", func(t *testing.T) {
		items := mappingItems(t, baseSubject(t), containerA)
		for index := range items {
			items[index].Source = "mapping\x01.json"
		}
		index := indexDomainRecords(bundleWith(items), baseTarget(t))
		if len(decodeDomainRecords(index).mappings) != 0 {
			t.Fatal("a source with an interior control must not be interpretable")
		}
	})

	t.Run("over-long value", func(t *testing.T) {
		items := mappingItems(t, subject, containerA)
		for index := range items {
			if items[index].Type == "product_v1.mapping.component_id" {
				replaceValue(&items[index], strings.Repeat("a", rulepack.MaxStringBytes+1))
			}
		}
		index := indexDomainRecords(bundleWith(items), baseTarget(t))
		if len(decodeDomainRecords(index).mappings) != 0 {
			t.Fatal("a value over 256 bytes must not be interpretable")
		}
	})

	t.Run("interior control", func(t *testing.T) {
		items := mappingItems(t, subject, containerA)
		for index := range items {
			if items[index].Type == "product_v1.mapping.component_id" {
				replaceValue(&items[index], "open\x00ssl")
			}
		}
		index := indexDomainRecords(bundleWith(items), baseTarget(t))
		if len(decodeDomainRecords(index).mappings) != 0 {
			t.Fatal("a value with an interior control must not be interpretable")
		}
	})

	t.Run("surrounding whitespace", func(t *testing.T) {
		items := mappingItems(t, subject, containerA)
		for index := range items {
			if items[index].Type == "product_v1.mapping.component_id" {
				replaceValue(&items[index], " openssl ")
			}
		}
		index := indexDomainRecords(bundleWith(items), baseTarget(t))
		if len(decodeDomainRecords(index).mappings) != 0 {
			t.Fatal("a value with surrounding whitespace must not be interpretable")
		}
	})

	t.Run("pin with an interior control", func(t *testing.T) {
		request := productReplayRequest(t, proofVulnerableBuild)
		domain := copyDomainContext(*request.Domain)
		domain.SourcePins[0].Source = "map\x01ping.json"
		request.Domain = &domain
		_, err := Evaluate(request)
		wantRulepackCode(t, err, rulepack.CodeInvalidContext)
	})

	t.Run("pin over the scalar length", func(t *testing.T) {
		request := productReplayRequest(t, proofVulnerableBuild)
		domain := copyDomainContext(*request.Domain)
		domain.SourcePins[0].Source = strings.Repeat("a", rulepack.MaxStringBytes+1)
		request.Domain = &domain
		_, err := Evaluate(request)
		wantRulepackCode(t, err, rulepack.CodeInvalidContext)
	})

	t.Run("advisory revision with an interior control", func(t *testing.T) {
		request := productReplayRequest(t, proofVulnerableBuild)
		domain := copyDomainContext(*request.Domain)
		value := "re\x02vision"
		domain.SourcePins[2].AdvisoryRevision = &value
		request.Domain = &domain
		_, err := Evaluate(request)
		wantRulepackCode(t, err, rulepack.CodeInvalidContext)
	})
}

// TestDomainIdentityUnion is the regression of P1-3: mapping, artifact, vendor
// and the observation must agree on the complete tuple, so no field can
// contradict another record.
func TestDomainIdentityUnion(t *testing.T) {
	cases := map[string]func(*[]contract.EvidenceItem){
		"mapping package contradicts artifact and vendor": func(items *[]contract.EvidenceItem) {
			// The artifact and the vendor share one package identity; the mapping
			// disagrees. Only the artifact-to-mapping agreement catches this.
			replaceFieldValue(items, "product_v1.mapping.package_name", "zlib")
		},
		"artifact package arch contradicts mapping": func(items *[]contract.EvidenceItem) {
			replaceFieldValue(items, "product_v1.artifact.package_arch", "aarch64")
		},
		"mapping platform contradicts image and artifact": func(items *[]contract.EvidenceItem) {
			// Mapping and vendor say arm64; image and artifact say amd64. Only the
			// artifact-to-mapping agreement catches this, because the artifact does
			// agree with the image.
			replaceFieldValue(items, "product_v1.mapping.architecture", "arm64")
			replaceFieldValue(items, "product_v1.vendor.architecture", "arm64")
		},
		"vendor platform contradicts image": func(items *[]contract.EvidenceItem) {
			replaceFieldValue(items, "product_v1.vendor.architecture", "arm64")
		},
		"vendor package contradicts artifact": func(items *[]contract.EvidenceItem) {
			replaceFieldValue(items, "product_v1.vendor.package_name", "zlib")
		},
		"vendor evr contradicts artifact": func(items *[]contract.EvidenceItem) {
			replaceFieldValue(items, "product_v1.vendor.version", "9.9.9")
		},
		"mapping component contradicts artifact": func(items *[]contract.EvidenceItem) {
			replaceFieldValue(items, "product_v1.mapping.component_id", "zlib")
		},
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			// The mutation happens on a complete control bundle, so the finding row
			// and the observation are present and the chain can only be refused by
			// the union rule under test.
			bundle := productControlBundle(t, proofVulnerableBuild)
			mutate(&bundle.Evidence)
			assessment := assessDomain(newResolver(mustCanonical(t, bundle), baseTarget(t), evaluatedAt, &referenceBudget{}), productDomainContext(t))
			if len(assessment.supported) != 0 {
				t.Fatalf("%s: the chain sustained %d states, want none", name, len(assessment.supported))
			}
			// The refusal must come from the identity union, not from a missing
			// operand: the mapping and the artifact are still resolvable.
			if !assessment.mappingOK {
				t.Fatal("the fixture broke the mapping instead of the union under test")
			}
		})
	}

	t.Run("control chain sustains the state", func(t *testing.T) {
		assessment := assessDomain(newResolver(productControlBundle(t, proofVulnerableBuild), baseTarget(t), evaluatedAt, &referenceBudget{}), productDomainContext(t))
		if len(assessment.supported) != 1 {
			t.Fatalf("the control must sustain one state, got %d", len(assessment.supported))
		}
	})
}

func replaceFieldValue(items *[]contract.EvidenceItem, itemType, value string) {
	for index := range *items {
		if (*items)[index].Type == itemType {
			replaceValue(&(*items)[index], value)
		}
	}
}

// TestDomainGlobalReferencesIndependentOfRules is the regression of P1-4: the
// global inspection of the domain is part of the result even when no rule
// selected it, and equivalent duplicates keep every reference.
func TestDomainGlobalReferencesIndependentOfRules(t *testing.T) {
	subject := baseSubject(t)

	t.Run("no applicable rule keeps the domain references", func(t *testing.T) {
		bundle := productControlBundle(t, proofVulnerableBuild)
		other := replaceRuleCVE(productRuleJSON("rule.other", rulepack.OutputAffected, "redhat_build_affected"), cveOther)
		result, err := Evaluate(productRequest(t, bundle, other))
		if err != nil {
			t.Fatalf("control: %v", err)
		}
		if !containsGlobalReason(result.Reasons, ReasonNoApplicableRule) {
			t.Fatalf("reasons = %v, want no_applicable_rule", result.Reasons)
		}
		// The oracle walks the canonical array, because the references are indices
		// of it and the caller's order is not the canonical one.
		canonical := mustCanonical(t, bundle)
		covered := map[int]bool{}
		for _, reference := range result.EvidenceReferences {
			if reference.ItemIndex < 0 || reference.ItemIndex >= len(canonical.Evidence) {
				t.Fatalf("the reference %d does not resolve in the canonical array", reference.ItemIndex)
			}
			covered[reference.ItemIndex] = true
		}
		missing := 0
		for index, item := range canonical.Evidence {
			if !isDomainType(item.Type) {
				continue
			}
			if !covered[index] {
				missing++
			}
		}
		if missing != 0 {
			t.Fatalf("%d domain items are not referenced without an applicable rule", missing)
		}
	})

	t.Run("equivalent duplicates keep every reference", func(t *testing.T) {
		bundle := productControlBundle(t, proofVulnerableBuild)
		duplicate := mappingItems(t, subject, containerA)
		for index := range duplicate {
			duplicate[index].Locator = "records/mapping/1"
		}
		bundle.Evidence = append(bundle.Evidence, duplicate...)
		result, err := Evaluate(productRequest(t, bundle))
		if err != nil {
			t.Fatalf("control: %v", err)
		}
		canonical := mustCanonical(t, bundle)
		covered := map[int]bool{}
		for _, reference := range result.EvidenceReferences {
			if reference.ItemIndex < 0 || reference.ItemIndex >= len(canonical.Evidence) {
				t.Fatalf("the reference %d does not resolve in the canonical array", reference.ItemIndex)
			}
			covered[reference.ItemIndex] = true
		}
		for index, item := range canonical.Evidence {
			if item.Type != "product_v1.mapping.component_id" {
				continue
			}
			if !covered[index] {
				t.Fatalf("the equivalent mapping occurrence %d is not referenced", index)
			}
		}

		// The trace of the rule is inspected directly as well: the global list
		// and a rule trace are two independent storage locations, and a loss in
		// either one must be visible here. This closes the reserve of I-28.
		for _, trace := range result.Rules {
			if trace.RuleID != "rule.affected" {
				continue
			}
			traceCovered := map[int]bool{}
			for _, reference := range trace.EvidenceReferences {
				traceCovered[reference.ItemIndex] = true
			}
			for index, item := range canonical.Evidence {
				if item.Type != "product_v1.mapping.component_id" {
					continue
				}
				if !traceCovered[index] {
					t.Fatalf("the equivalent mapping occurrence %d is missing from the rule trace", index)
				}
			}
		}
	})
}

// TestDomainVendorProofRequiresCompleteSet is the regression of P1-5: an
// unauthorized or incomplete candidate leaves the requirement unsatisfied, so no
// check runs and no candidate appears.
func TestDomainVendorProofRequiresCompleteSet(t *testing.T) {
	subject := baseSubject(t)

	t.Run("candidate without a pin", func(t *testing.T) {
		bundle := productControlBundle(t, proofVulnerableBuild)
		request := productRequest(t, bundle)
		domain := copyDomainContext(*request.Domain)
		domain.SourcePins = domain.SourcePins[:2]
		request.Domain = &domain
		result, err := Evaluate(request)
		if err != nil {
			t.Fatalf("control: %v", err)
		}
		rule := ruleIndex(t, &result, "rule.affected")
		trace := result.Rules[rule]
		if trace.State != RuleMissingEvidence {
			t.Fatalf("state = %s, want missing_evidence for an unauthorized candidate", trace.State)
		}
		if !containsRequirement(trace.MissingRequirements, rulepack.RequirementDomainVendorProof) {
			t.Fatalf("missing requirements = %v, want domain.vendor_proof", trace.MissingRequirements)
		}
		if len(trace.Checks) != 0 {
			t.Fatal("a rule with a missing requirement must not execute checks")
		}
		if len(result.Candidates) != 0 {
			t.Fatal("an unsatisfied requirement must not produce a candidate")
		}
	})

	t.Run("incomplete candidate blocks the requirement", func(t *testing.T) {
		bundle := productControlBundle(t, proofVulnerableBuild)
		partial := vendorItems(t, subject, containerA, proofFixedBuild)[:5]
		for index := range partial {
			partial[index].Locator = "records/proof/1"
		}
		bundle.Evidence = append(bundle.Evidence, partial...)
		result, err := Evaluate(productRequest(t, bundle))
		if err != nil {
			t.Fatalf("control: %v", err)
		}
		rule := ruleIndex(t, &result, "rule.affected")
		if result.Rules[rule].State != RuleMissingEvidence {
			t.Fatalf("state = %s, want missing_evidence", result.Rules[rule].State)
		}
		if len(result.Candidates) != 0 {
			t.Fatal("an incomplete candidate must not produce a candidate")
		}
	})

	t.Run("unknown name in the reserved namespace blocks the requirement", func(t *testing.T) {
		bundle := productControlBundle(t, proofVulnerableBuild)
		bundle.Evidence = append(bundle.Evidence,
			syntheticDomainItem(baseSubject(t), containerA, "product_v1.mapping.future_field", "x",
				mustSource(t, domainSourceMapping, "mapping source body\n"), domainLocatorMapping, contract.ProvenanceDerived))
		result, err := Evaluate(productRequest(t, bundle))
		if err != nil {
			t.Fatalf("an unknown name is uncertainty, not a rejection: %v", err)
		}
		rule := ruleIndex(t, &result, "rule.affected")
		trace := result.Rules[rule]
		if trace.State != RuleMissingEvidence {
			t.Fatalf("state = %s, want missing_evidence: an unknown name leaves the set uninterpretable", trace.State)
		}
		if !containsRequirement(trace.MissingRequirements, rulepack.RequirementDomainVendorProof) {
			t.Fatalf("missing requirements = %v, want domain.vendor_proof", trace.MissingRequirements)
		}
		if len(trace.Checks) != 0 {
			t.Fatal("a rule with a missing requirement must not execute checks")
		}
		if len(result.Candidates) != 0 {
			t.Fatal("an unknown name must not produce a candidate")
		}
		if !containsGlobalReason(result.Reasons, ReasonDomainProofUnsupported) {
			t.Fatalf("reasons = %v, want domain_proof_unsupported", result.Reasons)
		}
	})

	t.Run("a foreign vendor proof does not block the chain", func(t *testing.T) {
		// A complete proof of the same CVE and component but another product
		// release is explicitly not applicable: §6.4 allows discarding it, so it
		// must not be charged to the source policy or to the age policy.
		bundle := productControlBundle(t, proofVulnerableBuild)
		foreign := vendorItems(t, baseSubject(t), containerA, proofFixedBuild)
		old := mustStamp(t, sourceObservedAt.AddDate(-5, 0, 0))
		for index := range foreign {
			foreign[index].Locator = "records/proof/1"
			foreign[index].Source = "foreign-advisory.json"
			foreign[index].SourceHash = independentSourceHash("foreign advisory body")
			foreign[index].ObservedAt = stampPointer(old)
			if foreign[index].Type == "product_v1.vendor.product_release" {
				replaceValue(&foreign[index], "8")
			}
		}
		bundle.Evidence = append(bundle.Evidence, foreign...)
		result, err := Evaluate(productRequest(t, bundle))
		if err != nil {
			t.Fatalf("control: %v", err)
		}
		if result.ProductStatus != contract.ProductAffected {
			t.Fatalf("status = %s, want affected: a not-applicable proof of another release must not block", result.ProductStatus)
		}
		if containsGlobalReason(result.Reasons, ReasonDomainSourceUnapproved) {
			t.Fatalf("reasons = %v: an unpinned source of a not-applicable proof must not block", result.Reasons)
		}
		if containsGlobalReason(result.Reasons, ReasonDomainEvidenceExpired) {
			t.Fatalf("reasons = %v: an old not-applicable proof must not expire the target", result.Reasons)
		}
		// Its references stay in the global inspection, so the discarded record is
		// still visible.
		covered := map[int]bool{}
		for _, reference := range result.EvidenceReferences {
			covered[reference.ItemIndex] = true
		}
		missing := 0
		for index, item := range mustCanonical(t, bundle).Evidence {
			if item.Source != "foreign-advisory.json" {
				continue
			}
			if !covered[index] {
				missing++
			}
		}
		if missing != 0 {
			t.Fatalf("%d references of the discarded proof are not in the global inspection", missing)
		}
	})

	t.Run("conflict between valid proofs keeps the requirement satisfied", func(t *testing.T) {
		// The set is complete and interpretable; the conflict is a global blocker,
		// not a missing requirement. The terminal checks run and the result is
		// blocked with affirmative_conflict.
		bundle := productControlBundle(t, proofVulnerableBuild)
		second := vendorItems(t, subject, containerA, proofFixedBuild)
		for index := range second {
			second[index].Locator = "records/proof/1"
		}
		bundle.Evidence = append(bundle.Evidence, second...)
		result, err := Evaluate(productRequest(t, bundle))
		if err != nil {
			t.Fatalf("control: %v", err)
		}
		rule := ruleIndex(t, &result, "rule.affected")
		if result.Rules[rule].State != RuleChecked {
			t.Fatalf("state = %s, want checked: a valid conflict is not a missing requirement", result.Rules[rule].State)
		}
		if !containsGlobalReason(result.Reasons, ReasonAffirmativeConflict) {
			t.Fatalf("reasons = %v, want affirmative_conflict", result.Reasons)
		}
	})
}

func containsRequirement(requirements []rulepack.Requirement, wanted rulepack.Requirement) bool {
	for _, requirement := range requirements {
		if requirement == wanted {
			return true
		}
	}
	return false
}

// TestDomainPertinenceScope is the regression of P1-6: a record of another CVE,
// product or component is not a proof of this target and cannot block it through
// the source policy or the age policy.
func TestDomainPertinenceScope(t *testing.T) {
	subject := baseSubject(t)

	t.Run("foreign CVE mapping with an unpinned source", func(t *testing.T) {
		bundle := productControlBundle(t, proofVulnerableBuild)
		foreign := mappingItems(t, subject, containerA)
		for index := range foreign {
			foreign[index].Source = "other-cve.json"
			foreign[index].SourceHash = independentSourceHash("other cve body")
			foreign[index].Locator = "records/mapping/9"
			if foreign[index].Type == "product_v1.mapping.vulnerability_id" {
				replaceValue(&foreign[index], cveOther)
			}
		}
		bundle.Evidence = append(bundle.Evidence, foreign...)
		result, err := Evaluate(productRequest(t, bundle))
		if err != nil {
			t.Fatalf("control: %v", err)
		}
		if result.ProductStatus != contract.ProductAffected {
			t.Fatalf("status = %s, want affected: a mapping of another CVE is not a candidate of this target", result.ProductStatus)
		}
		if containsGlobalReason(result.Reasons, ReasonDomainSourceUnapproved) {
			t.Fatalf("reasons = %v: an unpinned source of another CVE must not block", result.Reasons)
		}
	})

	t.Run("foreign CVE mapping with an old timestamp", func(t *testing.T) {
		bundle := productControlBundle(t, proofVulnerableBuild)
		old := mustStamp(t, sourceObservedAt.AddDate(-5, 0, 0))
		foreign := mappingItems(t, subject, containerA)
		for index := range foreign {
			foreign[index].ObservedAt = stampPointer(old)
			foreign[index].Locator = "records/mapping/9"
			if foreign[index].Type == "product_v1.mapping.vulnerability_id" {
				replaceValue(&foreign[index], cveOther)
			}
		}
		bundle.Evidence = append(bundle.Evidence, foreign...)
		result, err := Evaluate(productRequest(t, bundle))
		if err != nil {
			t.Fatalf("control: %v", err)
		}
		if containsGlobalReason(result.Reasons, ReasonDomainEvidenceExpired) {
			t.Fatalf("reasons = %v: an old record of another CVE must not expire this target", result.Reasons)
		}
	})

	t.Run("another component artifact", func(t *testing.T) {
		bundle := productControlBundle(t, proofVulnerableBuild)
		foreign := artifactItems(t, subject, containerA)
		for index := range foreign {
			foreign[index].Locator = "records/artifact/9"
			if foreign[index].Type == "product_v1.artifact.component_id" {
				replaceValue(&foreign[index], "zlib")
			}
		}
		bundle.Evidence = append(bundle.Evidence, foreign...)
		result, err := Evaluate(productRequest(t, bundle))
		if err != nil {
			t.Fatalf("control: %v", err)
		}
		if result.ProductStatus != contract.ProductAffected {
			t.Fatalf("status = %s, want affected: another component is not a candidate", result.ProductStatus)
		}
	})

	t.Run("a pertinent incompatible candidate still blocks", func(t *testing.T) {
		// The correction must not weaken the ratified rule: a candidate of the same
		// CVE and component with an incompatible digest keeps blocking.
		bundle := productControlBundle(t, proofVulnerableBuild)
		incompatible := artifactItems(t, subject, containerA)
		for index := range incompatible {
			incompatible[index].Locator = "records/artifact/9"
			if incompatible[index].Type == "product_v1.artifact.artifact_digest" {
				replaceValue(&incompatible[index], "sha256:"+strings.Repeat("e", 64))
			}
		}
		bundle.Evidence = append(bundle.Evidence, incompatible...)
		result, err := Evaluate(productRequest(t, bundle))
		if err != nil {
			t.Fatalf("control: %v", err)
		}
		if result.ProductStatus != contract.ProductUnderInvestigation {
			t.Fatalf("status = %s, want under_investigation: a pertinent incompatible candidate blocks", result.ProductStatus)
		}
	})
}

// TestDomainPinCardinalityPhase is the regression of P1-7: the pin cardinality
// belongs to the limits phase, so an oversized collection of empty pins is
// input_limit even though it carries no bytes.
func TestDomainPinCardinalityPhase(t *testing.T) {
	request := productReplayRequest(t, proofVulnerableBuild)

	t.Run("empty pins exceed the cardinality", func(t *testing.T) {
		domain := DomainContext{MaximumEvidenceAgeSeconds: 60}
		domain.SourcePins = make([]SourcePin, MaxSourcePins+1)
		request.Domain = &domain
		_, err := Evaluate(request)
		wantCode(t, err, CodeInputLimit)
	})

	t.Run("the cardinality limit is not applied below it", func(t *testing.T) {
		// A context with a valid count reaches the form phase, so the rejection
		// above is the count and not a blanket refusal of the fixture.
		request := productReplayRequest(t, proofVulnerableBuild)
		if _, err := Evaluate(request); err != nil {
			t.Fatalf("the control must evaluate: %v", err)
		}
	})

	t.Run("a huge collection is rejected without being walked", func(t *testing.T) {
		domain := DomainContext{MaximumEvidenceAgeSeconds: 60}
		domain.SourcePins = make([]SourcePin, MaxSourcePins*1000)
		request.Domain = &domain
		_, err := Evaluate(request)
		wantCode(t, err, CodeInputLimit)
	})
}
