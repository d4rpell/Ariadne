package evaluator

import (
	"strings"
	"testing"

	"github.com/d4rpell/Ariadne/internal/rulepack"
	contract "github.com/d4rpell/Ariadne/pkg/evidence"
)

// TestDomainContextForm is I-19: the context is mandatory for the product
// profile, has no default TTL, and every form rule of ADR-0015 §7.1 is enforced
// literally.
func TestDomainContextForm(t *testing.T) {
	subject := baseSubject(t)
	bundle := productBundle(t, mappingItems(t, subject, containerA)...)
	bundle.Evidence = append(bundle.Evidence, artifactItems(t, subject, containerA)...)
	bundle.Evidence = append(bundle.Evidence, vendorItems(t, subject, containerA, proofVulnerableBuild)...)
	request := productRequest(t, bundle)

	t.Run("control evaluates", func(t *testing.T) {
		result, err := Evaluate(request)
		if err != nil {
			t.Fatalf("control product request must evaluate: %v", err)
		}
		if result.Domain == nil || result.Domain.MaximumEvidenceAgeSeconds != request.Domain.MaximumEvidenceAgeSeconds {
			t.Fatal("the admitted context must be preserved in the result")
		}
	})

	t.Run("absent context in product", func(t *testing.T) {
		broken := request
		broken.Domain = nil
		_, err := Evaluate(broken)
		wantRulepackCode(t, err, rulepack.CodeInvalidContext)
	})

	t.Run("context present in readiness", func(t *testing.T) {
		legacy := baseRequest(t)
		legacy.Domain = request.Domain
		_, err := Evaluate(legacy)
		wantRulepackCode(t, err, rulepack.CodeInvalidContext)
	})

	t.Run("form", func(t *testing.T) {
		advisoryID := domainAdvisoryID
		revision := domainAdvisoryRev
		cases := map[string]func(*DomainContext){
			"zero ttl":        func(c *DomainContext) { c.MaximumEvidenceAgeSeconds = 0 },
			"negative ttl":    func(c *DomainContext) { c.MaximumEvidenceAgeSeconds = -1 },
			"ttl over 2^53-1": func(c *DomainContext) { c.MaximumEvidenceAgeSeconds = 1<<53 - 1 + 1 },
			"no pins":         func(c *DomainContext) { c.SourcePins = nil },
			"too many pins": func(c *DomainContext) {
				// 129 pins carry at least 71 bytes of hash each, so the joint byte
				// budget dominates the cardinality limit (X-2). The rejection is
				// input_limit either way; the count rule itself is measured in
				// TestDomainContextBudgets.
				pin := c.SourcePins[0]
				c.SourcePins = make([]SourcePin, MaxSourcePins+1)
				for index := range c.SourcePins {
					c.SourcePins[index] = pin
				}
			},
			"unknown role": func(c *DomainContext) { c.SourcePins[0].Role = "audit" },
			"empty source": func(c *DomainContext) { c.SourcePins[0].Source = "" },
			"padded source": func(c *DomainContext) {
				c.SourcePins[0].Source = " " + c.SourcePins[0].Source
			},
			"bad hash": func(c *DomainContext) { c.SourcePins[0].SourceHash = "sha256:short" },
			"mapping with advisory": func(c *DomainContext) {
				c.SourcePins[0].AdvisoryID = &advisoryID
			},
			"mapping with revision": func(c *DomainContext) {
				c.SourcePins[0].AdvisoryRevision = &revision
			},
			"vendor without advisory": func(c *DomainContext) { c.SourcePins[2].AdvisoryID = nil },
			"vendor without revision": func(c *DomainContext) { c.SourcePins[2].AdvisoryRevision = nil },
			"duplicated pin": func(c *DomainContext) {
				c.SourcePins[1] = c.SourcePins[0]
			},
		}
		for name, mutate := range cases {
			t.Run(name, func(t *testing.T) {
				broken := request
				domain := copyDomainContext(*request.Domain)
				mutate(&domain)
				broken.Domain = &domain
				_, err := Evaluate(broken)
				if name == "too many pins" {
					wantCode(t, err, CodeInputLimit)
					return
				}
				wantRulepackCode(t, err, rulepack.CodeInvalidContext)
			})
		}
	})

	t.Run("maximum ttl is accepted", func(t *testing.T) {
		adjusted := request
		domain := copyDomainContext(*request.Domain)
		domain.MaximumEvidenceAgeSeconds = MaxDomainEvidenceAgeSeconds
		adjusted.Domain = &domain
		if _, err := Evaluate(adjusted); err != nil {
			t.Fatalf("the maximum age policy must be representable: %v", err)
		}
	})

	t.Run("result context is detached and ordered", func(t *testing.T) {
		result, err := Evaluate(request)
		if err != nil {
			t.Fatalf("control: %v", err)
		}
		pins := result.Domain.SourcePins
		if len(pins) != 3 {
			t.Fatalf("pins = %d, want 3", len(pins))
		}
		for index := 1; index < len(pins); index++ {
			if compareSourcePins(pins[index-1], pins[index]) > 0 {
				t.Fatal("the result context must be ordered by the ratified tuple")
			}
		}
		// Rewriting the caller's context after the call cannot change the result.
		request.Domain.SourcePins[0].Source = "mutated.json"
		if result.Domain.SourcePins[0].Source == "mutated.json" {
			t.Fatal("the result aliases the caller context")
		}
	})
}

// TestDomainContextBudgets is I-20: the joint 4 KiB budget counts the typed
// strings of the admission and domain contexts, every occurrence included.
func TestDomainContextBudgets(t *testing.T) {
	request := productRequest(t, productBundle(t))

	t.Run("joint budget", func(t *testing.T) {
		// The control context is small; a padded source pushes it past 4 KiB.
		padded := request
		domain := copyDomainContext(*request.Domain)
		domain.SourcePins[0].Source = strings.Repeat("a", MaxContextTotalBytes)
		padded.Domain = &domain
		_, err := Evaluate(padded)
		wantCode(t, err, CodeInputLimit)
	})

	t.Run("the budget is joint, never per context", func(t *testing.T) {
		// The admission context and the domain context share the same 4 KiB: a
		// domain context that fits alone must still be refused when the room the
		// admission context already used leaves less than its own size. A
		// per-context reading would give each one 4 KiB and accept this request.
		request := productRequest(t, productBundle(t))
		admission := request.Admission
		admission.ExpectedPackID = strings.Repeat("i", MaxContextTotalBytes/2)
		request.Admission = admission
		domain := copyDomainContext(*request.Domain)
		domain.SourcePins[0].Source = strings.Repeat("s", MaxContextTotalBytes/2)
		request.Domain = &domain
		_, err := Evaluate(request)
		wantCode(t, err, CodeInputLimit)
	})

	t.Run("counted before any copy", func(t *testing.T) {
		// The oversized context is rejected in the limits phase, before the
		// context form or the bundle is interpreted.
		broken := request
		domain := copyDomainContext(*request.Domain)
		domain.SourcePins[0].Source = strings.Repeat("b", MaxContextTotalBytes+1)
		broken.Domain = &domain
		broken.Bundle = contract.Bundle{}
		_, err := Evaluate(broken)
		wantCode(t, err, CodeInputLimit)
	})

	t.Run("cardinality is separate from bytes", func(t *testing.T) {
		// 128 pins of one byte are well inside the byte budget but at the exact
		// cardinality limit; 129 exceed it. This is the layered method accepted
		// for X-2: the byte budget and the count are distinct limits.
		base := SourcePin{Role: SourceRoleMapping, Source: "s", SourceHash: independentSourceHash("s")}
		domain := DomainContext{MaximumEvidenceAgeSeconds: 60}
		for index := 0; index < MaxSourcePins; index++ {
			pin := base
			pin.Source = "s" + suffixOf(index)
			domain.SourcePins = append(domain.SourcePins, pin)
		}
		if err := validateDomainContext(domain); err != nil {
			t.Fatalf("128 distinct pins must be a valid form: %v", err)
		}
		domain.SourcePins = append(domain.SourcePins, SourcePin{
			Role: SourceRoleMapping, Source: "s-extra", SourceHash: independentSourceHash("extra"),
		})
		if err := validateDomainContext(domain); err == nil {
			t.Fatal("129 pins must exceed the cardinality limit")
		}
	})
}

// TestDomainCatalogClosed is I-22: the catalog is exactly the 59 names of
// ADR-0015 §6, the grammar is ASCII with the ratified lengths, and an unknown
// name inside the reserved prefix blocks instead of being ignored.
func TestDomainCatalogClosed(t *testing.T) {
	recognized := map[string]bool{}
	for _, family := range []struct {
		name   string
		fields []domainField
	}{
		{"mapping", mappingFields},
		{"artifact", artifactFields},
		{"vendor", vendorCommonFields},
		{"vendor", vendorVulnerableFields},
		{"vendor", vendorFixedFields},
		{"vendor", vendorExcludedFields},
	} {
		for _, field := range family.fields {
			recognized["product_v1."+family.name+"."+string(field)] = true
		}
	}
	if len(recognized) != 59 {
		t.Fatalf("the transcribed catalog has %d names, want 59", len(recognized))
	}
	longest := 0
	for name := range recognized {
		if len(name) > longest {
			longest = len(name)
		}
		if _, _, ok := recognizeDomainType(name); !ok {
			t.Fatalf("the catalog name %s is not recognized", name)
		}
	}
	if longest > maxDomainTypeBytes {
		t.Fatalf("the longest catalog name is %d bytes, over the grammar ceiling", longest)
	}

	rejected := []string{
		"product_v1.mapping.unknown_field",
		"product_v1.mapping.Method",
		"product_v1.mapping.method.extra",
		"product_v1.unknown.method",
		"product_v1.mapping.",
		"product_v1.mapping",
		"product_v1.mapping._leading",
		"product_v1.mapping.1leading",
		"product_v1.vendor.fix_membership_extra",
		"product_v1.mapping." + strings.Repeat("a", 33),
		"prisma_v1.vulnerability_id",
	}
	for _, value := range rejected {
		t.Run(value, func(t *testing.T) {
			if _, _, ok := recognizeDomainType(value); ok {
				t.Fatalf("%s must not be recognized", value)
			}
		})
	}

	t.Run("grammar ceiling is a grammar rule", func(t *testing.T) {
		// The 32-byte suffix is the grammatical maximum; a longer one is not a
		// valid field even before registration is considered.
		name := "product_v1.mapping." + strings.Repeat("a", 32)
		if !validDomainFieldGrammar(strings.Repeat("a", 32)) {
			t.Fatal("the 32-byte suffix must be grammatically valid")
		}
		if len(name) > maxDomainTypeBytes {
			t.Fatalf("the longest grammatical name is %d bytes, over the ceiling", len(name))
		}
		if _, _, ok := recognizeDomainType(name); ok {
			t.Fatal("a valid grammar with an unregistered suffix stays unknown")
		}
		if validDomainFieldGrammar(strings.Repeat("a", 33)) {
			t.Fatal("a 33-byte suffix must be refused by the grammar")
		}
	})

	t.Run("reserved prefix is detected", func(t *testing.T) {
		if !isDomainType("product_v1.mapping.method") {
			t.Fatal("the reserved prefix must be detected")
		}
		if isDomainType("prisma_v1.vulnerability_id") {
			t.Fatal("a foreign type must not carry the reserved prefix")
		}
	})

	t.Run("unknown name in the namespace blocks the affirmation", func(t *testing.T) {
		subject := baseSubject(t)
		bundle := productBundle(t,
			mappingItems(t, subject, containerA)...,
		)
		bundle.Evidence = append(bundle.Evidence,
			artifactItems(t, subject, containerA)...)
		bundle.Evidence = append(bundle.Evidence,
			vendorItems(t, subject, containerA, proofVulnerableBuild)...)
		bundle.Evidence = append(bundle.Evidence,
			syntheticDomainItem(subject, containerA, "product_v1.mapping.future_field", "x",
				mustSource(t, domainSourceMapping, "mapping source body\n"), domainLocatorMapping, contract.ProvenanceDerived))

		result, err := Evaluate(productRequest(t, bundle))
		if err != nil {
			t.Fatalf("an unknown domain name is uncertainty, not a rejection: %v", err)
		}
		if result.ProductStatus != contract.ProductUnderInvestigation {
			t.Fatalf("status = %s, want under_investigation", result.ProductStatus)
		}
		if !containsGlobalReason(result.Reasons, ReasonDomainProofUnsupported) {
			t.Fatalf("reasons = %v, want domain_proof_unsupported", result.Reasons)
		}
	})
}

// TestDomainRecordShapes is I-23: the three families and the three variants with
// their mandatory and exclusive fields, exact constants and correct confidence.
func TestDomainRecordShapes(t *testing.T) {
	subject := baseSubject(t)

	build := func(items ...contract.EvidenceItem) contract.Bundle {
		bundle := productBundle(t, mappingItems(t, subject, containerA)...)
		bundle.Evidence = append(bundle.Evidence, artifactItems(t, subject, containerA)...)
		bundle.Evidence = append(bundle.Evidence, items...)
		return bundle
	}

	for _, kind := range []proofKind{proofVulnerableBuild, proofFixedBuild, proofCodeExcludedBuild} {
		t.Run("complete "+string(kind), func(t *testing.T) {
			bundle := build(vendorItems(t, subject, containerA, kind)...)
			index := indexDomainRecords(bundle, baseTarget(t))
			decoded := decodeDomainRecords(index)
			if len(decoded.mappings) != 1 || len(decoded.artifacts) != 1 || len(decoded.vendors) != 1 {
				t.Fatalf("records = %d/%d/%d, want 1/1/1", len(decoded.mappings), len(decoded.artifacts), len(decoded.vendors))
			}
			if decoded.vendors[0].kind != kind {
				t.Fatalf("kind = %s, want %s", decoded.vendors[0].kind, kind)
			}
		})
	}

	broken := map[string]func([]contract.EvidenceItem) []contract.EvidenceItem{
		"missing field": func(items []contract.EvidenceItem) []contract.EvidenceItem {
			return items[1:]
		},
		"wrong method": func(items []contract.EvidenceItem) []contract.EvidenceItem {
			for index := range items {
				if items[index].Type == "product_v1.vendor.method" {
					replaceValue(&items[index], "other-method")
				}
			}
			return items
		},
		"wrong coverage": func(items []contract.EvidenceItem) []contract.EvidenceItem {
			for index := range items {
				if items[index].Type == "product_v1.vendor.coverage" {
					replaceValue(&items[index], "partial")
				}
			}
			return items
		},
		"foreign exclusive field": func(items []contract.EvidenceItem) []contract.EvidenceItem {
			return append(items, syntheticDomainItem(subject, containerA, "product_v1.vendor.fix_membership", fixMembershipIncluded,
				mustSource(t, domainSourceVendor, "advisory source body\n"), domainLocatorVendor, contract.ProvenanceObserved))
		},
		"wrong variant constant": func(items []contract.EvidenceItem) []contract.EvidenceItem {
			for index := range items {
				if items[index].Type == "product_v1.vendor.applicability" {
					replaceValue(&items[index], "conditional")
				}
			}
			return items
		},
		"wrong confidence": func(items []contract.EvidenceItem) []contract.EvidenceItem {
			for index := range items {
				if items[index].Type == "product_v1.vendor.method" {
					items[index].Confidence = contract.ProvenanceDerived
				}
			}
			return items
		},
		"bad epoch": func(items []contract.EvidenceItem) []contract.EvidenceItem {
			for index := range items {
				if items[index].Type == "product_v1.vendor.epoch" {
					replaceValue(&items[index], "01")
				}
			}
			return items
		},
	}
	for name, mutate := range broken {
		t.Run(name, func(t *testing.T) {
			bundle := build(mutate(vendorItems(t, subject, containerA, proofVulnerableBuild))...)
			index := indexDomainRecords(bundle, baseTarget(t))
			decoded := decodeDomainRecords(index)
			if len(decoded.vendors) != 0 {
				t.Fatalf("a record with %s must not be interpreted", name)
			}
			if index.itemCount == 0 {
				t.Fatal("the fixture must keep the domain items in the index")
			}
		})
	}
}

// TestDomainRecordProvenanceIsolation is I-24: the provenance tuple is the
// record boundary; fields are never completed across groups and identical
// duplicates keep every occurrence.
func TestDomainRecordProvenanceIsolation(t *testing.T) {
	subject := baseSubject(t)
	otherStamp := mustStamp(t, statusObservedAt)

	t.Run("different source keeps two records", func(t *testing.T) {
		bundle := productBundle(t, mappingItems(t, subject, containerA)...)
		extra := mappingItems(t, subject, containerA)
		for index := range extra {
			extra[index].Source = "mapping-2.json"
			extra[index].SourceHash = independentSourceHash("mapping 2 body\n")
		}
		bundle.Evidence = append(bundle.Evidence, extra...)
		index := indexDomainRecords(bundle, baseTarget(t))
		if len(index.records) != 2 {
			t.Fatalf("records = %d, want 2", len(index.records))
		}
	})

	t.Run("different source name alone keeps two records", func(t *testing.T) {
		// Only the source name changes, so a grouping key that ignored that member
		// while still comparing the hash would merge two different provenances.
		bundle := productBundle(t, mappingItems(t, subject, containerA)...)
		extra := mappingItems(t, subject, containerA)
		for index := range extra {
			extra[index].Source = "mapping-2.json"
		}
		bundle.Evidence = append(bundle.Evidence, extra...)
		index := indexDomainRecords(bundle, baseTarget(t))
		if len(index.records) != 2 {
			t.Fatalf("records = %d, want 2: the source name is part of the provenance key", len(index.records))
		}
	})

	t.Run("different source hash alone keeps two records", func(t *testing.T) {
		bundle := productBundle(t, mappingItems(t, subject, containerA)...)
		extra := mappingItems(t, subject, containerA)
		for index := range extra {
			extra[index].SourceHash = independentSourceHash("another mapping body\n")
		}
		bundle.Evidence = append(bundle.Evidence, extra...)
		index := indexDomainRecords(bundle, baseTarget(t))
		if len(index.records) != 2 {
			t.Fatalf("records = %d, want 2: the source hash is part of the provenance key", len(index.records))
		}
	})

	t.Run("different timestamp keeps two records", func(t *testing.T) {
		bundle := productBundle(t, mappingItems(t, subject, containerA)...)
		extra := mappingItems(t, subject, containerA)
		for index := range extra {
			extra[index].ObservedAt = stampPointer(otherStamp)
		}
		bundle.Evidence = append(bundle.Evidence, extra...)
		index := indexDomainRecords(bundle, baseTarget(t))
		if len(index.records) != 2 {
			t.Fatalf("records = %d, want 2", len(index.records))
		}
	})

	t.Run("different locator keeps two records", func(t *testing.T) {
		bundle := productBundle(t, mappingItems(t, subject, containerA)...)
		extra := mappingItems(t, subject, containerA)
		for index := range extra {
			extra[index].Locator = "records/mapping/1"
		}
		bundle.Evidence = append(bundle.Evidence, extra...)
		index := indexDomainRecords(bundle, baseTarget(t))
		if len(index.records) != 2 {
			t.Fatalf("records = %d, want 2", len(index.records))
		}
	})

	t.Run("identical duplicates stay in one record with every occurrence", func(t *testing.T) {
		bundle := productBundle(t, mappingItems(t, subject, containerA)...)
		bundle.Evidence = append(bundle.Evidence, mappingItems(t, subject, containerA)...)
		index := indexDomainRecords(bundle, baseTarget(t))
		if len(index.records) != 1 {
			t.Fatalf("records = %d, want 1", len(index.records))
		}
		if len(index.records[0].refs) != 28 {
			t.Fatalf("occurrences = %d, want 28", len(index.records[0].refs))
		}
	})

	t.Run("fields are never completed across groups", func(t *testing.T) {
		// One group carries only half of the mapping: the other group must not
		// fill the gap even though both describe the same source.
		half := mappingItems(t, subject, containerA)[:7]
		rest := mappingItems(t, subject, containerA)[7:]
		for index := range rest {
			rest[index].Locator = "records/mapping/1"
		}
		bundle := productBundle(t, half...)
		bundle.Evidence = append(bundle.Evidence, rest...)
		index := indexDomainRecords(bundle, baseTarget(t))
		decoded := decodeDomainRecords(index)
		if len(decoded.mappings) != 0 {
			t.Fatal("a split record must not be completed from another group")
		}
	})

	t.Run("two different values of one field destroy uniqueness", func(t *testing.T) {
		bundle := productBundle(t, mappingItems(t, subject, containerA)...)
		conflicting := mappingItems(t, subject, containerA)
		for index := range conflicting {
			if conflicting[index].Type == "product_v1.mapping.product_release" {
				replaceValue(&conflicting[index], "10")
			}
		}
		bundle.Evidence = append(bundle.Evidence, conflicting...)
		index := indexDomainRecords(bundle, baseTarget(t))
		decoded := decodeDomainRecords(index)
		if len(decoded.mappings) != 0 {
			t.Fatal("a record with two different values of one field is not interpretable")
		}
	})
}

// TestDomainValueHashIntegrity is I-26: every recognized domain value is verified
// against the SHA-256 of its exact bytes in the bundle phase, before the pack is
// admitted, and a mismatch rejects without result.
func TestDomainValueHashIntegrity(t *testing.T) {
	subject := baseSubject(t)
	build := func() contract.Bundle {
		bundle := productBundle(t, mappingItems(t, subject, containerA)...)
		bundle.Evidence = append(bundle.Evidence, artifactItems(t, subject, containerA)...)
		bundle.Evidence = append(bundle.Evidence, vendorItems(t, subject, containerA, proofVulnerableBuild)...)
		return bundle
	}

	t.Run("control", func(t *testing.T) {
		if _, err := Evaluate(productRequest(t, build())); err != nil {
			t.Fatalf("the control must evaluate: %v", err)
		}
	})

	t.Run("mismatch rejects in the bundle phase", func(t *testing.T) {
		bundle := build()
		for index := range bundle.Evidence {
			if bundle.Evidence[index].Type == "product_v1.mapping.component_id" {
				breakDomainValueHash(&bundle.Evidence[index], "zlib")
			}
		}
		request := productRequest(t, bundle)
		_, err := Evaluate(request)
		wantCode(t, err, CodeValueHashMismatch)
	})

	t.Run("mismatch wins over a wrong pack hash", func(t *testing.T) {
		bundle := build()
		for index := range bundle.Evidence {
			if bundle.Evidence[index].Type == "product_v1.mapping.component_id" {
				breakDomainValueHash(&bundle.Evidence[index], "zlib")
			}
		}
		request := productRequest(t, bundle)
		request.Admission.ExpectedPackHash = independentDocumentHash("another document")
		_, err := Evaluate(request)
		wantCode(t, err, CodeValueHashMismatch)
	})

	t.Run("mismatch wins over an expired pack", func(t *testing.T) {
		bundle := build()
		for index := range bundle.Evidence {
			if bundle.Evidence[index].Type == "product_v1.mapping.component_id" {
				breakDomainValueHash(&bundle.Evidence[index], "zlib")
			}
		}
		request := productRequest(t, bundle)
		request.Admission.EvaluatedAt = mustStamp(t, evaluatedAt.AddDate(1, 0, 0))
		_, err := Evaluate(request)
		wantCode(t, err, CodeValueHashMismatch)
	})

	t.Run("mismatch wins over the profile cross", func(t *testing.T) {
		bundle := build()
		bundle.SchemaVersion = "0.1"
		for index := range bundle.Evidence {
			if bundle.Evidence[index].Type == "product_v1.mapping.component_id" {
				breakDomainValueHash(&bundle.Evidence[index], "zlib")
			}
		}
		request := productRequest(t, bundle)
		_, err := Evaluate(request)
		wantCode(t, err, CodeValueHashMismatch)
	})

	t.Run("readiness does not verify domain types", func(t *testing.T) {
		// A readiness request carrying domain items with a broken value hash is
		// not hardened: readiness keeps its previous recognition.
		bundle := build()
		for index := range bundle.Evidence {
			if bundle.Evidence[index].Type == "product_v1.mapping.component_id" {
				breakDomainValueHash(&bundle.Evidence[index], "zlib")
			}
		}
		bundle.SchemaVersion = "0.1"
		legacy := baseRequest(t)
		legacy.Bundle = bundle
		legacy.ExpectedBundleHash = mustBundleHash(t, bundle)
		if _, err := Evaluate(legacy); err != nil {
			t.Fatalf("readiness must not verify domain value hashes: %v", err)
		}
	})
}

func mustSource(t *testing.T, name, body string) syntheticSource {
	t.Helper()
	return syntheticSource{name: name, hash: independentSourceHash(body), stamp: mustStamp(t, sourceObservedAt)}
}

// breakDomainValueHash changes the value while leaving the previous hash, which
// is exactly the integrity defect the bundle phase must reject.
func breakDomainValueHash(item *contract.EvidenceItem, value string) {
	item.Value = &value
}

func replaceValue(item *contract.EvidenceItem, value string) {
	hash := independentValueHash(value)
	item.Value = &value
	item.ValueHash = &hash
}

func suffixOf(index int) string {
	return string(rune('a'+index%26)) + string(rune('a'+(index/26)%26))
}

func containsGlobalReason(reasons []Reason, wanted Reason) bool {
	for _, reason := range reasons {
		if reason == wanted {
			return true
		}
	}
	return false
}
