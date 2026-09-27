package evaluator

import (
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/d4rpell/Ariadne/internal/rulepack"
	contract "github.com/d4rpell/Ariadne/pkg/evidence"
)

// TestEvaluateInputOwnership is I-19: the evaluation neither mutates nor aliases
// its input, a returned result keeps its meaning after the caller changes what it
// holds, and a later evaluation reads the current input instead of a cached one.
func TestEvaluateInputOwnership(t *testing.T) {
	request := baseRequest(t)
	snapshot := cloneBundle(request.Bundle)
	previous := rulepack.PreviousVersion{Version: 6, Hash: request.Admission.ExpectedPackHash}
	request.Admission.Previous = &previous

	result := evaluate(t, request)
	control := string(encodeResultDTO(t, result))

	if !reflect.DeepEqual(snapshot, request.Bundle) {
		t.Fatalf("the evaluation mutated the caller's bundle")
	}

	// Mutating everything the caller still holds must not reach the result.
	request.Bundle.Evidence[0].Value = strPointer(marker)
	request.Bundle.Provenance.Errors = []string{marker}
	previous.Version = 1
	previous.Hash = sourceHashPod
	if encoded := string(encodeResultDTO(t, result)); encoded != control {
		t.Fatalf("the result is aliased to caller state: %s", encoded)
	}
	if mustBundleHash(t, researchBundle(request)) != result.BundleHash {
		t.Fatalf("the result hash changed with the caller's state")
	}

	t.Run("a mutated input is not silently accepted", func(t *testing.T) {
		if _, err := Evaluate(request); err == nil {
			t.Fatalf("an input changed after its hash was taken must be rejected")
		}
	})
}

// researchBundle returns the fixture bundle with the control values restored, so
// the hash comparison above runs against a coherent bundle.
func researchBundle(request Request) contract.Bundle {
	restored := cloneBundle(request.Bundle)
	restored.Evidence[0].Value = strPointer(cveA)
	hash := independentValueHash(cveA)
	restored.Evidence[0].ValueHash = &hash
	restored.Provenance.Errors = []string{}
	return restored
}

// TestEvaluationIgnoresOperationalMetadata is I-22: metadata excluded from the
// projection may not change a semantic result, while an invalid value still
// causes a structural rejection.
func TestEvaluationIgnoresOperationalMetadata(t *testing.T) {
	request := baseRequest(t)
	linked := mutateRequest(t, request, func(bundle *contract.Bundle) {
		bundle.Provenance.Ruleset = contract.RulesetRef{
			Path:    "rules/",
			Hash:    contract.SourceHash(request.Admission.ExpectedPackHash),
			Version: "1",
		}
	})
	control := evaluate(t, linked)
	controlBytes := string(encodeResultDTO(t, control))

	changed := mutateRequest(t, linked, func(bundle *contract.Bundle) {
		bundle.Provenance.CollectorVersion = "9.9.9"
		bundle.Provenance.ParserVersion = "prisma-v1.99"
		bundle.Provenance.ArgvSanitized = []string{"import", sourceCSV, "--verbose"}
		bundle.Provenance.Budget = contract.Budget{WallClock: "5m", Requests: 10, Objects: 20, Bytes: 30}
		bundle.Provenance.Ruleset.Version = "2"
		started := mustStamp(t, evaluatedAt.Add(-time.Hour))
		ended := mustStamp(t, evaluatedAt.Add(-time.Minute))
		bundle.Provenance.StartedAt = &started
		bundle.Provenance.EndedAt = &ended
	})
	if changed.ExpectedBundleHash != linked.ExpectedBundleHash {
		t.Fatalf("the projection hash must not cover the operational metadata")
	}
	result := evaluate(t, changed)
	if encoded := string(encodeResultDTO(t, result)); encoded != controlBytes {
		t.Fatalf("excluded metadata changed the semantic result")
	}

	t.Run("invalid excluded metadata still rejects", func(t *testing.T) {
		broken := request
		broken.Bundle = cloneBundle(request.Bundle)
		broken.Bundle.Provenance.CollectorVersion = ""
		if _, err := Evaluate(broken); !IsCode(err, CodeInvalidBundle) {
			t.Fatalf("an invalid provenance field is a structural rejection, got %v", err)
		}
	})
}

// referenceCount is the budget the result must respect: warning references,
// candidate references and every repetition of an evidence reference across
// traces, counted the same way the engine counts them.
func referenceCount(result Result) int {
	total := len(result.WarningReferences) + len(result.EvidenceReferences)
	for _, candidate := range result.Candidates {
		total += len(candidate.EvidenceReferences)
	}
	for _, trace := range result.Rules {
		total += len(trace.EvidenceReferences)
		for _, check := range trace.Checks {
			total += len(check.EvidenceReferences)
		}
	}
	return total
}

// firstRuleOf reads the first rule of the control pack through the pack decoder,
// so the unit control traces the same shape an admitted pack carries.
func firstRuleOf(t *testing.T, request Request) rulepack.Rule {
	t.Helper()
	pack, err := rulepack.Decode(request.PackBytes)
	if err != nil {
		t.Fatalf("the control pack does not decode: %v", err)
	}
	return pack.Rules[0]
}

func generousLimits() bundleLimits {
	return bundleLimits{items: 1 << 40, images: 1 << 40, elements: 1 << 40, bytes: 1 << 40}
}

// fillerItem is one inert fact of another container: it counts for the input
// budgets and is never an operand of the target.
func fillerItem(bundle *contract.Bundle) contract.EvidenceItem {
	item := bundle.Evidence[0]
	item.Type = "prisma_v1.severity"
	item.Value = strPointer("filler")
	hash := independentValueHash("filler")
	item.ValueHash = &hash
	item.Scope.ContainerName = otherName
	return item
}

// TestEvaluationLimits is I-03 for the evaluation budgets: each reachable limit
// is exercised at its inclusive bound and at limit+1, and the limits that cannot
// be isolated carry their dominance argument written down instead of a fabricated
// control.
func TestEvaluationLimits(t *testing.T) {
	request := baseRequest(t)

	t.Run("pack bytes", func(t *testing.T) {
		oversized := request
		oversized.PackBytes = make([]byte, rulepack.MaxPackBytes+1)
		if _, err := Evaluate(oversized); !IsCode(err, CodeInputLimit) {
			t.Fatalf("expected input_limit, got %v", err)
		}
	})

	t.Run("target string", func(t *testing.T) {
		atLimit := request
		atLimit.Target.Locator = contract.SourceLocator(strings.Repeat("l", MaxTargetStringBytes))
		if _, err := Evaluate(atLimit); IsCode(err, CodeInputLimit) {
			t.Fatalf("a field of exactly the per-string limit must not be a limit failure")
		}
		overLimit := request
		overLimit.Target.Locator = contract.SourceLocator(strings.Repeat("l", MaxTargetStringBytes+1))
		if _, err := Evaluate(overLimit); !IsCode(err, CodeInputLimit) {
			t.Fatalf("expected input_limit at limit+1, got %v", err)
		}
	})

	t.Run("target total", func(t *testing.T) {
		// Four strings at the per-field limit plus the fixed ones land exactly on
		// the total. The bound is inclusive, one more byte rejects, and the
		// accepted case is a fully valid evaluation: the bundle follows the target
		// in subject, scope, source and locator, and its hash is recomputed.
		fixed := len(string(contract.ContainerRegular)) + len(cveA) + len(string(contract.SourceHash(sourceHashCSV)))
		locator := MaxTargetTotalBytes - 3*MaxTargetStringBytes - fixed
		if locator <= 0 || locator > MaxTargetStringBytes {
			t.Fatalf("the fixture cannot reach the total: %d", locator)
		}
		build := func(locatorBytes int) Request {
			candidate := request
			uid := contract.UID(strings.Repeat("u", MaxTargetStringBytes))
			container := contract.ContainerName(strings.Repeat("c", MaxTargetStringBytes))
			source := strings.Repeat("s", MaxTargetStringBytes)
			candidate.Target.SubjectUID = uid
			candidate.Target.ContainerClass = contract.ContainerRegular
			candidate.Target.ContainerName = container
			candidate.Target.Source = source
			candidate.Target.Locator = contract.SourceLocator(strings.Repeat("l", locatorBytes))
			candidate.Target.SourceHash = contract.SourceHash(sourceHashCSV)
			candidate.Bundle = cloneBundle(request.Bundle)
			candidate.Bundle.Subject.UID = uid
			for index := range candidate.Bundle.Evidence {
				candidate.Bundle.Evidence[index].Scope.SubjectUID = uid
				candidate.Bundle.Evidence[index].Scope.ContainerName = container
				candidate.Bundle.Evidence[index].Source = source
				candidate.Bundle.Evidence[index].Locator = candidate.Target.Locator
			}
			candidate.Bundle.Images[0].ContainerName = container
			candidate.ExpectedBundleHash = mustBundleHash(t, candidate.Bundle)
			return candidate
		}
		result := evaluate(t, build(locator))
		if !resultReason(result, ReasonRequirementsMissing) && !resultReason(result, ReasonChecksFailed) {
			// The evaluation must be a real one, not an early rejection.
			if result.ProductStatus != contract.ProductUnderInvestigation {
				t.Fatalf("the accepted case must produce a result: %+v", result)
			}
		}
		if _, err := Evaluate(build(locator + 1)); !IsCode(err, CodeInputLimit) {
			t.Fatalf("expected input_limit at limit+1, got %v", err)
		}
	})

	t.Run("evidence count", func(t *testing.T) {
		fill := func(bundle *contract.Bundle, count int) {
			item := fillerItem(bundle)
			for index := 0; index < count; index++ {
				bundle.Evidence = append(bundle.Evidence, item)
			}
		}
		grown := mutateRequest(t, request, func(bundle *contract.Bundle) {
			fill(bundle, MaxEvidenceItems-len(bundle.Evidence))
		})
		if usage := measureBundle(grown.Bundle, generousLimits()); usage.items != MaxEvidenceItems {
			t.Fatalf("fixture does not reach the limit: %d items", usage.items)
		}
		if _, err := Evaluate(grown); err != nil {
			t.Fatalf("a bundle of exactly the item limit must be accepted: %v", err)
		}
		overCount := mutateRequest(t, grown, func(bundle *contract.Bundle) {
			fill(bundle, 1)
		})
		if _, err := Evaluate(overCount); !IsCode(err, CodeInputLimit) {
			t.Fatalf("expected input_limit at limit+1, got %v", err)
		}
	})

	t.Run("images", func(t *testing.T) {
		fill := func(bundle *contract.Bundle, count int) {
			image := bundle.Images[0]
			image.ContainerName = otherName
			for index := 0; index < count; index++ {
				bundle.Images = append(bundle.Images, image)
			}
		}
		grown := mutateRequest(t, request, func(bundle *contract.Bundle) {
			fill(bundle, MaxImages-len(bundle.Images))
		})
		if usage := measureBundle(grown.Bundle, generousLimits()); usage.images != MaxImages {
			t.Fatalf("fixture does not reach the limit: %d images", usage.images)
		}
		if _, err := Evaluate(grown); err != nil {
			t.Fatalf("a bundle of exactly the image limit must be accepted: %v", err)
		}
		overCount := mutateRequest(t, grown, func(bundle *contract.Bundle) {
			fill(bundle, 1)
		})
		if _, err := Evaluate(overCount); !IsCode(err, CodeInputLimit) {
			t.Fatalf("expected input_limit at limit+1, got %v", err)
		}
	})

	t.Run("collection elements", func(t *testing.T) {
		usage := measureBundle(request.Bundle, generousLimits())
		fill := func(bundle *contract.Bundle, count int) {
			for index := 0; index < count; index++ {
				bundle.Provenance.ArgvSanitized = append(bundle.Provenance.ArgvSanitized, "")
			}
		}
		grown := mutateRequest(t, request, func(bundle *contract.Bundle) {
			fill(bundle, int(MaxCollectionElements-usage.elements))
		})
		if usage := measureBundle(grown.Bundle, generousLimits()); usage.elements != MaxCollectionElements {
			t.Fatalf("fixture does not reach the limit: %d elements", usage.elements)
		}
		if _, err := Evaluate(grown); err != nil {
			t.Fatalf("a bundle of exactly the element limit must be accepted: %v", err)
		}
		overCount := mutateRequest(t, grown, func(bundle *contract.Bundle) {
			fill(bundle, 1)
		})
		if _, err := Evaluate(overCount); !IsCode(err, CodeInputLimit) {
			t.Fatalf("expected input_limit at limit+1, got %v", err)
		}
	})

	t.Run("bundle string bytes", func(t *testing.T) {
		// The inclusive bound is proven at unit level, where the limit is a
		// parameter, and the ratified limit is proven end to end on the field the
		// review named: an operational string excluded from the projection hash
		// still counts for the admission budget.
		bundle := cloneBundle(request.Bundle)
		bundle.Provenance.CollectorVersion = strings.Repeat("c", 1000)
		exact := measureBundle(cloneBundle(bundle), generousLimits()).bytes
		small := bundleLimits{items: 1 << 20, images: 1 << 20, elements: 1 << 20, bytes: exact}
		if usage := measureBundle(cloneBundle(bundle), small); usage.overBytes {
			t.Fatalf("exactly the byte limit must not be over it: %d", usage.bytes)
		}
		grown := cloneBundle(bundle)
		grown.Provenance.CollectorVersion += "c"
		if usage := measureBundle(grown, small); !usage.overBytes {
			t.Fatalf("limit+1 must be over it: %d", usage.bytes)
		}

		overLimit := mutateRequest(t, request, func(bundle *contract.Bundle) {
			bundle.Provenance.Budget.WallClock = strings.Repeat("w", MaxBundleStringBytes+1)
		})
		if _, err := Evaluate(overLimit); !IsCode(err, CodeInputLimit) {
			t.Fatalf("expected input_limit for an operational string, got %v", err)
		}
	})

	// boundary probes the largest count of added references that the engine
	// still accepts: the budget counts every materialized collection, so the
	// boundary is measured instead of assumed from one internal arithmetic.
	boundary := func(t *testing.T, fill func(*contract.Bundle, int), ceiling int) int {
		t.Helper()
		fits := func(count int) error {
			candidate := mutateRequest(t, request, func(bundle *contract.Bundle) {
				fill(bundle, count)
			})
			_, err := Evaluate(candidate)
			return err
		}
		if err := fits(0); err != nil {
			t.Fatalf("the fixture itself does not evaluate: %v", err)
		}
		low, high := 0, ceiling
		for low < high {
			middle := (low + high + 1) / 2
			if fits(middle) == nil {
				low = middle
			} else {
				high = middle - 1
			}
		}
		if err := fits(low); err != nil {
			t.Fatalf("the boundary count must be accepted: %v", err)
		}
		if err := fits(low + 1); !IsCode(err, CodeEvaluationLimit) {
			t.Fatalf("limit+1 must be rejected, got %v", err)
		}
		return low
	}

	t.Run("result references", func(t *testing.T) {
		fill := func(bundle *contract.Bundle, count int) {
			var source contract.EvidenceItem
			for _, item := range bundle.Evidence {
				if item.Type == "prisma_v1.fix_status" {
					source = item
				}
			}
			for index := 0; index < count; index++ {
				bundle.Evidence = append(bundle.Evidence, source)
			}
		}
		found := boundary(t, fill, MaxResultReferences)
		if found == 0 || found == MaxResultReferences {
			t.Fatalf("the evidence boundary was not bracketed by the budget: %d", found)
		}
		// The oracle counts the occurrences the Result stores, independently of the
		// engine: at the boundary one more copy would cross the limit.
		total := referenceCount(evaluate(t, mutateRequest(t, request, func(bundle *contract.Bundle) { fill(bundle, found) })))
		previous := referenceCount(evaluate(t, mutateRequest(t, request, func(bundle *contract.Bundle) { fill(bundle, found-1) })))
		step := total - previous
		if step <= 0 || total > MaxResultReferences || total+step <= MaxResultReferences {
			t.Fatalf("the boundary is not where the contract puts it: %d + %d", total, step)
		}
	})

	t.Run("warning references fill the budget exactly", func(t *testing.T) {
		baseline := referenceCount(evaluate(t, request))
		fill := func(bundle *contract.Bundle, count int) {
			bundle.Provenance.Warnings = make([]contract.Warning, 0, count)
			for index := 0; index < count; index++ {
				bundle.Provenance.Warnings = append(bundle.Provenance.Warnings, contract.Warning{
					Code: "redaction_applied", Class: contract.WarningInformational, Message: "w",
				})
			}
		}
		atLimit := mutateRequest(t, request, func(bundle *contract.Bundle) {
			fill(bundle, MaxResultReferences-baseline)
		})
		result := evaluate(t, atLimit)
		if got := referenceCount(result); got != MaxResultReferences {
			t.Fatalf("one warning is one occurrence: %d", got)
		}
		over := mutateRequest(t, atLimit, func(bundle *contract.Bundle) {
			bundle.Provenance.Warnings = append(bundle.Provenance.Warnings, contract.Warning{
				Code: "redaction_applied", Class: contract.WarningInformational, Message: "w",
			})
		})
		if _, err := Evaluate(over); !IsCode(err, CodeEvaluationLimit) {
			t.Fatalf("expected evaluation_limit at 100.001 references, got %v", err)
		}
	})

	t.Run("repeated checks are counted as occurrences", func(t *testing.T) {
		// The counterexample of the independent review: one rule with three checks
		// over the same field. Every check repeats its references in the result, so
		// the contractual total is 30.000 + 40.001 + 40.001 = 110.002 and must be
		// rejected, while a smaller bundle stays inside the budget.
		grow := func(bundle *contract.Bundle, count int) {
			var source contract.EvidenceItem
			for _, item := range bundle.Evidence {
				if item.Type == "prisma_v1.fix_status" {
					source = item
				}
			}
			for index := 0; index < count; index++ {
				bundle.Evidence = append(bundle.Evidence, source)
			}
		}
		rules := ruleJSON("rule.a", cveA,
			`{"check_id":"check.1","predicate":"finding_field_present","params":{"field":"fix_status"}},`+
				`{"check_id":"check.2","predicate":"finding_field_equals","params":{"field":"fix_status","value":"fixed"}},`+
				`{"check_id":"check.3","predicate":"finding_field_present","params":{"field":"fix_status"}}`,
			`"bundle.complete","finding.row","finding.fix_status"`)

		inside := packWith(t, mutateRequest(t, request, func(bundle *contract.Bundle) { grow(bundle, 8000) }), rules)
		result := evaluate(t, inside)
		if got := referenceCount(result); got >= MaxResultReferences {
			t.Fatalf("the control must stay inside the budget: %d", got)
		}

		over := packWith(t, mutateRequest(t, request, func(bundle *contract.Bundle) { grow(bundle, 10000) }), rules)
		if _, err := Evaluate(over); !IsCode(err, CodeEvaluationLimit) {
			t.Fatalf("repeated checks must be counted as occurrences, got %v", err)
		}
	})

	t.Run("storage never grows past the budget", func(t *testing.T) {
		// The temporal condition of ADR-0013 §5.4: an occurrence is admitted
		// before it is stored. With the budget exhausted, neither the warning
		// builder nor a check trace stores anything, even though the memoized
		// requirement already carries its references.
		exhausted := &referenceBudget{used: MaxResultReferences}
		bundle := cloneBundle(request.Bundle)
		bundle.Provenance.Warnings = make([]contract.Warning, 0, 10)
		for index := 0; index < 10; index++ {
			bundle.Provenance.Warnings = append(bundle.Provenance.Warnings, contract.Warning{
				Code: "redaction_applied", Class: contract.WarningInformational, Message: "w",
			})
		}
		references, _ := warningState(bundle, request.Target, exhausted)
		if len(references) != 0 || !exhausted.over {
			t.Fatalf("the warning builder stored references past the budget: %d", len(references))
		}

		resolver := newResolver(bundle, request.Target, evaluatedAt, exhausted)
		facts := newFactSet(resolver, &domainAssessment{})
		outcome := facts.resolve(rulepack.RequirementFindingRow)
		if len(outcome.refs) == 0 {
			t.Fatalf("the fixture must substantiate the row requirement")
		}
		check := rulepack.Check{CheckID: "check.one", Predicate: rulepack.PredicateFindingFieldPresent, Params: rulepack.Params{Field: "fix_status", FieldSet: true}}
		trace := runCheck(check, facts)
		if len(trace.EvidenceReferences) != 0 {
			t.Fatalf("a check stored references past the budget: %d", len(trace.EvidenceReferences))
		}

		// The platform predicate has two return paths that also store an
		// occurrence of the memoized requirement: both are admitted here.
		for _, predicate := range []rulepack.Check{
			{CheckID: "check.platform", Predicate: rulepack.PredicateImagePlatformKnown, Params: rulepack.Params{OS: "linux", OSSet: true, Architecture: "amd64", ArchitectureSet: true}},
			{CheckID: "check.digest", Predicate: rulepack.PredicateImageDigestBound},
		} {
			platform := runCheck(predicate, facts)
			if len(platform.EvidenceReferences) != 0 {
				t.Fatalf("the %s check stored references past the budget: %d", predicate.Predicate, len(platform.EvidenceReferences))
			}
		}
	})

	t.Run("collections after an exceeded byte budget are not visited", func(t *testing.T) {
		// Every collection of the inventory is enlarged one at a time: once the
		// byte budget is spent, no loop may keep touching its elements.
		small := bundleLimits{items: 1 << 20, images: 1 << 20, elements: 1 << 20, bytes: 4}
		before := measureBundle(cloneBundle(request.Bundle), small)
		if !before.overBytes {
			t.Fatalf("the fixture must exceed the tiny byte budget")
		}
		enlarge := []struct {
			name   string
			change func(*contract.Bundle)
		}{
			{"classes", func(b *contract.Bundle) {
				b.ObservedContainerClasses = append(b.ObservedContainerClasses, contract.ContainerClass("x"))
			}},
			{"argv", func(b *contract.Bundle) { b.Provenance.ArgvSanitized = append(b.Provenance.ArgvSanitized, "x") }},
			{"inputs", func(b *contract.Bundle) {
				b.Provenance.Inputs = append(b.Provenance.Inputs, contract.InputRef{Path: "x", Hash: contract.SourceHash(sourceHashPod)})
			}},
			{"namespaces", func(b *contract.Bundle) {
				b.Provenance.APIScope.Namespaces = append(b.Provenance.APIScope.Namespaces, contract.Namespace("x"))
			}},
			{"verbs", func(b *contract.Bundle) { b.Provenance.APIScope.Verbs = append(b.Provenance.APIScope.Verbs, "x") }},
			{"resources", func(b *contract.Bundle) {
				b.Provenance.APIScope.Resources = append(b.Provenance.APIScope.Resources, "x")
			}},
			{"warnings", func(b *contract.Bundle) {
				b.Provenance.Warnings = append(b.Provenance.Warnings, contract.Warning{Message: "x"})
			}},
			{"errors", func(b *contract.Bundle) { b.Provenance.Errors = append(b.Provenance.Errors, "x") }},
		}
		for _, testCase := range enlarge {
			t.Run(testCase.name, func(t *testing.T) {
				grown := cloneBundle(request.Bundle)
				testCase.change(&grown)
				usage := measureBundle(grown, small)
				if !usage.overBytes {
					t.Fatalf("the grown bundle must still exceed the byte budget")
				}
				if usage.inspected != before.inspected {
					t.Fatalf("the walk touched a collection past the budget: %d vs %d", usage.inspected, before.inspected)
				}
			})
		}
	})

	t.Run("rejected bundle is not walked further", func(t *testing.T) {
		// A bundle already over a count budget must not be walked by the string
		// inventory: the walk is observable through the inspected counter.
		crowded := func(limits bundleLimits) bundleUsage {
			bundle := cloneBundle(request.Bundle)
			shared := make([]contract.Warning, 100000)
			for index := range shared {
				shared[index] = contract.Warning{Code: "redaction_applied", Class: contract.WarningInformational, Message: "w"}
			}
			item := bundle.Evidence[0]
			item.Warnings = shared
			for index := 0; index < 10000; index++ {
				bundle.Evidence = append(bundle.Evidence, item)
			}
			return measureBundle(bundle, limits)
		}
		if usage := crowded(generousLimits()); usage.inspected == 0 {
			t.Fatalf("the control must inspect strings when nothing is over")
		}
		usage := crowded(ratifiedBundleLimits())
		if !usage.overElements {
			t.Fatalf("the fixture must exceed the element budget: %+v", usage)
		}
		if usage.inspected != 0 {
			t.Fatalf("a rejected bundle was walked anyway: %d strings inspected", usage.inspected)
		}
	})

	t.Run("string inventory covers every field", func(t *testing.T) {
		const probe = "0123456789"
		changes := []struct {
			name   string
			change func(*contract.Bundle)
		}{
			{"schema_version", func(b *contract.Bundle) { b.SchemaVersion += probe }},
			{"subject.cluster_alias", func(b *contract.Bundle) { b.Subject.ClusterAlias += probe }},
			{"subject.namespace", func(b *contract.Bundle) { b.Subject.Namespace += probe }},
			{"subject.kind", func(b *contract.Bundle) { b.Subject.Kind += probe }},
			{"subject.name", func(b *contract.Bundle) { b.Subject.Name += probe }},
			{"subject.uid", func(b *contract.Bundle) { b.Subject.UID += probe }},
			{"subject.owner_chain", func(b *contract.Bundle) { b.Subject.OwnerChain += probe }},
			{"observed_container_classes", func(b *contract.Bundle) {
				b.ObservedContainerClasses = append(b.ObservedContainerClasses, contract.ContainerClass(probe))
			}},
			{"images.container_class", func(b *contract.Bundle) { b.Images[0].ContainerClass += contract.ContainerClass(probe) }},
			{"images.container_name", func(b *contract.Bundle) { b.Images[0].ContainerName += probe }},
			{"images.requested_image", func(b *contract.Bundle) { *b.Images[0].RequestedImage += probe }},
			{"images.raw_image_id", func(b *contract.Bundle) { *b.Images[0].RawImageID += probe }},
			{"images.normalized_digest", func(b *contract.Bundle) { *b.Images[0].NormalizedDigest += probe }},
			{"images.platform.os", func(b *contract.Bundle) { b.Images[0].Platform.OS += probe }},
			{"images.platform.architecture", func(b *contract.Bundle) { b.Images[0].Platform.Architecture += probe }},
			{"images.platform.status", func(b *contract.Bundle) { b.Images[0].Platform.Status += contract.PlatformStatus(probe) }},
			{"evidence.type", func(b *contract.Bundle) { b.Evidence[0].Type += probe }},
			{"evidence.source", func(b *contract.Bundle) { b.Evidence[0].Source += probe }},
			{"evidence.source_hash", func(b *contract.Bundle) { b.Evidence[0].SourceHash += contract.SourceHash(probe) }},
			{"evidence.locator", func(b *contract.Bundle) { b.Evidence[0].Locator += contract.SourceLocator(probe) }},
			{"evidence.value", func(b *contract.Bundle) { *b.Evidence[0].Value += probe }},
			{"evidence.value_hash", func(b *contract.Bundle) { *b.Evidence[0].ValueHash += contract.ValueHash(probe) }},
			{"evidence.confidence", func(b *contract.Bundle) { b.Evidence[0].Confidence += contract.ProvenanceKind(probe) }},
			{"evidence.scope.subject_uid", func(b *contract.Bundle) { b.Evidence[0].Scope.SubjectUID += probe }},
			{"evidence.scope.container_name", func(b *contract.Bundle) { b.Evidence[0].Scope.ContainerName += probe }},
			{"evidence.warnings.message", func(b *contract.Bundle) {
				b.Evidence[0].Warnings = append(b.Evidence[0].Warnings, contract.Warning{Message: probe})
			}},
			{"provenance.collector_version", func(b *contract.Bundle) { b.Provenance.CollectorVersion += probe }},
			{"provenance.parser_version", func(b *contract.Bundle) { b.Provenance.ParserVersion += probe }},
			{"provenance.ruleset.path", func(b *contract.Bundle) { b.Provenance.Ruleset.Path += probe }},
			{"provenance.ruleset.hash", func(b *contract.Bundle) { b.Provenance.Ruleset.Hash += contract.SourceHash(probe) }},
			{"provenance.ruleset.version", func(b *contract.Bundle) { b.Provenance.Ruleset.Version += probe }},
			{"provenance.argv_sanitized", func(b *contract.Bundle) { b.Provenance.ArgvSanitized = append(b.Provenance.ArgvSanitized, probe) }},
			{"provenance.inputs.path", func(b *contract.Bundle) { b.Provenance.Inputs[0].Path += probe }},
			{"provenance.inputs.hash", func(b *contract.Bundle) { b.Provenance.Inputs[0].Hash += contract.SourceHash(probe) }},
			{"provenance.api_scope.namespaces", func(b *contract.Bundle) {
				b.Provenance.APIScope.Namespaces = append(b.Provenance.APIScope.Namespaces, contract.Namespace(probe))
			}},
			{"provenance.api_scope.verbs", func(b *contract.Bundle) { b.Provenance.APIScope.Verbs = append(b.Provenance.APIScope.Verbs, probe) }},
			{"provenance.api_scope.resources", func(b *contract.Bundle) {
				b.Provenance.APIScope.Resources = append(b.Provenance.APIScope.Resources, probe)
			}},
			{"provenance.budget.wall_clock", func(b *contract.Bundle) { b.Provenance.Budget.WallClock += probe }},
			{"provenance.coverage.method", func(b *contract.Bundle) { b.Provenance.Coverage.Method += contract.CoverageMethod(probe) }},
			{"provenance.coverage.termination", func(b *contract.Bundle) { b.Provenance.Coverage.Termination += contract.CoverageTermination(probe) }},
			{"provenance.completeness", func(b *contract.Bundle) { b.Provenance.Completeness += contract.Completeness(probe) }},
			{"provenance.consistency", func(b *contract.Bundle) { b.Provenance.Consistency += contract.Consistency(probe) }},
			{"provenance.redaction_policy", func(b *contract.Bundle) { b.Provenance.RedactionPolicy += probe }},
			{"provenance.warnings.message", func(b *contract.Bundle) {
				b.Provenance.Warnings = append(b.Provenance.Warnings, contract.Warning{Message: probe})
			}},
			{"evidence.warnings.code", func(b *contract.Bundle) {
				b.Evidence[0].Warnings = append(b.Evidence[0].Warnings, contract.Warning{Code: probe})
			}},
			{"evidence.warnings.class", func(b *contract.Bundle) {
				b.Evidence[0].Warnings = append(b.Evidence[0].Warnings, contract.Warning{Class: contract.WarningClass(probe)})
			}},
			{"provenance.warnings.code", func(b *contract.Bundle) {
				b.Provenance.Warnings = append(b.Provenance.Warnings, contract.Warning{Code: probe})
			}},
			{"provenance.warnings.class", func(b *contract.Bundle) {
				b.Provenance.Warnings = append(b.Provenance.Warnings, contract.Warning{Class: contract.WarningClass(probe)})
			}},
			{"provenance.errors", func(b *contract.Bundle) { b.Provenance.Errors = []string{probe} }},
		}
		for _, testCase := range changes {
			t.Run(testCase.name, func(t *testing.T) {
				bundle := cloneBundle(request.Bundle)
				before := measureBundle(bundle, generousLimits()).bytes
				testCase.change(&bundle)
				after := measureBundle(bundle, generousLimits()).bytes
				if after != before+uint64(len(probe)) {
					t.Fatalf("%s is not counted: %d -> %d", testCase.name, before, after)
				}
			})
		}
	})

	t.Run("candidate budget boundary", func(t *testing.T) {
		// A matched rule queries the complete record (1), the row (1) and the image
		// group twice, because its check reads it again. The scope group is sized
		// so that five rules land on the budget exactly: the calibration counts the
		// scope items the fixture already carries instead of hardcoding them, so
		// adding a fact to the control cannot silently move the boundary. The
		// budget is inclusive and the first reachable excess is rejected.
		scopeCarried := 0
		for _, item := range request.Bundle.Evidence {
			if item.Scope.SubjectUID == request.Target.SubjectUID && item.Scope.ContainerName == containerA {
				scopeCarried++
			}
		}
		if len(request.Bundle.Images) != 1 {
			t.Fatalf("the fixture must carry one image, found %d", len(request.Bundle.Images))
		}
		// per rule: complete (1) + row (1) + the image group read twice (the
		// requirement and the check), each read charging the scope items plus the
		// image identity, so five rules cost 5 × (2 + 2×(scope + images)).
		const rules = 5
		images := len(request.Bundle.Images)
		base := 2 + 2*images
		scopeTotal := (MaxCandidateBudget/rules - base) / 2
		if charged := rules * (base + 2*scopeTotal); charged != MaxCandidateBudget {
			t.Fatalf("the calibration is not exact: the boundary would sit at %d", charged)
		}
		for _, testCase := range []struct {
			name    string
			scope   int
			wantErr bool
		}{
			{name: "exactly at the budget", scope: scopeTotal, wantErr: false},
			{name: "over the budget", scope: scopeTotal + 1, wantErr: true},
		} {
			t.Run(testCase.name, func(t *testing.T) {
				target := testCase.scope - scopeCarried
				if target < 0 {
					t.Fatalf("the fixture already exceeds the target scope: %d > %d", scopeCarried, testCase.scope)
				}
				grow := func(bundle *contract.Bundle) {
					item := fillerItem(bundle)
					item.Scope.ContainerName = containerA
					item.Locator = contract.SourceLocator("record/99/bytes/0-40")
					for index := 0; index < target; index++ {
						bundle.Evidence = append(bundle.Evidence, item)
					}
				}
				rules := []string{}
				for index := 0; index < 5; index++ {
					rules = append(rules, ruleJSON("rule."+strconv.Itoa(index), cveA,
						`{"check_id":"check.`+strconv.Itoa(index)+`","predicate":"image_digest_bound","params":{}}`,
						`"bundle.complete","finding.row","image.bound_digest"`))
				}
				grown := packWith(t, mutateRequest(t, request, func(bundle *contract.Bundle) { grow(bundle) }), strings.Join(rules, ","))
				_, err := Evaluate(grown)
				if testCase.wantErr {
					if !IsCode(err, CodeEvaluationLimit) {
						t.Fatalf("expected evaluation_limit at the first excess, got %v", err)
					}
					return
				}
				if err != nil {
					t.Fatalf("exactly the candidate budget must be admitted: %v", err)
				}
			})
		}
	})

	t.Run("every evaluation error returns a zero result", func(t *testing.T) {
		brokenBundle := request
		brokenBundle.Bundle = cloneBundle(request.Bundle)
		brokenBundle.Bundle.SchemaVersion = "9.9"
		failedValue := mutateRequest(t, request, func(bundle *contract.Bundle) {
			bundle.Evidence[3].Value = strPointer("not_fixed")
		})
		linked := mutateRequest(t, request, func(bundle *contract.Bundle) {
			bundle.Provenance.Ruleset = contract.RulesetRef{Path: "rules/", Hash: contract.SourceHash(sourceHashPod), Version: "1"}
		})
		expired := request
		expired.Admission.EvaluatedAt = mustStamp(t, evaluatedAt.AddDate(1, 0, 0))
		cases := []struct {
			name    string
			request Request
		}{
			{"input_limit", request},
			{"invalid_target", func() Request { broken := request; broken.Target.Source = "x "; return broken }()},
			{"invalid_bundle", brokenBundle},
			{"bundle_hash_mismatch", func() Request {
				broken := request
				broken.ExpectedBundleHash = independentDocumentHash("other")
				return broken
			}()},
			{"value_hash_mismatch", failedValue},
			{"ruleset_mismatch", linked},
			{"pack_expired", expired},
		}
		for _, testCase := range cases {
			t.Run(testCase.name, func(t *testing.T) {
				candidate := testCase.request
				if testCase.name == "input_limit" {
					candidate.PackBytes = make([]byte, rulepack.MaxPackBytes+1)
				}
				result, err := Evaluate(candidate)
				if err == nil {
					t.Fatalf("the fixture must fail")
				}
				if !reflect.DeepEqual(result, Result{}) {
					t.Fatalf("a failed evaluation must return the zero result: %+v", result)
				}
			})
		}
	})

	t.Run("pack bytes are not aliased", func(t *testing.T) {
		mutable := append([]byte{}, request.PackBytes...)
		candidate := request
		candidate.PackBytes = mutable
		result := evaluate(t, candidate)
		control := string(encodeResultDTO(t, result))
		for index := range mutable {
			mutable[index] = 'x'
		}
		if encoded := string(encodeResultDTO(t, result)); encoded != control {
			t.Fatalf("the result is aliased to the pack buffer")
		}
		if _, err := Evaluate(candidate); err == nil {
			t.Fatalf("a mutated pack buffer must not be admitted")
		}
	})

	t.Run("admission context budget is dominated", func(t *testing.T) {
		domains := rulepack.MaxIDBytes + 2*(7+64)
		if domains >= MaxContextTotalBytes {
			t.Fatalf("the dominance argument no longer holds: %d bytes", domains)
		}
	})
}
