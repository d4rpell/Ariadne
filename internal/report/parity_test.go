package report

import (
	"bytes"
	"encoding/json"
	"fmt"
	"html"
	"os"
	"reflect"
	"regexp"
	"strings"
	"testing"

	"github.com/d4rpell/Ariadne/internal/evaluator"
	canonical "github.com/d4rpell/Ariadne/internal/evidence"
	"github.com/d4rpell/Ariadne/internal/rulepack"
	contract "github.com/d4rpell/Ariadne/pkg/evidence"
)

var (
	htmlIDPattern      = regexp.MustCompile(`\bid="([^"]+)"`)
	htmlRowPattern     = regexp.MustCompile(`<tr id="(e-[0-9]+)"><td><code>e-[0-9]+</code></td><td><code>([0-9]+)</code></td>`)
	htmlEvidenceLink   = regexp.MustCompile(`<a href="#(e-[0-9]+)"><code>item_index ([0-9]+)</code></a>`)
	htmlWarningRefItem = regexp.MustCompile(`<code>(provenance|evidence) evidence_index (-?[0-9]+) warning_index (-?[0-9]+)</code>`)
	htmlWarningRefRow  = regexp.MustCompile(`<tr id="(w-[0-9]+)"><td><code>w-[0-9]+</code></td><td><code>(provenance|evidence)</code></td><td><code>(-?[0-9]+)</code></td><td><code>(-?[0-9]+)</code></td>`)
)

// TestHTMLReproducesEveryDTOValue pins the parity rule of F0 §6: the page is a
// faithful reproduction of the whole DTO, not a summary. Every leaf the JSON
// report carries must appear inside a dynamic emission of the page — a value the
// page dropped is presentation loss, and static prose cannot mask it, because
// only the contents of the template's action elements are searched.
func TestHTMLReproducesEveryDTOValue(t *testing.T) {
	for _, slug := range []string{"F09-unmapped-redhat-package", "F10-redhat-backport", "F13-contradictory-evidence"} {
		t.Run(slug, func(t *testing.T) {
			result, bundle := loadEvaluated(t, slug)
			report := mustBuild(t, result, bundle)
			document, err := JSON(report)
			if err != nil {
				t.Fatalf("JSON: %v", err)
			}
			page, err := HTML(report)
			if err != nil {
				t.Fatalf("HTML: %v", err)
			}
			emitted := emittedValues(string(page))
			if len(emitted) == 0 {
				t.Fatalf("the page carries no dynamic value")
			}

			decoder := json.NewDecoder(bytes.NewReader(document))
			decoder.UseNumber()
			var decoded any
			if err := decoder.Decode(&decoded); err != nil {
				t.Fatalf("JSON does not decode: %v", err)
			}
			var missing []string
			walkLeaves(decoded, func(leaf string) {
				if leaf == "" || containedIn(emitted, leaf) {
					return
				}
				missing = append(missing, leaf)
			})
			if len(missing) > 0 {
				t.Errorf("the HTML page drops %d values of the DTO: %v", len(missing), missing)
			}
		})
	}
}

var codeElementPattern = regexp.MustCompile(`<code>(.*?)</code>`)

// emittedValues returns the decoded contents of every dynamic element of the
// page. The template emits data only through these elements, so a value absent
// from the set is absent from the presentation and not merely spelled
// differently by the surrounding prose.
func emittedValues(document string) []string {
	matches := codeElementPattern.FindAllStringSubmatch(document, -1)
	values := make([]string, 0, len(matches))
	for _, match := range matches {
		values = append(values, html.UnescapeString(match[1]))
	}
	return values
}

// containedIn reports whether one value was emitted somewhere in the page. It is
// used by the whole-document controls, where the question is only whether the
// value reached the presentation, and the exact-element rule of the section
// controls is not what is being asked.
func containedIn(emitted []string, value string) bool {
	for _, element := range emitted {
		if element == value || strings.Contains(element, value) {
			return true
		}
	}
	return false
}

// emittedExactly reports whether one dynamic element carries exactly this value.
// The section controls use it instead of a substring match: an index must not
// pass because a longer element happens to contain it, so the element and the
// value have to be equal.
func emittedExactly(emitted []string, value string) bool {
	for _, element := range emitted {
		if element == value {
			return true
		}
	}
	return false
}

// TestHTMLShowsEachProjectedField pins, section by section, the values a partial
// view could drop: the global references, the rule and check references, the
// candidate references, the declared warning references, the source pins, the
// admission pair and the whole catalogs. Each case builds a result in which the
// value can only reach the page through that one section — the other collections
// are emptied — so a view that omits the section cannot pass by coincidence.
func TestHTMLShowsEachProjectedField(t *testing.T) {
	const markerHash = "sha256:1111111111111111111111111111111111111111111111111111111111111111"
	cases := []struct {
		name  string
		build func(result evaluator.Result) evaluator.Result
		// jsonMarker must appear in the encoded report, which proves the case
		// carries the value at all.
		jsonMarker string
		// pageMarker is matched as the exact content of one dynamic element, never
		// as a substring: a short index must not pass because a longer element
		// happens to contain it.
		pageMarker string
		// pageCheck is the assertion for values the page states outside an element
		// (an explicit null in a table cell, an absence sentence). Exactly one of
		// pageMarker and pageCheck is set.
		pageCheck func(t *testing.T, page string)
	}{
		{
			name: "global evidence references",
			build: func(result evaluator.Result) evaluator.Result {
				isolated := withoutReferences(result)
				isolated.Reasons = nil
				isolated.EvidenceReferences = []evaluator.EvidenceReference{{ItemIndex: 7}}
				return isolated
			},
			jsonMarker: `"item_index":7`,
			pageMarker: "item_index 7",
		},
		{
			name: "rule evidence references",
			build: func(result evaluator.Result) evaluator.Result {
				isolated := withoutReferences(result)
				isolated.Reasons = nil
				isolated.Rules = []evaluator.RuleTrace{{
					RuleID:             "rule.marker",
					State:              evaluator.RuleChecked,
					EvidenceReferences: []evaluator.EvidenceReference{{ItemIndex: 8}},
				}}
				return isolated
			},
			jsonMarker: `"item_index":8`,
			pageMarker: "item_index 8",
		},
		{
			name: "check evidence references",
			build: func(result evaluator.Result) evaluator.Result {
				isolated := withoutReferences(result)
				isolated.Reasons = nil
				isolated.Rules = []evaluator.RuleTrace{{
					RuleID: "rule.marker",
					State:  evaluator.RuleChecked,
					Checks: []evaluator.CheckTrace{{
						CheckID:            "check.marker",
						Outcome:            evaluator.OutcomePass,
						EvidenceReferences: []evaluator.EvidenceReference{{ItemIndex: 9}},
					}},
				}}
				return isolated
			},
			jsonMarker: `"item_index":9`,
			pageMarker: "item_index 9",
		},
		{
			name: "candidate evidence references",
			build: func(result evaluator.Result) evaluator.Result {
				isolated := withoutReferences(result)
				isolated.Reasons = nil
				isolated.Candidates = []evaluator.Candidate{{
					RuleID:             "candidate.marker",
					ProductStatus:      contract.ProductFixed,
					EvidenceReferences: []evaluator.EvidenceReference{{ItemIndex: 10}},
				}}
				return isolated
			},
			jsonMarker: `"item_index":10`,
			pageMarker: "item_index 10",
		},
		{
			name: "candidate identity",
			build: func(result evaluator.Result) evaluator.Result {
				isolated := withoutReferences(result)
				isolated.Reasons = nil
				isolated.Candidates = []evaluator.Candidate{{
					RuleID:        "candidate.marker",
					ProductStatus: contract.ProductNotAffected,
				}}
				return isolated
			},
			jsonMarker: `"rule_id":"candidate.marker"`,
			pageMarker: "candidate.marker",
		},
		{
			// The declared-order list renders one composed element per reference,
			// so this case asserts the whole tuple inside a single element rather
			// than a fragment loose in the document.
			name: "declared warning references",
			build: func(result evaluator.Result) evaluator.Result {
				isolated := withoutReferences(result)
				isolated.Reasons = nil
				isolated.WarningReferences = []evaluator.WarningReference{
					{Origin: evaluator.WarningFromEvidence, EvidenceIndex: 83, WarningIndex: 0},
				}
				return isolated
			},
			jsonMarker: `"evidence_index":83`,
			pageCheck: func(t *testing.T, page string) {
				t.Helper()
				want := regexp.MustCompile(`^evidence evidence_index 83 warning_index 0$`)
				for _, element := range emittedValues(page) {
					if want.MatchString(element) {
						return
					}
				}
				t.Errorf("no dynamic element of the page states the declared warning tuple exactly")
			},
		},
		{
			name: "global reasons",
			build: func(result evaluator.Result) evaluator.Result {
				isolated := withoutReferences(result)
				isolated.Reasons = []evaluator.Reason{evaluator.ReasonChecksUnknown}
				return isolated
			},
			jsonMarker: `"checks_unknown"`,
			pageMarker: "checks_unknown",
		},
		{
			name: "rule requirement and reason",
			build: func(result evaluator.Result) evaluator.Result {
				isolated := withoutReferences(result)
				isolated.Reasons = nil
				isolated.Rules = []evaluator.RuleTrace{{
					RuleID:              "rule.marker",
					State:               evaluator.RuleMissingEvidence,
					MissingRequirements: []rulepack.Requirement{rulepack.RequirementDomainArtifact},
					Reasons:             []evaluator.CheckReason{evaluator.ReasonUnapprovedSource},
				}}
				return isolated
			},
			jsonMarker: `"domain.artifact"`,
			pageMarker: "domain.artifact",
		},
		{
			name: "rule reason",
			build: func(result evaluator.Result) evaluator.Result {
				isolated := withoutReferences(result)
				isolated.Reasons = nil
				isolated.Rules = []evaluator.RuleTrace{{
					RuleID:  "rule.marker",
					State:   evaluator.RuleChecked,
					Reasons: []evaluator.CheckReason{evaluator.ReasonUnapprovedSource},
				}}
				return isolated
			},
			jsonMarker: `"unapproved_source"`,
			pageMarker: "unapproved_source",
		},
		{
			name: "target strings",
			build: func(result evaluator.Result) evaluator.Result {
				isolated := withoutReferences(result)
				isolated.Reasons = nil
				isolated.Target.Source = "source-marker"
				isolated.Target.Locator = contract.SourceLocator("locator-marker")
				isolated.Target.VulnerabilityID = "vulnerability-marker"
				return isolated
			},
			jsonMarker: `"source-marker"`,
			pageMarker: "source-marker",
		},
		{
			name: "target locator",
			build: func(result evaluator.Result) evaluator.Result {
				isolated := withoutReferences(result)
				isolated.Reasons = nil
				isolated.Target.Locator = contract.SourceLocator("locator-marker")
				return isolated
			},
			jsonMarker: `"locator-marker"`,
			pageMarker: "locator-marker",
		},
		{
			name: "target vulnerability",
			build: func(result evaluator.Result) evaluator.Result {
				isolated := withoutReferences(result)
				isolated.Reasons = nil
				isolated.Target.VulnerabilityID = "vulnerability-marker"
				return isolated
			},
			jsonMarker: `"vulnerability-marker"`,
			pageMarker: "vulnerability-marker",
		},
		{
			name: "target source hash",
			build: func(result evaluator.Result) evaluator.Result {
				isolated := withoutReferences(result)
				isolated.Reasons = nil
				isolated.Target.SourceHash = contract.SourceHash(markerHash)
				return isolated
			},
			jsonMarker: markerHash,
			pageMarker: markerHash,
		},
		{
			name: "engine and pack identity",
			build: func(result evaluator.Result) evaluator.Result {
				isolated := withoutReferences(result)
				isolated.Reasons = nil
				isolated.EngineVersion = "engine-marker"
				isolated.PackID = "pack-marker"
				isolated.PackHash = markerHash
				return isolated
			},
			jsonMarker: `"engine-marker"`,
			pageMarker: "engine-marker",
		},
		{
			name: "pack identity",
			build: func(result evaluator.Result) evaluator.Result {
				isolated := withoutReferences(result)
				isolated.Reasons = nil
				isolated.PackID = "pack-marker"
				isolated.PackHash = markerHash
				return isolated
			},
			jsonMarker: `"pack-marker"`,
			pageMarker: "pack-marker",
		},
		{
			name: "admission pair",
			build: func(result evaluator.Result) evaluator.Result {
				isolated := withoutReferences(result)
				isolated.Reasons = nil
				isolated.Admission.ExpectedPackID = "admission-marker"
				isolated.Admission.ExpectedPackHash = markerHash
				isolated.Admission.MinimumVersion = 424242
				return isolated
			},
			jsonMarker: `"admission-marker"`,
			pageMarker: "admission-marker",
		},
		{
			name: "admission minimum version",
			build: func(result evaluator.Result) evaluator.Result {
				isolated := withoutReferences(result)
				isolated.Reasons = nil
				isolated.Admission.MinimumVersion = 424242
				return isolated
			},
			jsonMarker: `"minimum_version":424242`,
			pageMarker: "424242",
		},
		{
			name: "absent previous version",
			build: func(result evaluator.Result) evaluator.Result {
				isolated := withoutReferences(result)
				isolated.Reasons = nil
				isolated.Admission.Previous = nil
				return isolated
			},
			jsonMarker: `"previous":null`,
			pageCheck: func(t *testing.T, page string) {
				t.Helper()
				if !strings.Contains(page, "Previously admitted</th><td>null</td>") {
					t.Errorf("the absent previous version is not stated as null in its own row")
				}
			},
		},
		{
			// No committed fixture admits a previous pack, so these two controls
			// carry the positive branch. They are separate on purpose: a page that
			// showed the hash but dropped the version would pass a single combined
			// case only because the marker was the hash.
			name: "present previous version number",
			build: func(result evaluator.Result) evaluator.Result {
				isolated := withoutReferences(result)
				isolated.Reasons = nil
				isolated.Admission.Previous = &rulepack.PreviousVersion{
					Version: 424242,
					Hash:    markerHash,
				}
				return isolated
			},
			jsonMarker: `"previous":{"version":424242,"hash":"` + markerHash + `"}`,
			pageMarker: "424242",
		},
		{
			name: "present previous version hash",
			build: func(result evaluator.Result) evaluator.Result {
				isolated := withoutReferences(result)
				isolated.Reasons = nil
				isolated.Admission.Previous = &rulepack.PreviousVersion{
					Version: 424242,
					Hash:    markerHash,
				}
				return isolated
			},
			jsonMarker: `"previous":{"version":424242,"hash":"` + markerHash + `"}`,
			pageMarker: markerHash,
		},
		{
			name: "domain policy and pins",
			build: func(result evaluator.Result) evaluator.Result {
				isolated := cloneResult(t, result)
				isolated.Reasons = nil
				isolated.Domain = &evaluator.DomainContext{
					MaximumEvidenceAgeSeconds: 424242,
					SourcePins: []evaluator.SourcePin{{
						Role:             evaluator.SourceRoleVendor,
						Source:           "pin-marker.json",
						SourceHash:       contract.SourceHash(markerHash),
						AdvisoryID:       pointer("advisory-marker"),
						AdvisoryRevision: pointer("revision-marker"),
					}},
				}
				return withoutReferences(isolated)
			},
			jsonMarker: `"pin-marker.json"`,
			pageMarker: "pin-marker.json",
		},
		{
			name: "pin hash",
			build: func(result evaluator.Result) evaluator.Result {
				isolated := cloneResult(t, result)
				isolated.Reasons = nil
				isolated.Domain = &evaluator.DomainContext{
					MaximumEvidenceAgeSeconds: 424242,
					SourcePins: []evaluator.SourcePin{{
						Role:             evaluator.SourceRoleVendor,
						Source:           "pin-marker.json",
						SourceHash:       contract.SourceHash(markerHash),
						AdvisoryID:       pointer("advisory-marker"),
						AdvisoryRevision: pointer("revision-marker"),
					}},
				}
				return withoutReferences(isolated)
			},
			jsonMarker: markerHash,
			pageMarker: markerHash,
		},
		{
			name: "pin advisories",
			build: func(result evaluator.Result) evaluator.Result {
				isolated := cloneResult(t, result)
				isolated.Reasons = nil
				isolated.Domain = &evaluator.DomainContext{
					MaximumEvidenceAgeSeconds: 424242,
					SourcePins: []evaluator.SourcePin{{
						Role:             evaluator.SourceRoleVendor,
						Source:           "pin-marker.json",
						SourceHash:       contract.SourceHash(markerHash),
						AdvisoryID:       pointer("advisory-marker"),
						AdvisoryRevision: pointer("revision-marker"),
					}},
				}
				return withoutReferences(isolated)
			},
			jsonMarker: `"advisory-marker"`,
			pageMarker: "advisory-marker",
		},
		{
			name: "pin revision",
			build: func(result evaluator.Result) evaluator.Result {
				isolated := cloneResult(t, result)
				isolated.Reasons = nil
				isolated.Domain = &evaluator.DomainContext{
					MaximumEvidenceAgeSeconds: 424242,
					SourcePins: []evaluator.SourcePin{{
						Role:             evaluator.SourceRoleVendor,
						Source:           "pin-marker.json",
						SourceHash:       contract.SourceHash(markerHash),
						AdvisoryID:       pointer("advisory-marker"),
						AdvisoryRevision: pointer("revision-marker"),
					}},
				}
				return withoutReferences(isolated)
			},
			jsonMarker: `"revision-marker"`,
			pageMarker: "revision-marker",
		},
		{
			name: "domain maximum age",
			build: func(result evaluator.Result) evaluator.Result {
				isolated := cloneResult(t, result)
				isolated.Reasons = nil
				isolated.Domain.MaximumEvidenceAgeSeconds = 424242
				return withoutReferences(isolated)
			},
			jsonMarker: `"maximum_evidence_age_seconds":424242`,
			pageMarker: "424242",
		},
		{
			// The marker is a proper substring of other values the page emits, and
			// none of them equals it: the cited catalog row renders "item_index 17"
			// and the pack id "pack-marker-7". With the engine version row removed,
			// a substring match would still find "7" inside those longer strings and
			// pass; the exact-element rule is what makes the case discriminate. This
			// is the control for the substring weakness of the earlier matcher.
			name: "substring trap for the exact-element rule",
			build: func(result evaluator.Result) evaluator.Result {
				isolated := withoutReferences(result)
				isolated.Reasons = nil
				isolated.EvidenceReferences = []evaluator.EvidenceReference{{ItemIndex: 17}}
				isolated.PackID = "pack-marker-7"
				isolated.EngineVersion = "7"
				return isolated
			},
			jsonMarker: `"engine_version":"7"`,
			pageMarker: "7",
		},
		{
			name: "evidence catalog",
			build: func(result evaluator.Result) evaluator.Result {
				isolated := withoutReferences(result)
				isolated.Reasons = nil
				isolated.EvidenceReferences = []evaluator.EvidenceReference{{ItemIndex: 11}}
				return isolated
			},
			jsonMarker: `"source_hash":"sha256:4d8dedb9d18269b9a16e6a4b8a5e60d41cdaa88ed138220193f121ceb96cdd6c"`,
			pageMarker: "prisma_v1.package_id",
		},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			base, bundle := loadEvaluated(t, "F13-contradictory-evidence")
			result := testCase.build(cloneResult(t, base))
			report, err := Build(result, bundle)
			if err != nil {
				t.Fatalf("the case result must stay valid: %v", err)
			}
			page, err := HTML(report)
			if err != nil {
				t.Fatalf("HTML: %v", err)
			}
			document, err := JSON(report)
			if err != nil {
				t.Fatalf("JSON: %v", err)
			}
			// The marker must reach the JSON, so the case cannot pass by producing
			// a result that never carried the value.
			if !bytes.Contains(document, []byte(testCase.jsonMarker)) {
				t.Fatalf("the marker %s is absent from the JSON, so this case cannot discriminate", testCase.jsonMarker)
			}
			switch {
			case testCase.pageCheck != nil && testCase.pageMarker != "":
				t.Fatalf("the case declares two page assertions")
			case testCase.pageCheck != nil:
				testCase.pageCheck(t, string(page))
			case testCase.pageMarker != "":
				if !emittedExactly(emittedValues(string(page)), testCase.pageMarker) {
					t.Errorf("the value %q reaches the JSON but no dynamic element of the page carries it", testCase.pageMarker)
				}
			default:
				t.Fatalf("the case declares no page assertion")
			}
		})
	}
}

// TestBuildDoesNotAliasCallerMemory pins the deep immutability rule: the report
// and the renderer must not hold aliases of the caller's memory.
//
// Two properties are checked, and they are different. First, the build and the
// render leave the caller's result and bundle byte for byte as they were. Second,
// the presentation does not observe a later change of the caller's memory. The
// second is what a shallow copy would violate, so the test rewrites the value an
// existing optional pointer already points to — not the pointer itself, which
// would be replaced in the caller and prove nothing — and mutates elements of
// collections that already existed rather than appending to them. A previous
// pack is installed before the build so the pointer branch is exercised too.
func TestBuildDoesNotAliasCallerMemory(t *testing.T) {
	result, bundle := loadEvaluated(t, "F13-contradictory-evidence")
	prepareCallerState(t, &result)

	pins := result.Domain.SourcePins
	var advisoryPin, plainPin int
	for index, pin := range pins {
		switch {
		case pin.AdvisoryID != nil && pin.AdvisoryRevision != nil:
			advisoryPin = index
		case pin.AdvisoryID == nil && pin.AdvisoryRevision == nil && plainPin == 0 && index != 0:
			plainPin = index
		}
	}
	if pins[advisoryPin].AdvisoryID == nil {
		t.Fatalf("this fixture must carry a vendor pin with advisories")
	}

	before := snapshotResult(t, result)
	bundleBefore := cloneBundle(t, bundle)
	previousVersion := result.Admission.Previous.Version
	previousHash := result.Admission.Previous.Hash

	report := mustBuild(t, result, bundle)
	firstJSON, err := JSON(report)
	if err != nil {
		t.Fatalf("JSON: %v", err)
	}
	firstHTML, err := HTML(report)
	if err != nil {
		t.Fatalf("HTML: %v", err)
	}

	if !reflect.DeepEqual(before, snapshotResult(t, result)) {
		t.Fatalf("the build modified the caller's result")
	}
	if !reflect.DeepEqual(bundleBefore, cloneBundle(t, bundle)) {
		t.Fatalf("the build modified the caller's bundle")
	}
	// The presentation must carry what was present before any rewrite.
	for _, marker := range []string{
		pins[advisoryPin].Source,
		*pins[advisoryPin].AdvisoryID,
		*pins[advisoryPin].AdvisoryRevision,
		previousHash,
	} {
		if !bytes.Contains(firstJSON, []byte(marker)) || !bytes.Contains(firstHTML, []byte(marker)) {
			t.Fatalf("the presentation does not carry %q, so the rewrite below cannot discriminate", marker)
		}
	}
	if !bytes.Contains(firstJSON, []byte(fmt.Sprintf(`"version":%d`, previousVersion))) {
		t.Fatalf("the presentation does not carry the previous version, so the rewrite below cannot discriminate")
	}

	// Rewrite the caller's own memory in place. The pointed-to values are
	// modified through their existing pointers, the collection elements are
	// replaced at their existing positions, and the string fields the structures
	// expose are overwritten.
	*pins[advisoryPin].AdvisoryID = "aliased-advisory"
	*pins[advisoryPin].AdvisoryRevision = "aliased-revision"
	result.Domain.SourcePins[advisoryPin].Source = "aliased-source"
	result.Domain.SourcePins[plainPin].Role = evaluator.SourceRoleVendor
	result.Target.Source = "aliased-target-source"
	result.Target.VulnerabilityID = "aliased-vulnerability"
	result.EngineVersion = "aliased-engine"
	result.Admission.ExpectedPackID = "aliased-pack"
	result.Admission.MinimumVersion = previousVersion + 1
	result.Admission.Previous.Version = previousVersion + 1
	result.Admission.Previous.Hash = "aliased-previous-hash"
	result.Reasons[0] = evaluator.ReasonNoApplicableRule
	result.Rules[0].RuleID = "aliased-rule"
	result.Rules[0].State = evaluator.RuleNotApplicable
	result.Rules[0].EvidenceReferences[0] = evaluator.EvidenceReference{ItemIndex: 1}
	result.Rules[0].Checks[0].CheckID = "aliased-check"
	result.Rules[0].Checks[0].Outcome = evaluator.OutcomeFail
	result.Rules[0].Checks[0].Reasons[0] = evaluator.ReasonUnavailable
	result.Rules[0].Checks[0].EvidenceReferences[0] = evaluator.EvidenceReference{ItemIndex: 1}
	result.Candidates[0].RuleID = "aliased-candidate"
	result.Candidates[0].ProductStatus = contract.ProductNotAffected
	result.EvidenceReferences[0] = evaluator.EvidenceReference{ItemIndex: 1}
	result.WarningReferences[0] = evaluator.WarningReference{Origin: evaluator.WarningFromEvidence, EvidenceIndex: 84, WarningIndex: 0}
	bundle.Subject.Name = "aliased-subject"
	bundle.Evidence[0].Source = "aliased-evidence-source"
	bundle.Evidence[0].Locator = contract.SourceLocator("aliased-evidence-locator")

	secondJSON, err := JSON(report)
	if err != nil {
		t.Fatalf("JSON: %v", err)
	}
	secondHTML, err := HTML(report)
	if err != nil {
		t.Fatalf("HTML: %v", err)
	}
	if !bytes.Equal(firstJSON, secondJSON) {
		t.Fatalf("the JSON report changed after the caller's memory was rewritten in place")
	}
	if !bytes.Equal(firstHTML, secondHTML) {
		t.Fatalf("the HTML report changed after the caller's memory was rewritten in place")
	}
	for _, marker := range []string{
		"aliased-advisory", "aliased-revision", "aliased-source", "aliased-target-source",
		"aliased-vulnerability", "aliased-engine", "aliased-pack", "aliased-previous-hash",
		"aliased-rule", "aliased-check", "aliased-candidate", "aliased-subject",
		"aliased-evidence-source", "aliased-evidence-locator",
	} {
		if bytes.Contains(secondJSON, []byte(marker)) || bytes.Contains(secondHTML, []byte(marker)) {
			t.Fatalf("the presentation carries the caller's later value %q", marker)
		}
	}

	// A fresh build from a mutated result and its own unmodified bundle must
	// differ, so the equality above is a property of the copy and not of a
	// renderer that ignores its input.
	freshResult, freshBundle := loadEvaluated(t, "F13-contradictory-evidence")
	freshResult.Target.Source = "genuinely-different-source"
	thirdJSON, err := JSON(mustBuild(t, freshResult, freshBundle))
	if err != nil {
		t.Fatalf("JSON: %v", err)
	}
	if bytes.Equal(firstJSON, thirdJSON) {
		t.Fatalf("a genuine input change produced no output change")
	}
}

// prepareCallerState installs the shapes no committed fixture carries, so the
// aliasing controls can exercise the pointer and non-empty collection branches
// of the projection. It runs before the snapshot, so the state it writes is part
// of the baseline the build must not modify.
func prepareCallerState(t *testing.T, result *evaluator.Result) {
	t.Helper()
	result.Admission.Previous = &rulepack.PreviousVersion{
		Version: 424242,
		Hash:    "sha256:3333333333333333333333333333333333333333333333333333333333333333",
	}
	if len(result.Reasons) == 0 || len(result.Rules) == 0 || len(result.Candidates) == 0 {
		t.Fatalf("the fixture must carry reasons, rules and candidates")
	}
	rule := &result.Rules[0]
	if len(rule.Checks) == 0 || len(rule.Checks[0].Reasons) == 0 || len(rule.EvidenceReferences) == 0 ||
		len(rule.Checks[0].EvidenceReferences) == 0 || len(result.EvidenceReferences) == 0 ||
		len(result.WarningReferences) == 0 || len(result.Candidates[0].EvidenceReferences) == 0 {
		t.Fatalf("the fixture must carry non-empty collections for the in-place rewrite")
	}
}

func snapshotResult(t *testing.T, result evaluator.Result) evaluator.Result {
	t.Helper()
	return cloneResult(t, result)
}

// cloneBundle detaches the evidence items and the provenance arrays, including
// the pointers the wire keeps on the items.
func cloneBundle(t *testing.T, bundle contract.Bundle) contract.Bundle {
	t.Helper()
	cloned := bundle
	cloned.Evidence = make([]contract.EvidenceItem, len(bundle.Evidence))
	for index, item := range bundle.Evidence {
		copied := item
		if item.ObservedAt != nil {
			observed := *item.ObservedAt
			copied.ObservedAt = &observed
		}
		copied.Warnings = append([]contract.Warning{}, item.Warnings...)
		cloned.Evidence[index] = copied
	}
	cloned.Provenance.Warnings = append([]contract.Warning{}, bundle.Provenance.Warnings...)
	cloned.Provenance.Errors = append([]string{}, bundle.Provenance.Errors...)
	return cloned
}

func walkLeaves(value any, visit func(string)) {
	switch typed := value.(type) {
	case map[string]any:
		for _, member := range typed {
			walkLeaves(member, visit)
		}
	case []any:
		for _, member := range typed {
			walkLeaves(member, visit)
		}
	case string:
		visit(typed)
	case json.Number:
		visit(typed.String())
	case float64:
		visit(fmt.Sprintf("%v", typed))
	}
}

// TestHTMLHasUniqueOccurrenceAnchors pins the occurrence identity: the anchors of
// the document are exactly one per catalog row, in both catalogs, and every
// internal link resolves to one of them. Two occurrences of the same item index
// must not share an identifier.
func TestHTMLHasUniqueOccurrenceAnchors(t *testing.T) {
	result, bundle := loadEvaluated(t, "F13-contradictory-evidence")
	report := mustBuild(t, result, bundle)
	page, err := HTML(report)
	if err != nil {
		t.Fatalf("HTML: %v", err)
	}
	body := string(page)
	found := map[string]int{}
	for _, match := range htmlIDPattern.FindAllStringSubmatch(body, -1) {
		found[match[1]]++
	}
	want := map[string]bool{}
	for position := range report.evidence {
		want[fmt.Sprintf("e-%d", position)] = true
	}
	for position := range report.warnings {
		want[fmt.Sprintf("w-%d", position)] = true
	}
	if len(found) != len(want) {
		t.Fatalf("the page has %d identifiers, want %d", len(found), len(want))
	}
	for anchor, count := range found {
		if count != 1 {
			t.Errorf("the identifier %q appears %d times", anchor, count)
		}
		if !want[anchor] {
			t.Errorf("the identifier %q is not an occurrence of either catalog", anchor)
		}
	}
	for anchor := range want {
		if found[anchor] == 0 {
			t.Errorf("the occurrence %q has no identifier", anchor)
		}
	}
	for _, match := range regexp.MustCompile(`href="#([^"]+)"`).FindAllStringSubmatch(body, -1) {
		if found[match[1]] != 1 {
			t.Errorf("the link %q does not resolve", match[1])
		}
	}
}

// TestHTMLWarningCatalogOrderAndDuplicates pins the ratified catalog order of F0
// §5 — origin, evidence_index, warning_index — and that two occurrences of the
// same warning stay two rows instead of collapsing into one.
func TestHTMLWarningCatalogOrderAndDuplicates(t *testing.T) {
	result, bundle := loadEvaluated(t, "F13-contradictory-evidence")

	// A provenance warning is injected so the origin is part of the order under
	// test, and the references are declared in an order the catalog must correct.
	modified := bundle
	modified.Provenance.Warnings = []contract.Warning{{
		Code: "synthetic-run-warning", Class: contract.WarningInformational, Message: "synthetic run warning",
	}}
	hash, err := canonical.HashCanonicalJSON(modified)
	if err != nil {
		t.Fatalf("modified bundle does not project: %v", err)
	}
	result.BundleHash = hash
	result.WarningReferences = []evaluator.WarningReference{
		{Origin: evaluator.WarningFromProvenance, EvidenceIndex: -1, WarningIndex: 0},
		{Origin: evaluator.WarningFromEvidence, EvidenceIndex: 84, WarningIndex: 0},
		{Origin: evaluator.WarningFromEvidence, EvidenceIndex: 84, WarningIndex: 0},
		{Origin: evaluator.WarningFromEvidence, EvidenceIndex: 83, WarningIndex: 0},
	}
	report := mustBuild(t, result, modified)
	if len(report.warnings) != 4 {
		t.Fatalf("warning rows %d, want 4", len(report.warnings))
	}
	previous := report.warnings[0].Reference
	if previous.Origin != string(evaluator.WarningFromEvidence) || previous.EvidenceIndex != 83 {
		t.Fatalf("the catalog does not start with the evidence warning of the lowest index: %v", previous)
	}
	for index := 1; index < len(report.warnings); index++ {
		current := report.warnings[index].Reference
		if compareWarningReferences(previous, current) > 0 {
			t.Fatalf("row %d is out of the ratified order: %v after %v", index, current, previous)
		}
		previous = current
	}
	// The two equal occurrences of the same warning are rows 1 and 2, with the
	// same code and distinct anchors.
	if report.warnings[1].Code != report.warnings[2].Code || report.warnings[1].Reference != report.warnings[2].Reference {
		t.Fatalf("the duplicate occurrence was not preserved: %v / %v", report.warnings[1], report.warnings[2])
	}
	page, err := HTML(report)
	if err != nil {
		t.Fatalf("HTML: %v", err)
	}
	if got := len(htmlWarningRefRow.FindAllStringSubmatch(string(page), -1)); got != 4 {
		t.Fatalf("the page shows %d warning rows, want 4", got)
	}
}

// TestHTMLKeepsTheDeclaredWarningReferenceOrder pins that the page reproduces
// result.warning_references in the order the result declares: the catalog is
// sorted, and without the declared list that order would be lost.
func TestHTMLKeepsTheDeclaredWarningReferenceOrder(t *testing.T) {
	result, bundle := loadEvaluated(t, "F13-contradictory-evidence")
	modified := bundle
	modified.Provenance.Warnings = []contract.Warning{{
		Code: "synthetic-run-warning", Class: contract.WarningInformational, Message: "synthetic run warning",
	}}
	hash, err := canonical.HashCanonicalJSON(modified)
	if err != nil {
		t.Fatalf("modified bundle does not project: %v", err)
	}
	result.BundleHash = hash
	result.WarningReferences = []evaluator.WarningReference{
		{Origin: evaluator.WarningFromProvenance, EvidenceIndex: -1, WarningIndex: 0},
		{Origin: evaluator.WarningFromEvidence, EvidenceIndex: 84, WarningIndex: 0},
		{Origin: evaluator.WarningFromEvidence, EvidenceIndex: 83, WarningIndex: 0},
	}
	page, err := HTML(mustBuild(t, result, modified))
	if err != nil {
		t.Fatalf("HTML: %v", err)
	}
	section := sectionOf(t, string(page), "Global warning references", "Evidence catalog")
	var got [][3]string
	for _, match := range htmlWarningRefItem.FindAllStringSubmatch(section, -1) {
		got = append(got, [3]string{match[1], match[2], match[3]})
	}
	if len(got) != len(result.WarningReferences) {
		t.Fatalf("the declared list has %d rows, want %d", len(got), len(result.WarningReferences))
	}
	for index, reference := range result.WarningReferences {
		want := [3]string{string(reference.Origin), itoa(reference.EvidenceIndex), itoa(reference.WarningIndex)}
		if got[index] != want {
			t.Errorf("declared row %d is %v, want %v", index, got[index], want)
		}
	}
}

func sectionOf(t *testing.T, body, from, to string) string {
	t.Helper()
	start := strings.Index(body, from)
	if start < 0 {
		t.Fatalf("the section %q is absent", from)
	}
	rest := body[start:]
	end := strings.Index(rest, to)
	if end < 0 {
		t.Fatalf("the section %q is absent", to)
	}
	return rest[:end]
}

// TestHTMLRepresentsOptionalNulls pins that absence is stated, never left to be
// inferred from a blank cell: an absent previous version, an absent domain
// context, the advisory optionals of the non-vendor roles and every omitted
// warning message are all rendered as the explicit word null.
func TestHTMLRepresentsOptionalNulls(t *testing.T) {
	result, bundle := loadEvaluated(t, "F09-unmapped-redhat-package")
	if result.Admission.Previous != nil || result.Domain == nil {
		t.Fatalf("F09 must exercise an absent previous version inside a present domain context")
	}
	page, err := HTML(mustBuild(t, result, bundle))
	if err != nil {
		t.Fatalf("HTML: %v", err)
	}
	body := string(page)
	if !strings.Contains(body, "Previously admitted</th><td>null") {
		t.Errorf("an absent previous version must be the explicit null")
	}
	exercised := false
	for _, pin := range result.Domain.SourcePins {
		if pin.AdvisoryID == nil && pin.AdvisoryRevision == nil {
			exercised = true
		}
	}
	if !exercised {
		t.Fatalf("this fixture must exercise a pin without advisories")
	}
	if !strings.Contains(body, "<td><code>null</code></td>") {
		t.Errorf("the advisory optionals of a mapping or artifact pin must be explicit nulls")
	}

	// The conservative profile has no domain at all, and the page must say so.
	conservative := cloneResult(t, result)
	conservative.ProfileVersion = rulepack.SupportedProfile
	conservative.Domain = nil
	conservative.ProductStatus = contract.ProductUnderInvestigation
	page, err = HTML(mustBuild(t, conservative, bundle))
	if err != nil {
		t.Fatalf("HTML: %v", err)
	}
	if !strings.Contains(string(page), "Domain context</th><td>null") {
		t.Errorf("an absent domain context must be the explicit null")
	}

	other, otherBundle := loadEvaluated(t, "F13-contradictory-evidence")
	page, err = HTML(mustBuild(t, other, otherBundle))
	if err != nil {
		t.Fatalf("HTML: %v", err)
	}
	if !strings.Contains(string(page), "null (omitted by presentation policy)") {
		t.Errorf("an omitted warning message must be stated")
	}
}

// TestBuildServesAReferenceOnlyWarningCitation pins that an item whose only
// citation is a warning still produces its catalog row: dropping the warning
// collection from the reference walk would silently remove evidence from the
// page.
func TestBuildServesAReferenceOnlyWarningCitation(t *testing.T) {
	const marker = "warning-only-marker.json"
	result, bundle := loadEvaluated(t, "F13-contradictory-evidence")

	modified := bundle
	modified.Evidence = append([]contract.EvidenceItem{}, bundle.Evidence...)
	modified.Evidence[0] = withWarning(modified.Evidence[0], marker)
	hash, err := canonical.HashCanonicalJSON(modified)
	if err != nil {
		t.Fatalf("modified bundle does not project: %v", err)
	}
	ordered, err := canonicalBundle(modified)
	if err != nil {
		t.Fatalf("modified bundle does not canonicalize: %v", err)
	}
	target := -1
	for index, item := range ordered.Evidence {
		if item.Source == marker {
			target = index
			break
		}
	}
	if target < 0 {
		t.Fatalf("the modified item is not in the canonical array")
	}

	// Control: with every citation removed the item has no row at all, so the row
	// asserted below can only come from the warning citation.
	control := withoutReferences(result)
	control.BundleHash = hash
	if len(mustBuild(t, control, modified).evidence) != 0 {
		t.Fatalf("the control build must produce no catalog row")
	}

	cited := withoutReferences(result)
	cited.BundleHash = hash
	cited.WarningReferences = []evaluator.WarningReference{
		{Origin: evaluator.WarningFromEvidence, EvidenceIndex: target, WarningIndex: 0},
	}
	report := mustBuild(t, cited, modified)
	if len(report.evidence) != 1 || report.evidence[0].Reference.ItemIndex != target {
		t.Fatalf("the warning citation did not produce exactly its own row: %v", report.evidence)
	}
	if report.evidence[0].Source != marker {
		t.Fatalf("the row cites %q, want the modified item", report.evidence[0].Source)
	}
	if len(report.warnings) != 1 || report.warnings[0].Code != "synthetic-item-warning" {
		t.Fatalf("the warning was not resolved: %v", report.warnings)
	}
	if report.evidence[0].Scope.SubjectUID != report.result.Target.SubjectUID {
		t.Fatalf("the row must stay in the scope of the target")
	}
}

func withWarning(item contract.EvidenceItem, source string) contract.EvidenceItem {
	item.Source = source
	item.Warnings = []contract.Warning{{
		Code: "synthetic-item-warning", Class: contract.WarningInformational, Message: "synthetic item warning",
	}}
	return item
}

// withoutReferences returns a result that cites nothing at all, so a row found
// in the report of a build can only come from a reference that was added back.
func withoutReferences(result evaluator.Result) evaluator.Result {
	copied := result
	copied.EvidenceReferences = nil
	copied.WarningReferences = nil
	copied.Rules = nil
	copied.Candidates = nil
	return copied
}

// TestBuildAcceptsAResultWithoutReferences pins that an inconclusive result with
// empty reference sets is presentable: the empty catalogs are arrays, never
// nulls and never an error.
func TestBuildAcceptsAResultWithoutReferences(t *testing.T) {
	result, bundle := loadEvaluated(t, "F09-unmapped-redhat-package")
	empty := result
	empty.EvidenceReferences = nil
	empty.WarningReferences = nil
	empty.Rules = nil
	empty.Candidates = nil
	report, err := Build(empty, bundle)
	if err != nil {
		t.Fatalf("an empty reference set must be presentable: %v", err)
	}
	if len(report.evidence) != 0 || len(report.warnings) != 0 {
		t.Fatalf("the catalogs must be empty, got %d/%d rows", len(report.evidence), len(report.warnings))
	}
	document, err := JSON(report)
	if err != nil {
		t.Fatalf("JSON: %v", err)
	}
	for _, member := range []string{`"evidence_references":[]`, `"warning_references":[]`, `"rules":[]`, `"candidates":[]`, `"evidence_catalog":[]`, `"warning_catalog":[]`} {
		if !bytes.Contains(document, []byte(member)) {
			t.Errorf("the empty collection %s must be an array", member)
		}
	}
	page, err := HTML(report)
	if err != nil {
		t.Fatalf("HTML: %v", err)
	}
	for _, marker := range []string{
		"No evidence item is referenced by this result (explicit empty array).",
		"No warning is referenced by this result (explicit empty array).",
		"No rule trace is present in this result (explicit empty array).",
	} {
		if !strings.Contains(string(page), marker) {
			t.Errorf("the page must state the empty collection: %q", marker)
		}
	}
}

// TestBuildAcceptsTheUnknownCheckOutcome pins that the third outcome value is
// presentable and conserved: unknown is a valid result of a check, not a state
// the renderer may translate into a pass or a fail.
func TestBuildAcceptsTheUnknownCheckOutcome(t *testing.T) {
	result, bundle := loadEvaluated(t, "F13-contradictory-evidence")
	modified := cloneResult(t, result)
	modified.Rules[0].Checks[0].Outcome = evaluator.OutcomeUnknown
	modified.Rules[0].Checks[0].Reasons = []evaluator.CheckReason{evaluator.ReasonUnavailable}
	report, err := Build(modified, bundle)
	if err != nil {
		t.Fatalf("an unknown check outcome must be presentable: %v", err)
	}
	if report.result.Rules[0].Checks[0].Outcome != string(evaluator.OutcomeUnknown) {
		t.Fatalf("the outcome was rewritten to %s", report.result.Rules[0].Checks[0].Outcome)
	}
	document, err := JSON(report)
	if err != nil {
		t.Fatalf("JSON: %v", err)
	}
	if !bytes.Contains(document, []byte(`"outcome":"unknown"`)) {
		t.Errorf("the JSON must carry the unknown outcome")
	}
	page, err := HTML(report)
	if err != nil {
		t.Fatalf("HTML: %v", err)
	}
	if !strings.Contains(sectionOf(t, string(page), "Rule traces", "Global evidence references"), "<code>unknown</code>") {
		t.Errorf("the page must show the unknown outcome")
	}
}

// TestBuildKeepsFixedApartFromNotAffected pins the domain rule that fixed is
// never not_affected: the renderer copies the status it is given and never
// aliases the two, so a fabricated not_affected is presented as such and the
// fixed document stays different.
func TestBuildKeepsFixedApartFromNotAffected(t *testing.T) {
	result, bundle := loadEvaluated(t, "F10-redhat-backport")
	statuses := []contract.ProductStatus{contract.ProductFixed, contract.ProductNotAffected, contract.ProductAffected}
	documents := map[contract.ProductStatus][]byte{}
	for _, status := range statuses {
		modified := cloneResult(t, result)
		modified.ProductStatus = status
		if len(modified.Candidates) != 1 {
			t.Fatalf("the fixture must sustain exactly one candidate")
		}
		modified.Candidates[0].ProductStatus = status
		report, err := Build(modified, bundle)
		if err != nil {
			t.Fatalf("%s must be presentable in the product profile: %v", status, err)
		}
		if report.result.ProductStatus != string(status) || report.result.Candidates[0].ProductStatus != string(status) {
			t.Fatalf("the status %s was rewritten to %s/%s", status, report.result.ProductStatus, report.result.Candidates[0].ProductStatus)
		}
		document, err := JSON(report)
		if err != nil {
			t.Fatalf("JSON: %v", err)
		}
		documents[status] = document
		if !bytes.Contains(document, []byte(`"product_status":"`+string(status)+`"`)) {
			t.Errorf("the document of %s does not carry its own status", status)
		}
	}
	if bytes.Equal(documents[contract.ProductFixed], documents[contract.ProductNotAffected]) {
		t.Errorf("fixed and not_affected must not produce the same document")
	}
	if bytes.Contains(documents[contract.ProductFixed], []byte("not_affected")) {
		t.Errorf("a fixed result must never present itself as not_affected")
	}
	if bytes.Contains(documents[contract.ProductNotAffected], []byte(`"product_status":"fixed"`)) {
		t.Errorf("a not_affected result must never present itself as fixed")
	}
}

// TestBuildIgnoresOperationalMetadata pins ADR-0006 §1(a): the operational
// metadata of the run is outside the hash projection and outside the report.
// Rewriting it changes neither the hash contrast nor a byte of the presentation.
func TestBuildIgnoresOperationalMetadata(t *testing.T) {
	result, bundle := loadEvaluated(t, "F13-contradictory-evidence")
	base, err := JSON(mustBuild(t, result, bundle))
	if err != nil {
		t.Fatalf("JSON: %v", err)
	}
	modified := bundle
	modified.Provenance.CollectorVersion = "9.9.9-operational-marker"
	modified.Provenance.ParserVersion = "operational-marker"
	modified.Provenance.StartedAt = nil
	modified.Provenance.EndedAt = nil
	hash, err := canonical.HashCanonicalJSON(modified)
	if err != nil {
		t.Fatalf("the modified bundle does not project: %v", err)
	}
	if hash != result.BundleHash {
		t.Fatalf("operational metadata moved the bundle hash: %s", hash)
	}
	document, err := JSON(mustBuild(t, result, modified))
	if err != nil {
		t.Fatalf("JSON: %v", err)
	}
	if !bytes.Equal(base, document) {
		t.Fatalf("operational metadata reached the presentation")
	}
	if bytes.Contains(document, []byte("operational-marker")) {
		t.Fatalf("the presentation carries an operational value")
	}
}

// TestBuildIsInsensitiveToInputOrder pins that the two canonically ordered
// collections are input order independent: the bundle is canonicalized before it
// is read, so a permutation of the caller's arrays produces the same bytes.
func TestBuildIsInsensitiveToInputOrder(t *testing.T) {
	result, bundle := loadEvaluated(t, "F13-contradictory-evidence")
	base, err := JSON(mustBuild(t, result, bundle))
	if err != nil {
		t.Fatalf("JSON: %v", err)
	}
	reversed := bundle
	reversed.Evidence = reversedEvidence(bundle.Evidence)
	hash, err := canonical.HashCanonicalJSON(reversed)
	if err != nil {
		t.Fatalf("the permuted bundle does not project: %v", err)
	}
	if hash != result.BundleHash {
		t.Fatalf("the hash of a permutation moved: %s", hash)
	}
	document, err := JSON(mustBuild(t, result, reversed))
	if err != nil {
		t.Fatalf("JSON: %v", err)
	}
	if !bytes.Equal(base, document) {
		t.Fatalf("the presentation depends on the input order of the collections")
	}
}

func reversedEvidence(items []contract.EvidenceItem) []contract.EvidenceItem {
	reversed := make([]contract.EvidenceItem, 0, len(items))
	for index := len(items) - 1; index >= 0; index-- {
		reversed = append(reversed, items[index])
	}
	return reversed
}

// TestBuildRejectsOnlyTheSubjectUid pins the subject half of the identity rule,
// isolated: with the container and every other field unchanged, a target whose
// subject uid differs from the scope of the cited item is a reference failure.
func TestBuildRejectsOnlyTheSubjectUid(t *testing.T) {
	result, bundle := loadEvaluated(t, "F13-contradictory-evidence")
	result.Target.SubjectUID = contract.UID("uid-F13-other")
	if _, err := Build(result, bundle); !IsCode(err, CodeInvalidReference) {
		t.Fatalf("a citation of another subject uid: got %v, want invalid_reference", err)
	}
	// Control: the same result with the original uid is accepted, so the failure
	// above is the uid and not an unrelated reference of the fixture.
	control, _ := loadEvaluated(t, "F13-contradictory-evidence")
	if _, err := Build(control, bundle); err != nil {
		t.Fatalf("the unmodified result must build: %v", err)
	}
}

// TestBuildRejectsOutOfRangeYears pins the RFC3339Nano representability of the
// ratified timestamp rule: a year outside 0000-9999 is not presentable, because
// the grammar the contract fixes cannot express it.
func TestBuildRejectsOutOfRangeYears(t *testing.T) {
	result, bundle := loadEvaluated(t, "F13-contradictory-evidence")
	for _, year := range []int{-1, 10000} {
		modified := result
		modified.Target.ObservedAt = contract.Timestamp{Time: timeAt(year)}
		if _, err := Build(modified, bundle); !IsCode(err, CodeInvalidResult) {
			t.Errorf("year %d: got %v, want invalid_result", year, err)
		}
	}
	// The boundary years of the grammar stay presentable.
	for _, year := range []int{0, 9999} {
		modified := result
		modified.Target.ObservedAt = contract.Timestamp{Time: timeAt(year)}
		if _, err := Build(modified, bundle); err != nil {
			t.Errorf("year %d must be presentable: %v", year, err)
		}
	}
}

// TestEvaluateFailureHasNoPresentation pins the zero-result rule: an evaluation
// that fails returns no result, and no result has no report. The renderer must
// not present a failed evaluation as an inconclusive one.
func TestEvaluateFailureHasNoPresentation(t *testing.T) {
	_, bundle := loadEvaluated(t, "F13-contradictory-evidence")
	result, err := evaluator.Evaluate(evaluator.Request{
		Bundle:             bundle,
		ExpectedBundleHash: "sha256:" + strings.Repeat("00", 32),
	})
	if err == nil {
		t.Fatalf("the evaluation must fail on a hash that is not the bundle's own")
	}
	if !reflect.DeepEqual(result, evaluator.Result{}) {
		t.Fatalf("a failed evaluation returned a non-zero result")
	}
	report, buildErr := Build(result, bundle)
	if buildErr == nil || !IsCode(buildErr, CodeInvalidResult) {
		t.Fatalf("the zero result: got %v, want invalid_result", buildErr)
	}
	if report.Valid() {
		t.Fatalf("a rejected build must not produce a valid report")
	}
	if _, err := JSON(report); !IsCode(err, CodeInvalidReport) {
		t.Fatalf("JSON: got %v, want invalid_report", err)
	}
}

// TestDiagnosticsAreExactlyTheClosedCode pins the ratified text of ADR-0022 §D3:
// each failure renders as exactly "report: <code>", with no index, no detail and
// nothing taken from the input.
func TestDiagnosticsAreExactlyTheClosedCode(t *testing.T) {
	codes := []ErrorCode{
		CodeInvalidResult, CodeInvalidBundle, CodeBundleHashMismatch,
		CodeInvalidReference, CodeInvalidReport, CodeRenderFailure,
	}
	if len(codes) != 6 {
		t.Fatalf("the closed set has %d codes, want 6", len(codes))
	}
	for _, code := range codes {
		if got, want := problem(code).Error(), "report: "+string(code); got != want {
			t.Errorf("rendered %q, want %q", got, want)
		}
	}

	result, bundle := loadEvaluated(t, "F13-contradictory-evidence")
	_, other := loadEvaluated(t, "F10-redhat-backport")
	zeroReport, err := JSON(Report{})
	if !IsCode(err, CodeInvalidReport) {
		t.Fatalf("JSON on a zero report: %v", err)
	}
	_ = zeroReport
	cases := []struct {
		name string
		code ErrorCode
		call func() error
	}{
		{"invalid_result", CodeInvalidResult, func() error {
			_, err := Build(evaluator.Result{}, bundle)
			return err
		}},
		{"bundle_hash_mismatch", CodeBundleHashMismatch, func() error {
			_, err := Build(result, other)
			return err
		}},
		{"invalid_reference", CodeInvalidReference, func() error {
			modified := result
			modified.EvidenceReferences = []evaluator.EvidenceReference{{ItemIndex: len(bundle.Evidence) + 1}}
			_, err := Build(modified, bundle)
			return err
		}},
		{"invalid_report", CodeInvalidReport, func() error {
			_, err := HTML(Report{})
			return err
		}},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			err := testCase.call()
			if !IsCode(err, testCase.code) {
				t.Fatalf("got %v, want %s", err, testCase.code)
			}
			if got, want := err.Error(), "report: "+string(testCase.code); got != want {
				t.Fatalf("rendered %q, want %q", got, want)
			}
		})
	}
}

// TestProjectedInputsDeclareEveryField is the guard against a silent loss: a
// field added to one of the structures this package projects fails here until it
// is listed, which forces the decision instead of dropping data from the page.
// The list is also checked for stale names, so a removed field cannot leave a
// phantom behind.
func TestProjectedInputsDeclareEveryField(t *testing.T) {
	declared := []struct {
		name   string
		typ    reflect.Type
		fields []string
	}{
		{"evaluator.Result", reflect.TypeOf(evaluator.Result{}), []string{
			"EngineVersion", "ProfileVersion", "BundleHash", "PackID", "PackVersion", "PackHash",
			"Target", "Admission", "Domain", "ProductStatus", "Exploitability", "Reasons",
			"Rules", "Candidates", "EvidenceReferences", "WarningReferences",
		}},
		{"evaluator.Target", reflect.TypeOf(evaluator.Target{}), []string{
			"SubjectUID", "ContainerClass", "ContainerName", "VulnerabilityID",
			"Source", "SourceHash", "Locator", "ObservedAt",
		}},
		{"rulepack.AdmissionContext", reflect.TypeOf(rulepack.AdmissionContext{}), []string{
			"EvaluatedAt", "ExpectedPackID", "ExpectedPackHash", "MinimumVersion", "Previous",
		}},
		{"rulepack.PreviousVersion", reflect.TypeOf(rulepack.PreviousVersion{}), []string{
			"Version", "Hash",
		}},
		{"evaluator.DomainContext", reflect.TypeOf(evaluator.DomainContext{}), []string{
			"MaximumEvidenceAgeSeconds", "SourcePins",
		}},
		{"evaluator.SourcePin", reflect.TypeOf(evaluator.SourcePin{}), []string{
			"Role", "Source", "SourceHash", "AdvisoryID", "AdvisoryRevision",
		}},
		{"evaluator.RuleTrace", reflect.TypeOf(evaluator.RuleTrace{}), []string{
			"RuleID", "State", "MissingRequirements", "Checks", "Reasons", "EvidenceReferences",
		}},
		{"evaluator.CheckTrace", reflect.TypeOf(evaluator.CheckTrace{}), []string{
			"CheckID", "Outcome", "Reasons", "EvidenceReferences",
		}},
		{"evaluator.Candidate", reflect.TypeOf(evaluator.Candidate{}), []string{
			"RuleID", "ProductStatus", "EvidenceReferences",
		}},
		{"evaluator.EvidenceReference", reflect.TypeOf(evaluator.EvidenceReference{}), []string{
			"ItemIndex",
		}},
		{"evaluator.WarningReference", reflect.TypeOf(evaluator.WarningReference{}), []string{
			"Origin", "EvidenceIndex", "WarningIndex",
		}},
	}
	for _, declaration := range declared {
		t.Run(declaration.name, func(t *testing.T) {
			known := map[string]bool{}
			for _, field := range declaration.fields {
				if known[field] {
					t.Fatalf("the declaration repeats %s", field)
				}
				known[field] = true
			}
			present := map[string]bool{}
			for index := 0; index < declaration.typ.NumField(); index++ {
				field := declaration.typ.Field(index).Name
				present[field] = true
				if !known[field] {
					t.Errorf("%s.%s is not declared as projected: decide how the report presents it",
						declaration.name, field)
				}
			}
			for field := range known {
				if !present[field] {
					t.Errorf("the declaration names %s.%s, which no longer exists", declaration.name, field)
				}
			}
		})
	}
}

// TestHTMLReferenceLinksPointToTheFirstRowOfTheIndex pins that a citation whose
// item occurs several times links to the first row of that index, and that no
// link targets a row of another index.
func TestHTMLReferenceLinksPointToTheFirstRowOfTheIndex(t *testing.T) {
	result, bundle := loadEvaluated(t, "F13-contradictory-evidence")
	report := mustBuild(t, result, bundle)
	page, err := HTML(report)
	if err != nil {
		t.Fatalf("HTML: %v", err)
	}
	body := string(page)
	firstRow := map[string]string{}
	for _, match := range htmlRowPattern.FindAllStringSubmatch(body, -1) {
		if _, seen := firstRow[match[2]]; !seen {
			firstRow[match[2]] = match[1]
		}
	}
	if len(firstRow) == 0 {
		t.Fatalf("the fixture must produce catalog rows")
	}
	duplicated := false
	counts := map[string]int{}
	for _, match := range htmlRowPattern.FindAllStringSubmatch(body, -1) {
		counts[match[2]]++
		if counts[match[2]] > 1 {
			duplicated = true
		}
	}
	if !duplicated {
		t.Fatalf("the fixture must cite at least one item more than once for this control")
	}
	links := htmlEvidenceLink.FindAllStringSubmatch(body, -1)
	if len(links) == 0 {
		t.Fatalf("the fixture must produce citations")
	}
	for _, link := range links {
		if firstRow[link[2]] != link[1] {
			t.Errorf("the citation of item_index %s points at %s, want the first row %s", link[2], link[1], firstRow[link[2]])
		}
	}
}

// TestBuildDistinguishesWarningsWithEqualCodeAndClass pins the resolution of a
// warning occurrence when two warnings of the same item share code and class and
// differ only in their message: the message never reaches the presentation, so
// the two rows are equal in every presented member and the resolution must not
// collapse them into one, nor resolve every reference to the warning at index 0.
func TestBuildDistinguishesWarningsWithEqualCodeAndClass(t *testing.T) {
	result, bundle := loadEvaluated(t, "F13-contradictory-evidence")

	modified := bundle
	modified.Evidence = append([]contract.EvidenceItem{}, bundle.Evidence...)
	item := modified.Evidence[0]
	item.Warnings = []contract.Warning{
		{Code: "synthetic-twin-warning", Class: contract.WarningInformational, Message: "first message"},
		{Code: "synthetic-twin-warning", Class: contract.WarningInformational, Message: "second message"},
	}
	modified.Evidence[0] = item
	hash, err := canonical.HashCanonicalJSON(modified)
	if err != nil {
		t.Fatalf("the modified bundle does not project: %v", err)
	}
	ordered, err := canonicalBundle(modified)
	if err != nil {
		t.Fatalf("the modified bundle does not canonicalize: %v", err)
	}
	target := -1
	for index, candidate := range ordered.Evidence {
		if len(candidate.Warnings) == 2 && candidate.Warnings[0].Code == "synthetic-twin-warning" {
			target = index
			break
		}
	}
	if target < 0 {
		t.Fatalf("the modified item is not in the canonical arrays")
	}

	// The references name the second occurrence only, so a resolver that always
	// returned index 0 would still produce a row and could pass a weaker check.
	// Both occurrences are therefore cited, in the reverse order.
	isolated := withoutReferences(result)
	isolated.BundleHash = hash
	isolated.WarningReferences = []evaluator.WarningReference{
		{Origin: evaluator.WarningFromEvidence, EvidenceIndex: target, WarningIndex: 1},
		{Origin: evaluator.WarningFromEvidence, EvidenceIndex: target, WarningIndex: 0},
	}
	report := mustBuild(t, isolated, modified)
	if len(report.warnings) != 2 {
		t.Fatalf("warning rows %d, want 2", len(report.warnings))
	}
	// The canonical order is (origin, evidence_index, warning_index), so the two
	// rows are ordered 0 then 1 although they were declared 1 then 0.
	if report.warnings[0].Reference.WarningIndex != 0 || report.warnings[1].Reference.WarningIndex != 1 {
		t.Fatalf("the catalog does not carry both occurrences: %v", report.warnings)
	}
	for _, row := range report.warnings {
		if row.Code != "synthetic-twin-warning" || row.Class != string(contract.WarningInformational) {
			t.Errorf("the row does not conserve the warning vocabulary: %v", row)
		}
		if row.Message != nil {
			t.Errorf("the omitted message must stay an explicit nil: %v", row)
		}
	}
	// The page must carry the two anchors, reachable from the declared list.
	page, err := HTML(report)
	if err != nil {
		t.Fatalf("HTML: %v", err)
	}
	body := string(page)
	for _, anchor := range []string{`id="w-0"`, `id="w-1"`} {
		if !strings.Contains(body, anchor) {
			t.Errorf("the page does not carry the occurrence anchor %s", anchor)
		}
	}
}

// TestBuildResolvesTheCitedWarningIndex pins that a warning reference resolves
// the occurrence it names, not the first one of the item. The twins above share
// code and class, so resolving index 0 for both would be invisible there; here
// the two warnings of the item differ in code and class, and only the second is
// cited, so a resolver that always read element 0 would present the wrong
// vocabulary.
func TestBuildResolvesTheCitedWarningIndex(t *testing.T) {
	result, bundle := loadEvaluated(t, "F13-contradictory-evidence")

	modified := bundle
	modified.Evidence = append([]contract.EvidenceItem{}, bundle.Evidence...)
	item := modified.Evidence[0]
	item.Warnings = []contract.Warning{
		{Code: "synthetic-first-warning", Class: contract.WarningInformational, Message: "first"},
		{Code: "synthetic-second-warning", Class: contract.WarningContradictory, Message: "second"},
	}
	modified.Evidence[0] = item
	hash, err := canonical.HashCanonicalJSON(modified)
	if err != nil {
		t.Fatalf("the modified bundle does not project: %v", err)
	}
	ordered, err := canonicalBundle(modified)
	if err != nil {
		t.Fatalf("the modified bundle does not canonicalize: %v", err)
	}
	target := -1
	for index, candidate := range ordered.Evidence {
		if len(candidate.Warnings) == 2 && candidate.Warnings[0].Code == "synthetic-first-warning" {
			target = index
			break
		}
	}
	if target < 0 {
		t.Fatalf("the modified item is not in the canonical arrays")
	}

	isolated := withoutReferences(result)
	isolated.BundleHash = hash
	isolated.WarningReferences = []evaluator.WarningReference{
		{Origin: evaluator.WarningFromEvidence, EvidenceIndex: target, WarningIndex: 1},
	}
	report := mustBuild(t, isolated, modified)
	if len(report.warnings) != 1 {
		t.Fatalf("warning rows %d, want 1", len(report.warnings))
	}
	row := report.warnings[0]
	if row.Code != "synthetic-second-warning" {
		t.Errorf("the row presents %q, want the cited occurrence %q", row.Code, "synthetic-second-warning")
	}
	if row.Class != string(contract.WarningContradictory) {
		t.Errorf("the row presents class %q, want the cited occurrence's", row.Class)
	}
	if row.Reference.WarningIndex != 1 {
		t.Errorf("the row cites warning_index %d, want 1", row.Reference.WarningIndex)
	}
}

// TestJSONKeepsFormulaPrefixesAsText pins I-09 for the decoded JSON document: a
// value that begins with a formula prefix is preserved character for character
// after decoding. The encoding escapes <, > and &, and that escaping is
// presentation: decoding must restore the exact string, so no prefix is altered,
// prefixed with an apostrophe or dropped. The contract claims no protection when
// the file is later imported into a spreadsheet.
func TestJSONKeepsFormulaPrefixesAsText(t *testing.T) {
	result, bundle := loadEvaluated(t, "F13-contradictory-evidence")
	payloads := []string{
		"=1+1", "+SUM(A1)", "-2", "@import", " =1+1", "\t=cmd", "\n=cmd", "\r=cmd",
		`=cmd|' /C calc'!A0`, "=1+1", `'"=1+1"`,
	}
	for _, payload := range payloads {
		modified := cloneResult(t, result)
		modified.Target.Source = payload
		document, err := JSON(mustBuild(t, modified, bundle))
		if err != nil {
			t.Fatalf("JSON: %v", err)
		}
		var decoded struct {
			Result struct {
				Target struct {
					Source string `json:"source"`
				} `json:"target"`
			} `json:"result"`
		}
		if err := json.Unmarshal(document, &decoded); err != nil {
			t.Fatalf("the document does not decode: %v", err)
		}
		if decoded.Result.Target.Source != payload {
			t.Errorf("the decoded value is %q, want the exact %q", decoded.Result.Target.Source, payload)
		}
	}
}

// TestEncodersReadNoHostState pins M10: the encoders must not incorporate a
// property of the host. The same input is rendered with different working
// directories, locale variables, time zones and a modified environment; the
// bytes must be identical every time, which rules out a host value reaching the
// output. It sets the process state only for the duration of the calls.
func TestEncodersReadNoHostState(t *testing.T) {
	result, bundle := loadEvaluated(t, "F13-contradictory-evidence")
	report := mustBuild(t, result, bundle)
	wantJSON, err := JSON(report)
	if err != nil {
		t.Fatalf("JSON: %v", err)
	}
	wantHTML, err := HTML(report)
	if err != nil {
		t.Fatalf("HTML: %v", err)
	}

	workingDirectory, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	// The working directory is a real, existing directory obtained before any
	// variable changes. Entering os.TempDir() would make the test depend on the
	// value this test just wrote into TMPDIR, and on Unix it would then fail on a
	// path that does not exist.
	otherDirectory := t.TempDir()
	defer func() {
		if err := os.Chdir(workingDirectory); err != nil {
			t.Fatalf("restore the working directory: %v", err)
		}
	}()

	environments := [][]struct{ key, value string }{
		{{"TZ", "Pacific/Kiritimati"}, {"LANG", "fr_FR.UTF-8"}, {"LC_ALL", "fr_FR.UTF-8"}},
		{{"TZ", "America/Anchorage"}, {"LANG", "C"}, {"LC_ALL", "C"}, {"TMPDIR", otherDirectory}},
		{{"TZ", "UTC"}, {"LANG", "ja_JP.UTF-8"}, {"LC_ALL", "ja_JP.UTF-8"}, {"USERDOMAIN", "marker-host"}},
	}
	for index, environment := range environments {
		restore := applyEnvironment(t, environment)
		if err := os.Chdir(otherDirectory); err != nil {
			t.Fatalf("chdir: %v", err)
		}
		freshJSON, err := JSON(mustBuild(t, result, bundle))
		if err != nil {
			t.Fatalf("JSON: %v", err)
		}
		freshHTML, err := HTML(mustBuild(t, result, bundle))
		if err != nil {
			t.Fatalf("HTML: %v", err)
		}
		if !bytes.Equal(freshJSON, wantJSON) {
			t.Errorf("configuration %d changed the JSON bytes", index)
		}
		if !bytes.Equal(freshHTML, wantHTML) {
			t.Errorf("configuration %d changed the HTML bytes", index)
		}
		restore()
		if err := os.Chdir(workingDirectory); err != nil {
			t.Fatalf("restore the working directory: %v", err)
		}
	}

	// Control: the environment really changed, and restoring returns it to what
	// the process had, whether that was absent or a value inherited from the
	// environment the test runs in.
	const marker = "ARIADNE_HOST_MARKER"
	original, hadMarker := os.LookupEnv(marker)
	restore := applyEnvironment(t, []struct{ key, value string }{{marker, "set"}})
	if os.Getenv(marker) != "set" {
		t.Fatalf("the environment control did not take effect")
	}
	restore()
	after, present := os.LookupEnv(marker)
	if present != hadMarker || after != original {
		t.Fatalf("the environment control was not restored: present=%v value=%q, want present=%v value=%q",
			present, after, hadMarker, original)
	}
}

func applyEnvironment(t *testing.T, values []struct{ key, value string }) func() {
	t.Helper()
	type previous struct {
		key     string
		value   string
		present bool
	}
	saved := make([]previous, 0, len(values))
	for _, pair := range values {
		value, present := os.LookupEnv(pair.key)
		saved = append(saved, previous{key: pair.key, value: value, present: present})
		if err := os.Setenv(pair.key, pair.value); err != nil {
			t.Fatalf("setenv %s: %v", pair.key, err)
		}
	}
	return func() {
		for _, item := range saved {
			if item.present {
				_ = os.Setenv(item.key, item.value)
				continue
			}
			_ = os.Unsetenv(item.key)
		}
	}
}
