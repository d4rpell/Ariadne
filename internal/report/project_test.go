package report

import (
	"bytes"
	"encoding/json"
	"errors"
	"html"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/d4rpell/Ariadne/internal/evaluator"
	canonical "github.com/d4rpell/Ariadne/internal/evidence"
	"github.com/d4rpell/Ariadne/internal/rulepack"
	contract "github.com/d4rpell/Ariadne/pkg/evidence"
)

// hrefPattern finds the URL of every link the document builds. The contract
// admits only internal anchors, and they are derived from numeric indices.
var hrefPattern = regexp.MustCompile(`href="([^"]*)"`)

// The fixtures of this package are entirely synthetic: identifiers, hashes,
// timestamps, packages and advisories are fabricated for the tests.

const fixturesRoot = "../../fixtures"

type fixtureTarget struct {
	SubjectUID      string `json:"subject_uid"`
	ContainerClass  string `json:"container_class"`
	ContainerName   string `json:"container_name"`
	VulnerabilityID string `json:"vulnerability_id"`
	Source          string `json:"source"`
	SourceHash      string `json:"source_hash"`
	Locator         string `json:"locator"`
	ObservedAt      string `json:"observed_at"`
}

type fixtureAdmission struct {
	EvaluatedAt      string `json:"evaluated_at"`
	ExpectedPackID   string `json:"expected_pack_id"`
	ExpectedPackHash string `json:"expected_pack_hash"`
	MinimumVersion   int64  `json:"minimum_version"`
}

type fixturePin struct {
	Role             string  `json:"role"`
	Source           string  `json:"source"`
	SourceHash       string  `json:"source_hash"`
	AdvisoryID       *string `json:"advisory_id"`
	AdvisoryRevision *string `json:"advisory_revision"`
}

type fixtureDomainContext struct {
	MaximumEvidenceAgeSeconds int64        `json:"maximum_evidence_age_seconds"`
	SourcePins                []fixturePin `json:"source_pins"`
}

func readFixtureFile(t *testing.T, path string) []byte {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("fixture file %s: %v", path, err)
	}
	return data
}

func mustParseTime(t *testing.T, value string) contract.Timestamp {
	t.Helper()
	var stamp contract.Timestamp
	if err := json.Unmarshal([]byte(`"`+value+`"`), &stamp); err != nil {
		t.Fatalf("timestamp %s: %v", value, err)
	}
	return stamp
}

// loadEvaluated runs the real engine over one committed fixture: the report
// tests never fabricate a Result that the evaluator would not produce, so the
// projection is exercised against the actual producer.
func loadEvaluated(t *testing.T, slug string) (evaluator.Result, contract.Bundle) {
	t.Helper()
	root := filepath.Join(fixturesRoot, slug, "0.2")
	input := filepath.Join(root, "input")

	var bundle contract.Bundle
	if err := json.Unmarshal(readFixtureFile(t, filepath.Join(input, "bundle.json")), &bundle); err != nil {
		t.Fatalf("fixture bundle does not decode: %v", err)
	}
	var target fixtureTarget
	if err := json.Unmarshal(readFixtureFile(t, filepath.Join(input, "target.json")), &target); err != nil {
		t.Fatalf("fixture target does not decode: %v", err)
	}
	var admission fixtureAdmission
	if err := json.Unmarshal(readFixtureFile(t, filepath.Join(input, "admission-context.json")), &admission); err != nil {
		t.Fatalf("fixture admission does not decode: %v", err)
	}
	var domain fixtureDomainContext
	if err := json.Unmarshal(readFixtureFile(t, filepath.Join(input, "domain-context.json")), &domain); err != nil {
		t.Fatalf("fixture domain does not decode: %v", err)
	}
	hash, err := canonical.HashCanonicalJSON(bundle)
	if err != nil {
		t.Fatalf("fixture bundle does not project: %v", err)
	}
	pins := make([]evaluator.SourcePin, 0, len(domain.SourcePins))
	for _, pin := range domain.SourcePins {
		pins = append(pins, evaluator.SourcePin{
			Role:             evaluator.SourceRole(pin.Role),
			Source:           pin.Source,
			SourceHash:       contract.SourceHash(pin.SourceHash),
			AdvisoryID:       pin.AdvisoryID,
			AdvisoryRevision: pin.AdvisoryRevision,
		})
	}
	request := evaluator.Request{
		Bundle:             bundle,
		ExpectedBundleHash: hash,
		Target: evaluator.Target{
			SubjectUID:      contract.UID(target.SubjectUID),
			ContainerClass:  contract.ContainerClass(target.ContainerClass),
			ContainerName:   contract.ContainerName(target.ContainerName),
			VulnerabilityID: target.VulnerabilityID,
			Source:          target.Source,
			SourceHash:      contract.SourceHash(target.SourceHash),
			Locator:         contract.SourceLocator(target.Locator),
			ObservedAt:      mustParseTime(t, target.ObservedAt),
		},
		PackBytes: readFixtureFile(t, filepath.Join(input, "pack.json")),
		Admission: rulepack.AdmissionContext{
			EvaluatedAt:      mustParseTime(t, admission.EvaluatedAt),
			ExpectedPackID:   admission.ExpectedPackID,
			ExpectedPackHash: admission.ExpectedPackHash,
			MinimumVersion:   admission.MinimumVersion,
		},
		Domain: &evaluator.DomainContext{
			MaximumEvidenceAgeSeconds: domain.MaximumEvidenceAgeSeconds,
			SourcePins:                pins,
		},
	}
	result, err := evaluator.Evaluate(request)
	if err != nil {
		t.Fatalf("fixture %s must evaluate: %v", slug, err)
	}
	return result, bundle
}

func mustBuild(t *testing.T, result evaluator.Result, bundle contract.Bundle) Report {
	t.Helper()
	report, err := Build(result, bundle)
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	return report
}

// TestBuildRejectsZeroReport pins that a zero Report is not renderable: the
// encoders refuse a value Build never produced.
func TestBuildRejectsZeroReport(t *testing.T) {
	var zero Report
	if zero.Valid() {
		t.Fatalf("the zero Report must not be valid")
	}
	if _, err := JSON(zero); !IsCode(err, CodeInvalidReport) {
		t.Fatalf("JSON on a zero report: got %v, want invalid_report", err)
	}
	if _, err := HTML(zero); !IsCode(err, CodeInvalidReport) {
		t.Fatalf("HTML on a zero report: got %v, want invalid_report", err)
	}
}

// TestBuildProjectsEveryResultField contrasts the DTO against the Result field
// by field: a dropped or renamed field is a contract break the golden bytes
// would otherwise hide.
func TestBuildProjectsEveryResultField(t *testing.T) {
	result, bundle := loadEvaluated(t, "F13-contradictory-evidence")
	report := mustBuild(t, result, bundle)
	dto := report.result

	if dto.EngineVersion != result.EngineVersion || dto.ProfileVersion != Profile(result.ProfileVersion) {
		t.Errorf("identity fields are %s/%s", dto.EngineVersion, dto.ProfileVersion)
	}
	if dto.BundleHash != result.BundleHash || dto.PackID != result.PackID ||
		dto.PackVersion != result.PackVersion || dto.PackHash != result.PackHash {
		t.Errorf("pack fields do not match the result")
	}
	if dto.ProductStatus != string(result.ProductStatus) || dto.Exploitability != string(result.Exploitability) {
		t.Errorf("statuses are %s/%s", dto.ProductStatus, dto.Exploitability)
	}
	if dto.RiskDecision != nil {
		t.Errorf("risk_decision must be null, got %v", dto.RiskDecision)
	}
	if len(dto.Reasons) != len(result.Reasons) {
		t.Fatalf("reasons %d, want %d", len(dto.Reasons), len(result.Reasons))
	}
	for index, reason := range result.Reasons {
		if dto.Reasons[index] != string(reason) {
			t.Errorf("reason %d is %s, want %s", index, dto.Reasons[index], reason)
		}
	}
	if len(dto.Rules) != len(result.Rules) || len(dto.Candidates) != len(result.Candidates) {
		t.Fatalf("traces %d/%d, want %d/%d", len(dto.Rules), len(dto.Candidates), len(result.Rules), len(result.Candidates))
	}
	if len(dto.EvidenceReferences) != len(result.EvidenceReferences) {
		t.Errorf("global references %d, want %d", len(dto.EvidenceReferences), len(result.EvidenceReferences))
	}
	if len(dto.WarningReferences) != len(result.WarningReferences) {
		t.Errorf("warning references %d, want %d", len(dto.WarningReferences), len(result.WarningReferences))
	}
	if dto.Domain == nil {
		t.Fatalf("the product profile carries a domain context")
	}
	if dto.Domain.MaximumEvidenceAgeSeconds != result.Domain.MaximumEvidenceAgeSeconds {
		t.Errorf("domain TTL %d, want %d", dto.Domain.MaximumEvidenceAgeSeconds, result.Domain.MaximumEvidenceAgeSeconds)
	}
	if len(dto.Domain.SourcePins) != len(result.Domain.SourcePins) {
		t.Errorf("pins %d, want %d", len(dto.Domain.SourcePins), len(result.Domain.SourcePins))
	}
	for index, pin := range result.Domain.SourcePins {
		got := dto.Domain.SourcePins[index]
		if got.Role != string(pin.Role) || got.Source != pin.Source || got.SourceHash != string(pin.SourceHash) {
			t.Errorf("pin %d does not match the result", index)
		}
	}
	if dto.Target.SubjectUID != string(result.Target.SubjectUID) || dto.Target.Locator != string(result.Target.Locator) {
		t.Errorf("target fields do not match the result")
	}
	if dto.Admission.Previous != nil {
		t.Errorf("this fixture carries no previous version")
	}
	if dto.Admission.MinimumVersion != result.Admission.MinimumVersion {
		t.Errorf("minimum version %d, want %d", dto.Admission.MinimumVersion, result.Admission.MinimumVersion)
	}
}

// TestBuildRejectsNonUTCTimestamps pins the canonical instant rule with the
// identity comparison the wire uses: a fixed zone merely named "UTC" whose
// offset is not zero is not a canonical instant and must be rejected, not
// silently renormalized.
func TestBuildRejectsNonUTCTimestamps(t *testing.T) {
	result, bundle := loadEvaluated(t, "F13-contradictory-evidence")
	impostor := time.FixedZone("UTC", 3600)
	shifted := result
	shifted.Target.ObservedAt = contract.Timestamp{Time: result.Target.ObservedAt.In(impostor)}
	if _, err := Build(shifted, bundle); !IsCode(err, CodeInvalidResult) {
		t.Fatalf("a named-but-offset zone must be rejected: got %v", err)
	}
	// A genuine UTC instant in a different but zero-offset location is still not
	// the identity the contract requires.
	offsetZero := result
	offsetZero.Admission.EvaluatedAt = contract.Timestamp{Time: result.Admission.EvaluatedAt.In(time.FixedZone("Z", 0))}
	if _, err := Build(offsetZero, bundle); !IsCode(err, CodeInvalidResult) {
		t.Fatalf("a zero-offset non-UTC location must be rejected: got %v", err)
	}
}

// TestBuildRejectsBundleOfAnotherResult pins the hash contrast: a valid bundle
// that is not the one this result was computed over is rejected instead of
// producing citations of foreign evidence.
func TestBuildRejectsBundleOfAnotherResult(t *testing.T) {
	result, _ := loadEvaluated(t, "F13-contradictory-evidence")
	_, other := loadEvaluated(t, "F10-redhat-backport")
	if _, err := Build(result, other); !IsCode(err, CodeBundleHashMismatch) {
		t.Fatalf("Build with the wrong bundle: got %v, want bundle_hash_mismatch", err)
	}
}

// TestBuildRejectsFabricatedResults covers the form checks: each mutation of a
// genuine result must be rejected with the closed code, never rendered.
func TestBuildRejectsFabricatedResults(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(result *evaluator.Result)
	}{
		{"unknown product status", func(r *evaluator.Result) { r.ProductStatus = contract.ProductStatus("unknown") }},
		{"affirmative status in the conservative profile", func(r *evaluator.Result) {
			r.ProfileVersion = rulepack.SupportedProfile
			r.Domain = nil
			r.ProductStatus = contract.ProductFixed
			r.Candidates = nil
		}},
		{"exploitability invented", func(r *evaluator.Result) { r.Exploitability = contract.ExploitabilityUnknown }},
		{"domain context in the conservative profile", func(r *evaluator.Result) { r.ProfileVersion = rulepack.SupportedProfile }},
		{"missing domain context in the product profile", func(r *evaluator.Result) { r.Domain = nil }},
		{"unknown global reason", func(r *evaluator.Result) { r.Reasons = []evaluator.Reason{"made_up"} }},
		{"unknown check reason", func(r *evaluator.Result) {
			r.Rules[0].Checks[0].Reasons = []evaluator.CheckReason{"made_up"}
		}},
		{"unknown rule state", func(r *evaluator.Result) { r.Rules[0].State = evaluator.RuleState("made_up") }},
		{"unknown missing requirement", func(r *evaluator.Result) {
			r.Rules[0].MissingRequirements = []rulepack.Requirement{"requirement.made_up"}
		}},
		{"negative evidence reference", func(r *evaluator.Result) {
			r.EvidenceReferences = []evaluator.EvidenceReference{{ItemIndex: -1}}
		}},
		{"provenance warning with an evidence index", func(r *evaluator.Result) {
			r.WarningReferences = []evaluator.WarningReference{{Origin: evaluator.WarningFromProvenance, EvidenceIndex: 0, WarningIndex: 0}}
		}},
		{"unknown warning origin", func(r *evaluator.Result) {
			r.WarningReferences = []evaluator.WarningReference{{Origin: evaluator.WarningOrigin("made_up"), EvidenceIndex: 0, WarningIndex: 0}}
		}},
		{"candidate outside the product profile", func(r *evaluator.Result) {
			r.ProfileVersion = rulepack.SupportedProfile
			r.Domain = nil
			r.ProductStatus = contract.ProductUnderInvestigation
		}},
		{"candidate with an innocent status", func(r *evaluator.Result) {
			r.Candidates[0].ProductStatus = contract.ProductUnderInvestigation
		}},
		{"bad bundle hash grammar", func(r *evaluator.Result) { r.BundleHash = "sha256:short" }},
		{"zero evaluated_at", func(r *evaluator.Result) { r.Admission.EvaluatedAt = contract.Timestamp{} }},
		{"bad minimum version", func(r *evaluator.Result) { r.Admission.MinimumVersion = 0 }},
		{"pin role and nulls disagree", func(r *evaluator.Result) {
			r.Domain.SourcePins[0].AdvisoryID = pointer("RHSA-2026:0003")
		}},
	}
	base, bundle := loadEvaluated(t, "F13-contradictory-evidence")
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			result := cloneResult(t, base)
			testCase.mutate(&result)
			report, err := Build(result, bundle)
			if err == nil {
				t.Fatalf("the fabricated result was accepted and produced a report")
			}
			if !IsCode(err, CodeInvalidResult) {
				t.Fatalf("got %v, want invalid_result", err)
			}
			if report.Valid() {
				t.Fatalf("a rejected build must not return a usable report")
			}
			if _, err := JSON(report); err == nil {
				t.Fatalf("a rejected build must not render bytes")
			}
		})
	}
}

// TestBuildRejectsInvalidBundle pins that a bundle the wire rejects produces no
// report, and that the failure is not confused with a hash mismatch.
func TestBuildRejectsInvalidBundle(t *testing.T) {
	result, bundle := loadEvaluated(t, "F13-contradictory-evidence")
	broken := bundle
	broken.Subject.UID = ""
	if _, err := Build(result, broken); !IsCode(err, CodeInvalidBundle) {
		t.Fatalf("Build with an invalid bundle: got %v, want invalid_bundle", err)
	}
}

// TestBuildRejectsForeignScope pins that a reference into another container of
// the same subject is a reference failure: evidence is never silently attributed
// to a container it was not observed on. The wire already forbids an item scope
// with a foreign subject uid, so the container is what can differ.
func TestBuildRejectsForeignScope(t *testing.T) {
	const foreignContainer = contract.ContainerName("other-container")
	result, bundle := loadEvaluated(t, "F13-contradictory-evidence")

	foreign := bundle
	foreign.Evidence = append([]contract.EvidenceItem{}, bundle.Evidence...)
	item := foreign.Evidence[0]
	item.Scope.ContainerName = foreignContainer
	foreign.Evidence[0] = item
	hash, err := canonical.HashCanonicalJSON(foreign)
	if err != nil {
		t.Fatalf("foreign bundle does not project: %v", err)
	}
	// The rewritten container moves the item in the canonical order, so the
	// citation is pointed at the index the canonical array actually holds.
	ordered, err := canonicalBundle(foreign)
	if err != nil {
		t.Fatalf("foreign bundle does not canonicalize: %v", err)
	}
	target := -1
	for index, candidate := range ordered.Evidence {
		if candidate.Scope.ContainerName == foreignContainer {
			target = index
			break
		}
	}
	if target < 0 {
		t.Fatalf("the modified item is not in the canonical array")
	}
	// The result keeps exactly one citation, of that foreign item: every other
	// reference of the fixture would resolve against the reordered array and
	// could fail for an unrelated reason, which is what made an earlier version
	// of this test pass with the scope check removed.
	isolated := result
	isolated.BundleHash = hash
	isolated.EvidenceReferences = []evaluator.EvidenceReference{{ItemIndex: target}}
	isolated.Rules = []evaluator.RuleTrace{}
	isolated.Candidates = []evaluator.Candidate{}
	isolated.WarningReferences = []evaluator.WarningReference{}
	if _, err := Build(isolated, foreign); !IsCode(err, CodeInvalidReference) {
		t.Fatalf("Build with a foreign-container citation: got %v, want invalid_reference", err)
	}
}

// TestBuildRejectsOutOfRangeReference pins the bound check: an index beyond the
// canonical evidence array is a reference failure, not an empty row.
func TestBuildRejectsOutOfRangeReference(t *testing.T) {
	result, bundle := loadEvaluated(t, "F13-contradictory-evidence")
	result.EvidenceReferences = append(result.EvidenceReferences, evaluator.EvidenceReference{ItemIndex: len(bundle.Evidence)})
	if _, err := Build(result, bundle); !IsCode(err, CodeInvalidReference) {
		t.Fatalf("Build with an out-of-range reference: got %v, want invalid_reference", err)
	}
}

// TestBuildRejectsOutOfRangeWarning pins the same bound for warnings, including
// the provenance origin, whose index space is the run provenance.
func TestBuildRejectsOutOfRangeWarning(t *testing.T) {
	result, bundle := loadEvaluated(t, "F13-contradictory-evidence")
	result.WarningReferences = []evaluator.WarningReference{
		{Origin: evaluator.WarningFromProvenance, EvidenceIndex: -1, WarningIndex: 0},
	}
	if _, err := Build(result, bundle); !IsCode(err, CodeInvalidReference) {
		t.Fatalf("Build with a provenance warning that does not exist: got %v, want invalid_reference", err)
	}
}

// TestBuildCatalogsResolveExactItems pins the resolution: every row carries the
// citation of the item its reference names, in canonical index order, and the
// duplicates of the references are preserved.
func TestBuildCatalogsResolveExactItems(t *testing.T) {
	result, bundle := loadEvaluated(t, "F13-contradictory-evidence")
	report := mustBuild(t, result, bundle)

	canonicalBundle, err := canonicalBundle(bundle)
	if err != nil {
		t.Fatalf("canonical bundle: %v", err)
	}
	if len(report.evidence) == 0 {
		t.Fatalf("F13 references evidence and must produce rows")
	}
	previous := -1
	for index, row := range report.evidence {
		if row.Reference.ItemIndex < previous {
			t.Fatalf("row %d is out of canonical order", index)
		}
		previous = row.Reference.ItemIndex
		item := canonicalBundle.Evidence[row.Reference.ItemIndex]
		if row.Type != item.Type || row.Source != item.Source || row.Locator != string(item.Locator) {
			t.Errorf("row %d does not cite item %d", index, row.Reference.ItemIndex)
		}
		if row.Confidence != string(item.Confidence) || row.SourceHash != string(item.SourceHash) {
			t.Errorf("row %d does not carry the item provenance", index)
		}
		if row.Scope.SubjectUID != string(item.Scope.SubjectUID) || row.Scope.ContainerName != string(item.Scope.ContainerName) {
			t.Errorf("row %d does not carry the item scope", index)
		}
	}
	if len(report.warnings) != len(result.WarningReferences) {
		t.Fatalf("warnings %d, want %d", len(report.warnings), len(result.WarningReferences))
	}
	for index, row := range report.warnings {
		reference := result.WarningReferences[index]
		if row.Reference.Origin != string(reference.Origin) || row.Reference.EvidenceIndex != reference.EvidenceIndex ||
			row.Reference.WarningIndex != reference.WarningIndex {
			t.Errorf("warning row %d does not carry its own reference", index)
		}
		if row.Message != nil {
			t.Errorf("warning row %d must omit the message", index)
		}
	}
}

// TestBuildPreservesWarningVocabulary pins the taxonomy rule: an unknown code is
// conserved literally and never replaced or dropped, and the class is copied as
// the bundle states it.
func TestBuildPreservesWarningVocabulary(t *testing.T) {
	result, bundle := loadEvaluated(t, "F13-contradictory-evidence")
	report := mustBuild(t, result, bundle)
	var codes, classes []string
	for _, row := range report.warnings {
		codes = append(codes, row.Code)
		classes = append(classes, row.Class)
	}
	joined := strings.Join(codes, ",")
	if !strings.Contains(joined, "synthetic-uninterpretable-code") {
		t.Errorf("the unknown code was not conserved: %v", codes)
	}
	if !strings.Contains(joined, "source_conflict") {
		t.Errorf("the known contradictory code was not conserved: %v", codes)
	}
	if !strings.Contains(strings.Join(classes, ","), "contradictory") {
		t.Errorf("the class was not conserved: %v", classes)
	}
}

// TestBuildPreservesEveryCandidateBranch pins that the presentation never
// selects one branch: F13 sustains two candidates and both are shown.
func TestBuildPreservesEveryCandidateBranch(t *testing.T) {
	result, bundle := loadEvaluated(t, "F13-contradictory-evidence")
	if len(result.Candidates) < 2 {
		t.Fatalf("F13 must sustain more than one candidate, got %d", len(result.Candidates))
	}
	report := mustBuild(t, result, bundle)
	if len(report.result.Candidates) != len(result.Candidates) {
		t.Fatalf("candidates %d, want %d", len(report.result.Candidates), len(result.Candidates))
	}
	for index, candidate := range result.Candidates {
		got := report.result.Candidates[index]
		if got.RuleID != candidate.RuleID || got.ProductStatus != string(candidate.ProductStatus) {
			t.Errorf("candidate %d is %s/%s, want %s/%s", index, got.RuleID, got.ProductStatus, candidate.RuleID, candidate.ProductStatus)
		}
	}
	if report.result.ProductStatus != string(contract.ProductUnderInvestigation) {
		t.Errorf("the global status of F13 must stay inconclusive, got %s", report.result.ProductStatus)
	}
}

// TestJSONIsCompactAndStable pins the JSON grammar: no BOM, no trailing newline,
// no HTML-breaking raw text, and byte-identical output across runs.
func TestJSONIsCompactAndStable(t *testing.T) {
	result, bundle := loadEvaluated(t, "F13-contradictory-evidence")
	report := mustBuild(t, result, bundle)
	first, err := JSON(report)
	if err != nil {
		t.Fatalf("JSON: %v", err)
	}
	second, err := JSON(mustBuild(t, result, bundle))
	if err != nil {
		t.Fatalf("JSON: %v", err)
	}
	if !bytes.Equal(first, second) {
		t.Fatalf("JSON is not deterministic")
	}
	if bytes.HasPrefix(first, []byte{0xEF, 0xBB, 0xBF}) {
		t.Fatalf("JSON carries a BOM")
	}
	if bytes.HasSuffix(first, []byte("\n")) {
		t.Fatalf("JSON carries a trailing newline")
	}
	if bytes.Contains(first, []byte("</")) {
		t.Fatalf("JSON must escape the sequence that could close a tag when embedded")
	}
	if !json.Valid(first) {
		t.Fatalf("JSON is not valid")
	}
	// The decoded document must still carry the exact strings.
	var decoded struct {
		Result struct {
			Target struct {
				SubjectUID string `json:"subject_uid"`
			} `json:"target"`
		} `json:"result"`
	}
	if err := json.Unmarshal(first, &decoded); err != nil {
		t.Fatalf("JSON does not decode: %v", err)
	}
	if decoded.Result.Target.SubjectUID != string(result.Target.SubjectUID) {
		t.Errorf("decoded subject uid %s, want %s", decoded.Result.Target.SubjectUID, result.Target.SubjectUID)
	}
}

// TestJSONEscapesMarkupCharacters pins the ratified encoding rule of ADR-0022
// §D4: the JSON encoder runs with HTML escaping enabled, so a string carrying
// <, > or & is serialized as an escape sequence and cannot close a tag when the
// document is embedded in another one. The decoded value keeps the exact
// characters, so this is presentation and not corruption.
func TestJSONEscapesMarkupCharacters(t *testing.T) {
	result, bundle := loadEvaluated(t, "F13-contradictory-evidence")
	result.Target.Locator = contract.SourceLocator("items[0]<b>&</script>")
	document, err := JSON(mustBuild(t, result, bundle))
	if err != nil {
		t.Fatalf("JSON: %v", err)
	}
	body := string(document)
	for _, raw := range []string{"<", ">", "&"} {
		if strings.Contains(body, raw) {
			t.Errorf("the JSON document carries a raw %q: HTML escaping is not active", raw)
		}
	}
	var decoded struct {
		Result struct {
			Target struct {
				Locator string `json:"locator"`
			} `json:"target"`
		} `json:"result"`
	}
	if err := json.Unmarshal(document, &decoded); err != nil {
		t.Fatalf("the escaped document does not decode: %v", err)
	}
	if decoded.Result.Target.Locator != string(result.Target.Locator) {
		t.Fatalf("decoded locator %q, want %q", decoded.Result.Target.Locator, result.Target.Locator)
	}
}

// TestJSONCarriesEveryResultBranch pins that the JSON envelope exposes both the
// result core and the two catalogs, and that empty collections are arrays.
func TestJSONCarriesEveryResultBranch(t *testing.T) {
	result, bundle := loadEvaluated(t, "F09-unmapped-redhat-package")
	report := mustBuild(t, result, bundle)
	document, err := JSON(report)
	if err != nil {
		t.Fatalf("JSON: %v", err)
	}
	var decoded map[string]json.RawMessage
	if err := json.Unmarshal(document, &decoded); err != nil {
		t.Fatalf("JSON does not decode: %v", err)
	}
	for _, key := range []string{"result", "evidence_catalog", "warning_catalog"} {
		if _, ok := decoded[key]; !ok {
			t.Errorf("the envelope is missing %s", key)
		}
	}
	var envelope struct {
		Result struct {
			Candidates []json.RawMessage `json:"candidates"`
			Reasons    []json.RawMessage `json:"reasons"`
		} `json:"result"`
		Evidence []json.RawMessage `json:"evidence_catalog"`
		Warnings []json.RawMessage `json:"warning_catalog"`
	}
	if err := json.Unmarshal(document, &envelope); err != nil {
		t.Fatalf("JSON does not decode: %v", err)
	}
	// F09 has no affirmative candidate and no warning: the empty collections must
	// still be arrays, not null.
	if strings.Contains(string(document), `"candidates":null`) || strings.Contains(string(document), `"warning_catalog":null`) {
		t.Fatalf("empty collections must be arrays, never null")
	}
}

// TestJSONOmitsEveryValue pins the T7 rule of the presentation: no evidence
// value and no warning message reaches the report, not even the ones that exist
// in the bundle.
// TestJSONOmitsEveryValue pins the T7 rule of the presentation: no evidence
// value and no warning message reaches the report. Distinctive markers are
// injected into a bundle that stays valid, so their absence from the bytes is a
// property of the renderer and not of the fixture vocabulary — a value that
// coincides with a status name would give a false positive.
func TestJSONOmitsEveryValue(t *testing.T) {
	const valueMarker = "sensitive-value-marker-7f3a"
	const messageMarker = "sensitive-message-marker-7f3a"
	result, bundle := loadEvaluated(t, "F13-contradictory-evidence")

	modified := bundle
	modified.Evidence = append([]contract.EvidenceItem{}, bundle.Evidence...)
	item := modified.Evidence[0]
	item.Value = pointer(valueMarker)
	if item.ValueHash == nil {
		hash := contract.ValueHash("sha256:" + strings.Repeat("ab", 32))
		item.ValueHash = &hash
	}
	modified.Evidence[0] = item
	modified.Provenance.Warnings = []contract.Warning{
		{Code: "provenance-marker", Class: contract.WarningInformational, Message: messageMarker},
	}

	hash, err := canonical.HashCanonicalJSON(modified)
	if err != nil {
		t.Fatalf("modified bundle does not project: %v", err)
	}
	result.BundleHash = hash
	// The item is referenced so that its citation is presented, and the warning
	// so that its code and class are.
	result.EvidenceReferences = append(result.EvidenceReferences, evaluator.EvidenceReference{ItemIndex: 0})
	result.WarningReferences = append(result.WarningReferences, evaluator.WarningReference{
		Origin: evaluator.WarningFromProvenance, EvidenceIndex: -1, WarningIndex: 0,
	})

	report := mustBuild(t, result, modified)
	document, err := JSON(report)
	if err != nil {
		t.Fatalf("JSON: %v", err)
	}
	documentHTML, err := HTML(report)
	if err != nil {
		t.Fatalf("HTML: %v", err)
	}
	for _, output := range [][]byte{document, documentHTML} {
		if bytes.Contains(output, []byte(valueMarker)) {
			t.Fatalf("an evidence value reached the report")
		}
		if bytes.Contains(output, []byte(messageMarker)) {
			t.Fatalf("a warning message reached the report")
		}
	}
	if !bytes.Contains(document, []byte(`"item_index":0`)) {
		t.Errorf("the citation of the referenced item must be presented")
	}
	if !bytes.Contains(document, []byte("provenance-marker")) {
		t.Errorf("the warning code must be conserved")
	}
	if bytes.Contains(document, []byte(`"value":`)) || bytes.Contains(document, []byte(`"argv_sanitized":`)) {
		t.Errorf("the report carries a member the contract excludes")
	}
}

// TestHTMLIsStandaloneAndStable pins the HTML grammar: doctype, UTF-8, a static
// title, one trailing newline and byte-identical output across runs.
func TestHTMLIsStandaloneAndStable(t *testing.T) {
	result, bundle := loadEvaluated(t, "F13-contradictory-evidence")
	first, err := HTML(mustBuild(t, result, bundle))
	if err != nil {
		t.Fatalf("HTML: %v", err)
	}
	second, err := HTML(mustBuild(t, result, bundle))
	if err != nil {
		t.Fatalf("HTML: %v", err)
	}
	if !bytes.Equal(first, second) {
		t.Fatalf("HTML is not deterministic")
	}
	body := string(first)
	if !strings.HasPrefix(body, "<!doctype html>") {
		t.Errorf("HTML does not start with the doctype")
	}
	if !strings.Contains(body, `<html lang="en">`) || !strings.Contains(body, `<meta charset="utf-8">`) {
		t.Errorf("HTML does not declare language and charset")
	}
	if !strings.Contains(body, "<title>Ariadne evaluation report</title>") {
		t.Errorf("HTML does not carry the static title")
	}
	if !strings.HasSuffix(body, "\n") {
		t.Errorf("HTML must end with a newline")
	}
	if strings.Contains(body, "<script") || strings.Contains(body, "javascript:") {
		t.Errorf("HTML must not carry script or javascript URLs")
	}
}

// TestHTMLShowsEveryLayerSeparately pins that the three decision layers are
// presented apart and that the risk decision is shown as absent.
func TestHTMLShowsEveryLayerSeparately(t *testing.T) {
	result, bundle := loadEvaluated(t, "F10-redhat-backport")
	document, err := HTML(mustBuild(t, result, bundle))
	if err != nil {
		t.Fatalf("HTML: %v", err)
	}
	body := string(document)
	for _, marker := range []string{
		"Product status (technical)",
		"Exploitability (local profile, not a VEX field)",
		"Risk decision (human governance)",
		"No human risk decision is present in this evaluator result.",
		"the replay parameter the caller supplied",
	} {
		if !strings.Contains(body, marker) {
			t.Errorf("HTML is missing %q", marker)
		}
	}
	if !strings.Contains(body, string(result.ProductStatus)) {
		t.Errorf("HTML does not show the technical status")
	}
}

// TestHTMLEscapesEveryContext pins T3 and XSS: a hostile string is shown as
// inert text. The offset that matters is not which entity the template chose but
// that the document carries the payload as text, creates no script element and
// builds no URL out of data.
func TestHTMLEscapesEveryContext(t *testing.T) {
	result, bundle := loadEvaluated(t, "F13-contradictory-evidence")
	hostile := `<script>alert(1)</script>&"' onerror=javascript:alert(2)`
	result.Target.Source = hostile
	document, err := HTML(mustBuild(t, result, bundle))
	if err != nil {
		t.Fatalf("HTML: %v", err)
	}
	body := string(document)
	if strings.Contains(strings.ToLower(body), "<script") {
		t.Fatalf("a script element was emitted")
	}
	if strings.Contains(strings.ToLower(body), "<iframe") || strings.Contains(strings.ToLower(body), "<object") {
		t.Fatalf("an embedding element was emitted")
	}
	// The payload survived as text: decoding the entities must reproduce it.
	if !strings.Contains(html.UnescapeString(body), "alert(1)") {
		t.Fatalf("the payload text was altered")
	}
	// Every URL in the document is an internal anchor derived from an index,
	// never a value taken from the report.
	for _, match := range hrefPattern.FindAllStringSubmatch(body, -1) {
		if !strings.HasPrefix(match[1], "#") {
			t.Fatalf("the document carries a non-internal URL: %s", match[1])
		}
	}
}

// TestHTMLKeepsFormulaPrefixesAsText pins the T3 scope of this contract: every
// spreadsheet formula prefix is inert text. The value is preserved as text —
// the template may encode characters, and decoding must restore them — and no
// prefix is rewritten or apostrophe-prefixed. The contract claims no protection
// when these files are later imported into a spreadsheet.
func TestHTMLKeepsFormulaPrefixesAsText(t *testing.T) {
	result, bundle := loadEvaluated(t, "F13-contradictory-evidence")
	payloads := []string{"=1+1", "+SUM(A1)", "-2", "@import", " =1+1", "\t=cmd", "\n=cmd", "\r=cmd"}
	for _, payload := range payloads {
		result.Target.Source = payload
		document, err := HTML(mustBuild(t, result, bundle))
		if err != nil {
			t.Fatalf("HTML: %v", err)
		}
		decoded := html.UnescapeString(string(document))
		if !strings.Contains(decoded, payload) {
			t.Errorf("the prefix %q was altered instead of shown as inert text", payload)
		}
		if strings.Contains(string(document), "'"+payload) {
			t.Errorf("the prefix %q was apostrophe-prefixed", payload)
		}
	}
}

// TestEncodersDoNotTouchCallerState pins the immutability rule: encoding never
// reorders nor rewrites what the caller owns.
func TestEncodersDoNotTouchCallerState(t *testing.T) {
	result, bundle := loadEvaluated(t, "F13-contradictory-evidence")
	before := cloneResult(t, result)
	report := mustBuild(t, result, bundle)
	if _, err := JSON(report); err != nil {
		t.Fatalf("JSON: %v", err)
	}
	if _, err := HTML(report); err != nil {
		t.Fatalf("HTML: %v", err)
	}
	after := cloneResult(t, result)
	if !sameResult(before, after) {
		t.Fatalf("the encoders modified the caller's result")
	}
	// Mutating the caller's slices after Build must not change the report.
	result.Target.Source = "rewritten"
	result.Reasons = append(result.Reasons, evaluator.ReasonNoApplicableRule)
	document, err := JSON(report)
	if err != nil {
		t.Fatalf("JSON: %v", err)
	}
	if strings.Contains(string(document), "rewritten") || strings.Contains(string(document), "no_applicable_rule") {
		t.Fatalf("the report holds a live reference to the caller's state")
	}
}

// TestBuildIsConcurrentAndImmutable pins M11: several goroutines rendering the
// same report, and one building from a stable input, produce byte-identical
// output. It is the test the -race gate exercises.
func TestBuildIsConcurrentAndImmutable(t *testing.T) {
	result, bundle := loadEvaluated(t, "F09-unmapped-redhat-package")
	report := mustBuild(t, result, bundle)
	wantJSON, err := JSON(report)
	if err != nil {
		t.Fatalf("JSON: %v", err)
	}
	wantHTML, err := HTML(report)
	if err != nil {
		t.Fatalf("HTML: %v", err)
	}
	const workers = 8
	done := make(chan struct{}, workers)
	failures := make(chan string, workers)
	for worker := 0; worker < workers; worker++ {
		go func() {
			defer func() { done <- struct{}{} }()
			document, err := JSON(report)
			if err != nil {
				failures <- "JSON: " + err.Error()
				return
			}
			if !bytes.Equal(document, wantJSON) {
				failures <- "JSON bytes differ across goroutines"
				return
			}
			page, err := HTML(report)
			if err != nil {
				failures <- "HTML: " + err.Error()
				return
			}
			if !bytes.Equal(page, wantHTML) {
				failures <- "HTML bytes differ across goroutines"
				return
			}
			fresh, err := Build(result, bundle)
			if err != nil {
				failures <- "Build: " + err.Error()
				return
			}
			freshJSON, err := JSON(fresh)
			if err != nil {
				failures <- "JSON: " + err.Error()
				return
			}
			if !bytes.Equal(freshJSON, wantJSON) {
				failures <- "a concurrent build produced different bytes"
			}
		}()
	}
	for worker := 0; worker < workers; worker++ {
		<-done
	}
	close(failures)
	for failure := range failures {
		t.Error(failure)
	}
}

// TestBuildIsDeterministicAcrossBuilds pins that two builds of the same input
// produce identical bytes in both formats.
func TestBuildIsDeterministicAcrossBuilds(t *testing.T) {
	result, bundle := loadEvaluated(t, "F10-redhat-backport")
	first := mustBuild(t, result, bundle)
	second := mustBuild(t, result, bundle)
	firstJSON, err := JSON(first)
	if err != nil {
		t.Fatalf("JSON: %v", err)
	}
	secondJSON, err := JSON(second)
	if err != nil {
		t.Fatalf("JSON: %v", err)
	}
	if !bytes.Equal(firstJSON, secondJSON) {
		t.Fatalf("two builds of the same input are not byte-identical")
	}
}

// TestBuildTreatsAConservativeProfileWithoutDomain pins the profile
// combination of the legacy profile: no domain context, no candidates and no
// affirmative status, which is exactly what the evaluator produces there.
func TestBuildTreatsAConservativeProfileWithoutDomain(t *testing.T) {
	result, bundle := loadEvaluated(t, "F13-contradictory-evidence")
	result.ProfileVersion = rulepack.SupportedProfile
	result.Domain = nil
	result.Candidates = nil
	result.ProductStatus = contract.ProductUnderInvestigation
	report, err := Build(result, bundle)
	if err != nil {
		t.Fatalf("the conservative combination must be accepted: %v", err)
	}
	if report.result.RiskDecision != nil || report.result.Domain != nil {
		t.Fatalf("the conservative report must carry no domain and no risk decision")
	}
	document, err := JSON(report)
	if err != nil {
		t.Fatalf("JSON: %v", err)
	}
	if !strings.Contains(string(document), `"domain":null`) {
		t.Errorf("the domain must be an explicit null in this profile")
	}
}

// TestErrorsAreStatic pins that no diagnostic carries input: the rendered
// message is the closed code and, at most, a bounded index.
func TestErrorsAreStatic(t *testing.T) {
	result, bundle := loadEvaluated(t, "F13-contradictory-evidence")
	result.Target.Source = "sensitive-marker"
	result.Reasons = []evaluator.Reason{"made_up"}
	_, err := Build(result, bundle)
	if err == nil {
		t.Fatalf("the fabricated result must be rejected")
	}
	message := err.Error()
	if strings.Contains(message, "sensitive-marker") || strings.Contains(message, "made_up") {
		t.Fatalf("the diagnostic leaked input: %s", message)
	}
	var reportError *Error
	if !errors.As(err, &reportError) {
		t.Fatalf("the failure is not a static report error")
	}
	if reportError.Code != CodeInvalidResult {
		t.Fatalf("code %s, want %s", reportError.Code, CodeInvalidResult)
	}
}
