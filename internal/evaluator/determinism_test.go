package evaluator

import (
	"crypto/sha256"
	"encoding/json"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/d4rpell/Ariadne/internal/rulepack"
	contract "github.com/d4rpell/Ariadne/pkg/evidence"
)

// resultDTO is a test-only encoding of Result: every field, in the order of
// ADR-0013 §7, sorted arrays, fixed object order, no maps and no clock. It is
// never a public format and its hash is never bundle.sha256.
type resultDTO struct {
	EngineVersion      string          `json:"engine_version"`
	ProfileVersion     string          `json:"profile_version"`
	BundleHash         string          `json:"bundle_hash"`
	PackID             string          `json:"pack_id"`
	PackVersion        int64           `json:"pack_version"`
	PackHash           string          `json:"pack_hash"`
	Target             targetDTO       `json:"target"`
	Admission          admissionDTO    `json:"admission"`
	Domain             *domainDTO      `json:"domain"`
	ProductStatus      string          `json:"product_status"`
	Exploitability     string          `json:"exploitability"`
	Reasons            []string        `json:"reasons"`
	Rules              []ruleTraceDTO  `json:"rules"`
	Candidates         []candidateDTO  `json:"candidates"`
	EvidenceReferences []int           `json:"evidence_references"`
	WarningReferences  []warningRefDTO `json:"warning_references"`
}

// domainDTO covers every leaf of DomainContext and every pin field, including
// the explicit nulls of the advisory pair.
type domainDTO struct {
	MaximumEvidenceAgeSeconds int64    `json:"maximum_evidence_age_seconds"`
	SourcePins                []pinDTO `json:"source_pins"`
}

type pinDTO struct {
	Role             string  `json:"role"`
	Source           string  `json:"source"`
	SourceHash       string  `json:"source_hash"`
	AdvisoryID       *string `json:"advisory_id"`
	AdvisoryRevision *string `json:"advisory_revision"`
}

type candidateDTO struct {
	RuleID             string `json:"rule_id"`
	ProductStatus      string `json:"product_status"`
	EvidenceReferences []int  `json:"evidence_references"`
}

type targetDTO struct {
	SubjectUID      string `json:"subject_uid"`
	ContainerClass  string `json:"container_class"`
	ContainerName   string `json:"container_name"`
	VulnerabilityID string `json:"vulnerability_id"`
	Source          string `json:"source"`
	SourceHash      string `json:"source_hash"`
	Locator         string `json:"locator"`
	ObservedAt      string `json:"observed_at"`
}

type admissionDTO struct {
	EvaluatedAt      string `json:"evaluated_at"`
	ExpectedPackID   string `json:"expected_pack_id"`
	ExpectedPackHash string `json:"expected_pack_hash"`
	MinimumVersion   int64  `json:"minimum_version"`
	HasPrevious      bool   `json:"has_previous"`
	PreviousVersion  int64  `json:"previous_version"`
	PreviousHash     string `json:"previous_hash"`
}

type ruleTraceDTO struct {
	RuleID              string          `json:"rule_id"`
	State               string          `json:"state"`
	MissingRequirements []string        `json:"missing_requirements"`
	Checks              []checkTraceDTO `json:"checks"`
	Reasons             []string        `json:"reasons"`
	EvidenceReferences  []int           `json:"evidence_references"`
}

type checkTraceDTO struct {
	CheckID            string   `json:"check_id"`
	Outcome            string   `json:"outcome"`
	Reasons            []string `json:"reasons"`
	EvidenceReferences []int    `json:"evidence_references"`
}

type warningRefDTO struct {
	Origin        string `json:"origin"`
	EvidenceIndex int    `json:"evidence_index"`
	WarningIndex  int    `json:"warning_index"`
}

func dtoFromResult(result Result) resultDTO {
	dto := resultDTO{
		EngineVersion:  result.EngineVersion,
		ProfileVersion: result.ProfileVersion,
		BundleHash:     result.BundleHash,
		PackID:         result.PackID,
		PackVersion:    result.PackVersion,
		PackHash:       result.PackHash,
		Target: targetDTO{
			SubjectUID:      string(result.Target.SubjectUID),
			ContainerClass:  string(result.Target.ContainerClass),
			ContainerName:   string(result.Target.ContainerName),
			VulnerabilityID: result.Target.VulnerabilityID,
			Source:          result.Target.Source,
			SourceHash:      string(result.Target.SourceHash),
			Locator:         string(result.Target.Locator),
			ObservedAt:      result.Target.ObservedAt.UTC().Format(time.RFC3339Nano),
		},
		Admission: admissionDTO{
			EvaluatedAt:      result.Admission.EvaluatedAt.UTC().Format(time.RFC3339Nano),
			ExpectedPackID:   result.Admission.ExpectedPackID,
			ExpectedPackHash: result.Admission.ExpectedPackHash,
			MinimumVersion:   result.Admission.MinimumVersion,
		},
		Domain:             domainFromResult(result.Domain),
		ProductStatus:      string(result.ProductStatus),
		Exploitability:     string(result.Exploitability),
		Reasons:            globalReasonStrings(result.Reasons),
		Rules:              make([]ruleTraceDTO, 0, len(result.Rules)),
		Candidates:         make([]candidateDTO, 0, len(result.Candidates)),
		EvidenceReferences: referenceIndices(result.EvidenceReferences),
		WarningReferences:  make([]warningRefDTO, 0, len(result.WarningReferences)),
	}
	if previous := result.Admission.Previous; previous != nil {
		dto.Admission.HasPrevious = true
		dto.Admission.PreviousVersion = previous.Version
		dto.Admission.PreviousHash = previous.Hash
	}
	for _, trace := range result.Rules {
		rule := ruleTraceDTO{
			RuleID:              trace.RuleID,
			State:               string(trace.State),
			MissingRequirements: make([]string, 0, len(trace.MissingRequirements)),
			Checks:              make([]checkTraceDTO, 0, len(trace.Checks)),
			Reasons:             reasonStrings(trace.Reasons),
			EvidenceReferences:  referenceIndices(trace.EvidenceReferences),
		}
		for _, requirement := range trace.MissingRequirements {
			rule.MissingRequirements = append(rule.MissingRequirements, string(requirement))
		}
		for _, check := range trace.Checks {
			rule.Checks = append(rule.Checks, checkTraceDTO{
				CheckID:            check.CheckID,
				Outcome:            string(check.Outcome),
				Reasons:            reasonStrings(check.Reasons),
				EvidenceReferences: referenceIndices(check.EvidenceReferences),
			})
		}
		dto.Rules = append(dto.Rules, rule)
	}
	for _, candidate := range result.Candidates {
		dto.Candidates = append(dto.Candidates, candidateDTO{
			RuleID:             candidate.RuleID,
			ProductStatus:      string(candidate.ProductStatus),
			EvidenceReferences: referenceIndices(candidate.EvidenceReferences),
		})
	}
	for _, reference := range result.WarningReferences {
		dto.WarningReferences = append(dto.WarningReferences, warningRefDTO{
			Origin:        string(reference.Origin),
			EvidenceIndex: reference.EvidenceIndex,
			WarningIndex:  reference.WarningIndex,
		})
	}
	return dto
}

// domainFromResult encodes the domain context leaf by leaf; a nil context stays
// a JSON null, which is the legacy absence and not a zero TTL.
func domainFromResult(context *DomainContext) *domainDTO {
	if context == nil {
		return nil
	}
	dto := &domainDTO{
		MaximumEvidenceAgeSeconds: context.MaximumEvidenceAgeSeconds,
		SourcePins:                make([]pinDTO, 0, len(context.SourcePins)),
	}
	for _, pin := range context.SourcePins {
		dto.SourcePins = append(dto.SourcePins, pinDTO{
			Role:             string(pin.Role),
			Source:           pin.Source,
			SourceHash:       string(pin.SourceHash),
			AdvisoryID:       copyPointer(pin.AdvisoryID),
			AdvisoryRevision: copyPointer(pin.AdvisoryRevision),
		})
	}
	return dto
}

func globalReasonStrings(reasons []Reason) []string {
	values := make([]string, 0, len(reasons))
	for _, reason := range reasons {
		values = append(values, string(reason))
	}
	return values
}

func reasonStrings(reasons []CheckReason) []string {
	values := make([]string, 0, len(reasons))
	for _, reason := range reasons {
		values = append(values, string(reason))
	}
	return values
}

func referenceIndices(references []EvidenceReference) []int {
	values := make([]int, 0, len(references))
	for _, reference := range references {
		values = append(values, reference.ItemIndex)
	}
	return values
}

func encodeResultDTO(t *testing.T, result Result) []byte {
	t.Helper()
	encoded, err := json.Marshal(dtoFromResult(result))
	if err != nil {
		t.Fatalf("the test encoding failed: %v", err)
	}
	return encoded
}

// TestResultTestEncodingCoverage fails when a Result field is added without
// being represented in the test DTO: the list below is the contract of this
// encoding, not a convenience.
func TestResultTestEncodingCoverage(t *testing.T) {
	declared := []string{
		"EngineVersion", "ProfileVersion", "BundleHash", "PackID", "PackVersion", "PackHash",
		"Target", "Admission", "Domain", "ProductStatus", "Exploitability", "Reasons", "Rules",
		"Candidates", "EvidenceReferences", "WarningReferences",
	}
	resultType := reflect.TypeOf(Result{})
	if resultType.NumField() != len(declared) {
		t.Fatalf("Result has %d fields, the test encoding declares %d", resultType.NumField(), len(declared))
	}
	for index, name := range declared {
		if resultType.Field(index).Name != name {
			t.Fatalf("Result field %d is %s, the test encoding expects %s", index, resultType.Field(index).Name, name)
		}
	}
}

// TestEvaluationDeterminism is I-20: repetitions and concurrent evaluations of
// one immutable request produce the identical result and the identical test
// encoding.
func TestEvaluationDeterminism(t *testing.T) {
	request := baseRequest(t)
	control := evaluate(t, request)
	controlBytes := encodeResultDTO(t, control)

	for repetition := 0; repetition < 100; repetition++ {
		candidate := evaluate(t, request)
		if !reflect.DeepEqual(control, candidate) {
			t.Fatalf("repetition %d differs from the control result", repetition)
		}
		if string(encodeResultDTO(t, candidate)) != string(controlBytes) {
			t.Fatalf("repetition %d differs byte to byte", repetition)
		}
	}

	const workers = 16
	var wait sync.WaitGroup
	results := make([][]byte, workers)
	structures := make([]Result, workers)
	failures := make([]error, workers)
	for worker := 0; worker < workers; worker++ {
		wait.Add(1)
		go func(index int) {
			defer wait.Done()
			result, err := Evaluate(request)
			if err != nil {
				failures[index] = err
				return
			}
			structures[index] = result
			encoded, err := json.Marshal(dtoFromResult(result))
			if err != nil {
				failures[index] = err
				return
			}
			results[index] = encoded
		}(worker)
	}
	wait.Wait()
	for index := 0; index < workers; index++ {
		if failures[index] != nil {
			t.Fatalf("concurrent evaluation %d failed: %v", index, failures[index])
		}
		if !reflect.DeepEqual(control, structures[index]) {
			t.Fatalf("concurrent evaluation %d differs structurally from the control", index)
		}
		if string(results[index]) != string(controlBytes) {
			t.Fatalf("concurrent evaluation %d differs from the control", index)
		}
	}
}

// TestEvaluationCanonicalPermutations is I-21: permutations that are equivalent
// under the canonical order leave the result and its references unchanged, and
// duplicates are never collapsed.
func TestEvaluationCanonicalPermutations(t *testing.T) {
	request := baseRequest(t)
	control := string(encodeResultDTO(t, evaluate(t, request)))

	t.Run("reversed evidence", func(t *testing.T) {
		reversed := mutateRequest(t, request, func(bundle *contract.Bundle) {
			items := bundle.Evidence
			flipped := make([]contract.EvidenceItem, 0, len(items))
			for index := len(items) - 1; index >= 0; index-- {
				flipped = append(flipped, items[index])
			}
			bundle.Evidence = flipped
		})
		if encoded := string(encodeResultDTO(t, evaluate(t, reversed))); encoded != control {
			t.Fatalf("reversing the evidence array changed the result")
		}
	})

	t.Run("reversed identical duplicates", func(t *testing.T) {
		forward := mutateRequest(t, request, func(bundle *contract.Bundle) {
			for _, item := range bundle.Evidence {
				if item.Type == "prisma_v1.package_name" {
					bundle.Evidence = append(bundle.Evidence, item)
				}
			}
		})
		flipped := mutateRequest(t, forward, func(bundle *contract.Bundle) {
			items := bundle.Evidence
			reversed := make([]contract.EvidenceItem, 0, len(items))
			for index := len(items) - 1; index >= 0; index-- {
				reversed = append(reversed, items[index])
			}
			bundle.Evidence = reversed
		})
		if encoded := string(encodeResultDTO(t, evaluate(t, flipped))); encoded != string(encodeResultDTO(t, evaluate(t, forward))) {
			t.Fatalf("a permutation of identical duplicates changed the result")
		}
	})

	t.Run("reversed warnings of one item", func(t *testing.T) {
		first := mutateRequest(t, request, func(bundle *contract.Bundle) {
			for index := range bundle.Evidence {
				if bundle.Evidence[index].Type == "prisma_v1.package_id" {
					bundle.Evidence[index].Warnings = []contract.Warning{
						{Code: "stale_observation", Class: contract.WarningInformational, Message: "stale"},
						{Code: "partial_observation", Class: contract.WarningInformational, Message: "partial"},
					}
				}
			}
		})
		second := mutateRequest(t, first, func(bundle *contract.Bundle) {
			for index := range bundle.Evidence {
				if bundle.Evidence[index].Type == "prisma_v1.package_id" {
					warnings := bundle.Evidence[index].Warnings
					bundle.Evidence[index].Warnings = []contract.Warning{warnings[1], warnings[0]}
				}
			}
		})
		encodedFirst := string(encodeResultDTO(t, evaluate(t, first)))
		encodedSecond := string(encodeResultDTO(t, evaluate(t, second)))
		if encodedFirst != encodedSecond {
			t.Fatalf("the canonical order of warnings must not depend on the input order")
		}
		if !strings.Contains(encodedFirst, `"warning_references"`) {
			t.Fatalf("the warning references are missing from the encoding")
		}
	})
}

// TestEvaluationReplayIdentity is I-23: every semantic input is visible either in
// the input fingerprint of the result, in the result itself or in a rejection.
func TestEvaluationReplayIdentity(t *testing.T) {
	request := baseRequest(t)
	control := evaluate(t, request)

	t.Run("pack version", func(t *testing.T) {
		bumped := packWith(t, request, baseRules())
		bumped.PackBytes = []byte(strings.Replace(string(bumped.PackBytes), `"version":7`, `"version":8`, 1))
		bumped.Admission = baseContext(t, string(bumped.PackBytes))
		result := evaluate(t, bumped)
		if result.PackVersion == control.PackVersion {
			t.Fatalf("a version change must be visible in the result")
		}
	})

	t.Run("pack bytes", func(t *testing.T) {
		spaced := packWith(t, request, baseRules())
		spaced.PackBytes = append([]byte{}, append(spaced.PackBytes, ' ')...)
		spaced.Admission = baseContext(t, string(spaced.PackBytes))
		result := evaluate(t, spaced)
		if result.PackHash == control.PackHash {
			t.Fatalf("a byte change must be visible in the pack identity")
		}
	})

	t.Run("bundle value", func(t *testing.T) {
		changed := mutateRequest(t, request, func(bundle *contract.Bundle) {
			for index := range bundle.Evidence {
				if bundle.Evidence[index].Type == "prisma_v1.package_name" {
					bundle.Evidence[index].Value = strPointer("libcrypto")
					hash := independentValueHash("libcrypto")
					bundle.Evidence[index].ValueHash = &hash
				}
			}
		})
		result := evaluate(t, changed)
		if result.BundleHash == control.BundleHash {
			t.Fatalf("a covered field change must change the bundle hash")
		}
	})

	t.Run("operational metadata inside the hash", func(t *testing.T) {
		changed := mutateRequest(t, request, func(bundle *contract.Bundle) {
			bundle.Provenance.RedactionPolicy = "other-v1"
		})
		result := evaluate(t, changed)
		if result.BundleHash == control.BundleHash {
			t.Fatalf("a provenance claim must be covered by the projection hash")
		}
	})

	t.Run("evaluation instant", func(t *testing.T) {
		shifted := request
		stamp := mustStamp(t, evaluatedAt.Add(time.Hour))
		shifted.Admission.EvaluatedAt = stamp
		result := evaluate(t, shifted)
		if !result.Admission.EvaluatedAt.Equal(shifted.Admission.EvaluatedAt.Time) {
			t.Fatalf("the evaluation instant must be part of the replay identity")
		}
	})

	t.Run("target", func(t *testing.T) {
		moved := request
		moved.Target.ObservedAt = mustStamp(t, sourceObservedAt.Add(time.Minute))
		result := evaluate(t, moved)
		if result.Target.ObservedAt.Equal(control.Target.ObservedAt.Time) {
			t.Fatalf("the target must be part of the result")
		}
		if !resultReason(result, ReasonRequirementsMissing) {
			t.Fatalf("a target of another row cannot be substantiated: %v", result.Reasons)
		}
	})

	t.Run("admission policy", func(t *testing.T) {
		tightened := request
		tightened.Admission.MinimumVersion = 8
		if _, err := Evaluate(tightened); !rulepack.Is(err, rulepack.CodePackDowngrade) {
			t.Fatalf("a stricter policy must reject a lower version, got %v", err)
		}
	})
}

// TestResultTestEncodingDetectsFieldChanges is the guard the review asked for:
// every field of Result, nested members included, must be represented in the test
// encoding, so omitting one of them from the DTO fails here.
func TestResultTestEncodingDetectsFieldChanges(t *testing.T) {
	request := baseRequest(t)
	control := string(encodeResultDTO(t, evaluate(t, request)))

	changes := []struct {
		name   string
		change func(*Result)
	}{
		{"EngineVersion", func(r *Result) { r.EngineVersion = "9.9.9" }},
		{"ProfileVersion", func(r *Result) { r.ProfileVersion = "other-profile" }},
		{"BundleHash", func(r *Result) { r.BundleHash = "sha256:" + strings.Repeat("a", 64) }},
		{"PackID", func(r *Result) { r.PackID = "pack.other" }},
		{"PackVersion", func(r *Result) { r.PackVersion = 999 }},
		{"PackHash", func(r *Result) { r.PackHash = "sha256:" + strings.Repeat("b", 64) }},
		{"Target.SubjectUID", func(r *Result) { r.Target.SubjectUID = "uid-z" }},
		{"Target.ContainerClass", func(r *Result) { r.Target.ContainerClass = contract.ContainerInit }},
		{"Target.ContainerName", func(r *Result) { r.Target.ContainerName = "sidecar" }},
		{"Target.VulnerabilityID", func(r *Result) { r.Target.VulnerabilityID = cveOther }},
		{"Target.Source", func(r *Result) { r.Target.Source = "other.csv" }},
		{"Target.SourceHash", func(r *Result) { r.Target.SourceHash = contract.SourceHash(sourceHashPod) }},
		{"Target.Locator", func(r *Result) { r.Target.Locator = "record/9/bytes/0-40" }},
		{"Target.ObservedAt", func(r *Result) { r.Target.ObservedAt = mustStamp(t, sourceObservedAt.Add(time.Hour)) }},
		{"Admission.EvaluatedAt", func(r *Result) { r.Admission.EvaluatedAt = mustStamp(t, evaluatedAt.Add(time.Hour)) }},
		{"Admission.ExpectedPackID", func(r *Result) { r.Admission.ExpectedPackID = "pack.other" }},
		{"Admission.ExpectedPackHash", func(r *Result) { r.Admission.ExpectedPackHash = "sha256:" + strings.Repeat("c", 64) }},
		{"Admission.MinimumVersion", func(r *Result) { r.Admission.MinimumVersion = 4 }},
		{"Admission.Previous present", func(r *Result) {
			r.Admission.Previous = &rulepack.PreviousVersion{Version: 5, Hash: "sha256:" + strings.Repeat("d", 64)}
		}},
		{"ProductStatus", func(r *Result) { r.ProductStatus = contract.ProductAffected }},
		{"Exploitability", func(r *Result) { r.Exploitability = contract.ExploitabilityConditionsNotMet }},
		{"Reasons", func(r *Result) { r.Reasons = append(r.Reasons, Reason("zzz_extra")) }},
		{"Rules.RuleID", func(r *Result) { r.Rules[0].RuleID = "zzz" }},
		{"Rules.State", func(r *Result) { r.Rules[0].State = RuleNotApplicable }},
		{"Rules.MissingRequirements", func(r *Result) {
			// Only this leaf changes: the state stays whatever the control had.
			r.Rules[0].MissingRequirements = []rulepack.Requirement{rulepack.RequirementFindingRow}
		}},
		{"Rules.Checks.CheckID", func(r *Result) { r.Rules[ruleIndex(t, r, "rule.b")].Checks[0].CheckID = "zzz" }},
		{"Rules.Checks.Outcome", func(r *Result) { r.Rules[ruleIndex(t, r, "rule.b")].Checks[0].Outcome = OutcomeFail }},
		{"Rules.Checks.Reasons", func(r *Result) { r.Rules[ruleIndex(t, r, "rule.b")].Checks[0].Reasons = []CheckReason{ReasonMismatch} }},
		{"Rules.Checks.EvidenceReferences", func(r *Result) {
			index := ruleIndex(t, r, "rule.b")
			r.Rules[index].Checks[0].EvidenceReferences = append(r.Rules[index].Checks[0].EvidenceReferences, EvidenceReference{ItemIndex: 99})
		}},
		{"Rules.Reasons", func(r *Result) { r.Rules[0].Reasons = append(r.Rules[0].Reasons, ReasonMismatch) }},
		{"Rules.EvidenceReferences", func(r *Result) {
			r.Rules[0].EvidenceReferences = append(r.Rules[0].EvidenceReferences, EvidenceReference{ItemIndex: 99})
		}},
		{"EvidenceReferences", func(r *Result) { r.EvidenceReferences = append(r.EvidenceReferences, EvidenceReference{ItemIndex: 99}) }},
		{"WarningReferences present", func(r *Result) {
			r.WarningReferences = append(r.WarningReferences, WarningReference{Origin: WarningFromEvidence, EvidenceIndex: 0, WarningIndex: 0})
		}},
	}
	// Leaves with a value already present in the control: changing one of them
	// must change the encoding on its own, which proves the DTO carries it.
	leaves := []struct {
		name   string
		base   func() Result
		change func(*Result)
	}{
		{"Admission.Previous.Version", func() Result { return previousResult(t, request) }, func(r *Result) { r.Admission.Previous.Version = 99 }},
		{"Admission.Previous.Hash", func() Result { return previousResult(t, request) }, func(r *Result) { r.Admission.Previous.Hash = "sha256:" + strings.Repeat("e", 64) }},
		{"WarningReferences.Origin", func() Result { return warnedResult(t, request) }, func(r *Result) { r.WarningReferences[0].Origin = WarningFromEvidence }},
		{"WarningReferences.EvidenceIndex", func() Result { return warnedResult(t, request) }, func(r *Result) { r.WarningReferences[0].EvidenceIndex = 7 }},
		{"WarningReferences.WarningIndex", func() Result { return warnedResult(t, request) }, func(r *Result) { r.WarningReferences[0].WarningIndex = 7 }},
		{"Rules.MissingRequirements value", func() Result { return missingResult(t, request) }, func(r *Result) {
			// One existing element changes and the length stays: a DTO that kept the
			// count while blanking the values would still be detected.
			if len(r.Rules[0].MissingRequirements) < 2 {
				t.Fatalf("the fixture must leave two missing requirements")
			}
			r.Rules[0].MissingRequirements[0] = rulepack.RequirementImageBoundDigest
		}},
	}
	for _, testCase := range changes {
		t.Run(testCase.name, func(t *testing.T) {
			result := evaluate(t, request)
			testCase.change(&result)
			if encoded := string(encodeResultDTO(t, result)); encoded == control {
				t.Fatalf("%s is not represented in the test encoding", testCase.name)
			}
		})
	}
	for _, testCase := range leaves {
		t.Run(testCase.name, func(t *testing.T) {
			base := testCase.base()
			baseline := string(encodeResultDTO(t, base))
			testCase.change(&base)
			if encoded := string(encodeResultDTO(t, base)); encoded == baseline {
				t.Fatalf("%s is not represented in the test encoding", testCase.name)
			}
		})
	}
}

// previousResult evaluates a request whose admission context already carries a
// previously accepted version/hash pair.
func previousResult(t *testing.T, request Request) Result {
	t.Helper()
	linked := request
	linked.Admission.Previous = &rulepack.PreviousVersion{
		Version: 6,
		Hash:    request.Admission.ExpectedPackHash,
	}
	return evaluate(t, linked)
}

// warnedResult evaluates a request whose provenance carries one warning.
func warnedResult(t *testing.T, request Request) Result {
	t.Helper()
	warned := mutateRequest(t, request, func(bundle *contract.Bundle) {
		bundle.Provenance.Warnings = []contract.Warning{
			{Code: "redaction_applied", Class: contract.WarningInformational, Message: "w"},
		}
	})
	return evaluate(t, warned)
}

// missingResult evaluates a request whose rules lose their row.
func missingResult(t *testing.T, request Request) Result {
	t.Helper()
	reduced := mutateRequest(t, request, func(bundle *contract.Bundle) {
		kept := []contract.EvidenceItem{}
		for _, item := range bundle.Evidence {
			if !strings.HasPrefix(item.Type, "prisma_v1.") {
				kept = append(kept, item)
			}
		}
		bundle.Evidence = kept
	})
	return evaluate(t, reduced)
}

func ruleIndex(t *testing.T, result *Result, ruleID string) int {
	t.Helper()
	for index, trace := range result.Rules {
		if trace.RuleID == ruleID {
			return index
		}
	}
	t.Fatalf("rule %s has no trace", ruleID)
	return 0
}

// TestEvaluationReplayIdentityFingerprint is the fingerprint the contract asks
// for: a SHA-256 over the test-only bytes, never the bundle digest.
func TestEvaluationReplayIdentityFingerprint(t *testing.T) {
	request := baseRequest(t)
	first := evaluate(t, request)
	second := evaluate(t, request)
	firstDigest := sha256.Sum256(encodeResultDTO(t, first))
	secondDigest := sha256.Sum256(encodeResultDTO(t, second))
	if firstDigest != secondDigest {
		t.Fatalf("the test fingerprint is not reproducible")
	}
	changed := mutateRequest(t, request, func(bundle *contract.Bundle) {
		bundle.Provenance.RedactionPolicy = "other-v1"
	})
	changedDigest := sha256.Sum256(encodeResultDTO(t, evaluate(t, changed)))
	if changedDigest == firstDigest {
		t.Fatalf("a covered provenance change must change the fingerprint")
	}
}
