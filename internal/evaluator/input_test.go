package evaluator

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"
	"time"

	canonical "github.com/d4rpell/Ariadne/internal/evidence"
	"github.com/d4rpell/Ariadne/internal/rulepack"
	contract "github.com/d4rpell/Ariadne/pkg/evidence"
)

// Synthetic fixtures of the evaluator tests. There are no real cluster, customer
// or scanner data here: identifiers, hashes and timestamps are fabricated and
// the bundle is assembled explicitly, never through the projection under test.

const (
	uidA        = "uid-a"
	containerA  = "api"
	otherName   = "sidecar"
	clusterA    = "cluster-a"
	namespaceA  = "ns-a"
	podNameA    = "pod-a"
	cveA        = "CVE-2026-12345"
	cveOther    = "CVE-2026-99999"
	sourceCSV   = "findings.csv"
	sourcePods  = "pods.json"
	locatorRow  = "record/1/bytes/0-40"
	locatorStat = "items[0].status.containerStatuses[0].imageID"
	requestedA  = "reg.example/app:1"
	marker      = "SYNTHETIC_PRIVATE_MARKER"

	digestValue   = "sha256:" + "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	rawImageValue = "reg.example/app@sha256:" + "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	sourceHashCSV = "sha256:" + "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
	sourceHashPod = "sha256:" + "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"
)

var (
	sourceObservedAt = time.Date(2026, 9, 20, 10, 0, 0, 0, time.UTC)
	statusObservedAt = time.Date(2026, 9, 20, 10, 5, 0, 0, time.UTC)
	evaluatedAt      = time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)
)

func mustStamp(t *testing.T, value time.Time) contract.Timestamp {
	t.Helper()
	stamp, err := contract.NewTimestamp(value)
	if err != nil {
		t.Fatalf("timestamp construction failed: %v", err)
	}
	return stamp
}

func stampPointer(stamp contract.Timestamp) *contract.Timestamp { return &stamp }

func strPointer(value string) *string { return &value }

// independentValueHash computes the value-hash preimage without production code:
// SHA-256 over the exact UTF-8 bytes of the value.
func independentValueHash(value string) contract.ValueHash {
	digest := sha256.Sum256([]byte(value))
	return contract.ValueHash("sha256:" + hex.EncodeToString(digest[:]))
}

func independentDocumentHash(document string) string {
	digest := sha256.Sum256([]byte(document))
	return "sha256:" + hex.EncodeToString(digest[:])
}

func evidenceItem(subject contract.Subject, container contract.ContainerName, itemType, value, source, sourceHash, locator string, stamp contract.Timestamp, confidence contract.ProvenanceKind) contract.EvidenceItem {
	hash := independentValueHash(value)
	return contract.EvidenceItem{
		Type:       itemType,
		Source:     source,
		SourceHash: contract.SourceHash(sourceHash),
		Locator:    contract.SourceLocator(locator),
		Value:      strPointer(value),
		ValueHash:  &hash,
		ObservedAt: stampPointer(stamp),
		Confidence: confidence,
		Scope:      contract.Scope{SubjectUID: subject.UID, ContainerName: container},
		Warnings:   []contract.Warning{},
	}
}

func declaredRow(t *testing.T, subject contract.Subject, container contract.ContainerName) []contract.EvidenceItem {
	t.Helper()
	stamp := mustStamp(t, sourceObservedAt)
	make := func(itemType, value string, confidence contract.ProvenanceKind) contract.EvidenceItem {
		return evidenceItem(subject, container, itemType, value, sourceCSV, sourceHashCSV, locatorRow, stamp, confidence)
	}
	return []contract.EvidenceItem{
		make("prisma_v1.vulnerability_id", cveA, contract.ProvenanceObserved),
		make("prisma_v1.package_name", "openssl", contract.ProvenanceObserved),
		make("prisma_v1.installed_version", "3.0.0-1", contract.ProvenanceObserved),
		make("prisma_v1.fix_status", "fixed", contract.ProvenanceObserved),
		make("prisma_v1.package_type", "rpm", contract.ProvenanceObserved),
		make("prisma_v1.package_id", "pkg-1", contract.ProvenanceObserved),
		make("prisma_v1.severity", "high", contract.ProvenanceObserved),
		make(TypeRequestedImage, requestedA, contract.ProvenanceDerived),
	}
}

func observationRow(t *testing.T, subject contract.Subject, container contract.ContainerName) []contract.EvidenceItem {
	t.Helper()
	stamp := mustStamp(t, statusObservedAt)
	make := func(itemType, value string, confidence contract.ProvenanceKind) contract.EvidenceItem {
		return evidenceItem(subject, container, itemType, value, sourcePods, sourceHashPod, locatorStat, stamp, confidence)
	}
	return []contract.EvidenceItem{
		make(TypeImageID, rawImageValue, contract.ProvenanceObserved),
		make(TypeNormalizedDigest, digestValue, contract.ProvenanceDerived),
		make(TypePlatformOS, "linux", contract.ProvenanceObserved),
		make(TypePlatformArchitecture, "amd64", contract.ProvenanceObserved),
	}
}

func baseBundle(t *testing.T) contract.Bundle {
	t.Helper()
	total := uint64(1)
	subject := contract.Subject{
		ClusterAlias: clusterA,
		Namespace:    namespaceA,
		Kind:         "Pod",
		Name:         podNameA,
		UID:          uidA,
		OwnerChain:   "deployments/app",
	}
	requested := contract.RequestedImage(requestedA)
	raw := contract.RawImageID(rawImageValue)
	digest := contract.NormalizedDigest(digestValue)
	image := contract.ImageIdentity{
		ContainerClass:   contract.ContainerRegular,
		ContainerName:    containerA,
		RequestedImage:   &requested,
		RawImageID:       &raw,
		NormalizedDigest: &digest,
		Platform:         contract.Platform{OS: "linux", Architecture: "amd64", Status: contract.PlatformKnown},
		ObservedAt:       stampPointer(mustStamp(t, statusObservedAt)),
	}
	bundle := contract.Bundle{
		SchemaVersion:            "0.1",
		Subject:                  subject,
		Images:                   []contract.ImageIdentity{image},
		ObservedContainerClasses: []contract.ContainerClass{},
		Provenance: contract.RunProvenance{
			CollectorVersion: "0.1.0",
			ParserVersion:    "prisma-v1.0",
			ArgvSanitized:    []string{"import", sourceCSV},
			Inputs:           []contract.InputRef{{Path: sourceCSV, Hash: contract.SourceHash(sourceHashCSV)}},
			APIScope: contract.APIScope{
				Namespaces: []contract.Namespace{},
				Verbs:      []string{},
				Resources:  []string{},
			},
			Budget:          contract.Budget{},
			Coverage:        contract.Coverage{Method: contract.CoverageFindingsImport, Termination: contract.TerminationFinished, Rows: &contract.CoverageRows{Total: &total, Accepted: 1, Rejected: 0}},
			Completeness:    contract.CompletenessComplete,
			Consistency:     contract.ConsistencyPointObservation,
			RedactionPolicy: "default-v1",
			Warnings:        []contract.Warning{},
			Errors:          []string{},
		},
	}
	bundle.Evidence = append(declaredRow(t, subject, containerA), observationRow(t, subject, containerA)...)
	return bundle
}

func baseTarget(t *testing.T) Target {
	t.Helper()
	return Target{
		SubjectUID:      uidA,
		ContainerClass:  contract.ContainerRegular,
		ContainerName:   containerA,
		VulnerabilityID: cveA,
		Source:          sourceCSV,
		SourceHash:      contract.SourceHash(sourceHashCSV),
		Locator:         contract.SourceLocator(locatorRow),
		ObservedAt:      mustStamp(t, sourceObservedAt),
	}
}

func ruleJSON(ruleID, vulnerability, checkJSON, requiresJSON string) string {
	return `{"rule_id":"` + ruleID + `",` +
		`"selector":{"coverage_method":"findings_import","vulnerability_id":"` + vulnerability + `"},` +
		`"requires":[` + requiresJSON + `],` +
		`"checks":[` + checkJSON + `],` +
		`"on_missing_evidence":"under_investigation","emit":"under_investigation"}`
}

func baseRules() string {
	// Declared out of order on purpose: the traces must come out ordered by
	// ASCII id, so a pack cannot choose the order of its own result.
	rules := []string{
		ruleJSON("rule.c", cveA, `{"check_id":"check.c","predicate":"finding_field_present","params":{"field":"package_name"}}`, `"bundle.complete","finding.row","finding.package_name"`),
		ruleJSON("rule.a", cveA, `{"check_id":"check.a","predicate":"finding_field_equals","params":{"field":"fix_status","value":"fixed"}}`, `"bundle.complete","finding.row","finding.fix_status"`),
		ruleJSON("rule.d", cveOther, `{"check_id":"check.d","predicate":"finding_field_present","params":{"field":"package_name"}}`, `"bundle.complete","finding.row","finding.package_name"`),
		ruleJSON("rule.b", cveA, `{"check_id":"check.b","predicate":"image_digest_bound","params":{}}`, `"bundle.complete","finding.row","image.bound_digest"`),
	}
	return strings.Join(rules, ",")
}

func packDocument(rules string) string {
	return `{"schema_version":"0.1","profile":"evidence-readiness-v1","pack_id":"pack.one","version":7,` +
		`"valid_from":"2026-09-01T00:00:00Z","expires_at":"2026-12-31T23:59:59Z","rules":[` + rules + `]}`
}

func baseContext(t *testing.T, document string) rulepack.AdmissionContext {
	t.Helper()
	return rulepack.AdmissionContext{
		EvaluatedAt:      mustStamp(t, evaluatedAt),
		ExpectedPackID:   "pack.one",
		ExpectedPackHash: independentDocumentHash(document),
		MinimumVersion:   1,
	}
}

// baseRequest is the control request: a valid, complete bundle, a matching
// target and an admissible pack. Every test asserts the control passes, so a
// failing case cannot be a broken fixture.
func baseRequest(t *testing.T) Request {
	t.Helper()
	bundle := baseBundle(t)
	document := packDocument(baseRules())
	request := Request{
		Bundle:             bundle,
		ExpectedBundleHash: mustBundleHash(t, bundle),
		Target:             baseTarget(t),
		PackBytes:          []byte(document),
		Admission:          baseContext(t, document),
	}
	if err := contract.ValidateBundle(bundle); err != nil {
		t.Fatalf("fixture bundle is invalid: %v", err)
	}
	if _, err := Evaluate(request); err != nil {
		t.Fatalf("control request must evaluate: %v", err)
	}
	return request
}

func mustBundleHash(t *testing.T, bundle contract.Bundle) string {
	t.Helper()
	hash, err := canonical.HashCanonicalJSON(bundle)
	if err != nil {
		t.Fatalf("fixture bundle does not project: %v", err)
	}
	return hash
}

// cloneBundle deep-copies a fixture, so a mutation in one test can never reach
// another: the fixtures share slices otherwise.
func cloneBundle(bundle contract.Bundle) contract.Bundle {
	cloned := bundle
	cloned.Images = make([]contract.ImageIdentity, len(bundle.Images))
	for index, image := range bundle.Images {
		copied := image
		copied.RequestedImage = clonePointer(image.RequestedImage)
		copied.RawImageID = clonePointer(image.RawImageID)
		copied.NormalizedDigest = clonePointer(image.NormalizedDigest)
		copied.ObservedAt = clonePointer(image.ObservedAt)
		cloned.Images[index] = copied
	}
	cloned.Evidence = make([]contract.EvidenceItem, len(bundle.Evidence))
	for index, item := range bundle.Evidence {
		copied := item
		copied.Value = clonePointer(item.Value)
		copied.ValueHash = clonePointer(item.ValueHash)
		copied.ObservedAt = clonePointer(item.ObservedAt)
		copied.Warnings = append([]contract.Warning{}, item.Warnings...)
		cloned.Evidence[index] = copied
	}
	cloned.ObservedContainerClasses = append([]contract.ContainerClass{}, bundle.ObservedContainerClasses...)
	cloned.Provenance.ArgvSanitized = append([]string{}, bundle.Provenance.ArgvSanitized...)
	cloned.Provenance.Inputs = append([]contract.InputRef{}, bundle.Provenance.Inputs...)
	cloned.Provenance.APIScope.Namespaces = append([]contract.Namespace{}, bundle.Provenance.APIScope.Namespaces...)
	cloned.Provenance.APIScope.Verbs = append([]string{}, bundle.Provenance.APIScope.Verbs...)
	cloned.Provenance.APIScope.Resources = append([]string{}, bundle.Provenance.APIScope.Resources...)
	cloned.Provenance.Warnings = append([]contract.Warning{}, bundle.Provenance.Warnings...)
	cloned.Provenance.Errors = append([]string{}, bundle.Provenance.Errors...)
	if bundle.Provenance.Coverage.Rows != nil {
		rows := *bundle.Provenance.Coverage.Rows
		if bundle.Provenance.Coverage.Rows.Total != nil {
			total := *bundle.Provenance.Coverage.Rows.Total
			rows.Total = &total
		}
		cloned.Provenance.Coverage.Rows = &rows
	}
	return cloned
}

func clonePointer[T any](value *T) *T {
	if value == nil {
		return nil
	}
	copied := *value
	return &copied
}

// mutateRequest clones the control fixture, applies one change and recomputes the
// expected projection hash, so a case only differs in what it declares.
func mutateRequest(t *testing.T, request Request, change func(*contract.Bundle)) Request {
	t.Helper()
	mutated := request
	mutated.Bundle = cloneBundle(request.Bundle)
	change(&mutated.Bundle)
	mutated.ExpectedBundleHash = mustBundleHash(t, mutated.Bundle)
	return mutated
}

func evaluate(t *testing.T, request Request) Result {
	t.Helper()
	result, err := Evaluate(request)
	if err != nil {
		t.Fatalf("evaluation failed: %v", err)
	}
	return result
}

func resultReason(result Result, reason Reason) bool {
	for _, present := range result.Reasons {
		if present == reason {
			return true
		}
	}
	return false
}

func ruleTrace(t *testing.T, result Result, ruleID string) RuleTrace {
	t.Helper()
	for _, trace := range result.Rules {
		if trace.RuleID == ruleID {
			return trace
		}
	}
	t.Fatalf("rule %s has no trace", ruleID)
	return RuleTrace{}
}

func requiresReason(reasons []CheckReason, wanted CheckReason) bool {
	for _, reason := range reasons {
		if reason == wanted {
			return true
		}
	}
	return false
}

// TestEvaluateBundleIntegrity is I-08: the bundle is validated by the existing
// contract, the projection hash is recomputed and compared with the caller's
// expectation, and a projection or any other document is never a substitute for
// the bundle.
func TestEvaluateBundleIntegrity(t *testing.T) {
	request := baseRequest(t)
	if result := evaluate(t, request); result.BundleHash != request.ExpectedBundleHash {
		t.Fatalf("the result must carry the proven bundle hash")
	}

	t.Run("wrong expected hash", func(t *testing.T) {
		broken := request
		broken.ExpectedBundleHash = independentDocumentHash("other")
		_, err := Evaluate(broken)
		if !IsCode(err, CodeBundleHashMismatch) {
			t.Fatalf("expected bundle_hash_mismatch, got %v", err)
		}
	})

	t.Run("canonical bytes are not the projection", func(t *testing.T) {
		encoded, err := canonical.CanonicalJSON(request.Bundle)
		if err != nil {
			t.Fatalf("canonical encoding failed: %v", err)
		}
		envelope := sha256.Sum256(encoded)
		broken := request
		broken.ExpectedBundleHash = "sha256:" + hex.EncodeToString(envelope[:])
		if _, err := Evaluate(broken); !IsCode(err, CodeBundleHashMismatch) {
			t.Fatalf("the envelope hash must not be accepted as the projection hash, got %v", err)
		}
	})

	t.Run("invalid bundle", func(t *testing.T) {
		broken := request
		broken.Bundle.SchemaVersion = "9.9"
		if _, err := Evaluate(broken); !IsCode(err, CodeInvalidBundle) {
			t.Fatalf("expected invalid_bundle, got %v", err)
		}
	})

	t.Run("nil collection", func(t *testing.T) {
		broken := request
		broken.Bundle.ObservedContainerClasses = nil
		if _, err := Evaluate(broken); !IsCode(err, CodeInvalidBundle) {
			t.Fatalf("expected invalid_bundle for a nil collection, got %v", err)
		}
	})

	t.Run("valid partial bundle is inconclusive, not rejected", func(t *testing.T) {
		partial := mutateRequest(t, request, func(bundle *contract.Bundle) {
			bundle.Provenance.Completeness = contract.CompletenessPartial
			bundle.Provenance.Coverage.Termination = contract.TerminationAborted
			bundle.Provenance.Errors = []string{"capture aborted"}
		})
		result := evaluate(t, partial)
		if !resultReason(result, ReasonIncompleteEvidence) {
			t.Fatalf("an incomplete capture must be visible as incomplete: %v", result.Reasons)
		}
		for _, trace := range result.Rules {
			if trace.State == RuleChecked {
				t.Fatalf("a rule cannot be checked over an incomplete capture: %+v", trace)
			}
		}
	})

	t.Run("ruleset of another pack", func(t *testing.T) {
		mismatched := mutateRequest(t, request, func(bundle *contract.Bundle) {
			bundle.Provenance.Ruleset = contract.RulesetRef{Path: "rules/", Hash: contract.SourceHash(sourceHashPod), Version: "1"}
		})
		if _, err := Evaluate(mismatched); !IsCode(err, CodeRulesetMismatch) {
			t.Fatalf("expected ruleset_mismatch, got %v", err)
		}
	})

	t.Run("ruleset of the admitted pack", func(t *testing.T) {
		linked := mutateRequest(t, request, func(bundle *contract.Bundle) {
			bundle.Provenance.Ruleset = contract.RulesetRef{
				Path:    "rules/",
				Hash:    contract.SourceHash(request.Admission.ExpectedPackHash),
				Version: "not-a-decision",
			}
		})
		evaluate(t, linked)
	})
}

// TestEvaluateValueIntegrity is I-09: a present value whose hash does not match
// rejects the evaluation, an absent value is never reconstructed from its hash,
// and a malformed hash is not accepted.
func TestEvaluateValueIntegrity(t *testing.T) {
	request := baseRequest(t)

	t.Run("value edited keeping its hash", func(t *testing.T) {
		broken := mutateRequest(t, request, func(bundle *contract.Bundle) {
			bundle.Evidence[3].Value = strPointer("not_fixed")
		})
		if _, err := Evaluate(broken); !IsCode(err, CodeValueHashMismatch) {
			t.Fatalf("expected value_hash_mismatch, got %v", err)
		}
	})

	t.Run("malformed value hash", func(t *testing.T) {
		broken := mutateRequest(t, request, func(bundle *contract.Bundle) {
			hash := contract.ValueHash("sha256:zz")
			bundle.Evidence[1].ValueHash = &hash
		})
		if _, err := Evaluate(broken); !IsCode(err, CodeValueHashMismatch) {
			t.Fatalf("expected value_hash_mismatch, got %v", err)
		}
	})

	t.Run("absent value is never reconstructed", func(t *testing.T) {
		reduced := mutateRequest(t, request, func(bundle *contract.Bundle) {
			bundle.Evidence[1].Value = nil // hash kept, value removed
		})
		result := evaluate(t, reduced)
		trace := ruleTrace(t, result, "rule.c")
		if trace.State != RuleMissingEvidence {
			t.Fatalf("a redacted value cannot satisfy a requirement: %+v", trace)
		}
		if !requiresReason(trace.Reasons, ReasonRedacted) {
			t.Fatalf("the reason must be redacted, got %v", trace.Reasons)
		}
		if result.ProductStatus != contract.ProductUnderInvestigation {
			t.Fatalf("no profile outcome may be affirmative")
		}
	})
}

// TestEvaluateTargetScope is I-10: identity is uid, class and container name.
// Another uid, another container or the same name in another class never
// substantiates the target, and the engine never picks a candidate by order.
func TestEvaluateTargetScope(t *testing.T) {
	request := baseRequest(t)

	t.Run("same name, other uid", func(t *testing.T) {
		other := mutateRequest(t, request, func(bundle *contract.Bundle) {
			bundle.Subject.UID = "uid-b"
			for index := range bundle.Evidence {
				bundle.Evidence[index].Scope.SubjectUID = "uid-b"
			}
		})
		other.Target.SubjectUID = "uid-a"
		if _, err := Evaluate(other); !IsCode(err, CodeInvalidTarget) {
			t.Fatalf("a foreign target must be rejected, got %v", err)
		}
	})

	t.Run("other container", func(t *testing.T) {
		other := request
		other.Target.ContainerName = otherName
		result := evaluate(t, other)
		if !resultReason(result, ReasonTargetUnsubstantiated) {
			t.Fatalf("a target without row or image is unsubstantiated: %v", result.Reasons)
		}
		for _, trace := range result.Rules {
			if trace.State == RuleChecked {
				t.Fatalf("no rule can be checked without evidence: %+v", trace)
			}
		}
	})

	t.Run("same name in two classes", func(t *testing.T) {
		collided := mutateRequest(t, request, func(bundle *contract.Bundle) {
			second := bundle.Images[0]
			second.ContainerClass = contract.ContainerInit
			bundle.Images = append(bundle.Images, second)
		})
		result := evaluate(t, collided)
		trace := ruleTrace(t, result, "rule.b")
		if !requiresReason(trace.Reasons, ReasonConflict) {
			t.Fatalf("a class collision makes the image evidence ambiguous, got %v", trace.Reasons)
		}
	})

	t.Run("divergent identical-class candidates", func(t *testing.T) {
		divergent := mutateRequest(t, request, func(bundle *contract.Bundle) {
			second := bundle.Images[0]
			otherDigest := contract.NormalizedDigest("sha256:" + strings.Repeat("e", 64))
			second.NormalizedDigest = &otherDigest
			bundle.Images = append(bundle.Images, second)
		})
		result := evaluate(t, divergent)
		trace := ruleTrace(t, result, "rule.b")
		if !requiresReason(trace.Reasons, ReasonConflict) {
			t.Fatalf("divergent candidates must not be resolved by order, got %v", trace.Reasons)
		}
	})

	t.Run("identical duplicates back the same fact", func(t *testing.T) {
		duplicated := mutateRequest(t, request, func(bundle *contract.Bundle) {
			bundle.Images = append(bundle.Images, bundle.Images[0])
		})
		result := evaluate(t, duplicated)
		if trace := ruleTrace(t, result, "rule.b"); trace.State != RuleChecked {
			t.Fatalf("identical duplicates must still substantiate the identity: %+v", trace)
		}
	})
}

// TestFindingRowIsolation is I-11: columns are joined only inside one exact row
// reference; another row, another source, another hash or another instant never
// contributes facts.
func TestFindingRowIsolation(t *testing.T) {
	request := baseRequest(t)

	t.Run("row moved to another locator", func(t *testing.T) {
		moved := mutateRequest(t, request, func(bundle *contract.Bundle) {
			for index := range bundle.Evidence {
				if strings.HasPrefix(bundle.Evidence[index].Type, "prisma_v1.") {
					bundle.Evidence[index].Locator = "record/2/bytes/0-40"
				}
			}
		})
		result := evaluate(t, moved)
		if !resultReason(result, ReasonRequirementsMissing) {
			t.Fatalf("a row under another locator must leave the requirements missing: %v", result.Reasons)
		}
		for _, trace := range result.Rules {
			if trace.State == RuleChecked {
				t.Fatalf("no rule can be checked without its row: %+v", trace)
			}
		}
	})

	t.Run("second row with a different value does not create a conflict", func(t *testing.T) {
		second := mutateRequest(t, request, func(bundle *contract.Bundle) {
			for _, item := range bundle.Evidence {
				if item.Type != "prisma_v1.fix_status" {
					continue
				}
				moved := item
				moved.Locator = "record/2/bytes/0-40"
				moved.Value = strPointer("not_fixed")
				hash := independentValueHash("not_fixed")
				moved.ValueHash = &hash
				bundle.Evidence = append(bundle.Evidence, moved)
			}
		})
		result := evaluate(t, second)
		trace := ruleTrace(t, result, "rule.a")
		if trace.State != RuleChecked {
			t.Fatalf("another row must not disturb this row: %+v", trace)
		}
		for _, check := range trace.Checks {
			if check.Outcome != OutcomePass {
				t.Fatalf("the fixture row must still pass: %+v", check)
			}
		}
	})

	t.Run("row of another vulnerability", func(t *testing.T) {
		// The row exists and the columns agree, but its vulnerability is not the
		// target one: a match on the package name or the CVE of another row is
		// never a join.
		other := request
		other.Target.VulnerabilityID = cveOther
		result := evaluate(t, other)
		trace := ruleTrace(t, result, "rule.d")
		if trace.State != RuleMissingEvidence {
			t.Fatalf("a row of another vulnerability does not substantiate the target: %+v", trace)
		}
		if len(trace.MissingRequirements) != 1 || trace.MissingRequirements[0] != rulepack.RequirementFindingRow {
			t.Fatalf("finding.row must be the missing requirement: %+v", trace.MissingRequirements)
		}
		if !requiresReason(trace.Reasons, ReasonMismatch) {
			t.Fatalf("the mismatch must be visible: %v", trace.Reasons)
		}
	})

	t.Run("another source hash does not substantiate the row", func(t *testing.T) {
		other := mutateRequest(t, request, func(bundle *contract.Bundle) {
			for index := range bundle.Evidence {
				bundle.Evidence[index].SourceHash = contract.SourceHash(sourceHashPod)
			}
		})
		result := evaluate(t, other)
		rowSatisfied := false
		for _, trace := range result.Rules {
			for _, check := range trace.Checks {
				if check.Outcome == OutcomePass {
					rowSatisfied = true
				}
			}
		}
		if rowSatisfied {
			t.Fatalf("a different source hash cannot substantiate the target row")
		}
	})
}

// TestEvidenceConflict is I-12: identical duplicates are kept, divergent values
// for one required field are a conflict and the order of the candidates never
// decides.
func TestEvidenceConflict(t *testing.T) {
	request := baseRequest(t)

	t.Run("identical duplicates are preserved", func(t *testing.T) {
		duplicated := mutateRequest(t, request, func(bundle *contract.Bundle) {
			for _, item := range bundle.Evidence {
				if item.Type == "prisma_v1.package_name" {
					bundle.Evidence = append(bundle.Evidence, item)
				}
			}
		})
		result := evaluate(t, duplicated)
		trace := ruleTrace(t, result, "rule.c")
		if trace.State != RuleChecked {
			t.Fatalf("identical duplicates are one fact: %+v", trace)
		}
		if len(trace.Checks) != 1 || len(trace.Checks[0].EvidenceReferences) != 2 {
			t.Fatalf("both occurrences must be referenced: %+v", trace.Checks)
		}
	})

	t.Run("divergent values conflict", func(t *testing.T) {
		divergent := mutateRequest(t, request, func(bundle *contract.Bundle) {
			for _, item := range bundle.Evidence {
				if item.Type != "prisma_v1.package_name" {
					continue
				}
				moved := item
				moved.Value = strPointer("libcrypto")
				hash := independentValueHash("libcrypto")
				moved.ValueHash = &hash
				bundle.Evidence = append(bundle.Evidence, moved)
			}
		})
		result := evaluate(t, divergent)
		trace := ruleTrace(t, result, "rule.c")
		if trace.State != RuleMissingEvidence || !requiresReason(trace.Reasons, ReasonConflict) {
			t.Fatalf("divergent values must be a visible conflict: %+v", trace)
		}
		if !resultReason(result, ReasonConflictingEvidence) {
			t.Fatalf("the global reasons must report the conflict: %v", result.Reasons)
		}
	})

	t.Run("order does not decide", func(t *testing.T) {
		divergentItem := func(bundle *contract.Bundle) contract.EvidenceItem {
			for _, item := range bundle.Evidence {
				if item.Type != "prisma_v1.package_name" {
					continue
				}
				moved := item
				moved.Value = strPointer("libcrypto")
				hash := independentValueHash("libcrypto")
				moved.ValueHash = &hash
				return moved
			}
			t.Fatalf("fixture lost its package_name item")
			return contract.EvidenceItem{}
		}
		forward := mutateRequest(t, request, func(bundle *contract.Bundle) {
			bundle.Evidence = append(bundle.Evidence, divergentItem(bundle))
		})
		reversed := mutateRequest(t, request, func(bundle *contract.Bundle) {
			bundle.Evidence = append([]contract.EvidenceItem{divergentItem(bundle)}, bundle.Evidence...)
		})
		forwardResult := evaluate(t, forward)
		reversedResult := evaluate(t, reversed)
		if !requiresReason(ruleTrace(t, forwardResult, "rule.c").Reasons, ReasonConflict) ||
			!requiresReason(ruleTrace(t, reversedResult, "rule.c").Reasons, ReasonConflict) {
			t.Fatalf("both orders must report the same conflict")
		}
	})
}

// TestBoundImageEvidence is I-13: a tag or raw id without a proven digest never
// satisfies the requirement, an index digest stays raw, and the observation items
// must be coherent with the image and with their own instant.
func TestBoundImageEvidence(t *testing.T) {
	request := baseRequest(t)

	t.Run("resolved identity", func(t *testing.T) {
		result := evaluate(t, request)
		trace := ruleTrace(t, result, "rule.b")
		if trace.State != RuleChecked || len(trace.Checks) != 1 || trace.Checks[0].Outcome != OutcomePass {
			t.Fatalf("the control image must substantiate the requirement: %+v", trace)
		}
		// The identity rests on two observations, and the references come out in
		// canonical order, where the image id precedes the normalised digest.
		references := trace.Checks[0].EvidenceReferences
		if len(references) != 2 {
			t.Fatalf("the identity must reference both observations: %+v", references)
		}
		if references[0].ItemIndex >= references[1].ItemIndex {
			t.Fatalf("references must be ordered by canonical index: %+v", references)
		}
	})

	t.Run("raw id without digest", func(t *testing.T) {
		broken := mutateRequest(t, request, func(bundle *contract.Bundle) {
			bundle.Images[0].NormalizedDigest = nil
			bundle.Images[0].Platform = contract.Platform{Status: contract.PlatformUnknown}
		})
		result := evaluate(t, broken)
		trace := ruleTrace(t, result, "rule.b")
		if trace.State != RuleMissingEvidence {
			t.Fatalf("a raw id without proven digest cannot satisfy the requirement: %+v", trace)
		}
	})

	t.Run("digest without observation items", func(t *testing.T) {
		broken := mutateRequest(t, request, func(bundle *contract.Bundle) {
			kept := []contract.EvidenceItem{}
			for _, item := range bundle.Evidence {
				if strings.HasPrefix(item.Type, "prisma_v1.") {
					kept = append(kept, item)
				}
			}
			bundle.Evidence = kept
		})
		result := evaluate(t, broken)
		if trace := ruleTrace(t, result, "rule.b"); trace.State != RuleMissingEvidence {
			t.Fatalf("identity without observation items is not traceable: %+v", trace)
		}
	})

	t.Run("observation of another instant", func(t *testing.T) {
		broken := mutateRequest(t, request, func(bundle *contract.Bundle) {
			other := mustStamp(t, statusObservedAt.Add(time.Minute))
			for index := range bundle.Evidence {
				if strings.HasPrefix(bundle.Evidence[index].Type, "container_status.") {
					bundle.Evidence[index].ObservedAt = stampPointer(other)
				}
			}
		})
		result := evaluate(t, broken)
		if trace := ruleTrace(t, result, "rule.b"); trace.State != RuleMissingEvidence {
			t.Fatalf("the observation instant must match the accredited one: %+v", trace)
		}
	})

	t.Run("divergent observation provenance", func(t *testing.T) {
		broken := mutateRequest(t, request, func(bundle *contract.Bundle) {
			for index := range bundle.Evidence {
				if bundle.Evidence[index].Type == TypeImageID {
					bundle.Evidence[index].Source = "other.json"
				}
			}
		})
		result := evaluate(t, broken)
		if trace := ruleTrace(t, result, "rule.b"); !requiresReason(trace.Reasons, ReasonConflict) {
			t.Fatalf("an incoherent observation must be a conflict: %+v", trace)
		}
	})

	t.Run("digest item of the wrong confidence", func(t *testing.T) {
		broken := mutateRequest(t, request, func(bundle *contract.Bundle) {
			for index := range bundle.Evidence {
				if bundle.Evidence[index].Type == TypeNormalizedDigest {
					bundle.Evidence[index].Confidence = contract.ProvenanceObserved
				}
			}
		})
		result := evaluate(t, broken)
		if trace := ruleTrace(t, result, "rule.b"); !requiresReason(trace.Reasons, ReasonMismatch) {
			t.Fatalf("a normalised value is derived, never observed: %+v", trace)
		}
	})

	t.Run("missing raw image id", func(t *testing.T) {
		broken := mutateRequest(t, request, func(bundle *contract.Bundle) {
			bundle.Images[0].RawImageID = nil
		})
		result := evaluate(t, broken)
		if trace := ruleTrace(t, result, "rule.b"); trace.State != RuleMissingEvidence {
			t.Fatalf("a digest without its image id is not a traceable identity: %+v", trace)
		}
	})
}

// TestCoveragePrerequisites is I-14: completeness is relative to the method, and
// no capture of any completeness yields a favourable product state.
func TestCoveragePrerequisites(t *testing.T) {
	request := baseRequest(t)

	t.Run("complete import stays inconclusive", func(t *testing.T) {
		result := evaluate(t, request)
		if result.ProductStatus != contract.ProductUnderInvestigation || result.Exploitability != contract.ExploitabilityNotAssessed {
			t.Fatalf("the initial profile is inconclusive by contract: %+v", result)
		}
		if !resultReason(result, ReasonDomainAssessmentDeferred) {
			t.Fatalf("domain_assessment_deferred is always present: %v", result.Reasons)
		}
	})

	cases := []struct {
		name         string
		completeness contract.Completeness
		termination  contract.CoverageTermination
		errors       []string
	}{
		{"partial", contract.CompletenessPartial, contract.TerminationAborted, []string{"capture partial"}},
		{"unknown", contract.CompletenessUnknown, contract.TerminationUnknown, []string{"capture unknown"}},
		{"aborted", contract.CompletenessPartial, contract.TerminationAborted, []string{"budget exceeded"}},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			broken := mutateRequest(t, request, func(bundle *contract.Bundle) {
				bundle.Provenance.Completeness = testCase.completeness
				bundle.Provenance.Coverage.Termination = testCase.termination
				bundle.Provenance.Errors = testCase.errors
			})
			result := evaluate(t, broken)
			if !resultReason(result, ReasonIncompleteEvidence) {
				t.Fatalf("an incomplete capture must be visible: %v", result.Reasons)
			}
			for _, trace := range result.Rules {
				if trace.State == RuleChecked {
					t.Fatalf("rules must stay missing_evidence without a complete capture: %+v", trace)
				}
			}
		})
	}
}

// TestWarningsVisible is I-15: provenance warnings and every warning of the
// target scope stay visible, a contradictory or unknown warning blocks, and an
// informational one does not block by itself.
func TestWarningsVisible(t *testing.T) {
	request := baseRequest(t)

	t.Run("informational warning does not block", func(t *testing.T) {
		warned := mutateRequest(t, request, func(bundle *contract.Bundle) {
			bundle.Provenance.Warnings = []contract.Warning{{Code: "redaction_applied", Class: contract.WarningInformational, Message: "redaction applied"}}
		})
		result := evaluate(t, warned)
		if resultReason(result, ReasonBlockingWarning) {
			t.Fatalf("a known informational warning must not block: %v", result.Reasons)
		}
		if len(result.WarningReferences) != 1 || result.WarningReferences[0].Origin != WarningFromProvenance {
			t.Fatalf("the provenance warning must stay visible: %+v", result.WarningReferences)
		}
	})

	t.Run("contradictory warning of an unselected item blocks", func(t *testing.T) {
		warned := mutateRequest(t, request, func(bundle *contract.Bundle) {
			for index := range bundle.Evidence {
				if bundle.Evidence[index].Type == "prisma_v1.package_id" {
					bundle.Evidence[index].Warnings = []contract.Warning{{Code: "source_conflict", Class: contract.WarningContradictory, Message: "conflicting sources"}}
				}
			}
		})
		result := evaluate(t, warned)
		if !resultReason(result, ReasonBlockingWarning) {
			t.Fatalf("a contradictory warning blocks, selected or not: %v", result.Reasons)
		}
		found := false
		for _, reference := range result.WarningReferences {
			if reference.Origin == WarningFromEvidence {
				found = true
			}
		}
		if !found {
			t.Fatalf("the item warning must be referenced: %+v", result.WarningReferences)
		}
	})

	t.Run("unknown code blocks", func(t *testing.T) {
		warned := mutateRequest(t, request, func(bundle *contract.Bundle) {
			bundle.Provenance.Warnings = []contract.Warning{{Code: "brand_new_code", Class: contract.WarningInformational, Message: "unknown to this schema"}}
		})
		result := evaluate(t, warned)
		if !resultReason(result, ReasonBlockingWarning) {
			t.Fatalf("an unknown warning code blocks: %v", result.Reasons)
		}
	})

	t.Run("warnings of other scopes are not referenced", func(t *testing.T) {
		warned := mutateRequest(t, request, func(bundle *contract.Bundle) {
			for _, item := range bundle.Evidence {
				if item.Type == "prisma_v1.package_id" {
					moved := item
					moved.Warnings = []contract.Warning{{Code: "source_conflict", Class: contract.WarningContradictory, Message: "elsewhere"}}
					moved.Scope.ContainerName = otherName
					bundle.Evidence = append(bundle.Evidence, moved)
				}
			}
		})
		result := evaluate(t, warned)
		if resultReason(result, ReasonBlockingWarning) {
			t.Fatalf("another container's warning must not block this target: %v", result.Reasons)
		}
	})
}

// TestDiagnosticsDoNotEchoInputs is I-27: reasons, trace identifiers and
// references are static; no evidence value, warning message, error text or
// locator is copied into the result or into an error message.
func TestDiagnosticsDoNotEchoInputs(t *testing.T) {
	request := baseRequest(t)

	t.Run("errors carry no input text", func(t *testing.T) {
		broken := request
		broken.Bundle.SchemaVersion = marker
		_, err := Evaluate(broken)
		if err == nil {
			t.Fatalf("the broken fixture must fail")
		}
		if strings.Contains(err.Error(), marker) {
			t.Fatalf("the error message leaked input content: %v", err)
		}
		tampered := request
		tampered.ExpectedBundleHash = marker
		_, err = Evaluate(tampered)
		if err == nil || strings.Contains(err.Error(), marker) {
			t.Fatalf("the hash error leaked the caller value: %v", err)
		}
	})

	t.Run("result text is static", func(t *testing.T) {
		marked := mutateRequest(t, request, func(bundle *contract.Bundle) {
			bundle.Provenance.Completeness = contract.CompletenessPartial
			bundle.Provenance.Coverage.Termination = contract.TerminationAborted
			bundle.Provenance.Errors = []string{marker}
			bundle.Provenance.Warnings = []contract.Warning{{Code: "redaction_applied", Class: contract.WarningInformational, Message: marker}}
			for index := range bundle.Evidence {
				bundle.Evidence[index].Warnings = []contract.Warning{{Code: "stale_observation", Class: contract.WarningInformational, Message: marker}}
			}
		})
		result := evaluate(t, marked)
		for _, reason := range result.Reasons {
			if strings.Contains(string(reason), marker) {
				t.Fatalf("a reason echoed input content: %q", reason)
			}
		}
		for _, trace := range result.Rules {
			if strings.Contains(trace.RuleID, marker) {
				t.Fatalf("a rule id echoed input content")
			}
			for _, check := range trace.Checks {
				if strings.Contains(check.CheckID, marker) {
					t.Fatalf("a check id echoed input content")
				}
				for _, reason := range check.Reasons {
					if strings.Contains(string(reason), marker) {
						t.Fatalf("a check reason echoed input content: %q", reason)
					}
				}
			}
			for _, reason := range trace.Reasons {
				if strings.Contains(string(reason), marker) {
					t.Fatalf("a trace reason echoed input content: %q", reason)
				}
			}
		}
	})
}

// semanticShape is the outcome of a result without its references: adding a fact
// to a bundle shifts canonical indices, so "inert" facts are compared by what
// they decide, not by the indices they move.
func semanticShape(result Result) string {
	var builder strings.Builder
	builder.WriteString(string(result.ProductStatus))
	builder.WriteString(string(result.Exploitability))
	for _, reason := range result.Reasons {
		builder.WriteString(string(reason))
	}
	for _, trace := range result.Rules {
		builder.WriteString(trace.RuleID)
		builder.WriteString(string(trace.State))
		for _, check := range trace.Checks {
			builder.WriteString(check.CheckID)
			builder.WriteString(string(check.Outcome))
		}
	}
	return builder.String()
}

// TestEvaluateObservationAccreditation covers the identity requirement item by
// item: both observation items are required, and an item whose source hash is not
// a sha256 digest is not accredited.
func TestEvaluateObservationAccreditation(t *testing.T) {
	request := baseRequest(t)

	t.Run("digest without its image id item", func(t *testing.T) {
		broken := mutateRequest(t, request, func(bundle *contract.Bundle) {
			kept := []contract.EvidenceItem{}
			for _, item := range bundle.Evidence {
				if item.Type != TypeImageID {
					kept = append(kept, item)
				}
			}
			bundle.Evidence = kept
		})
		trace := ruleTrace(t, evaluate(t, broken), "rule.b")
		if trace.State != RuleMissingEvidence || !requiresReason(trace.Reasons, ReasonMissing) {
			t.Fatalf("a digest without its image id is not a traceable identity: %+v", trace)
		}
	})

	t.Run("malformed row source hash", func(t *testing.T) {
		// The row group is keyed by the target's hash, which is validated as a
		// sha256 digest: an item with another hash is not a candidate at all, so
		// the row is missing rather than mismatched.
		broken := mutateRequest(t, request, func(bundle *contract.Bundle) {
			for index := range bundle.Evidence {
				if strings.HasPrefix(bundle.Evidence[index].Type, "prisma_v1.") {
					bundle.Evidence[index].SourceHash = contract.SourceHash("sha256:" + strings.Repeat("A", 64))
				}
			}
		})
		trace := ruleTrace(t, evaluate(t, broken), "rule.a")
		if trace.State != RuleMissingEvidence || !requiresReason(trace.Reasons, ReasonMissing) {
			t.Fatalf("a row outside the target key is a missing row: %+v", trace)
		}
	})

	malformed := []string{"x", "sha256:" + strings.Repeat("A", 64), "sha512:" + strings.Repeat("a", 128), "sha256:" + strings.Repeat("a", 63)}
	for _, value := range malformed {
		t.Run("malformed observation source hash", func(t *testing.T) {
			broken := mutateRequest(t, request, func(bundle *contract.Bundle) {
				for index := range bundle.Evidence {
					if strings.HasPrefix(bundle.Evidence[index].Type, "container_status.") {
						bundle.Evidence[index].SourceHash = contract.SourceHash(value)
					}
				}
			})
			trace := ruleTrace(t, evaluate(t, broken), "rule.b")
			if trace.State != RuleMissingEvidence || !requiresReason(trace.Reasons, ReasonMismatch) {
				t.Fatalf("a source hash outside the frontier grammar is not accredited: %+v", trace)
			}
		})
	}
}

// TestEvaluateTargetFormRefused covers the target's own textual form: an
// identifier, a path or a reference outside the contractual shape rejects the
// request instead of being repaired.
func TestEvaluateTargetFormRefused(t *testing.T) {
	request := baseRequest(t)
	cases := []struct {
		name   string
		change func(*Target)
	}{
		{"source with invalid UTF-8", func(target *Target) { target.Source = "findings\xff.csv" }},
		{"locator with surrounding whitespace", func(target *Target) { target.Locator = contract.SourceLocator(" record/1 ") }},
		{"container name with whitespace", func(target *Target) { target.ContainerName = " api " }},
		{"uid with whitespace", func(target *Target) { target.SubjectUID = " uid-a " }},
		{"source hash of another shape", func(target *Target) { target.SourceHash = contract.SourceHash("sha256:abc") }},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			broken := request
			testCase.change(&broken.Target)
			if _, err := Evaluate(broken); !IsCode(err, CodeInvalidTarget) {
				t.Fatalf("expected invalid_target, got %v", err)
			}
		})
	}
}

// TestEvaluateTargetSubstantiation covers when the target counts as
// substantiated: it needs both its row and its image, and half a target is a
// visible reason, never a silent omission.
func TestEvaluateTargetSubstantiation(t *testing.T) {
	request := baseRequest(t)
	withoutRow := func(bundle *contract.Bundle) {
		kept := []contract.EvidenceItem{}
		for _, item := range bundle.Evidence {
			if !strings.HasPrefix(item.Type, "prisma_v1.") {
				kept = append(kept, item)
			}
		}
		bundle.Evidence = kept
	}
	withoutObservation := func(bundle *contract.Bundle) {
		kept := []contract.EvidenceItem{}
		for _, item := range bundle.Evidence {
			if !strings.HasPrefix(item.Type, "container_status.") {
				kept = append(kept, item)
			}
		}
		bundle.Evidence = kept
	}

	cases := []struct {
		name    string
		changes []func(*contract.Bundle)
	}{
		{"row only", []func(*contract.Bundle){withoutObservation}},
		{"image only", []func(*contract.Bundle){withoutRow}},
		{"neither", []func(*contract.Bundle){withoutRow, withoutObservation}},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			broken := mutateRequest(t, request, func(bundle *contract.Bundle) {
				for _, change := range testCase.changes {
					change(bundle)
				}
			})
			result := evaluate(t, broken)
			if !resultReason(result, ReasonTargetUnsubstantiated) {
				t.Fatalf("an incompletely substantiated target must be reported: %v", result.Reasons)
			}
			if result.ProductStatus != contract.ProductUnderInvestigation {
				t.Fatalf("the profile stays inconclusive")
			}
		})
	}

	t.Run("fully substantiated", func(t *testing.T) {
		if resultReason(evaluate(t, request), ReasonTargetUnsubstantiated) {
			t.Fatalf("a substantiated target must not carry that reason")
		}
	})
}

// TestFindingRowJoinComponents changes one component of the row reference at a
// time: every matched rule loses its row, and none of them is checked.
func TestFindingRowJoinComponents(t *testing.T) {
	request := baseRequest(t)
	cases := []struct {
		name   string
		change func(*Target)
	}{
		{"source", func(target *Target) { target.Source = "other.csv" }},
		{"source hash", func(target *Target) { target.SourceHash = contract.SourceHash(sourceHashPod) }},
		{"locator", func(target *Target) { target.Locator = contract.SourceLocator("record/9/bytes/0-40") }},
		{"observed at", func(target *Target) { target.ObservedAt = mustStamp(t, sourceObservedAt.Add(time.Second)) }},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			broken := request
			testCase.change(&broken.Target)
			result := evaluate(t, broken)
			for _, trace := range result.Rules {
				if trace.State == RuleChecked {
					t.Fatalf("a changed join component must leave every rule missing: %+v", trace)
				}
			}
			if !resultReason(result, ReasonRequirementsMissing) {
				t.Fatalf("the missing row must be visible: %v", result.Reasons)
			}
		})
	}
}

// TestNonOperandFactsAreInert adds a fact the vocabulary does not name: it is
// carried by the bundle and decides nothing.
func TestNonOperandFactsAreInert(t *testing.T) {
	request := baseRequest(t)
	control := semanticShape(evaluate(t, request))
	extended := mutateRequest(t, request, func(bundle *contract.Bundle) {
		item := bundle.Evidence[0]
		item.Type = "prisma_v1.severity"
		item.Value = strPointer("critical")
		hash := independentValueHash("critical")
		item.ValueHash = &hash
		bundle.Evidence = append(bundle.Evidence, item)
	})
	if shape := semanticShape(evaluate(t, extended)); shape != control {
		t.Fatalf("a non-operand fact changed the outcome")
	}
}

// TestOtherContainerItemsAreNotReferenced keeps evidence of another container of
// the same subject in the bundle: it belongs to another evaluation and is never
// referenced here. Evidence of another subject cannot reach this frontier at all,
// because the bundle contract refuses it, and that refusal is asserted too.
func TestOtherContainerItemsAreNotReferenced(t *testing.T) {
	request := baseRequest(t)
	extended := mutateRequest(t, request, func(bundle *contract.Bundle) {
		for _, item := range bundle.Evidence {
			moved := item
			moved.Scope.ContainerName = otherName
			bundle.Evidence = append(bundle.Evidence, moved)
		}
	})
	result := evaluate(t, extended)
	if shape := semanticShape(result); shape != semanticShape(evaluate(t, request)) {
		t.Fatalf("another container's items changed the outcome")
	}
	if len(result.WarningReferences) != 0 {
		t.Fatalf("another container's items must not be referenced: %+v", result.WarningReferences)
	}

	t.Run("another subject is refused by the bundle contract", func(t *testing.T) {
		other := request
		other.Bundle = cloneBundle(request.Bundle)
		other.Bundle.Evidence[0].Scope.SubjectUID = "uid-b"
		other.ExpectedBundleHash = independentDocumentHash("irrelevant")
		if _, err := Evaluate(other); !IsCode(err, CodeInvalidBundle) {
			t.Fatalf("the contract must refuse evidence of another subject: %v", err)
		}
	})
}
