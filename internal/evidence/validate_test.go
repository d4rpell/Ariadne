package evidence

import (
	"testing"
	"time"

	contract "github.com/d4rpell/Ariadne/pkg/evidence"
)

func testSubject() contract.Subject {
	return contract.Subject{
		ClusterAlias: contract.ClusterAlias("cluster-a"),
		Namespace:    contract.Namespace("payments"),
		Kind:         "Pod",
		Name:         "payments-api-7f4d",
		UID:          contract.UID("pod-uid-1"),
		OwnerChain:   contract.OwnerChain("deployments/payments-api"),
	}
}

func testContainer() contract.ContainerName {
	return contract.ContainerName("api")
}

func testScope(subject contract.Subject, container contract.ContainerName) contract.Scope {
	return contract.Scope{SubjectUID: subject.UID, ContainerName: container}
}

func testTimestamp(t *testing.T) contract.Timestamp {
	t.Helper()
	observedAt, err := contract.NewTimestamp(time.Date(2026, 9, 23, 12, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatalf("NewTimestamp: %v", err)
	}
	return observedAt
}

func testItem(t *testing.T, scope contract.Scope, confidence contract.ProvenanceKind, warnings []contract.Warning) contract.EvidenceItem {
	t.Helper()
	if warnings == nil {
		warnings = []contract.Warning{}
	}
	observedAt := testTimestamp(t)
	valueHash := contract.ValueHash("sha256:bbb")
	return contract.EvidenceItem{
		Type:       "container_status.image_id",
		Source:     "sanitized-pods.json",
		SourceHash: contract.SourceHash("sha256:ccc"),
		Locator:    contract.SourceLocator("items[3].status.containerStatuses[0].imageID"),
		ValueHash:  &valueHash,
		ObservedAt: &observedAt,
		Confidence: confidence,
		Scope:      scope,
		Warnings:   warnings,
	}
}

// testProvenance is the container observation path of ADR-0006 §7(a).
func testProvenance(t *testing.T) contract.RunProvenance {
	t.Helper()
	startedAt := testTimestamp(t)
	return contract.RunProvenance{
		CollectorVersion: "0.1",
		ParserVersion:    "kubectl-v1.2",
		Ruleset:          contract.RulesetRef{Path: "rules/", Hash: contract.SourceHash("sha256:ddd"), Version: "2026-09"},
		ArgvSanitized:    []string{"get", "pods", "-o", "json"},
		Inputs:           []contract.InputRef{{Path: "sanitized-pods.json", Hash: contract.SourceHash("sha256:eee")}},
		APIScope:         contract.APIScope{Namespaces: []contract.Namespace{"payments"}, Verbs: []string{"get", "list"}, Resources: []string{"pods"}},
		StartedAt:        &startedAt,
		EndedAt:          &startedAt,
		Coverage:         contract.Coverage{Method: contract.CoverageContainerObservation, Termination: contract.TerminationFinished},
		Completeness:     contract.CompletenessComplete,
		Consistency:      contract.ConsistencyPointObservation,
		RedactionPolicy:  "default-v1",
		Warnings:         []contract.Warning{},
		Errors:           []string{},
	}
}

func testBundle(t *testing.T) contract.Bundle {
	t.Helper()
	subject := testSubject()
	requested := contract.RequestedImage("registry.example/app:release")
	raw := contract.RawImageID("registry.example/app@sha256:aaa")
	normalized := contract.NormalizedDigest("sha256:aaa")
	observedAt := testTimestamp(t)
	return contract.Bundle{
		SchemaVersion: contract.SchemaVersionSupported,
		Subject:       subject,
		Images: []contract.ImageIdentity{{
			ContainerClass:   contract.ContainerRegular,
			ContainerName:    testContainer(),
			RequestedImage:   &requested,
			RawImageID:       &raw,
			NormalizedDigest: &normalized,
			Platform:         contract.Platform{OS: "linux", Architecture: "amd64", Status: contract.PlatformKnown},
			ObservedAt:       &observedAt,
		}},
		Evidence: []contract.EvidenceItem{
			testItem(t, testScope(subject, testContainer()), contract.ProvenanceObserved, nil),
		},
		ObservedContainerClasses: []contract.ContainerClass{
			contract.ContainerEphemeral,
			contract.ContainerInit,
			contract.ContainerRegular,
		},
		Provenance: testProvenance(t),
	}
}

func TestValidateConclusionRejectsNotAffectedWithoutEvidence(t *testing.T) {
	subject := testSubject()
	if err := ValidateConclusion(contract.ProductNotAffected, subject, testContainer(), nil); err == nil {
		t.Fatal("not_affected was accepted without any evidence")
	}
	if err := ValidateConclusion(contract.ProductNotAffected, subject, testContainer(), []contract.EvidenceItem{}); err == nil {
		t.Fatal("not_affected was accepted with an empty evidence list")
	}
}

func TestValidateConclusionRejectsUnavailableEvidenceAsAffirmative(t *testing.T) {
	subject := testSubject()
	item := testItem(t, testScope(subject, testContainer()), contract.ProvenanceUnavailable, nil)
	if err := ValidateConclusion(contract.ProductNotAffected, subject, testContainer(), []contract.EvidenceItem{item}); err == nil {
		t.Fatal("unavailable evidence was accepted as affirmative evidence")
	}
}

func TestValidateConclusionRejectsUnavailableEvidenceMixedWithAffirmative(t *testing.T) {
	subject := testSubject()
	unavailable := testItem(t, testScope(subject, testContainer()), contract.ProvenanceUnavailable, nil)
	observed := testItem(t, testScope(subject, testContainer()), contract.ProvenanceObserved, nil)
	items := []contract.EvidenceItem{unavailable, observed}
	if err := ValidateConclusion(contract.ProductNotAffected, subject, testContainer(), items); err == nil {
		t.Fatal("not_affected was accepted while the evidence referenced unavailable data")
	}
}

func TestValidateConclusionRejectsAffirmativeEvidenceWithoutValueHash(t *testing.T) {
	subject := testSubject()
	item := testItem(t, testScope(subject, testContainer()), contract.ProvenanceObserved, nil)
	item.ValueHash = nil
	if err := ValidateConclusion(contract.ProductNotAffected, subject, testContainer(), []contract.EvidenceItem{item}); err == nil {
		t.Fatal("not_affected was accepted without an auditable value hash")
	}
}

func TestValidateConclusionAcceptsAffirmativeEvidenceInScope(t *testing.T) {
	subject := testSubject()
	for _, confidence := range []contract.ProvenanceKind{contract.ProvenanceObserved, contract.ProvenanceDerived} {
		item := testItem(t, testScope(subject, testContainer()), confidence, nil)
		if err := ValidateConclusion(contract.ProductNotAffected, subject, testContainer(), []contract.EvidenceItem{item}); err != nil {
			t.Fatalf("%s evidence in scope was rejected: %v", confidence, err)
		}
	}
}

func TestValidateConclusionRejectsContradictoryWarning(t *testing.T) {
	subject := testSubject()
	warnings := []contract.Warning{{
		Code:    "uid_changed",
		Class:   contract.WarningContradictory,
		Message: "the pod uid changed during the re-read",
	}}
	item := testItem(t, testScope(subject, testContainer()), contract.ProvenanceObserved, warnings)
	if err := ValidateConclusion(contract.ProductNotAffected, subject, testContainer(), []contract.EvidenceItem{item}); err == nil {
		t.Fatal("not_affected was accepted while evidence carried a contradictory warning")
	}
}

func TestValidateConclusionAcceptsInformationalWarning(t *testing.T) {
	subject := testSubject()
	warnings := []contract.Warning{{
		Code:    "redaction_applied",
		Class:   contract.WarningInformational,
		Message: "the value was redacted before persisting",
	}}
	item := testItem(t, testScope(subject, testContainer()), contract.ProvenanceObserved, warnings)
	if err := ValidateConclusion(contract.ProductNotAffected, subject, testContainer(), []contract.EvidenceItem{item}); err != nil {
		t.Fatalf("an informational warning must not block not_affected by itself: %v", err)
	}
}

// TestValidateConclusionRejectsUnknownWarningCode covers the fail-closed rule of
// ADR-0006 §8: a code this version cannot classify cannot support a negative
// conclusion either, even when it arrives labelled as informational.
func TestValidateConclusionRejectsUnknownWarningCode(t *testing.T) {
	subject := testSubject()
	warnings := []contract.Warning{{
		Code:    "future_code",
		Class:   contract.WarningInformational,
		Message: "uninterpretable by this version",
	}}
	item := testItem(t, testScope(subject, testContainer()), contract.ProvenanceObserved, warnings)
	if err := ValidateConclusion(contract.ProductNotAffected, subject, testContainer(), []contract.EvidenceItem{item}); err == nil {
		t.Fatal("not_affected was accepted while evidence carried an uninterpretable warning")
	}
}

func TestValidateConclusionRejectsEvidenceWithoutWarningsArray(t *testing.T) {
	subject := testSubject()
	item := testItem(t, testScope(subject, testContainer()), contract.ProvenanceObserved, nil)
	item.Warnings = nil
	if err := ValidateConclusion(contract.ProductNotAffected, subject, testContainer(), []contract.EvidenceItem{item}); err == nil {
		t.Fatal("not_affected was accepted with a nil warnings array")
	}
}

func TestValidateConclusionRejectsEvidenceFromAnotherUID(t *testing.T) {
	subject := testSubject()
	replaced := subject
	replaced.UID = contract.UID("pod-uid-2")
	item := testItem(t, testScope(replaced, testContainer()), contract.ProvenanceObserved, nil)
	if replaced.Namespace != subject.Namespace || replaced.Name != subject.Name {
		t.Fatal("the fixture must keep namespace/name to prove they do not identify")
	}
	if err := ValidateConclusion(contract.ProductNotAffected, subject, testContainer(), []contract.EvidenceItem{item}); err == nil {
		t.Fatal("evidence from a replaced pod was accepted for the new subject")
	}
}

func TestValidateConclusionRejectsEvidenceFromAnotherContainer(t *testing.T) {
	subject := testSubject()
	item := testItem(t, testScope(subject, contract.ContainerName("sidecar")), contract.ProvenanceObserved, nil)
	if err := ValidateConclusion(contract.ProductNotAffected, subject, testContainer(), []contract.EvidenceItem{item}); err == nil {
		t.Fatal("evidence from another container was accepted")
	}
}

func TestValidateConclusionRejectsUnknownStatus(t *testing.T) {
	subject := testSubject()
	if err := ValidateConclusion(contract.ProductStatus(""), subject, testContainer(), nil); err == nil {
		t.Fatal("an unknown product status was accepted")
	}
	if err := ValidateConclusion(contract.ProductStatus("unknown"), subject, testContainer(), nil); err == nil {
		t.Fatal("unknown was accepted as a product status value")
	}
}

func TestValidateConclusionLeavesOtherStatusesOutOfTheGuard(t *testing.T) {
	subject := testSubject()
	for _, status := range []contract.ProductStatus{
		contract.ProductAffected,
		contract.ProductFixed,
		contract.ProductUnderInvestigation,
	} {
		if status == contract.ProductNotAffected {
			t.Fatal("fixed or affected must not collapse into not_affected")
		}
		if err := ValidateConclusion(status, subject, testContainer(), nil); err != nil {
			t.Fatalf("status %q was rejected although the guard only covers not_affected: %v", status, err)
		}
	}
}
