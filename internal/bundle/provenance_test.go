package bundle

import (
	"regexp"
	"strings"
	"testing"

	"github.com/d4rpell/Ariadne/internal/ingest"
	"github.com/d4rpell/Ariadne/internal/normalize"
	contract "github.com/d4rpell/Ariadne/pkg/evidence"
)

func TestBuildImportDiagnosticsExact(t *testing.T) {
	csv := testCSVHeader + csvRow("CVE-2024-1234") + "1.0,NOT-A-CVE,openssl,1.1.1k,fixed,registry.example,payments/api,release,high\n"
	input := testInput(t, csv, []normalize.Binding{
		testBinding(t, 0, contract.UID("pod-uid-1"), contract.ContainerRegular, contract.ContainerName("api")),
	})
	bundle, _ := buildForTest(t, input)

	pattern := regexp.MustCompile(`^ingest: prisma-v1: record/2/bytes/[0-9]+-[0-9]+: invalid vulnerability ID$`)
	found := 0
	for _, message := range bundle.Provenance.Errors {
		if pattern.MatchString(message) {
			found++
		}
	}
	if found != 1 {
		t.Fatalf("rejection errors = %d in %+v", found, bundle.Provenance.Errors)
	}
	if len(input.Normalized.Diagnostics.Rejections) != 1 {
		t.Fatal("the fixture must carry exactly one rejection")
	}
	if got, want := bundle.Provenance.Errors[0], input.Normalized.Diagnostics.Rejections[0].String(); got != want {
		t.Fatalf("error = %q, want the allowlisted formatter %q", got, want)
	}
}

func TestBuildStructuralFailureStaysVisibleAndSanitized(t *testing.T) {
	parsed, err := ingest.ParsePrismaV1(strings.NewReader("\ufeff" + csvOneRow))
	if err == nil {
		t.Fatal("a BOM must abort the import")
	}
	failure, ok := err.(*ingest.FileError)
	if !ok {
		t.Fatalf("structural error type = %T", err)
	}
	normalized, normalizeErr := normalize.Normalize(normalize.Input{Import: parsed, StructuralError: failure})
	if normalizeErr != nil {
		t.Fatalf("normalize aborted import: %v", normalizeErr)
	}
	bundle, diagnostics, buildErr := Build(Input{
		Normalized: normalized,
		Subject:    testSubject(),
		Source:     ImportSource{Path: "findings.csv", Hash: HashSource([]byte(csvOneRow)), ObservedAt: testTimestamp(t, "2026-09-26T10:00:00Z")},
		Run:        testRun(t),
	})
	if buildErr != nil {
		t.Fatalf("build: %v", buildErr)
	}
	if diagnostics.Ingest.StructuralError == nil {
		t.Fatal("the structural failure must be preserved in the diagnostics")
	}
	if got, want := bundle.Provenance.Errors[0], "ingest: prisma-v1: byte/0: BOM is not allowed"; got != want {
		t.Fatalf("error = %q, want %q", got, want)
	}
	if bundle.Provenance.Completeness != contract.CompletenessUnknown {
		t.Fatalf("completeness = %q, want unknown for an abort without progress", bundle.Provenance.Completeness)
	}
	if bundle.Provenance.Coverage.Termination != contract.TerminationAborted || bundle.Provenance.Coverage.Rows.Total != nil {
		t.Fatal("an aborted import must keep its termination and an unknown total")
	}
}

func TestBuildReasonsAreAllowlisted(t *testing.T) {
	const marker = "SYNTHETIC_PRIVATE_MARKER"
	input := testInput(t, csvOneRow, []normalize.Binding{
		testBinding(t, 0, contract.UID("pod-uid-1"), contract.ContainerRegular, contract.ContainerName("api")),
	})
	input.Normalized = copyResult(input.Normalized)
	input.Normalized.Diagnostics.Rejections = append(input.Normalized.Diagnostics.Rejections, ingest.Rejection{
		Locator: ingest.Locator{Record: 9, StartByte: 1, EndByte: 2},
		Reason:  ingest.Reason(marker),
	})
	bundle, _ := buildForTest(t, input)

	want := "ingest: prisma-v1: record/9/bytes/1-2: invalid input"
	assertErrorPresent(t, bundle, want)
	if strings.Contains(envelopeOf(t, bundle), marker) {
		t.Fatal("a reason outside the allowlist leaked its value")
	}
}

func TestBuildKeepsCallerWarnings(t *testing.T) {
	informational := contract.Warning{Code: "redaction_applied", Class: contract.WarningInformational, Message: "policy \"default\" applied"}
	input := testInput(t, csvOneRow, []normalize.Binding{
		testBinding(t, 0, contract.UID("pod-uid-1"), contract.ContainerRegular, contract.ContainerName("api")),
	})
	input.Run.Warnings = []contract.Warning{informational, informational}
	bundle, _ := buildForTest(t, input)

	kept := 0
	for _, warning := range bundle.Provenance.Warnings {
		if warning == informational {
			kept++
		}
	}
	if kept != 2 {
		t.Fatalf("caller warnings kept = %d, want 2 (duplicates preserved)", kept)
	}
	if bundle.Provenance.Ruleset != (contract.RulesetRef{}) {
		t.Fatal("no ruleset is invented for a findings import")
	}
}

func TestBuildRefusesIncompleteImportWithoutVisibleErrors(t *testing.T) {
	input := testInput(t, csvTwoRows, []normalize.Binding{
		testBinding(t, 0, contract.UID("pod-uid-1"), contract.ContainerRegular, contract.ContainerName("api")),
	})
	input.Normalized = copyResult(input.Normalized)
	input.Normalized.Completeness = contract.CompletenessPartial
	input.Normalized.Diagnostics.Rejections = nil
	bundle, _, err := Build(input)
	if err == nil {
		t.Fatal("an incomplete import without visible errors must not produce a bundle")
	}
	if len(bundle.Provenance.Errors) != 0 {
		t.Fatal("a refused bundle must not carry claims")
	}
}

func TestBuildDiagnosticsAreNotSerialized(t *testing.T) {
	csv := testCSVHeader + csvRow("CVE-2024-1234") + "1.0,NOT-A-CVE,openssl,1.1.1k,fixed,registry.example,payments/api,release,high\n"
	input := testInput(t, csv, []normalize.Binding{
		testBinding(t, 0, contract.UID("pod-uid-1"), contract.ContainerRegular, contract.ContainerName("api")),
	})
	input.Normalized = copyResult(input.Normalized)
	input.Normalized.Diagnostics.Rejections = append(input.Normalized.Diagnostics.Rejections, ingest.Rejection{
		Locator: ingest.Locator{Record: 7, StartByte: 5, EndByte: 9},
		Reason:  ingest.ReasonInvalidCVE,
	})
	bundle, _ := buildForTest(t, input)

	envelope := envelopeOf(t, bundle)
	for _, forbidden := range []string{"omission", "diagnostics", "finding_index", "collision_count"} {
		if strings.Contains(envelope, forbidden) {
			t.Fatalf("diagnostics vocabulary %q leaked into the wire", forbidden)
		}
	}
	assertErrorPresent(t, bundle, "ingest: prisma-v1: record/7/bytes/5-9: invalid vulnerability ID")
}
