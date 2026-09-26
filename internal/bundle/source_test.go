package bundle

import (
	"errors"
	"io"
	"regexp"
	"strings"
	"testing"
	"testing/iotest"

	"github.com/d4rpell/Ariadne/internal/ingest"
	"github.com/d4rpell/Ariadne/internal/normalize"
	contract "github.com/d4rpell/Ariadne/pkg/evidence"
)

func TestHashSourceShapeAndDeterminism(t *testing.T) {
	first := HashSource([]byte("complete source"))
	second := HashSource([]byte("complete source"))
	if first != second {
		t.Fatal("the source hash is not deterministic")
	}
	if !isSha256(string(first)) || !strings.HasPrefix(string(first), "sha256:") {
		t.Fatalf("source hash = %q", first)
	}
	if HashSource([]byte("complete source ")) == first {
		t.Fatal("a different byte sequence shares the hash")
	}
	if !isSha256(string(HashSource(nil))) {
		t.Fatal("an empty source still has a well-formed hash")
	}
	for _, malformed := range []string{
		"sha256:" + strings.ToUpper(strings.Repeat("a", 64)),
		"sha256:" + strings.Repeat("a", 63),
		strings.Repeat("a", 64),
		"SHA256:" + strings.Repeat("a", 64),
	} {
		if isSha256(malformed) {
			t.Fatalf("malformed hash accepted: %q", malformed)
		}
	}
}

func TestHashValuePreimage(t *testing.T) {
	if HashValue(" padded ") != contract.ValueHash(HashSource([]byte(" padded "))) {
		t.Fatal("the value hash must cover the exact bytes of the value")
	}
	if HashValue("value") == HashValue("value ") {
		t.Fatal("the preimage must not be trimmed")
	}
}

func TestSourceHashRequiresCompleteInput(t *testing.T) {
	accepted := csvRow("CVE-2024-1234")
	complete := testCSVHeader + accepted
	withSuffix := complete + csvRow("CVE-2024-5678")

	first := parseImport(t, complete)
	second := parseImport(t, withSuffix)
	if first.source.Hash == second.source.Hash {
		t.Fatal("the hash must cover the complete file, not the accepted rows")
	}

	firstInput := Input{
		Normalized: normalizeImport(t, first, []normalize.Binding{
			testBinding(t, 0, contract.UID("pod-uid-1"), contract.ContainerRegular, contract.ContainerName("api")),
		}),
		Subject: testSubject(),
		Source:  first.source,
		Run:     testRun(t),
	}
	firstBundle, _ := buildForTest(t, firstInput)
	if got := firstBundle.Provenance.Inputs[0].Hash; got != first.source.Hash {
		t.Fatalf("input hash = %q, want the hash of the bytes that were parsed", got)
	}
	for _, item := range firstBundle.Evidence {
		if !strings.HasPrefix(item.Type, "prisma_v1.") {
			continue
		}
		if item.Source != first.source.Path || item.SourceHash != first.source.Hash {
			t.Fatalf("declared item %q cites %q/%q", item.Type, item.Source, item.SourceHash)
		}
	}

	failing := io.MultiReader(strings.NewReader(complete), iotest.ErrReader(errors.New("synthetic reader failure")))
	result, err := ingest.ParsePrismaV1(failing)
	if err == nil {
		t.Fatal("a reader failure must abort the import")
	}
	failure, ok := err.(*ingest.FileError)
	if !ok {
		t.Fatalf("structural error type = %T", err)
	}
	aborted, normalizeErr := normalize.Normalize(normalize.Input{Import: result, StructuralError: failure})
	if normalizeErr != nil {
		t.Fatalf("normalize aborted import: %v", normalizeErr)
	}
	bundle, diagnostics, buildErr := Build(Input{
		Normalized: aborted,
		Subject:    testSubject(),
		Source: ImportSource{
			Path:       "findings.csv",
			Hash:       HashSource([]byte(complete)),
			ObservedAt: testTimestamp(t, "2026-09-26T10:00:00Z"),
		},
		Run: testRun(t),
	})
	if buildErr != nil {
		t.Fatalf("build: %v", buildErr)
	}
	if bundle.Provenance.Completeness == contract.CompletenessComplete {
		t.Fatal("a prefix read must never be declared complete")
	}
	if bundle.Provenance.Coverage.Termination != contract.TerminationAborted || bundle.Provenance.Coverage.Rows.Total != nil {
		t.Fatal("an aborted read keeps its termination and an unknown total")
	}
	if len(diagnostics.Ingest.Rejections) != 0 || diagnostics.Ingest.StructuralError == nil {
		t.Fatalf("diagnostics = %+v", diagnostics.Ingest)
	}
	for _, message := range bundle.Provenance.Errors {
		if strings.Contains(message, "synthetic reader failure") {
			t.Fatal("a raw reader error leaked into provenance")
		}
	}
	readFailure := regexp.MustCompile(`^ingest: prisma-v1: byte/[0-9]+: input read failed$`)
	matched := false
	for _, message := range bundle.Provenance.Errors {
		if readFailure.MatchString(message) {
			matched = true
		}
	}
	if !matched {
		t.Fatalf("read failure not reported in %+v", bundle.Provenance.Errors)
	}
}
