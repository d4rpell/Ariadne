package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/d4rpell/Ariadne/internal/casefile"
	"github.com/d4rpell/Ariadne/internal/platform"
)

// Unit and E2E anchors of the validity-diff command (ADR-0038, task A3-10). The
// document golden is produced by the independent Python oracle
// (.internal/a3-10-fixture-gen.py); the receipt agrees with the derived view.

const (
	diffSince = "2026-02-01T00:00:00Z"
	diffAsOf  = "2026-05-01T00:00:00Z"
)

func diffBase(book, out string) []string {
	return []string{"diff",
		"--casebook", book,
		"--since", diffSince,
		"--as-of", diffAsOf,
		"--out", out}
}

func diffFixtureBook(t *testing.T) string {
	t.Helper()
	return filepath.Join("testdata", "diff", "book.json")
}

// absDiffFixtureBook returns the fixture's absolute route, for the direct
// runDiff calls whose working directory is a temporary directory.
func absDiffFixtureBook(t *testing.T) string {
	t.Helper()
	absolute, err := filepath.Abs(diffFixtureBook(t))
	if err != nil {
		t.Fatal(err)
	}
	return absolute
}

func TestDiffGoldenBytes(t *testing.T) {
	dir := t.TempDir()
	out := filepath.Join(dir, "diff.json")
	exit, stdout, stderr := runCLI(t, diffBase(diffFixtureBook(t), out))
	if exit != 0 || stderr != "" {
		t.Fatalf("diff exit=%d stderr=%q", exit, stderr)
	}
	if stdout != "{\"subjects\":6,\"changed\":4}\n" {
		t.Fatalf("receipt = %q", stdout)
	}
	want, err := os.ReadFile(filepath.Join("testdata", "diff", "golden.json"))
	if err != nil {
		t.Fatal(err)
	}
	got := readTemp(t, out)
	if string(got) != string(want) {
		t.Fatalf("document differs from the oracle golden:\n got %s\nwant %s", got, want)
	}
}

func TestDiffNeverOverwrites(t *testing.T) {
	dir := t.TempDir()
	out := writeBookFile(t, dir, "pre-existing.json", casefile.NewBook())
	sentinel := readTemp(t, out)
	expectRejection(t, diffBase(diffFixtureBook(t), out), stageOutputWrite, codeAlreadyExists, 4)
	if after := readTemp(t, out); string(after) != string(sentinel) {
		t.Fatalf("the pre-existing destination was modified")
	}
}

func TestDiffGrammarBeforeAnyRead(t *testing.T) {
	// Every argv names a casebook that does not exist: a rejection proves the
	// grammar decided before any file was read.
	absent := filepath.Join(t.TempDir(), "absent.json")
	cases := []struct {
		name   string
		mutate func([]string) []string
	}{
		{"since not canonical", func(argv []string) []string {
			return replaceValue(argv, "--since", "2026-02-01T00:00:00+00:00")
		}},
		{"as-of with a fraction", func(argv []string) []string {
			return replaceValue(argv, "--as-of", "2026-05-01T00:00:00.5Z")
		}},
		{"inverted interval", func(argv []string) []string {
			return replaceValue(replaceValue(argv, "--since", diffAsOf), "--as-of", diffSince)
		}},
		{"unknown flag", func(argv []string) []string {
			return append(argv, "--extra", "x")
		}},
		{"repeated flag", func(argv []string) []string {
			return append(argv, "--since", diffSince)
		}},
		{"missing flag", func(argv []string) []string {
			return argv[:len(argv)-2]
		}},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			expectRejection(t, testCase.mutate(diffBase(absent, filepath.Join(t.TempDir(), "out.json"))),
				stageArguments, codeInvalidArguments, 2)
		})
	}
}

func TestDiffDeclaredFailures(t *testing.T) {
	dir := t.TempDir()
	t.Run("casebook missing", func(t *testing.T) {
		expectRejection(t, diffBase(filepath.Join(dir, "absent.json"), filepath.Join(dir, "out.json")),
			stageBundleRead, codeNotFound, 4)
	})
	t.Run("casebook not canonical", func(t *testing.T) {
		path := filepath.Join(dir, "broken.json")
		if err := os.WriteFile(path, []byte("{"), 0o600); err != nil {
			t.Fatalf("write: %v", err)
		}
		expectRejection(t, diffBase(path, filepath.Join(dir, "out.json")),
			stageBundleDecode, codeInvalidBundle, 3)
	})
	t.Run("casebook over the transport bound", func(t *testing.T) {
		oversized := filepath.Join(dir, "oversized.json")
		if err := os.WriteFile(oversized, make([]byte, casefile.MaxBookBytes+1), 0o600); err != nil {
			t.Fatalf("write oversized casebook: %v", err)
		}
		expectRejection(t, diffBase(oversized, filepath.Join(dir, "out.json")),
			stageBundleRead, codeInputLimit, 3)
	})
}

func TestDiffWriteFailureEmitsNoReceipt(t *testing.T) {
	dir := t.TempDir()
	original := createDestination
	defer func() { createDestination = original }()
	createDestination = func(string) (destinationFile, error) {
		return &failingDestination{write: 1}, nil
	}
	var stdout strings.Builder
	failure := runDiff(mustParse(t, diffBase(absDiffFixtureBook(t), filepath.Join(dir, "out.json"))), &stdout, dir)
	if failure == nil || failure.stage != stageOutputWrite || failure.code != codeWriteFailure {
		t.Fatalf("failure = %+v, want output_write/write_failure", failure)
	}
	if stdout.String() != "" {
		t.Fatalf("a partial delivery emitted a receipt: %q", stdout.String())
	}
}

func TestDiffFailedReceiptKeepsDocument(t *testing.T) {
	dir := t.TempDir()
	out := filepath.Join(dir, "diff.json")
	failure := runDiff(mustParse(t, diffBase(absDiffFixtureBook(t), out)), &brokenWriter{}, dir)
	if failure == nil || failure.stage != stageStdoutWrite || failure.code != codeWriteFailure {
		t.Fatalf("failure = %+v, want stdout_write/write_failure", failure)
	}
	want, err := os.ReadFile(filepath.Join("testdata", "diff", "golden.json"))
	if err != nil {
		t.Fatal(err)
	}
	if got := readTemp(t, out); string(got) != string(want) {
		t.Fatalf("the document was not fully written before the receipt failed")
	}
}

func TestDiffServeCompatibility(t *testing.T) {
	bookBytes, err := os.ReadFile(diffFixtureBook(t))
	if err != nil {
		t.Fatal(err)
	}
	book, err := casefile.Verify(bookBytes)
	if err != nil {
		t.Fatalf("the fixture book does not verify: %v", err)
	}
	if _, err := platform.BuildModel(book, diffAsOf); err != nil {
		t.Fatalf("BuildModel rejected the book a diff reads: %v", err)
	}
}
