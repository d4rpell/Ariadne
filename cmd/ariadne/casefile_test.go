package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/d4rpell/Ariadne/internal/casefile"
	"github.com/d4rpell/Ariadne/internal/platform"
)

// Unit anchors of the book persistence commands (ADR-0037). The library is
// the oracle for every document: the produced bytes must equal casefile.Encode
// of a book the library itself admits, and the receipts must agree with
// Records and HeadHash of that same admitted book.

const casefileInstant = "2026-10-07T00:00:00Z"

func appendBase(book, out string) []string {
	return []string{"append",
		"--casebook", book,
		"--decision", "accepted",
		"--owner", "owner-example",
		"--approver", "approver-example",
		"--rationale", "synthetic rationale",
		"--bundle-hash", validHashA,
		"--subject-uid", "uid-1",
		"--container-name", "api",
		"--container-class", "regular",
		"--vulnerability-id", "CVE-2026-1001",
		"--decided-at", casefileInstant,
		"--out", out}
}

func writeBookFile(t *testing.T, dir, name string, book casefile.Book) string {
	t.Helper()
	document, err := casefile.Encode(book)
	if err != nil {
		t.Fatalf("encode oracle book: %v", err)
	}
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, document, 0o600); err != nil {
		t.Fatalf("write %s: %v", name, err)
	}
	return path
}

func TestBookWritesCanonicalEmptyBook(t *testing.T) {
	dir := t.TempDir()
	out := filepath.Join(dir, "book.json")
	exit, stdout, stderr := runCLI(t, []string{"book", "--out", out})
	if exit != 0 || stderr != "" {
		t.Fatalf("book exit=%d stderr=%q", exit, stderr)
	}
	if stdout != "{\"records\":0}\n" {
		t.Fatalf("receipt = %q", stdout)
	}
	document := readTemp(t, out)
	want, err := casefile.Encode(casefile.NewBook())
	if err != nil {
		t.Fatalf("oracle encode: %v", err)
	}
	if string(document) != string(want) {
		t.Fatalf("book bytes differ from the canonical empty book")
	}
	if _, err := casefile.Verify(document); err != nil {
		t.Fatalf("the produced book is not admitted: %v", err)
	}
}

func TestBookNeverOverwrites(t *testing.T) {
	dir := t.TempDir()
	out := writeBookFile(t, dir, "book.json", casefile.NewBook())
	sentinel := readTemp(t, out)
	expectRejection(t, []string{"book", "--out", out}, stageOutputWrite, codeAlreadyExists, 4)
	if after := readTemp(t, out); string(after) != string(sentinel) {
		t.Fatalf("the pre-existing destination was modified")
	}
}

func TestAppendRoundTrip(t *testing.T) {
	dir := t.TempDir()
	book := writeBookFile(t, dir, "book.json", casefile.NewBook())
	out := filepath.Join(dir, "grown.json")
	exit, stdout, stderr := runCLI(t, appendBase(book, out))
	if exit != 0 || stderr != "" {
		t.Fatalf("append exit=%d stderr=%q", exit, stderr)
	}
	admitted, err := casefile.Verify(readTemp(t, out))
	if err != nil {
		t.Fatalf("the produced book is not admitted: %v", err)
	}
	records, err := casefile.Records(admitted)
	if err != nil {
		t.Fatalf("records: %v", err)
	}
	head, err := casefile.HeadHash(admitted)
	if err != nil {
		t.Fatalf("head: %v", err)
	}
	if len(records) != 1 {
		t.Fatalf("records = %d, want 1", len(records))
	}
	if want := "{\"records\":1,\"head_hash\":\"" + head + "\"}\n"; stdout != want {
		t.Fatalf("receipt = %q, want %q", stdout, want)
	}
	if records[0].Decision.Scope.BundleHash != validHashA || records[0].Decision.RiskDecision != casefile.DecisionAccepted {
		t.Fatalf("the declared decision did not travel verbatim")
	}
}

func TestAppendFullOptionalsAndServeCompatibility(t *testing.T) {
	dir := t.TempDir()
	book := writeBookFile(t, dir, "book.json", casefile.NewBook())
	first := filepath.Join(dir, "first.json")
	if exit, _, stderr := runCLI(t, appendBase(book, first)); exit != 0 {
		t.Fatalf("first append exit=%d stderr=%q", exit, stderr)
	}
	admittedFirst, err := casefile.Verify(readTemp(t, first))
	if err != nil {
		t.Fatalf("first book not admitted: %v", err)
	}
	head, err := casefile.HeadHash(admittedFirst)
	if err != nil {
		t.Fatalf("head: %v", err)
	}
	second := filepath.Join(dir, "second.json")
	argv := append(appendBase(first, second),
		"--expires-at", "2027-01-01T00:00:00Z",
		"--supersedes", head,
		"--result-fingerprint", validFinger,
		"--controls", "change-control-1,ticket-42")
	exit, stdout, stderr := runCLI(t, argv)
	if exit != 0 || stderr != "" {
		t.Fatalf("append exit=%d stderr=%q", exit, stderr)
	}
	grown, err := casefile.Verify(readTemp(t, second))
	if err != nil {
		t.Fatalf("the produced book is not admitted: %v", err)
	}
	records, err := casefile.Records(grown)
	if err != nil || len(records) != 2 {
		t.Fatalf("records = %v", err)
	}
	if records[1].Decision.Supersedes == nil || *records[1].Decision.Supersedes != head {
		t.Fatalf("supersedes did not travel")
	}
	if records[1].Decision.ExpiresAt == nil || *records[1].Decision.ExpiresAt != "2027-01-01T00:00:00Z" {
		t.Fatalf("expires-at did not travel")
	}
	if records[1].Decision.Scope.ResultFingerprint == nil || *records[1].Decision.Scope.ResultFingerprint != validFinger {
		t.Fatalf("result-fingerprint did not travel")
	}
	if len(records[1].Decision.Controls) != 2 || records[1].Decision.Controls[1] != "ticket-42" {
		t.Fatalf("controls did not travel verbatim: %v", records[1].Decision.Controls)
	}
	// The serve read model consumes the produced book at a canonical instant.
	if _, err := platform.BuildModel(grown, casefileInstant); err != nil {
		t.Fatalf("BuildModel rejected the produced book: %v", err)
	}
	if want := "{\"records\":2,\"head_hash\":\"" + records[1].Hash + "\"}\n"; stdout != want {
		t.Fatalf("receipt = %q, want %q", stdout, want)
	}
}

func TestAppendGrammarBeforeAnyRead(t *testing.T) {
	// Every argv names a casebook that does not exist: a rejection here proves
	// the grammar decided before any file was read.
	absent := filepath.Join(t.TempDir(), "absent.json")
	cases := []struct {
		name   string
		mutate func([]string) []string
	}{
		{"decision outside the vocabulary", func(argv []string) []string {
			return replaceValue(argv, "--decision", "maybe")
		}},
		{"container class outside the vocabulary", func(argv []string) []string {
			return replaceValue(argv, "--container-class", "sidecar")
		}},
		{"bundle hash without sha256 grammar", func(argv []string) []string {
			return replaceValue(argv, "--bundle-hash", "1111")
		}},
		{"supersedes without sha256 grammar", func(argv []string) []string {
			return append(argv, "--supersedes", "sha256:ZZ")
		}},
		{"fingerprint without sha256 grammar", func(argv []string) []string {
			return append(argv, "--result-fingerprint", "sha256:ZZ")
		}},
		{"instant with offset", func(argv []string) []string {
			return replaceValue(argv, "--decided-at", "2026-10-07T00:00:00+00:00")
		}},
		{"instant with fraction", func(argv []string) []string {
			return replaceValue(argv, "--decided-at", "2026-10-07T00:00:00.5Z")
		}},
		{"expiry instant outside the profile", func(argv []string) []string {
			return append(argv, "--expires-at", "2027-1-1T00:00:00Z")
		}},
		{"controls with an empty element", func(argv []string) []string {
			return append(argv, "--controls", "a,,b")
		}},
		{"controls with a trailing comma", func(argv []string) []string {
			return append(argv, "--controls", "a,")
		}},
		{"controls that name nothing", func(argv []string) []string {
			return append(argv, "--controls", "")
		}},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			expectRejection(t, testCase.mutate(appendBase(absent, filepath.Join(t.TempDir(), "out.json"))),
				stageArguments, codeInvalidArguments, 2)
		})
	}
}

func replaceValue(argv []string, flag, value string) []string {
	for index, token := range argv {
		if token == flag {
			argv[index+1] = value
			return argv
		}
	}
	return argv
}

func TestAppendDeclaredFailures(t *testing.T) {
	dir := t.TempDir()
	t.Run("casebook missing", func(t *testing.T) {
		expectRejection(t, appendBase(filepath.Join(dir, "absent.json"), filepath.Join(dir, "out.json")),
			stageBundleRead, codeNotFound, 4)
	})
	t.Run("casebook not canonical", func(t *testing.T) {
		path := filepath.Join(dir, "broken.json")
		if err := os.WriteFile(path, []byte("{"), 0o600); err != nil {
			t.Fatalf("write: %v", err)
		}
		expectRejection(t, appendBase(path, filepath.Join(dir, "out.json")),
			stageBundleDecode, codeInvalidBundle, 3)
	})
	t.Run("supersedes names no record", func(t *testing.T) {
		book := writeBookFile(t, dir, "empty.json", casefile.NewBook())
		expectRejection(t, append(appendBase(book, filepath.Join(dir, "out.json")), "--supersedes", validHashB),
			stageCasefile, "invalid_reference", 3)
	})
	t.Run("owner beyond the actor budget", func(t *testing.T) {
		book := writeBookFile(t, dir, "empty2.json", casefile.NewBook())
		expectRejection(t, replaceValue(appendBase(book, filepath.Join(dir, "out.json")),
			"--owner", strings.Repeat("o", 257)),
			stageCasefile, "field_limit", 3)
	})
	t.Run("controls beyond the cardinality budget", func(t *testing.T) {
		book := writeBookFile(t, dir, "empty3.json", casefile.NewBook())
		many := make([]string, 33)
		for index := range many {
			many[index] = "control-" + strings.Repeat("c", 1) + string(rune('a'+index%26))
		}
		expectRejection(t, append(appendBase(book, filepath.Join(dir, "out.json")), "--controls", strings.Join(many, ",")),
			stageCasefile, "control_limit", 3)
	})
}

// TestAppendCasebookBoundAnchorsTheReadLimit pins the casebook transport bound
// to the book profile: one byte over MaxBookBytes is an input_limit at the read
// stage, before any decoder — a looser bound would silently accept a larger
// source and defer the refusal to the verifier.
func TestAppendCasebookBoundAnchorsTheReadLimit(t *testing.T) {
	dir := t.TempDir()
	oversized := filepath.Join(dir, "oversized.json")
	if err := os.WriteFile(oversized, make([]byte, casefile.MaxBookBytes+1), 0o600); err != nil {
		t.Fatalf("write oversized casebook: %v", err)
	}
	expectRejection(t, appendBase(oversized, filepath.Join(dir, "out.json")),
		stageBundleRead, codeInputLimit, 3)
}

// TestAppendNeverOverwritesThePredecessor proves the declared promise that the
// book an append derives from is never the file being written: naming the same
// path for the casebook and the destination is an already_exists at the write
// stage and the original bytes survive untouched.
func TestAppendNeverOverwritesThePredecessor(t *testing.T) {
	dir := t.TempDir()
	book := writeBookFile(t, dir, "book.json", casefile.NewBook())
	before := readTemp(t, book)
	expectRejection(t, appendBase(book, book), stageOutputWrite, codeAlreadyExists, 4)
	if after := readTemp(t, book); string(after) != string(before) {
		t.Fatalf("the predecessor book was modified")
	}
}

// TestAppendRecordBudgetAndPartialDelivery covers the remaining persistence
// failures the contract declares: a book at the record ceiling refuses one more
// record without touching the destination, a short destination delivery is a
// write failure with no receipt, and a failed receipt is named at stdout while
// the book itself is fully written.
func TestAppendRecordBudgetAndPartialDelivery(t *testing.T) {
	t.Run("record ceiling", func(t *testing.T) {
		dir := t.TempDir()
		book := casefile.NewBook()
		for index := 0; index < casefile.MaxRecords; index++ {
			grown, err := casefile.Append(book, casefile.DecisionInput{
				RiskDecision: casefile.DecisionAccepted,
				Owner:        "owner-example",
				Approver:     "approver-example",
				Rationale:    "synthetic rationale",
				Scope: casefile.Scope{
					BundleHash:      validHashA,
					SubjectUID:      "uid-1",
					ContainerName:   "api",
					ContainerClass:  casefile.ContainerRegular,
					VulnerabilityID: "CVE-2026-1001",
				},
				DecidedAt: casefileInstant,
			})
			if err != nil {
				t.Fatalf("oracle append %d: %v", index, err)
			}
			book = grown
		}
		full := writeBookFile(t, dir, "full.json", book)
		out := filepath.Join(dir, "never.json")
		expectRejection(t, appendBase(full, out), stageCasefile, "book_limit", 3)
		if _, err := os.Stat(out); !os.IsNotExist(err) {
			t.Fatalf("a refused append created the destination")
		}
	})

	t.Run("short destination delivery", func(t *testing.T) {
		dir := t.TempDir()
		book := writeBookFile(t, dir, "book.json", casefile.NewBook())
		original := createDestination
		defer func() { createDestination = original }()
		createDestination = func(string) (destinationFile, error) {
			return &failingDestination{write: 1}, nil
		}
		var stdout strings.Builder
		failure := runAppend(mustParse(t, appendBase(book, filepath.Join(dir, "out.json"))), &stdout, dir)
		if failure == nil || failure.stage != stageOutputWrite || failure.code != codeWriteFailure {
			t.Fatalf("failure = %+v, want output_write/write_failure", failure)
		}
		if stdout.String() != "" {
			t.Fatalf("a partial delivery emitted a receipt: %q", stdout.String())
		}
	})

	t.Run("failed receipt keeps the book", func(t *testing.T) {
		dir := t.TempDir()
		book := writeBookFile(t, dir, "book.json", casefile.NewBook())
		out := filepath.Join(dir, "grown.json")
		failure := runAppend(mustParse(t, appendBase(book, out)), &brokenWriter{}, dir)
		if failure == nil || failure.stage != stageStdoutWrite || failure.code != codeWriteFailure {
			t.Fatalf("failure = %+v, want stdout_write/write_failure", failure)
		}
		if _, err := casefile.Verify(readTemp(t, out)); err != nil {
			t.Fatalf("the book was not fully written before the receipt failed: %v", err)
		}
	})
}

// mustParse runs the argument phase and fails the test on rejection.
func mustParse(t *testing.T, argv []string) invocation {
	t.Helper()
	call, failure := parseArguments(argv)
	if failure != nil {
		t.Fatalf("parse %v: %+v", argv, failure)
	}
	return call
}
