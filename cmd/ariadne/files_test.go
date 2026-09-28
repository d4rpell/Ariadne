package main

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// IO-01..IO-06: the ratified filesystem frontier. The cases use real files in
// private temporary directories; the deterministic failures of the write side
// use the injected destination, which never reaches production.

func TestReadInputMissingFile(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "absent.json")
	_, failure := readInput(missing, stageBundleRead, maxBundleInputBytes, true, t.TempDir())
	if failure == nil || failure.code != codeNotFound || failure.exit != 4 {
		t.Fatalf("missing file = %+v, want not_found/4", failure)
	}
}

func TestReadInputDirectoryIsInvalidFile(t *testing.T) {
	dir := t.TempDir()
	_, failure := readInput(dir, stageBundleRead, maxBundleInputBytes, true, dir)
	if failure == nil || failure.code != codeInvalidFile {
		t.Fatalf("directory = %+v, want invalid_file", failure)
	}
}

func TestReadInputEmptyPackIsNotMissing(t *testing.T) {
	// An empty pack is a valid read; its emptiness is decided by pack admission
	// (missing_pack), never confused with not_found.
	empty := writeTemp(t, "empty.pack", nil)
	data, failure := readInput(empty, stagePackRead, 1<<20, false, filepath.Dir(empty))
	if failure != nil {
		t.Fatalf("empty pack read failed: %+v", failure)
	}
	if len(data) != 0 {
		t.Fatalf("empty pack read %d bytes", len(data))
	}
}

func TestReadInputLimitNPlusOne(t *testing.T) {
	dir := t.TempDir()
	limitPath := filepath.Join(dir, "limit.json")
	if err := os.WriteFile(limitPath, []byte(strings.Repeat("x", 100)), 0o600); err != nil {
		t.Fatal(err)
	}
	// N bytes are accepted.
	if _, failure := readInput(limitPath, stageBundleRead, 100, false, dir); failure != nil {
		t.Fatalf("N bytes rejected: %+v", failure)
	}
	// N+1 bytes are rejected as input_limit of the read stage.
	overPath := filepath.Join(dir, "over.json")
	if err := os.WriteFile(overPath, []byte(strings.Repeat("x", 101)), 0o600); err != nil {
		t.Fatal(err)
	}
	failure := func() *cliError {
		_, failure := readInput(overPath, stageBundleRead, 100, false, dir)
		return failure
	}()
	if failure == nil || failure.code != codeInputLimit || failure.exit != 3 {
		t.Fatalf("N+1 bytes = %+v, want input_limit/3", failure)
	}
}

func TestReadInputDepthLimit(t *testing.T) {
	deep := writeTemp(t, "deep.json", []byte(`{"a":`+strings.Repeat("[", 40)+strings.Repeat("]", 40)+`}`))
	failure := func() *cliError {
		_, failure := readInput(deep, stageContextRead, maxContextInputBytes, true, filepath.Dir(deep))
		return failure
	}()
	if failure == nil || failure.code != codeInputLimit {
		t.Fatalf("deep document = %+v, want input_limit", failure)
	}
}

func TestSymlinkInputRejected(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "real.json")
	if err := os.WriteFile(target, []byte(`{}`), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "link.json")
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	failure := func() *cliError {
		_, failure := readInput(link, stageBundleRead, maxBundleInputBytes, true, dir)
		return failure
	}()
	if failure == nil || failure.code != codeInvalidFile {
		t.Fatalf("symlink = %+v, want invalid_file", failure)
	}
}

func TestWriteOutputCreatesExclusively(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "report.json")
	if failure := writeOutput(path, []byte("first"), dir); failure != nil {
		t.Fatalf("first create failed: %+v", failure)
	}
	if got := string(readTemp(t, path)); got != "first" {
		t.Fatalf("written bytes = %q", got)
	}
	// A second delivery to the same path is already_exists and the existing
	// bytes stay byte-identical.
	failure := writeOutput(path, []byte("second"), dir)
	if failure == nil || failure.code != codeAlreadyExists || failure.exit != 4 {
		t.Fatalf("second create = %+v, want already_exists/4", failure)
	}
	if got := string(readTemp(t, path)); got != "first" {
		t.Fatalf("existing file was modified: %q", got)
	}
}

func TestWriteOutputMissingParent(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "absent", "report.json")
	failure := writeOutput(path, []byte("x"), dir)
	if failure == nil || failure.code != codeWriteFailure {
		t.Fatalf("missing parent = %+v, want write_failure", failure)
	}
}

// The write side reports a short write and a failed Close as write failures,
// and it never reports success for a partial delivery.
func TestWriteOutputShortWriteAndCloseFailure(t *testing.T) {
	dir := t.TempDir()
	original := createDestination
	defer func() { createDestination = original }()

	createDestination = func(path string) (destinationFile, error) {
		return &failingDestination{write: 1, err: nil}, nil
	}
	failure := writeOutput(filepath.Join(dir, "short.json"), []byte("payload"), dir)
	if failure == nil || failure.code != codeWriteFailure {
		t.Fatalf("short write = %+v, want write_failure", failure)
	}

	createDestination = func(path string) (destinationFile, error) {
		return &failingDestination{write: -1, err: nil, closeErr: errors.New("close failed")}, nil
	}
	failure = writeOutput(filepath.Join(dir, "close.json"), []byte("payload"), dir)
	if failure == nil || failure.code != codeWriteFailure {
		t.Fatalf("close failure = %+v, want write_failure", failure)
	}
}

// failingDestination is a deterministic double: write = -1 completes the write
// and fails only Close; any other value fails the write after that many bytes.
// statErr or a non-regular mode exercise the descriptor check, and writes counts
// every Write call so a test can prove the check preceded any delivery.
type failingDestination struct {
	write    int
	err      error
	closeErr error
	statErr  error
	mode     os.FileMode
	writes   int
}

func (destination *failingDestination) Write(data []byte) (int, error) {
	destination.writes++
	if destination.write < 0 {
		return len(data), destination.err
	}
	if destination.write < len(data) {
		return destination.write, destination.err
	}
	return len(data), destination.err
}

func (destination *failingDestination) Close() error { return destination.closeErr }

func (destination *failingDestination) Stat() (os.FileInfo, error) {
	mode := destination.mode
	if mode == 0 {
		mode = 0o644
	}
	return fakeFileInfo{mode: mode}, destination.statErr
}

// fakeFileInfo carries only the mode: the descriptor checks read nothing else.
type fakeFileInfo struct {
	mode os.FileMode
}

func (info fakeFileInfo) Name() string       { return "fake" }
func (info fakeFileInfo) Size() int64        { return 0 }
func (info fakeFileInfo) Mode() os.FileMode  { return info.mode }
func (info fakeFileInfo) ModTime() time.Time { return time.Time{} }
func (info fakeFileInfo) IsDir() bool        { return info.mode.IsDir() }
func (info fakeFileInfo) Sys() any           { return nil }

// The output descriptor is the authority: a created path that is not a regular
// file is refused before any byte is written.
func TestWriteOutputRejectsNonRegularDescriptor(t *testing.T) {
	dir := t.TempDir()
	original := createDestination
	defer func() { createDestination = original }()
	createDestination = func(path string) (destinationFile, error) {
		return &failingDestination{mode: os.ModeNamedPipe}, nil
	}
	failure := writeOutput(filepath.Join(dir, "report.json"), []byte("x"), dir)
	if failure == nil || failure.code != codeInvalidFile {
		t.Fatalf("non-regular destination = %+v, want invalid_file", failure)
	}
}

func TestWriteOutputDescriptorStatFailure(t *testing.T) {
	dir := t.TempDir()
	original := createDestination
	defer func() { createDestination = original }()
	createDestination = func(path string) (destinationFile, error) {
		return &failingDestination{statErr: errors.New("stat failed")}, nil
	}
	failure := writeOutput(filepath.Join(dir, "report.json"), []byte("x"), dir)
	if failure == nil || failure.code != codeWriteFailure {
		t.Fatalf("descriptor stat failure = %+v, want write_failure", failure)
	}
}

// H02 regression: the refusal covers every mode os.Lstat exposes for a link, a
// reparse point or a special file, and admits only a regular file or a
// directory. A reparse point that the mode hides — DEDUP — is not this
// function's responsibility: the walker refuses it through the attribute bit
// (reparseAttribute), which needs no forbidden dependency.
func TestUnacceptableModes(t *testing.T) {
	refused := []os.FileMode{
		os.ModeSymlink,
		os.ModeIrregular,
		os.ModeSymlink | os.ModeDir,
		os.ModeIrregular | os.ModeDir,
		os.ModeSocket,
		os.ModeDevice,
		os.ModeCharDevice,
		os.ModeNamedPipe,
	}
	for _, mode := range refused {
		if !unacceptableMode(mode) {
			t.Errorf("unacceptableMode(%v) = false, want true", mode)
		}
	}
	admitted := []os.FileMode{0, 0o644, os.ModeDir | 0o755}
	for _, mode := range admitted {
		if unacceptableMode(mode) {
			t.Errorf("unacceptableMode(%v) = true, want false", mode)
		}
	}
}

// A write failure before the destination exists leaves nothing behind, and no
// temporary file is ever created in the operator directory.
func TestWriteOutputLeavesNoTemporaries(t *testing.T) {
	dir := t.TempDir()
	original := createDestination
	defer func() { createDestination = original }()
	createDestination = func(path string) (destinationFile, error) {
		return nil, errors.New("create failed")
	}
	failure := writeOutput(filepath.Join(dir, "report.json"), []byte("x"), dir)
	if failure == nil || failure.code != codeWriteFailure {
		t.Fatalf("create failure = %+v, want write_failure", failure)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatalf("directory is not empty after failure: %v", entries)
	}
}

// A writer that fails mid-stream keeps the partial file and reports failure:
// the runner never deletes what it cannot prove complete, and it never claims
// success either.
func TestStdoutWriteFailureIsReported(t *testing.T) {
	figures := composeFixture(t, "F09-unmapped-redhat-package")
	broken := &brokenWriter{}
	exit := run(evaluateArgs(figures), broken, io.Discard)
	if exit != 4 {
		t.Fatalf("stdout failure exit = %d, want 4", exit)
	}
}

type brokenWriter struct{}

func (writer *brokenWriter) Write(data []byte) (int, error) {
	return 0, errors.New("stdout closed")
}
