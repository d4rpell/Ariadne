package main

import (
	"bytes"
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/d4rpell/Ariadne/internal/evaluator"
	"github.com/d4rpell/Ariadne/internal/report"
	"github.com/d4rpell/Ariadne/internal/rulepack"
)

// H06 regression: every stdout delivery checks the byte count and names an
// observed timeout as itself. The three outputs are covered with a partial
// write, a short write and a timeout.
type stuckWriter struct {
	partial int
	err     error
}

func (writer *stuckWriter) Write(data []byte) (int, error) {
	if writer.err != nil {
		return writer.partial, writer.err
	}
	return writer.partial, nil
}

type timeoutFailure struct{}

func (timeoutFailure) Error() string { return "io timeout" }
func (timeoutFailure) Timeout() bool { return true }

func TestStdoutDeliveriesReportPartialWritesAndTimeouts(t *testing.T) {
	figures := composeFixture(t, "F09-unmapped-redhat-package")
	fingerprint := receiptFingerprint(t, figures)

	deliveries := []struct {
		name string
		argv []string
	}{
		{"help", []string{"--help"}},
		{"receipt", evaluateArgs(figures)},
		{"verified", verifyArgs(figures, fingerprint)},
	}
	for _, delivery := range deliveries {
		t.Run(delivery.name+"/short write", func(t *testing.T) {
			writer := &stuckWriter{partial: 0}
			exit := run(delivery.argv, writer, io.Discard)
			if exit != 4 {
				t.Fatalf("exit = %d, want 4", exit)
			}
		})
		t.Run(delivery.name+"/partial then nil", func(t *testing.T) {
			// A writer that reports fewer bytes than it received without an
			// error is a short delivery, never a success.
			writer := &stuckWriter{partial: 1}
			exit := run(delivery.argv, writer, io.Discard)
			if exit != 4 {
				t.Fatalf("exit = %d, want 4", exit)
			}
		})
		t.Run(delivery.name+"/timeout", func(t *testing.T) {
			writer := &stuckWriter{partial: 0, err: timeoutFailure{}}
			var stderr bytes.Buffer
			exit := run(delivery.argv, writer, &stderr)
			if exit != 4 {
				t.Fatalf("exit = %d, want 4", exit)
			}
			want := `{"error":{"stage":"stdout_write","code":"timeout","message":"ariadne: timeout"}}` + "\n"
			if stderr.String() != want {
				t.Fatalf("stderr = %q, want %q", stderr.String(), want)
			}
		})
	}
}

// H07 regression: the exact token `-` designates no valid file and is refused
// at the argument phase, for every file flag and every command.
func TestArgumentsRejectDashToken(t *testing.T) {
	cases := [][]string{
		{"evaluate", "--bundle", "-", "--bundle-hash", validHashA, "--pack", "p", "--context", "c"},
		{"evaluate", "--bundle", "b", "--bundle-hash", validHashA, "--pack", "-", "--context", "c"},
		{"evaluate", "--bundle", "b", "--bundle-hash", validHashA, "--pack", "p", "--context", "-"},
		{"report", "--bundle", "b", "--bundle-hash", validHashA, "--pack", "p", "--context", "c",
			"--format", "json", "--out", "-"},
		{"verify", "--bundle", "-", "--bundle-hash", validHashA, "--pack", "p", "--context", "c",
			"--result-fingerprint", validFinger},
	}
	for _, argv := range cases {
		expectRejection(t, argv, stageArguments, codeInvalidArguments, 2)
	}
}

// H09 regression: an empty string is a semantic restriction of the Request, not
// a forma one: the decoder admits it and the kernel names it with its own
// precedence (invalid_target), never context_decode/invalid_context.
func TestEmptyTargetReachesTheKernelAsInvalidTarget(t *testing.T) {
	figures := composeFixture(t, "F09-unmapped-redhat-package")
	emptyUID := mutateContextPath(t, func(document map[string]any) {
		document["target"].(map[string]any)["subject_uid"] = ""
	})
	argv := []string{"evaluate",
		"--bundle", figures.bundle, "--bundle-hash", figures.bundleHash,
		"--pack", figures.pack, "--context", emptyUID}
	expectRejection(t, argv, stageEvaluate, "invalid_target", 3)
}

// H03 regression: reserved device names beyond the basic four are refused, with
// their extensions, and the check is a pure function, so it is testable on
// every platform.
func TestReservedDeviceNames(t *testing.T) {
	reserved := []string{
		"CON", "con", "Con.txt", "NUL.", "NUL.tar.gz", "PRN", "AUX",
		"CONIN$", "CONOUT$", "conin$", "COM1", "com9", "LPT1", "lpt9",
		"COM\u00b9", "LPT\u00b2", "COM0", "LPT0", "NUL ", "CON..",
	}
	for _, component := range reserved {
		if !reservedDeviceName(component) {
			t.Errorf("reservedDeviceName(%q) = false, want true", component)
		}
	}
	admitted := []string{"console", "connection", "com", "lpt", "com10", "lpt10", "auxiliary", "nulls", "con-", "c"}
	for _, component := range admitted {
		if reservedDeviceName(component) {
			t.Errorf("reservedDeviceName(%q) = true, want false", component)
		}
	}
}

// H01/H02 regression: a route whose intermediate component is a link is refused
// as well as one whose final component is. The intermediate case is the one a
// root-losing walk would miss.
func TestSymlinkIntermediateComponentRejected(t *testing.T) {
	dir := t.TempDir()
	realDir := filepath.Join(dir, "real")
	if err := os.Mkdir(realDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(realDir, "bundle.json"), []byte(`{}`), 0o600); err != nil {
		t.Fatal(err)
	}
	linkDir := filepath.Join(dir, "linked")
	if err := os.Symlink(realDir, linkDir); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	failure := func() *cliError {
		_, failure := readInput(filepath.Join(linkDir, "bundle.json"), stageBundleRead, maxBundleInputBytes, true, dir)
		return failure
	}()
	if failure == nil || failure.code != codeInvalidFile {
		t.Fatalf("intermediate link = %+v, want invalid_file", failure)
	}
}

// H03 regression: the type is decided before the open. On Unix a FIFO would
// block an open and is refused by the pre-check; the case skips where the
// platform cannot create the special file.
func TestFIFOInputRejectedBeforeOpen(t *testing.T) {
	dir := t.TempDir()
	fifo := filepath.Join(dir, "pipe")
	if err := makeFIFO(fifo); err != nil {
		t.Skipf("FIFO unavailable: %v", err)
	}
	failure := func() *cliError {
		_, failure := readInput(fifo, stageBundleRead, maxBundleInputBytes, true, dir)
		return failure
	}()
	if failure == nil || failure.code != codeInvalidFile {
		t.Fatalf("FIFO = %+v, want invalid_file", failure)
	}
}

// H05 regression: a Close failure of the input is a transport failure, named
// read_failure whatever the underlying error looks like — a close is not an
// open — and timeout only when the error is identifiable as one. The three
// input roles share the classification.
func TestInputCloseFailureIsReported(t *testing.T) {
	dir := t.TempDir()
	real := filepath.Join(dir, "input.json")
	if err := os.WriteFile(real, []byte(`{}`), 0o600); err != nil {
		t.Fatal(err)
	}
	original := openSource
	defer func() { openSource = original }()
	stages := []string{stageBundleRead, stageContextRead, stagePackRead}
	cases := []struct {
		name     string
		closeErr error
		want     string
	}{
		{"generic", errors.New("close failed"), codeReadFailure},
		{"permission", compositeFailure{message: "permission", is: []error{fs.ErrPermission}}, codeReadFailure},
		{"missing", compositeFailure{message: "missing", is: []error{fs.ErrNotExist}}, codeReadFailure},
		{"timeout", timeoutFailure{}, codeTimeout},
	}
	for _, testCase := range cases {
		for _, stage := range stages {
			t.Run(testCase.name+"/"+stage, func(t *testing.T) {
				openSource = func(path string) (sourceFile, error) {
					file, err := os.Open(path)
					if err != nil {
						return nil, err
					}
					return &closingSource{file: file, closeErr: testCase.closeErr}, nil
				}
				failure := func() *cliError {
					_, failure := readInput(real, stage, maxBundleInputBytes, false, dir)
					return failure
				}()
				if failure == nil || failure.code != testCase.want || failure.exit != 4 {
					t.Fatalf("close %s = %+v, want %s/4", testCase.name, failure, testCase.want)
				}
			})
		}
	}
}

type closingSource struct {
	file     *os.File
	closeErr error
}

func (source *closingSource) Read(data []byte) (int, error) { return source.file.Read(data) }
func (source *closingSource) Stat() (os.FileInfo, error)    { return source.file.Stat() }
func (source *closingSource) Close() error                  { _ = source.file.Close(); return source.closeErr }

// IN-08: the full error table as data, independent of the production table: every
// listed pair resolves to its ratified status and an unknown pair fails closed.
func TestErrorTableRows(t *testing.T) {
	rows := []struct {
		stage string
		code  string
		exit  int
	}{
		{stageArguments, codeInvalidArguments, 2},
		{stageArguments, codeUnknownCommand, 2},
		{stageArguments, codeCommandDeferred, 2},
		{stageBundleDecode, codeInvalidBundle, 3},
		{stageContextDecode, codeInvalidContext, 3},
		{stageBundleRead, codeInputLimit, 3},
		{stageContextRead, codeInputLimit, 3},
		{stagePackRead, codeInputLimit, 3},
		{stageBundleDecode, codeInputLimit, 3},
		{stageEvaluate, codeInputLimit, 3},
		{stageEvaluate, "invalid_target", 3},
		{stageEvaluate, "invalid_bundle", 3},
		{stageEvaluate, codeInvalidContext, 3},
		{stageEvaluate, "value_hash_mismatch", 3},
		{stageEvaluate, "missing_pack", 3},
		{stageEvaluate, "invalid_pack", 3},
		{stageEvaluate, "unsupported_pack", 3},
		{stageEvaluate, "pack_identity_mismatch", 3},
		{stageEvaluate, "pack_downgrade", 3},
		{stageEvaluate, "pack_equivocation", 3},
		{stageEvaluate, "pack_not_yet_valid", 3},
		{stageEvaluate, "pack_expired", 3},
		{stageEvaluate, "ruleset_mismatch", 3},
		{stageEvaluate, "evaluation_limit", 3},
		{stageBundleRead, codeNotFound, 4},
		{stageBundleRead, codePermissionDenied, 4},
		{stageBundleRead, codeInvalidFile, 4},
		{stageBundleRead, codeReadFailure, 4},
		{stageBundleRead, codeTimeout, 4},
		{stageContextRead, codeNotFound, 4},
		{stageContextRead, codePermissionDenied, 4},
		{stageContextRead, codeInvalidFile, 4},
		{stageContextRead, codeReadFailure, 4},
		{stageContextRead, codeTimeout, 4},
		{stagePackRead, codeNotFound, 4},
		{stagePackRead, codePermissionDenied, 4},
		{stagePackRead, codeInvalidFile, 4},
		{stagePackRead, codeReadFailure, 4},
		{stagePackRead, codeTimeout, 4},
		{stageOutputWrite, "already_exists", 4},
		{stageOutputWrite, codePermissionDenied, 4},
		{stageOutputWrite, codeInvalidFile, 4},
		{stageOutputWrite, codeWriteFailure, 4},
		{stageOutputWrite, codeTimeout, 4},
		{stageStdoutWrite, codeWriteFailure, 4},
		{stageStdoutWrite, codeTimeout, 4},
		{stageEvaluate, "bundle_hash_mismatch", 5},
		{stageEvaluate, "pack_hash_mismatch", 5},
		{stageVerify, codeResultFingerprintMismatch, 5},
		{stageReport, "invalid_result", 6},
		{stageReport, "invalid_bundle", 6},
		{stageReport, "bundle_hash_mismatch", 6},
		{stageReport, "invalid_reference", 6},
		{stageReport, "invalid_report", 6},
		{stageReport, "render_failure", 6},
		{stageInternal, codeInternalFailure, 6},
	}
	for _, row := range rows {
		if got := newFailure(row.stage, row.code); got.exit != row.exit {
			t.Errorf("newFailure(%q, %q).exit = %d, want %d", row.stage, row.code, got.exit, row.exit)
		}
	}
	if got := newFailure(stageEvaluate, "no_such_code"); got.code != codeInternalFailure || got.exit != 6 {
		t.Fatalf("unknown code = %+v, want internal_failure/6", got)
	}
	if got := newFailure("no_such_stage", codeNotFound); got.code != codeInternalFailure || got.exit != 6 {
		t.Fatalf("unknown stage = %+v, want internal_failure/6", got)
	}
}

// The classifiers follow the ratified order with errors that satisfy more than
// one category at once: only the precedence decides, so swapping two clauses
// turns a case red.
type compositeFailure struct {
	message string
	is      []error
	timed   bool
}

func (failure compositeFailure) Error() string { return failure.message }
func (failure compositeFailure) Timeout() bool { return failure.timed }
func (failure compositeFailure) Is(target error) bool {
	for _, candidate := range failure.is {
		if candidate == target {
			return true
		}
	}
	return false
}

func TestClassifiersOrder(t *testing.T) {
	// A failure that is both a timeout and a permission failure: the observed
	// timeout must win, which only a first-clause timeout check produces.
	both := compositeFailure{message: "timeout and permission", is: []error{fs.ErrPermission}, timed: true}
	if code := classifyRead(both); code != codeTimeout {
		t.Fatalf("timeout over permission = %q, want timeout", code)
	}
	if code := classifyCreate(both); code != codeTimeout {
		t.Fatalf("create timeout over permission = %q, want timeout", code)
	}
	// A failure that is both a permission and a missing-file failure: permission
	// comes first.
	permissionAndMissing := compositeFailure{message: "permission and missing", is: []error{fs.ErrPermission, fs.ErrNotExist}}
	if code := classifyRead(permissionAndMissing); code != codePermissionDenied {
		t.Fatalf("permission over not-found = %q, want permission_denied", code)
	}
	// Create side: existence loses against permission and against timeout.
	permissionAndExists := compositeFailure{message: "permission and exists", is: []error{fs.ErrPermission, fs.ErrExist}}
	if code := classifyCreate(permissionAndExists); code != codePermissionDenied {
		t.Fatalf("permission over exists = %q, want permission_denied", code)
	}
	existsAndTimed := compositeFailure{message: "exists and timeout", is: []error{fs.ErrExist}, timed: true}
	if code := classifyCreate(existsAndTimed); code != codeTimeout {
		t.Fatalf("timeout over exists = %q, want timeout", code)
	}
	// Close side: every close failure is a read failure except a timeout, even
	// when the underlying failure looks like a permission or existence story.
	if code := classifyClose(compositeFailure{message: "permission", is: []error{fs.ErrPermission}}); code != codeReadFailure {
		t.Fatalf("close permission = %q, want read_failure", code)
	}
	if code := classifyClose(compositeFailure{message: "missing", is: []error{fs.ErrNotExist}}); code != codeReadFailure {
		t.Fatalf("close not-found = %q, want read_failure", code)
	}
	if code := classifyClose(both); code != codeTimeout {
		t.Fatalf("close timeout = %q, want timeout", code)
	}
	// Plain single-category controls.
	if code := classifyRead(fs.ErrPermission); code != codePermissionDenied {
		t.Fatalf("permission = %q, want permission_denied", code)
	}
	if code := classifyRead(fs.ErrNotExist); code != codeNotFound {
		t.Fatalf("not found = %q, want not_found", code)
	}
	if code := classifyRead(errors.New("other")); code != codeReadFailure {
		t.Fatalf("other = %q, want read_failure", code)
	}
	if code := classifyCreate(fs.ErrExist); code != codeAlreadyExists {
		t.Fatalf("create exist = %q, want already_exists", code)
	}
	if code := classifyCreate(errors.New("other")); code != codeWriteFailure {
		t.Fatalf("create other = %q, want write_failure", code)
	}
}

// The diagnostic is exactly one compact JSON line with LF and no extra field,
// whatever the pair.
func TestDiagnosticExactBytes(t *testing.T) {
	var buffer bytes.Buffer
	writeDiagnostic(&buffer, newFailure(stageEvaluate, "pack_expired"))
	want := `{"error":{"stage":"evaluate","code":"pack_expired","message":"ariadne: pack_expired"}}` + "\n"
	if buffer.String() != want {
		t.Fatalf("diagnostic = %q, want %q", buffer.String(), want)
	}
	if strings.Count(buffer.String(), "\n") != 1 {
		t.Fatalf("diagnostic is not one line")
	}
}

// kernelFailure maps evaluator and rulepack failures by code and fails closed on
// anything it cannot name; rendererFailure owns the report stage. Both are
// exercised with typed errors of the real packages, not with message strings.
func TestKernelAndRendererFailureMapping(t *testing.T) {
	evaluatorCodes := []struct {
		code string
		exit int
	}{
		{"input_limit", 3},
		{"invalid_target", 3},
		{"invalid_bundle", 3},
		{"value_hash_mismatch", 3},
		{"ruleset_mismatch", 3},
		{"evaluation_limit", 3},
		{"bundle_hash_mismatch", 5},
	}
	for _, testCase := range evaluatorCodes {
		err := &evaluator.Error{Code: evaluator.ErrorCode(testCase.code), Index: -1}
		got := kernelFailure(err)
		if got.stage != stageEvaluate || got.code != testCase.code || got.exit != testCase.exit {
			t.Errorf("kernelFailure(evaluator/%s) = %+v, want evaluate/%s/%d", testCase.code, got, testCase.code, testCase.exit)
		}
	}
	rulepackCodes := []struct {
		code string
		exit int
	}{
		{"input_limit", 3},
		{"invalid_context", 3},
		{"missing_pack", 3},
		{"invalid_pack", 3},
		{"unsupported_pack", 3},
		{"pack_identity_mismatch", 3},
		{"pack_downgrade", 3},
		{"pack_equivocation", 3},
		{"pack_not_yet_valid", 3},
		{"pack_expired", 3},
		{"pack_hash_mismatch", 5},
	}
	for _, testCase := range rulepackCodes {
		err := &rulepack.Error{Code: rulepack.ErrorCode(testCase.code), Index: -1}
		got := kernelFailure(err)
		if got.stage != stageEvaluate || got.code != testCase.code || got.exit != testCase.exit {
			t.Errorf("kernelFailure(rulepack/%s) = %+v, want evaluate/%s/%d", testCase.code, got, testCase.code, testCase.exit)
		}
	}
	if got := kernelFailure(errors.New("untyped")); got.code != codeInternalFailure || got.exit != 6 {
		t.Fatalf("untyped kernel failure = %+v, want internal_failure/6", got)
	}

	reportCodes := []string{"invalid_result", "invalid_bundle", "bundle_hash_mismatch", "invalid_reference", "invalid_report", "render_failure"}
	for _, code := range reportCodes {
		err := &report.Error{Code: report.ErrorCode(code)}
		got := rendererFailure(err)
		if got.stage != stageReport || got.code != code || got.exit != 6 {
			t.Errorf("rendererFailure(%s) = %+v, want report/%s/6", code, got, code)
		}
	}
	if got := rendererFailure(errors.New("untyped")); got.code != codeInternalFailure || got.exit != 6 {
		t.Fatalf("untyped renderer failure = %+v, want internal_failure/6", got)
	}
}

// H01 regression: the route is resolved exactly once, and a Windows
// drive-rooted spelling — which `Open` resolves against the drive root while the
// walk would resolve it against the working directory — is refused as ambiguous
// instead of being inspected and opened as two different files.
func TestDriveRootedSpellingRefusedOnWindows(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("drive-rooted spelling is a Windows form")
	}
	dir := t.TempDir()
	failure := func() *cliError {
		_, failure := readInput(`\Windows\win.ini`, stageBundleRead, maxBundleInputBytes, false, dir)
		return failure
	}()
	if failure == nil || failure.code != codeInvalidFile {
		t.Fatalf("drive-rooted route = %+v, want invalid_file", failure)
	}
	// The same shape as an output path is refused before the create.
	outputFailure := writeOutput(`\Windows\win.ini`, []byte("x"), dir)
	if outputFailure == nil || outputFailure.code != codeInvalidFile {
		t.Fatalf("drive-rooted output = %+v, want invalid_file", outputFailure)
	}
}

// H01 regression, third pass: the separator set is the platform's. On Unix a
// backslash is an ordinary character of a name, so a component like `link\name`
// must stay one component; splitting it would walk a path that does not exist
// and let the real link pass uninspected. The function is parameterised, so both
// platform behaviours are tested from any host.
func TestSplitRouteComponentsPerPlatform(t *testing.T) {
	unix := splitRouteComponents(`tmp/base/link\name/file`, false)
	want := []string{"tmp", "base", `link\name`, "file"}
	if len(unix) != len(want) {
		t.Fatalf("unix split = %q, want %q", unix, want)
	}
	for index := range want {
		if unix[index] != want[index] {
			t.Fatalf("unix split = %q, want %q", unix, want)
		}
	}
	windows := splitRouteComponents(`tmp\base\link\name\file`, true)
	if len(windows) != 5 {
		t.Fatalf("windows split = %q, want five components", windows)
	}
	// A Windows route also accepts the forward slash; a Unix route does not
	// treat the backslash as a separator.
	mixed := splitRouteComponents(`tmp/base/link/name`, true)
	if len(mixed) != 4 {
		t.Fatalf("windows split of forward slashes = %q, want four components", mixed)
	}
}

// H02 regression, third pass: the reparse attribute is read from the value
// Sys() hands out, so a DEDUP tag — which Go classifies as a regular file —
// is refused by the same rule as any other reparse point. The synthetic values
// exercise the reader on any platform; the Windows gate stays in
// reparseAttribute.
func TestReparseAttributeReader(t *testing.T) {
	type win32Attributes struct {
		FileAttributes uint32
	}
	refused := []any{
		&win32Attributes{FileAttributes: 0x00000400}, // reparse point
		&win32Attributes{FileAttributes: 0x00000400 | 0x00000010},
		&win32Attributes{FileAttributes: 0x00000410}, // DEDUP-like combination
		(*win32Attributes)(nil),
		nil,
		struct{}{},
		"not a structure",
	}
	for _, system := range refused {
		if !attributesSayReparse(system) {
			t.Errorf("attributesSayReparse(%#v) = false, want true", system)
		}
	}
	admitted := []any{
		&win32Attributes{FileAttributes: 0},
		&win32Attributes{FileAttributes: 0x00000010}, // directory
		&win32Attributes{FileAttributes: 0x00000080}, // normal
	}
	for _, system := range admitted {
		if attributesSayReparse(system) {
			t.Errorf("attributesSayReparse(%#v) = true, want false", system)
		}
	}
}

// A real regular file carries no reparse attribute, and a directory neither.
func TestReparseAttributeOnRealEntries(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("the reparse attribute is a Windows fact")
	}
	dir := t.TempDir()
	file := filepath.Join(dir, "file.json")
	if err := os.WriteFile(file, []byte(`{}`), 0o600); err != nil {
		t.Fatal(err)
	}
	info, err := os.Lstat(file)
	if err != nil {
		t.Fatal(err)
	}
	if reparseAttribute(info) {
		t.Fatalf("a regular file carries the reparse attribute")
	}
	dirInfo, err := os.Lstat(dir)
	if err != nil {
		t.Fatal(err)
	}
	if reparseAttribute(dirInfo) {
		t.Fatalf("a plain directory carries the reparse attribute")
	}
}

// H02 regression: the walk consults the attribute, not only the mode. A
// synthetic entry whose mode looks regular but whose attributes carry the
// reparse bit — the DEDUP class — must make the walk refuse the route. This is
// the test the mode-only check fails.
func TestWalkerRefusesReparseAttributeWithRegularMode(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("the reparse attribute is a Windows fact")
	}
	original := lstatPath
	defer func() { lstatPath = original }()
	lstatPath = func(string) (os.FileInfo, error) {
		return attributeInfo{attributes: 0x00000400 | 0x00000080}, nil
	}
	if !symlinkComponent(filepath.Join(t.TempDir(), "dir", "file.json")) {
		t.Fatalf("the walk admitted an entry with the reparse attribute and a regular mode")
	}
	// Control: the same walk with a clean attribute does not refuse.
	lstatPath = func(string) (os.FileInfo, error) {
		return attributeInfo{attributes: 0x00000080}, nil
	}
	if symlinkComponent(filepath.Join(t.TempDir(), "dir", "file.json")) {
		t.Fatalf("the walk refused an entry without the reparse attribute")
	}
}

// attributeInfo is a FileInfo whose Sys() carries the Windows attribute word.
type attributeInfo struct {
	attributes uint32
}

func (info attributeInfo) Name() string       { return "synthetic" }
func (info attributeInfo) Size() int64        { return 0 }
func (info attributeInfo) Mode() os.FileMode  { return 0o644 }
func (info attributeInfo) ModTime() time.Time { return time.Time{} }
func (info attributeInfo) IsDir() bool        { return false }
func (info attributeInfo) Sys() any {
	return &struct{ FileAttributes uint32 }{FileAttributes: info.attributes}
}

// H01 coverage, creation side: the resolved route is what the create uses. A
// relative output with the captured directory distinct from the process
// directory must land under the captured one; ignoring the resolution would
// make the create fail (the process directory has no such subdirectory) or land
// in the wrong tree.
func TestWriteOutputResolvedAgainstCapturedCwd(t *testing.T) {
	captured := t.TempDir()
	if err := os.Mkdir(filepath.Join(captured, "sub"), 0o755); err != nil {
		t.Fatal(err)
	}
	relative := filepath.Join("sub", "out.json")
	if failure := writeOutput(relative, []byte("payload"), captured); failure != nil {
		t.Fatalf("writeOutput = %+v, want success under the captured directory", failure)
	}
	if got := string(readTemp(t, filepath.Join(captured, "sub", "out.json"))); got != "payload" {
		t.Fatalf("bytes = %q", got)
	}
	processDir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(processDir, "sub", "out.json")); err == nil {
		t.Fatalf("the output landed in the process working directory")
	}
}

// H01 regression, read side: the resolved route is what the read uses. A
// relative input is resolved against the captured working directory, not
// against the process working directory.
func TestRelativeRouteResolvedAgainstCapturedCwd(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "input.json"), []byte(`{}`), 0o600); err != nil {
		t.Fatal(err)
	}
	other := t.TempDir()
	failure := func() *cliError {
		_, failure := readInput("input.json", stageBundleRead, maxBundleInputBytes, false, other)
		return failure
	}()
	if failure == nil || failure.code != codeNotFound {
		t.Fatalf("relative route against captured cwd = %+v, want not_found", failure)
	}
	if _, failure := readInput("input.json", stageBundleRead, maxBundleInputBytes, false, dir); failure != nil {
		t.Fatalf("relative route in the right directory failed: %+v", failure)
	}
}

// H04 salvedad: the descriptor checks precede any write, and the counter proves
// zero Write calls reached the double, not only that the failure was reported.
func TestWriteOutputDescriptorChecksPrecedeWrite(t *testing.T) {
	dir := t.TempDir()
	original := createDestination
	defer func() { createDestination = original }()
	cases := []struct {
		name        string
		destination *failingDestination
	}{
		{"non-regular descriptor", &failingDestination{mode: os.ModeNamedPipe}},
		{"stat failure", &failingDestination{statErr: errors.New("stat failed")}},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			createDestination = func(string) (destinationFile, error) {
				return testCase.destination, nil
			}
			failure := writeOutput(filepath.Join(dir, "out.json"), []byte("payload"), dir)
			if failure == nil {
				t.Fatalf("write was not refused")
			}
			if testCase.destination.writes != 0 {
				t.Fatalf("bytes were written before the descriptor check: %d calls", testCase.destination.writes)
			}
		})
	}
}
