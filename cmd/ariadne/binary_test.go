package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// F3 — the real-binary harness (ADR-0023 §5.5).
//
// The suite builds the executable once per `go test` invocation, launches it by
// argv — never through a shell — in an isolated working directory, and asserts
// exact transport bytes over the materialized fixtures: help, diagnostics, the
// replay receipt, `verified` and the byte parity of the reports against the
// presentation goldens reviewed before this task (`internal/report/testdata`,
// reused here, never modified). The transport goldens of this package live in
// `testdata/`: the help texts and the F09 receipt, frozen after manual review
// against ADR-0023 and the fixture's own digest.
//
// Test files may use os/exec and context; production may not, and the import
// boundary gate reads production sources only, so that split is enforced rather
// than assumed.
//
// The watchdog belongs to the harness, not to the product: it is not a ratified
// limit and it is never counted as a red product result. An expiry is a
// verification failure that escalates the measurement.

const e2eWatchdog = 120 * time.Second

// requiredScenarios is the inventory of E2E scenarios a green unfiltered run
// must exercise. Each scenario records its identifier when it completes, and
// TestMain demands the whole inventory afterwards: a bare invocation total
// cannot see a group of cases skipped — `-count=2` would mask it by doubling
// the number — so the control is the set of identities, not their count. The
// filter and the repetition count are read after m.Run, because that is when
// the testing package has parsed the flags; reading them earlier always sees
// the default and would fail legitimate directed runs.
var requiredScenarios = map[string]bool{
	"help/root":     true,
	"help/evaluate": true,
	"help/report":   true,
	"help/verify":   true,

	"error/no arguments":                  true,
	"error/unknown command":               true,
	"error/deferred import with help":     true,
	"error/deferred normalize":            true,
	"error/deferred diff":                 true,
	"error/help mixed with flags":         true,
	"error/unknown flag":                  true,
	"error/flag of another command":       true,
	"error/missing required flag":         true,
	"error/dash is not stdin":             true,
	"error/missing bundle file":           true,
	"error/malformed bundle":              true,
	"error/malformed context":             true,
	"error/wrong bundle hash":             true,
	"error/tampered pack against the pin": true,
	"error/wrong fingerprint":             true,
	"error/format outside the vocabulary": true,
	"error/out already exists":            true,

	"receipt/f09":                 true,
	"verify/f09":                  true,
	"report-parity/f09-json":      true,
	"report-parity/f09-html":      true,
	"report-parity/f10-json":      true,
	"fixture/" + fixtureF09:       true,
	"fixture/" + fixtureF10:       true,
	"fixture/" + fixtureF13:       true,
	"report-determinism/f13-json": true,
	"report-determinism/f13-html": true,
	"replay/cross-bundle":         true,
	"watchdog/timeout":            true,
}

const (
	fixtureF09 = "F09-unmapped-redhat-package"
	fixtureF10 = "F10-redhat-backport"
	fixtureF13 = "F13-contradictory-evidence"
)

var fingerprintShape = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)

var (
	e2eTempDir        string
	e2eBinaryPath     string
	e2eBinaryErr      error
	e2eBuildOnce      sync.Once
	binaryRuns        atomic.Int64
	observedScenarios sync.Map
)

// TestMain owns the harness build directory and the non-vacuity control: on a
// green, unfiltered run every declared scenario must have been observed, so
// skipping or removing cases cannot leave the suite green even under `-count`.
// A listing run and a `-run` filter are exempt: they do not execute the suite,
// and the Makefile's golden guard depends on the listing mode.
func TestMain(m *testing.M) {
	dir, err := os.MkdirTemp("", "ariadne-e2e-")
	if err != nil {
		fmt.Fprintf(os.Stderr, "harness: cannot create the build directory: %v\n", err)
		os.Exit(1)
	}
	e2eTempDir = dir
	code := m.Run()

	runFilter := ""
	if lookup := flag.Lookup("test.run"); lookup != nil {
		runFilter = lookup.Value.String()
	}
	// `-list` enumerates tests without executing them, and it is the mode the
	// golden guard of the Makefile uses: enforcing the inventory there would
	// fail `make check` (and CI) before any test ran.
	listOnly := false
	if lookup := flag.Lookup("test.list"); lookup != nil && lookup.Value.String() != "" {
		listOnly = true
	}
	if code == 0 && runFilter == "" && !listOnly {
		var missing []string
		for id := range requiredScenarios {
			if _, observed := observedScenarios.Load(id); !observed {
				missing = append(missing, id)
			}
		}
		if len(missing) > 0 {
			sort.Strings(missing)
			fmt.Fprintf(os.Stderr, "harness: %d binary invocations, %d scenarios not exercised (skipped or removed): %v\n",
				binaryRuns.Load(), len(missing), missing)
			code = 1
		}
	}
	_ = os.RemoveAll(dir)
	os.Exit(code)
}

// binaryUnderTest builds the executable once with the module as it is: no
// dependency download (GOPROXY off) and no workspace or go.mod mutation.
func binaryUnderTest(t *testing.T) string {
	t.Helper()
	e2eBuildOnce.Do(func() {
		name := "ariadne"
		if runtime.GOOS == "windows" {
			name += ".exe"
		}
		e2eBinaryPath = filepath.Join(e2eTempDir, name)
		build := exec.Command("go", "build", "-o", e2eBinaryPath, ".")
		build.Env = append(os.Environ(), "GOPROXY=off", "GOSUMDB=off", "GOFLAGS=-mod=readonly")
		if output, err := build.CombinedOutput(); err != nil {
			e2eBinaryErr = fmt.Errorf("harness build failed: %v\n%s", err, output)
		}
	})
	if e2eBinaryErr != nil {
		t.Fatalf("%v", e2eBinaryErr)
	}
	return e2eBinaryPath
}

// runClass is the harness verdict of one invocation. classTimeout is a
// verification failure by contract: it is neither a pass nor a product
// rejection, and it forces the measurement to be escalated instead of hidden.
type runClass int

const (
	classPass runClass = iota
	classReject
	classTimeout
	classStartFailure
)

type runResult struct {
	argv     []string
	exit     int
	stdout   []byte
	stderr   []byte
	timedOut bool
	startErr error
}

func classifyRun(run runResult) runClass {
	switch {
	case run.timedOut:
		return classTimeout
	case run.startErr != nil:
		return classStartFailure
	case run.exit == 0:
		return classPass
	default:
		return classReject
	}
}

// runBinaryRaw registers command, platform, exit, stdout and stderr of one real
// invocation, and maps a watchdog expiry to the timeout class.
func runBinaryRaw(t *testing.T, workDir string, timeout time.Duration, argv ...string) runResult {
	t.Helper()
	binary := binaryUnderTest(t)
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	command := exec.CommandContext(ctx, binary, argv...)
	command.Dir = workDir
	var stdout, stderr bytes.Buffer
	command.Stdout = &stdout
	command.Stderr = &stderr
	err := command.Run()
	binaryRuns.Add(1)
	result := runResult{argv: argv, exit: -1, stdout: stdout.Bytes(), stderr: stderr.Bytes()}
	switch {
	case err == nil:
		result.exit = 0
	case ctx.Err() == context.DeadlineExceeded:
		result.timedOut = true
	default:
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			result.exit = exitErr.ExitCode()
		} else {
			result.startErr = err
		}
	}
	t.Logf("harness run: %s/%s argv=%q workdir=%s exit=%d timedOut=%v stdout=%dB stderr=%dB",
		runtime.GOOS, runtime.GOARCH, argv, workDir, result.exit, result.timedOut, len(result.stdout), len(result.stderr))
	return result
}

func runBinary(t *testing.T, workDir string, argv ...string) runResult {
	t.Helper()
	result := runBinaryRaw(t, workDir, e2eWatchdog, argv...)
	switch classifyRun(result) {
	case classTimeout:
		t.Fatalf("harness watchdog (%v) expired for argv %q: verification failure, not a product limit; escalate the measurement", e2eWatchdog, argv)
	case classStartFailure:
		t.Fatalf("harness could not start the built binary: %v", result.startErr)
	}
	return result
}

func readGolden(t *testing.T, parts ...string) []byte {
	t.Helper()
	path := filepath.Join(parts...)
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read golden %s: %v", path, err)
	}
	return data
}

func diagnosticLine(stage, code string) []byte {
	return []byte(`{"error":{"stage":"` + stage + `","code":"` + code + `","message":"ariadne: ` + code + `"}}` + "\n")
}

// recordScenario marks one completed E2E scenario, never a skipped or failed
// one: it is called after the assertions. An identifier the inventory does not
// declare is a failure, so a renamed or new case must be added to the inventory
// instead of leaving the control blind.
func recordScenario(t *testing.T, id string) {
	t.Helper()
	if !requiredScenarios[id] {
		t.Fatalf("scenario %q is not declared in the harness inventory", id)
	}
	observedScenarios.Store(id, true)
}

// absoluteFixture resolves the fixture paths the package helpers produce
// relative to the package directory: the child process runs in an isolated
// working directory, so every input and destination it receives is absolute.
func absoluteFixture(t *testing.T, figures fixturePaths) fixturePaths {
	t.Helper()
	abs := func(path string) string {
		resolved, err := filepath.Abs(path)
		if err != nil {
			t.Fatalf("absolutize %s: %v", path, err)
		}
		return resolved
	}
	return fixturePaths{
		bundle:     abs(figures.bundle),
		bundleHash: figures.bundleHash,
		pack:       abs(figures.pack),
		context:    abs(figures.context),
	}
}

// TestBinaryHelpGoldens freezes the exact help bytes of the ratified surface.
func TestBinaryHelpGoldens(t *testing.T) {
	cases := []struct {
		name   string
		argv   []string
		golden string
	}{
		{"root", []string{"--help"}, "root.txt"},
		{"evaluate", []string{"evaluate", "--help"}, "evaluate.txt"},
		{"report", []string{"report", "--help"}, "report.txt"},
		{"verify", []string{"verify", "--help"}, "verify.txt"},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			run := runBinary(t, t.TempDir(), testCase.argv...)
			if run.exit != 0 {
				t.Fatalf("exit = %d, want 0 (stderr %q)", run.exit, run.stderr)
			}
			if len(run.stderr) != 0 {
				t.Fatalf("stderr = %q, want empty", run.stderr)
			}
			want := readGolden(t, "testdata", "help", testCase.golden)
			if !bytes.Equal(run.stdout, want) {
				t.Fatalf("help bytes differ from the frozen golden:\ngot  %q\nwant %q", run.stdout, want)
			}
			recordScenario(t, "help/"+testCase.name)
		})
	}
}

// TestBinaryDiagnosticsExact asserts the whole transport of representative
// failures over the real process: exit code, empty stdout and the exact
// one-line diagnostic. A destination that already exists is left untouched.
func TestBinaryDiagnosticsExact(t *testing.T) {
	figures := absoluteFixture(t, composeFixture(t, fixtureF09))
	dir := t.TempDir()
	missing := filepath.Join(dir, "absent-bundle.json")
	malformedBundle := writeTemp(t, "malformed-bundle.json", []byte("{"))
	malformedContext := writeTemp(t, "malformed-context.json", []byte("{}"))
	zeros := "sha256:" + strings.Repeat("0", 64)

	canonicalPack := readTemp(t, figures.pack)
	mutatedPack := []byte(strings.Replace(string(canonicalPack), "CVE-2026-9001", "CVE-2026-9002", 1))
	if string(mutatedPack) == string(canonicalPack) {
		t.Fatalf("pack mutation did not change the bytes")
	}
	tamperedPack := writeTemp(t, "tampered-pack.json", mutatedPack)

	existingOut := filepath.Join(dir, "existing.json")
	sentinel := []byte("sentinel\n")
	if err := os.WriteFile(existingOut, sentinel, 0o600); err != nil {
		t.Fatalf("prepare the pre-existing destination: %v", err)
	}

	evaluate := evaluateArgs(figures)
	withEvaluate := func(extra ...string) []string {
		return append(append([]string{}, evaluate...), extra...)
	}
	base := func(bundle, hash, pack, context string) []string {
		return []string{"evaluate",
			"--bundle", bundle, "--bundle-hash", hash, "--pack", pack, "--context", context}
	}

	cases := []struct {
		name  string
		argv  []string
		exit  int
		stage string
		code  string
	}{
		{"no arguments", nil, 2, stageArguments, codeInvalidArguments},
		{"unknown command", []string{"frobnicate"}, 2, stageArguments, codeUnknownCommand},
		{"deferred import with help", []string{"import", "--help"}, 2, stageArguments, codeCommandDeferred},
		{"deferred normalize", []string{"normalize"}, 2, stageArguments, codeCommandDeferred},
		{"deferred diff", []string{"diff"}, 2, stageArguments, codeCommandDeferred},
		{"help mixed with flags", []string{"evaluate", "--help", "--bundle", figures.bundle}, 2, stageArguments, codeInvalidArguments},
		{"unknown flag", withEvaluate("--extra", "x"), 2, stageArguments, codeInvalidArguments},
		{"flag of another command", withEvaluate("--format", "json"), 2, stageArguments, codeInvalidArguments},
		{"missing required flag", []string{"evaluate", "--bundle", figures.bundle}, 2, stageArguments, codeInvalidArguments},
		{"dash is not stdin", base("-", figures.bundleHash, figures.pack, figures.context), 2, stageArguments, codeInvalidArguments},
		{"missing bundle file", base(missing, figures.bundleHash, figures.pack, figures.context), 4, stageBundleRead, codeNotFound},
		{"malformed bundle", base(malformedBundle, figures.bundleHash, figures.pack, figures.context), 3, stageBundleDecode, codeInvalidBundle},
		{"malformed context", base(figures.bundle, figures.bundleHash, figures.pack, malformedContext), 3, stageContextDecode, codeInvalidContext},
		{"wrong bundle hash", base(figures.bundle, zeros, figures.pack, figures.context), 5, stageEvaluate, "bundle_hash_mismatch"},
		{"tampered pack against the pin", base(figures.bundle, figures.bundleHash, tamperedPack, figures.context), 5, stageEvaluate, "pack_hash_mismatch"},
		{"wrong fingerprint", verifyArgs(figures, zeros), 5, stageVerify, codeResultFingerprintMismatch},
		{"format outside the vocabulary", []string{"report",
			"--bundle", figures.bundle, "--bundle-hash", figures.bundleHash,
			"--pack", figures.pack, "--context", figures.context,
			"--format", "xml", "--out", filepath.Join(dir, "xml.out")}, 2, stageArguments, codeInvalidArguments},
		{"out already exists", []string{"report",
			"--bundle", figures.bundle, "--bundle-hash", figures.bundleHash,
			"--pack", figures.pack, "--context", figures.context,
			"--format", "json", "--out", existingOut}, 4, stageOutputWrite, codeAlreadyExists},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			run := runBinary(t, dir, testCase.argv...)
			if run.exit != testCase.exit {
				t.Fatalf("exit = %d, want %d (stderr %q)", run.exit, testCase.exit, run.stderr)
			}
			if len(run.stdout) != 0 {
				t.Fatalf("stdout = %q, want empty", run.stdout)
			}
			if want := diagnosticLine(testCase.stage, testCase.code); !bytes.Equal(run.stderr, want) {
				t.Fatalf("stderr = %q, want %q", run.stderr, want)
			}
			recordScenario(t, "error/"+testCase.name)
		})
	}
	if after := readTemp(t, existingOut); !bytes.Equal(after, sentinel) {
		t.Fatalf("the pre-existing destination was modified")
	}
}

// TestBinaryReceiptMatchesGoldenAndOracle freezes the transport receipt of F09
// and cross-checks both hashes against sources this test does not own: the
// fixture's expected digest and the `result` bytes of the reviewed presentation
// golden, re-hashed by the independent scanner of replay_test.go.
func TestBinaryReceiptMatchesGoldenAndOracle(t *testing.T) {
	figures := absoluteFixture(t, composeFixture(t, fixtureF09))
	run := runBinary(t, t.TempDir(), evaluateArgs(figures)...)
	if run.exit != 0 || len(run.stderr) != 0 {
		t.Fatalf("evaluate exit = %d, stderr = %q", run.exit, run.stderr)
	}
	golden := readGolden(t, "testdata", "receipt", "f09.receipt.json")
	if !bytes.Equal(run.stdout, golden) {
		t.Fatalf("receipt bytes differ from the frozen golden:\ngot  %q\nwant %q", run.stdout, golden)
	}
	if !bytes.HasSuffix(run.stdout, []byte("\n")) || bytes.Count(run.stdout, []byte("\n")) != 1 {
		t.Fatalf("receipt is not one line with LF: %q", run.stdout)
	}
	var receipt struct {
		BundleHash        string `json:"bundle_hash"`
		ResultFingerprint string `json:"result_fingerprint"`
	}
	if err := json.Unmarshal(run.stdout, &receipt); err != nil {
		t.Fatalf("receipt is not JSON: %v", err)
	}
	if receipt.BundleHash != string(figures.bundleHash) {
		t.Fatalf("bundle_hash = %q, want the fixture digest %q", receipt.BundleHash, figures.bundleHash)
	}
	if !fingerprintShape.MatchString(receipt.ResultFingerprint) {
		t.Fatalf("fingerprint shape = %q", receipt.ResultFingerprint)
	}
	document := readGolden(t, "..", "..", "internal", "report", "testdata", "f09.report.json")
	sum := sha256.Sum256(independentResultBytes(t, document))
	if want := "sha256:" + hex.EncodeToString(sum[:]); receipt.ResultFingerprint != want {
		t.Fatalf("fingerprint = %q, oracle = %q", receipt.ResultFingerprint, want)
	}
	recordScenario(t, "receipt/f09")
}

// TestBinaryVerifyRoundTrip replays a fingerprint produced by the real binary.
func TestBinaryVerifyRoundTrip(t *testing.T) {
	figures := absoluteFixture(t, composeFixture(t, fixtureF09))
	run := runBinary(t, t.TempDir(), evaluateArgs(figures)...)
	if run.exit != 0 {
		t.Fatalf("evaluate exit = %d, stderr = %q", run.exit, run.stderr)
	}
	var receipt struct {
		ResultFingerprint string `json:"result_fingerprint"`
	}
	if err := json.Unmarshal(run.stdout, &receipt); err != nil {
		t.Fatalf("receipt is not JSON: %v", err)
	}
	accepted := runBinary(t, t.TempDir(), verifyArgs(figures, receipt.ResultFingerprint)...)
	if accepted.exit != 0 || len(accepted.stderr) != 0 || !bytes.Equal(accepted.stdout, []byte("verified\n")) {
		t.Fatalf("verify exit = %d stdout = %q stderr = %q", accepted.exit, accepted.stdout, accepted.stderr)
	}
	recordScenario(t, "verify/f09")
}

// TestBinaryReportParityWithReviewedGoldens writes reports with the real binary
// and compares them byte for byte with the presentation goldens of
// internal/report, which predate this task and are not duplicated or modified.
func TestBinaryReportParityWithReviewedGoldens(t *testing.T) {
	cases := []struct {
		id     string
		name   string
		slug   string
		format string
		golden []string
	}{
		{"report-parity/f09-json", "F09 json", fixtureF09, "json", []string{"..", "..", "internal", "report", "testdata", "f09.report.json"}},
		{"report-parity/f09-html", "F09 html", fixtureF09, "html", []string{"..", "..", "internal", "report", "testdata", "f09.report.html"}},
		{"report-parity/f10-json", "F10 json", fixtureF10, "json", []string{"..", "..", "internal", "report", "testdata", "f10.report.json"}},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			figures := absoluteFixture(t, composeFixture(t, testCase.slug))
			out := filepath.Join(t.TempDir(), "report.out")
			argv := []string{"report",
				"--bundle", figures.bundle, "--bundle-hash", figures.bundleHash,
				"--pack", figures.pack, "--context", figures.context,
				"--format", testCase.format, "--out", out}
			run := runBinary(t, t.TempDir(), argv...)
			if run.exit != 0 || len(run.stdout) != 0 || len(run.stderr) != 0 {
				t.Fatalf("report exit = %d stdout = %q stderr = %q", run.exit, run.stdout, run.stderr)
			}
			got := readTemp(t, out)
			want := readGolden(t, testCase.golden...)
			t.Logf("harness artifact: %s = %d bytes", out, len(got))
			if !bytes.Equal(got, want) {
				t.Fatalf("report bytes (%d) differ from the reviewed golden (%d)", len(got), len(want))
			}
			recordScenario(t, testCase.id)
		})
	}
}

// TestBinaryFixturesEndToEnd runs evaluate and verify over every materialized
// fixture and repeats the evaluation across processes: same inputs, same bytes.
func TestBinaryFixturesEndToEnd(t *testing.T) {
	for _, slug := range []string{fixtureF09, fixtureF10, fixtureF13} {
		t.Run(slug, func(t *testing.T) {
			figures := absoluteFixture(t, composeFixture(t, slug))
			first := runBinary(t, t.TempDir(), evaluateArgs(figures)...)
			if first.exit != 0 || len(first.stderr) != 0 {
				t.Fatalf("evaluate exit = %d, stderr = %q", first.exit, first.stderr)
			}
			var receipt struct {
				BundleHash        string `json:"bundle_hash"`
				ResultFingerprint string `json:"result_fingerprint"`
			}
			if err := json.Unmarshal(first.stdout, &receipt); err != nil {
				t.Fatalf("receipt is not JSON: %v", err)
			}
			if receipt.BundleHash != string(figures.bundleHash) {
				t.Fatalf("bundle_hash = %q, want %q", receipt.BundleHash, figures.bundleHash)
			}
			if !fingerprintShape.MatchString(receipt.ResultFingerprint) {
				t.Fatalf("fingerprint shape = %q", receipt.ResultFingerprint)
			}
			second := runBinary(t, t.TempDir(), evaluateArgs(figures)...)
			if first.exit != second.exit || !bytes.Equal(first.stdout, second.stdout) || !bytes.Equal(first.stderr, second.stderr) {
				t.Fatalf("two runs of evaluate produced different transport")
			}
			verified := runBinary(t, t.TempDir(), verifyArgs(figures, receipt.ResultFingerprint)...)
			if verified.exit != 0 || len(verified.stderr) != 0 || !bytes.Equal(verified.stdout, []byte("verified\n")) {
				t.Fatalf("verify exit = %d stdout = %q stderr = %q", verified.exit, verified.stdout, verified.stderr)
			}
			recordScenario(t, "fixture/"+slug)
		})
	}
}

// TestBinaryReportDeterminismWithoutNewGoldens covers F13, whose presentation
// has no reviewed golden yet: the property asserted is determinism across
// processes, and no new golden is frozen for it.
func TestBinaryReportDeterminismWithoutNewGoldens(t *testing.T) {
	figures := absoluteFixture(t, composeFixture(t, fixtureF13))
	for _, format := range []string{"json", "html"} {
		t.Run(format, func(t *testing.T) {
			render := func() []byte {
				out := filepath.Join(t.TempDir(), "report."+format)
				argv := []string{"report",
					"--bundle", figures.bundle, "--bundle-hash", figures.bundleHash,
					"--pack", figures.pack, "--context", figures.context,
					"--format", format, "--out", out}
				run := runBinary(t, t.TempDir(), argv...)
				if run.exit != 0 || len(run.stdout) != 0 || len(run.stderr) != 0 {
					t.Fatalf("report exit = %d stdout = %q stderr = %q", run.exit, run.stdout, run.stderr)
				}
				data := readTemp(t, out)
				if len(data) == 0 {
					t.Fatalf("report artifact is empty")
				}
				return data
			}
			first := render()
			t.Logf("harness artifact: F13 %s = %d bytes", format, len(first))
			if second := render(); !bytes.Equal(first, second) {
				t.Fatalf("report bytes differ between two runs")
			}
			recordScenario(t, "report-determinism/f13-"+format)
		})
	}
}

// TestBinaryReplayIsNotTransferableAcrossBundles covers F15's integrity and
// replay scope with the two materialized digests: different bundles produce
// different receipts, and one bundle's fingerprint never verifies another's.
func TestBinaryReplayIsNotTransferableAcrossBundles(t *testing.T) {
	f09 := absoluteFixture(t, composeFixture(t, fixtureF09))
	f10 := absoluteFixture(t, composeFixture(t, fixtureF10))
	receiptOf := func(figures fixturePaths) (string, string) {
		run := runBinary(t, t.TempDir(), evaluateArgs(figures)...)
		if run.exit != 0 {
			t.Fatalf("evaluate exit = %d, stderr = %q", run.exit, run.stderr)
		}
		var receipt struct {
			BundleHash        string `json:"bundle_hash"`
			ResultFingerprint string `json:"result_fingerprint"`
		}
		if err := json.Unmarshal(run.stdout, &receipt); err != nil {
			t.Fatalf("receipt is not JSON: %v", err)
		}
		return receipt.BundleHash, receipt.ResultFingerprint
	}
	hashF09, fingerprintF09 := receiptOf(f09)
	hashF10, fingerprintF10 := receiptOf(f10)
	if hashF09 == hashF10 || fingerprintF09 == fingerprintF10 {
		t.Fatalf("two different bundles produced the same receipt: %q/%q vs %q/%q", hashF09, fingerprintF09, hashF10, fingerprintF10)
	}
	run := runBinary(t, t.TempDir(), verifyArgs(f10, fingerprintF09)...)
	if run.exit != 5 {
		t.Fatalf("cross-bundle verify exit = %d, want 5 (stderr %q)", run.exit, run.stderr)
	}
	if want := diagnosticLine(stageVerify, codeResultFingerprintMismatch); !bytes.Equal(run.stderr, want) {
		t.Fatalf("cross-bundle stderr = %q, want %q", run.stderr, want)
	}
	recordScenario(t, "replay/cross-bundle")
}

// TestHarnessWatchdogIsVerificationFailure is the control of the mutation that
// would turn a harness timeout into a pass, into a red product result or into
// skipped cases: a forced expiry against the real binary must classify as
// classTimeout, the watchdog value is the ratified one, and TestMain fails any
// unfiltered green run whose declared scenarios were not all observed.
func TestHarnessWatchdogIsVerificationFailure(t *testing.T) {
	if e2eWatchdog != 120*time.Second {
		t.Fatalf("harness watchdog = %v, want the 120 s of ADR-0023 §5.5", e2eWatchdog)
	}
	expired := runBinaryRaw(t, t.TempDir(), time.Nanosecond, "--help")
	if classified := classifyRun(expired); classified != classTimeout {
		t.Fatalf("forced expiry classified as %v (exit=%d, timedOut=%v, startErr=%v), want classTimeout",
			classified, expired.exit, expired.timedOut, expired.startErr)
	}
	recordScenario(t, "watchdog/timeout")
}
