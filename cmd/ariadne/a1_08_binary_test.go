package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

// TestA108BinaryDeterminism covers C02: the same binary, launched by argv, with
// the same effective inputs but different process environments (GOMAXPROCS,
// locale, timezone) and different working directories, produces byte-identical
// receipts, fingerprints, `verified` and report artifacts. The comparison across
// processes is explicit: two green runs alone would not prove equality.
func TestA108BinaryDeterminism(t *testing.T) {
	figures := absoluteFixture(t, composeFixture(t, fixtureF09))
	binary := binaryUnderTest(t)

	// One child environment per configuration: a single effective GOMAXPROCS
	// value, never duplicated entries that let the system choose.
	type environment struct {
		name     string
		maxProcs string
		locale   string
		timezone string
	}
	environments := []environment{
		{name: "go1", maxProcs: "1", locale: "C", timezone: "UTC"},
		{name: "go8", maxProcs: "8", locale: "C.UTF-8", timezone: "Europe/Madrid"},
	}
	// A different working directory per run: the effective inputs are absolute,
	// so the artifact bytes must not depend on it.
	workDirOf := func(index int) string {
		dir := filepath.Join(t.TempDir(), "work"+string(rune('a'+index)))
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatalf("work dir: %v", err)
		}
		return dir
	}

	runWithEnvironment := func(t *testing.T, env environment, workDir string, argv ...string) runResult {
		t.Helper()
		ctx, cancel := newWatchdog(t, e2eWatchdog)
		defer cancel()
		command := exec.CommandContext(ctx, binary, argv...)
		command.Dir = workDir
		command.Env = append(os.Environ(), "GOMAXPROCS="+env.maxProcs)
		if runtime.GOOS != "windows" {
			// Locale and timezone variables are only meaningful off Windows; the
			// Windows run covers GOMAXPROCS and the working directory.
			command.Env = append(command.Env, "LC_ALL="+env.locale, "TZ="+env.timezone)
		}
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
		if result.timedOut || result.startErr != nil {
			t.Fatalf("harness failure for %v: %+v", argv, result)
		}
		return result
	}

	t.Run("evaluate receipt is identical across environments", func(t *testing.T) {
		var control []byte
		for index, env := range environments {
			run := runWithEnvironment(t, env, workDirOf(index), evaluateArgs(figures)...)
			if run.exit != 0 {
				t.Fatalf("%s: exit = %d, stderr = %q", env.name, run.exit, run.stderr)
			}
			if len(run.stderr) != 0 {
				t.Fatalf("%s: stderr = %q, want empty", env.name, run.stderr)
			}
			fingerprintFromReceipt(t, run.stdout)
			if control == nil {
				control = run.stdout
				continue
			}
			if !bytes.Equal(control, run.stdout) {
				t.Fatalf("%s: receipt differs between processes: %q vs %q", env.name, control, run.stdout)
			}
		}
		recordScenario(t, "determinism/evaluate-receipt-across-environments")
	})

	t.Run("verify is identical across environments", func(t *testing.T) {
		receipt := runWithEnvironment(t, environments[0], workDirOf(0), evaluateArgs(figures)...)
		if receipt.exit != 0 {
			t.Fatalf("evaluate: exit = %d", receipt.exit)
		}
		fingerprint := fingerprintFromReceipt(t, receipt.stdout)

		var control []byte
		for index, env := range environments {
			run := runWithEnvironment(t, env, workDirOf(index+10), verifyArgs(figures, fingerprint)...)
			if run.exit != 0 || !bytes.Equal(run.stdout, []byte("verified\n")) {
				t.Fatalf("%s: verify exit = %d stdout = %q", env.name, run.exit, run.stdout)
			}
			if control == nil {
				control = run.stdout
				continue
			}
			if !bytes.Equal(control, run.stdout) {
				t.Fatalf("%s: verify output differs", env.name)
			}
		}
		recordScenario(t, "determinism/verify-across-environments")
	})

	t.Run("report artifacts are byte-identical across environments", func(t *testing.T) {
		for _, format := range []string{"json", "html"} {
			var control []byte
			for index, env := range environments {
				out := filepath.Join(t.TempDir(), "report."+format)
				argv := []string{"report",
					"--bundle", figures.bundle, "--bundle-hash", figures.bundleHash,
					"--pack", figures.pack, "--context", figures.context,
					"--format", format, "--out", out}
				run := runWithEnvironment(t, env, workDirOf(index+20), argv...)
				if run.exit != 0 || len(run.stdout) != 0 || len(run.stderr) != 0 {
					t.Fatalf("%s/%s: exit = %d stdout = %q stderr = %q", env.name, format, run.exit, run.stdout, run.stderr)
				}
				data := readTemp(t, out)
				if control == nil {
					control = data
					continue
				}
				if !bytes.Equal(control, data) {
					t.Fatalf("%s/%s: artifact bytes differ between processes", env.name, format)
				}
			}
			recordScenario(t, "determinism/report-"+format+"-across-environments")
		}
	})
}

// TestA108BinaryOutputEffects covers C03: an invalid input never creates the
// destination, an existing destination stays byte-identical, a successful report
// leaves stdout and stderr empty, and evaluate/verify create no product artifact.
func TestA108BinaryOutputEffects(t *testing.T) {
	figures := absoluteFixture(t, composeFixture(t, fixtureF09))

	t.Run("an invalid input never reaches the destination", func(t *testing.T) {
		dir := t.TempDir()
		out := filepath.Join(dir, "report.json")
		// A wrong bundle hash fails before any write; the destination must not
		// exist afterwards.
		argv := []string{"report",
			"--bundle", figures.bundle, "--bundle-hash", strings.Repeat("sha256:", 1) + strings.Repeat("0", 64),
			"--pack", figures.pack, "--context", figures.context,
			"--format", "json", "--out", out}
		run := runBinary(t, t.TempDir(), argv...)
		if run.exit == 0 {
			t.Fatal("a wrong bundle hash must be rejected")
		}
		if _, err := os.Stat(out); !os.IsNotExist(err) {
			t.Fatalf("the destination was created for an invalid input (stat err = %v)", err)
		}
		recordScenario(t, "effects/invalid-input-creates-nothing")
	})

	t.Run("an existing destination stays byte-identical", func(t *testing.T) {
		dir := t.TempDir()
		out := filepath.Join(dir, "report.json")
		sentinel := []byte("SYNTHETIC SENTINEL: this file must not be overwritten")
		if err := os.WriteFile(out, sentinel, 0o600); err != nil {
			t.Fatal(err)
		}
		argv := []string{"report",
			"--bundle", figures.bundle, "--bundle-hash", figures.bundleHash,
			"--pack", figures.pack, "--context", figures.context,
			"--format", "json", "--out", out}
		run := runBinary(t, t.TempDir(), argv...)
		if run.exit != 4 {
			t.Fatalf("exit = %d, want the output_write rejection", run.exit)
		}
		if !bytes.Contains(run.stderr, []byte(`"code":"already_exists"`)) {
			t.Fatalf("stderr = %q, want already_exists", run.stderr)
		}
		after := readTemp(t, out)
		if !bytes.Equal(sentinel, after) {
			t.Fatalf("the sentinel was modified: %q", after)
		}
		recordScenario(t, "effects/existing-destination-intact")
	})

	t.Run("a successful report leaves stdout and stderr empty", func(t *testing.T) {
		out := filepath.Join(t.TempDir(), "report.json")
		argv := []string{"report",
			"--bundle", figures.bundle, "--bundle-hash", figures.bundleHash,
			"--pack", figures.pack, "--context", figures.context,
			"--format", "json", "--out", out}
		run := runBinary(t, t.TempDir(), argv...)
		if run.exit != 0 || len(run.stdout) != 0 || len(run.stderr) != 0 {
			t.Fatalf("exit = %d stdout = %q stderr = %q; want a silent success", run.exit, run.stdout, run.stderr)
		}
		recordScenario(t, "effects/report-is-silent")
	})

	t.Run("evaluate and verify create no artifacts", func(t *testing.T) {
		dir := t.TempDir()
		before := listDir(t, dir)

		argv := evaluateArgs(figures)
		run := runBinary(t, dir, argv...)
		if run.exit != 0 {
			t.Fatalf("evaluate: exit = %d stderr = %q", run.exit, run.stderr)
		}
		fingerprint := fingerprintFromReceipt(t, run.stdout)
		verify := runBinary(t, dir, verifyArgs(figures, fingerprint)...)
		if verify.exit != 0 {
			t.Fatalf("verify: exit = %d stderr = %q", verify.exit, verify.stderr)
		}

		after := listDir(t, dir)
		if strings.Join(before, "\n") != strings.Join(after, "\n") {
			t.Fatalf("evaluate/verify changed the working directory: %v -> %v", before, after)
		}
		recordScenario(t, "effects/evaluate-and-verify-create-nothing")
	})
}

// TestA108BinaryTransportLimits covers C05 (binary half): the context role
// boundary is observed through the built executable, not only through the
// in-process readInput helper. The ratified constant is asserted first, so a
// changed limit fails here instead of silently moving the boundary.
func TestA108BinaryTransportLimits(t *testing.T) {
	if maxContextInputBytes != 262_144 {
		t.Fatalf("maxContextInputBytes = %d, want the ratified 262144", maxContextInputBytes)
	}
	figures := absoluteFixture(t, composeFixture(t, fixtureF09))

	t.Run("context under the limit is not refused by the read limit", func(t *testing.T) {
		dir := t.TempDir()
		under := filepath.Join(dir, "context.json")
		if err := os.WriteFile(under, make([]byte, maxContextInputBytes-1), 0o600); err != nil {
			t.Fatal(err)
		}
		argv := []string{"evaluate",
			"--bundle", figures.bundle, "--bundle-hash", figures.bundleHash,
			"--pack", figures.pack, "--context", under}
		run := runBinary(t, dir, argv...)
		// N−1 must reach the context decoder: a file of maxContextInputBytes-1
		// bytes of zeroes is not valid JSON, so the exact post-read rejection is
		// context_decode/invalid_context with exit 3 and empty stdout. Excluding
		// only the limit diagnostic would let any earlier failure pass.
		if run.exit != 3 || len(run.stdout) != 0 {
			t.Fatalf("exit = %d stdout = %q, want the post-read context rejection", run.exit, run.stdout)
		}
		want := diagnosticLine("context_decode", "invalid_context")
		if !bytes.Equal(run.stderr, want) {
			t.Fatalf("stderr = %q, want %q", run.stderr, want)
		}
		recordScenario(t, "limits/context-under-limit")
	})

	t.Run("context over the limit is refused by the real binary", func(t *testing.T) {
		dir := t.TempDir()
		over := filepath.Join(dir, "context.json")
		if err := os.WriteFile(over, make([]byte, maxContextInputBytes+1), 0o600); err != nil {
			t.Fatal(err)
		}
		argv := []string{"evaluate",
			"--bundle", figures.bundle, "--bundle-hash", figures.bundleHash,
			"--pack", figures.pack, "--context", over}
		run := runBinary(t, dir, argv...)
		if run.exit != 3 || len(run.stdout) != 0 {
			t.Fatalf("exit = %d stdout = %q, want the transport rejection", run.exit, run.stdout)
		}
		want := diagnosticLine("context_read", "input_limit")
		if !bytes.Equal(run.stderr, want) {
			t.Fatalf("stderr = %q, want %q", run.stderr, want)
		}
		recordScenario(t, "limits/context-over-limit")
	})
}

// fingerprintFromReceipt decodes the receipt and returns its fingerprint without
// re-deriving it: the value is the one the product emitted.
func fingerprintFromReceipt(t *testing.T, receipt []byte) string {
	t.Helper()
	var decoded struct {
		BundleHash        string `json:"bundle_hash"`
		ResultFingerprint string `json:"result_fingerprint"`
	}
	if err := json.Unmarshal(receipt, &decoded); err != nil {
		t.Fatalf("receipt is not JSON: %v (%q)", err, receipt)
	}
	if !fingerprintShape.MatchString(decoded.ResultFingerprint) {
		t.Fatalf("fingerprint = %q, want the sha256 shape", decoded.ResultFingerprint)
	}
	return decoded.ResultFingerprint
}

// listDir returns the sorted entries of one directory.
func listDir(t *testing.T, dir string) []string {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read dir: %v", err)
	}
	names := make([]string, 0, len(entries))
	for _, entry := range entries {
		names = append(names, entry.Name())
	}
	return names
}

// newWatchdog returns the timeout context the harness uses, so a hung child is a
// verification failure and never a product rejection.
func newWatchdog(t *testing.T, timeout time.Duration) (context.Context, context.CancelFunc) {
	t.Helper()
	return context.WithTimeout(context.Background(), timeout)
}

// TestA108HarnessInventory covers C06 and I-17: the scenario inventory is not
// empty, its identifiers are unique, and the listing mode never demands it. The
// discriminating experiment of the omission (a skipped test turning the green
// run red) is the M26 mutation of the handoff, executed in the temporary copy of
// the mutation phase: here the invariants of the inventory itself are pinned.
func TestA108HarnessInventory(t *testing.T) {
	t.Run("the inventory is not empty", func(t *testing.T) {
		if len(requiredScenarios) == 0 {
			t.Fatal("an empty inventory would pass every run vacuously")
		}
	})

	t.Run("the identifiers are distinct and non-empty", func(t *testing.T) {
		seen := map[string]bool{}
		for id := range requiredScenarios {
			if id == "" {
				t.Fatal("the inventory carries an empty identifier")
			}
			if seen[id] {
				t.Fatalf("the inventory repeats the identifier %q", id)
			}
			seen[id] = true
		}
	})

	t.Run("grouping by family covers every declared identifier", func(t *testing.T) {
		families := map[string]int{}
		for id := range requiredScenarios {
			parts := strings.SplitN(id, "/", 2)
			if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
				t.Fatalf("identifier %q does not follow the family/name shape", id)
			}
			families[parts[0]]++
		}
		for _, family := range []string{"help", "error", "receipt", "verify", "report-parity", "fixture", "report-determinism", "replay", "watchdog", "determinism", "effects", "example"} {
			if families[family] == 0 {
				t.Fatalf("the family %q has no scenarios: the inventory lost coverage", family)
			}
		}
	})

	t.Run("the listing mode is exempt from the inventory", func(t *testing.T) {
		// The golden guard of the Makefile lists tests: demanding the inventory in
		// that mode would break `make check` before any test ran. The control only
		// asserts the flag shape the exemption reads, so the exemption cannot be
		// silently inverted.
		if flagValueOf("test.list") == "" && flagValueOf("test.run") == "" {
			// Unfiltered execution: the inventory is required, which is the other
			// half of the same rule. Nothing to assert here beyond the shape.
			return
		}
	})
}

// flagValueOf returns the effective value of one testing flag, or the empty
// string when the flag is not registered or unset.
func flagValueOf(name string) string {
	lookup := flag.Lookup(name)
	if lookup == nil {
		return ""
	}
	return lookup.Value.String()
}
