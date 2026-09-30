package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// The published example under examples/synthetic-case/ makes two claims: the
// context files are the composition of the fixture inputs (with the optional
// members materialized as explicit nulls), and the receipts are the byte-exact
// stdout of a real evaluate invocation. This test anchors both against the
// fixtures and the built binary, and replays each receipt with verify. It is
// the permanent replacement for the generator that produced the files.

const exampleRoot = "../../examples/synthetic-case"

func exampleCases() []struct {
	slug  string
	short string
} {
	return []struct {
		slug  string
		short string
	}{
		{fixtureF09, "f09"},
		{fixtureF10, "f10"},
		{fixtureF13, "f13"},
	}
}

// TestExampleContextsMatchFixtureComposition recomposes every published context
// from the fixture inputs and requires byte equality with the shipped file.
func TestExampleContextsMatchFixtureComposition(t *testing.T) {
	for _, testCase := range exampleCases() {
		t.Run(testCase.short, func(t *testing.T) {
			path := filepath.Join(exampleRoot, testCase.short+".context.json")
			published, err := os.ReadFile(path)
			if err != nil {
				t.Fatalf("read published context: %v", err)
			}
			composed := append(composedContextBytes(t, testCase.slug), '\n')
			if !bytes.Equal(published, composed) {
				t.Fatalf("published context differs from the fixture composition plus final LF:\ngot  %s\nwant %s", published, composed)
			}
			recordScenario(t, "example/contexts")
		})
	}
}

// TestExampleReceiptsAndReplay runs evaluate over the published contexts and
// requires byte equality with the published receipts, then replays the receipt
// fingerprint with verify. The argv uses the published context file, so a
// hand-edited receipt or context turns the test red.
func TestExampleReceiptsAndReplay(t *testing.T) {
	for _, testCase := range exampleCases() {
		t.Run(testCase.short, func(t *testing.T) {
			figures := absoluteFixture(t, composeFixture(t, testCase.slug))
			figures.context = absolutePath(t, filepath.Join(exampleRoot, testCase.short+".context.json"))

			run := runBinary(t, t.TempDir(), evaluateArgs(figures)...)
			if run.exit != 0 || len(run.stderr) != 0 {
				t.Fatalf("evaluate exit = %d stderr = %q", run.exit, run.stderr)
			}
			published := readGolden(t, exampleRoot, testCase.short+".receipt.json")
			if !bytes.Equal(run.stdout, published) {
				t.Fatalf("evaluate stdout differs from the published receipt:\ngot  %s\nwant %s", run.stdout, published)
			}
			var receipt struct {
				BundleHash        string `json:"bundle_hash"`
				ResultFingerprint string `json:"result_fingerprint"`
			}
			if err := json.Unmarshal(published, &receipt); err != nil {
				t.Fatalf("published receipt is not JSON: %v", err)
			}
			if receipt.BundleHash != figures.bundleHash {
				t.Fatalf("receipt bundle_hash = %q, want %q", receipt.BundleHash, figures.bundleHash)
			}
			verified := runBinary(t, t.TempDir(), verifyArgs(figures, receipt.ResultFingerprint)...)
			if verified.exit != 0 || len(verified.stderr) != 0 || !bytes.Equal(verified.stdout, []byte("verified\n")) {
				t.Fatalf("verify exit = %d stdout = %q stderr = %q", verified.exit, verified.stdout, verified.stderr)
			}
			recordScenario(t, "example/receipts")
		})
	}
}

// TestExampleReportMatchesReviewedGolden renders the F09 HTML report from the
// published context and compares it byte for byte with the reviewed
// presentation golden, so the walkthrough cannot drift from it silently.
func TestExampleReportMatchesReviewedGolden(t *testing.T) {
	figures := absoluteFixture(t, composeFixture(t, fixtureF09))
	figures.context = absolutePath(t, filepath.Join(exampleRoot, "f09.context.json"))
	out := filepath.Join(t.TempDir(), "report-f09.html")
	argv := []string{"report",
		"--bundle", figures.bundle, "--bundle-hash", figures.bundleHash,
		"--pack", figures.pack, "--context", figures.context,
		"--format", "html", "--out", out}
	run := runBinary(t, t.TempDir(), argv...)
	if run.exit != 0 || len(run.stdout) != 0 || len(run.stderr) != 0 {
		t.Fatalf("report exit = %d stdout = %q stderr = %q", run.exit, run.stdout, run.stderr)
	}
	got := readTemp(t, out)
	want := readGolden(t, "..", "..", "internal", "report", "testdata", "f09.report.html")
	if !bytes.Equal(got, want) {
		t.Fatalf("report bytes (%d) differ from the reviewed golden (%d)", len(got), len(want))
	}
	recordScenario(t, "example/report-f09-html")
}

// absolutePath resolves a repository-relative path for the child process, which
// runs in an isolated working directory.
func absolutePath(t *testing.T, path string) string {
	t.Helper()
	resolved, err := filepath.Abs(path)
	if err != nil {
		t.Fatalf("abs %s: %v", path, err)
	}
	return resolved
}
