package main

import (
	"path/filepath"
	"strings"
	"testing"
)

// End-to-end cases over the existing fixtures. The CLI is exercised through its
// real runner with real files; the presentation bytes are contrasted against the
// reviewed goldens of internal/report, which were accepted before this task and
// are not modified here.

// renderF09JSON returns the exact bytes the CLI writes for `report --format
// json` over the F09 fixture.
func renderF09JSON(t *testing.T, figures fixturePaths) []byte {
	t.Helper()
	out := filepath.Join(t.TempDir(), "report.json")
	argv := []string{"report",
		"--bundle", figures.bundle, "--bundle-hash", figures.bundleHash,
		"--pack", figures.pack, "--context", figures.context,
		"--format", "json", "--out", out}
	exit, stdout, stderr := runCLI(t, argv)
	if exit != 0 {
		t.Fatalf("report exit=%d stderr=%q", exit, stderr)
	}
	if stdout != "" {
		t.Fatalf("report wrote to stdout: %q", stdout)
	}
	return readTemp(t, out)
}

func TestEvaluateReceiptExactShape(t *testing.T) {
	figures := composeFixture(t, "F09-unmapped-redhat-package")
	exit, stdout, stderr := runCLI(t, evaluateArgs(figures))
	if exit != 0 || stderr != "" {
		t.Fatalf("evaluate exit=%d stderr=%q", exit, stderr)
	}
	if !strings.HasSuffix(stdout, "\n") || strings.Count(stdout, "\n") != 1 {
		t.Fatalf("receipt is not one line with LF: %q", stdout)
	}
	fingerprint := receiptFingerprint(t, figures)
	if fingerprint == "" || len(fingerprint) != len("sha256:")+64 {
		t.Fatalf("fingerprint shape: %q", fingerprint)
	}
}

func TestEvaluateIsDeterministic(t *testing.T) {
	figures := composeFixture(t, "F09-unmapped-redhat-package")
	first := receiptFingerprint(t, figures)
	for attempt := 0; attempt < 2; attempt++ {
		if again := receiptFingerprint(t, figures); again != first {
			t.Fatalf("fingerprint changed between runs: %s vs %s", first, again)
		}
	}
}

func TestReportJSONMatchesReviewedGolden(t *testing.T) {
	figures := composeFixture(t, "F09-unmapped-redhat-package")
	got := renderF09JSON(t, figures)
	golden := readTemp(t, filepath.Join("..", "..", "internal", "report", "testdata", "f09.report.json"))
	if string(got) != string(golden) {
		t.Fatalf("report JSON differs from the reviewed golden")
	}
}

func TestReportHTMLMatchesReviewedGolden(t *testing.T) {
	figures := composeFixture(t, "F09-unmapped-redhat-package")
	out := filepath.Join(t.TempDir(), "report.html")
	argv := []string{"report",
		"--bundle", figures.bundle, "--bundle-hash", figures.bundleHash,
		"--pack", figures.pack, "--context", figures.context,
		"--format", "html", "--out", out}
	exit, _, stderr := runCLI(t, argv)
	if exit != 0 {
		t.Fatalf("report --format html exit=%d stderr=%q", exit, stderr)
	}
	got := readTemp(t, out)
	golden := readTemp(t, filepath.Join("..", "..", "internal", "report", "testdata", "f09.report.html"))
	if string(got) != string(golden) {
		t.Fatalf("report HTML differs from the reviewed golden")
	}
}

func TestVerifyAcceptsMatchingFingerprint(t *testing.T) {
	figures := composeFixture(t, "F09-unmapped-redhat-package")
	fingerprint := receiptFingerprint(t, figures)
	exit, stdout, stderr := runCLI(t, verifyArgs(figures, fingerprint))
	if exit != 0 || stderr != "" || stdout != "verified\n" {
		t.Fatalf("verify exit=%d stdout=%q stderr=%q", exit, stdout, stderr)
	}
}

func TestVerifyRejectsChangedFingerprint(t *testing.T) {
	figures := composeFixture(t, "F09-unmapped-redhat-package")
	changed := "sha256:" + strings.Repeat("0", 63) + "1"
	argv := verifyArgs(figures, changed)
	expectRejection(t, argv, stageVerify, codeResultFingerprintMismatch, 5)
}

// IN-04: a changed bundle against the old hash is a bundle_hash_mismatch of the
// evaluate stage, exit 5, with no favorable output. The mutation keeps the
// envelope valid (a provenance alias inside the projection), so validation of
// the decoded model succeeds and the pinned projection is what refuses it.
func TestChangedBundleAgainstOldHash(t *testing.T) {
	figures := composeFixture(t, "F09-unmapped-redhat-package")
	canonical := readTemp(t, figures.bundle)
	mutated := []byte(strings.Replace(string(canonical), "cluster-fixtures", "cluster-fixturez", 1))
	if string(mutated) == string(canonical) {
		t.Fatalf("mutation did not change the envelope")
	}
	tampered := writeTemp(t, "tampered-bundle.json", mutated)
	argv := []string{"evaluate",
		"--bundle", tampered, "--bundle-hash", figures.bundleHash,
		"--pack", figures.pack, "--context", figures.context}
	expectRejection(t, argv, stageEvaluate, "bundle_hash_mismatch", 5)
}

// IN-07 and the read-first precedence: a malformed bundle never masks a missing
// pack, and an argument error never reaches the filesystem.
func TestPrecedenceReadsBeforeDecode(t *testing.T) {
	figures := composeFixture(t, "F09-unmapped-redhat-package")
	dir := t.TempDir()
	malformed := writeTemp(t, "malformed.json", []byte(`{ not json`))
	missing := filepath.Join(dir, "absent.pack")
	argv := []string{"evaluate",
		"--bundle", malformed, "--bundle-hash", figures.bundleHash,
		"--pack", missing, "--context", figures.context}
	expectRejection(t, argv, stagePackRead, codeNotFound, 4)

	// Both decoders invalid: the bundle decoder wins.
	badContext := writeTemp(t, "bad-context.json", []byte(`{}`))
	argv = []string{"evaluate",
		"--bundle", malformed, "--bundle-hash", figures.bundleHash,
		"--pack", figures.pack, "--context", badContext}
	expectRejection(t, argv, stageBundleDecode, codeInvalidBundle, 3)

	// A missing bundle wins over an invalid context (reads precede decodes).
	argv = []string{"evaluate",
		"--bundle", missing, "--bundle-hash", figures.bundleHash,
		"--pack", figures.pack, "--context", badContext}
	expectRejection(t, argv, stageBundleRead, codeNotFound, 4)

	// Invalid arguments win over everything: the destination is never opened.
	existing := writeTemp(t, "existing.json", []byte(`keep`))
	argv = []string{"report",
		"--bundle", missing, "--bundle-hash", "not-a-hash",
		"--pack", figures.pack, "--context", figures.context,
		"--format", "json", "--out", existing}
	expectRejection(t, argv, stageArguments, codeInvalidArguments, 2)
	if got := string(readTemp(t, existing)); got != "keep" {
		t.Fatalf("destination was touched: %q", got)
	}

	// Valid arguments but invalid inputs: the destination still stays untouched
	// and the failure keeps its own stage, because the output is only opened
	// after every byte exists.
	argv = []string{"report",
		"--bundle", malformed, "--bundle-hash", figures.bundleHash,
		"--pack", figures.pack, "--context", figures.context,
		"--format", "json", "--out", existing}
	expectRejection(t, argv, stageBundleDecode, codeInvalidBundle, 3)
	if got := string(readTemp(t, existing)); got != "keep" {
		t.Fatalf("destination was touched by a failed run: %q", got)
	}
}

// IN-05: pack admission failures map to their own codes at the evaluate stage.
// The phase order of ADR-0013 §5.3 is visible here: hash before syntax, so a
// malformed pack only reaches invalid_pack when its bytes are the ones the
// context pinned.
func TestPackAdmissionCodes(t *testing.T) {
	figures := composeFixture(t, "F09-unmapped-redhat-package")
	empty := writeTemp(t, "empty.pack", nil)
	argv := []string{"evaluate",
		"--bundle", figures.bundle, "--bundle-hash", figures.bundleHash,
		"--pack", empty, "--context", figures.context}
	expectRejection(t, argv, stageEvaluate, "missing_pack", 3)

	// A pack whose bytes changed against the pinned hash is pack_hash_mismatch,
	// even when it is also malformed: hash precedes syntax.
	malformed := writeTemp(t, "malformed.pack", []byte(`{`))
	argv = []string{"evaluate",
		"--bundle", figures.bundle, "--bundle-hash", figures.bundleHash,
		"--pack", malformed, "--context", figures.context}
	expectRejection(t, argv, stageEvaluate, "pack_hash_mismatch", 5)

	// With the malformed bytes pinned by the context, the syntax phase is what
	// rejects: invalid_pack.
	pinned := mutateContextPath(t, func(document map[string]any) {
		document["admission"].(map[string]any)["expected_pack_hash"] = hashOfBytes([]byte(`{`))
	})
	argv = []string{"evaluate",
		"--bundle", figures.bundle, "--bundle-hash", figures.bundleHash,
		"--pack", malformed, "--context", pinned}
	expectRejection(t, argv, stageEvaluate, "invalid_pack", 3)

	// A pack that is valid syntax but a different pack identity keeps its own
	// code: the identity check follows the syntax phase.
	packBytes := readTemp(t, figures.pack)
	tampered := writeTemp(t, "tampered.pack", packBytes)
	otherPackID := mutateContextPath(t, func(document map[string]any) {
		document["admission"].(map[string]any)["expected_pack_hash"] = hashOfBytes(packBytes)
		document["admission"].(map[string]any)["expected_pack_id"] = "pack.other"
	})
	argv = []string{"evaluate",
		"--bundle", figures.bundle, "--bundle-hash", figures.bundleHash,
		"--pack", tampered, "--context", otherPackID}
	expectRejection(t, argv, stageEvaluate, "pack_identity_mismatch", 3)
}

// The receipt covers the whole projection: two different bundles over the same
// inputs produce different fingerprints.
func TestDifferentInputsDifferentFingerprint(t *testing.T) {
	f09 := composeFixture(t, "F09-unmapped-redhat-package")
	f10 := composeFixture(t, "F10-redhat-backport")
	first := receiptFingerprint(t, f09)
	second := receiptFingerprint(t, f10)
	if first == second {
		t.Fatalf("two fixtures share a fingerprint: %s", first)
	}
}
