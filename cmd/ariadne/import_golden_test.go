package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// Golden anchors of the import pipeline (ADR-0036). The fixture is fully
// synthetic (testdata/import); the frozen bytes live beside it in expected/.
// Every run uses relative paths from a private working directory, so the argv
// copy inside the canonical envelope is machine-independent and the artifacts
// are byte-comparable across runs and platforms. The receipt, the three
// artifacts and the cross-checks against the other commands are the DoD
// residual criterion: the full pipeline fixture → bundle → evaluate → report
// is runnable with the binary alone.

type importReceipt struct {
	BundleHash      string `json:"bundle_hash"`
	RowsTotal       int    `json:"rows_total"`
	RowsAccepted    int    `json:"rows_accepted"`
	RowsRejected    int    `json:"rows_rejected"`
	Omissions       int    `json:"omissions"`
	ScopeCollisions int    `json:"scope_collisions"`
}

// runRelativeImport runs one deterministic import over the fixture copies of a
// private working directory and returns the receipt.
func runRelativeImport(t *testing.T) importReceipt {
	t.Helper()
	dir := t.TempDir()
	copyImportFixture(t, dir)
	inDir(t, dir)
	exit, stdout, stderr := runCLI(t, relativeImportArgs())
	if exit != 0 {
		t.Fatalf("import exit=%d stderr=%q", exit, stderr)
	}
	var receipt importReceipt
	if err := json.Unmarshal([]byte(stdout), &receipt); err != nil {
		t.Fatalf("receipt is not JSON: %v (%q)", err, stdout)
	}
	return receipt
}

func runRelativeImportFiles(t *testing.T) (dir string, receipt importReceipt) {
	t.Helper()
	dir = t.TempDir()
	copyImportFixture(t, dir)
	inDir(t, dir)
	exit, stdout, stderr := runCLI(t, relativeImportArgs())
	if exit != 0 {
		t.Fatalf("import exit=%d stderr=%q", exit, stderr)
	}
	if err := json.Unmarshal([]byte(stdout), &receipt); err != nil {
		t.Fatalf("receipt is not JSON: %v (%q)", err, stdout)
	}
	return dir, receipt
}

// goldenPath resolves one golden against the package directory. It must be
// called before the working-directory switch of a relative import run.
func goldenPath(t *testing.T, name string) string {
	t.Helper()
	return mustAbs(t, filepath.Join("testdata", "import", "expected", name))
}

func TestImportGoldenArtifacts(t *testing.T) {
	goldens := map[string]string{}
	for _, artifact := range []string{"envelope.json", "projection.json", "digest.txt"} {
		goldens[artifact] = goldenPath(t, artifact)
	}
	dir, _ := runRelativeImportFiles(t)
	for _, artifact := range []string{"envelope.json", "projection.json", "digest.txt"} {
		got := readTemp(t, filepath.Join(dir, map[string]string{
			"envelope.json":   "bundle-envelope.json",
			"projection.json": "bundle-projection.json",
			"digest.txt":      "bundle-digest.txt",
		}[artifact]))
		want := readTemp(t, goldens[artifact])
		if !bytes.Equal(got, want) {
			t.Fatalf("%s differs from the frozen golden:\ngot  %q\nwant %q", artifact, got, want)
		}
	}
}

func TestImportGoldenReceipt(t *testing.T) {
	digestPath := goldenPath(t, "digest.txt")
	receipt := runRelativeImport(t)
	digest := string(readTemp(t, digestPath))
	if receipt.BundleHash+"\n" != digest {
		t.Fatalf("receipt bundle_hash = %q, want the frozen digest %q", receipt.BundleHash, digest)
	}
	if receipt.RowsTotal != 2 || receipt.RowsAccepted != 2 || receipt.RowsRejected != 0 {
		t.Fatalf("row accounting = %d/%d/%d, want 2/2/0", receipt.RowsTotal, receipt.RowsAccepted, receipt.RowsRejected)
	}
	if receipt.Omissions != 0 || receipt.ScopeCollisions != 0 {
		t.Fatalf("diagnostics = %d omissions / %d collisions, want none", receipt.Omissions, receipt.ScopeCollisions)
	}
}

// TestImportGoldenEvaluateReportParity proves the imported artifacts are
// bundles the ratified commands consume: evaluate builds a Result, report
// renders it and verify accepts the fingerprint. The pack and the domain
// context come from the reviewed F09 fixture; the target names the imported
// subject and vulnerability, so the evaluation itself may land on
// under_investigation — the parity criterion is the transport, not a verdict.
func TestImportGoldenEvaluateReportParity(t *testing.T) {
	// Resolve the fixture tree before the working-directory switch: the test
	// process leaves the package directory for the private import directory.
	input := mustAbs(t, filepath.Join(fixturesRoot, fixtureF09, "0.2", "input"))
	packPath := mustAbs(t, filepath.Join(input, "pack.json"))
	admissionBytes := readTemp(t, filepath.Join(input, "admission-context.json"))
	domainBytes := readTemp(t, filepath.Join(input, "domain-context.json"))

	dir, receipt := runRelativeImportFiles(t)
	var admission map[string]any
	if err := json.Unmarshal(admissionBytes, &admission); err != nil {
		t.Fatalf("admission-context.json: %v", err)
	}
	if _, present := admission["previous"]; !present {
		admission["previous"] = nil
	}
	var domain map[string]any
	if err := json.Unmarshal(domainBytes, &domain); err != nil {
		t.Fatalf("domain-context.json: %v", err)
	}
	pins, ok := domain["source_pins"].([]any)
	if !ok {
		t.Fatalf("domain-context.json has no source_pins array")
	}
	for _, rawPin := range pins {
		pin, ok := rawPin.(map[string]any)
		if !ok {
			t.Fatalf("source pin is not an object")
		}
		if _, present := pin["advisory_id"]; !present {
			pin["advisory_id"] = nil
		}
		if _, present := pin["advisory_revision"]; !present {
			pin["advisory_revision"] = nil
		}
	}
	var bindings struct {
		Containers []struct {
			ObservedAt string `json:"observed_at"`
			SourceName string `json:"source_name"`
			SourceHash string `json:"source_hash"`
			Locator    string `json:"locator"`
		} `json:"containers"`
		Subject struct {
			UID string `json:"uid"`
		} `json:"subject"`
	}
	if err := json.Unmarshal(readTemp(t, filepath.Join(dir, "bindings.json")), &bindings); err != nil {
		t.Fatalf("bindings fixture: %v", err)
	}
	container := bindings.Containers[0]
	contextBytes := marshalForTest(t, map[string]any{
		"target": map[string]any{
			"subject_uid":      bindings.Subject.UID,
			"container_class":  "regular",
			"container_name":   "api",
			"vulnerability_id": "CVE-2026-1001",
			"source":           container.SourceName,
			"source_hash":      container.SourceHash,
			"locator":          container.Locator,
			"observed_at":      container.ObservedAt,
		},
		"admission": admission,
		"domain":    domain,
	})
	contextPath := filepath.Join(dir, "context.json")
	if err := os.WriteFile(contextPath, contextBytes, 0o600); err != nil {
		t.Fatalf("write context: %v", err)
	}

	figure := fixturePaths{
		bundle:     "bundle-envelope.json",
		bundleHash: receipt.BundleHash,
		pack:       packPath,
		context:    "context.json",
	}
	fingerprint := receiptFingerprint(t, figure)

	reportArgs := []string{"report",
		"--bundle", figure.bundle, "--bundle-hash", figure.bundleHash,
		"--pack", figure.pack, "--context", figure.context,
		"--format", "json", "--out", "report.json"}
	if exit, _, stderr := runCLI(t, reportArgs); exit != 0 {
		t.Fatalf("report exit=%d stderr=%q", exit, stderr)
	}
	if _, err := os.Stat(filepath.Join(dir, "report.json")); err != nil {
		t.Fatalf("report artifact missing: %v", err)
	}

	if exit, stdout, stderr := runCLI(t, verifyArgs(figure, fingerprint)); exit != 0 || stdout != "verified\n" {
		t.Fatalf("verify exit=%d stdout=%q stderr=%q", exit, stdout, stderr)
	}
}

// mustAbs resolves one path against the working directory at call time and
// fails the test on error. Paths resolved before the chdir stay valid after it.
func mustAbs(t *testing.T, relative string) string {
	t.Helper()
	absolute, err := filepath.Abs(relative)
	if err != nil {
		t.Fatalf("abs %s: %v", relative, err)
	}
	return absolute
}
