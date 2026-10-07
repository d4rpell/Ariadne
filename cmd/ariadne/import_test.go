package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// Pipeline-level tests of ADR-0036 (task A3-09). Every rejection is asserted as
// a whole (exit, empty stdout, exact one-line diagnostic); every success path
// is deterministic byte a byte. The fixture lives in testdata/import; the
// golden anchors live in import_golden_test.go.

const (
	testObservedAt = "2026-10-07T09:00:00Z"
)

// importArgs builds one import invocation over the package fixture.
func importArgs(t *testing.T, dir string, findingsPath, bindingsPath string, extra ...string) []string {
	t.Helper()
	argv := []string{"import",
		"--findings", findingsPath,
		"--bindings", bindingsPath,
		"--observed-at", testObservedAt,
		"--out-envelope", filepath.Join(dir, "bundle-envelope.json"),
		"--out-projection", filepath.Join(dir, "bundle-projection.json"),
		"--out-digest", filepath.Join(dir, "bundle-digest.txt"),
	}
	return append(argv, extra...)
}

func fixtureImportArgs(t *testing.T, dir string, extra ...string) []string {
	t.Helper()
	return importArgs(t, dir, "testdata/import/fixture.csv", "testdata/import/bindings.json", extra...)
}

func writeBindings(t *testing.T, dir string, document string) string {
	t.Helper()
	path := filepath.Join(dir, "bindings.json")
	if err := os.WriteFile(path, []byte(document), 0o600); err != nil {
		t.Fatalf("write bindings: %v", err)
	}
	return path
}

// inDir moves the process working directory to dir for the duration of the
// test, so an import can run against relative paths and the argv copy inside
// the bundle stays free of machine-specific absolute paths.
func inDir(t *testing.T, dir string) {
	t.Helper()
	original, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	if err := os.Chdir(dir); err != nil {
		t.Fatalf("chdir %s: %v", dir, err)
	}
	t.Cleanup(func() {
		if err := os.Chdir(original); err != nil {
			t.Fatalf("restore cwd: %v", err)
		}
	})
}

// copyImportFixture materializes the synthetic import fixture into dir under
// fixed relative names, so every run sees the same argv words.
func copyImportFixture(t *testing.T, dir string) {
	t.Helper()
	for name, data := range map[string][]byte{
		"fixture.csv":   readTemp(t, "testdata/import/fixture.csv"),
		"bindings.json": readTemp(t, "testdata/import/bindings.json"),
	} {
		if err := os.WriteFile(filepath.Join(dir, name), data, 0o600); err != nil {
			t.Fatalf("copy fixture %s: %v", name, err)
		}
	}
}

// relativeImportArgs is the deterministic invocation shape of the golden and
// determinism tests: relative paths only, so the argv copy and therefore the
// canonical envelope are machine-independent.
func relativeImportArgs() []string {
	return []string{"import",
		"--findings", "fixture.csv",
		"--bindings", "bindings.json",
		"--observed-at", testObservedAt,
		"--out-envelope", "bundle-envelope.json",
		"--out-projection", "bundle-projection.json",
		"--out-digest", "bundle-digest.txt"}
}

const validBindingsFixture = `{
  "format": "case-import-bindings-v1",
  "version": "1.0",
  "subject": {
    "cluster_alias": "cluster-a", "namespace": "payments", "kind": "Pod",
    "name": "payments-api", "uid": "pod-uid-1", "owner_chain": "deployments/payments-api"
  },
  "containers": [
    {
      "container_name": "api", "container_class": "regular",
      "observed_at": "2026-10-07T09:00:00Z",
      "platform": {"status": "unknown"},
      "source_name": "sanitized-pods.json",
      "source_hash": "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
      "locator": "items[0].status.containerStatuses[0].imageID"
    }
  ],
  "bindings": [{"finding_index": 0, "container_name": "api", "container_class": "regular"}]
}`

const headerOnlyCSV = "schema_version,vulnerability_id,package_name,installed_version,fix_status,image_registry,image_repository,image_tag,severity\n"

func TestImportArgumentsRequireAllFlags(t *testing.T) {
	complete := []string{"import",
		"--findings", "f.csv", "--bindings", "b.json", "--observed-at", testObservedAt,
		"--out-envelope", "e.json", "--out-projection", "p.json", "--out-digest", "d.txt"}
	for index := 1; index < len(complete); index += 2 {
		name := complete[index][2:]
		reduced := append([]string{}, complete[:index]...)
		reduced = append(reduced, complete[index+2:]...)
		expectRejection(t, reduced, stageArguments, codeInvalidArguments, 2)
		if name == "" {
			t.Fatalf("flag name must not be empty")
		}
	}
}

func TestImportRejectsDeferredCommands(t *testing.T) {
	for _, name := range deferredCommands {
		expectRejection(t, []string{name}, stageArguments, codeCommandDeferred, 2)
	}
}

func TestImportRejectsNonCanonicalObservedAt(t *testing.T) {
	for _, instant := range []string{
		"2026-10-07T09:00:00", "2026-10-07T09:00:00+00:00", "2026-10-07T11:00:00+02:00",
		"2026-10-07T09:00:00.000Z", "not-a-time", "",
	} {
		argv := importArgs(t, t.TempDir(), "testdata/import/fixture.csv", "testdata/import/bindings.json")
		argv[5] = instant
		expectRejection(t, argv, stageArguments, codeInvalidArguments, 2)
	}
}

func TestImportReadsFindingsOnceForHashAndParse(t *testing.T) {
	dir := t.TempDir()
	exit, stdout, stderr := runCLI(t, fixtureImportArgs(t, dir))
	if exit != 0 {
		t.Fatalf("exit=%d stderr=%q", exit, stderr)
	}
	envelope := readTemp(t, filepath.Join(dir, "bundle-envelope.json"))
	wantHash := hashOfBytes(readTemp(t, "testdata/import/fixture.csv"))
	var document struct {
		Provenance struct {
			Inputs []struct {
				Path string `json:"path"`
				Hash string `json:"hash"`
			} `json:"inputs"`
		} `json:"provenance"`
	}
	if err := json.Unmarshal(envelope, &document); err != nil {
		t.Fatalf("envelope is not JSON: %v", err)
	}
	if len(document.Provenance.Inputs) != 1 {
		t.Fatalf("inputs = %d, want exactly the findings source", len(document.Provenance.Inputs))
	}
	if document.Provenance.Inputs[0].Hash != wantHash {
		t.Fatalf("input hash = %q, want the sha256 of the exact source bytes %q", document.Provenance.Inputs[0].Hash, wantHash)
	}
	var receipt struct {
		BundleHash string `json:"bundle_hash"`
	}
	if err := json.Unmarshal([]byte(stdout), &receipt); err != nil {
		t.Fatalf("receipt is not JSON: %v (%q)", err, stdout)
	}
	digest := strings.TrimRight(string(readTemp(t, filepath.Join(dir, "bundle-digest.txt"))), "\n")
	if receipt.BundleHash != digest {
		t.Fatalf("receipt hash = %q, want the digest artifact %q", receipt.BundleHash, digest)
	}
}

func TestImportRejectsFindingsLimit(t *testing.T) {
	dir := t.TempDir()
	oversized := filepath.Join(dir, "oversized.csv")
	if err := os.WriteFile(oversized, make([]byte, maxFindingsInputBytes+1), 0o600); err != nil {
		t.Fatalf("write oversized findings: %v", err)
	}
	bindingsPath := writeBindings(t, dir, validBindingsFixture)
	argv := importArgs(t, dir, oversized, bindingsPath)
	expectRejection(t, argv, stageFindingsRead, codeInputLimit, 3)
}

func TestImportRejectsBindingsLimit(t *testing.T) {
	dir := t.TempDir()
	oversized := filepath.Join(dir, "oversized.json")
	if err := os.WriteFile(oversized, make([]byte, maxBindingsInputBytes+1), 0o600); err != nil {
		t.Fatalf("write oversized bindings: %v", err)
	}
	argv := importArgs(t, dir, "testdata/import/fixture.csv", oversized)
	expectRejection(t, argv, stageBindingsRead, codeInputLimit, 3)
}

func TestImportRejectsBindingOutOfRange(t *testing.T) {
	dir := t.TempDir()
	document := strings.Replace(validBindingsFixture, `"finding_index": 0`, `"finding_index": 9`, 1)
	bindingsPath := writeBindings(t, dir, document)
	csvPath := filepath.Join(dir, "findings.csv")
	if err := os.WriteFile(csvPath, []byte(headerOnlyCSV), 0o600); err != nil {
		t.Fatalf("write findings: %v", err)
	}
	expectRejection(t, importArgs(t, dir, csvPath, bindingsPath), stageImport, codeInvalidBindings, 3)
}

func TestImportRejectsDuplicateFindingBinding(t *testing.T) {
	dir := t.TempDir()
	document := strings.Replace(validBindingsFixture,
		`"bindings": [{"finding_index": 0, "container_name": "api", "container_class": "regular"}]`,
		`"bindings": [{"finding_index": 0, "container_name": "api", "container_class": "regular"},`+
			`{"finding_index": 0, "container_name": "api", "container_class": "regular"}]`, 1)
	bindingsPath := writeBindings(t, dir, document)
	expectRejection(t, importArgs(t, dir, "testdata/import/fixture.csv", bindingsPath), stageImport, codeInvalidBindings, 3)
}

func TestImportRejectsMissingContainer(t *testing.T) {
	dir := t.TempDir()
	document := strings.Replace(validBindingsFixture, `"container_name": "api", "container_class": "regular"}`, `"container_name": "sidecar", "container_class": "regular"}`, 1)
	bindingsPath := writeBindings(t, dir, document)
	expectRejection(t, importArgs(t, dir, "testdata/import/fixture.csv", bindingsPath), stageImport, codeInvalidBindings, 3)
}

func TestImportZeroFindingsWithBindings(t *testing.T) {
	dir := t.TempDir()
	bindingsPath := writeBindings(t, dir, validBindingsFixture)
	csvPath := filepath.Join(dir, "findings.csv")
	if err := os.WriteFile(csvPath, []byte(headerOnlyCSV), 0o600); err != nil {
		t.Fatalf("write findings: %v", err)
	}
	expectRejection(t, importArgs(t, dir, csvPath, bindingsPath), stageImport, codeInvalidBindings, 3)
}

func TestImportWritesExclusive0600(t *testing.T) {
	dir := t.TempDir()
	if exit, _, stderr := runCLI(t, fixtureImportArgs(t, dir)); exit != 0 {
		t.Fatalf("first import exit=%d stderr=%q", exit, stderr)
	}
	if runtime.GOOS != "windows" {
		// Windows does not enforce POSIX modes on Stat; the exclusive creation
		// itself is the observable contract there.
		for _, artifact := range []string{"bundle-envelope.json", "bundle-projection.json", "bundle-digest.txt"} {
			info, err := os.Stat(filepath.Join(dir, artifact))
			if err != nil {
				t.Fatalf("artifact %s missing: %v", artifact, err)
			}
			if info.Mode().Perm() != 0o600 {
				t.Fatalf("artifact %s mode = %v, want 0600", artifact, info.Mode().Perm())
			}
		}
	}
	expectRejection(t, fixtureImportArgs(t, dir), stageOutputWrite, codeAlreadyExists, 4)
}

func TestImportReportsPartialDelivery(t *testing.T) {
	dir := t.TempDir()
	projectionPath := filepath.Join(dir, "bundle-projection.json")
	if err := os.WriteFile(projectionPath, []byte("sentinel\n"), 0o600); err != nil {
		t.Fatalf("prepare the pre-existing projection: %v", err)
	}
	exit, stdout, stderr := runCLI(t, fixtureImportArgs(t, dir))
	if exit != 4 || stdout != "" {
		t.Fatalf("exit=%d stdout=%q stderr=%q, want exit 4 without receipt", exit, stdout, stderr)
	}
	if _, err := os.Stat(filepath.Join(dir, "bundle-envelope.json")); err != nil {
		t.Fatalf("the envelope of the partial delivery is missing: %v", err)
	}
	data, err := os.ReadFile(projectionPath)
	if err != nil || string(data) != "sentinel\n" {
		t.Fatalf("pre-existing projection was touched: %q (%v)", data, err)
	}
}

func TestImportSuppressesReceiptUntilComplete(t *testing.T) {
	dir := t.TempDir()
	digestPath := filepath.Join(dir, "bundle-digest.txt")
	if err := os.WriteFile(digestPath, []byte("sentinel\n"), 0o600); err != nil {
		t.Fatalf("prepare the pre-existing digest: %v", err)
	}
	exit, stdout, _ := runCLI(t, fixtureImportArgs(t, dir))
	if exit != 4 || stdout != "" {
		t.Fatalf("exit=%d stdout=%q, want exit 4 and no receipt on a failed third write", exit, stdout)
	}
}

func TestImportDeterministic(t *testing.T) {
	first, second := t.TempDir(), t.TempDir()
	for _, dir := range []string{first, second} {
		copyImportFixture(t, dir)
	}
	inDir(t, first)
	if exit, _, stderr := runCLI(t, relativeImportArgs()); exit != 0 {
		t.Fatalf("first run exit=%d stderr=%q", exit, stderr)
	}
	os.Chdir(second)
	if exit, _, stderr := runCLI(t, relativeImportArgs()); exit != 0 {
		t.Fatalf("second run exit=%d stderr=%q", exit, stderr)
	}
	os.Chdir(first)
	for _, artifact := range []string{"bundle-envelope.json", "bundle-projection.json", "bundle-digest.txt"} {
		a := readTemp(t, filepath.Join(first, artifact))
		b := readTemp(t, filepath.Join(second, artifact))
		if string(a) != string(b) {
			t.Fatalf("%s is not byte-for-byte deterministic", artifact)
		}
	}
}

// brokenStructuralCSV is one unterminated quoted field: the parser reports a
// structural failure together with its verified progress (zero usable rows),
// and the pipeline must surface it, never repair it.
const brokenStructuralCSV = "schema_version,vulnerability_id,package_name,installed_version,fix_status,image_registry,image_repository,image_tag,severity\n" +
	"1.0,CVE-2026-1001,openssl,\"1.1.1k,fixed,registry.example,payments/api,release,high\n"

func TestImportPreservesStructuralErrorWithProgress(t *testing.T) {
	dir := t.TempDir()
	csvPath := filepath.Join(dir, "findings.csv")
	if err := os.WriteFile(csvPath, []byte(brokenStructuralCSV), 0o600); err != nil {
		t.Fatalf("write findings: %v", err)
	}
	// The document links nothing: the structural failure is the only fact.
	document := strings.Replace(validBindingsFixture,
		`"bindings": [{"finding_index": 0, "container_name": "api", "container_class": "regular"}]`,
		`"bindings": []`, 1)
	bindingsPath := writeBindings(t, dir, document)
	exit, stdout, stderr := runCLI(t, importArgs(t, dir, csvPath, bindingsPath))
	if exit != 0 {
		t.Fatalf("exit=%d stderr=%q, want a partial bundle, not a rejection", exit, stderr)
	}
	var receipt importReceipt
	if err := json.Unmarshal([]byte(stdout), &receipt); err != nil {
		t.Fatalf("receipt is not JSON: %v (%q)", err, stdout)
	}
	if receipt.RowsTotal != 0 {
		t.Fatalf("rows_total = %d, want the zero usable rows of the broken source", receipt.RowsTotal)
	}
	envelope := readTemp(t, filepath.Join(dir, "bundle-envelope.json"))
	var envelopeDocument struct {
		Provenance struct {
			Completeness string   `json:"completeness"`
			Errors       []string `json:"errors"`
		} `json:"provenance"`
	}
	if err := json.Unmarshal(envelope, &envelopeDocument); err != nil {
		t.Fatalf("envelope is not JSON: %v", err)
	}
	if envelopeDocument.Provenance.Completeness == "complete" {
		t.Fatalf("a structurally broken source must never project complete")
	}
	if len(envelopeDocument.Provenance.Errors) == 0 {
		t.Fatalf("the structural error is not visible in the bundle")
	}
}

func TestImportRejectsStructuralFailureWithoutProgress(t *testing.T) {
	// A BOM aborts the parser before the header is admitted: there is no
	// verified progress to evidence, so the source is unusable instead of a
	// partial bundle.
	dir := t.TempDir()
	csvPath := filepath.Join(dir, "findings.csv")
	if err := os.WriteFile(csvPath, append([]byte{0xEF, 0xBB, 0xBF}, []byte(headerOnlyCSV)...), 0o600); err != nil {
		t.Fatalf("write findings: %v", err)
	}
	document := strings.Replace(validBindingsFixture,
		`"bindings": [{"finding_index": 0, "container_name": "api", "container_class": "regular"}]`,
		`"bindings": []`, 1)
	bindingsPath := writeBindings(t, dir, document)
	expectRejection(t, importArgs(t, dir, csvPath, bindingsPath), stageFindingsDecode, codeInvalidFindings, 3)
}

func TestImportBuildsDeclaredRunMetadata(t *testing.T) {
	dir := t.TempDir()
	if exit, _, stderr := runCLI(t, fixtureImportArgs(t, dir)); exit != 0 {
		t.Fatalf("exit=%d stderr=%q", exit, stderr)
	}
	envelope := readTemp(t, filepath.Join(dir, "bundle-envelope.json"))
	var document struct {
		Provenance struct {
			CollectorVersion string           `json:"collector_version"`
			ParserVersion    string           `json:"parser_version"`
			ArgvSanitized    []string         `json:"argv_sanitized"`
			Budget           map[string]any   `json:"budget"`
			Consistency      string           `json:"consistency"`
			RedactionPolicy  string           `json:"redaction_policy"`
			StartedAt        *string          `json:"started_at"`
			EndedAt          *string          `json:"ended_at"`
			Warnings         []map[string]any `json:"warnings"`
		} `json:"provenance"`
	}
	if err := json.Unmarshal(envelope, &document); err != nil {
		t.Fatalf("envelope is not JSON: %v", err)
	}
	run := document.Provenance
	if run.CollectorVersion != "none" || run.ParserVersion != "prisma-v1.0" {
		t.Fatalf("declared versions = %q/%q, want none/prisma-v1.0", run.CollectorVersion, run.ParserVersion)
	}
	if len(run.ArgvSanitized) == 0 || run.ArgvSanitized[0] != "import" {
		t.Fatalf("argv_sanitized = %v, want the exact argv copy", run.ArgvSanitized)
	}
	if run.Budget["wall_clock"] != "none" {
		t.Fatalf("budget.wall_clock = %v, want none", run.Budget["wall_clock"])
	}
	if run.Consistency != "point-observation" || run.RedactionPolicy != "default-v1" {
		t.Fatalf("consistency/redaction = %q/%q", run.Consistency, run.RedactionPolicy)
	}
	if run.StartedAt != nil || run.EndedAt != nil {
		t.Fatalf("run timestamps = %v/%v, want null without a clock", run.StartedAt, run.EndedAt)
	}
	if len(run.Warnings) != 0 {
		t.Fatalf("run warnings = %v, want none", run.Warnings)
	}
}
