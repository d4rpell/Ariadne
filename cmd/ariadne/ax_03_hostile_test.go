package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// AX-03 — CLI edge of the hostile-input contract (T1–T3).
//
// The parser-level classes live in internal/ingest/ax_03_hostile_test.go. This
// file pins the one place where the CLI turns a hostile findings source into a
// diagnostic: a structural failure before the header is admitted is an unusable
// source (findings_decode/invalid_findings, exit 3), and the diagnostic carries
// no bytes of the input. A delimited row rejection does not abort the parser and
// therefore does not reach this path.

// ax03Canary is a distinctive marker embedded in the hostile source: if it ever
// appears in the diagnostic, the CLI is echoing input bytes.
const ax03Canary = "AX03PRIVATECANARY"

// ax03AdmittedCanary is a second, distinct marker placed on an admitted value
// that the wire does publish. It is the positive control: the same sweep that
// asserts the hostile canary is absent must find this one present, so the
// absence is never vacuous.
const ax03AdmittedCanary = "AX03ADMITTEDCANARY"

// ax03WriteFindings writes a findings file whose bytes are exactly payload.
func ax03WriteFindings(t *testing.T, dir string, payload []byte) string {
	t.Helper()
	path := filepath.Join(dir, "findings.csv")
	if err := os.WriteFile(path, payload, 0o600); err != nil {
		t.Fatalf("write findings: %v", err)
	}
	return path
}

// ax03BindingsWithoutLinks returns the bindings fixture with no declared links,
// so the findings source is the only fact of the run.
func ax03BindingsWithoutLinks(t *testing.T, dir string) string {
	t.Helper()
	document := strings.Replace(validBindingsFixture,
		`"bindings": [{"finding_index": 0, "container_name": "api", "container_class": "regular"}]`,
		`"bindings": []`, 1)
	return writeBindings(t, dir, document)
}

// TestAX03CLIRejectsHostileSourceWithoutHeader pins that a source aborted before
// the header is admitted (a BOM carrying a canary) is rejected as
// findings_decode/invalid_findings with exit 3, and that the one-line diagnostic
// carries neither the canary nor any byte of the source.
func TestAX03CLIRejectsHostileSourceWithoutHeader(t *testing.T) {
	dir := t.TempDir()
	payload := append([]byte{0xEF, 0xBB, 0xBF}, []byte(ax03Canary+headerOnlyCSV)...)
	csvPath := ax03WriteFindings(t, dir, payload)
	bindingsPath := ax03BindingsWithoutLinks(t, dir)

	argv := importArgs(t, dir, csvPath, bindingsPath)
	gotExit, stdout, stderr := runCLI(t, argv)
	if gotExit != 3 {
		t.Fatalf("exit = %d, want 3 (stderr %q)", gotExit, stderr)
	}
	if stdout != "" {
		t.Fatalf("stdout = %q, want empty", stdout)
	}
	const want = `{"error":{"stage":"findings_decode","code":"invalid_findings","message":"ariadne: invalid_findings"}}` + "\n"
	if stderr != want {
		t.Fatalf("stderr = %q, want %q", stderr, want)
	}
	if strings.Contains(stderr, ax03Canary) {
		t.Fatalf("diagnostic leaked input bytes: %q", stderr)
	}
}

// TestAX03CLIKeepsRowRejectionAsAPartialBundle pins the other side of the
// boundary: a hostile *row* (a NUL inside a quoted field) does not abort the
// parser, so the import is not rejected — it produces a partial bundle. The
// hostile canary never reaches a published artefact, while a second canary on an
// admitted value of the same file does: the sweep is non-vacuous.
func TestAX03CLIKeepsRowRejectionAsAPartialBundle(t *testing.T) {
	dir := t.TempDir()
	header := "schema_version,vulnerability_id,package_name,installed_version,fix_status,image_registry,image_repository\n"
	// Row 0 is rejected (NUL inside a quoted field); row 1 is admitted and becomes
	// finding index 0, which the bindings fixture links to the container.
	hostileRow := "1.0,CVE-2026-1001,\"" + ax03Canary + "\x00tail\",1.1.1k,fixed,registry.example,payments/api\n"
	admittedRow := "1.0,CVE-2026-1002," + ax03AdmittedCanary + ",1.2.13,not_fixed,registry.example,payments/api\n"
	csvPath := ax03WriteFindings(t, dir, []byte(header+hostileRow+admittedRow))
	bindingsPath := writeBindings(t, dir, validBindingsFixture)

	argv := importArgs(t, dir, csvPath, bindingsPath)
	gotExit, stdout, stderr := runCLI(t, argv)
	if gotExit != 0 {
		t.Fatalf("exit = %d, want 0: a row rejection must stay a partial bundle (stderr %q)", gotExit, stderr)
	}
	if stderr != "" {
		t.Fatalf("a successful import must not write a diagnostic, got %q", stderr)
	}
	if strings.Contains(stdout, ax03Canary) {
		t.Fatalf("receipt leaked input bytes: %q", stdout)
	}
	// The hostile row is a real rejection, not a silently dropped line: the
	// accounting counts both rows and the bundle is published as partial.
	var receipt importReceipt
	if err := json.Unmarshal([]byte(stdout), &receipt); err != nil {
		t.Fatalf("receipt is not JSON: %v (%q)", err, stdout)
	}
	if receipt.RowsTotal != 2 || receipt.RowsAccepted != 1 || receipt.RowsRejected != 1 {
		t.Fatalf("accounting = %d/%d/%d, want 2 total, 1 accepted, 1 rejected",
			receipt.RowsTotal, receipt.RowsAccepted, receipt.RowsRejected)
	}
	envelope, err := os.ReadFile(filepath.Join(dir, "bundle-envelope.json"))
	if err != nil {
		t.Fatalf("read envelope: %v", err)
	}
	var document struct {
		Provenance struct {
			Completeness string `json:"completeness"`
			Coverage     struct {
				Termination string `json:"termination"`
			} `json:"coverage"`
		} `json:"provenance"`
	}
	if err := json.Unmarshal(envelope, &document); err != nil {
		t.Fatalf("envelope is not JSON: %v", err)
	}
	if document.Provenance.Completeness != "partial" {
		t.Fatalf("completeness = %q, want partial", document.Provenance.Completeness)
	}
	if document.Provenance.Coverage.Termination != "finished" {
		t.Fatalf("termination = %q, want finished", document.Provenance.Coverage.Termination)
	}
	sawAdmitted := false
	for _, name := range []string{"bundle-envelope.json", "bundle-projection.json"} {
		body, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			t.Fatalf("read %s: %v", name, err)
		}
		if strings.Contains(string(body), ax03Canary) {
			t.Fatalf("%s leaked the hostile input bytes", name)
		}
		if strings.Contains(string(body), ax03AdmittedCanary) {
			sawAdmitted = true
		}
	}
	if !sawAdmitted {
		t.Fatal("the admitted canary is absent from every artefact: the absence sweep would be vacuous")
	}
	digest, err := os.ReadFile(filepath.Join(dir, "bundle-digest.txt"))
	if err != nil {
		t.Fatalf("read digest: %v", err)
	}
	if strings.Contains(string(digest), ax03Canary) {
		t.Fatalf("digest leaked input bytes: %q", digest)
	}
}
