package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// Shared fixture plumbing: the CLI reads real files, so every test composes the
// documented CLI context (target + admission + domain, ADR-0023 §4.2) from the
// package fixtures and writes it to a private temporary directory. The fixture
// files themselves are never modified.

const fixturesRoot = "../../fixtures"

type fixturePaths struct {
	bundle     string
	bundleHash string
	pack       string
	context    string
}

func composeFixture(t *testing.T, slug string) fixturePaths {
	t.Helper()
	root := filepath.Join(fixturesRoot, slug, "0.2")
	input := filepath.Join(root, "input")
	expected := filepath.Join(root, "expected")

	read := func(path string) []byte {
		t.Helper()
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("fixture read %s: %v", path, err)
		}
		return data
	}

	var target map[string]any
	if err := json.Unmarshal(read(filepath.Join(input, "target.json")), &target); err != nil {
		t.Fatalf("target.json: %v", err)
	}
	var admission map[string]any
	if err := json.Unmarshal(read(filepath.Join(input, "admission-context.json")), &admission); err != nil {
		t.Fatalf("admission-context.json: %v", err)
	}
	if _, present := admission["previous"]; !present {
		admission["previous"] = nil
	}
	var domain map[string]any
	if err := json.Unmarshal(read(filepath.Join(input, "domain-context.json")), &domain); err != nil {
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
	contextDocument := map[string]any{
		"target":    target,
		"admission": admission,
		"domain":    domain,
	}
	contextBytes, err := json.Marshal(contextDocument)
	if err != nil {
		t.Fatalf("compose context: %v", err)
	}

	dir := t.TempDir()
	contextPath := filepath.Join(dir, "context.json")
	if err := os.WriteFile(contextPath, contextBytes, 0o600); err != nil {
		t.Fatalf("write context: %v", err)
	}
	return fixturePaths{
		bundle:     filepath.Join(input, "bundle.json"),
		bundleHash: string(trimSpace(read(filepath.Join(expected, "bundle.sha256")))),
		pack:       filepath.Join(input, "pack.json"),
		context:    contextPath,
	}
}

func trimSpace(data []byte) []byte {
	start := 0
	for start < len(data) && (data[start] == ' ' || data[start] == '\n' || data[start] == '\r' || data[start] == '\t') {
		start++
	}
	end := len(data)
	for end > start && (data[end-1] == ' ' || data[end-1] == '\n' || data[end-1] == '\r' || data[end-1] == '\t') {
		end--
	}
	return data[start:end]
}

func evaluateArgs(f fixturePaths) []string {
	return []string{"evaluate",
		"--bundle", f.bundle, "--bundle-hash", f.bundleHash,
		"--pack", f.pack, "--context", f.context}
}

func verifyArgs(f fixturePaths, fingerprint string) []string {
	argv := evaluateArgs(f)
	argv[0] = "verify"
	return append(argv, "--result-fingerprint", fingerprint)
}

// receiptFingerprint runs evaluate and returns the fingerprint of its receipt.
func receiptFingerprint(t *testing.T, f fixturePaths) string {
	t.Helper()
	exit, stdout, stderr := runCLI(t, evaluateArgs(f))
	if exit != 0 {
		t.Fatalf("evaluate exit=%d stderr=%q", exit, stderr)
	}
	var receipt struct {
		BundleHash        string `json:"bundle_hash"`
		ResultFingerprint string `json:"result_fingerprint"`
	}
	if err := json.Unmarshal([]byte(stdout), &receipt); err != nil {
		t.Fatalf("receipt is not JSON: %v (%q)", err, stdout)
	}
	if receipt.BundleHash != f.bundleHash {
		t.Fatalf("receipt bundle_hash = %q, want %q", receipt.BundleHash, f.bundleHash)
	}
	return receipt.ResultFingerprint
}

func writeTemp(t *testing.T, name string, data []byte) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("write %s: %v", name, err)
	}
	return path
}

func readTemp(t *testing.T, path string) []byte {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return data
}

// jsonUnmarshal and marshalForTest keep the test helpers free of a second JSON
// stack: they are the standard codec, used only to compose oversized models in
// tests, never in production paths.
func jsonUnmarshal(data []byte, target any) error { return json.Unmarshal(data, target) }

func marshalForTest(t *testing.T, value any) []byte {
	t.Helper()
	data, err := json.Marshal(value)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return data
}

// maxImagesForTest, maxItemsForTest, maxElementsForTest and maxStringsForTest
// mirror the evaluator's ratified budgets so a composed model exceeds them
// without importing the evaluator into this file.
func maxImagesForTest() int   { return 10000 }
func maxItemsForTest() int    { return 100000 }
func maxElementsForTest() int { return 500000 }
func maxStringsForTest() int  { return 64 << 20 }

// hashOfBytes is the same preimage rule the project uses everywhere: SHA-256 of
// the exact bytes.
func hashOfBytes(data []byte) string {
	sum := sha256.Sum256(data)
	return "sha256:" + hex.EncodeToString(sum[:])
}
