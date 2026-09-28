package main

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"
)

// RP-02 and RP-04: the replay fingerprint. The oracle is independent of the
// production helper: it locates the `result` value with its own minimal scan and
// hashes it with the standard library, so a shared bug cannot hide behind both.

func independentResultBytes(t *testing.T, document []byte) []byte {
	t.Helper()
	marker := []byte(`{"result":`)
	if !strings.HasPrefix(string(document), string(marker)) {
		t.Fatalf("report JSON does not start with %s", marker)
	}
	rest := string(document)[len(marker):]
	depth := 0
	inString := false
	for index := 0; index < len(rest); index++ {
		character := rest[index]
		if inString {
			if character == '\\' {
				index++
				continue
			}
			if character == '"' {
				inString = false
			}
			continue
		}
		switch character {
		case '"':
			inString = true
		case '{', '[':
			depth++
		case '}', ']':
			depth--
			if depth == 0 {
				return []byte(rest[:index+1])
			}
		}
	}
	t.Fatalf("unbalanced result value")
	return nil
}

func TestFingerprintMatchesIndependentOracle(t *testing.T) {
	figures := composeFixture(t, "F09-unmapped-redhat-package")
	fingerprint := receiptFingerprint(t, figures)

	// Re-run evaluate to obtain the very JSON the fingerprint covers, via the
	// report renderer, and hash it with the independent scanner.
	jsonBytes := renderF09JSON(t, figures)
	value := independentResultBytes(t, jsonBytes)
	sum := sha256.Sum256(value)
	want := "sha256:" + hex.EncodeToString(sum[:])
	if fingerprint != want {
		t.Fatalf("fingerprint = %s, oracle = %s", fingerprint, want)
	}
}

func TestRootMemberValueIgnoresNestedKeys(t *testing.T) {
	document := []byte(`{"result":{"a":1,"note":"result: {}"},"evidence_catalog":[],"warning_catalog":[]}`)
	value, ok := rootMemberValue(document, "result")
	if !ok {
		t.Fatalf("result member not found")
	}
	if string(value) != `{"a":1,"note":"result: {}"}` {
		t.Fatalf("value = %q", value)
	}
}

func TestRootMemberValueMissing(t *testing.T) {
	document := []byte(`{"other":1}`)
	if _, ok := rootMemberValue(document, "result"); ok {
		t.Fatalf("absent member reported as found")
	}
}

// The fingerprint is not the bundle hash and not a hash of the complete report.
func TestFingerprintIsNotBundleHashOrWholeReport(t *testing.T) {
	figures := composeFixture(t, "F09-unmapped-redhat-package")
	fingerprint := receiptFingerprint(t, figures)
	if fingerprint == figures.bundleHash {
		t.Fatalf("fingerprint equals the bundle hash")
	}
	jsonBytes := renderF09JSON(t, figures)
	sum := sha256.Sum256(jsonBytes)
	if fingerprint == "sha256:"+hex.EncodeToString(sum[:]) {
		t.Fatalf("fingerprint covers the complete report")
	}
}
