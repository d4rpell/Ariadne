package rulepack

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	contract "github.com/d4rpell/Ariadne/pkg/evidence"
)

// AX-04 group B (F14, expired-or-tampered-rule): committed pack vectors. Each
// case is a golden of rejection: the pack bytes are frozen, the admission
// context is frozen, and the expected typed error code is frozen. The base case
// is the positive control: an admitted pack. Every rejection vector differs
// from the base only in the condition under test; the pack hash in the context
// is recomputed independently with crypto/sha256 so it always matches the
// committed bytes (except in wrong-hash, where the mismatch is the subject).
//
// What this accredit: the exact rejection code of each vector, attributed to
// its cause. What it does not accredit: isolation (that is the import contract
// test) and no general detection of executable code: the forbidden field is an
// inert datum refused by the closed grammar.

const ax04F14Root = "../../fixtures/F14-expired-or-tampered-rule/0.2"

// ax04F14Expected is the committed expectation of one vector. An empty
// error_code means the pack must be admitted (positive control).
type ax04F14Expected struct {
	EntryPoint     string `json:"entry_point"`
	EvaluatedAt    string `json:"evaluated_at"`
	ExpectedPackID string `json:"expected_pack_id"`
	MinimumVersion int64  `json:"minimum_version"`
	PackSHA256     string `json:"pack_sha256"`
	ErrorCode      string `json:"error_code"`
}

func ax04F14Read(t *testing.T, caseName, file string) []byte {
	t.Helper()
	body, err := os.ReadFile(filepath.Join(ax04F14Root, caseName, file))
	if err != nil {
		t.Fatalf("read %s/%s: %v", caseName, file, err)
	}
	return body
}

// ax04F14IndependentHash recomputes the SHA-256 of the exact committed bytes
// with crypto/sha256, never through a production helper.
func ax04F14IndependentHash(data []byte) string {
	digest := sha256.Sum256(data)
	return "sha256:" + hex.EncodeToString(digest[:])
}

// ax04F14ReplaceOnce reverses exactly one occurrence of a field in a committed
// vector: it fails if the fragment is absent or not unique, so the reversal is
// forced to have happened and the equality with the base is not vacuous.
func ax04F14ReplaceOnce(t *testing.T, caseName, before, after string) string {
	t.Helper()
	document := string(ax04F14Read(t, caseName, "pack.json"))
	if strings.Count(document, before) != 1 {
		t.Fatalf("%s: the field %q must appear exactly once, found %d", caseName, before, strings.Count(document, before))
	}
	return strings.Replace(document, before, after, 1)
}

func TestAX04F14FixtureVectors(t *testing.T) {
	baseBytes := ax04F14Read(t, "base", "pack.json")
	base := string(baseBytes)
	// The isolated variation is verified by exact field reversal, not merely by
	// inequality: reverting ONLY the announced field must reproduce the base bytes
	// exactly. This rejects a vector that varies some additional field.
	if bytes.Equal(baseBytes, ax04F14Read(t, "wrong-hash", "pack.json")) == false {
		t.Fatal("wrong-hash must commit the base bytes; only its pinned context varies")
	}
	if bytes.Equal(baseBytes, ax04F14Read(t, "downgrade", "pack.json")) == false {
		t.Fatal("downgrade must commit the base bytes; only the minimum version varies")
	}
	// The reversal must actually happen: replaceOneOccurrence fails if the target
	// fragment is absent or appears more than once, so a no-op replace cannot make
	// this check pass vacuously.
	revertedExpired := ax04F14ReplaceOnce(t, "expired",
		`"expires_at":"2026-09-30T23:59:59Z"`,
		`"expires_at":"2026-12-31T23:59:59Z"`)
	if revertedExpired != base {
		t.Fatal("expired must differ from base ONLY in expires_at")
	}
	revertedForbidden := ax04F14ReplaceOnce(t, "forbidden-field",
		`"executable":"/bin/sh -c true",`, "")
	if revertedForbidden != base {
		t.Fatal("forbidden-field must differ from base ONLY in the added key")
	}

	cases := []string{"base", "expired", "wrong-hash", "downgrade", "forbidden-field"}
	for _, caseName := range cases {
		t.Run(caseName, func(t *testing.T) {
			packBytes := ax04F14Read(t, caseName, "pack.json")
			var expected ax04F14Expected
			if err := json.Unmarshal(ax04F14Read(t, caseName, "expected.json"), &expected); err != nil {
				t.Fatalf("expected.json does not decode: %v", err)
			}
			if expected.EntryPoint != "Admit" {
				t.Fatalf("entry_point = %q, want the committed Admit call", expected.EntryPoint)
			}

			// The committed bytes must be exactly the ones the expectation pins:
			// the independent hash is the contract between them.
			if got := ax04F14IndependentHash(packBytes); got != expected.PackSHA256 {
				t.Fatalf("pack.json hash = %s, want the expected %s", got, expected.PackSHA256)
			}

			evaluatedAt, err := time.Parse(time.RFC3339, expected.EvaluatedAt)
			if err != nil {
				t.Fatalf("evaluated_at: %v", err)
			}
			stamp, err := contract.NewTimestamp(evaluatedAt)
			if err != nil {
				t.Fatalf("timestamp: %v", err)
			}
			context := AdmissionContext{
				EvaluatedAt:    stamp,
				ExpectedPackID: expected.ExpectedPackID,
				MinimumVersion: expected.MinimumVersion,
			}
			if expected.ErrorCode == "pack_hash_mismatch" {
				// The vector's subject is a pin that disagrees with the bytes; the
				// context keeps that pinned digest, which the expectation froze.
				context.ExpectedPackHash = "sha256:" + repeatByte('0', 64)
			} else {
				context.ExpectedPackHash = ax04F14IndependentHash(packBytes)
			}

			admitted, err := Admit(packBytes, context)
			if expected.ErrorCode == "" {
				if err != nil {
					t.Fatalf("the positive control must be admitted: %v", err)
				}
				if !admitted.Valid() {
					t.Fatal("an admitted pack must be valid")
				}
				return
			}
			if err == nil {
				t.Fatalf("the %s vector must be rejected, but admission succeeded", caseName)
			}
			if !Is(err, ErrorCode(expected.ErrorCode)) {
				t.Fatalf("error = %v, want the exact code %s", err, expected.ErrorCode)
			}

			// Attribution: repairing the single varied condition must admit a pack
			// again, so the rejection is caused by that condition and not by an
			// earlier phase. For vectors whose variation is in the bytes (expired,
			// forbidden-field) the repair is the base document with a context whose
			// hash matches those bytes.
			repairBytes, repairContext := packBytes, context
			switch caseName {
			case "expired", "forbidden-field":
				repairBytes = ax04F14Read(t, "base", "pack.json")
				repairContext.ExpectedPackHash = ax04F14IndependentHash(repairBytes)
			case "wrong-hash":
				repairContext.ExpectedPackHash = ax04F14IndependentHash(packBytes)
			case "downgrade":
				repairContext.MinimumVersion = 1
			}
			if _, err := Admit(repairBytes, repairContext); err != nil {
				t.Fatalf("after repairing the varied condition the pack must be admitted: %v", err)
			}
		})
	}
}

func repeatByte(symbol byte, count int) string {
	out := make([]byte, count)
	for index := range out {
		out[index] = symbol
	}
	return string(out)
}
