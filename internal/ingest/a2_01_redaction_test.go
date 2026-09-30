package ingest

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"
)

// Redaction frontier (ADR-0025 A.5, A.12.3): a key outside the allowlist is
// refused before its value is decoded or examined, and the source hash exists
// only after the whole examination succeeded and covers every original byte.

func TestA201RejectBeforeValueDecode(t *testing.T) {
	t.Run("prohibited key with a value above the string budget", func(t *testing.T) {
		// The value is a 70 KiB string: scanning it would report string_limit.
		// The reported code proves the value was never examined.
		value := strings.Repeat("s", 70*1024)
		document := `{"apiVersion":"v1","kind":"PodList","env":"` + value + `","items":[]}`
		_, err := a201Parse(t, document)
		a201WantFailure(t, err, a201Literal(at(t, document, `"env"`), "field is not allowed by the redaction profile"))
	})
	t.Run("prohibited key with a value of an unparseable shape", func(t *testing.T) {
		document := `{"apiVersion":"v1","kind":"PodList","env":[{"a":` + strings.Repeat("[]", 40) + `,"items":[]}`
		_, err := a201Parse(t, document)
		a201WantFailure(t, err, a201Literal(at(t, document, `"env"`), "field is not allowed by the redaction profile"))
	})
	t.Run("duplicate key with an invalid escape in its value", func(t *testing.T) {
		document := `{"apiVersion":"v1","kind":"PodList","metadata":{"resourceVersion":"a","resourceVersion":"\q"},"items":[]}`
		_, err := a201Parse(t, document)
		a201WantFailure(t, err, a201Literal(uint64(strings.LastIndex(document, `"resourceVersion"`)), "duplicate JSON key"))
	})
	t.Run("prohibited key whose value would exceed the depth budget", func(t *testing.T) {
		document := `{"apiVersion":"v1","kind":"PodList","env":` + strings.Repeat("[", 30) + strings.Repeat("]", 30) + `,"items":[]}`
		_, err := a201Parse(t, document)
		a201WantFailure(t, err, a201Literal(at(t, document, `"env"`), "field is not allowed by the redaction profile"))
	})
	t.Run("prohibited key whose value carries a marker", func(t *testing.T) {
		const marker = "marker-env-value"
		document := `{"apiVersion":"v1","kind":"PodList","env":{"TOKEN":"` + marker + `"},"items":[]}`
		result, err := a201Parse(t, document)
		a201Problem(t, err)
		if strings.Contains(err.Error(), marker) {
			t.Fatal("the prohibited value reached the error message")
		}
		a201NoPublication(t, result)
		for _, diagnostic := range result.Diagnostics {
			if strings.Contains(diagnostic.Error(), marker) {
				t.Fatal("the prohibited value reached a diagnostic")
			}
		}
	})
}

func TestA201HashOnlyAfterAdmission(t *testing.T) {
	// a201IndependentHash is the oracle: the SHA-256 of the exact bytes.
	a201IndependentHash := func(data string) string {
		sum := sha256.Sum256([]byte(data))
		return "sha256:" + hex.EncodeToString(sum[:])
	}

	t.Run("admitted source carries the complete hash", func(t *testing.T) {
		document := a201List(a201CompletePod("uid-1", "api", "sha256:aaaa"))
		result := a201MustParse(t, document)
		if result.Source == nil {
			t.Fatal("an admitted source carries no source")
		}
		if string(result.Source.Hash) != a201IndependentHash(document) {
			t.Fatalf("hash = %s, want the SHA-256 of every original byte", result.Source.Hash)
		}
		if result.Source.ByteCount != uint64(len(document)) {
			t.Fatalf("byte count = %d, want %d", result.Source.ByteCount, len(document))
		}
		if result.Source.Name != "sanitized-pods.json" {
			t.Fatalf("source name = %q, want the logical alias", result.Source.Name)
		}
	})

	t.Run("the hash covers the trailing whitespace", func(t *testing.T) {
		document := a201List()
		padded := document + "\n\t  "
		plain := a201MustParse(t, document)
		spaced := a201MustParse(t, padded)
		if plain.Source.Hash == spaced.Source.Hash {
			t.Fatal("two sources with different bytes share a hash")
		}
		if string(spaced.Source.Hash) != a201IndependentHash(padded) {
			t.Fatal("the hash does not cover the trailing whitespace")
		}
	})

	t.Run("the hash is never a prefix", func(t *testing.T) {
		document := a201List(a201CompletePod("uid-1", "api", "sha256:aaaa"))
		result := a201MustParse(t, document)
		prefix := document[:len(document)-2]
		if string(result.Source.Hash) == a201IndependentHash(prefix) {
			t.Fatal("the published hash is the hash of a prefix")
		}
	})

	t.Run("a rejected source exposes no hash", func(t *testing.T) {
		rejected := []struct {
			name     string
			document string
		}{
			{name: "structural failure", document: `{"apiVersion":"v1","kind":"PodList","items":[`},
			{name: "allowlist failure", document: `{"apiVersion":"v1","kind":"PodList","items":[{"env":1}]}`},
			{name: "resource failure", document: a201List(`{"apiVersion":"apps/v1","kind":"Deployment"}`)},
			{name: "pagination failure", document: `{"apiVersion":"v1","kind":"PodList","metadata":{"continue":"t"},"items":[]}`},
			{name: "budget failure", document: `{"apiVersion":"v1","kind":"PodList","items":[{"apiVersion":"v1","kind":"Pod","metadata":{"uid":"u","namespace":"payments","name":"n"},"spec":{"containers":[{"name":"api","image":"` + strings.Repeat("x", 65535) + `"}]}}]}`},
		}
		for _, testCase := range rejected {
			t.Run(testCase.name, func(t *testing.T) {
				result, err := a201Parse(t, testCase.document)
				if err == nil {
					t.Fatal("the vector was admitted")
				}
				a201NoPublication(t, result)
			})
		}
	})
}
