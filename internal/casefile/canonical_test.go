package casefile

import (
	"bytes"
	"strings"
	"testing"
)

func TestCanonicalStringsAndOptionalValues(t *testing.T) {
	quote := "quote \" backslash \\ newline \n tab \t end"
	input := validInput()
	input.Rationale = quote
	book := mustAppend(t, NewBook(), input)
	document := mustEncode(t, book)

	for _, spelling := range []string{`\"`, `\\`, `\n`, `\t`} {
		if !bytes.Contains(document, []byte(spelling)) {
			t.Fatalf("escape %q missing from the canonical document", spelling)
		}
	}
	for _, forbidden := range []string{`\u0022`, `\u005c`, `\n ` + `"`, `\\\\"`} {
		if bytes.Contains(document, []byte(forbidden)) {
			t.Fatalf("alternative escape %q leaked into the document", forbidden)
		}
	}

	// Multibyte runes travel verbatim; the slash is never escaped.
	unicode := validInput()
	unicode.Owner = "dueño ñ テスト 𝄞"
	unicodeDocument := mustEncode(t, mustAppend(t, NewBook(), unicode))
	if !bytes.Contains(unicodeDocument, []byte("dueño ñ テスト 𝄞")) {
		t.Fatal("multibyte values were re-encoded")
	}

	// Absent optionals are literal nulls; a present empty string is invalid.
	absent := validInput()
	absent.Scope.ResultFingerprint = nil
	absent.ExpiresAt = nil
	absent.Supersedes = nil
	absentDocument := mustEncode(t, mustAppend(t, NewBook(), absent))
	for _, optional := range []string{`"result_fingerprint":null`, `"expires_at":null`, `"supersedes":null`, `"previous_hash":null`} {
		if !bytes.Contains(absentDocument, []byte(optional)) {
			t.Fatalf("missing %s in the document", optional)
		}
	}
	empty := validInput()
	value := ""
	empty.Scope.ResultFingerprint = &value
	if _, err := Append(NewBook(), empty); !IsCode(err, CodeInvalidReference) {
		t.Fatalf("an empty present optional was admitted: %v", err)
	}

	// The empty book and the nil/empty controls equivalence are byte-exact.
	if !bytes.Equal(mustEncode(t, NewBook()), []byte(emptyBookDocument)) {
		t.Fatal("the empty document drifted")
	}
	withNil := validInput()
	withNil.Controls = nil
	withEmpty := validInput()
	withEmpty.Controls = []string{}
	if !bytes.Contains(mustEncode(t, mustAppend(t, NewBook(), withNil)), []byte(`"controls":[]`)) {
		t.Fatal("nil controls did not serialize as []")
	}
	if !bytes.Equal(mustEncode(t, mustAppend(t, NewBook(), withNil)), mustEncode(t, mustAppend(t, NewBook(), withEmpty))) {
		t.Fatal("nil and empty controls are not equivalent on the wire")
	}

	// Keys are emitted in the fixed order, without omitempty: every key of
	// §4.2 appears even when its value is null.
	for _, key := range []string{
		`"format"`, `"version"`, `"sequence"`, `"previous_hash"`, `"risk_decision"`,
		`"owner"`, `"approver"`, `"rationale"`, `"scope"`, `"controls"`,
		`"decided_at"`, `"expires_at"`, `"supersedes"`, `"hash"`,
	} {
		if !bytes.Contains(document, []byte(key)) {
			t.Fatalf("key %s missing from the document", key)
		}
	}
	if !bytes.Contains(document, []byte(`"scope":{"bundle_hash":`)) {
		t.Fatal("the scope keys are not in the fixed order")
	}
	_ = strings.TrimSpace
}
