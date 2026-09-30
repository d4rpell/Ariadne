package ingest

import (
	"strings"
	"testing"
)

// Strict JSON structure, strings, duplicate keys and numbers (ADR-0025 A.3.2,
// A.3.4, A.4, A.10.1, A.10.3 §5–§6). Every rejection is compared as the complete
// literal diagnostic and every anchor is computed over the original bytes.

func TestA201JSONStructure(t *testing.T) {
	t.Run("valid object", func(t *testing.T) {
		if _, err := a201Parse(t, a201List()); err != nil {
			t.Fatalf("ParseSanitizedPodList: %v", err)
		}
	})
	t.Run("surrounding whitespace", func(t *testing.T) {
		if _, err := a201Parse(t, " \n\t"+a201List()+"\r\n "); err != nil {
			t.Fatalf("ParseSanitizedPodList: %v", err)
		}
	})
	t.Run("any key order", func(t *testing.T) {
		document := `{"items":[],"kind":"PodList","apiVersion":"v1"}`
		if _, err := a201Parse(t, document); err != nil {
			t.Fatalf("ParseSanitizedPodList: %v", err)
		}
	})
	t.Run("whitespace between tokens", func(t *testing.T) {
		document := `{ "apiVersion" : "v1" , "kind" : "PodList" , "items" : [ ] }`
		if _, err := a201Parse(t, document); err != nil {
			t.Fatalf("ParseSanitizedPodList: %v", err)
		}
	})
	t.Run("trailing data", func(t *testing.T) {
		document := a201List() + `{"kind":"PodList"}`
		_, err := a201Parse(t, document)
		a201WantFailure(t, err, a201Literal(uint64(len(a201List())), "invalid JSON structure"))
	})
	t.Run("comment", func(t *testing.T) {
		document := `{"apiVersion":"v1",/* note */"kind":"PodList","items":[]}`
		_, err := a201Parse(t, document)
		a201WantFailure(t, err, a201Literal(at(t, document, "/*"), "invalid JSON structure"))
	})
	t.Run("trailing comma", func(t *testing.T) {
		document := `{"apiVersion":"v1","kind":"PodList","items":[],}`
		_, err := a201Parse(t, document)
		a201WantFailure(t, err, a201Literal(at(t, document, "}"), "invalid JSON structure"))
	})
	t.Run("trailing comma in an array", func(t *testing.T) {
		document := `{"apiVersion":"v1","kind":"PodList","items":[{"apiVersion":"v1","kind":"Pod",}]}`
		_, err := a201Parse(t, document)
		a201WantFailure(t, err, a201Literal(at(t, document, "}]"), "invalid JSON structure"))
	})
	t.Run("scalar root", func(t *testing.T) {
		// A scalar root is valid JSON but a wrong-typed document for this profile:
		// the anchor is the start of the root value.
		result, err := a201Parse(t, "5")
		a201WantFailure(t, err, a201Literal(0, "invalid field type"))
		a201NoPublication(t, result)
	})
	t.Run("string root", func(t *testing.T) {
		_, err := a201Parse(t, `"PodList"`)
		a201WantFailure(t, err, a201Literal(0, "invalid field type"))
	})
	t.Run("array root", func(t *testing.T) {
		_, err := a201Parse(t, `[]`)
		a201WantFailure(t, err, a201Literal(0, "invalid field type"))
	})
	t.Run("empty document", func(t *testing.T) {
		_, err := a201Parse(t, "")
		a201WantFailure(t, err, a201Literal(0, "invalid JSON structure"))
	})
	t.Run("unterminated object", func(t *testing.T) {
		document := `{"apiVersion":"v1"`
		_, err := a201Parse(t, document)
		a201WantFailure(t, err, a201Literal(uint64(len(document)), "invalid JSON structure"))
	})
	t.Run("unterminated string", func(t *testing.T) {
		document := `{"apiVersion":"v1`
		_, err := a201Parse(t, document)
		a201WantFailure(t, err, a201Literal(uint64(len(document)), "invalid JSON structure"))
	})
	t.Run("missing colon", func(t *testing.T) {
		document := `{"apiVersion" "v1"}`
		_, err := a201Parse(t, document)
		a201WantFailure(t, err, a201Literal(at(t, document, `"v1"`), "invalid JSON structure"))
	})
	t.Run("vertical tab is not JSON whitespace", func(t *testing.T) {
		document := "{ \x0b" + a201List()[1:]
		_, err := a201Parse(t, document)
		a201WantFailure(t, err, a201Literal(at(t, document, "\x0b"), "invalid JSON structure"))
	})
}

func TestA201JSONText(t *testing.T) {
	// documentFor embeds one raw value inside a field that survives the structural
	// walk, so a lexical failure is the only possible rejection.
	documentFor := func(value string) string {
		return `{"apiVersion":"v1","kind":"PodList","metadata":{"resourceVersion":` + value + `},"items":[]}`
	}
	cases := []struct {
		name    string
		value   string
		message string
		anchor  string
	}{
		{name: "escaped NUL", value: `"\u0000"`, message: "NUL is not allowed", anchor: `\u0000`},
		{name: "escaped control", value: `"\u0001"`, message: "forbidden text character", anchor: `\u0001`},
		{name: "escaped DEL", value: `"\u007f"`, message: "forbidden text character", anchor: `\u007f`},
		{name: "escaped C1", value: `"\u0085"`, message: "forbidden text character", anchor: `\u0085`},
		{name: "escaped format character", value: `"\u200b"`, message: "forbidden text character", anchor: `\u200b`},
		{name: "escaped byte order mark", value: `"\ufeff"`, message: "forbidden text character", anchor: `\ufeff`},
		{name: "escaped newline", value: `"a\nb"`, message: "forbidden text character", anchor: `\n`},
		{name: "escaped tab", value: `"a\tb"`, message: "forbidden text character", anchor: `\t`},
		{name: "lone low surrogate", value: `"\uDC00"`, message: "invalid Unicode surrogate sequence", anchor: `\uDC00`},
		{name: "high surrogate then a plain escape", value: `"\uD800\u0041"`, message: "invalid Unicode surrogate sequence", anchor: `\uD800`},
		{name: "high surrogate at EOF", value: `"\uD800"`, message: "invalid Unicode surrogate sequence", anchor: `\uD800`},
		{name: "malformed escape", value: `"a\qb"`, message: "invalid JSON structure", anchor: `\q`},
		{name: "malformed escape without hex digits", value: `"a\uZZ"`, message: "invalid JSON structure", anchor: `\uZZ`},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			document := documentFor(testCase.value)
			_, err := a201Parse(t, document)
			a201WantFailure(t, err, a201Literal(at(t, document, testCase.anchor), testCase.message))
		})
	}

	t.Run("truncated escape at EOF", func(t *testing.T) {
		// The document ends inside the escape: the anchor is the total number of
		// bytes received, not the backslash.
		document := `{"apiVersion":"v1","kind":"PodList","metadata":{"resourceVersion":"a\u00`
		_, err := a201Parse(t, document)
		a201WantFailure(t, err, a201Literal(uint64(len(document)), "invalid JSON structure"))
	})
	t.Run("literal invalid UTF-8", func(t *testing.T) {
		document := documentFor("\"a\xffb\"")
		_, err := a201Parse(t, document)
		a201WantFailure(t, err, a201Literal(at(t, document, "\xff"), "invalid UTF-8"))
	})
	t.Run("truncated UTF-8 sequence", func(t *testing.T) {
		document := documentFor("\"a\xe2\x82\"")
		_, err := a201Parse(t, document)
		a201WantFailure(t, err, a201Literal(at(t, document, "\xe2\x82"), "invalid UTF-8"))
	})
	t.Run("truncated UTF-8 at EOF", func(t *testing.T) {
		document := `{"apiVersion":"v1","kind":"PodList","metadata":{"resourceVersion":"a` + "\xe2\x82"
		_, err := a201Parse(t, document)
		a201WantFailure(t, err, a201Literal(at(t, document, "\xe2\x82"), "invalid UTF-8"))
	})
	t.Run("literal NUL", func(t *testing.T) {
		document := documentFor("\"a\x00b\"")
		_, err := a201Parse(t, document)
		a201WantFailure(t, err, a201Literal(at(t, document, "\x00"), "NUL is not allowed"))
	})
	t.Run("literal control character", func(t *testing.T) {
		document := documentFor("\"a\x01b\"")
		_, err := a201Parse(t, document)
		a201WantFailure(t, err, a201Literal(at(t, document, "\x01"), "forbidden text character"))
	})
	t.Run("literal DEL", func(t *testing.T) {
		document := documentFor("\"a\x7fb\"")
		_, err := a201Parse(t, document)
		a201WantFailure(t, err, a201Literal(at(t, document, "\x7f"), "forbidden text character"))
	})
	t.Run("literal format character", func(t *testing.T) {
		document := documentFor("\"a\u200bb\"")
		_, err := a201Parse(t, document)
		a201WantFailure(t, err, a201Literal(at(t, document, "\u200b"), "forbidden text character"))
	})

	t.Run("legitimate replacement character", func(t *testing.T) {
		document := documentFor("\"\uFFFDb\"")
		if _, err := a201Parse(t, document); err != nil {
			t.Fatalf("a legitimate U+FFFD was refused: %v", err)
		}
	})
	t.Run("valid surrogate pair", func(t *testing.T) {
		document := documentFor(`"\uD83D\uDCA9"`)
		result, err := a201Parse(t, document)
		if err != nil {
			t.Fatalf("a valid surrogate pair was refused: %v", err)
		}
		if result.Rejected != 0 {
			t.Fatalf("rejected items = %d, want 0", result.Rejected)
		}
	})
	t.Run("supplementary character", func(t *testing.T) {
		if _, err := a201Parse(t, documentFor("\"\U0001F4A9\"")); err != nil {
			t.Fatalf("a supplementary character was refused: %v", err)
		}
	})
	t.Run("escaped and literal forms are different bytes but both admitted", func(t *testing.T) {
		if _, err := a201Parse(t, documentFor(`"\u0061"`)); err != nil {
			t.Fatalf("an escape-equivalent value was refused: %v", err)
		}
	})
	t.Run("value exactly at the raw budget", func(t *testing.T) {
		// image is a reference, not a contextual identifier: only the raw string
		// budget applies to it.
		content := strings.Repeat("a", 65534)
		document := a201List(`{"apiVersion":"v1","kind":"Pod","metadata":{"uid":"u","namespace":"payments","name":"n"},` +
			`"spec":{"containers":[{"name":"api","image":"` + content + `"}]}}`)
		if _, err := a201Parse(t, document); err != nil {
			t.Fatalf("a value at the raw string budget was refused: %v", err)
		}
	})
	t.Run("value above the raw budget", func(t *testing.T) {
		content := strings.Repeat("a", 65535)
		document := a201List(`{"apiVersion":"v1","kind":"Pod","metadata":{"uid":"u","namespace":"payments","name":"n"},` +
			`"spec":{"containers":[{"name":"api","image":"` + content + `"}]}}`)
		_, err := a201Parse(t, document)
		a201WantFailure(t, err, a201Literal(at(t, document, `"`+content+`"`), "string byte limit exceeded"))
	})
	t.Run("key at the raw budget", func(t *testing.T) {
		// Two plain bytes and 42 escapes: 254 raw content bytes (a 256-byte raw
		// token, exactly at the budget) decoding to 44 bytes, inside the decoded
		// budget, so the allowlist is what rejects the key.
		key := "ab" + strings.Repeat(`\u0061`, 42)
		document := `{"apiVersion":"v1","kind":"PodList",` + `"` + key + `":0}`
		if len(key) != 254 {
			t.Fatalf("the vector must be a 254-byte raw content, got %d", len(key))
		}
		_, err := a201Parse(t, document)
		a201WantFailure(t, err, a201Literal(at(t, document, `"`+key+`"`), "field is not allowed by the redaction profile"))
	})
	t.Run("key above the raw budget", func(t *testing.T) {
		key := strings.Repeat("k", 255)
		document := `{"apiVersion":"v1","kind":"PodList",` + `"` + key + `":0}`
		_, err := a201Parse(t, document)
		a201WantFailure(t, err, a201Literal(uint64(strings.Index(document, `"`+key+`"`)), "key byte limit exceeded"))
	})
	t.Run("key above the decoded budget through escapes", func(t *testing.T) {
		// 123 plain bytes plus 6 escapes: 159 raw content bytes inside the raw
		// budget, decoding to 129 bytes, one above the decoded budget.
		key := strings.Repeat("k", 123) + strings.Repeat(`\u006b`, 6)
		document := `{"apiVersion":"v1","kind":"PodList",` + `"` + key + `":0}`
		if len(key) > 254 {
			t.Fatalf("the vector must stay inside the raw budget, got %d bytes", len(key))
		}
		_, err := a201Parse(t, document)
		a201WantFailure(t, err, a201Literal(at(t, document, `"`+key+`"`), "key byte limit exceeded"))
	})
}

func TestA201DuplicateKeys(t *testing.T) {
	t.Run("identical keys at the root", func(t *testing.T) {
		document := `{"apiVersion":"v1","kind":"PodList","kind":"PodList","items":[]}`
		_, err := a201Parse(t, document)
		a201WantFailure(t, err, a201Literal(uint64(strings.LastIndex(document, `"kind"`)), "duplicate JSON key"))
	})
	t.Run("escape-equivalent keys at the root", func(t *testing.T) {
		document := `{"apiVersion":"v1","ap\u0069Version":"v1","kind":"PodList","items":[]}`
		_, err := a201Parse(t, document)
		a201WantFailure(t, err, a201Literal(at(t, document, `"ap\u0069Version"`), "duplicate JSON key"))
	})
	t.Run("nested level", func(t *testing.T) {
		document := a201List(a201Pod("uid-1", "api", `{"name":"api"}`, `{"name":"api"}`))
		document = strings.Replace(document, `"uid":"uid-1"`, `"uid":"uid-1","u\u0069d":"uid-2"`, 1)
		_, err := a201Parse(t, document)
		a201WantFailure(t, err, a201Literal(at(t, document, `"u\u0069d"`), "duplicate JSON key"))
	})
	t.Run("the value of a duplicate key is never examined", func(t *testing.T) {
		document := `{"apiVersion":"v1","kind":"PodList","metadata":{"resourceVersion":"x","resourceVersion":"\q"},"items":[]}`
		_, err := a201Parse(t, document)
		a201WantFailure(t, err, a201Literal(uint64(strings.LastIndex(document, `"resourceVersion"`)), "duplicate JSON key"))
	})
	t.Run("six distinct allowed keys are admitted", func(t *testing.T) {
		document := a201List(`{"apiVersion":"v1","kind":"Pod","metadata":{"uid":"u","namespace":"payments","name":"n"},` +
			`"spec":{"containers":[{"name":"api"}]},` +
			`"status":{"containerStatuses":[{"name":"api","imageID":"sha256:x","image":"y","ready":true,"state":{},"restartCount":3}]}}`)
		if _, err := a201Parse(t, document); err != nil {
			t.Fatalf("the full container status shape was refused: %v", err)
		}
	})
	t.Run("an oversized key is refused before its duplicate", func(t *testing.T) {
		// The key exceeds its raw budget and would also repeat an earlier one.
		key := strings.Repeat("k", 255)
		document := `{"apiVersion":"v1","kind":"PodList","` + key + `":0,"` + key + `":0}`
		_, err := a201Parse(t, document)
		a201WantFailure(t, err, a201Literal(uint64(strings.Index(document, `"`+key+`"`)), "key byte limit exceeded"))
	})
	t.Run("the 33rd member is refused before its duplicate", func(t *testing.T) {
		member := `"name":"api",`
		members := strings.TrimSuffix(strings.Repeat(member, 33), ",")
		document := `{"apiVersion":"v1","kind":"PodList","items":[{"apiVersion":"v1","kind":"Pod",` +
			`"metadata":{"uid":"u","namespace":"payments","name":"n"},` +
			`"spec":{"containers":[{` + members + `}]}}]}`
		// The member budget is checked at the 33rd key, but the allowlist admits at
		// most six distinct keys per object and the duplicate resolution precedes
		// the allowlist: the seventh occurrence is already a duplicate, so
		// member_limit stays unreachable through this profile (ADR-0025 A.4).
		second := uint64(strings.Index(document, member) + len(member))
		_, err := a201Parse(t, document)
		a201WantFailure(t, err, a201Literal(second, "duplicate JSON key"))
	})
}

func TestA201Numbers(t *testing.T) {
	documentFor := func(value string) string {
		return `{"apiVersion":"v1","kind":"PodList","metadata":{"remainingItemCount":` + value + `},"items":[]}`
	}
	t.Run("canonical zero", func(t *testing.T) {
		if _, err := a201Parse(t, documentFor("0")); err != nil {
			t.Fatalf("the only admitted remainder was refused: %v", err)
		}
	})
	canonical := []struct{ name, value string }{
		{name: "small", value: "7"},
		{name: "large", value: strings.Repeat("9", 30)},
	}
	for _, testCase := range canonical {
		t.Run("canonical "+testCase.name, func(t *testing.T) {
			document := documentFor(testCase.value)
			_, err := a201Parse(t, document)
			// remainingItemCount must be exactly 0: every other canonical integer
			// is a pagination rejection, never a number failure.
			a201WantFailure(t, err, a201Literal(at(t, document, testCase.value), "paginated export is not supported"))
		})
	}
	nonCanonical := []struct{ name, value string }{
		{name: "leading zero", value: "01"},
		{name: "double zero", value: "00"},
		{name: "negative zero", value: "-0"},
		{name: "plus sign", value: "+1"},
		{name: "negative", value: "-1"},
		{name: "fraction", value: "1.0"},
		{name: "exponent", value: "1e0"},
		{name: "fraction and exponent", value: "1.5e3"},
	}
	for _, testCase := range nonCanonical {
		t.Run("non-canonical "+testCase.name, func(t *testing.T) {
			document := documentFor(testCase.value)
			_, err := a201Parse(t, document)
			a201WantFailure(t, err, a201Literal(at(t, document, testCase.value), "non-canonical JSON number"))
		})
	}
	t.Run("numeric string is a type error", func(t *testing.T) {
		document := `{"apiVersion":"v1","kind":"PodList","metadata":{"remainingItemCount":"0"},"items":[]}`
		_, err := a201Parse(t, document)
		a201WantFailure(t, err, a201Literal(at(t, document, `"0"`), "invalid field type"))
	})
	t.Run("restartCount range is checked after the grammar", func(t *testing.T) {
		document := a201List(a201Pod("uid-1", "api", `{"name":"api"}`, `{"name":"api","restartCount":2147483647}`))
		if _, err := a201Parse(t, document); err != nil {
			t.Fatalf("the maximum restartCount was refused: %v", err)
		}
		document = a201List(a201Pod("uid-1", "api", `{"name":"api"}`, `{"name":"api","restartCount":2147483648}`))
		result, err := a201Parse(t, document)
		if err != nil {
			t.Fatalf("ParseSanitizedPodList: %v", err)
		}
		if result.Accepted != 0 || result.Rejected != 1 {
			t.Fatalf("accounting = %d/%d, want 0/1", result.Accepted, result.Rejected)
		}
		if result.Rejections[0].Code != PodListCodeInvalidFieldValue {
			t.Fatalf("rejection code = %s, want invalid_field_value", result.Rejections[0].Code)
		}
		if result.Rejections[0].Offset != at(t, document, "2147483648") {
			t.Fatalf("rejection offset = %d, want the start of the value", result.Rejections[0].Offset)
		}
	})
	t.Run("non-canonical beats the range", func(t *testing.T) {
		document := a201List(a201Pod("uid-1", "api", `{"name":"api"}`, `{"name":"api","restartCount":007}`))
		_, err := a201Parse(t, document)
		a201WantFailure(t, err, a201Literal(at(t, document, "007"), "non-canonical JSON number"))
	})
}

// TestA201SurrogatePairClassification keeps the classification of a surrogate
// pair: a pair can express a format character outside the BMP, which this
// profile refuses exactly like a literal one.
func TestA201SurrogatePairClassification(t *testing.T) {
	documentFor := func(value string) string {
		return `{"apiVersion":"v1","kind":"PodList","metadata":{"resourceVersion":` + value + `},"items":[]}`
	}
	t.Run("pair expressing a format character", func(t *testing.T) {
		document := documentFor(`"\uDB40\uDC01"`)
		_, err := a201Parse(t, document)
		a201WantFailure(t, err, a201Literal(at(t, document, `\uDB40`), "forbidden text character"))
	})
	t.Run("literal formatting character outside the BMP", func(t *testing.T) {
		// U+E0001 is a language tag: format, refused. A supplementary character is
		// not forbidden for being outside the BMP, only for its category, so the
		// classification is what decides.
		literal := "\U000E0001"
		document := documentFor(`"` + literal + `"`)
		_, err := a201Parse(t, document)
		a201WantFailure(t, err, a201Literal(at(t, document, literal), "forbidden text character"))
	})
	t.Run("legitimate supplementary character is still admitted", func(t *testing.T) {
		document := documentFor(`"\uD83D\uDCA9"`)
		if _, err := a201Parse(t, document); err != nil {
			t.Fatalf("a legitimate supplementary character was refused: %v", err)
		}
	})
}

// TestA201BudgetBeforeLexical pins the order of A.10.3 §4 over the lexical
// checks: the raw budget is decided before a defective escape is classified, and
// it is decided at the closing brace of an empty object as well.
func TestA201BudgetBeforeLexical(t *testing.T) {
	t.Run("raw budget precedes a defective escape", func(t *testing.T) {
		// 65534 plain bytes plus an escaped NUL: the raw token is 65542 bytes, over
		// the 65536 budget, so the budget wins even though the escape decodes to a
		// forbidden character.
		content := strings.Repeat("a", 65534)
		document := a201List(`{"apiVersion":"v1","kind":"Pod","metadata":{"uid":"u","namespace":"payments","name":"n"},` +
			`"spec":{"containers":[{"name":"api","image":"` + content + `\u0000"}]}}`)
		_, err := a201Parse(t, document)
		a201WantFailure(t, err, a201Literal(at(t, document, `"`+content), "string byte limit exceeded"))
	})
	t.Run("pod budget precedes a missing field in an empty object", func(t *testing.T) {
		// The element is an empty object padded with whitespace to 1048577 bytes:
		// the Pod interval budget is decided before the missing identity.
		padding := strings.Repeat(" ", 1048575)
		document := `{"apiVersion":"v1","kind":"PodList","items":[{` + padding + `}]}`
		_, err := a201Parse(t, document)
		a201WantFailure(t, err, a201Literal(at(t, document, `[{`)+1, "Pod byte limit exceeded"))
	})
	t.Run("the same insertion inside the budget reports the missing field", func(t *testing.T) {
		padding := strings.Repeat(" ", 1048570)
		document := `{"apiVersion":"v1","kind":"PodList","items":[{` + padding + `}]}`
		_, err := a201Parse(t, document)
		// The Pod interval is inside its budget, so the document continues and the
		// element is refused for what it lacks: an element of items must declare its
		// own resource.
		a201WantFailure(t, err, a201Literal(at(t, document, `[{`)+1, "required field is missing"))
	})
}

// TestA201PodBudgetAcrossAFailedEscape pins the range the Pod budget is checked
// over when an escape is refused: the bytes the escape actually inspected, not
// the cursor of a successful read. The padding is whitespace between members, so
// no other budget is reached first, and the vector is verified before the parser
// runs: the byte that exceeds the Pod interval falls inside the escape.
func TestA201PodBudgetAcrossAFailedEscape(t *testing.T) {
	head := `{"apiVersion":"v1","kind":"PodList","items":[{"apiVersion":"v1","kind":"Pod",`
	tail := `"metadata":{"uid":"u","namespace":"payments","name":"n"},` +
		`"spec":{"containers":[{"name":"api","image":"\u0000"}]}}]}`
	probe := head + tail
	podStart := uint64(strings.Index(probe, `[{`)) + 1
	escapeStart := uint64(strings.Index(probe, `\u0000`))
	// The last byte of the six-byte escape lands one byte past the interval.
	padding := 1048576 - 5 - (int(escapeStart) - int(podStart))
	if padding < 0 {
		t.Fatalf("the vector does not fit: %d", padding)
	}
	document := head + strings.Repeat(" ", padding) + tail
	escape := uint64(strings.Index(document, `\u0000`))
	// The escape may start inside the interval: what matters is that its last byte
	// lands past it, which is what makes the Pod budget the first failure.
	if escape+5 <= podStart+1048575 {
		t.Fatalf("the escape does not cross the Pod budget: %d", escape)
	}
	_, err := a201Parse(t, document)
	a201WantFailure(t, err, a201Literal(podStart, "Pod byte limit exceeded"))
}
