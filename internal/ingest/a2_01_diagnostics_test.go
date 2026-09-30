package ingest

import (
	"errors"
	"strings"
	"testing"
	"time"

	contract "github.com/d4rpell/Ariadne/pkg/evidence"
)

// Exact diagnostic anchors of ADR-0025 A.10.1/A.10.2. Every expectation is the
// complete literal message of the contract, copied from the ADR rather than
// derived from the production tables, and the anchor is computed in the test
// over the original bytes before the parser is called.

// at returns the unique offset of one needle, so a vector states where its
// anchor is instead of trusting the scanner under test.
func at(t *testing.T, document, needle string) uint64 {
	t.Helper()
	index := strings.Index(document, needle)
	if index < 0 {
		t.Fatalf("the vector does not contain %q", needle)
	}
	if strings.Index(document[index+1:], needle) >= 0 {
		t.Fatalf("the vector contains %q more than once", needle)
	}
	return uint64(index)
}

// TestA201DiagnosticOffsets pins the seven literal vectors of A.12.1.
func TestA201DiagnosticOffsets(t *testing.T) {
	cases := []struct {
		name     string
		document string
		anchor   func(document string, test *testing.T) uint64
		message  string
	}{
		{
			name:     "duplicate key",
			document: `{"kind":"PodList","kind":"PodList"}`,
			anchor: func(document string, test *testing.T) uint64 {
				return uint64(strings.LastIndex(document, `"kind"`))
			},
			message: "duplicate JSON key",
		},
		{
			name:     "malformed escape",
			document: `{"kind":"\q"}`,
			anchor:   func(document string, test *testing.T) uint64 { return at(test, document, `\q`) },
			message:  "invalid JSON structure",
		},
		{
			name:     "lone high surrogate",
			document: `{"kind":"\uD800"}`,
			anchor:   func(document string, test *testing.T) uint64 { return at(test, document, `\uD800`) },
			message:  "invalid Unicode surrogate sequence",
		},
		{
			name:     "escaped NUL",
			document: `{"kind":"\u0000"}`,
			anchor:   func(document string, test *testing.T) uint64 { return at(test, document, `\u0000`) },
			message:  "NUL is not allowed",
		},
		{
			name:     "non-canonical number",
			document: `{"metadata":{"remainingItemCount":01}}`,
			anchor:   func(document string, test *testing.T) uint64 { return at(test, document, `01`) },
			message:  "non-canonical JSON number",
		},
		{
			name:     "truncated structure at EOF",
			document: `{"kind":`,
			anchor:   func(document string, test *testing.T) uint64 { return uint64(len(document)) },
			message:  "invalid JSON structure",
		},
		{
			name:     "field outside the redaction profile",
			document: `{"env": "\q"}`,
			anchor:   func(document string, test *testing.T) uint64 { return at(test, document, `"env"`) },
			message:  "field is not allowed by the redaction profile",
		},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			offset := testCase.anchor(testCase.document, t)
			_, err := a201Parse(t, testCase.document)
			if err == nil {
				t.Fatalf("document %q was admitted, want %s", testCase.document, testCase.message)
			}
			a201WantFailure(t, err, a201Literal(offset, testCase.message))
		})
	}

	t.Run("multibyte text before the failure counts bytes", func(t *testing.T) {
		// A three-byte character before the offending byte separates a byte
		// count from a character count: the anchor is where the bytes are.
		document := "{\"apiVersion\":\"v1\",\"kind\":\"\u00e9\u00e9\u00e9a\xffb\"}"
		_, err := a201Parse(t, document)
		a201WantFailure(t, err, a201Literal(at(t, document, "\xff"), "invalid UTF-8"))
	})
	t.Run("surrogate without its pair at EOF keeps the backslash", func(t *testing.T) {
		document := `{"kind":"\uD800`
		_, err := a201Parse(t, document)
		a201WantFailure(t, err, a201Literal(at(t, document, `\uD800`), "invalid Unicode surrogate sequence"))
	})
	t.Run("escape truncated at EOF anchors at the total", func(t *testing.T) {
		document := `{"kind":"\u00`
		_, err := a201Parse(t, document)
		a201WantFailure(t, err, a201Literal(uint64(len(document)), "invalid JSON structure"))
	})
	t.Run("duplicate uid anchors at every occurrence", func(t *testing.T) {
		pod := func(name string) string {
			return `{"apiVersion":"v1","kind":"Pod","metadata":{"uid":"uid-1","namespace":"payments","name":"` + name + `"},"spec":{}}`
		}
		document := a201List(pod("a"), pod("b"))
		first := uint64(strings.Index(document, `"uid-1"`))
		second := uint64(strings.LastIndex(document, `"uid-1"`))
		if first == second {
			t.Fatal("the vector needs two distinct occurrences")
		}
		result, err := a201Parse(t, document)
		if err != nil {
			t.Fatalf("ParseSanitizedPodList: %v", err)
		}
		if len(result.Rejections) != 2 {
			t.Fatalf("rejections = %d, want 2", len(result.Rejections))
		}
		if result.Rejections[0].Offset != first || result.Rejections[1].Offset != second {
			t.Fatalf("anchors = %d and %d, want %d and %d", result.Rejections[0].Offset, result.Rejections[1].Offset, first, second)
		}
		if got := result.Rejections[0].String(); got != a201Literal(first, "duplicate Pod UID") {
			t.Fatalf("first rejection = %q", got)
		}
	})
	t.Run("capture diagnostics anchor at the admitted root", func(t *testing.T) {
		context := a201ContextWith(func(context *PodListContext) { context.CaptureTermination = contract.TerminationAborted })
		result, err := a201ParseWith(t, a201List(), context)
		if err != nil {
			t.Fatalf("ParseSanitizedPodList: %v", err)
		}
		if len(result.Diagnostics) != 1 {
			t.Fatalf("diagnostics = %+v, want the aborted capture one", result.Diagnostics)
		}
		if got := result.Diagnostics[0].Error(); got != a201Literal(0, "export capture was aborted") {
			t.Fatalf("capture diagnostic = %q, want the literal message at the root", got)
		}
	})
}

// TestA201DiagnosticContextAnchors covers the anchors that do not belong to the
// JSON stream: every context failure is reported at offset zero.
func TestA201DiagnosticContextAnchors(t *testing.T) {
	cases := []struct {
		name    string
		context PodListContext
		message string
	}{
		{
			name:    "selector",
			context: a201ContextWith(func(context *PodListContext) { context.Selector = "" }),
			message: "unsupported input selector",
		},
		{
			name:    "version",
			context: a201ContextWith(func(context *PodListContext) { context.Version = "01.0" }),
			message: "unsupported input version",
		},
		{
			name:    "policy",
			context: a201ContextWith(func(context *PodListContext) { context.RedactionPolicy = "" }),
			message: "required redaction policy was not acknowledged",
		},
		{
			name:    "alias",
			context: a201ContextWith(func(context *PodListContext) { context.SourceName = ".." }),
			message: "invalid observation context",
		},
		{
			name:    "namespace",
			context: a201ContextWith(func(context *PodListContext) { context.Namespace = " payments" }),
			message: "invalid observation context",
		},
		{
			name:    "zero timestamp",
			context: a201ContextWith(func(context *PodListContext) { context.ObservedAt = time.Time{} }),
			message: "invalid observation context",
		},
		{
			name: "timestamp with an offset",
			context: a201ContextWith(func(context *PodListContext) {
				context.ObservedAt = time.Date(2026, 9, 30, 12, 0, 0, 0, time.FixedZone("CEST", 2*60*60))
			}),
			message: "invalid observation context",
		},
		{
			name: "termination outside the enum",
			context: a201ContextWith(func(context *PodListContext) {
				context.CaptureTermination = contract.CoverageTermination("partial")
			}),
			message: "invalid observation context",
		},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			result, err := a201ParseWith(t, a201List(), testCase.context)
			a201WantFailure(t, err, a201Literal(0, testCase.message))
			if result.Source != nil {
				t.Fatalf("a refused context produced a source")
			}
			if result.LocalAborted {
				t.Fatalf("a refused context never started a local read")
			}
		})
	}
}

// TestA201DiagnosticNilReader keeps the reader failure at offset zero and after
// the context, in the order the contract fixes.
func TestA201DiagnosticNilReader(t *testing.T) {
	if _, err := ParseSanitizedPodList(nil, a201Context()); err == nil {
		t.Fatal("a nil reader was admitted")
	} else {
		a201WantFailure(t, err, a201Literal(0, "nil reader"))
	}
	var typedNil *strings.Reader
	if _, err := ParseSanitizedPodList(typedNil, a201Context()); err == nil {
		t.Fatal("a typed nil reader was admitted")
	} else {
		a201WantFailure(t, err, a201Literal(0, "nil reader"))
	}
	refused := a201ContextWith(func(context *PodListContext) { context.Selector = "other" })
	if _, err := ParseSanitizedPodList(nil, refused); err == nil {
		t.Fatal("a refused context with a nil reader was admitted")
	} else {
		a201WantFailure(t, err, a201Literal(0, "unsupported input selector"))
	}
}

// TestA201DiagnosticCatalog reaches each code of A.10.2 through a scenario of
// its own stage; the expected message is the literal of the ADR copied here, not
// a lookup into the production table. Three codes have no reachable producer in
// this package and say so explicitly instead of pretending to be exercised:
// invalid_input (fallback for an unknown code), member_limit (the closed
// allowlist admits at most six distinct keys per object, so the seventh key is
// always a duplicate first) and invalid_projection (produced by the bundle DTO
// validation of A-21, outside ingest).
func TestA201DiagnosticCatalog(t *testing.T) {
	// fatal asserts the exact fatal failure of one scenario.
	fatal := func(t *testing.T, document string, anchor uint64, message string) {
		t.Helper()
		_, err := a201Parse(t, document)
		a201WantFailure(t, err, a201Literal(anchor, message))
	}
	// rejected asserts the single semantic rejection of one scenario.
	rejected := func(t *testing.T, document string, code PodListDiagnosticCode, anchor uint64, message string) {
		t.Helper()
		result, err := a201Parse(t, document)
		a201WantRejection(t, result, err, code, anchor, message)
	}
	// diagnostic asserts one subject or source diagnostic of one scenario.
	diagnostic := func(t *testing.T, result PodListResult, code PodListDiagnosticCode, anchor uint64, message string) {
		t.Helper()
		for _, candidate := range result.Diagnostics {
			if candidate.Code == code {
				if candidate.ByteOffset != anchor {
					t.Fatalf("diagnostic %s anchored at %d, want %d", code, candidate.ByteOffset, anchor)
				}
				if got := candidate.Error(); got != a201Literal(anchor, message) {
					t.Fatalf("diagnostic = %q, want %q", got, a201Literal(anchor, message))
				}
				return
			}
		}
		for _, subject := range result.Subjects {
			for _, candidate := range subject.Diagnostics {
				if candidate.Code == code {
					if candidate.ByteOffset != anchor {
						t.Fatalf("diagnostic %s anchored at %d, want %d", code, candidate.ByteOffset, anchor)
					}
					if got := candidate.Error(); got != a201Literal(anchor, message) {
						t.Fatalf("diagnostic = %q, want %q", got, a201Literal(anchor, message))
					}
					return
				}
			}
		}
		t.Fatalf("no %s diagnostic was produced", code)
	}

	t.Run("invalid_input", func(t *testing.T) {
		// Only the safe fallback produces this code: an unknown code renders as
		// invalid_input at zero and never prints its own content.
		unknown := PodListDiagnostic{Code: PodListDiagnosticCode("attacker"), ByteOffset: 99}
		if got := unknown.Error(); got != a201Literal(0, "invalid input") {
			t.Fatalf("fallback = %q, want the literal invalid_input message", got)
		}
	})
	t.Run("invalid_context", func(t *testing.T) {
		context := a201ContextWith(func(context *PodListContext) { context.Namespace = "pay\u0000ments" })
		_, err := a201ParseWith(t, a201List(), context)
		a201WantFailure(t, err, a201Literal(0, "invalid observation context"))
	})
	t.Run("unsupported_selector", func(t *testing.T) {
		context := a201ContextWith(func(context *PodListContext) { context.Selector = "other" })
		_, err := a201ParseWith(t, a201List(), context)
		a201WantFailure(t, err, a201Literal(0, "unsupported input selector"))
	})
	t.Run("unsupported_version", func(t *testing.T) {
		context := a201ContextWith(func(context *PodListContext) { context.Version = "2.0" })
		_, err := a201ParseWith(t, a201List(), context)
		a201WantFailure(t, err, a201Literal(0, "unsupported input version"))
	})
	t.Run("redaction_policy_required", func(t *testing.T) {
		context := a201ContextWith(func(context *PodListContext) { context.RedactionPolicy = "" })
		_, err := a201ParseWith(t, a201List(), context)
		a201WantFailure(t, err, a201Literal(0, "required redaction policy was not acknowledged"))
	})
	t.Run("nil_reader", func(t *testing.T) {
		_, err := ParseSanitizedPodList(nil, a201Context())
		a201WantFailure(t, err, a201Literal(0, "nil reader"))
	})
	t.Run("read_failed", func(t *testing.T) {
		reader := &a201ScriptedReader{steps: []a201Step{{data: []byte("abc"), err: errors.New("marker")}}}
		_, err := ParseSanitizedPodList(reader, a201Context())
		a201WantFailure(t, err, a201Literal(3, "input read failed"))
	})
	t.Run("file_limit", func(t *testing.T) {
		_, err := ParseSanitizedPodList(a201PaddedSource(a201List(), 67108865), a201Context())
		a201WantFailure(t, err, a201Literal(67108864, "file byte limit exceeded"))
	})
	t.Run("depth_limit", func(t *testing.T) {
		prefix := `{"apiVersion":"v1","kind":"PodList","items":`
		fatal(t, prefix+strings.Repeat("[", 16)+strings.Repeat("]", 16)+"}", uint64(len(prefix)+15), "JSON depth limit exceeded")
	})
	t.Run("token_limit", func(t *testing.T) {
		document := a201TokenDocument(9997, func(int) int { return 12 })
		_, offsets := a201CountTokens(document)
		if len(offsets) <= 2000000 {
			t.Fatalf("the vector counts %d tokens, want more than 2000000", len(offsets))
		}
		fatal(t, document, offsets[2000000], "JSON token limit exceeded")
	})
	t.Run("item_limit", func(t *testing.T) {
		element := `{"apiVersion":"v1","kind":"Pod"}`
		items := make([]string, 10001)
		for index := range items {
			items[index] = element
		}
		document := a201List(items...)
		_, offsets := a201CountTokens(document)
		fatal(t, document, offsets[12+10*10000], "Pod item limit exceeded")
	})
	t.Run("pod_limit", func(t *testing.T) {
		base := a201Pod("u1", "n1", "", "")
		pod := a201Pod("u1", "n1", strings.Repeat(" ", 1048577-len(base)), "")
		prefix := `{"apiVersion":"v1","kind":"PodList","items":[`
		fatal(t, a201List(pod), uint64(len(prefix)), "Pod byte limit exceeded")
	})
	t.Run("member_limit", func(t *testing.T) {
		// Unreachable through the closed profile: at most six distinct keys are
		// admitted per object, so a 33rd member is necessarily a repetition and
		// duplicate_key wins at its own second occurrence. The literal message is
		// pinned here, and the reachable precedence is asserted with it.
		if got := PodListMessage(PodListCodeMemberLimit); got != "object member limit exceeded" {
			t.Fatalf("member_limit message = %q", got)
		}
		repeated := make([]string, 0, 33)
		for index := 0; index < 33; index++ {
			repeated = append(repeated, `"name":"api"`)
		}
		document := a201List(`{"apiVersion":"v1","kind":"Pod","metadata":{"uid":"u","namespace":"payments","name":"n"},` +
			`"spec":{"containers":[{"name":"api"}]},"status":{"containerStatuses":[{` + strings.Join(repeated, ",") + `}]}}`)
		second := uint64(strings.Index(document, `"name":"api","name"`) + len(`"name":"api",`))
		fatal(t, document, second, "duplicate JSON key")
	})
	t.Run("string_limit", func(t *testing.T) {
		content := strings.Repeat("a", 65535)
		document := a201List(`{"apiVersion":"v1","kind":"Pod","metadata":{"uid":"u","namespace":"payments","name":"n"},` +
			`"spec":{"containers":[{"name":"api","image":"` + content + `"}]}}`)
		fatal(t, document, at(t, document, `"`+content+`"`), "string byte limit exceeded")
	})
	t.Run("key_limit", func(t *testing.T) {
		key := strings.Repeat("k", 129)
		document := `{"apiVersion":"v1","kind":"PodList","` + key + `":"v","items":[]}`
		fatal(t, document, uint64(strings.Index(document, `"`+key+`"`)), "key byte limit exceeded")
	})
	t.Run("collection_limit", func(t *testing.T) {
		document := a201List(a201EntryPod(0, 1025, false))
		start := uint64(strings.Index(document, `"containers":[`) + len(`"containers":[`))
		anchor := start + 3*1024
		if document[anchor:anchor+2] != "{}" {
			t.Fatalf("anchor %d does not hold the 1025th entry", anchor)
		}
		fatal(t, document, anchor, "collection limit exceeded")
	})
	t.Run("identifier_limit", func(t *testing.T) {
		name := strings.Repeat("a", 1025)
		document := a201List(a201CompletePod("u1", name, "sha256:deadbeef"))
		anchor := uint64(strings.Index(document, `"name":"`) + len(`"name":"`) - 1)
		result, err := a201Parse(t, document)
		a201WantRejection(t, result, err, PodListCodeIdentifierLimit, anchor, "identifier byte limit exceeded")
	})
	t.Run("bom", func(t *testing.T) {
		fatal(t, "\xEF\xBB\xBF"+a201List(), 0, "BOM is not allowed")
	})
	t.Run("invalid_utf8", func(t *testing.T) {
		document := "{\"apiVersion\":\"v1\",\"kind\":\"a\xff\xfeb\"}"
		fatal(t, document, at(t, document, "\xff\xfe"), "invalid UTF-8")
	})
	t.Run("nul", func(t *testing.T) {
		document := "{\"apiVersion\":\"v1\",\"kind\":\"a\x00b\"}"
		fatal(t, document, at(t, document, "\x00"), "NUL is not allowed")
	})
	t.Run("forbidden_text", func(t *testing.T) {
		document := "{\"apiVersion\":\"v1\",\"kind\":\"a\x01b\"}"
		fatal(t, document, at(t, document, "\x01"), "forbidden text character")
	})
	t.Run("invalid_json", func(t *testing.T) {
		document := `{"kind":`
		fatal(t, document, uint64(len(document)), "invalid JSON structure")
	})
	t.Run("invalid_surrogate", func(t *testing.T) {
		document := `{"kind":"\uD800"}`
		fatal(t, document, at(t, document, `\uD800`), "invalid Unicode surrogate sequence")
	})
	t.Run("duplicate_key", func(t *testing.T) {
		document := `{"kind":"PodList","kind":"PodList"}`
		fatal(t, document, uint64(strings.LastIndex(document, `"kind"`)), "duplicate JSON key")
	})
	t.Run("noncanonical_number", func(t *testing.T) {
		document := `{"metadata":{"remainingItemCount":01}}`
		fatal(t, document, at(t, document, "01"), "non-canonical JSON number")
	})
	t.Run("field_not_allowed", func(t *testing.T) {
		document := `{"env": "\q"}`
		fatal(t, document, at(t, document, `"env"`), "field is not allowed by the redaction profile")
	})
	t.Run("unsupported_resource", func(t *testing.T) {
		document := `{"apiVersion":"v1","kind":"Secret","items":[]}`
		fatal(t, document, at(t, document, `"Secret"`), "unsupported resource kind or API version")
	})
	t.Run("pagination_not_supported", func(t *testing.T) {
		document := `{"apiVersion":"v1","kind":"PodList","metadata":{"continue":"abc"},"items":[]}`
		fatal(t, document, at(t, document, `"abc"`), "paginated export is not supported")
	})
	t.Run("missing_required_field", func(t *testing.T) {
		document := `{"kind":"PodList","items":[]}`
		fatal(t, document, 0, "required field is missing")
	})
	t.Run("invalid_field_type", func(t *testing.T) {
		document := `{"apiVersion":"v1","kind":"PodList","items":null}`
		fatal(t, document, at(t, document, "null"), "invalid field type")
	})
	t.Run("invalid_identifier", func(t *testing.T) {
		document := a201List(`{"apiVersion":"v1","kind":"Pod","metadata":{"uid":"","namespace":"payments","name":"n"},"spec":{}}`)
		anchor := uint64(strings.Index(document, `"uid":""`) + len(`"uid":`))
		rejected(t, document, PodListCodeInvalidIdentifier, anchor, "invalid identifier")
	})
	t.Run("invalid_field_value", func(t *testing.T) {
		document := a201List(a201Pod("u1", "n1",
			`{"name":"api","image":"registry.example/app:release"}`,
			`{"name":"api","restartCount":2147483648}`))
		anchor := uint64(strings.Index(document, ":2147483648") + 1)
		rejected(t, document, PodListCodeInvalidFieldValue, anchor, "invalid field value")
	})
	t.Run("namespace_mismatch", func(t *testing.T) {
		document := a201List(`{"apiVersion":"v1","kind":"Pod","metadata":{"uid":"u","namespace":"other","name":"n"},"spec":{}}`)
		rejected(t, document, PodListCodeNamespaceMismatch, at(t, document, `"other"`), "Pod namespace is outside the declared scope")
	})
	t.Run("duplicate_uid", func(t *testing.T) {
		pod := func(name string) string {
			return `{"apiVersion":"v1","kind":"Pod","metadata":{"uid":"uid-1","namespace":"payments","name":"` + name + `"},"spec":{}}`
		}
		document := a201List(pod("a"), pod("b"))
		result, err := a201Parse(t, document)
		if err != nil {
			t.Fatalf("ParseSanitizedPodList: %v", err)
		}
		if len(result.Rejections) != 2 {
			t.Fatalf("rejections = %d, want 2", len(result.Rejections))
		}
		for index, rejection := range result.Rejections {
			want := uint64(strings.Index(document, `"uid-1"`))
			if index == 1 {
				want = uint64(strings.LastIndex(document, `"uid-1"`))
			}
			if rejection.Code != PodListCodeDuplicateUID || rejection.Offset != want {
				t.Fatalf("rejection %d = %s at %d, want duplicate_uid at the occurrence", index, rejection.Code, rejection.Offset)
			}
			if got := rejection.String(); got != a201Literal(want, "duplicate Pod UID") {
				t.Fatalf("rejection = %q, want the literal message", got)
			}
		}
	})
	t.Run("duplicate_container", func(t *testing.T) {
		document := a201List(`{"apiVersion":"v1","kind":"Pod","metadata":{"uid":"u","namespace":"payments","name":"n"},` +
			`"spec":{"containers":[{"name":"api"},{"name":"api"}]}}`)
		repeated := uint64(strings.LastIndex(document, `"name":`) + len(`"name":`))
		rejected(t, document, PodListCodeDuplicateContainer, repeated, "duplicate container name within a category")
	})
	t.Run("duplicate_status", func(t *testing.T) {
		document := a201List(`{"apiVersion":"v1","kind":"Pod","metadata":{"uid":"u","namespace":"payments","name":"n"},` +
			`"spec":{"containers":[{"name":"api"}]},` +
			`"status":{"containerStatuses":[{"name":"api"},{"name":"api"}]}}`)
		repeated := uint64(strings.LastIndex(document, `"name":`) + len(`"name":`))
		rejected(t, document, PodListCodeDuplicateStatus, repeated, "duplicate container status name")
	})
	t.Run("orphan_status", func(t *testing.T) {
		document := a201List(`{"apiVersion":"v1","kind":"Pod","metadata":{"uid":"u","namespace":"payments","name":"n"},` +
			`"spec":{"containers":[{"name":"api"}]},` +
			`"status":{"containerStatuses":[{"name":"sidecar"}]}}`)
		rejected(t, document, PodListCodeOrphanStatus, at(t, document, `"sidecar"`), "container status has no matching declaration")
	})
	t.Run("invalid_state", func(t *testing.T) {
		document := a201List(`{"apiVersion":"v1","kind":"Pod","metadata":{"uid":"u","namespace":"payments","name":"n"},` +
			`"spec":{"containers":[{"name":"api"}]},` +
			`"status":{"containerStatuses":[{"name":"api","state":{"waiting":{},"running":{}}}]}}`)
		rejected(t, document, PodListCodeInvalidState, at(t, document, `"running"`), "container state is ambiguous")
	})
	t.Run("category_unobserved", func(t *testing.T) {
		document := a201List(`{"apiVersion":"v1","kind":"Pod","metadata":{"uid":"u","namespace":"payments","name":"n"},"spec":{}}`)
		result := a201MustParse(t, document)
		anchor := uint64(strings.Index(document, `"spec":{`) + len(`"spec":`))
		diagnostic(t, result, PodListCodeCategoryUnobserved, anchor, "container category was not observed")
	})
	t.Run("status_unobserved", func(t *testing.T) {
		// The absent status anchors at the Pod object; the missing array at the
		// status object; the missing association at its own status array. The
		// other two variants are pinned by TestA201CategoryPresence.
		document := a201List(`{"apiVersion":"v1","kind":"Pod","metadata":{"uid":"u","namespace":"payments","name":"n"},` +
			`"spec":{"containers":[{"name":"api"},{"name":"worker"}]},` +
			`"status":{"containerStatuses":[{"name":"api"}]}}`)
		result := a201MustParse(t, document)
		diagnostic(t, result, PodListCodeStatusUnobserved, at(t, document, `[{"name":"api"}]`), "container status coverage is incomplete")
	})
	t.Run("requested_image_unavailable", func(t *testing.T) {
		document := a201List(`{"apiVersion":"v1","kind":"Pod","metadata":{"uid":"u","namespace":"payments","name":"n"},` +
			`"spec":{"containers":[{"name":"api"}]}}`)
		result := a201MustParse(t, document)
		diagnostic(t, result, PodListCodeRequestedImageUnavailable, at(t, document, `{"name":"api"}`), "requested image was not provided")
	})
	t.Run("capture_aborted", func(t *testing.T) {
		context := a201ContextWith(func(context *PodListContext) { context.CaptureTermination = contract.TerminationAborted })
		result, err := a201ParseWith(t, a201List(), context)
		if err != nil {
			t.Fatalf("ParseSanitizedPodList: %v", err)
		}
		diagnostic(t, result, PodListCodeCaptureAborted, 0, "export capture was aborted")
	})
	t.Run("capture_unknown", func(t *testing.T) {
		context := a201ContextWith(func(context *PodListContext) { context.CaptureTermination = contract.TerminationUnknown })
		result, err := a201ParseWith(t, a201List(), context)
		if err != nil {
			t.Fatalf("ParseSanitizedPodList: %v", err)
		}
		diagnostic(t, result, PodListCodeCaptureUnknown, 0, "export capture termination is unknown")
	})
	t.Run("source_items_rejected", func(t *testing.T) {
		document := a201List(a201CompletePod("uid-1", "api", "sha256:a"),
			`{"apiVersion":"v1","kind":"Pod","metadata":{"uid":"","namespace":"payments","name":"b"},"spec":{}}`)
		result := a201MustParse(t, document)
		diagnostic(t, result, PodListCodeSourceItemsRejected, at(t, document, `[{"apiVersion"`), "source contains rejected Pod items")
	})
	t.Run("subject_context_conflict", func(t *testing.T) {
		document := a201List(
			a201CompletePod("uid-a", "api", "sha256:a"),
			a201CompletePod("uid-b", "api", "sha256:b"),
		)
		result := a201MustParse(t, document)
		needle := `"payments","name":`
		for index := range result.Subjects {
			want := uint64(strings.Index(document, needle) + len(needle))
			if index == 1 {
				want = uint64(strings.LastIndex(document, needle) + len(needle))
			}
			found := false
			for _, candidate := range result.Subjects[index].Diagnostics {
				if candidate.Code == PodListCodeSubjectContextConflict {
					found = true
					if candidate.ByteOffset != want {
						t.Fatalf("conflict %d anchored at %d, want %d", index, candidate.ByteOffset, want)
					}
					if got := candidate.Error(); got != a201Literal(want, "source contains conflicting Pod identity context") {
						t.Fatalf("conflict = %q, want the literal message", got)
					}
				}
			}
			if !found {
				t.Fatalf("subject %d carries no conflict diagnostic", index)
			}
		}
	})
	t.Run("invalid_projection", func(t *testing.T) {
		// The code is emitted by the bundle DTO validation of A-21, not by the
		// ingest stage; the literal message is pinned here so the catalog stays
		// complete and the writer of that stage inherits the exact text.
		diagnosticLiteral := PodListDiagnostic{Code: PodListCodeInvalidProjection}.Error()
		if diagnosticLiteral != a201Literal(0, "observation cannot be projected consistently") {
			t.Fatalf("invalid_projection = %q, want the literal message at zero", diagnosticLiteral)
		}
	})
}

// TestA201DiagnosticFallback keeps an unknown code out of the output: it is
// formatted as invalid_input at offset zero and never prints its own content.
func TestA201DiagnosticFallback(t *testing.T) {
	unknown := PodListDiagnostic{Code: PodListDiagnosticCode("attacker_controlled"), ByteOffset: 4242}
	if got := unknown.Error(); got != a201Literal(0, "invalid input") {
		t.Fatalf("unknown code rendered as %q, want the invalid_input fallback at zero", got)
	}
	if got := PodListMessage(PodListDiagnosticCode("attacker_controlled")); got != "invalid input" {
		t.Fatalf("unknown code message = %q, want the invalid_input fallback", got)
	}
	if child := (&PodListError{}); child.Error() != a201Literal(0, "invalid input") {
		t.Fatalf("empty diagnostic rendered as %q", child.Error())
	}
}

// TestA201DiagnosticPrecedence covers the ordering rules of A.10.3 that the
// per-stage tests cannot express: a stage boundary, the first detectable failure
// instead of the smallest anchor, and the key phase order. The remaining rules
// are covered by the tests that own their stage and are named there:
// budget order (member before duplicate, key before duplicate) in
// TestA201DuplicateKeys, the value-before-exam rules in
// TestA201RejectBeforeValueDecode, and the number grammar before the range in
// TestA201Numbers.
func TestA201DiagnosticPrecedence(t *testing.T) {
	t.Run("context before reader", func(t *testing.T) {
		context := a201ContextWith(func(context *PodListContext) { context.Version = "9.9" })
		if _, err := ParseSanitizedPodList(nil, context); err == nil {
			t.Fatal("a nil reader was examined before the context")
		} else {
			a201WantFailure(t, err, a201Literal(0, "unsupported input version"))
		}
	})
	t.Run("read error before invalid JSON", func(t *testing.T) {
		// The bytes scanned so far are an invalid document, but the acquisition
		// never completed: the read failure is the one that is reported.
		reader := &a201ScriptedReader{steps: []a201Step{{data: []byte(`{"apiVersion":`)}, {err: errors.New("marker")}}}
		result, err := ParseSanitizedPodList(reader, a201Context())
		a201WantFailure(t, err, a201Literal(uint64(len(`{"apiVersion":`)), "input read failed"))
		a201NoPublication(t, result)
	})
	t.Run("first detectable failure wins over a smaller anchor", func(t *testing.T) {
		// The prohibited key is far to the right of the Pod identity defect, and
		// it is still the failure that is reported: the walk stops at the first
		// structural failure and never looks for a smaller anchor.
		document := `{"apiVersion":"v1","kind":"PodList","items":[` +
			`{"apiVersion":"v1","kind":"Pod","metadata":{"uid":"","namespace":"payments","name":"n"},"spec":{}},` +
			a201CompletePod("uid-2", "api", "sha256:a") + `],"env":1}`
		_, err := a201Parse(t, document)
		a201WantFailure(t, err, a201Literal(at(t, document, `"env"`), "field is not allowed by the redaction profile"))
	})
	t.Run("a structural failure inside a Pod outranks its semantic defect", func(t *testing.T) {
		document := a201List(`{"apiVersion":"v1","kind":"Pod","metadata":{"namespace":"payments","name":"n"},` +
			`"spec":{"containers":[{"name":"api","env":[]}]}}`)
		_, err := a201Parse(t, document)
		a201WantFailure(t, err, a201Literal(at(t, document, `"env"`), "field is not allowed by the redaction profile"))
	})
	t.Run("prohibited text outranks the identifier budget", func(t *testing.T) {
		// 1030 bytes of name: the identifier budget would reject it, but the
		// control character is detected in the structural examination first.
		name := strings.Repeat("n", 1030) + "\u0001"
		document := a201List(`{"apiVersion":"v1","kind":"Pod","metadata":{"uid":"u","namespace":"payments","name":"` + name + `"},"spec":{}}`)
		_, err := a201Parse(t, document)
		a201WantFailure(t, err, a201Literal(at(t, document, "\u0001"), "forbidden text character"))
	})
	t.Run("duplicate key before the allowlist", func(t *testing.T) {
		// A duplicated admitted key is resolved before its value is examined.
		document := `{"apiVersion":"v1","kind":"PodList","kind":"List","items":[]}`
		_, err := a201Parse(t, document)
		a201WantFailure(t, err, a201Literal(uint64(strings.LastIndex(document, `"kind"`)), "duplicate JSON key"))
	})
	t.Run("the first occurrence of a prohibited key is refused before the second", func(t *testing.T) {
		// The allowlist rejects the first occurrence, so the duplicate pair is
		// never reached: A.10.3 §6 applies per key occurrence.
		document := `{"apiVersion":"v1","kind":"PodList","env":1,"env":2,"items":[]}`
		_, err := a201Parse(t, document)
		a201WantFailure(t, err, a201Literal(uint64(strings.Index(document, `"env"`)), "field is not allowed by the redaction profile"))
	})
	t.Run("rejections keep the item order and their own field order", func(t *testing.T) {
		document := a201List(
			// First item: the category is null, a spec defect.
			`{"apiVersion":"v1","kind":"Pod","metadata":{"uid":"uid-1","namespace":"payments","name":"a"},"spec":{"containers":null}}`,
			// Second item: the namespace is outside the scope, an identity defect.
			`{"apiVersion":"v1","kind":"Pod","metadata":{"uid":"uid-2","namespace":"other","name":"b"},"spec":{}}`,
		)
		result := a201MustParse(t, document)
		if len(result.Rejections) != 2 {
			t.Fatalf("rejections = %d, want 2", len(result.Rejections))
		}
		if result.Rejections[0].Code != PodListCodeInvalidFieldType || result.Rejections[0].ItemIndex != 0 {
			t.Fatalf("first rejection = %+v, want the category defect of item 0", result.Rejections[0])
		}
		if result.Rejections[1].Code != PodListCodeNamespaceMismatch || result.Rejections[1].ItemIndex != 1 {
			t.Fatalf("second rejection = %+v, want the namespace defect of item 1", result.Rejections[1])
		}
	})
	t.Run("identity outranks categories inside one Pod", func(t *testing.T) {
		document := a201List(`{"apiVersion":"v1","kind":"Pod","metadata":{"uid":"u","name":"n","namespace":"payments"},` +
			`"spec":{"containers":null}}`)
		// The identity is complete and correct, so the category defect is the one
		// reported; permuting the two would report the namespace instead.
		result := a201MustParse(t, document)
		if result.Rejections[0].Code != PodListCodeInvalidFieldType {
			t.Fatalf("code = %s, want the category defect", result.Rejections[0].Code)
		}
		document = a201List(`{"apiVersion":"v1","kind":"Pod","metadata":{"uid":"u","name":"","namespace":"payments"},` +
			`"spec":{"containers":null}}`)
		result = a201MustParse(t, document)
		if result.Rejections[0].Code != PodListCodeInvalidIdentifier {
			t.Fatalf("code = %s, want the identity defect to come first", result.Rejections[0].Code)
		}
	})
	t.Run("an incomplete source keeps its diagnostics", func(t *testing.T) {
		context := a201ContextWith(func(context *PodListContext) { context.CaptureTermination = contract.TerminationUnknown })
		result, err := a201ParseWith(t, a201List(a201CompletePod("uid-1", "api", "sha256:a")), context)
		if err != nil {
			t.Fatalf("ParseSanitizedPodList: %v", err)
		}
		found := false
		for _, diagnostic := range result.Diagnostics {
			if diagnostic.Code == PodListCodeCaptureUnknown {
				found = true
				if diagnostic.ByteOffset != 0 {
					t.Fatalf("capture anchor = %d, want the root of the admitted source", diagnostic.ByteOffset)
				}
			}
		}
		if !found {
			t.Fatal("an unknown termination produced no visible diagnostic")
		}
	})
	t.Run("rejected items stay visible at the source level", func(t *testing.T) {
		document := a201List(a201CompletePod("uid-1", "api", "sha256:a"), `{"apiVersion":"v1","kind":"Pod","metadata":{"uid":"","namespace":"payments","name":"b"},"spec":{}}`)
		result := a201MustParse(t, document)
		found := false
		for _, diagnostic := range result.Diagnostics {
			if diagnostic.Code == PodListCodeSourceItemsRejected {
				found = true
				if diagnostic.ByteOffset != at(t, document, `[{"apiVersion"`) {
					t.Fatalf("rejection anchor = %d, want the items array", diagnostic.ByteOffset)
				}
			}
		}
		if !found {
			t.Fatal("a rejected item was not visible at the source level")
		}
	})
}
