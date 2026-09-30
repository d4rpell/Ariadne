package ingest

import (
	"errors"
	"io"
	"strings"
	"testing"
)

// Boundary tests of the hard budgets of ADR-0025 A.4 and A.12.2, the precedence
// table of A.10.3 and the no-progress rule of the acquisition stage. Every
// expectation is written from the contract: the literal message of A.10.2, the
// anchor of A.10.1 and the exact code, never a prefix and never a value read
// from the production tables. The boundaries cross the public API of the
// profile; the token oracle below is independent of the production counter.
//
// Passing one guard never means that the document satisfies the whole profile:
// each subtest states which guard was passed and, separately, the exact failure
// the profile still produces or the exact semantic rejection a Pod still
// carries.

// a201CountTokens is an independent oracle: it counts tokens exactly as the
// profile defines them (each brace, bracket, comma, colon, string and scalar is
// one token) and returns the offset of each token. It never calls the parser.
func a201CountTokens(document string) (count uint64, offsets []uint64) {
	offsets = make([]uint64, 0, len(document)/4+1)
	for index := 0; index < len(document); {
		switch document[index] {
		case ' ', '\t', '\n', '\r':
			index++
		case '{', '}', '[', ']', ',', ':':
			offsets = append(offsets, uint64(index))
			index++
		case '"':
			offsets = append(offsets, uint64(index))
			index++
			for index < len(document) {
				if document[index] == '\\' {
					index += 2
					continue
				}
				if document[index] == '"' {
					index++
					break
				}
				index++
			}
		default:
			offsets = append(offsets, uint64(index))
			for index < len(document) && !a201TokenBoundary(document[index]) {
				index++
			}
		}
	}
	return uint64(len(offsets)), offsets
}

// a201TokenBoundary reports whether a byte ends a scalar token.
func a201TokenBoundary(character byte) bool {
	switch character {
	case ' ', '\t', '\n', '\r', '{', '}', '[', ']', ',', ':', '"':
		return true
	}
	return false
}

// a201SpaceReader emits JSON whitespace without materializing a buffer, so the
// 64 MiB boundary documents never need a second copy of themselves.
type a201SpaceReader struct{ remaining int64 }

func (r *a201SpaceReader) Read(p []byte) (int, error) {
	if r.remaining <= 0 {
		return 0, io.EOF
	}
	count := int64(len(p))
	if count > r.remaining {
		count = r.remaining
	}
	for index := int64(0); index < count; index++ {
		p[index] = ' '
	}
	r.remaining -= count
	return int(count), nil
}

// a201PaddedSource returns a reader over prefix followed by JSON whitespace up
// to exactly total bytes. At most one byte beyond the 64 MiB budget is ever
// produced for the oversized case.
func a201PaddedSource(prefix string, total int) io.Reader {
	padding := total - len(prefix)
	if padding < 0 {
		panic("a201PaddedSource: total is shorter than the prefix")
	}
	return io.MultiReader(
		strings.NewReader(prefix),
		io.LimitReader(&a201SpaceReader{remaining: int64(padding)}, int64(padding)),
	)
}

// a201SpaceTailErrorReader delivers a fixed number of whitespace bytes and then
// exactly one further byte together with error. It is used to prove that the
// source budget wins over the failure of the same read without exposing the
// original error text.
type a201SpaceTailErrorReader struct {
	remaining int64
	err       error
}

func (r *a201SpaceTailErrorReader) Read(p []byte) (int, error) {
	if r.remaining > 0 {
		count := int64(len(p))
		if count > r.remaining {
			count = r.remaining
		}
		for index := int64(0); index < count; index++ {
			p[index] = ' '
		}
		r.remaining -= count
		return int(count), nil
	}
	if r.err != nil {
		err := r.err
		r.err = nil
		if len(p) == 0 {
			return 0, err
		}
		p[0] = ' '
		return 1, err
	}
	return 0, io.EOF
}

// a201ProgressReturn is one scripted Read outcome: a literal block delivered
// with an optional error. The zero value is the empty successful read (0, nil).
type a201ProgressReturn struct {
	block string
	err   error
}

// a201ProgressReader replays a fixed list of read outcomes and counts how many
// returns were consumed, so a test can prove that an extra return was never
// requested. Its script is small on purpose: the block never exceeds the pull
// buffer of the parser. It is deliberately distinct from the acquisition reader
// of a2_01_read_test.go, which scripts []byte steps.
type a201ProgressReader struct {
	script []a201ProgressReturn
	calls  int
}

func (r *a201ProgressReader) Read(p []byte) (int, error) {
	if r.calls >= len(r.script) {
		r.calls++
		return 0, io.EOF
	}
	outcome := r.script[r.calls]
	r.calls++
	if outcome.block == "" {
		return 0, outcome.err
	}
	if len(outcome.block) > len(p) {
		panic("a201ProgressReader: scripted block larger than the read buffer")
	}
	copy(p, outcome.block)
	return len(outcome.block), outcome.err
}

// a201ProgressReturns is a script of count consecutive (0, nil) returns.
func a201ProgressReturns(count int) []a201ProgressReturn {
	return make([]a201ProgressReturn, count)
}

// a201Joined renders count occurrences of one element separated by commas.
func a201Joined(element string, count int) string {
	if count <= 0 {
		return ""
	}
	return strings.Repeat(element+",", count-1) + element
}

// a201TokenReference is one owner reference with its four required strings.
func a201TokenReference() string {
	return `{"apiVersion":"a","kind":"k","name":"n","uid":"u"}`
}

// a201TokenPod builds one Pod element with the given number of owner
// references. The Pod carries no spec on purpose: the document is built only to
// move the token counter, and the resulting semantic rejection of each item is
// a separate expectation.
func a201TokenPod(index, references int) string {
	owners := make([]string, references)
	for position := range owners {
		owners[position] = a201TokenReference()
	}
	return `{"apiVersion":"v1","kind":"Pod","metadata":{"uid":"u` + itoaTest(uint64(index)) +
		`","namespace":"payments","name":"n` + itoaTest(uint64(index)) +
		`","ownerReferences":[` + strings.Join(owners, ",") + `]}}`
}

// a201TokenDocument renders a PodList whose Pods carry the references returned
// by referencesFor.
func a201TokenDocument(pods int, referencesFor func(index int) int) string {
	elements := make([]string, pods)
	for index := range elements {
		elements[index] = a201TokenPod(index, referencesFor(index))
	}
	return a201List(elements...)
}

// a201ExactTokenDocument builds a PodList whose token count is exactly target.
// A Pod without owner references counts 30 tokens; with r >= 1 references it
// counts 29 + 18r: the first reference replaces the empty array brackets (17
// tokens for the reference itself) and every additional reference costs 18
// tokens (17 of the reference plus the comma before it). With n pods, z of
// them empty, and R references spread over the remaining m = n - z, the total
// is 13 + 30n + 18R + z: twelve tokens of the outer list plus its closing
// bracket and brace, and the n - 1 separators between Pods. The search below
// finds a distribution inside the item budget (at most 10000 Pods) and the
// per-Pod reference budget (32); it fails the test when the target cannot be
// represented. The caller verifies the count with the oracle.
func a201ExactTokenDocument(t *testing.T, target uint64) string {
	t.Helper()
	for pods := 10000; pods >= 1; pods-- {
		for empty := 0; empty <= pods && empty < 18; empty++ {
			rest := int64(target) - 13 - 30*int64(pods) - int64(empty)
			if rest < 0 || rest%18 != 0 {
				continue
			}
			references := rest / 18
			withReferences := int64(pods - empty)
			if withReferences == 0 || references < withReferences || references > 32*withReferences {
				continue
			}
			base := int(references / withReferences)
			extra := int(references % withReferences)
			return a201TokenDocument(pods, func(index int) int {
				if index < empty {
					return 0
				}
				if index-empty < extra {
					return base + 1
				}
				return base
			})
		}
	}
	t.Fatalf("no pod/reference distribution reaches exactly %d tokens", target)
	return ""
}

// a201EntryPod builds one Pod with count empty entries either in its
// spec.containers array or in its status.containerStatuses array. The entries
// are structurally valid empty objects; the Pod is still rejected by the
// semantic pass for the missing container names.
func a201EntryPod(index, entries int, status bool) string {
	metadata := `{"uid":"u` + itoaTest(uint64(index)) + `","namespace":"payments","name":"n` + itoaTest(uint64(index)) + `"}`
	if status {
		return `{"apiVersion":"v1","kind":"Pod","metadata":` + metadata +
			`,"spec":{"containers":[]},"status":{"containerStatuses":[` + a201Joined("{}", entries) + `]}}`
	}
	return `{"apiVersion":"v1","kind":"Pod","metadata":` + metadata +
		`,"spec":{"containers":[` + a201Joined("{}", entries) + `]}}`
}

// a201EntrySourceDocument spreads total entries over the smallest number of
// Pods, never exceeding 1024 entries per Pod, so only the source counter can
// refuse an element. A full Pod occupies about 3.2 KB: the 100001-entry
// document is about 0.31 MB and stays far below every other budget.
func a201EntrySourceDocument(total int, status bool) string {
	pods := []string{}
	for index := 0; total > 0; index++ {
		entries := 1024
		if total < entries {
			entries = total
		}
		pods = append(pods, a201EntryPod(index, entries, status))
		total -= entries
	}
	return a201List(pods...)
}

// a201WantRejection asserts one semantic item failure of an admitted source:
// no fatal error, exactly one rejected item, and that rejection carries the
// expected code, anchor and complete message. The codes of the per-Pod pass of
// A.10.3 section 8 (identifier budget, field value range) never abort the
// source, so a fatal-error assertion would not detect them.
func a201WantRejection(t *testing.T, result PodListResult, err error, code PodListDiagnosticCode, offset uint64, message string) {
	t.Helper()
	if err != nil {
		t.Fatalf("ParseSanitizedPodList: %v", err)
	}
	if !result.PodListAccepted() {
		t.Fatal("the source was not admitted")
	}
	if result.Rejected != 1 || len(result.Rejections) != 1 {
		t.Fatalf("rejected/listed = %d/%d, want 1/1", result.Rejected, len(result.Rejections))
	}
	rejection := result.Rejections[0]
	if rejection.Code != code || rejection.Offset != offset {
		t.Fatalf("rejection = %s at %d, want %s at %d", rejection.Code, rejection.Offset, code, offset)
	}
	if got := rejection.String(); got != a201Literal(offset, message) {
		t.Fatalf("rejection message = %q, want %q", got, a201Literal(offset, message))
	}
}

// TestA201LimitBoundaries pins L-1, L and L+1 of every hard budget. The two
// lower sizes must pass the guard under test; the upper one must return the
// exact code, anchor and complete message of the contract.
func TestA201LimitBoundaries(t *testing.T) {
	t.Run("source_bytes", func(t *testing.T) {
		// The stream budget is 67108864 bytes and at most one extra byte is
		// requested to tell an exact-size source from an oversized one. The
		// documents are generated with io.MultiReader and a whitespace reader,
		// so the test never holds a second copy; the parser itself accumulates
		// the whole source (the append growth transiently doubles the slice, so
		// one parse of a 64 MiB source can allocate up to roughly 128 MiB).
		// Passing this guard only proves that the exact size is not refused as
		// an oversized source; the document must also be admitted as JSON.
		prefix := a201List()
		for _, size := range []int{67108863, 67108864} {
			result, err := ParseSanitizedPodList(a201PaddedSource(prefix, size), a201Context())
			if err != nil {
				t.Fatalf("size %d: ParseSanitizedPodList: %v", size, err)
			}
			if !result.PodListAccepted() || result.Source.ByteCount != uint64(size) {
				t.Fatalf("size %d: source = %+v, want an admitted source of exactly %d bytes", size, result.Source, size)
			}
		}
		_, err := ParseSanitizedPodList(a201PaddedSource(prefix, 67108865), a201Context())
		a201WantFailure(t, err, a201Literal(67108864, "file byte limit exceeded"))
	})

	t.Run("depth", func(t *testing.T) {
		// Root is depth 1 and the items array is depth 2, so the k-th array
		// bracket of the document (the first one is the items array itself)
		// opens a value of depth k + 1: 15 brackets leave the deepest value at
		// exactly depth 16 and 16 brackets make the sixteenth bracket a value
		// of depth 17. The lexical guard is exercised through the real API
		// because the allowlist of fields cannot reach depth 16 by itself.
		// Passing the depth guard does not satisfy the profile: the element of
		// items is an array instead of a Pod and the document is refused as
		// soon as that element closes, with invalid_field_type at its opening
		// bracket.
		prefix := `{"apiVersion":"v1","kind":"PodList","items":`
		_, err := a201Parse(t, prefix+strings.Repeat("[", 15)+strings.Repeat("]", 15)+"}")
		a201WantFailure(t, err, a201Literal(uint64(len(prefix)+1), "invalid field type"))
		_, err = a201Parse(t, prefix+strings.Repeat("[", 16)+strings.Repeat("]", 16)+"}")
		a201WantFailure(t, err, a201Literal(uint64(len(prefix)+15), "JSON depth limit exceeded"))
	})

	t.Run("tokens", func(t *testing.T) {
		// The owner references are the only field that can carry a document
		// past two million tokens: each Pod admits up to 32 references and the
		// source admits up to 10000 Pods. A reference costs 18 tokens after the
		// first one (17 of the reference plus its comma), not 15: the oracle
		// below counts the real document and the exact distributions are found
		// for 1999999 and 2000000 tokens. Passing the token guard does not
		// admit the Pods: each one lacks its required spec and is rejected
		// semantically after the walk completes.
		for _, target := range []uint64{1999999, 2000000} {
			document := a201ExactTokenDocument(t, target)
			count, _ := a201CountTokens(document)
			if count != target {
				t.Fatalf("document for %d tokens counts %d", target, count)
			}
			result, err := a201Parse(t, document)
			if err != nil {
				t.Fatalf("tokens %d: ParseSanitizedPodList: %v", target, err)
			}
			if result.Accepted != 0 || result.Rejected == 0 {
				t.Fatalf("tokens %d: accepted/rejected = %d/%d, want 0/many", target, result.Accepted, result.Rejected)
			}
		}
		document := a201TokenDocument(9997, func(int) int { return 12 })
		count, offsets := a201CountTokens(document)
		if count <= 2000001 {
			t.Fatalf("oversized document counts %d tokens, want more than 2000001", count)
		}
		_, err := a201Parse(t, document)
		a201WantFailure(t, err, a201Literal(offsets[2000000], "JSON token limit exceeded"))
	})

	t.Run("items", func(t *testing.T) {
		// Every occurrence of items counts, without deduplication. 10000
		// elements pass the guard and every Pod is still rejected by the
		// semantic pass because it carries no identity metadata; the 10001st
		// element is refused at its own opening brace.
		element := `{"apiVersion":"v1","kind":"Pod"}`
		full := make([]string, 10000)
		for index := range full {
			full[index] = element
		}
		result, err := a201Parse(t, a201List(full...))
		if err != nil {
			t.Fatalf("items 10000: ParseSanitizedPodList: %v", err)
		}
		if result.Accepted != 0 || result.Rejected != 10000 || len(result.Rejections) != 10000 {
			t.Fatalf("items 10000: accepted/rejected/listed = %d/%d/%d, want 0/10000/10000",
				result.Accepted, result.Rejected, len(result.Rejections))
		}
		over := make([]string, 10001)
		for index := range over {
			over[index] = element
		}
		document := a201List(over...)
		_, offsets := a201CountTokens(document)
		// The outer list opens with 12 tokens and every element contributes its
		// 9 tokens followed by a comma, so the brace of element k is token
		// 12 + 10*(k-1).
		anchor := offsets[12+10*10000]
		if document[anchor:anchor+uint64(len(element))] != element {
			t.Fatalf("oracle anchor %d does not hold the 10001st element", anchor)
		}
		_, err = a201Parse(t, document)
		a201WantFailure(t, err, a201Literal(anchor, "Pod item limit exceeded"))
	})

	t.Run("pod_bytes", func(t *testing.T) {
		// The Pod interval runs from its opening brace to its closing brace
		// inclusive, so interior whitespace belongs to the Pod. The padding is
		// JSON whitespace inside spec.containers: the Pod still satisfies the
		// profile (one admitted subject with three observed categories), which
		// is what tells the L and L-1 cases apart from a rejection.
		base := a201Pod("u1", "n1", "", "")
		prefix := `{"apiVersion":"v1","kind":"PodList","items":[`
		for _, size := range []int{1048575, 1048576} {
			pod := a201Pod("u1", "n1", strings.Repeat(" ", size-len(base)), "")
			if len(pod) != size {
				t.Fatalf("pod size = %d, want %d", len(pod), size)
			}
			result, err := a201Parse(t, a201List(pod))
			if err != nil {
				t.Fatalf("pod size %d: ParseSanitizedPodList: %v", size, err)
			}
			if result.Accepted != 1 || len(result.Subjects) != 1 {
				t.Fatalf("pod size %d: accepted/subjects = %d/%d, want 1/1", size, result.Accepted, len(result.Subjects))
			}
			subject := result.Subjects[0]
			if subject.EndByte-subject.StartByte+1 != uint64(size) {
				t.Fatalf("pod size %d: interval = [%d, %d]", size, subject.StartByte, subject.EndByte)
			}
		}
		pod := a201Pod("u1", "n1", strings.Repeat(" ", 1048577-len(base)), "")
		_, err := a201Parse(t, a201List(pod))
		a201WantFailure(t, err, a201Literal(uint64(len(prefix)), "Pod byte limit exceeded"))
	})

	t.Run("object_members", func(t *testing.T) {
		// The member budget of A.4 (32 occurrences of keys, checked before
		// resolving duplicates) cannot be reached through this profile: the
		// allowlist admits at most six distinct keys per object (for a
		// container status: name, imageID, image, ready, state, restartCount),
		// so the seventh key of any object is necessarily a repetition and the
		// duplicate check of A.10.3 section 6 fires long before the 33rd
		// member. The A-8 vector of A.12.1 ("member 33 that would also repeat")
		// describes the precedence in the abstract; with a closed allowlist the
		// reachable failure is duplicate_key, anchored at the opening quote of
		// the second occurrence. No production constant is lowered to simulate
		// the boundary.
		build := func(members []string) (string, uint64) {
			pod := `{"apiVersion":"v1","kind":"Pod","metadata":{"uid":"u1","namespace":"payments","name":"n1"},` +
				`"spec":{"containers":[{"name":"api"}]},"status":{"containerStatuses":[{` + strings.Join(members, ",") + `}]}}`
			document := a201List(pod)
			start := uint64(strings.Index(document, `"containerStatuses":[{`) + len(`"containerStatuses":[{`))
			return document, start
		}
		repeated := make([]string, 33)
		for index := range repeated {
			repeated[index] = `"name":"api"`
		}
		document, start := build(repeated)
		if document[start:start+uint64(len(`"name"`))] != `"name"` {
			t.Fatalf("anchor %d does not hold the first member", start)
		}
		_, err := a201Parse(t, document)
		a201WantFailure(t, err, a201Literal(start+13, "duplicate JSON key"))
		// The budget exists and does not fire early: the six distinct admitted
		// keys of one container status pass the structural walk together, and
		// the Pod is admitted because the status joins its declared container.
		admitted, _ := build([]string{
			`"name":"api"`,
			`"imageID":"sha256:deadbeef"`,
			`"image":"registry.example/app:release"`,
			`"ready":true`,
			`"state":{}`,
			`"restartCount":0`,
		})
		result, err := a201Parse(t, admitted)
		if err != nil {
			t.Fatalf("six distinct members: ParseSanitizedPodList: %v", err)
		}
		if result.Accepted != 1 {
			t.Fatalf("six distinct members: accepted = %d, want 1", result.Accepted)
		}
	})

	t.Run("value_raw_bytes", func(t *testing.T) {
		// The raw budget of a string value counts the complete token, quotes
		// and escapes included: 65534 content bytes fill the token to exactly
		// 65536, and one more content byte exceeds it. The admitted variants
		// satisfy the whole profile: the status joins its declared container.
		build := func(content int) (string, uint64) {
			filler := strings.Repeat("a", content)
			pod := `{"apiVersion":"v1","kind":"Pod","metadata":{"uid":"u1","namespace":"payments","name":"n1"},` +
				`"spec":{"containers":[{"name":"api","image":"registry.example/app:release"}]},` +
				`"status":{"containerStatuses":[{"name":"api","imageID":"` + filler + `"}]}}`
			document := a201List(pod)
			start := uint64(strings.Index(document, `"imageID":"`) + len(`"imageID":"`) - 1)
			return document, start
		}
		for _, content := range []int{65533, 65534} {
			document, _ := build(content)
			result, err := a201Parse(t, document)
			if err != nil {
				t.Fatalf("content %d: ParseSanitizedPodList: %v", content, err)
			}
			if result.Accepted != 1 {
				t.Fatalf("content %d: accepted = %d, want 1", content, result.Accepted)
			}
		}
		document, start := build(65535)
		_, err := a201Parse(t, document)
		a201WantFailure(t, err, a201Literal(start, "string byte limit exceeded"))
	})

	t.Run("key_raw_bytes", func(t *testing.T) {
		// A key admits 256 raw bytes and 128 decoded bytes; both budgets are
		// checked before the duplicate pass and before the allowlist. A key of
		// 254 raw content bytes written as 42 \u00e9 escapes (two decoded bytes
		// each) plus one escaped backslash fills the raw token to exactly 256
		// while its decoded form stays at 85 bytes: only the allowlist rejects
		// it. 255 raw content bytes exceed the raw budget, anchored at the
		// opening quote.
		const prefix = `{"apiVersion":"v1","kind":"PodList",`
		quote := uint64(len(prefix))
		within := prefix + `"` + strings.Repeat(`\u00e9`, 42) + `\\` + `":"v","items":[]}`
		_, err := a201Parse(t, within)
		a201WantFailure(t, err, a201Literal(quote, "field is not allowed by the redaction profile"))
		over := prefix + `"` + strings.Repeat(`\u00e9`, 42) + `\\` + `a` + `":"v","items":[]}`
		_, err = a201Parse(t, over)
		a201WantFailure(t, err, a201Literal(quote, "key byte limit exceeded"))
	})

	t.Run("key_decoded_bytes", func(t *testing.T) {
		// The decoded budget is checked while the key grows, before the raw one
		// can only be checked at the closing quote. 64 two-byte characters
		// decode to exactly 128 bytes and only the allowlist rejects the key;
		// 65 characters decode to 130 bytes with a raw token of 132, so the
		// decoded budget fails at the opening quote. Escapes cannot exceed the
		// decoded budget before the raw one past 127 decoded bytes, because
		// every escape decodes to fewer bytes than it occupies; multibyte text
		// written literally is what reaches this boundary.
		const prefix = `{"apiVersion":"v1","kind":"PodList",`
		quote := uint64(len(prefix))
		within := prefix + `"` + strings.Repeat("é", 64) + `":"v","items":[]}`
		_, err := a201Parse(t, within)
		a201WantFailure(t, err, a201Literal(quote, "field is not allowed by the redaction profile"))
		boundary := prefix + `"` + strings.Repeat("é", 64) + `a` + `":"v","items":[]}`
		_, err = a201Parse(t, boundary)
		a201WantFailure(t, err, a201Literal(quote, "key byte limit exceeded"))
		over := prefix + `"` + strings.Repeat("é", 65) + `":"v","items":[]}`
		_, err = a201Parse(t, over)
		a201WantFailure(t, err, a201Literal(quote, "key byte limit exceeded"))
	})

	t.Run("identifier_decoded_bytes", func(t *testing.T) {
		// metadata.name admits 1024 decoded bytes; the Pod is fully admitted at
		// that size. 1025 bytes fail the length budget; the same size with
		// surrounding whitespace also fails with identifier_limit, never with
		// invalid_identifier: the length check precedes the form check.
		for _, size := range []int{1023, 1024} {
			name := strings.Repeat("a", size)
			result, err := a201Parse(t, a201List(a201CompletePod("u1", name, "sha256:deadbeef")))
			if err != nil {
				t.Fatalf("name size %d: ParseSanitizedPodList: %v", size, err)
			}
			if result.Accepted != 1 {
				t.Fatalf("name size %d: accepted = %d, want 1", size, result.Accepted)
			}
		}
		name := strings.Repeat("a", 1025)
		document := a201List(a201CompletePod("u1", name, "sha256:deadbeef"))
		anchor := uint64(strings.Index(document, `"name":"`) + len(`"name":"`) - 1)
		if document[anchor] != '"' || document[anchor+1:anchor+1+uint64(len(name))] != name {
			t.Fatalf("anchor %d does not hold the Pod name", anchor)
		}
		result, err := a201Parse(t, document)
		a201WantRejection(t, result, err, PodListCodeIdentifierLimit, anchor, "identifier byte limit exceeded")
		spaced := " " + strings.Repeat("a", 1023) + " "
		result, err = a201Parse(t, a201List(a201CompletePod("u1", spaced, "sha256:deadbeef")))
		a201WantRejection(t, result, err, PodListCodeIdentifierLimit, anchor, "identifier byte limit exceeded")
	})

	t.Run("spec_entries_per_pod", func(t *testing.T) {
		// The per-Pod spec budget adds the three categories. An empty object is
		// structurally valid, so every entry passes the walk: 1024 entries are
		// admitted structurally and the Pod is rejected later, once, for the
		// missing name of its first container. The 1025th entry is refused at
		// its own opening brace.
		result, err := a201Parse(t, a201List(a201EntryPod(0, 1024, false)))
		if err != nil {
			t.Fatalf("spec 1024: ParseSanitizedPodList: %v", err)
		}
		if result.Accepted != 0 || result.Rejected != 1 || result.Rejections[0].Code != PodListCodeMissingRequiredField {
			t.Fatalf("spec 1024: accepted/rejected = %d/%d, code = %s",
				result.Accepted, result.Rejected, result.Rejections[0].Code)
		}
		document := a201List(a201EntryPod(0, 1025, false))
		start := uint64(strings.Index(document, `"containers":[`) + len(`"containers":[`))
		anchor := start + 3*1024
		if document[anchor:anchor+2] != "{}" {
			t.Fatalf("anchor %d does not hold the 1025th entry", anchor)
		}
		_, err = a201Parse(t, document)
		a201WantFailure(t, err, a201Literal(anchor, "collection limit exceeded"))
	})

	t.Run("status_entries_per_pod", func(t *testing.T) {
		// Same boundary on the status side: 1024 empty status entries pass the
		// walk and the Pod is rejected once, semantically, for the missing
		// status name; the 1025th entry is refused at its brace.
		result, err := a201Parse(t, a201List(a201EntryPod(0, 1024, true)))
		if err != nil {
			t.Fatalf("status 1024: ParseSanitizedPodList: %v", err)
		}
		if result.Accepted != 0 || result.Rejected != 1 || result.Rejections[0].Code != PodListCodeMissingRequiredField {
			t.Fatalf("status 1024: accepted/rejected = %d/%d, code = %s",
				result.Accepted, result.Rejected, result.Rejections[0].Code)
		}
		document := a201List(a201EntryPod(0, 1025, true))
		start := uint64(strings.Index(document, `"containerStatuses":[`) + len(`"containerStatuses":[`))
		anchor := start + 3*1024
		if document[anchor:anchor+2] != "{}" {
			t.Fatalf("anchor %d does not hold the 1025th entry", anchor)
		}
		_, err = a201Parse(t, document)
		a201WantFailure(t, err, a201Literal(anchor, "collection limit exceeded"))
	})

	t.Run("spec_entries_per_source", func(t *testing.T) {
		// The source budget sums every Pod in physical order. 100000 entries
		// pass the guard across 98 Pods (97 full ones plus a partial one) and
		// every Pod is rejected later, semantically; entry 100001 of the
		// source, the 673rd of the last Pod, is refused at its brace with the
		// same code, which is what separates the source counter from the
		// per-Pod one.
		for _, total := range []int{99999, 100000} {
			document := a201EntrySourceDocument(total, false)
			result, err := a201Parse(t, document)
			if err != nil {
				t.Fatalf("source spec %d: ParseSanitizedPodList: %v", total, err)
			}
			pods := uint64((total + 1023) / 1024)
			if result.Accepted != 0 || result.Rejected != pods {
				t.Fatalf("source spec %d: accepted/rejected = %d/%d, want 0/%d",
					total, result.Accepted, result.Rejected, pods)
			}
		}
		document := a201EntrySourceDocument(100001, false)
		start := uint64(strings.LastIndex(document, `"containers":[`) + len(`"containers":[`))
		anchor := start + 3*672
		if document[anchor:anchor+2] != "{}" {
			t.Fatalf("anchor %d does not hold the 100001st entry", anchor)
		}
		_, err := a201Parse(t, document)
		a201WantFailure(t, err, a201Literal(anchor, "collection limit exceeded"))
	})

	t.Run("status_entries_per_source", func(t *testing.T) {
		// Same boundary on the status source counter: entry 100001 of the
		// source is the 673rd status of the last Pod.
		for _, total := range []int{99999, 100000} {
			document := a201EntrySourceDocument(total, true)
			result, err := a201Parse(t, document)
			if err != nil {
				t.Fatalf("source status %d: ParseSanitizedPodList: %v", total, err)
			}
			pods := uint64((total + 1023) / 1024)
			if result.Accepted != 0 || result.Rejected != pods {
				t.Fatalf("source status %d: accepted/rejected = %d/%d, want 0/%d",
					total, result.Accepted, result.Rejected, pods)
			}
		}
		document := a201EntrySourceDocument(100001, true)
		start := uint64(strings.LastIndex(document, `"containerStatuses":[`) + len(`"containerStatuses":[`))
		anchor := start + 3*672
		if document[anchor:anchor+2] != "{}" {
			t.Fatalf("anchor %d does not hold the 100001st entry", anchor)
		}
		_, err := a201Parse(t, document)
		a201WantFailure(t, err, a201Literal(anchor, "collection limit exceeded"))
	})

	t.Run("owner_references_per_pod", func(t *testing.T) {
		// Owner references are bounded per Pod (32), not per source. 32
		// references are admitted and the Pod satisfies the profile; the 33rd
		// is refused at its opening brace.
		reference := a201TokenReference()
		build := func(count int) (string, uint64) {
			references := make([]string, count)
			for index := range references {
				references[index] = reference
			}
			pod := `{"apiVersion":"v1","kind":"Pod","metadata":{"uid":"u1","namespace":"payments","name":"n1",` +
				`"ownerReferences":[` + strings.Join(references, ",") + `]},"spec":{"containers":[]}}`
			document := a201List(pod)
			start := uint64(strings.Index(document, `"ownerReferences":[`) + len(`"ownerReferences":[`))
			return document, start
		}
		document, _ := build(32)
		result, err := a201Parse(t, document)
		if err != nil {
			t.Fatalf("owners 32: ParseSanitizedPodList: %v", err)
		}
		if result.Accepted != 1 {
			t.Fatalf("owners 32: accepted = %d, want 1", result.Accepted)
		}
		document, start := build(33)
		step := uint64(len(reference) + 1)
		anchor := start + step*32
		if document[anchor:anchor+uint64(len(reference))] != reference {
			t.Fatalf("anchor %d does not hold the 33rd reference", anchor)
		}
		_, err = a201Parse(t, document)
		a201WantFailure(t, err, a201Literal(anchor, "collection limit exceeded"))
	})
}

// TestA201LimitPrecedence pins the ordering of A.10.3 for the cases the budgets
// share with another stage.
func TestA201LimitPrecedence(t *testing.T) {
	t.Run("context_before_reader", func(t *testing.T) {
		// The context is validated before the reader: an invalid selector with a
		// nil reader reports unsupported_selector, not nil_reader, and a valid
		// context never lets the reader be touched while a field is refused.
		refused := a201ContextWith(func(context *PodListContext) { context.Selector = "" })
		if _, err := ParseSanitizedPodList(nil, refused); err == nil {
			t.Fatal("a refused context with a nil reader was admitted")
		} else {
			a201WantFailure(t, err, a201Literal(0, "unsupported input selector"))
		}
		reader := &a201ProgressReader{script: []a201ProgressReturn{{block: a201List()}}}
		if _, err := ParseSanitizedPodList(reader, refused); err == nil {
			t.Fatal("a refused context with a reading reader was admitted")
		} else {
			a201WantFailure(t, err, a201Literal(0, "unsupported input selector"))
		}
		if reader.calls != 0 {
			t.Fatalf("the reader was consumed %d times before the context was refused", reader.calls)
		}
	})

	t.Run("file_limit_before_read_error", func(t *testing.T) {
		// A single read that delivers the byte exceeding the stream budget and
		// an error at the same time reports file_limit, not read_failed, and
		// never exposes the original error text. The reader delivers exactly
		// 67108864 whitespace bytes and then one more byte with the error; the
		// parser accumulates the complete source (about 64 MiB, transiently up
		// to roughly 128 MiB while the slice grows) before refusing it.
		marker := "a201-reader-error-marker"
		reader := &a201SpaceTailErrorReader{remaining: 67108864, err: errors.New(marker)}
		_, err := ParseSanitizedPodList(reader, a201Context())
		a201WantFailure(t, err, a201Literal(67108864, "file byte limit exceeded"))
		if strings.Contains(err.Error(), marker) {
			t.Fatalf("the original reader error leaked into %q", err.Error())
		}
	})

	t.Run("member_budget_never_reached", func(t *testing.T) {
		// The member budget of A.4 (32) precedes the duplicate check of A.10.3
		// section 6 only in the abstract: the closed allowlist admits at most
		// six distinct keys per object, so the seventh key is always a repeat
		// and duplicate_key is the first detectable failure, anchored at the
		// second occurrence. With 33 occurrences of the admitted key "name"
		// the walk never reaches the 33rd member.
		repeated := make([]string, 33)
		for index := range repeated {
			repeated[index] = `"name":"api"`
		}
		pod := `{"apiVersion":"v1","kind":"Pod","metadata":{"uid":"u1","namespace":"payments","name":"n1"},` +
			`"spec":{"containers":[{"name":"api"}]},"status":{"containerStatuses":[{` + strings.Join(repeated, ",") + `}]}}`
		document := a201List(pod)
		start := uint64(strings.Index(document, `"containerStatuses":[{`) + len(`"containerStatuses":[{`))
		_, err := a201Parse(t, document)
		a201WantFailure(t, err, a201Literal(start+13, "duplicate JSON key"))
		// The same object with two short identical keys also reports
		// duplicate_key, and a repeated admitted key of any length would too:
		// only the 33rd *member* is out of reach, not the budget itself.
		short := `{"apiVersion":"v1","kind":"PodList","apiVersion":"v1","items":[]}`
		_, err = a201Parse(t, short)
		a201WantFailure(t, err, a201Literal(uint64(strings.LastIndex(short, `"apiVersion"`)), "duplicate JSON key"))
	})

	t.Run("noncanonical_number_before_range", func(t *testing.T) {
		// The number grammar is checked by the lexical walk before the range of
		// the field: restartCount with a leading zero is noncanonical_number at
		// the start of the number, never invalid_field_value; a canonical
		// number above the range reaches the semantic check and is
		// invalid_field_value at its first byte.
		document := a201List(a201Pod("u1", "n1",
			`{"name":"api","image":"registry.example/app:release"}`,
			`{"name":"api","restartCount":007}`))
		anchor := uint64(strings.Index(document, ":007") + 1)
		if document[anchor:anchor+3] != "007" {
			t.Fatalf("anchor %d does not hold the non-canonical number", anchor)
		}
		_, err := a201Parse(t, document)
		a201WantFailure(t, err, a201Literal(anchor, "non-canonical JSON number"))
		document = a201List(a201Pod("u1", "n1",
			`{"name":"api","image":"registry.example/app:release"}`,
			`{"name":"api","restartCount":2147483648}`))
		anchor = uint64(strings.Index(document, ":2147483648") + 1)
		result, err := a201Parse(t, document)
		a201WantRejection(t, result, err, PodListCodeInvalidFieldValue, anchor, "invalid field value")
	})

	t.Run("key_limit_before_duplicate", func(t *testing.T) {
		// A key that exceeds its budgets is never continued to find out whether
		// it would repeat: the same oversized key twice reports key_limit at
		// the opening quote of its first occurrence, and the duplicate pass
		// never sees the second one. A repeated admitted key of the same shape
		// does report duplicate_key, which is the reachable contrast: the
		// oversized form cannot be written while its decoded text stays under
		// 128 bytes, so the first occurrence is always the one that fails.
		oversized := strings.Repeat("k", 129)
		document := `{"apiVersion":"v1","kind":"PodList","` + oversized + `":"v","` + oversized + `":"v","items":[]}`
		quote := uint64(len(`{"apiVersion":"v1","kind":"PodList","`) - 1)
		if document[quote] != '"' || document[quote+1:quote+1+uint64(len(oversized))] != oversized {
			t.Fatalf("anchor %d does not hold the oversized key", quote)
		}
		_, err := a201Parse(t, document)
		a201WantFailure(t, err, a201Literal(quote, "key byte limit exceeded"))
		repeated := `{"apiVersion":"v1","kind":"PodList","apiVersion":"v1","items":[]}`
		_, err = a201Parse(t, repeated)
		a201WantFailure(t, err, a201Literal(uint64(strings.LastIndex(repeated, `"apiVersion"`)), "duplicate JSON key"))
	})

	t.Run("collection_limit_is_one_diagnostic_when_both_counters_exceed", func(t *testing.T) {
		// An element that exceeds the per-Pod and the per-source entry budget at
		// the same time produces a single collection_limit, anchored at that
		// element: the two counters are not reported separately. 96 full Pods
		// plus a 672-entry one contribute exactly 98976 entries, so the 1025th
		// entry of the last Pod is its own 1025th and the 100001st of the
		// source.
		pods := make([]string, 0, 98)
		for index := 0; index < 96; index++ {
			pods = append(pods, a201EntryPod(index, 1024, false))
		}
		pods = append(pods, a201EntryPod(96, 672, false))
		pods = append(pods, a201EntryPod(97, 1025, false))
		document := a201List(pods...)
		start := uint64(strings.LastIndex(document, `"containers":[`) + len(`"containers":[`))
		anchor := start + 3*1024
		if document[anchor:anchor+2] != "{}" {
			t.Fatalf("anchor %d does not hold the exceeding entry", anchor)
		}
		_, err := a201Parse(t, document)
		a201WantFailure(t, err, a201Literal(anchor, "collection limit exceeded"))
	})

	t.Run("identifier_limit_before_form", func(t *testing.T) {
		// An identifier of 1025 decoded bytes with surrounding whitespace is
		// identifier_limit at its opening quote, not invalid_identifier: the
		// length check precedes the form check of A.10.3 section 8.
		name := " " + strings.Repeat("a", 1023) + " "
		document := a201List(a201CompletePod("u1", name, "sha256:deadbeef"))
		anchor := uint64(strings.Index(document, `"name":"`) + len(`"name":"`) - 1)
		if document[anchor] != '"' || document[anchor+1:anchor+1+uint64(len(name))] != name {
			t.Fatalf("anchor %d does not hold the spaced identifier", anchor)
		}
		result, err := a201Parse(t, document)
		a201WantRejection(t, result, err, PodListCodeIdentifierLimit, anchor, "identifier byte limit exceeded")
	})
}

// TestA201ReaderProgressLimit pins the acquisition rule of A.3/A.10.1: one
// hundred consecutive (0, nil) returns end the read with read_failed, an extra
// return is never requested, and progress between two empty sequences resets
// the consecutive counter.
func TestA201ReaderProgressLimit(t *testing.T) {
	t.Run("ninety_nine_then_progress", func(t *testing.T) {
		// 99 empty returns followed by the complete document continue the
		// reading and admit the source: the counter fails only at the hundredth
		// consecutive empty return.
		document := a201List()
		script := a201ProgressReturns(99)
		script = append(script, a201ProgressReturn{block: document})
		reader := &a201ProgressReader{script: script}
		result, err := ParseSanitizedPodList(reader, a201Context())
		if err != nil {
			t.Fatalf("ParseSanitizedPodList: %v", err)
		}
		if !result.PodListAccepted() || result.Rejected != 0 {
			t.Fatalf("result = %+v, want an admitted empty source", result)
		}
	})

	t.Run("hundredth_without_progress", func(t *testing.T) {
		// The hundredth consecutive (0, nil) return fails at the bytes received
		// at that moment, zero here, and the exact message of the contract.
		reader := &a201ProgressReader{script: a201ProgressReturns(100)}
		_, err := ParseSanitizedPodList(reader, a201Context())
		a201WantFailure(t, err, a201Literal(0, "input read failed"))
		if reader.calls != 100 {
			t.Fatalf("reader consumed %d returns, want 100", reader.calls)
		}
	})

	t.Run("return_101_not_consumed", func(t *testing.T) {
		// A reader prepared for 101 empty returns: the parse stops at the
		// hundredth and the extra return is never requested.
		script := a201ProgressReturns(101)
		script = append(script, a201ProgressReturn{block: a201List()})
		reader := &a201ProgressReader{script: script}
		_, err := ParseSanitizedPodList(reader, a201Context())
		a201WantFailure(t, err, a201Literal(0, "input read failed"))
		if reader.calls != 100 {
			t.Fatalf("reader consumed %d returns, want 100", reader.calls)
		}
	})

	t.Run("progress_resets_counter", func(t *testing.T) {
		// Progress between two empty sequences resets the consecutive counter:
		// 99 empty returns, one byte, 99 empty returns and the rest of the
		// document are admitted.
		document := a201List()
		script := a201ProgressReturns(99)
		script = append(script, a201ProgressReturn{block: document[:1]})
		script = append(script, a201ProgressReturns(99)...)
		script = append(script, a201ProgressReturn{block: document[1:]})
		reader := &a201ProgressReader{script: script}
		result, err := ParseSanitizedPodList(reader, a201Context())
		if err != nil {
			t.Fatalf("ParseSanitizedPodList: %v", err)
		}
		if !result.PodListAccepted() {
			t.Fatalf("result = %+v, want an admitted source", result)
		}
	})

	t.Run("failure_offset_counts_received_bytes", func(t *testing.T) {
		// The failure offset of the no-progress rule is the number of bytes
		// received when the hundredth consecutive empty return is reached: one
		// byte here, after 99 empty returns, one byte and 100 more empty ones.
		script := a201ProgressReturns(99)
		script = append(script, a201ProgressReturn{block: "{"})
		script = append(script, a201ProgressReturns(100)...)
		reader := &a201ProgressReader{script: script}
		_, err := ParseSanitizedPodList(reader, a201Context())
		a201WantFailure(t, err, a201Literal(1, "input read failed"))
	})
}
