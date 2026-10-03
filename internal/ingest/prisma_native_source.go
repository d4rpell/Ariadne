package ingest

import (
	"crypto/sha256"
	"encoding/hex"
	"sort"
	"strconv"
	"unicode/utf8"

	"github.com/d4rpell/Ariadne/internal/schema"
)

// Wire model and canonical serialization of ADR-0027 §11.2–§11.6. The native
// source and its manifest are a new import format, separate from the 0.2
// evidence bundle. Serialization is deterministic and hand-written; general
// decoders (encoding/json) are deliberately not used for the native paths.

// NativeValue is a node of the projected record data. Only the classes of
// §11.3 can appear: conserved strings, booleans, nulls, arrays, objects, and
// the two wrappers.
type NativeValue interface{ nativeValue() }

// NativeNull is a conserved member present with null.
type NativeNull struct{}

// NativeString is a conserved string.
type NativeString string

// NativeBool is a conserved boolean.
type NativeBool bool

// NativeNumber is the numeric wrapper {"number": token} of §11.3.
type NativeNumber struct{ Token string }

// NativeRedacted is the discard witness {"redacted": kind} of §11.3, where kind
// is "null", "empty" or "value".
type NativeRedacted struct{ Kind string }

// NativeArray preserves order, repetitions and emptiness.
type NativeArray struct{ Items []NativeValue }

// NativeObject preserves its members; canonical serialization sorts its keys
// lexicographically by decoded UTF-8 bytes.
type NativeObject struct {
	Keys   []string
	Values []NativeValue
}

func (NativeNull) nativeValue()     {}
func (NativeString) nativeValue()   {}
func (NativeBool) nativeValue()     {}
func (NativeNumber) nativeValue()   {}
func (NativeRedacted) nativeValue() {}
func (NativeArray) nativeValue()    {}
func (NativeObject) nativeValue()   {}

// NativeProfile is the closed profile object of §11.2.
type NativeProfile struct {
	Selector         string
	InputVersion     string
	Name             string
	RedactionPolicy  string
	AdapterSemantics string
}

// NativeInput is the closed input object of §11.2. OriginalHash is always null:
// the original bytes are not retained.
type NativeInput struct {
	SourceAlias   string
	NativeFormat  string
	OriginalBytes uint64
}

// NativeRecord is one records[] object of §11.2.
type NativeRecord struct {
	Ordinal       int
	OriginLocator string
	OriginStart   uint64
	OriginEnd     uint64
	Data          NativeValue
}

// NativeSource is the native-source.json wire of §11.2. Version is the artifact
// provenance version (ADR-0028 §9.5); empty means the 1.0 offline version.
type NativeSource struct {
	Profile NativeProfile
	Context NativeContext
	Input   NativeInput
	Records []NativeRecord
	Version string
}

// NativeCounts is the closed counts object of §11.7.
type NativeCounts struct {
	Records                     uint64
	FindingOccurrences          uint64
	CVEOccurrences              uint64
	OpaqueIdentifierOccurrences uint64
	UnidentifiedOccurrences     uint64
	PackageInventoryOccurrences uint64
}

// NativeLoss is one aggregated losses[] entry of §11.7.
type NativeLoss struct {
	Path        string
	Reason      string
	Occurrences uint64
}

// NativeManifest is the native-manifest.json wire of §11.7. Version is the
// artifact provenance version (ADR-0028 §9.5); empty means the 1.0 version.
type NativeManifest struct {
	SourceHash    string
	SourceBytes   uint64
	OriginalBytes uint64
	Profile       NativeProfile
	Counts        NativeCounts
	Losses        []NativeLoss
	Limitations   []string
	Version       string
}

// canonicalArtifactVersion returns the serialized artifact version: the explicit
// value when set, or the 1.0 offline version when empty. It never selects a
// version by inspection; the caller chooses it.
func canonicalArtifactVersion(v string) string {
	if v == "" {
		return schema.NativeFormatVersion
	}
	return v
}

// EncodeNativeSource serializes the source with §11.4 canonical rules.
func EncodeNativeSource(src NativeSource) []byte {
	var w nativeWriter
	writeNativeSource(&w, src)
	return w.bytes()
}

// EncodeNativeSourceBounded serializes the source and reports whether it stayed
// within limit. The §11.9.1 budget is checked before the buffer grows; a
// truncated buffer is never published.
func EncodeNativeSourceBounded(src NativeSource, limit int) ([]byte, bool) {
	var w nativeWriter
	w.limit = limit
	writeNativeSource(&w, src)
	return w.bytes(), !w.over
}

// NativeOutputBudget is the shared, mutable derived-output accounting of the
// acquisition (ADR-0028 §7.9). It is plain data, never a caller callback.
// PageSourceBytes is the remaining per-page native-source.json budget; the
// caller resets it per page. RetainedBytes and DerivedTokens are accumulated
// across pages and are decremented by the caller only once a page's three
// artifacts are accepted.
type NativeOutputBudget struct {
	PageSourceBytes uint64
	RetainedBytes   uint64
	DerivedTokens   uint64
}

// NativeSourceTokenCount returns the F1 derived-token count of an already
// canonical native source, using the same reader and token definition as the
// replay admission of §11.9.1. It reports false when the bytes are not a valid
// canonical source or exceed the derived-token ceiling.
func NativeSourceTokenCount(sourceBytes []byte) (uint64, bool) {
	var p nativeJSONParser
	if _, err := p.parseTree(sourceBytes, schema.NativeMaxDerivedSourceDepth, schema.NativeMaxDerivedSourceTokens, sourceLexicalLimits()); err != nil {
		return 0, false
	}
	return p.tokens, true
}

// EncodeNativeSourceBudgeted serializes the source under the shared derived
// output budget of §7.9. The page and retained byte budgets stop the shared
// writer before the buffer grows past them; the derived-token budget is reserved
// by the same shared writer as it emits every canonical lexeme, so an
// over-budget source is refused before the rest is built instead of being
// serialized and then re-parsed. The count is identical to the replay admission
// (parseTree) of the delivered canonical bytes. It does not mutate the budget;
// the caller reserves only on success. The returned diagnostic distinguishes a
// byte exhaustion (output_limit) from a derived-token exhaustion (token_limit).
func EncodeNativeSourceBudgeted(src NativeSource, b NativeOutputBudget) ([]byte, uint64, *NativeError) {
	limit := b.PageSourceBytes
	if b.RetainedBytes < limit {
		limit = b.RetainedBytes
	}
	if limit == 0 || limit > uint64(maxInt()) {
		return nil, 0, budgetFailure(NativeCodeOutputLimit)
	}
	var w nativeWriter
	w.limit = int(limit)
	w.tokenActive = true
	w.tokenLimit = b.DerivedTokens
	writeNativeSource(&w, src)
	switch {
	case w.tokenOver:
		return nil, 0, budgetFailure(NativeCodeTokenLimit)
	case w.over:
		return nil, 0, budgetFailure(NativeCodeOutputLimit)
	}
	return w.bytes(), w.tokens, nil
}

// budgetFailure is the closed derived-budget diagnostic of §7.14.
func budgetFailure(code string) *NativeError {
	return &NativeError{Code: code, Phase: NativePhaseProjection, OffsetSpace: NativeSpaceNone}
}

// maxInt is the platform maximum int value, so a uint64 budget is converted
// without overflow.
func maxInt() int { return int(^uint(0) >> 1) }

// writeNativeSource emits the canonical source into w. Once a budget is
// exhausted it returns without traversing the remaining records or emitting
// further canonical bytes (§7.10).
func writeNativeSource(w *nativeWriter, src NativeSource) {
	w.enter()
	w.rawByte('{')
	w.key("format")
	w.stringValue(nativeSourceFormat(src.Profile))
	w.sep()
	w.key("version")
	w.stringValue(canonicalArtifactVersion(src.Version))
	w.sep()
	w.key("profile")
	w.profile(src.Profile)
	w.sep()
	w.key("context")
	w.context(src.Context)
	w.sep()
	w.key("input")
	w.input(src.Input)
	w.sep()
	w.key("records")
	w.enter()
	w.rawByte('[')
	for i, record := range src.Records {
		if w.over {
			return
		}
		if i > 0 {
			w.sep()
		}
		writeNativeRecord(w, record)
	}
	w.end(']')
	w.end('}')
}

// writeNativeRecord emits one complete records[] envelope, stopping before any
// further work once a budget is exhausted.
func writeNativeRecord(w *nativeWriter, record NativeRecord) {
	if w.over {
		return
	}
	w.enter()
	w.rawByte('{')
	w.key("ordinal")
	w.uint(uint64(record.Ordinal))
	w.sep()
	w.key("origin_locator")
	w.stringValue(record.OriginLocator)
	w.sep()
	w.key("origin_start")
	w.uint(record.OriginStart)
	w.sep()
	w.key("origin_end")
	w.uint(record.OriginEnd)
	w.sep()
	w.key("data")
	w.value(record.Data)
	w.end('}')
}

// EncodeNativeManifest serializes the manifest with §11.4 canonical rules.
func EncodeNativeManifest(man NativeManifest) []byte {
	var w nativeWriter
	writeNativeManifest(&w, man)
	return w.bytes()
}

// EncodeNativeManifestBounded serializes the manifest and reports whether it
// stayed within limit. The §11.9.1 budget is checked before the buffer grows.
func EncodeNativeManifestBounded(man NativeManifest, limit int) ([]byte, bool) {
	var w nativeWriter
	w.limit = limit
	writeNativeManifest(&w, man)
	return w.bytes(), !w.over
}

// writeNativeManifest emits the canonical manifest into w.
func writeNativeManifest(w *nativeWriter, man NativeManifest) {
	w.rawByte('{')
	w.key("format")
	w.stringLiteral(nativeManifestFormat(man.Profile))
	w.rawByte(',')
	w.key("version")
	w.stringLiteral(canonicalArtifactVersion(man.Version))
	w.rawByte(',')
	w.key("source_name")
	w.stringLiteral("native-source.json")
	w.rawByte(',')
	w.key("source_hash")
	w.stringLiteral(man.SourceHash)
	w.rawByte(',')
	w.key("source_bytes")
	w.uint(man.SourceBytes)
	w.rawByte(',')
	w.key("original_bytes")
	w.uint(man.OriginalBytes)
	w.rawByte(',')
	w.key("original_hash")
	w.rawLiteral("null")
	w.rawByte(',')
	w.key("profile")
	w.profile(man.Profile)
	w.rawByte(',')
	w.key("counts")
	w.rawByte('{')
	w.key("records")
	w.uint(man.Counts.Records)
	w.rawByte(',')
	w.key("finding_occurrences")
	w.uint(man.Counts.FindingOccurrences)
	w.rawByte(',')
	w.key("cve_occurrences")
	w.uint(man.Counts.CVEOccurrences)
	w.rawByte(',')
	w.key("opaque_identifier_occurrences")
	w.uint(man.Counts.OpaqueIdentifierOccurrences)
	w.rawByte(',')
	w.key("unidentified_occurrences")
	w.uint(man.Counts.UnidentifiedOccurrences)
	w.rawByte(',')
	w.key("package_inventory_occurrences")
	w.uint(man.Counts.PackageInventoryOccurrences)
	w.rawByte('}')
	w.rawByte(',')
	w.key("losses")
	w.rawByte('[')
	for i, loss := range man.Losses {
		if i > 0 {
			w.rawByte(',')
		}
		w.rawByte('{')
		w.key("path")
		w.stringLiteral(loss.Path)
		w.rawByte(',')
		w.key("reason")
		w.stringLiteral(loss.Reason)
		w.rawByte(',')
		w.key("occurrences")
		w.uint(loss.Occurrences)
		w.rawByte('}')
	}
	w.rawByte(']')
	w.rawByte(',')
	w.key("limitations")
	w.rawByte('[')
	for i, limitation := range man.Limitations {
		if i > 0 {
			w.rawByte(',')
		}
		w.stringLiteral(limitation)
	}
	w.rawByte(']')
	w.rawByte('}')
}

// HashNativeSource returns "sha256:" + lower hex of the SHA-256 over the
// complete derived source bytes (§11.5).
func HashNativeSource(source []byte) string { return "sha256:" + sha256Hex(source) }

// HashNativeManifest returns "sha256:" + lower hex over the complete manifest
// bytes (§11.8).
func HashNativeManifest(manifest []byte) string { return "sha256:" + sha256Hex(manifest) }

// NativeManifestSidecar returns the 72-byte sidecar: digest plus LF (§11.8).
func NativeManifestSidecar(manifestDigest string) []byte {
	return append([]byte(manifestDigest), '\n')
}

func sha256Hex(data []byte) string {
	digest := sha256.Sum256(data)
	return hex.EncodeToString(digest[:])
}

// nativeWriter accumulates canonical JSON bytes under an optional byte budget.
// When limit is positive the §11.9.1 budget is enforced before every append: an
// over-budget write sets over and leaves the truncated buffer, so a caller can
// refuse to publish it instead of growing an unbounded buffer first.
type nativeWriter struct {
	buf   []byte
	limit int
	over  bool

	// Derived-token accounting (ADR-0028 §7.9). When tokenActive the writer
	// reserves one derived token per canonical lexeme as it emits and stops
	// (over) as soon as the remaining derived-token budget is exhausted, so an
	// over-budget source is refused before the rest is built. The count equals
	// the replay admission (parseTree) of the same canonical bytes. When
	// tokenActive is false (the offline 1.0/2.0 paths) the counter is inert and
	// the emitted bytes are unchanged.
	tokenActive bool
	tokenLimit  uint64
	tokens      uint64
	tokenOver   bool

	// processed counts the value entries the shared writer actually started
	// while a derived-token budget was active. Production never reads it; the
	// derived-budget tests use it to prove the writer stops traversing the
	// source as soon as the budget is exhausted (§7.10) instead of only
	// refusing an already built buffer. It is not incremented on the offline
	// paths, so their work and bytes are unchanged.
	processed uint64
}

func (w *nativeWriter) bytes() []byte { return w.buf }

// tick reserves one derived token. It is O(1) and inert on the offline paths.
func (w *nativeWriter) tick() {
	if !w.tokenActive || w.over {
		return
	}
	w.tokens++
	if w.tokens > w.tokenLimit {
		w.tokenOver = true
		w.over = true
	}
}

// enter reserves the entry token of one JSON value (scalar, object or array).
// Once a budget is exhausted the caller must not reach it again, so the entry
// count is bounded by the token budget; the counter is inert on the offline
// paths.
func (w *nativeWriter) enter() {
	if w.tokenActive {
		w.processed++
	}
	w.tick()
}

// sep emits a structural comma and reserves its token. The byte budget is
// checked first (preserving the output_limit precedence) and the token is
// reserved before the byte is written, so an exhaustion never emits a comma it
// has not accounted for and never keeps processing another lexeme (§7.10).
func (w *nativeWriter) sep() {
	if !w.hasRoom(1) {
		return
	}
	w.tick()
	if w.over {
		return
	}
	w.rawByte(',')
}

// end emits a closing brace or bracket and reserves its token before the byte,
// with the same byte-budget precedence as sep.
func (w *nativeWriter) end(b byte) {
	if !w.hasRoom(1) {
		return
	}
	w.tick()
	if w.over {
		return
	}
	w.rawByte(b)
}

// hasRoom reports whether n more bytes fit the byte budget without appending,
// marking the writer over when they do not.
func (w *nativeWriter) hasRoom(n int) bool {
	if w.over {
		return false
	}
	if w.limit > 0 && len(w.buf)+n > w.limit {
		w.over = true
		return false
	}
	return true
}

// stringValue reserves one value token and emits a canonical string literal.
func (w *nativeWriter) stringValue(value string) {
	if w.over {
		return
	}
	w.enter()
	if w.over {
		return
	}
	w.stringLiteral(value)
}

// put appends p only while the writer stays within its budget.
func (w *nativeWriter) put(p []byte) {
	if w.over {
		return
	}
	if w.limit > 0 && len(w.buf)+len(p) > w.limit {
		w.over = true
		return
	}
	w.buf = append(w.buf, p...)
}

func (w *nativeWriter) rawByte(b byte) {
	if w.over {
		return
	}
	if w.limit > 0 && len(w.buf)+1 > w.limit {
		w.over = true
		return
	}
	w.buf = append(w.buf, b)
}

func (w *nativeWriter) rawLiteral(s string) { w.put([]byte(s)) }

// key emits a canonical object key followed by ':' and reserves the key and the
// colon lexemes, mirroring the replay admission. Both tokens are reserved before
// their bytes, so an exhaustion never writes a lexeme it has not accounted for.
func (w *nativeWriter) key(name string) {
	if w.over {
		return
	}
	w.tick()
	if w.over {
		return
	}
	w.rawByte('"')
	w.escape(name)
	w.rawByte('"')
	w.tick()
	if w.over {
		return
	}
	w.rawByte(':')
}

// stringLiteral emits a canonical string literal.
func (w *nativeWriter) stringLiteral(value string) {
	w.rawByte('"')
	w.escape(value)
	w.rawByte('"')
}

// uint emits a canonical non-negative decimal integer as one value.
func (w *nativeWriter) uint(value uint64) {
	if w.over {
		return
	}
	w.enter()
	if w.over {
		return
	}
	w.put([]byte(strconv.FormatUint(value, 10)))
}

// escape appends the §11.4 escape table for one string.
func (w *nativeWriter) escape(value string) {
	const hexDigits = "0123456789abcdef"
	for i := 0; i < len(value); {
		if w.over {
			return
		}
		r, size := utf8.DecodeRuneInString(value[i:])
		if r < 0x80 {
			switch byte(r) {
			case '"':
				w.put([]byte{'\\', '"'})
			case '\\':
				w.put([]byte{'\\', '\\'})
			case '\b':
				w.put([]byte{'\\', 'b'})
			case '\f':
				w.put([]byte{'\\', 'f'})
			case '\n':
				w.put([]byte{'\\', 'n'})
			case '\r':
				w.put([]byte{'\\', 'r'})
			case '\t':
				w.put([]byte{'\\', 't'})
			default:
				if r < 0x20 {
					w.put([]byte{'\\', 'u', '0', '0', hexDigits[byte(r)>>4], hexDigits[byte(r)&0x0f]})
				} else {
					w.rawByte(byte(r))
				}
			}
			i++
			continue
		}
		if r == 0x2028 || r == 0x2029 {
			w.put([]byte{'\\', 'u', '2', '0', '2', hexDigits[byte(r)&0x0f]})
			i += size
			continue
		}
		w.put([]byte(value[i : i+size]))
		i += size
	}
}

// profile emits the closed profile object in §11.2 order.
func (w *nativeWriter) profile(p NativeProfile) {
	if w.over {
		return
	}
	w.enter()
	w.rawByte('{')
	w.key("selector")
	w.stringValue(p.Selector)
	w.sep()
	w.key("input_version")
	w.stringValue(p.InputVersion)
	w.sep()
	w.key("name")
	w.stringValue(p.Name)
	w.sep()
	w.key("redaction_policy")
	w.stringValue(p.RedactionPolicy)
	w.sep()
	w.key("adapter_semantics")
	w.stringValue(p.AdapterSemantics)
	w.end('}')
}

// context emits the closed context object in §11.2 order.
func (w *nativeWriter) context(c NativeContext) {
	if w.over {
		return
	}
	w.enter()
	w.rawByte('{')
	w.key("origin_alias")
	w.stringValue(c.OriginAlias)
	w.sep()
	w.key("source_alias")
	w.stringValue(c.SourceAlias)
	w.sep()
	w.key("declared_edition")
	w.stringValue(c.DeclaredEdition)
	w.sep()
	w.key("declared_release")
	w.stringValue(c.DeclaredRelease)
	w.sep()
	w.key("version_basis")
	w.stringValue(c.VersionBasis)
	w.sep()
	w.key("report_kind")
	w.stringValue(c.ReportKind)
	w.sep()
	w.key("acquisition_kind")
	w.stringValue(c.AcquisitionKind)
	w.sep()
	w.key("acquired_at")
	w.stringValue(c.AcquiredAt)
	w.sep()
	w.key("capture_termination")
	w.stringValue(c.CaptureTermination)
	w.sep()
	w.key("scope_mode")
	w.stringValue(c.ScopeMode)
	w.sep()
	w.key("scope_alias")
	w.optString(c.ScopeAlias)
	w.sep()
	w.key("filter_status")
	w.stringValue(c.FilterStatus)
	w.sep()
	w.key("compact")
	w.optBool(c.Compact)
	w.sep()
	w.key("normalized_severity")
	w.optBool(c.NormalizedSeverity)
	w.sep()
	w.key("layers")
	w.optBool(c.Layers)
	w.sep()
	w.key("fields_mode")
	w.stringValue(c.FieldsMode)
	w.sep()
	w.key("selected_fields")
	w.enter()
	w.rawByte('[')
	for i, field := range c.SelectedFields {
		if w.over {
			return
		}
		if i > 0 {
			w.sep()
		}
		w.stringValue(field)
	}
	w.end(']')
	w.sep()
	w.key("page_mode")
	w.stringValue(c.PageMode)
	w.sep()
	w.key("page_ordinal")
	w.optInt(c.PageOrdinal)
	w.sep()
	w.key("pages_expected")
	w.optInt(c.PagesExpected)
	w.sep()
	w.key("data_policy_ack")
	w.stringValue(c.DataPolicyAck)
	w.end('}')
}

// input emits the closed input object in §11.2 order.
func (w *nativeWriter) input(in NativeInput) {
	if w.over {
		return
	}
	w.enter()
	w.rawByte('{')
	w.key("source_alias")
	w.stringValue(in.SourceAlias)
	w.sep()
	w.key("native_format")
	w.stringValue(in.NativeFormat)
	w.sep()
	w.key("original_bytes")
	w.uint(in.OriginalBytes)
	w.sep()
	w.key("local_eof")
	w.rawLiteralValue("true")
	w.sep()
	w.key("original_hash")
	w.rawLiteralValue("null")
	w.end('}')
}

// rawLiteralValue reserves one value token and emits a raw canonical literal.
func (w *nativeWriter) rawLiteralValue(s string) {
	if w.over {
		return
	}
	w.enter()
	if w.over {
		return
	}
	w.rawLiteral(s)
}

func (w *nativeWriter) optString(value *string) {
	if w.over {
		return
	}
	w.enter()
	if value == nil {
		w.rawLiteral("null")
		return
	}
	w.stringLiteral(*value)
}

func (w *nativeWriter) optBool(value *bool) {
	if w.over {
		return
	}
	w.enter()
	if value == nil {
		w.rawLiteral("null")
		return
	}
	if *value {
		w.rawLiteral("true")
		return
	}
	w.rawLiteral("false")
}

func (w *nativeWriter) optInt(value *int) {
	if w.over {
		return
	}
	w.enter()
	if value == nil {
		w.rawLiteral("null")
		return
	}
	w.put([]byte(strconv.FormatInt(int64(*value), 10)))
}

// value emits one projected data node and reserves its entry token. Once a
// budget is exhausted it returns before entering any further node, so the
// traversal of arrays and objects stops instead of walking the rest of the
// source (§7.10).
func (w *nativeWriter) value(v NativeValue) {
	if w.over {
		return
	}
	w.enter()
	if w.over {
		return
	}
	switch t := v.(type) {
	case nil:
		w.rawLiteral("null")
	case NativeNull:
		w.rawLiteral("null")
	case NativeString:
		w.stringLiteral(string(t))
	case NativeBool:
		if bool(t) {
			w.rawLiteral("true")
		} else {
			w.rawLiteral("false")
		}
	case NativeNumber:
		w.rawByte('{')
		w.key("number")
		w.stringValue(t.Token)
		w.end('}')
	case NativeRedacted:
		w.rawByte('{')
		w.key("redacted")
		w.stringValue(t.Kind)
		w.end('}')
	case NativeArray:
		w.rawByte('[')
		for i, item := range t.Items {
			if w.over {
				return
			}
			if i > 0 {
				w.sep()
			}
			w.value(item)
		}
		w.end(']')
	case NativeObject:
		w.object(t)
	default:
		// Unreachable for admitted values; emit null rather than a Go error.
		w.rawLiteral("null")
	}
}

// object emits a projected object with keys in canonical (lexicographic by
// decoded UTF-8 bytes) order. The caller has already reserved the entry token.
// It returns before allocating or sorting once a budget is exhausted, so no
// make/sort runs for an object that will not be emitted (§7.10).
func (w *nativeWriter) object(o NativeObject) {
	if w.over {
		return
	}
	order := make([]int, len(o.Keys))
	for i := range order {
		order[i] = i
	}
	sort.SliceStable(order, func(a, b int) bool { return o.Keys[order[a]] < o.Keys[order[b]] })
	w.rawByte('{')
	for i, idx := range order {
		if w.over {
			return
		}
		if i > 0 {
			w.sep()
		}
		w.key(o.Keys[idx])
		w.value(o.Values[idx])
	}
	w.end('}')
}

// NativeOriginLocator builds the §11.6 origin locator for a record.
func NativeOriginLocator(format string, ordinal int, start, end uint64) string {
	if format == "csv" {
		return "csv:record/" + strconv.Itoa(ordinal+1) + "/bytes/" +
			strconv.FormatUint(start, 10) + "-" + strconv.FormatUint(end, 10)
	}
	return "json:/" + strconv.Itoa(ordinal)
}

// EncodeNativeRecordData returns the canonical bytes of one projected record
// data value, using the same writer as the source and manifest. It is a
// comparison representation for the acquisition repeat/drift guards (ADR-0028
// §8.10–§8.11), not a wire artifact: it never carries context, acquired_at,
// aliases, ordinals or locators of the original document.
func EncodeNativeRecordData(v NativeValue) []byte {
	var w nativeWriter
	w.value(v)
	return w.bytes()
}

// NativeValueSize returns the canonical byte length of one projected value,
// used to enforce the derived size budgets of §11.9.1.
func NativeValueSize(v NativeValue) int {
	var w nativeWriter
	w.value(v)
	return len(w.bytes())
}

// NativeRecordSize returns the canonical byte length of one complete record
// envelope (§11.9.1 "registro derivado completo"): the data object plus its
// ordinal, locator and original interval members.
func NativeRecordSize(record NativeRecord) int {
	var w nativeWriter
	writeNativeRecord(&w, record)
	return len(w.bytes())
}

// NativeRecordFits reports whether a complete record envelope stays within
// limit, refusing to grow the buffer past it (§11.9.1).
func NativeRecordFits(record NativeRecord, limit int) bool {
	var w nativeWriter
	w.limit = limit
	writeNativeRecord(&w, record)
	return !w.over
}

// NativeContextSize returns the canonical byte length of the context object
// (§11.9.1 "context canónico").
func NativeContextSize(ctx NativeContext) int {
	var w nativeWriter
	w.context(ctx)
	return len(w.bytes())
}

// NativeContextFits reports whether the canonical context object stays within
// limit (§11.9.1).
func NativeContextFits(ctx NativeContext, limit int) bool {
	var w nativeWriter
	w.limit = limit
	w.context(ctx)
	return !w.over
}

// FirstDifference exposes the first differing byte between two documents.
func FirstDifference(a, b []byte) uint64 { return firstDifference(a, b) }
