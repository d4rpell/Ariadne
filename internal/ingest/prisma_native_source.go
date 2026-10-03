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

// writeNativeSource emits the canonical source into w.
func writeNativeSource(w *nativeWriter, src NativeSource) {
	w.rawByte('{')
	w.key("format")
	w.stringLiteral("prisma-native-source-v1")
	w.rawByte(',')
	w.key("version")
	w.stringLiteral(canonicalArtifactVersion(src.Version))
	w.rawByte(',')
	w.key("profile")
	w.profile(src.Profile)
	w.rawByte(',')
	w.key("context")
	w.context(src.Context)
	w.rawByte(',')
	w.key("input")
	w.input(src.Input)
	w.rawByte(',')
	w.key("records")
	w.rawByte('[')
	for i, record := range src.Records {
		if i > 0 {
			w.rawByte(',')
		}
		writeNativeRecord(w, record)
	}
	w.rawByte(']')
	w.rawByte('}')
}

// writeNativeRecord emits one complete records[] envelope.
func writeNativeRecord(w *nativeWriter, record NativeRecord) {
	w.rawByte('{')
	w.key("ordinal")
	w.uint(uint64(record.Ordinal))
	w.rawByte(',')
	w.key("origin_locator")
	w.stringLiteral(record.OriginLocator)
	w.rawByte(',')
	w.key("origin_start")
	w.uint(record.OriginStart)
	w.rawByte(',')
	w.key("origin_end")
	w.uint(record.OriginEnd)
	w.rawByte(',')
	w.key("data")
	w.value(record.Data)
	w.rawByte('}')
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
	w.stringLiteral("prisma-native-manifest-v1")
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
}

func (w *nativeWriter) bytes() []byte { return w.buf }

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

// key emits a canonical object key followed by ':'.
func (w *nativeWriter) key(name string) {
	w.rawByte('"')
	w.escape(name)
	w.rawByte('"')
	w.rawByte(':')
}

// stringLiteral emits a canonical string literal.
func (w *nativeWriter) stringLiteral(value string) {
	w.rawByte('"')
	w.escape(value)
	w.rawByte('"')
}

// uint emits a canonical non-negative decimal integer.
func (w *nativeWriter) uint(value uint64) {
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
	w.rawByte('{')
	w.key("selector")
	w.stringLiteral(p.Selector)
	w.rawByte(',')
	w.key("input_version")
	w.stringLiteral(p.InputVersion)
	w.rawByte(',')
	w.key("name")
	w.stringLiteral(p.Name)
	w.rawByte(',')
	w.key("redaction_policy")
	w.stringLiteral(p.RedactionPolicy)
	w.rawByte(',')
	w.key("adapter_semantics")
	w.stringLiteral(p.AdapterSemantics)
	w.rawByte('}')
}

// context emits the closed context object in §11.2 order.
func (w *nativeWriter) context(c NativeContext) {
	w.rawByte('{')
	w.key("origin_alias")
	w.stringLiteral(c.OriginAlias)
	w.rawByte(',')
	w.key("source_alias")
	w.stringLiteral(c.SourceAlias)
	w.rawByte(',')
	w.key("declared_edition")
	w.stringLiteral(c.DeclaredEdition)
	w.rawByte(',')
	w.key("declared_release")
	w.stringLiteral(c.DeclaredRelease)
	w.rawByte(',')
	w.key("version_basis")
	w.stringLiteral(c.VersionBasis)
	w.rawByte(',')
	w.key("report_kind")
	w.stringLiteral(c.ReportKind)
	w.rawByte(',')
	w.key("acquisition_kind")
	w.stringLiteral(c.AcquisitionKind)
	w.rawByte(',')
	w.key("acquired_at")
	w.stringLiteral(c.AcquiredAt)
	w.rawByte(',')
	w.key("capture_termination")
	w.stringLiteral(c.CaptureTermination)
	w.rawByte(',')
	w.key("scope_mode")
	w.stringLiteral(c.ScopeMode)
	w.rawByte(',')
	w.key("scope_alias")
	w.optString(c.ScopeAlias)
	w.rawByte(',')
	w.key("filter_status")
	w.stringLiteral(c.FilterStatus)
	w.rawByte(',')
	w.key("compact")
	w.optBool(c.Compact)
	w.rawByte(',')
	w.key("normalized_severity")
	w.optBool(c.NormalizedSeverity)
	w.rawByte(',')
	w.key("layers")
	w.optBool(c.Layers)
	w.rawByte(',')
	w.key("fields_mode")
	w.stringLiteral(c.FieldsMode)
	w.rawByte(',')
	w.key("selected_fields")
	w.rawByte('[')
	for i, field := range c.SelectedFields {
		if i > 0 {
			w.rawByte(',')
		}
		w.stringLiteral(field)
	}
	w.rawByte(']')
	w.rawByte(',')
	w.key("page_mode")
	w.stringLiteral(c.PageMode)
	w.rawByte(',')
	w.key("page_ordinal")
	w.optInt(c.PageOrdinal)
	w.rawByte(',')
	w.key("pages_expected")
	w.optInt(c.PagesExpected)
	w.rawByte(',')
	w.key("data_policy_ack")
	w.stringLiteral(c.DataPolicyAck)
	w.rawByte('}')
}

// input emits the closed input object in §11.2 order.
func (w *nativeWriter) input(in NativeInput) {
	w.rawByte('{')
	w.key("source_alias")
	w.stringLiteral(in.SourceAlias)
	w.rawByte(',')
	w.key("native_format")
	w.stringLiteral(in.NativeFormat)
	w.rawByte(',')
	w.key("original_bytes")
	w.uint(in.OriginalBytes)
	w.rawByte(',')
	w.key("local_eof")
	w.rawLiteral("true")
	w.rawByte(',')
	w.key("original_hash")
	w.rawLiteral("null")
	w.rawByte('}')
}

func (w *nativeWriter) optString(value *string) {
	if value == nil {
		w.rawLiteral("null")
		return
	}
	w.stringLiteral(*value)
}

func (w *nativeWriter) optBool(value *bool) {
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
	if value == nil {
		w.rawLiteral("null")
		return
	}
	w.put([]byte(strconv.FormatInt(int64(*value), 10)))
}

// value emits one projected data node.
func (w *nativeWriter) value(v NativeValue) {
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
		w.rawLiteral("{\"number\":")
		w.stringLiteral(t.Token)
		w.rawByte('}')
	case NativeRedacted:
		w.rawLiteral("{\"redacted\":")
		w.stringLiteral(t.Kind)
		w.rawByte('}')
	case NativeArray:
		w.rawByte('[')
		for i, item := range t.Items {
			if i > 0 {
				w.rawByte(',')
			}
			w.value(item)
		}
		w.rawByte(']')
	case NativeObject:
		w.object(t)
	default:
		// Unreachable for admitted values; emit null rather than a Go error.
		w.rawLiteral("null")
	}
}

// object emits a projected object with keys in canonical (lexicographic by
// decoded UTF-8 bytes) order.
func (w *nativeWriter) object(o NativeObject) {
	order := make([]int, len(o.Keys))
	for i := range order {
		order[i] = i
	}
	sort.SliceStable(order, func(a, b int) bool { return o.Keys[order[a]] < o.Keys[order[b]] })
	w.rawByte('{')
	for i, idx := range order {
		if i > 0 {
			w.rawByte(',')
		}
		w.key(o.Keys[idx])
		w.value(o.Values[idx])
	}
	w.rawByte('}')
}

// NativeOriginLocator builds the §11.6 origin locator for a record.
func NativeOriginLocator(format string, ordinal int, start, end uint64) string {
	if format == "csv" {
		return "csv:record/" + strconv.Itoa(ordinal+1) + "/bytes/" +
			strconv.FormatUint(start, 10) + "-" + strconv.FormatUint(end, 10)
	}
	return "json:/" + strconv.Itoa(ordinal)
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
