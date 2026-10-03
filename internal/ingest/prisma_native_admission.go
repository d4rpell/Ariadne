package ingest

// Shared, side-effect-free admission seam of ADR-0028 §3.3, §7.10 and §7.11.
//
// The connector (internal/prismaacquire) feeds a bounded page body to the exact
// JSON admission of the offline adapters — the same lexer, the same closed
// disposition table and the same projection. The second parser that §7.10
// forbids does not exist here: ParsePrismaNative and AdmitNativeJSON run the
// same admitNativeJSON function.
//
// Two properties are deliberate:
//
//   - The additional acquisition limits travel as data (NativeBudget), never as
//     a caller callback, so no accounting mechanism becomes a public hook.
//   - Cancellation travels as a receive-only channel (NativeAdmission.Done),
//     which is the language's select primitive and imports nothing. A
//     <-chan struct{} executes no caller code and cannot perform I/O, so it is
//     neither the "callback able to run network or filesystem" of §3.3 nor a
//     widened privilege. The offline roots keep the core standard-library set
//     (which excludes context).
//
// The admission returns a private draft: sanitized records plus numeric
// accounting, without a finalized context, hash or manifest. Finalization stays
// in internal/normalize and in the connector, after the global termination is
// known (§8.18).

// NativeCodeCancelled is the admission-internal cancellation signal. It is not a
// wire diagnostic of the native adapters and never appears in a serialized
// artifact; the connector maps it to its own closed code (§11.2). It is exported
// so the connector can recognize cancellation without parsing any text.
const NativeCodeCancelled = "admission_cancelled"

// nativeCancelled is the unexported sentinel returned by an admission that
// observed the caller's Done channel closed. It is unexported so a caller cannot
// replace it; use IsNativeCancelled to test for it.
var nativeCancelled = &NativeError{
	Code:        NativeCodeCancelled,
	Phase:       NativePhaseAdmission,
	OffsetSpace: NativeSpaceNone,
}

// IsNativeCancelled reports whether err is the admission cancellation signal.
func IsNativeCancelled(err *NativeError) bool {
	return err != nil && err.Code == NativeCodeCancelled
}

// NativeBudget carries the additional acquisition limits as data. A zero field
// means "no additional limit beyond the F1 limit already in force". Images,
// Findings and Packages are the limits in force for this single admission call;
// the connector lowers them to the remaining accumulated budget before each
// page (§7.7).
type NativeBudget struct {
	Tokens   uint64 // lexical tokens of this admission
	Images   uint64 // image objects admitted by this call
	Findings uint64 // vulnerability occurrences admitted by this call
	Packages uint64 // package occurrences admitted by this call
}

// NativeAdmission is the closed, side-effect-free admission control. Done, when
// non-nil, is polled non-blockingly at bounded checkpoints; a closed channel
// aborts the admission with NativeCancelled.
type NativeAdmission struct {
	Budget NativeBudget
	Done   <-chan struct{}
}

// NativeAccounting reports what one admission consumed. Only numbers; no input
// value, key, host or credential is retained.
type NativeAccounting struct {
	Tokens   uint64
	Bytes    uint64
	Images   uint64
	Findings uint64
	Packages uint64
}

// NativeDraft is the private sanitized result of one admission: the projected
// records plus accounting, without a finalized context, source hash or manifest.
// A caller finalizes it once the global termination is known.
type NativeDraft struct {
	Format        string // "json" (this extension admits no CSV page)
	OriginalBytes uint64
	Records       []NativeRecord
	Accounting    NativeAccounting
}

// Source builds a NativeSource from a finalized profile and context. The records
// are copied so the draft and the produced source never share a mutable slice
// (§3.6). The caller is responsible for validating the context before this call;
// the offline entry point validates it with the version in force.
func (d NativeDraft) Source(profile NativeProfile, ctx NativeContext) NativeSource {
	records := make([]NativeRecord, len(d.Records))
	copy(records, d.Records)
	return NativeSource{
		Profile: profile,
		Context: nativeContextClone(ctx),
		Input: NativeInput{
			SourceAlias:   ctx.SourceAlias,
			NativeFormat:  d.Format,
			OriginalBytes: d.OriginalBytes,
		},
		Records: records,
	}
}

// AdmitNativeJSON admits one bounded JSON page against the F1 admission rules
// under the given acquisition control, and returns the sanitized draft. The
// caller validates its context (and its declared origin and selector) before
// calling. The input bytes are not retained.
func AdmitNativeJSON(data []byte, adm NativeAdmission) (NativeDraft, *NativeError) {
	return admitNativeJSON(data, adm)
}
