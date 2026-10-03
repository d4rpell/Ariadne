package ingest

import "strings"

// NativeContext is the explicit operator context of ADR-0027 §5. Every member
// is obligatory: optional values use nil, they are never omitted and never take
// a default. The library never consults clock, mtime, environment or host data
// to complete it.
type NativeContext struct {
	OriginAlias        string
	SourceAlias        string
	DeclaredEdition    string
	DeclaredRelease    string
	VersionBasis       string
	ReportKind         string
	AcquisitionKind    string
	AcquiredAt         string
	CaptureTermination string
	ScopeMode          string
	ScopeAlias         *string
	FilterStatus       string
	Compact            *bool
	NormalizedSeverity *bool
	Layers             *bool
	FieldsMode         string
	SelectedFields     []string
	PageMode           string
	PageOrdinal        *int
	PagesExpected      *int
	DataPolicyAck      string
}

// nativeContextClone returns an independent copy so a later mutation of the
// caller's context cannot alter an already produced artifact (§13.3).
func nativeContextClone(in NativeContext) NativeContext {
	out := in
	if in.ScopeAlias != nil {
		v := *in.ScopeAlias
		out.ScopeAlias = &v
	}
	if in.Compact != nil {
		v := *in.Compact
		out.Compact = &v
	}
	if in.NormalizedSeverity != nil {
		v := *in.NormalizedSeverity
		out.NormalizedSeverity = &v
	}
	if in.Layers != nil {
		v := *in.Layers
		out.Layers = &v
	}
	if in.PageOrdinal != nil {
		v := *in.PageOrdinal
		out.PageOrdinal = &v
	}
	if in.PagesExpected != nil {
		v := *in.PagesExpected
		out.PagesExpected = &v
	}
	out.SelectedFields = append([]string{}, in.SelectedFields...)
	return out
}

// validNativeAlias reports whether value is an ASCII alias of §5:
// [A-Za-z0-9][A-Za-z0-9._-]{0,127}.
func validNativeAlias(value string) bool {
	if len(value) == 0 || len(value) > 128 {
		return false
	}
	for i := 0; i < len(value); i++ {
		c := value[i]
		switch {
		case c >= 'A' && c <= 'Z', c >= 'a' && c <= 'z', c >= '0' && c <= '9':
		case i > 0 && (c == '.' || c == '_' || c == '-'):
		default:
			return false
		}
	}
	return true
}

// validateNativeContext enforces every domain and relation of §5 before any
// reader consumes the source. It returns nil when the context is admissible.
func validateNativeContext(ctx NativeContext) *NativeError {
	fail := func() *NativeError {
		return nativeFailure(NativeCodeInvalidContext, NativePhaseContext, NativeSpaceNone, 0)
	}
	if !validNativeAlias(ctx.OriginAlias) || !validNativeAlias(ctx.SourceAlias) {
		return fail()
	}
	switch ctx.DeclaredEdition {
	case "compute_self_hosted", "unknown":
	default:
		return fail()
	}
	switch ctx.DeclaredRelease {
	case "34.04.145", "unknown":
	default:
		return nativeFailure(NativeCodeUnsupportedProfile, NativePhaseContext, NativeSpaceNone, 0)
	}
	editionKnown := ctx.DeclaredEdition != "unknown"
	releaseKnown := ctx.DeclaredRelease != "unknown"
	switch ctx.VersionBasis {
	case "operator_declared":
		if !editionKnown || !releaseKnown {
			return fail()
		}
	case "documentary_assumption":
		if editionKnown && releaseKnown {
			return fail()
		}
	default:
		return fail()
	}
	if ctx.ReportKind != "deployed_images" {
		return fail()
	}
	switch ctx.AcquisitionKind {
	case "operator_export", "synthetic_fixture":
	default:
		return fail()
	}
	if !validCanonicalNativeTime(ctx.AcquiredAt) || ctx.AcquiredAt == "0001-01-01T00:00:00Z" {
		return fail()
	}
	switch ctx.CaptureTermination {
	case "finished", "aborted", "unknown":
	default:
		return fail()
	}
	switch ctx.ScopeMode {
	case "unfiltered_declared", "filtered_declared", "unknown":
	default:
		return fail()
	}
	if ctx.ScopeMode == "filtered_declared" {
		if ctx.ScopeAlias == nil || !validNativeAlias(*ctx.ScopeAlias) {
			return fail()
		}
	} else if ctx.ScopeAlias != nil {
		return fail()
	}
	switch ctx.FilterStatus {
	case "none_declared":
		if ctx.ScopeMode == "filtered_declared" {
			return fail()
		}
	case "present":
		if ctx.ScopeMode != "filtered_declared" {
			return fail()
		}
	case "unknown":
	default:
		return fail()
	}
	switch ctx.FieldsMode {
	case "unrestricted_declared":
		if len(ctx.SelectedFields) != 0 {
			return fail()
		}
	case "restricted_declared":
		if len(ctx.SelectedFields) < 1 || len(ctx.SelectedFields) > 128 {
			return fail()
		}
		seen := make(map[string]struct{}, len(ctx.SelectedFields))
		for _, field := range ctx.SelectedFields {
			if len(field) > 256 {
				return fail()
			}
			if _, dup := seen[field]; dup {
				return fail()
			}
			seen[field] = struct{}{}
		}
	case "unknown":
		if len(ctx.SelectedFields) != 0 {
			return fail()
		}
	default:
		return fail()
	}
	switch ctx.PageMode {
	case "export_declared", "unknown":
		if ctx.PageOrdinal != nil {
			return fail()
		}
	case "single_page_declared":
	default:
		return fail()
	}
	if ctx.PageOrdinal != nil && (*ctx.PageOrdinal < 1 || *ctx.PageOrdinal > 10000) {
		return fail()
	}
	if ctx.PagesExpected != nil && (*ctx.PagesExpected < 1 || *ctx.PagesExpected > 10000) {
		return fail()
	}
	if ctx.PageOrdinal != nil && ctx.PagesExpected != nil && *ctx.PageOrdinal > *ctx.PagesExpected {
		return fail()
	}
	if ctx.DataPolicyAck != nativePolicyLiteral() {
		return nativeFailure(NativeCodeRedactionPolicyMissing, NativePhaseContext, NativeSpaceNone, 0)
	}
	return nil
}

// validCanonicalNativeTime checks YYYY-MM-DDTHH:MM:SS[.fracción]Z with a real
// calendar, seconds 00-59 and between one and nine fraction digits. A fraction
// present does not end in zero and a numerically zero fraction is omitted.
func validCanonicalNativeTime(value string) bool {
	if len(value) < 20 || value[len(value)-1] != 'Z' {
		return false
	}
	if value[4] != '-' || value[7] != '-' || value[10] != 'T' || value[13] != ':' || value[16] != ':' {
		return false
	}
	digit := func(s string) bool {
		for i := 0; i < len(s); i++ {
			if s[i] < '0' || s[i] > '9' {
				return false
			}
		}
		return true
	}
	if !digit(value[0:4]) || !digit(value[5:7]) || !digit(value[8:10]) ||
		!digit(value[11:13]) || !digit(value[14:16]) || !digit(value[17:19]) {
		return false
	}
	year := atoi4(value[0:4])
	if year < 1 {
		return false
	}
	month := atoi2(value[5:7])
	day := atoi2(value[8:10])
	hour := atoi2(value[11:13])
	minute := atoi2(value[14:16])
	second := atoi2(value[17:19])
	if month < 1 || month > 12 || hour > 23 || minute > 59 || second > 59 {
		return false
	}
	if day < 1 || day > daysInMonth(year, month) {
		return false
	}
	rest := value[19 : len(value)-1]
	if rest == "" {
		return len(value) == 20
	}
	if rest[0] != '.' {
		return false
	}
	frac := rest[1:]
	if len(frac) < 1 || len(frac) > 9 || !digit(frac) {
		return false
	}
	if frac[len(frac)-1] == '0' {
		return false
	}
	return true
}

func atoi2(s string) int { return int(s[0]-'0')*10 + int(s[1]-'0') }

func atoi4(s string) int {
	return int(s[0]-'0')*1000 + int(s[1]-'0')*100 + int(s[2]-'0')*10 + int(s[3]-'0')
}

func daysInMonth(year, month int) int {
	switch month {
	case 1, 3, 5, 7, 8, 10, 12:
		return 31
	case 4, 6, 9, 11:
		return 30
	case 2:
		if isLeap(year) {
			return 29
		}
		return 28
	}
	return 0
}

func isLeap(year int) bool { return year%4 == 0 && (year%100 != 0 || year%400 == 0) }

// nativePolicyLiteral is the single acknowledged redaction policy of §4.1.
func nativePolicyLiteral() string { return "prisma-native-offline-redaction-v1/1.0" }

// nativeContextEqual reports whether two contexts are structurally equal. It is
// used by the independent-copy invariants of §13.3.
func nativeContextEqual(a, b NativeContext) bool {
	if a.OriginAlias != b.OriginAlias || a.SourceAlias != b.SourceAlias ||
		a.DeclaredEdition != b.DeclaredEdition || a.DeclaredRelease != b.DeclaredRelease ||
		a.VersionBasis != b.VersionBasis || a.ReportKind != b.ReportKind ||
		a.AcquisitionKind != b.AcquisitionKind || a.AcquiredAt != b.AcquiredAt ||
		a.CaptureTermination != b.CaptureTermination || a.ScopeMode != b.ScopeMode ||
		a.FilterStatus != b.FilterStatus || a.FieldsMode != b.FieldsMode ||
		a.PageMode != b.PageMode || a.DataPolicyAck != b.DataPolicyAck {
		return false
	}
	if !optStringEqual(a.ScopeAlias, b.ScopeAlias) ||
		!optBoolEqual(a.Compact, b.Compact) ||
		!optBoolEqual(a.NormalizedSeverity, b.NormalizedSeverity) ||
		!optBoolEqual(a.Layers, b.Layers) ||
		!optIntEqual(a.PageOrdinal, b.PageOrdinal) ||
		!optIntEqual(a.PagesExpected, b.PagesExpected) {
		return false
	}
	return strings.Join(a.SelectedFields, "\x00") == strings.Join(b.SelectedFields, "\x00")
}

func optStringEqual(a, b *string) bool {
	if a == nil || b == nil {
		return a == b
	}
	return *a == *b
}

func optBoolEqual(a, b *bool) bool {
	if a == nil || b == nil {
		return a == b
	}
	return *a == *b
}

func optIntEqual(a, b *int) bool {
	if a == nil || b == nil {
		return a == b
	}
	return *a == *b
}

// CloneNativeContext returns an independent copy of a native context.
func CloneNativeContext(in NativeContext) NativeContext { return nativeContextClone(in) }
