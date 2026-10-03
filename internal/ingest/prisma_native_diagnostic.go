package ingest

import (
	"strconv"

	"github.com/d4rpell/Ariadne/internal/schema"
)

// Diagnostic vocabulary of the prisma-native offline adapters (ADR-0027 §12.3).
// Codes are literals from the program, never input data; the categorical error
// carries no provider value, unknown key, physical path or original message.

// Native phases (§12.3).
const (
	NativePhaseContext            = "context"
	NativePhaseAcquisition        = "acquisition"
	NativePhaseAdmission          = "admission"
	NativePhaseProjection         = "projection"
	NativePhaseInterpretation     = "interpretation"
	NativePhaseReplayAdmission    = "replay_admission"
	NativePhaseReplayVerification = "replay_verification"
)

// Native offset spaces (§12.3).
const (
	NativeSpaceNone     = "none"
	NativeSpaceNative   = "native"
	NativeSpaceSource   = "source"
	NativeSpaceManifest = "manifest"
	NativeSpaceDigest   = "digest"
)

// Fatal diagnostic codes (§12.3).
const (
	NativeCodeInvalidContext         = "invalid_context"
	NativeCodeUnsupportedSelector    = "unsupported_selector"
	NativeCodeUnsupportedVersion     = "unsupported_version"
	NativeCodeUnsupportedProfile     = "unsupported_profile"
	NativeCodeRedactionPolicyMissing = "redaction_policy_required"
	NativeCodeNilReader              = "nil_reader"
	NativeCodeReadFailed             = "read_failed"
	NativeCodeSourceLimit            = "source_limit"
	NativeCodeDepthLimit             = "depth_limit"
	NativeCodeTokenLimit             = "token_limit"
	NativeCodeMemberLimit            = "member_limit"
	NativeCodeKeyLimit               = "key_limit"
	NativeCodeStringLimit            = "string_limit"
	NativeCodeNumberLimit            = "number_limit"
	NativeCodeCollectionLimit        = "collection_limit"
	NativeCodeRecordLimit            = "record_limit"
	NativeCodeFieldLimit             = "field_limit"
	NativeCodeInvalidUTF8            = "invalid_utf8"
	NativeCodeInvalidUnicode         = "invalid_unicode"
	NativeCodeForbiddenText          = "forbidden_text"
	NativeCodeInvalidJSON            = "invalid_json"
	NativeCodeDuplicateKey           = "duplicate_key"
	NativeCodeFieldNotAllowed        = "field_not_allowed"
	NativeCodeInvalidFieldType       = "invalid_field_type"
	NativeCodeInvalidCSV             = "invalid_csv"
	NativeCodeInvalidHeader          = "invalid_header"
	NativeCodeFieldCount             = "field_count"
	NativeCodeUnsupportedReportScope = "unsupported_report_scope"
	NativeCodeOutputLimit            = "output_limit"
	NativeCodeInvalidArtifact        = "invalid_artifact"
	NativeCodeHashMismatch           = "hash_mismatch"
	NativeCodeManifestMismatch       = "manifest_mismatch"
)

// Interpretation and coverage diagnostic codes (§12.3).
const (
	NativeCodeFieldAbsent                = "field_absent"
	NativeCodeFieldNull                  = "field_null"
	NativeCodeFieldEmpty                 = "field_empty"
	NativeCodeIdentifierUninterpreted    = "identifier_uninterpreted"
	NativeCodeIdentifierUnavailable      = "identifier_unavailable"
	NativeCodeRowSemanticsUnverified     = "row_semantics_unverified"
	NativeCodeScalarInvalid              = "scalar_invalid"
	NativeCodeScalarUninterpretable      = "scalar_uninterpretable"
	NativeCodeVectorSyntaxInvalid        = "vector_syntax_invalid"
	NativeCodeVectorSemanticsUnverified  = "vector_semantics_unverified"
	NativeCodeCVSSConsistencyNotVerified = "cvss_consistency_not_verified"
	NativeCodeAttributeSourceConflict    = "attribute_source_conflict"
	NativeCodeTimeUninterpretable        = "time_uninterpretable"
	NativeCodeTimeZeroUnspecified        = "time_zero_unspecified"
	NativeCodeScanAfterAcquisition       = "scan_after_acquisition"
	NativeCodeTemporalOrderConflict      = "temporal_order_conflict"
	NativeCodeCaptureAborted             = "capture_aborted"
	NativeCodeCaptureUnknown             = "capture_unknown"
	NativeCodeOriginVersionUnknown       = "origin_version_unknown"
	NativeCodeScopeUnknown               = "scope_unknown"
	NativeCodeSelectionRestricted        = "selection_restricted"
	NativeCodePageScopeUnverified        = "page_scope_unverified"
	NativeCodeScanErrorReported          = "scan_error_reported"
	NativeCodeDistroCoverageMissing      = "distro_coverage_missing"
	NativeCodeDeclaredCountDifference    = "declared_count_difference"
	NativeCodeNoRuntimeBinding           = "no_runtime_binding"
	NativeCodeExcludedByPolicy           = "excluded_by_policy"
)

// NativeError is the typed, closed diagnostic of the native adapters. It never
// carries input values, unknown keys, physical paths or original error text.
type NativeError struct {
	Code        string
	Phase       string
	Path        *string
	Locator     *string
	OffsetSpace string
	Offset      uint64
}

func (e *NativeError) Error() string {
	if e == nil {
		return "ingest: prisma-native: byte/0: " + NativeCodeInvalidArtifact
	}
	code := e.Code
	offset := e.Offset
	if !isKnownFatalCode(code) {
		code = NativeCodeInvalidArtifact
		offset = 0
	}
	return "ingest: prisma-native: byte/" + strconv.FormatUint(offset, 10) + ": " + code
}

// isKnownFatalCode reports whether a code belongs to the closed fatal catalogue
// of §12.3; an unknown code is a fabrication and is reported as invalid_artifact.
func isKnownFatalCode(code string) bool {
	for _, known := range schema.NativeFatalCodes() {
		if known == code {
			return true
		}
	}
	return false
}

// nativeFailure builds a fatal diagnostic with no path, locator or free text.
func nativeFailure(code, phase, space string, offset uint64) *NativeError {
	return &NativeError{Code: code, Phase: phase, OffsetSpace: space, Offset: offset}
}

// strptr returns a pointer to a copy of value, for optional diagnostic members.
func strptr(value string) *string { return &value }

// NativeDiagnostic is the typed interpretation/coverage diagnostic of §12.3. It
// is a contract of the typed result, not a member of the wire artifacts. Path
// and Locator are JSON pointers into the sanitized source; Offset is a byte
// offset into the space named by OffsetSpace.
type NativeDiagnostic struct {
	Code        string
	Phase       string
	Path        *string
	Locator     *string
	OffsetSpace string
	Offset      uint64
}
