package ingest

import "strconv"

// The sanitized-podlist-v1 diagnostic vocabulary is closed (ADR-0025 A.10.2).
// A code is a program literal; messages are derived exclusively from this
// catalog, so no input key, value, uid, name, path or reader error is ever
// interpolated into a diagnostic.

// PodListDiagnosticCode is one allowlisted diagnostic code.
type PodListDiagnosticCode string

const (
	PodListCodeInvalidInput            PodListDiagnosticCode = "invalid_input"
	PodListCodeInvalidContext          PodListDiagnosticCode = "invalid_context"
	PodListCodeUnsupportedSelector     PodListDiagnosticCode = "unsupported_selector"
	PodListCodeUnsupportedVersion      PodListDiagnosticCode = "unsupported_version"
	PodListCodeRedactionPolicyRequired PodListDiagnosticCode = "redaction_policy_required"
	PodListCodeNilReader               PodListDiagnosticCode = "nil_reader"
	PodListCodeReadFailed              PodListDiagnosticCode = "read_failed"
	PodListCodeFileLimit               PodListDiagnosticCode = "file_limit"
	PodListCodeDepthLimit              PodListDiagnosticCode = "depth_limit"
	PodListCodeTokenLimit              PodListDiagnosticCode = "token_limit"
	PodListCodeItemLimit               PodListDiagnosticCode = "item_limit"
	PodListCodePodLimit                PodListDiagnosticCode = "pod_limit"
	PodListCodeMemberLimit             PodListDiagnosticCode = "member_limit"
	PodListCodeStringLimit             PodListDiagnosticCode = "string_limit"
	PodListCodeKeyLimit                PodListDiagnosticCode = "key_limit"
	PodListCodeCollectionLimit         PodListDiagnosticCode = "collection_limit"
	PodListCodeIdentifierLimit         PodListDiagnosticCode = "identifier_limit"
	PodListCodeBOM                     PodListDiagnosticCode = "bom"
	PodListCodeInvalidUTF8             PodListDiagnosticCode = "invalid_utf8"
	PodListCodeNUL                     PodListDiagnosticCode = "nul"
	PodListCodeForbiddenText           PodListDiagnosticCode = "forbidden_text"
	PodListCodeInvalidJSON             PodListDiagnosticCode = "invalid_json"
	PodListCodeInvalidSurrogate        PodListDiagnosticCode = "invalid_surrogate"
	PodListCodeDuplicateKey            PodListDiagnosticCode = "duplicate_key"
	PodListCodeNoncanonicalNumber      PodListDiagnosticCode = "noncanonical_number"
	PodListCodeFieldNotAllowed         PodListDiagnosticCode = "field_not_allowed"
	PodListCodeUnsupportedResource     PodListDiagnosticCode = "unsupported_resource"
	PodListCodePaginationNotSupported  PodListDiagnosticCode = "pagination_not_supported"
	PodListCodeMissingRequiredField    PodListDiagnosticCode = "missing_required_field"
	PodListCodeInvalidFieldType        PodListDiagnosticCode = "invalid_field_type"
	PodListCodeInvalidIdentifier       PodListDiagnosticCode = "invalid_identifier"
	PodListCodeInvalidFieldValue       PodListDiagnosticCode = "invalid_field_value"
	PodListCodeNamespaceMismatch       PodListDiagnosticCode = "namespace_mismatch"
	PodListCodeDuplicateUID            PodListDiagnosticCode = "duplicate_uid"
	PodListCodeDuplicateContainer      PodListDiagnosticCode = "duplicate_container"
	PodListCodeDuplicateStatus         PodListDiagnosticCode = "duplicate_status"
	PodListCodeOrphanStatus            PodListDiagnosticCode = "orphan_status"
	PodListCodeInvalidState            PodListDiagnosticCode = "invalid_state"

	// Incompleteness and projection diagnostics, same local format.
	PodListCodeCategoryUnobserved        PodListDiagnosticCode = "category_unobserved"
	PodListCodeStatusUnobserved          PodListDiagnosticCode = "status_unobserved"
	PodListCodeRequestedImageUnavailable PodListDiagnosticCode = "requested_image_unavailable"
	PodListCodeCaptureAborted            PodListDiagnosticCode = "capture_aborted"
	PodListCodeCaptureUnknown            PodListDiagnosticCode = "capture_unknown"
	PodListCodeSourceItemsRejected       PodListDiagnosticCode = "source_items_rejected"
	PodListCodeSubjectContextConflict    PodListDiagnosticCode = "subject_context_conflict"
	PodListCodeInvalidProjection         PodListDiagnosticCode = "invalid_projection"
)

// podListMessages is the exact message of every code (ADR-0025 A.10.2).
var podListMessages = map[PodListDiagnosticCode]string{
	PodListCodeInvalidInput:            "invalid input",
	PodListCodeInvalidContext:          "invalid observation context",
	PodListCodeUnsupportedSelector:     "unsupported input selector",
	PodListCodeUnsupportedVersion:      "unsupported input version",
	PodListCodeRedactionPolicyRequired: "required redaction policy was not acknowledged",
	PodListCodeNilReader:               "nil reader",
	PodListCodeReadFailed:              "input read failed",
	PodListCodeFileLimit:               "file byte limit exceeded",
	PodListCodeDepthLimit:              "JSON depth limit exceeded",
	PodListCodeTokenLimit:              "JSON token limit exceeded",
	PodListCodeItemLimit:               "Pod item limit exceeded",
	PodListCodePodLimit:                "Pod byte limit exceeded",
	PodListCodeMemberLimit:             "object member limit exceeded",
	PodListCodeStringLimit:             "string byte limit exceeded",
	PodListCodeKeyLimit:                "key byte limit exceeded",
	PodListCodeCollectionLimit:         "collection limit exceeded",
	PodListCodeIdentifierLimit:         "identifier byte limit exceeded",
	PodListCodeBOM:                     "BOM is not allowed",
	PodListCodeInvalidUTF8:             "invalid UTF-8",
	PodListCodeNUL:                     "NUL is not allowed",
	PodListCodeForbiddenText:           "forbidden text character",
	PodListCodeInvalidJSON:             "invalid JSON structure",
	PodListCodeInvalidSurrogate:        "invalid Unicode surrogate sequence",
	PodListCodeDuplicateKey:            "duplicate JSON key",
	PodListCodeNoncanonicalNumber:      "non-canonical JSON number",
	PodListCodeFieldNotAllowed:         "field is not allowed by the redaction profile",
	PodListCodeUnsupportedResource:     "unsupported resource kind or API version",
	PodListCodePaginationNotSupported:  "paginated export is not supported",
	PodListCodeMissingRequiredField:    "required field is missing",
	PodListCodeInvalidFieldType:        "invalid field type",
	PodListCodeInvalidIdentifier:       "invalid identifier",
	PodListCodeInvalidFieldValue:       "invalid field value",
	PodListCodeNamespaceMismatch:       "Pod namespace is outside the declared scope",
	PodListCodeDuplicateUID:            "duplicate Pod UID",
	PodListCodeDuplicateContainer:      "duplicate container name within a category",
	PodListCodeDuplicateStatus:         "duplicate container status name",
	PodListCodeOrphanStatus:            "container status has no matching declaration",
	PodListCodeInvalidState:            "container state is ambiguous",

	PodListCodeCategoryUnobserved:        "container category was not observed",
	PodListCodeStatusUnobserved:          "container status coverage is incomplete",
	PodListCodeRequestedImageUnavailable: "requested image was not provided",
	PodListCodeCaptureAborted:            "export capture was aborted",
	PodListCodeCaptureUnknown:            "export capture termination is unknown",
	PodListCodeSourceItemsRejected:       "source contains rejected Pod items",
	PodListCodeSubjectContextConflict:    "source contains conflicting Pod identity context",
	PodListCodeInvalidProjection:         "observation cannot be projected consistently",
}

// PodListMessage returns the exact message of one code. An unknown code falls
// back to invalid_input and never prints its own content.
func PodListMessage(code PodListDiagnosticCode) string {
	if message, known := podListMessages[code]; known {
		return message
	}
	return podListMessages[PodListCodeInvalidInput]
}

// PodListDiagnostic is one local diagnostic: closed code, verified byte offset
// and optional item index and field locator. The locator contains only
// allowlist keys and computed indices.
type PodListDiagnostic struct {
	Code         PodListDiagnosticCode
	ByteOffset   uint64
	ItemIndex    *int
	FieldLocator string
}

// Error renders the diagnostic with the fixed local format. A diagnostic with
// an unknown code renders as invalid_input at offset zero and never leaks a
// supplied value.
func (d PodListDiagnostic) Error() string {
	code := d.Code
	if _, known := podListMessages[code]; !known {
		code = PodListCodeInvalidInput
		return podListError(code, 0)
	}
	return podListError(code, d.ByteOffset)
}

func podListError(code PodListDiagnosticCode, offset uint64) string {
	return "ingest: sanitized-podlist-v1: byte/" + strconv.FormatUint(offset, 10) + ": " + PodListMessage(code)
}

// PodListError is the failure returned by ParseSanitizedPodList. It carries the
// diagnostic verbatim; no raw reader error is exposed.
type PodListError struct {
	Diagnostic PodListDiagnostic
}

func (e *PodListError) Error() string {
	if e == nil {
		return podListError(PodListCodeInvalidInput, 0)
	}
	return e.Diagnostic.Error()
}

// failure builds the error value for an internal scan failure.
func failure(code PodListDiagnosticCode, offset uint64) *PodListError {
	return &PodListError{Diagnostic: PodListDiagnostic{Code: code, ByteOffset: offset}}
}

// PodListRejection reports one rejected Pod item with its primary reason.
type PodListRejection struct {
	ItemIndex int
	Offset    uint64
	Code      PodListDiagnosticCode
}

func (r PodListRejection) String() string {
	return podListError(r.Code, r.Offset)
}

// PodListRejectionReason maps a rejection onto the wire error string form.
// Rejections are reported as local diagnostics; they never invent a bundle.
func (r PodListRejection) Diagnostic() PodListDiagnostic {
	index := r.ItemIndex
	return PodListDiagnostic{Code: r.Code, ByteOffset: r.Offset, ItemIndex: &index}
}

// PodListCodeKnown reports whether one code belongs to the closed catalog. A code
// outside it has no message of its own and is rendered as invalid_input.
func PodListCodeKnown(code string) bool {
	_, known := podListMessages[PodListDiagnosticCode(code)]
	return known
}

// podListLocatorArrays are the only array names a locator may carry.
var podListLocatorArrays = map[string]bool{
	"status.containerStatuses":          true,
	"status.initContainerStatuses":      true,
	"status.ephemeralContainerStatuses": true,
	"spec.containers":                   true,
	"spec.initContainers":               true,
	"spec.ephemeralContainers":          true,
}

// podListLocatorFields are the only leaves a locator may name, per array family.
var podListLocatorFields = map[string]map[string]bool{
	"status": {"imageID": true, "image": true},
	"spec":   {"image": true, "name": true},
}

// PodListLocatorValid reports whether one locator belongs to the closed grammar
// of the profile: items[N].<spec|status>.<array>[N].<leaf>, where both indices
// are canonical non-negative decimals and the array and leaf are enumerated.
// Nothing else may be concatenated into a diagnostic or an evidence locator.
func PodListLocatorValid(locator string) bool {
	if locator == "" {
		return true
	}
	rest, ok := podListCut(locator, "items[")
	if !ok {
		return false
	}
	itemIndex, rest, ok := podListCutIndex(rest)
	if !ok {
		return false
	}
	_ = itemIndex
	rest, ok = podListCut(rest, "].")
	if !ok {
		return false
	}
	family := ""
	switch {
	case len(rest) > len("status.") && rest[:len("status.")] == "status.":
		family = "status"
	case len(rest) > len("spec.") && rest[:len("spec.")] == "spec.":
		family = "spec"
	default:
		return false
	}
	rest = rest[len(family)+1:]
	array, rest, ok := podListCutArray(rest)
	if !ok || !podListLocatorArrays[family+"."+array] {
		return false
	}
	_ = array
	rest, ok = podListCut(rest, "[")
	if !ok {
		return false
	}
	if _, rest, ok = podListCutIndex(rest); !ok {
		return false
	}
	rest, ok = podListCut(rest, "].")
	if !ok {
		return false
	}
	return podListLocatorFields[family][rest]
}

func podListCut(value, prefix string) (string, bool) {
	if len(value) < len(prefix) || value[:len(prefix)] != prefix {
		return "", false
	}
	return value[len(prefix):], true
}

// podListCutIndex consumes one canonical non-negative decimal and returns the
// rest of the text.
func podListCutIndex(value string) (uint64, string, bool) {
	index := 0
	for index < len(value) && value[index] >= '0' && value[index] <= '9' {
		index++
	}
	if index == 0 || (index > 1 && value[0] == '0') {
		return 0, "", false
	}
	var parsed uint64
	for position := 0; position < index; position++ {
		parsed = parsed*10 + uint64(value[position]-'0')
	}
	return parsed, value[index:], true
}

// podListCutArray consumes one array name made of letters.
func podListCutArray(value string) (string, string, bool) {
	index := 0
	for index < len(value) && ((value[index] >= 'a' && value[index] <= 'z') || (value[index] >= 'A' && value[index] <= 'Z')) {
		index++
	}
	if index == 0 {
		return "", "", false
	}
	return value[:index], value[index:], true
}
