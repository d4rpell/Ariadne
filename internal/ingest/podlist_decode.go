package ingest

import (
	"strconv"

	"github.com/d4rpell/Ariadne/internal/schema"
)

// Typed decoding of the admitted structural walk (ADR-0025 A.3.4, A.8, A.10.3
// §8). Decoding never coerces: a value keeps its declared type, presence and
// original offset, an empty string stays "not informed" without becoming a
// missing field, and no number passes through float64. The structural stage
// already validated the text; this stage classifies it semantically, in the
// field order of the contract: required absence, wrong type, identifier budget,
// identifier form and then the specific value restrictions.

// podListRestartCountMax is the greatest admitted restartCount (A.3.4).
const podListRestartCountMax = 2147483647

// podListIdentifierText returns the text of one contextual identifier and its
// type or budget failure, if any. Form is checked by the callers: a required
// identifier cannot be empty, an optional one can mean "not informed".
func podListIdentifierText(value podListValue) (string, PodListDiagnosticCode) {
	if value.Kind != podListValueString {
		return "", PodListCodeInvalidFieldType
	}
	if uint64(len(value.Text)) > uint64(schema.SanitizedPodListMaxIdentifierBytes) {
		return "", PodListCodeIdentifierLimit
	}
	return value.Text, ""
}

// podListRequiredIdentifier decodes an identifier that must be present and
// non-empty: uid, namespace, Pod name, container name and the owner fields.
func podListRequiredIdentifier(value podListValue) (string, PodListDiagnosticCode) {
	text, code := podListIdentifierText(value)
	if code != "" {
		return "", code
	}
	if text == "" || podListWhitespaceSurrounded(text) {
		return "", PodListCodeInvalidIdentifier
	}
	return text, ""
}

// podListOptionalIdentifier decodes an identifier whose absence or empty value
// means "not informed", such as resourceVersion.
func podListOptionalIdentifier(value podListValue) (PodOptionalString, PodListDiagnosticCode) {
	text, code := podListIdentifierText(value)
	if code != "" {
		return PodOptionalString{}, code
	}
	if text == "" {
		return PodOptionalString{Present: PresenceEmpty}, ""
	}
	if podListWhitespaceSurrounded(text) {
		return PodOptionalString{}, PodListCodeInvalidIdentifier
	}
	return PodOptionalString{Present: PresenceValue, Value: text}, ""
}

// podListOptionalReference decodes an image reference: absence and the empty
// string both mean "not informed", and the two are kept apart internally.
func podListOptionalReference(value podListValue) (PodOptionalString, PodListDiagnosticCode) {
	if value.Kind != podListValueString {
		return PodOptionalString{}, PodListCodeInvalidFieldType
	}
	if value.Text == "" {
		return PodOptionalString{Present: PresenceEmpty}, ""
	}
	if podListWhitespaceSurrounded(value.Text) {
		return PodOptionalString{}, PodListCodeInvalidIdentifier
	}
	return PodOptionalString{Present: PresenceValue, Value: value.Text}, ""
}

// podListOptionalBool decodes an optional boolean. Its absence is never turned
// into false.
func podListOptionalBool(value podListValue) (PodOptionalBool, PodListDiagnosticCode) {
	if value.Kind != podListValueBool {
		return PodOptionalBool{}, PodListCodeInvalidFieldType
	}
	return PodOptionalBool{Present: PresenceValue, Value: value.Bool}, ""
}

// podListRestartCount decodes restartCount as context and validates its range.
// The grammar was already fixed by the structural walk; the range is checked
// here, after the type, as the contract requires.
func podListRestartCount(value podListValue) (int64, PodListDiagnosticCode) {
	if value.Kind != podListValueNumber {
		return 0, PodListCodeInvalidFieldType
	}
	count, err := strconv.ParseInt(value.Digits, 10, 64)
	if err != nil || count > podListRestartCountMax {
		return 0, PodListCodeInvalidFieldValue
	}
	return count, ""
}

// podListStateCategory reads the declared state category of one container
// status. An empty object means the state was not informed; two variants are
// ambiguous and rejected at the second variant in physical order; a second
// variant that appears first in the document does not change that anchor.
func podListStateCategory(value podListValue) (PodContainerState, PodListDiagnosticCode, uint64) {
	state := PodContainerState{Offset: value.Offset}
	if len(value.Members) > 1 {
		return PodContainerState{}, PodListCodeInvalidState, value.Members[1].KeyOffset
	}
	if len(value.Members) == 0 {
		return state, "", 0
	}
	variant := value.Members[0]
	if variant.Value.Kind != podListValueObject {
		return PodContainerState{}, PodListCodeInvalidFieldType, variant.Value.Offset
	}
	state.Category = variant.Key
	return state, "", 0
}
