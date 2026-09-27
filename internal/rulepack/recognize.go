package rulepack

// Recognition is the outcome of the strict, bounded, non-admitting profile
// classification of ADR-0018 §3. It decides which context contract a request
// owes; it never authenticates bytes, never validates the profile/version cross
// and never yields a usable Pack or AdmittedPack.
type Recognition int

const (
	// RecognizedIndeterminate means the document is not a strictly recognizable
	// pack header: invalid JSON, an exceeded scanner limit, a non-object root, a
	// missing or wrongly typed header, or an unknown schema/profile. Each phase
	// keeps its own real error in that case; recognition invents none.
	RecognizedIndeterminate Recognition = iota
	// RecognizedReadiness is schema_version 0.1 with the legacy profile.
	RecognizedReadiness
	// RecognizedProduct is schema_version 0.1 with the product profile.
	RecognizedProduct
)

// RecognizeProfile classifies the pack header with the same strict scanner as
// Decode, over the whole document and without admitting anything (ADR-0018 §3).
// Duplicates at any depth, a non-object root, absent or wrongly typed headers
// and unknown schema/profile values are indeterminate. The rest of the schema is
// not required to be valid for the header to be recognized.
func RecognizeProfile(data []byte) Recognition {
	if len(data) > MaxPackBytes {
		return RecognizedIndeterminate
	}
	root, err := scanDocument(data)
	if err != nil {
		return RecognizedIndeterminate
	}
	if root.kind != jsonObject {
		return RecognizedIndeterminate
	}
	schema, ok := memberValue(root, "schema_version")
	if !ok || schema.kind != jsonString || schema.text != SupportedSchemaVersion {
		return RecognizedIndeterminate
	}
	profile, ok := memberValue(root, "profile")
	if !ok || profile.kind != jsonString {
		return RecognizedIndeterminate
	}
	switch profile.text {
	case SupportedProfile:
		return RecognizedReadiness
	case ProductEvidenceProfile:
		return RecognizedProduct
	default:
		return RecognizedIndeterminate
	}
}

// RequiresDomainContext reports whether the recognized profile owes a
// DomainContext. An indeterminate classification owes nothing: its error belongs
// to the phase that actually fails.
func (recognition Recognition) RequiresDomainContext() bool {
	return recognition == RecognizedProduct
}

// ForbidsDomainContext reports whether the recognized profile rejects an extra
// DomainContext instead of ignoring it (ADR-0018 §1).
func (recognition Recognition) ForbidsDomainContext() bool {
	return recognition == RecognizedReadiness
}
