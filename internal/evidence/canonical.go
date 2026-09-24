package evidence

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	contract "github.com/d4rpell/Ariadne/pkg/evidence"
)

// CanonicalJSON returns the frozen wire bytes of the complete envelope, with the
// collections in the canonical order of ADR-0006 §1 and §4. It validates first,
// never mutates the bundle it receives and returns no bytes for an invalid one.
func CanonicalJSON(bundle contract.Bundle) ([]byte, error) {
	canonical, err := canonicalBundle(bundle)
	if err != nil {
		return nil, err
	}
	return encodeCanonical(canonical)
}

// HashCanonicalJSON returns "sha256:<64 lowercase hex>" over the hash projection
// of ADR-0006 §1(a): the provenance claims are covered and only the enumerated
// operational metadata is excluded. The digest is never embedded in the bundle
// and proves integrity of those bytes, never authenticity.
func HashCanonicalJSON(bundle contract.Bundle) (string, error) {
	canonical, err := canonicalBundle(bundle)
	if err != nil {
		return "", err
	}
	projection, err := encodeCanonical(hashProjection(canonical))
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(projection)
	return "sha256:" + hex.EncodeToString(digest[:]), nil
}

// canonicalBundle validates the bundle and returns a copy whose contractual
// collections follow the canonical order. A nil collection stays nil: it was
// already rejected instead of being collapsed into [].
func canonicalBundle(bundle contract.Bundle) (contract.Bundle, error) {
	if err := contract.ValidateBundle(bundle); err != nil {
		return contract.Bundle{}, err
	}
	canonical := bundle
	canonical.Images = sortedBy(bundle.Images, compareImages)
	canonical.ObservedContainerClasses = sortedBy(bundle.ObservedContainerClasses, compareStringsAs[contract.ContainerClass])
	canonical.Evidence = sortedEvidence(bundle.Evidence)
	canonical.Provenance.Inputs = sortedBy(bundle.Provenance.Inputs, compareInputs)
	canonical.Provenance.APIScope.Namespaces = sortedBy(bundle.Provenance.APIScope.Namespaces, compareStringsAs[contract.Namespace])
	canonical.Provenance.APIScope.Verbs = sortedBy(bundle.Provenance.APIScope.Verbs, compareStrings)
	canonical.Provenance.APIScope.Resources = sortedBy(bundle.Provenance.APIScope.Resources, compareStrings)
	canonical.Provenance.Warnings = sortedBy(bundle.Provenance.Warnings, compareWarnings)
	orderedErrors, err := sortedErrors(bundle.Provenance.Errors)
	if err != nil {
		return contract.Bundle{}, err
	}
	canonical.Provenance.Errors = orderedErrors
	return canonical, nil
}

func sortedEvidence(items []contract.EvidenceItem) []contract.EvidenceItem {
	if items == nil {
		return nil
	}
	cloned := make([]contract.EvidenceItem, len(items))
	for index, item := range items {
		item.Warnings = sortedBy(item.Warnings, compareWarnings)
		cloned[index] = item
	}
	return sortedBy(cloned, compareEvidenceItems)
}

// sortedBy orders a copy and leaves the input untouched.
func sortedBy[T any](values []T, compare func(a, b T) int) []T {
	if values == nil {
		return nil
	}
	sorted := make([]T, len(values))
	copy(sorted, values)
	sort.SliceStable(sorted, func(i, j int) bool { return compare(sorted[i], sorted[j]) < 0 })
	return sorted
}

// sortedErrors orders strings by the UTF-8 bytes of their canonical JSON
// representation, quotes and escapes included (ADR-0006 §4).
func sortedErrors(values []string) ([]string, error) {
	if values == nil {
		return nil, nil
	}
	type keyedString struct {
		key   []byte
		value string
	}
	keyed := make([]keyedString, len(values))
	for index, value := range values {
		encoded, err := encodeCanonical(value)
		if err != nil {
			return nil, fmt.Errorf("evidence: provenance.errors[%d]: %w", index, err)
		}
		keyed[index] = keyedString{key: encoded, value: value}
	}
	sort.SliceStable(keyed, func(i, j int) bool { return bytes.Compare(keyed[i].key, keyed[j].key) < 0 })
	sorted := make([]string, len(keyed))
	for index := range keyed {
		sorted[index] = keyed[index].value
	}
	return sorted, nil
}

// encodeCanonical serializes a document as a single UTF-8 JSON value without BOM,
// without whitespace outside tokens, without a trailing newline and without HTML
// escaping (ADR-0006 §4).
func encodeCanonical(document any) ([]byte, error) {
	var buffer bytes.Buffer
	encoder := json.NewEncoder(&buffer)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(document); err != nil {
		return nil, err
	}
	return bytes.TrimSuffix(buffer.Bytes(), []byte("\n")), nil
}

func compareStrings(a, b string) int {
	return strings.Compare(a, b)
}

func compareStringsAs[T ~string](a, b T) int {
	return strings.Compare(string(a), string(b))
}

// compareOptionalStrings orders an absent value before a present one, as
// ADR-0006 §4 requires for the image tuple.
func compareOptionalStrings(a, b *string) int {
	switch {
	case a == nil && b == nil:
		return 0
	case a == nil:
		return -1
	case b == nil:
		return 1
	}
	return strings.Compare(*a, *b)
}

func compareOptionalTimestamps(a, b *contract.Timestamp) int {
	switch {
	case a == nil && b == nil:
		return 0
	case a == nil:
		return -1
	case b == nil:
		return 1
	}
	return a.Time.Compare(b.Time)
}

func compareWarnings(a, b contract.Warning) int {
	if result := compareStrings(a.Code, b.Code); result != 0 {
		return result
	}
	if result := compareStrings(string(a.Class), string(b.Class)); result != 0 {
		return result
	}
	return compareStrings(a.Message, b.Message)
}

func compareWarningsList(a, b []contract.Warning) int {
	limit := len(a)
	if len(b) < limit {
		limit = len(b)
	}
	for index := 0; index < limit; index++ {
		if result := compareWarnings(a[index], b[index]); result != 0 {
			return result
		}
	}
	return len(a) - len(b)
}

func compareImages(a, b contract.ImageIdentity) int {
	if result := compareStringsAs(a.ContainerClass, b.ContainerClass); result != 0 {
		return result
	}
	if result := compareStringsAs(a.ContainerName, b.ContainerName); result != 0 {
		return result
	}
	if result := compareOptionalStrings(optionalString(a.RequestedImage), optionalString(b.RequestedImage)); result != 0 {
		return result
	}
	if result := compareOptionalStrings(optionalString(a.RawImageID), optionalString(b.RawImageID)); result != 0 {
		return result
	}
	if result := compareOptionalStrings(optionalString(a.NormalizedDigest), optionalString(b.NormalizedDigest)); result != 0 {
		return result
	}
	if result := compareOptionalStrings(platformOS(a), platformOS(b)); result != 0 {
		return result
	}
	if result := compareOptionalStrings(platformArchitecture(a), platformArchitecture(b)); result != 0 {
		return result
	}
	if result := compareStringsAs(a.Platform.Status, b.Platform.Status); result != 0 {
		return result
	}
	return compareOptionalTimestamps(a.ObservedAt, b.ObservedAt)
}

// platformOS and platformArchitecture return the wire value of those fields: null
// unless the platform is known, so an unobserved value orders before an observed
// one.
func platformOS(image contract.ImageIdentity) *string {
	if image.Platform.Status != contract.PlatformKnown {
		return nil
	}
	return &image.Platform.OS
}

func platformArchitecture(image contract.ImageIdentity) *string {
	if image.Platform.Status != contract.PlatformKnown {
		return nil
	}
	return &image.Platform.Architecture
}

func compareEvidenceItems(a, b contract.EvidenceItem) int {
	if result := compareStringsAs(a.Scope.SubjectUID, b.Scope.SubjectUID); result != 0 {
		return result
	}
	if result := compareStringsAs(a.Scope.ContainerName, b.Scope.ContainerName); result != 0 {
		return result
	}
	if result := compareStrings(a.Type, b.Type); result != 0 {
		return result
	}
	if result := compareStrings(a.Source, b.Source); result != 0 {
		return result
	}
	if result := compareStringsAs(a.Locator, b.Locator); result != 0 {
		return result
	}
	if result := compareStringsAs(a.SourceHash, b.SourceHash); result != 0 {
		return result
	}
	if result := compareOptionalTimestamps(a.ObservedAt, b.ObservedAt); result != 0 {
		return result
	}
	if result := compareOptionalStrings(optionalString(a.ValueHash), optionalString(b.ValueHash)); result != 0 {
		return result
	}
	if result := compareStringsAs(a.Confidence, b.Confidence); result != 0 {
		return result
	}
	if result := compareOptionalStrings(a.Value, b.Value); result != 0 {
		return result
	}
	return compareWarningsList(a.Warnings, b.Warnings)
}

func compareInputs(a, b contract.InputRef) int {
	if result := compareStrings(a.Path, b.Path); result != 0 {
		return result
	}
	return compareStringsAs(a.Hash, b.Hash)
}

func optionalString[T ~string](value *T) *string {
	if value == nil {
		return nil
	}
	converted := string(*value)
	return &converted
}

// hashProjection is the document of ADR-0006 §1(a): the five shared sections plus
// the provenance claims, without the operational metadata.
type hashProjectionEnvelope struct {
	SchemaVersion            string                    `json:"schema_version"`
	Subject                  contract.Subject          `json:"subject"`
	Images                   []contract.ImageIdentity  `json:"images"`
	Evidence                 []contract.EvidenceItem   `json:"evidence"`
	ObservedContainerClasses []contract.ContainerClass `json:"observed_container_classes"`
	Provenance               hashProjectionProvenance  `json:"provenance"`
}

type hashProjectionProvenance struct {
	Ruleset         *hashProjectionRuleset `json:"ruleset"`
	Inputs          []contract.InputRef    `json:"inputs"`
	APIScope        contract.APIScope      `json:"api_scope"`
	Coverage        contract.Coverage      `json:"coverage"`
	Completeness    contract.Completeness  `json:"completeness"`
	Consistency     contract.Consistency   `json:"consistency"`
	RedactionPolicy string                 `json:"redaction_policy"`
	Warnings        []contract.Warning     `json:"warnings"`
	Errors          []string               `json:"errors"`
}

// hashProjectionRuleset is ruleset without its operational version.
type hashProjectionRuleset struct {
	Path string              `json:"path"`
	Hash contract.SourceHash `json:"hash"`
}

func hashProjection(envelope contract.Bundle) hashProjectionEnvelope {
	provenance := envelope.Provenance
	var ruleset *hashProjectionRuleset
	if provenance.Ruleset != (contract.RulesetRef{}) {
		ruleset = &hashProjectionRuleset{Path: provenance.Ruleset.Path, Hash: provenance.Ruleset.Hash}
	}
	return hashProjectionEnvelope{
		SchemaVersion:            envelope.SchemaVersion,
		Subject:                  envelope.Subject,
		Images:                   envelope.Images,
		Evidence:                 envelope.Evidence,
		ObservedContainerClasses: envelope.ObservedContainerClasses,
		Provenance: hashProjectionProvenance{
			Ruleset:         ruleset,
			Inputs:          provenance.Inputs,
			APIScope:        provenance.APIScope,
			Coverage:        provenance.Coverage,
			Completeness:    provenance.Completeness,
			Consistency:     provenance.Consistency,
			RedactionPolicy: provenance.RedactionPolicy,
			Warnings:        provenance.Warnings,
			Errors:          provenance.Errors,
		},
	}
}
