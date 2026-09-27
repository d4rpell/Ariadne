package evaluator

import (
	"sort"

	"github.com/d4rpell/Ariadne/internal/rulepack"
	contract "github.com/d4rpell/Ariadne/pkg/evidence"
)

// domainItem is one recognized scalar item of the domain namespace, resolved
// against the canonical evidence array.
type domainItem struct {
	family     domainFamily
	field      domainField
	value      string
	hasValue   bool
	itemIndex  int
	confidence contract.ProvenanceKind
	source     string
	sourceHash contract.SourceHash
	locator    contract.SourceLocator
	observedAt contract.Timestamp
}

// recordKey is the complete provenance tuple of ADR-0015 §5.2. Two groups that
// differ in any member are different records: fields are never completed from
// another group.
type recordKey struct {
	family     domainFamily
	source     string
	sourceHash contract.SourceHash
	locator    contract.SourceLocator
	observedAt contract.Timestamp
}

// domainRecord keeps every occurrence of every field of one provenance group,
// before any interpretation. Materialising the typed record only happens after
// uniqueness and shape are verified.
type domainRecord struct {
	key     recordKey
	fields  map[domainField][]domainItem
	indices []int
	refs    []EvidenceReference
}

// add stores one item, preserving duplicates and every reference.
func (record *domainRecord) add(item domainItem) {
	if record.fields == nil {
		record.fields = make(map[domainField][]domainItem)
	}
	record.fields[item.field] = append(record.fields[item.field], item)
	record.indices = append(record.indices, item.itemIndex)
	record.refs = append(record.refs, EvidenceReference{ItemIndex: item.itemIndex})
}

// single returns the unique value of one field. ok is false when the field is
// absent, carries no value, carries two different values, carries a value
// outside the scalar rule, or carries an occurrence whose confidence is not the
// family's contractual one (ADR-0015 §5.2). Every occurrence is checked, not
// just the first: a duplicate with the wrong confidence or a malformed value
// destroys the interpretation of the record.
func (record *domainRecord) single(field domainField) (string, bool) {
	occurrences := record.fields[field]
	if len(occurrences) == 0 {
		return "", false
	}
	wanted := record.key.family.expectedConfidence()
	value := ""
	seen := false
	for _, occurrence := range occurrences {
		if !occurrence.hasValue || occurrence.confidence != wanted {
			return "", false
		}
		if !domainStringOK(occurrence.value) {
			return "", false
		}
		if !seen {
			value = occurrence.value
			seen = true
			continue
		}
		if occurrence.value != value {
			return "", false
		}
	}
	return value, true
}

// expectedConfidence is the contractual confidence of one family: mapping is
// derived, artifact and vendor are observed (ADR-0015 §§6.1-6.3).
func (family domainFamily) expectedConfidence() contract.ProvenanceKind {
	if family == familyMapping {
		return contract.ProvenanceDerived
	}
	return contract.ProvenanceObserved
}

// constant reports whether a field is present and equal to the exact constant.
func (record *domainRecord) constant(field domainField, wanted string) bool {
	value, ok := record.single(field)
	return ok && value == wanted
}

// domainIndex is every recognized domain item of the target scope, grouped by
// provenance tuple. Unknown names inside the reserved prefix are recorded as
// such, because they block an affirmation instead of being ignored.
type domainIndex struct {
	records    []*domainRecord
	unknown    []int
	itemCount  int
	recognized int
}

// indexDomainRecords walks the canonical evidence array once and groups the
// domain items of the target scope. Items of another scope are not operands and
// are not even inspected for shape.
func indexDomainRecords(bundle contract.Bundle, target Target) domainIndex {
	var index domainIndex
	positions := make(map[recordKey]int)
	for itemIndex, item := range bundle.Evidence {
		if item.Scope.SubjectUID != target.SubjectUID || item.Scope.ContainerName != target.ContainerName {
			continue
		}
		if !isDomainType(item.Type) {
			continue
		}
		// A validated bundle always carries observed_at; the guard keeps this walk
		// safe on any other input instead of panicking.
		if item.ObservedAt == nil {
			continue
		}
		index.itemCount++
		family, field, ok := recognizeDomainType(item.Type)
		if !ok {
			index.unknown = append(index.unknown, itemIndex)
			continue
		}
		key := recordKey{
			family:     family,
			source:     item.Source,
			sourceHash: item.SourceHash,
			locator:    item.Locator,
			observedAt: *item.ObservedAt,
		}
		position, exists := positions[key]
		if !exists {
			index.records = append(index.records, &domainRecord{key: key})
			position = len(index.records) - 1
			positions[key] = position
		}
		recognized := domainItem{
			family:     family,
			field:      field,
			itemIndex:  itemIndex,
			confidence: item.Confidence,
			source:     item.Source,
			sourceHash: item.SourceHash,
			locator:    item.Locator,
			observedAt: *item.ObservedAt,
		}
		if item.Value != nil {
			recognized.value = *item.Value
			recognized.hasValue = true
		}
		index.records[position].add(recognized)
		index.recognized++
	}
	sort.Slice(index.unknown, func(i, j int) bool { return index.unknown[i] < index.unknown[j] })
	for _, record := range index.records {
		sort.Ints(record.indices)
	}
	return index
}

// mappingRecord is one fully interpretable mapping group (ADR-0015 §6.1).
type mappingRecord struct {
	record          *domainRecord
	vulnerabilityID string
	scannerType     string
	scannerName     string
	scannerID       string
	vendor          string
	productID       string
	productRelease  string
	os              string
	architecture    string
	componentID     string
	packageName     string
	packageArch     string
	refs            []EvidenceReference
}

// artifactRecord is one fully interpretable artifact group (ADR-0015 §6.2).
type artifactRecord struct {
	record         *domainRecord
	artifactDigest string
	digestKind     string
	vendor         string
	productID      string
	productRelease string
	os             string
	architecture   string
	componentID    string
	packageName    string
	packageArch    string
	epoch          string
	version        string
	packageRelease string
	refs           []EvidenceReference
}

// vendorProof is one fully interpretable vendor group of a known variant
// (ADR-0015 §6.3).
type vendorProof struct {
	record             *domainRecord
	kind               proofKind
	vulnerabilityID    string
	advisoryID         string
	advisoryRevision   string
	vendor             string
	productID          string
	productRelease     string
	os                 string
	architecture       string
	componentID        string
	packageName        string
	packageArch        string
	epoch              string
	version            string
	packageRelease     string
	statusVocabulary   string
	statusValue        string
	basisID            string
	basisLocator       string
	applicability      string
	fixMembership      string
	exclusion          string
	exclusionCoverage  string
	exclusiveCodeField domainField
	exclusiveCodeID    string
	refs               []EvidenceReference
}

// domainRecords is the typed view of one index. Each slice keeps only fully
// interpretable records; incomplete or contradictory groups stay in the index
// (and in the references) as unknown candidates.
type domainRecords struct {
	mappings  []mappingRecord
	artifacts []artifactRecord
	vendors   []vendorProof
	// unusable are the references of groups inside the reserved namespace that
	// the closed vocabulary cannot interpret.
	unusable []EvidenceReference
}

// decodeDomainRecords materialises the typed records. It never repairs: a group
// with a missing field, a wrong constant, a wrong confidence or a foreign
// exclusive field is not interpreted.
func decodeDomainRecords(index domainIndex) domainRecords {
	var decoded domainRecords
	for _, record := range index.records {
		interpreted := false
		if !recordProvenanceOK(record) {
			// The provenance of a domain record is domain data: a source or a
			// locator outside the scalar rule leaves the group uninterpretable,
			// exactly like a malformed value.
			decoded.unusable = append(decoded.unusable, record.refs...)
			continue
		}
		switch record.key.family {
		case familyMapping:
			if mapping, ok := decodeMapping(record); ok {
				decoded.mappings = append(decoded.mappings, mapping)
				interpreted = true
			}
		case familyArtifact:
			if artifact, ok := decodeArtifact(record); ok {
				decoded.artifacts = append(decoded.artifacts, artifact)
				interpreted = true
			}
		case familyVendor:
			if proof, ok := decodeVendorProof(record); ok {
				decoded.vendors = append(decoded.vendors, proof)
				interpreted = true
			}
		}
		// A group inside the namespace that cannot be interpreted is not ignored:
		// nothing proves it foreign, so it blocks an affirmation (ADR-0015 §5.1).
		if !interpreted {
			decoded.unusable = append(decoded.unusable, record.refs...)
		}
	}
	sortReferencesInPlace(decoded.unusable)
	return decoded
}

// recordProvenanceOK applies the scalar rule of ADR-0015 §5.2 to the provenance
// members of the group. The wire validator accepts a longer or control-bearing
// locator, so the profile boundary has to refuse it.
func recordProvenanceOK(record *domainRecord) bool {
	if !domainStringOK(record.key.source) {
		return false
	}
	return domainStringOK(string(record.key.locator))
}

// recordHasExactFields reports whether the record declares every required field
// exactly once and no field outside the list. A field of another family or
// variant is not ignored: it invalidates the interpretation of the record.
func recordHasExactFields(record *domainRecord, required []domainField) bool {
	for _, field := range required {
		if _, ok := record.single(field); !ok {
			return false
		}
	}
	for field := range record.fields {
		if !containsField(required, field) {
			return false
		}
	}
	return true
}

func decodeMapping(record *domainRecord) (mappingRecord, bool) {
	if !record.constant("method", mappingMethod) || !record.constant("coverage", domainCoverage) {
		return mappingRecord{}, false
	}
	if !record.constant("vendor", domainVendorRedhat) || !record.constant("scanner_package_type", mappingScannerPackageType) {
		return mappingRecord{}, false
	}
	if !recordHasExactFields(record, mappingFields) {
		return mappingRecord{}, false
	}
	mapping := mappingRecord{record: record, refs: record.refs}
	var found bool
	if mapping.vulnerabilityID, found = record.single("vulnerability_id"); !found {
		return mappingRecord{}, false
	}
	if mapping.scannerName, found = record.single("scanner_package_name"); !found {
		return mappingRecord{}, false
	}
	if mapping.scannerID, found = record.single("scanner_package_id"); !found {
		return mappingRecord{}, false
	}
	if mapping.productID, found = record.single("product_id"); !found {
		return mappingRecord{}, false
	}
	if mapping.productRelease, found = record.single("product_release"); !found {
		return mappingRecord{}, false
	}
	if mapping.os, found = record.single("os"); !found {
		return mappingRecord{}, false
	}
	if mapping.architecture, found = record.single("architecture"); !found {
		return mappingRecord{}, false
	}
	if mapping.componentID, found = record.single("component_id"); !found {
		return mappingRecord{}, false
	}
	if mapping.packageName, found = record.single("package_name"); !found {
		return mappingRecord{}, false
	}
	if mapping.packageArch, found = record.single("package_arch"); !found {
		return mappingRecord{}, false
	}
	mapping.scannerType = mappingScannerPackageType
	mapping.vendor = domainVendorRedhat
	return mapping, true
}

func decodeArtifact(record *domainRecord) (artifactRecord, bool) {
	if !record.constant("method", artifactMethod) || !record.constant("coverage", domainCoverage) {
		return artifactRecord{}, false
	}
	if !record.constant("vendor", domainVendorRedhat) || !record.constant("digest_kind", artifactDigestKind) {
		return artifactRecord{}, false
	}
	if !recordHasExactFields(record, artifactFields) {
		return artifactRecord{}, false
	}
	artifact := artifactRecord{record: record, refs: record.refs}
	var found bool
	if artifact.artifactDigest, found = record.single("artifact_digest"); !found {
		return artifactRecord{}, false
	}
	if artifact.productID, found = record.single("product_id"); !found {
		return artifactRecord{}, false
	}
	if artifact.productRelease, found = record.single("product_release"); !found {
		return artifactRecord{}, false
	}
	if artifact.os, found = record.single("os"); !found {
		return artifactRecord{}, false
	}
	if artifact.architecture, found = record.single("architecture"); !found {
		return artifactRecord{}, false
	}
	if artifact.componentID, found = record.single("component_id"); !found {
		return artifactRecord{}, false
	}
	if artifact.packageName, found = record.single("package_name"); !found {
		return artifactRecord{}, false
	}
	if artifact.packageArch, found = record.single("package_arch"); !found {
		return artifactRecord{}, false
	}
	if artifact.epoch, found = record.single("epoch"); !found || !validEpoch(artifact.epoch) {
		return artifactRecord{}, false
	}
	if artifact.version, found = record.single("version"); !found {
		return artifactRecord{}, false
	}
	if artifact.packageRelease, found = record.single("package_release"); !found {
		return artifactRecord{}, false
	}
	artifact.digestKind = artifactDigestKind
	artifact.vendor = domainVendorRedhat
	return artifact, true
}

func decodeVendorProof(record *domainRecord) (vendorProof, bool) {
	if !record.constant("method", vendorMethod) || !record.constant("coverage", domainCoverage) {
		return vendorProof{}, false
	}
	if !record.constant("vendor", domainVendorRedhat) {
		return vendorProof{}, false
	}
	kindValue, ok := record.single("proof_kind")
	if !ok {
		return vendorProof{}, false
	}
	kind := proofKind(kindValue)
	exclusive := exclusiveFieldsFor(kind)
	if exclusive == nil {
		return vendorProof{}, false
	}
	// Exactly one variant: the common fields plus this variant's exclusive ones,
	// and no field of another variant.
	for _, other := range []proofKind{proofVulnerableBuild, proofFixedBuild, proofCodeExcludedBuild} {
		if other == kind {
			continue
		}
		for _, field := range exclusiveFieldsFor(other) {
			if _, present := record.fields[field]; present {
				return vendorProof{}, false
			}
		}
	}
	if !recordHasExactFields(record, fieldsForVariant(kind)) {
		return vendorProof{}, false
	}
	proof := vendorProof{record: record, kind: kind, refs: record.refs}
	var found bool
	if proof.vulnerabilityID, found = record.single("vulnerability_id"); !found {
		return vendorProof{}, false
	}
	if proof.advisoryID, found = record.single("advisory_id"); !found {
		return vendorProof{}, false
	}
	if proof.advisoryRevision, found = record.single("advisory_revision"); !found {
		return vendorProof{}, false
	}
	if proof.productID, found = record.single("product_id"); !found {
		return vendorProof{}, false
	}
	if proof.productRelease, found = record.single("product_release"); !found {
		return vendorProof{}, false
	}
	if proof.os, found = record.single("os"); !found {
		return vendorProof{}, false
	}
	if proof.architecture, found = record.single("architecture"); !found {
		return vendorProof{}, false
	}
	if proof.componentID, found = record.single("component_id"); !found {
		return vendorProof{}, false
	}
	if proof.packageName, found = record.single("package_name"); !found {
		return vendorProof{}, false
	}
	if proof.packageArch, found = record.single("package_arch"); !found {
		return vendorProof{}, false
	}
	if proof.epoch, found = record.single("epoch"); !found || !validEpoch(proof.epoch) {
		return vendorProof{}, false
	}
	if proof.version, found = record.single("version"); !found {
		return vendorProof{}, false
	}
	if proof.packageRelease, found = record.single("package_release"); !found {
		return vendorProof{}, false
	}
	if proof.statusVocabulary, found = record.single("source_status_vocabulary"); !found {
		return vendorProof{}, false
	}
	if proof.statusValue, found = record.single("source_status_value"); !found {
		return vendorProof{}, false
	}
	if proof.basisID, found = record.single("basis_id"); !found {
		return vendorProof{}, false
	}
	if proof.basisLocator, found = record.single("basis_locator"); !found {
		return vendorProof{}, false
	}
	switch kind {
	case proofVulnerableBuild:
		if !record.constant("applicability", applicabilityUnconditional) {
			return vendorProof{}, false
		}
		if proof.exclusiveCodeID, found = record.single("vulnerable_code_id"); !found {
			return vendorProof{}, false
		}
		proof.exclusiveCodeField = "vulnerable_code_id"
		proof.applicability = applicabilityUnconditional
	case proofFixedBuild:
		if !record.constant("fix_membership", fixMembershipIncluded) {
			return vendorProof{}, false
		}
		if proof.exclusiveCodeID, found = record.single("fixed_code_id"); !found {
			return vendorProof{}, false
		}
		if _, found = record.single("fix_id"); !found {
			return vendorProof{}, false
		}
		proof.exclusiveCodeField = "fixed_code_id"
		proof.fixMembership = fixMembershipIncluded
	case proofCodeExcludedBuild:
		if !record.constant("exclusion", exclusionNotBuiltOrShipped) {
			return vendorProof{}, false
		}
		if !record.constant("exclusion_coverage", exclusionAllVulnerableCode) {
			return vendorProof{}, false
		}
		if proof.exclusiveCodeID, found = record.single("excluded_code_id"); !found {
			return vendorProof{}, false
		}
		if _, found = record.single("build_id"); !found {
			return vendorProof{}, false
		}
		proof.exclusiveCodeField = "excluded_code_id"
		proof.exclusion = exclusionNotBuiltOrShipped
		proof.exclusionCoverage = exclusionAllVulnerableCode
	}
	proof.vendor = domainVendorRedhat
	return proof, true
}

// validEpoch is the canonical non-negative decimal of ADR-0015 §5.2: no sign,
// no leading zero except the single digit 0.
func validEpoch(value string) bool {
	if len(value) == 0 || len(value) > rulepack.MaxStringBytes {
		return false
	}
	for index := 0; index < len(value); index++ {
		if value[index] < '0' || value[index] > '9' {
			return false
		}
	}
	return len(value) == 1 || value[0] != '0'
}
