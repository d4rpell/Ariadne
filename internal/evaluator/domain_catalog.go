package evaluator

// domainFamily is the closed set of record families of ADR-0015 §5.1.
type domainFamily string

const (
	familyMapping  domainFamily = "mapping"
	familyArtifact domainFamily = "artifact"
	familyVendor   domainFamily = "vendor"
)

// domainField is the exact suffix of one type inside its family. The catalog is
// closed: the grammar alone does not register a name.
type domainField string

const domainTypePrefix = "product_v1."

// The catalog of ADR-0015 §6, transcribed as an exact list. 59 names:
// 14 mapping + 15 artifact + 21 vendor common + 2 vulnerable_build
// + 3 fixed_build + 4 code_excluded_build.
var (
	mappingFields = []domainField{
		"method", "coverage", "vulnerability_id", "scanner_package_type",
		"scanner_package_name", "scanner_package_id", "vendor", "product_id",
		"product_release", "os", "architecture", "component_id", "package_name",
		"package_arch",
	}
	artifactFields = []domainField{
		"method", "coverage", "artifact_digest", "digest_kind", "vendor",
		"product_id", "product_release", "os", "architecture", "component_id",
		"package_name", "package_arch", "epoch", "version", "package_release",
	}
	vendorCommonFields = []domainField{
		"method", "coverage", "vulnerability_id", "advisory_id",
		"advisory_revision", "vendor", "product_id", "product_release", "os",
		"architecture", "component_id", "package_name", "package_arch", "epoch",
		"version", "package_release", "source_status_vocabulary",
		"source_status_value", "proof_kind", "basis_id", "basis_locator",
	}
	vendorVulnerableFields = []domainField{"vulnerable_code_id", "applicability"}
	vendorFixedFields      = []domainField{"fixed_code_id", "fix_id", "fix_membership"}
	vendorExcludedFields   = []domainField{"excluded_code_id", "build_id", "exclusion", "exclusion_coverage"}
)

// proofKind is the closed set of vendor proof variants (ADR-0015 §6.3).
type proofKind string

const (
	proofVulnerableBuild   proofKind = "vulnerable_build"
	proofFixedBuild        proofKind = "fixed_build"
	proofCodeExcludedBuild proofKind = "code_excluded_build"
)

// domainConstants of ADR-0015 §6.
const (
	domainVendorRedhat = "redhat"
	domainCoverage     = "complete"

	mappingMethod  = "product-component-map-v1"
	artifactMethod = "artifact-package-inspection-v1"
	vendorMethod   = "vendor-exact-build-proof-v1"

	mappingScannerPackageType = "rpm"
	artifactDigestKind        = "platform_manifest"

	applicabilityUnconditional = "unconditional_for_exact_build"
	fixMembershipIncluded      = "included_in_exact_build"
	exclusionNotBuiltOrShipped = "not_built_or_shipped"
	exclusionAllVulnerableCode = "all_vulnerable_code_for_component_cve"
)

// recognizeDomainType classifies one type string against the closed catalog. The
// boolean is false for an unknown family, an unregistered suffix, a suffix of
// another variant and any shape outside the ASCII grammar. The caller checks the
// reserved prefix separately, so an unknown name inside the namespace is not
// confused with a foreign type.
func recognizeDomainType(value string) (domainFamily, domainField, bool) {
	if len(value) > maxDomainTypeBytes || len(value) <= len(domainTypePrefix) {
		return "", "", false
	}
	if value[:len(domainTypePrefix)] != domainTypePrefix {
		return "", "", false
	}
	rest := value[len(domainTypePrefix):]
	separator := indexByte(rest, '.')
	if separator <= 0 || separator == len(rest)-1 {
		return "", "", false
	}
	family := domainFamily(rest[:separator])
	field := domainField(rest[separator+1:])
	if !validDomainFieldGrammar(string(field)) {
		return "", "", false
	}
	switch family {
	case familyMapping:
		if containsField(mappingFields, field) {
			return family, field, true
		}
	case familyArtifact:
		if containsField(artifactFields, field) {
			return family, field, true
		}
	case familyVendor:
		if containsField(vendorCommonFields, field) || isVendorExclusiveField(field) {
			return family, field, true
		}
	}
	return "", "", false
}

// maxDomainTypeBytes is the grammar ceiling of ADR-0015 §5.1: the prefix, the
// family and a suffix of at most 32 bytes.
const maxDomainTypeBytes = 52

// validDomainFieldGrammar is [a-z][a-z0-9_]{0,31}: ASCII, 1-32 bytes, lowercase
// first, no uppercase, no additional dot.
func validDomainFieldGrammar(field string) bool {
	if len(field) == 0 || len(field) > 32 {
		return false
	}
	if field[0] < 'a' || field[0] > 'z' {
		return false
	}
	for index := 1; index < len(field); index++ {
		c := field[index]
		switch {
		case c >= 'a' && c <= 'z', c >= '0' && c <= '9', c == '_':
		default:
			return false
		}
	}
	return true
}

func containsField(fields []domainField, wanted domainField) bool {
	for _, field := range fields {
		if field == wanted {
			return true
		}
	}
	return false
}

// isVendorExclusiveField reports whether a suffix belongs to exactly one of the
// three proof variants.
func isVendorExclusiveField(field domainField) bool {
	return containsField(vendorVulnerableFields, field) ||
		containsField(vendorFixedFields, field) ||
		containsField(vendorExcludedFields, field)
}

// exclusiveFieldsFor returns the exclusive suffixes of one variant.
func exclusiveFieldsFor(kind proofKind) []domainField {
	switch kind {
	case proofVulnerableBuild:
		return vendorVulnerableFields
	case proofFixedBuild:
		return vendorFixedFields
	case proofCodeExcludedBuild:
		return vendorExcludedFields
	}
	return nil
}

// fieldsForVariant returns the complete required field list of one vendor
// variant: the common fields plus its own exclusive ones.
func fieldsForVariant(kind proofKind) []domainField {
	fields := append([]domainField{}, vendorCommonFields...)
	return append(fields, exclusiveFieldsFor(kind)...)
}

// isDomainType reports whether a type string carries the reserved prefix. The
// caller must still recognize it: an unknown name inside the namespace blocks an
// affirmation instead of being ignored.
func isDomainType(value string) bool {
	return len(value) >= len(domainTypePrefix) && value[:len(domainTypePrefix)] == domainTypePrefix
}

func indexByte(value string, wanted byte) int {
	for index := 0; index < len(value); index++ {
		if value[index] == wanted {
			return index
		}
	}
	return -1
}
