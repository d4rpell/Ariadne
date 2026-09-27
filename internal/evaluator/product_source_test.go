package evaluator

import (
	"strings"
	"testing"

	"github.com/d4rpell/Ariadne/internal/rulepack"
	contract "github.com/d4rpell/Ariadne/pkg/evidence"
)

// wantCode asserts that an evaluation failed with one of the codes this
// package owns.
func wantCode(t *testing.T, err error, code ErrorCode) {
	t.Helper()
	if err == nil {
		t.Fatalf("expected %s, got no error", code)
	}
	if !IsCode(err, code) {
		t.Fatalf("expected %s, got %v", code, err)
	}
}

// wantRulepackCode asserts that an evaluation failed with a pack-phase code.
func wantRulepackCode(t *testing.T, err error, code rulepack.ErrorCode) {
	t.Helper()
	if err == nil {
		t.Fatalf("expected %s, got no error", code)
	}
	if !rulepack.Is(err, code) {
		t.Fatalf("expected %s, got %v", code, err)
	}
}

// baseSubject is the synthetic subject of the evaluator fixtures.
func baseSubject(t *testing.T) contract.Subject {
	t.Helper()
	return contract.Subject{
		ClusterAlias: clusterA,
		Namespace:    namespaceA,
		Kind:         "Pod",
		Name:         podNameA,
		UID:          uidA,
		OwnerChain:   "deployments/app",
	}
}

// Synthetic domain source of the product profile tests. The source is complete,
// explicit and entirely fabricated: it carries the technical fact and the basis
// of each proof, so a literal "complete" is never the only authority. There is
// no real advisory, cluster or customer data here.
const (
	domainSourceMapping   = "mapping.json"
	domainSourceArtifact  = "inspection.json"
	domainSourceVendor    = "advisory.json"
	domainLocatorMapping  = "records/mapping/0"
	domainLocatorArtifact = "records/artifact/0"
	domainLocatorVendor   = "records/proof/0"

	domainProductID      = "rhel"
	domainProductRelease = "9"
	domainOS             = "linux"
	domainArch           = "amd64"
	domainComponentID    = "openssl"
	domainPackageName    = "openssl"
	domainPackageArch    = "x86_64"
	domainEpoch          = "1"
	domainVersion        = "3.0.0"
	domainPackageRelease = "1.el9"
	domainAdvisoryID     = "RHSA-2026:0001"
	domainAdvisoryRev    = "1"
	domainBasisID        = "basis.openssl.CVE-2026-12345"
	domainBasisLocator   = "definitions/0/support"
	domainStatusVocab    = "redhat-severity-free"
	domainStatusValue    = "vendor-declared-status"
)

// syntheticSource is one fabricated source with its explicit identity.
type syntheticSource struct {
	name  string
	hash  contract.SourceHash
	stamp contract.Timestamp
}

func domainSources(t *testing.T) (mapping, artifact, vendor syntheticSource) {
	t.Helper()
	stamp := mustStamp(t, sourceObservedAt)
	return syntheticSource{
			name:  domainSourceMapping,
			hash:  independentSourceHash("mapping source body\n"),
			stamp: stamp,
		}, syntheticSource{
			name:  domainSourceArtifact,
			hash:  independentSourceHash("inspection source body\n"),
			stamp: stamp,
		}, syntheticSource{
			name:  domainSourceVendor,
			hash:  independentSourceHash("advisory source body\n"),
			stamp: stamp,
		}
}

func independentSourceHash(body string) contract.SourceHash {
	return contract.SourceHash(independentDocumentHash(body))
}

// domainItem builds one scalar domain item with an independent value hash.
func syntheticDomainItem(subject contract.Subject, container contract.ContainerName, itemType, value string, source syntheticSource, locator string, confidence contract.ProvenanceKind) contract.EvidenceItem {
	return evidenceItem(subject, container, itemType, value, source.name, string(source.hash), locator, source.stamp, confidence)
}

func mappingItems(t *testing.T, subject contract.Subject, container contract.ContainerName) []contract.EvidenceItem {
	t.Helper()
	source, _, _ := domainSources(t)
	make := func(field, value string) contract.EvidenceItem {
		return syntheticDomainItem(subject, container, "product_v1.mapping."+field, value, source, domainLocatorMapping, contract.ProvenanceDerived)
	}
	return []contract.EvidenceItem{
		make("method", mappingMethod),
		make("coverage", domainCoverage),
		make("vulnerability_id", cveA),
		make("scanner_package_type", mappingScannerPackageType),
		make("scanner_package_name", "openssl"),
		make("scanner_package_id", "pkg-1"),
		make("vendor", domainVendorRedhat),
		make("product_id", domainProductID),
		make("product_release", domainProductRelease),
		make("os", domainOS),
		make("architecture", domainArch),
		make("component_id", domainComponentID),
		make("package_name", domainPackageName),
		make("package_arch", domainPackageArch),
	}
}

func artifactItems(t *testing.T, subject contract.Subject, container contract.ContainerName) []contract.EvidenceItem {
	t.Helper()
	_, source, _ := domainSources(t)
	make := func(field, value string) contract.EvidenceItem {
		return syntheticDomainItem(subject, container, "product_v1.artifact."+field, value, source, domainLocatorArtifact, contract.ProvenanceObserved)
	}
	return []contract.EvidenceItem{
		make("method", artifactMethod),
		make("coverage", domainCoverage),
		make("artifact_digest", digestValue),
		make("digest_kind", artifactDigestKind),
		make("vendor", domainVendorRedhat),
		make("product_id", domainProductID),
		make("product_release", domainProductRelease),
		make("os", domainOS),
		make("architecture", domainArch),
		make("component_id", domainComponentID),
		make("package_name", domainPackageName),
		make("package_arch", domainPackageArch),
		make("epoch", domainEpoch),
		make("version", domainVersion),
		make("package_release", domainPackageRelease),
	}
}

// vendorItems builds one complete proof of the requested variant, including its
// technical support and the exclusive fields of that variant only.
func vendorItems(t *testing.T, subject contract.Subject, container contract.ContainerName, kind proofKind) []contract.EvidenceItem {
	t.Helper()
	_, _, source := domainSources(t)
	make := func(field, value string) contract.EvidenceItem {
		return syntheticDomainItem(subject, container, "product_v1.vendor."+field, value, source, domainLocatorVendor, contract.ProvenanceObserved)
	}
	items := []contract.EvidenceItem{
		make("method", vendorMethod),
		make("coverage", domainCoverage),
		make("vulnerability_id", cveA),
		make("advisory_id", domainAdvisoryID),
		make("advisory_revision", domainAdvisoryRev),
		make("vendor", domainVendorRedhat),
		make("product_id", domainProductID),
		make("product_release", domainProductRelease),
		make("os", domainOS),
		make("architecture", domainArch),
		make("component_id", domainComponentID),
		make("package_name", domainPackageName),
		make("package_arch", domainPackageArch),
		make("epoch", domainEpoch),
		make("version", domainVersion),
		make("package_release", domainPackageRelease),
		make("source_status_vocabulary", domainStatusVocab),
		make("source_status_value", domainStatusValue),
		make("proof_kind", string(kind)),
		make("basis_id", domainBasisID),
		make("basis_locator", domainBasisLocator),
	}
	switch kind {
	case proofVulnerableBuild:
		items = append(items,
			make("vulnerable_code_id", "code.vulnerable.1"),
			make("applicability", applicabilityUnconditional),
		)
	case proofFixedBuild:
		items = append(items,
			make("fixed_code_id", "code.fixed.1"),
			make("fix_id", "fix.1"),
			make("fix_membership", fixMembershipIncluded),
		)
	case proofCodeExcludedBuild:
		items = append(items,
			make("excluded_code_id", "code.excluded.1"),
			make("build_id", "build.1"),
			make("exclusion", exclusionNotBuiltOrShipped),
			make("exclusion_coverage", exclusionAllVulnerableCode),
		)
	}
	return items
}

// productBundle assembles the synthetic bundle of the product profile on Bundle
// 0.2, with the declared row and the observation of the target container.
func productBundle(t *testing.T, extra ...contract.EvidenceItem) contract.Bundle {
	t.Helper()
	bundle := baseBundle(t)
	bundle.SchemaVersion = rulepack.ProductBundleSchemaVersion
	bundle.Evidence = append(bundle.Evidence, extra...)
	return bundle
}

// productDomainContext pins the three synthetic sources exactly.
func productDomainContext(t *testing.T) DomainContext {
	t.Helper()
	mapping, artifact, vendor := domainSources(t)
	advisoryID := domainAdvisoryID
	revision := domainAdvisoryRev
	return DomainContext{
		MaximumEvidenceAgeSeconds: 30 * 24 * 60 * 60,
		SourcePins: []SourcePin{
			{Role: SourceRoleMapping, Source: mapping.name, SourceHash: mapping.hash},
			{Role: SourceRoleArtifact, Source: artifact.name, SourceHash: artifact.hash},
			{Role: SourceRoleVendor, Source: vendor.name, SourceHash: vendor.hash, AdvisoryID: &advisoryID, AdvisoryRevision: &revision},
		},
	}
}

// productRuleJSON declares one affirmative rule with the eleven requirements and
// its terminal.
func productRuleJSON(ruleID, emit, terminal string) string {
	return `{"rule_id":"` + ruleID + `",` +
		`"selector":{"coverage_method":"findings_import","vulnerability_id":"` + cveA + `"},` +
		`"requires":[` + productRequiresJSON() + `],` +
		`"checks":[{"check_id":"check.terminal","predicate":"` + terminal + `","params":{}}],` +
		`"on_missing_evidence":"under_investigation","emit":"` + emit + `"}`
}

func productRequiresJSON() string {
	return `"bundle.complete","finding.row",` +
		`"finding.package_type","finding.package_name","finding.package_id",` +
		`"image.bound_digest","image.known_platform",` +
		`"domain.mapping","domain.artifact","domain.vendor_proof","domain.current"`
}

func productPackDocument(rules ...string) string {
	return `{"schema_version":"0.1","profile":"` + rulepack.ProductEvidenceProfile + `","pack_id":"pack.one","version":7,` +
		`"valid_from":"2026-09-01T00:00:00Z","expires_at":"2026-12-31T23:59:59Z","rules":[` + strings.Join(rules, ",") + `]}`
}

// productRequest assembles one product-profile request with the control
// affirmative rule of the requested state.
func productRequest(t *testing.T, bundle contract.Bundle, rules ...string) Request {
	t.Helper()
	if len(rules) == 0 {
		rules = []string{productRuleJSON("rule.affected", rulepack.OutputAffected, "redhat_build_affected")}
	}
	document := productPackDocument(rules...)
	domain := productDomainContext(t)
	return Request{
		Bundle:             bundle,
		ExpectedBundleHash: mustBundleHash(t, bundle),
		Target:             baseTarget(t),
		PackBytes:          []byte(document),
		Admission:          baseContext(t, document),
		Domain:             &domain,
	}
}
