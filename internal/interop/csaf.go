package interop

import (
	"github.com/d4rpell/Ariadne/internal/evaluator"
	contract "github.com/d4rpell/Ariadne/pkg/evidence"
)

// CSAF returns the compact CSAF 2.0 VEX document of one validated result: a
// single product, a single vulnerability, an identity mapping of the closed
// product status, an inert human-readable impact statement where the standard
// requires one for known_not_affected, and a caller-supplied action statement
// for known_affected. Ariadne invents no remediation category and no
// machine-readable justification label. It emits no timestamp other than the
// caller-supplied issuance instant.
func CSAF(result evaluator.Result, bundle contract.Bundle, issuer CSAFIssuer, remediation *CSAFRemediation) ([]byte, error) {
	if err := admissible(result, bundle); err != nil {
		return nil, err
	}
	if err := validateCSAFIssuer(issuer); err != nil {
		return nil, err
	}
	if err := validateCSAFRemediation(result.ProductStatus, remediation); err != nil {
		return nil, err
	}
	if !isCVE(result.Target.VulnerabilityID) {
		return nil, problem(CodeInvalidResult)
	}
	statusName := csafStatusName(result.ProductStatus)
	product := productID(result.Target)
	instant := formatTimestamp(issuer.IssuedAt)
	vulnerability := csafVulnerability{
		CVE:           result.Target.VulnerabilityID,
		Title:         "Ariadne: " + statusName + " for " + result.Target.VulnerabilityID,
		ProductStatus: csafProductStatusFor(result.ProductStatus, product),
	}
	switch result.ProductStatus {
	case contract.ProductNotAffected:
		vulnerability.Threats = []csafThreat{{
			Category:   csafThreatImpact,
			Details:    csafImpactStatement,
			ProductIDs: []string{product},
		}}
	case contract.ProductAffected:
		vulnerability.Remediations = []csafRemediationItem{{
			Category:   remediation.Category,
			Details:    remediation.Details,
			ProductIDs: []string{product},
		}}
	}
	document := csafDocument{
		Document: csafDocumentMeta{
			Category:    csafCategory,
			SpecVersion: csafSpecVersion,
			Publisher: csafPublisher{
				Category:  csafPublisherCategory,
				Name:      issuer.PublisherName,
				Namespace: issuer.PublisherNamespace,
			},
			Title: "Ariadne VEX: " + result.Target.VulnerabilityID + " (" + statusName + ")",
			Tracking: csafTracking{
				ID:                 issuer.DocumentID,
				Status:             csafTrackingStatus,
				Version:            csafTrackingVersion,
				InitialReleaseDate: instant,
				CurrentReleaseDate: instant,
				RevisionHistory:    []csafRevision{{Date: instant, Number: csafRevisionNumber, Summary: csafTrackingSummary}},
			},
		},
		ProductTree: csafProductTree{
			FullProductNames: []csafFullProductName{{Name: product, ProductID: product}},
		},
		Vulnerabilities: []csafVulnerability{vulnerability},
	}
	return encode(document)
}

// csafStatusName is the identity mapping of the closed Ariadne status to the
// CSAF product_status property. admissible has already rejected any status
// outside the four, so the default is under_investigation.
func csafStatusName(status contract.ProductStatus) string {
	switch status {
	case contract.ProductAffected:
		return "known_affected"
	case contract.ProductNotAffected:
		return "known_not_affected"
	case contract.ProductFixed:
		return "fixed"
	default:
		return "under_investigation"
	}
}

// csafProductStatusFor carries the single status property the result maps to.
func csafProductStatusFor(status contract.ProductStatus, product string) csafProductStatus {
	ids := []string{product}
	switch status {
	case contract.ProductAffected:
		return csafProductStatus{KnownAffected: ids}
	case contract.ProductNotAffected:
		return csafProductStatus{KnownNotAffected: ids}
	case contract.ProductFixed:
		return csafProductStatus{Fixed: ids}
	default:
		return csafProductStatus{UnderInvestigation: ids}
	}
}
