package interop

import (
	"crypto/sha256"
	"encoding/hex"

	"github.com/d4rpell/Ariadne/internal/evaluator"
	contract "github.com/d4rpell/Ariadne/pkg/evidence"
)

// OpenVEX returns the compact OpenVEX v0.2.0 document of one validated result:
// a single statement, an identity mapping of the closed product status, an inert
// conditional statement where the standard requires one, and an opaque local
// product identifier. It emits no justification, no local extension and no
// timestamp other than the caller-supplied issuance instant.
func OpenVEX(result evaluator.Result, bundle contract.Bundle, issuer Issuer) ([]byte, error) {
	if err := admissible(result, bundle); err != nil {
		return nil, err
	}
	if err := validateIssuer(issuer); err != nil {
		return nil, err
	}
	statement := openVEXStatement{
		Vulnerability: openVEXVulnerability{Name: result.Target.VulnerabilityID},
		Products:      []openVEXProduct{{ID: productID(result.Target)}},
		Status:        string(result.ProductStatus),
	}
	switch result.ProductStatus {
	case contract.ProductNotAffected:
		statement.ImpactStatement = stringPointer(openVEXImpactStatement)
	case contract.ProductAffected:
		statement.ActionStatement = stringPointer(openVEXActionStatement)
	}
	document := openVEXDocument{
		Context:    openVEXContext,
		ID:         issuer.DocumentID,
		Author:     issuer.Author,
		Timestamp:  formatTimestamp(issuer.IssuedAt),
		Version:    1,
		Tooling:    "ariadne/" + result.EngineVersion,
		Statements: []openVEXStatement{statement},
	}
	return encode(document)
}

// productID is the opaque local product identifier: a URN over the hash of the
// container identity. It is an IRI, deterministic and stable for the scope set,
// and it leaks no cluster identifier into a document that may be shared. It is
// not a purl or a CPE, and it is not map back without Ariadne.
func productID(target evaluator.Target) string {
	preimage := string(target.SubjectUID) + "\x1f" + string(target.ContainerClass) + "\x1f" + string(target.ContainerName)
	digest := sha256.Sum256([]byte(preimage))
	return "urn:ariadne:subject:sha256:" + hex.EncodeToString(digest[:])
}
