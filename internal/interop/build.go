package interop

import (
	"bytes"
	"encoding/json"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/d4rpell/Ariadne/internal/evaluator"
	canonical "github.com/d4rpell/Ariadne/internal/evidence"
	"github.com/d4rpell/Ariadne/internal/rulepack"
	contract "github.com/d4rpell/Ariadne/pkg/evidence"
)

const (
	profileReadiness = "evidence-readiness-v1"
	profileProduct   = "product-evidence-v1"
)

// admissible runs the ordered phases 1 to 3 shared by both exports: the form of
// the result, the canonicalization of the bundle and the hash contrast that
// anchors the result to the bundle it names. Form is not authenticity: this
// check cannot claim that Evaluate ran or that the conclusion is substantiated.
func admissible(result evaluator.Result, bundle contract.Bundle) error {
	if err := validateResultForm(result); err != nil {
		return err
	}
	if _, err := canonical.CanonicalJSON(bundle); err != nil {
		return problem(CodeInvalidBundle)
	}
	hash, err := canonical.HashCanonicalJSON(bundle)
	if err != nil {
		return problem(CodeInvalidBundle)
	}
	if hash != result.BundleHash {
		return problem(CodeBundleHashMismatch)
	}
	return nil
}

// encode serializes one document: compact UTF-8 JSON, HTML escaping on, no BOM
// and no trailing newline. It reads no clock, no environment and no file.
func encode(document any) ([]byte, error) {
	var buffer bytes.Buffer
	encoder := json.NewEncoder(&buffer)
	encoder.SetEscapeHTML(true)
	if err := encoder.Encode(document); err != nil {
		return nil, problem(CodeRenderFailure)
	}
	return bytes.TrimSuffix(buffer.Bytes(), []byte("\n")), nil
}

// validateResultForm checks the closed subset of ADR-0032 §3.2 the export needs
// to avoid producing a malformed document. It is deliberately a subset of the
// report validator: it never resolves the catalogues the exports omit, and it
// keeps the two roots independent.
func validateResultForm(result evaluator.Result) error {
	if !boundedString(result.EngineVersion) || !boundedString(result.PackID) {
		return problem(CodeInvalidResult)
	}
	if result.ProfileVersion != profileReadiness && result.ProfileVersion != profileProduct {
		return problem(CodeInvalidResult)
	}
	if !isSha256(result.BundleHash) || !isSha256(result.PackHash) {
		return problem(CodeInvalidResult)
	}
	if result.PackVersion < 1 || result.PackVersion > rulepack.MaxVersion {
		return problem(CodeInvalidResult)
	}
	if err := validateTargetForm(result.Target); err != nil {
		return err
	}
	if err := validateStatusForm(result); err != nil {
		return err
	}
	if err := validateCandidatesForm(result.Candidates); err != nil {
		return err
	}
	for _, trace := range result.Rules {
		if err := validateRuleTraceForm(trace); err != nil {
			return err
		}
	}
	return nil
}

func validateTargetForm(target evaluator.Target) error {
	if !boundedString(string(target.SubjectUID)) || !boundedString(string(target.ContainerName)) ||
		!boundedString(target.VulnerabilityID) || !boundedString(target.Source) ||
		!boundedString(string(target.Locator)) {
		return problem(CodeInvalidResult)
	}
	switch target.ContainerClass {
	case contract.ContainerRegular, contract.ContainerInit, contract.ContainerEphemeral:
	default:
		return problem(CodeInvalidResult)
	}
	if !isSha256(string(target.SourceHash)) {
		return problem(CodeInvalidResult)
	}
	if !canonicalInstant(target.ObservedAt) {
		return problem(CodeInvalidResult)
	}
	return nil
}

// validateStatusForm enforces the status each profile can emit and the
// exploitability combination both implemented profiles leave unassessed. A
// fabricated combination is not form.
func validateStatusForm(result evaluator.Result) error {
	switch result.ProductStatus {
	case contract.ProductUnderInvestigation:
	case contract.ProductAffected, contract.ProductNotAffected, contract.ProductFixed:
		if result.ProfileVersion != profileProduct {
			return problem(CodeInvalidResult)
		}
	default:
		return problem(CodeInvalidResult)
	}
	if result.Exploitability != contract.ExploitabilityNotAssessed {
		return problem(CodeInvalidResult)
	}
	return nil
}

func validateCandidatesForm(candidates []evaluator.Candidate) error {
	for _, candidate := range candidates {
		if !boundedString(candidate.RuleID) {
			return problem(CodeInvalidResult)
		}
		switch candidate.ProductStatus {
		case contract.ProductAffected, contract.ProductNotAffected, contract.ProductFixed:
		default:
			return problem(CodeInvalidResult)
		}
		for _, reference := range candidate.EvidenceReferences {
			if reference.ItemIndex < 0 {
				return problem(CodeInvalidResult)
			}
		}
	}
	return nil
}

func validateRuleTraceForm(trace evaluator.RuleTrace) error {
	if !boundedString(trace.RuleID) {
		return problem(CodeInvalidResult)
	}
	switch trace.State {
	case evaluator.RuleNotApplicable, evaluator.RuleMissingEvidence, evaluator.RuleChecked:
	default:
		return problem(CodeInvalidResult)
	}
	return nil
}

// validateIssuer checks the OpenVEX document identity and issuance instant
// supplied by the caller. The canonical-UTC requirement is an Ariadne policy,
// not an OpenVEX requirement.
func validateIssuer(issuer Issuer) error {
	if !isIRI(issuer.DocumentID) {
		return problem(CodeInvalidIssuer)
	}
	if !boundedAuthor(issuer.Author) {
		return problem(CodeInvalidIssuer)
	}
	if !canonicalInstant(issuer.IssuedAt) {
		return problem(CodeInvalidIssuer)
	}
	return nil
}

// validateCSAFIssuer checks the CSAF document identity supplied by the caller:
// the tracking id (non-empty, no control character), the publisher name and its
// namespace IRI, and the canonical issuance instant. It is an Ariadne policy,
// not a CSAF rule, except where the CSAF schema requires the field to be present.
func validateCSAFIssuer(issuer CSAFIssuer) error {
	if !boundedAuthor(issuer.DocumentID) {
		return problem(CodeInvalidIssuer)
	}
	if !boundedAuthor(issuer.PublisherName) {
		return problem(CodeInvalidIssuer)
	}
	if !isIRI(issuer.PublisherNamespace) {
		return problem(CodeInvalidIssuer)
	}
	if !canonicalInstant(issuer.IssuedAt) {
		return problem(CodeInvalidIssuer)
	}
	return nil
}

// validateCSAFRemediation enforces the closed contract of the action statement:
// an affected product requires a caller-supplied remediation with a category
// from the CSAF enum and non-empty details; any other status requires none. A
// supplied remediation outside affected is a caller error, not silently ignored.
func validateCSAFRemediation(status contract.ProductStatus, remediation *CSAFRemediation) error {
	if status == contract.ProductAffected {
		if remediation == nil {
			return problem(CodeInvalidRemediation)
		}
		if !isCSAFRemediationCategory(remediation.Category) {
			return problem(CodeInvalidRemediation)
		}
		if !boundedAuthor(remediation.Details) {
			return problem(CodeInvalidRemediation)
		}
		return nil
	}
	if remediation != nil {
		return problem(CodeInvalidRemediation)
	}
	return nil
}

// isCSAFRemediationCategory is the closed CSAF remediation enum of §3.2.3.12.
func isCSAFRemediationCategory(value string) bool {
	switch value {
	case "mitigation", "no_fix_planned", "none_available", "vendor_fix", "workaround":
		return true
	default:
		return false
	}
}

// isCVE is the adapter's own check of the CVE grammar: it does not trust that
// the evaluator validated the identifier. "CVE-", at least four digits, a
// hyphen, and at least four digits. A non-CVE advisory identifier is never
// presented as a CVE.
func isCVE(value string) bool {
	const prefix = "CVE-"
	if !strings.HasPrefix(value, prefix) {
		return false
	}
	rest := value[len(prefix):]
	if len(rest) < 9 || rest[4] != '-' {
		return false
	}
	for index := 0; index < len(rest); index++ {
		if index == 4 {
			continue
		}
		if rest[index] < '0' || rest[index] > '9' {
			return false
		}
	}
	return true
}

// isIRI accepts an IRI for the document identifier: a scheme (letter followed by
// letters, digits, '+', '-' or '.') with a non-empty remainder, and no space or
// control character anywhere.
func isIRI(value string) bool {
	colon := strings.IndexByte(value, ':')
	if colon < 1 || colon == len(value)-1 {
		return false
	}
	scheme := value[:colon]
	if !isAlpha(scheme[0]) {
		return false
	}
	for index := 1; index < len(scheme); index++ {
		c := scheme[index]
		if !isAlpha(c) && !isDigit(c) && c != '+' && c != '-' && c != '.' {
			return false
		}
	}
	for index := 0; index < len(value); index++ {
		if value[index] <= 0x20 || value[index] == 0x7f {
			return false
		}
	}
	return true
}

// boundedAuthor accepts the issuer author: non-empty valid UTF-8 with no control
// character. It is emitted verbatim.
func boundedAuthor(value string) bool {
	if value == "" || !utf8.ValidString(value) {
		return false
	}
	for _, r := range value {
		if r < 0x20 || r == 0x7f {
			return false
		}
	}
	return true
}

func isAlpha(c byte) bool {
	return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
}

func isDigit(c byte) bool {
	return c >= '0' && c <= '9'
}

func boundedString(value string) bool {
	return value != "" && len(value) <= evaluator.MaxTargetStringBytes && utf8.ValidString(value)
}

// canonicalInstant accepts the instants this presentation can express: a
// non-zero UTC timestamp whose year is representable by the RFC3339 grammar. It
// reads no clock; the identity comparison is the same rule the wire validator
// applies.
func canonicalInstant(value contract.Timestamp) bool {
	if value.IsZero() || value.Location() != time.UTC {
		return false
	}
	if year := value.Year(); year < 0 || year > 9999 {
		return false
	}
	return true
}

// formatTimestamp is the presentation grammar of the issuance instant: canonical
// UTC with nanosecond precision and the Z offset.
func formatTimestamp(value contract.Timestamp) string {
	return value.UTC().Format(time.RFC3339Nano)
}

func stringPointer(value string) *string {
	copied := value
	return &copied
}
