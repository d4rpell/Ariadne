package interop

import (
	contract "github.com/d4rpell/Ariadne/pkg/evidence"
)

// Issuer carries the OpenVEX document identity and issuance instant. OpenVEX
// requires @id, author and timestamp, and Ariadne cannot invent them: the
// evaluation instant (result.Admission.EvaluatedAt) is a replay parameter, never
// a declared issuance date, and this package reads no clock. The caller supplies
// the issuer, as casefile takes its instant explicitly.
type Issuer struct {
	DocumentID string
	Author     string
	IssuedAt   contract.Timestamp
}

// openVEXContext is the fixed OpenVEX v0.2.0 JSON-LD context.
const openVEXContext = "https://openvex.dev/ns/v0.2.0"

// The two conditionals OpenVEX requires are emitted as inert, constant text:
// they carry no evidence value, no warning message and no machine-readable
// claim. Ariadne cannot attribute a justification label (it holds none) nor a
// remediation action (it models none).
const (
	openVEXImpactStatement = "Not affected: the affirmative product evidence is recorded in the Ariadne evaluation record."
	openVEXActionStatement = "Affected: Ariadne models no remediation action; see the Ariadne evaluation record."
)

// openVEXDocument is the single-statement OpenVEX document. The field order is
// the normative key order; the conditional statement fields are emitted only
// when their status requires them.
type openVEXDocument struct {
	Context    string             `json:"@context"`
	ID         string             `json:"@id"`
	Author     string             `json:"author"`
	Timestamp  string             `json:"timestamp"`
	Version    int                `json:"version"`
	Tooling    string             `json:"tooling"`
	Statements []openVEXStatement `json:"statements"`
}

type openVEXStatement struct {
	Vulnerability   openVEXVulnerability `json:"vulnerability"`
	Products        []openVEXProduct     `json:"products"`
	Status          string               `json:"status"`
	ImpactStatement *string              `json:"impact_statement,omitempty"`
	ActionStatement *string              `json:"action_statement,omitempty"`
}

type openVEXVulnerability struct {
	Name string `json:"name"`
}

type openVEXProduct struct {
	ID string `json:"@id"`
}

// sarifLog is the single-run SARIF log. The field order is the normative key
// order; the local extensions travel only inside properties.ariadne.
type sarifLog struct {
	Version string     `json:"version"`
	Schema  string     `json:"$schema"`
	Runs    []sarifRun `json:"runs"`
}

type sarifRun struct {
	Tool    sarifTool     `json:"tool"`
	Results []sarifResult `json:"results"`
}

type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}

type sarifDriver struct {
	Name    string      `json:"name"`
	Version string      `json:"version"`
	Rules   []sarifRule `json:"rules"`
}

type sarifRule struct {
	ID                   string             `json:"id"`
	ShortDescription     sarifMessageString `json:"shortDescription"`
	DefaultConfiguration sarifConfiguration `json:"defaultConfiguration"`
}

type sarifMessageString struct {
	Text string `json:"text"`
}

type sarifConfiguration struct {
	Level string `json:"level"`
}

type sarifResult struct {
	RuleID     string             `json:"ruleId"`
	Level      string             `json:"level"`
	Message    sarifMessageString `json:"message"`
	Properties sarifProperties    `json:"properties"`
}

type sarifProperties struct {
	Ariadne sarifAriadne `json:"ariadne"`
}

// sarifAriadne is the namespaced property bag carrying the Ariadne-local
// extensions. It is not SARIF semantics.
type sarifAriadne struct {
	ProductStatus  string `json:"product_status"`
	Exploitability string `json:"exploitability"`
	ProfileVersion string `json:"profile_version"`
	BundleHash     string `json:"bundle_hash"`
}

// CSAFIssuer carries the CSAF 2.0 document identity Ariadne cannot invent: the
// tracking id, the publisher name and namespace, and the issuance instant. The
// evaluation instant (result.Admission.EvaluatedAt) is a replay parameter, never
// a declared issuance date, and this package reads no clock, so the caller
// supplies these, as it supplies the OpenVEX Issuer.
type CSAFIssuer struct {
	DocumentID         string
	PublisherName      string
	PublisherNamespace string
	IssuedAt           contract.Timestamp
}

// CSAFRemediation is the caller-supplied action statement of an affected
// product. Ariadne models no remediation, and every CSAF category asserts a
// factual state the evaluation does not carry, so the adapter refuses to invent
// one: it demands it from the caller and fails closed when it is absent.
type CSAFRemediation struct {
	Category string
	Details  string
}

// The fixed CSAF 2.0 document constants. category, csaf_version and status are
// not configurable: the document producer is a tool, not the product vendor.
const (
	csafCategory          = "csaf_vex"
	csafSpecVersion       = "2.0"
	csafPublisherCategory = "other"
	csafTrackingStatus    = "final"
	csafTrackingVersion   = "1"
	csafRevisionNumber    = "1"
	csafTrackingSummary   = "Ariadne export"
	csafThreatImpact      = "impact"
)

// csafImpactStatement is the frozen, non-probative impact statement emitted for
// known_not_affected. It names Ariadne's classification within the declared
// evidence scope; it asserts no universal absence and re-projects no sufficiency
// of evidence.
const csafImpactStatement = "Ariadne evaluation classified the product as known not affected within the declared evidence scope."

// csafDocument is the compact CSAF 2.0 VEX document. Field order is a local
// determinism requirement, not a CSAF rule.
type csafDocument struct {
	Document        csafDocumentMeta    `json:"document"`
	ProductTree     csafProductTree     `json:"product_tree"`
	Vulnerabilities []csafVulnerability `json:"vulnerabilities"`
}

type csafDocumentMeta struct {
	Category    string        `json:"category"`
	SpecVersion string        `json:"csaf_version"`
	Publisher   csafPublisher `json:"publisher"`
	Title       string        `json:"title"`
	Tracking    csafTracking  `json:"tracking"`
}

type csafPublisher struct {
	Category  string `json:"category"`
	Name      string `json:"name"`
	Namespace string `json:"namespace"`
}

type csafTracking struct {
	ID                 string         `json:"id"`
	Status             string         `json:"status"`
	Version            string         `json:"version"`
	InitialReleaseDate string         `json:"initial_release_date"`
	CurrentReleaseDate string         `json:"current_release_date"`
	RevisionHistory    []csafRevision `json:"revision_history"`
}

type csafRevision struct {
	Date    string `json:"date"`
	Number  string `json:"number"`
	Summary string `json:"summary"`
}

type csafProductTree struct {
	FullProductNames []csafFullProductName `json:"full_product_names"`
}

type csafFullProductName struct {
	Name      string `json:"name"`
	ProductID string `json:"product_id"`
}

type csafVulnerability struct {
	CVE           string                `json:"cve"`
	Title         string                `json:"title"`
	ProductStatus csafProductStatus     `json:"product_status"`
	Threats       []csafThreat          `json:"threats,omitempty"`
	Remediations  []csafRemediationItem `json:"remediations,omitempty"`
}

// csafProductStatus carries exactly one of the eight CSAF properties. The
// adapter emits the single one its closed status maps to.
type csafProductStatus struct {
	KnownAffected      []string `json:"known_affected,omitempty"`
	KnownNotAffected   []string `json:"known_not_affected,omitempty"`
	Fixed              []string `json:"fixed,omitempty"`
	UnderInvestigation []string `json:"under_investigation,omitempty"`
}

type csafThreat struct {
	Category   string   `json:"category"`
	Details    string   `json:"details"`
	ProductIDs []string `json:"product_ids"`
}

type csafRemediationItem struct {
	Category   string   `json:"category"`
	Details    string   `json:"details"`
	ProductIDs []string `json:"product_ids"`
}
