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
