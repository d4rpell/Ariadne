package platform

import (
	"bytes"
	"html/template"
)

// banner is the fixed, visible limits notice of the read-only platform. It is a
// constant of this package, never data from any file.
const banner = "read-only projection of one human decision record; not a risk acceptance, not an approval, not a security statement; not a source of truth"

// RenderDashboard returns the standalone dashboard document: a fixed header, a
// derived summary and one row per entry in append order. Every value is emitted
// in text context by html/template; the only link is /decision/{sequence}, built
// from the numeric Sequence inside the constant template, never from a UID, CVE,
// source or locator. The document is UTF-8, lang="en", has no JavaScript and
// references no external resource.
func RenderDashboard(model Model) ([]byte, error) {
	var buffer bytes.Buffer
	if err := dashboardDocument.Execute(&buffer, dashboardView(model)); err != nil {
		return nil, err
	}
	return buffer.Bytes(), nil
}

// RenderDecision returns the detail document of the entry with the given
// sequence. The second result is false when no entry carries it; the caller
// answers 404 in that case.
func RenderDecision(model Model, sequence uint64) ([]byte, bool, error) {
	entry, found := model.Entry(sequence)
	if !found {
		return nil, false, nil
	}
	var buffer bytes.Buffer
	if err := decisionDocument.Execute(&buffer, decisionViewOf(model, entry)); err != nil {
		return nil, false, err
	}
	return buffer.Bytes(), true, nil
}

type dashboardPage struct {
	Banner      string
	AsOf        string
	RecordCount int
	HeadHash    string
	Summary     summaryView
	Entries     []rowView
}

// summaryView is a derived count over the projected entries: it adds no state
// that is not already present in the entries, and it never invents a product
// status or an exploitability value.
type summaryView struct {
	Effective  int
	Pending    int
	Expired    int
	Superseded int
	Accepted   int
	Deferred   int
	Rejected   int
}

type rowView struct {
	Sequence        uint64
	SubjectUID      string
	ContainerClass  string
	ContainerName   string
	VulnerabilityID string
	RiskDecision    string
	DecidedAt       string
	ExpiresAt       string
	Standing        string
	SupersededBy    string
	Anomalies       []string
}

type decisionPage struct {
	Banner            string
	Sequence          uint64
	Hash              string
	PreviousHash      string
	RiskDecision      string
	Owner             string
	Approver          string
	Rationale         string
	DecidedAt         string
	ExpiresAt         string
	Standing          string
	SupersededBy      string
	Anomalies         []string
	BundleHash        string
	SubjectUID        string
	ContainerName     string
	ContainerClass    string
	VulnerabilityID   string
	ResultFingerprint string
	Controls          []string
}

func dashboardView(model Model) dashboardPage {
	page := dashboardPage{
		Banner:      banner,
		AsOf:        explicitText(model.AsOf),
		RecordCount: model.RecordCount,
		HeadHash:    explicitText(model.HeadHash),
		Entries:     make([]rowView, 0, len(model.Entries)),
	}
	for position := range model.Entries {
		entry := model.Entries[position]
		switch entry.Standing {
		case "effective":
			page.Summary.Effective++
		case "pending":
			page.Summary.Pending++
		case "expired":
			page.Summary.Expired++
		case "superseded":
			page.Summary.Superseded++
		}
		switch entry.RiskDecision {
		case "accepted":
			page.Summary.Accepted++
		case "deferred":
			page.Summary.Deferred++
		case "rejected":
			page.Summary.Rejected++
		}
		page.Entries = append(page.Entries, rowView{
			Sequence:        entry.Sequence,
			SubjectUID:      explicitText(entry.Scope.SubjectUID),
			ContainerClass:  explicitText(entry.Scope.ContainerClass),
			ContainerName:   explicitText(entry.Scope.ContainerName),
			VulnerabilityID: explicitText(entry.Scope.VulnerabilityID),
			RiskDecision:    explicitText(entry.RiskDecision),
			DecidedAt:       explicitText(entry.DecidedAt),
			ExpiresAt:       explicitPointer(entry.ExpiresAt),
			Standing:        explicitText(entry.Standing),
			SupersededBy:    explicitPointer(entry.SupersededBy),
			Anomalies:       entry.Anomalies,
		})
	}
	return page
}

func decisionViewOf(model Model, entry Entry) decisionPage {
	return decisionPage{
		Banner:            banner,
		Sequence:          entry.Sequence,
		Hash:              explicitText(entry.Hash),
		PreviousHash:      explicitPointer(entry.PreviousHash),
		RiskDecision:      explicitText(entry.RiskDecision),
		Owner:             explicitText(entry.Owner),
		Approver:          explicitText(entry.Approver),
		Rationale:         explicitText(entry.Rationale),
		DecidedAt:         explicitText(entry.DecidedAt),
		ExpiresAt:         explicitPointer(entry.ExpiresAt),
		Standing:          explicitText(entry.Standing),
		SupersededBy:      explicitPointer(entry.SupersededBy),
		Anomalies:         entry.Anomalies,
		BundleHash:        explicitText(entry.Scope.BundleHash),
		SubjectUID:        explicitText(entry.Scope.SubjectUID),
		ContainerName:     explicitText(entry.Scope.ContainerName),
		ContainerClass:    explicitText(entry.Scope.ContainerClass),
		VulnerabilityID:   explicitText(entry.Scope.VulnerabilityID),
		ResultFingerprint: explicitPointer(entry.Scope.ResultFingerprint),
		Controls:          entry.Controls,
	}
}

// explicitText renders an absent optional value as the literal null, so the page
// states absence instead of leaving the reader to infer it from a blank cell.
func explicitText(value string) string {
	if value == "" {
		return "null"
	}
	return value
}

func explicitPointer(value *string) string {
	if value == nil {
		return "null"
	}
	return explicitText(*value)
}

const documentStyle = `
:root {
	color: #18212b;
	background: #f5f7f9;
	font-family: system-ui, sans-serif;
	line-height: 1.5;
	--standing-effective-text: #185b35;
	--standing-effective-background: #eaf4ee;
	--standing-pending-text: #715007;
	--standing-pending-background: #fff4d8;
	--standing-expired-text: #912b2b;
	--standing-expired-background: #faeded;
	--standing-superseded-text: #4b5563;
	--standing-superseded-background: #edf0f3;
	--risk-accepted-text: #185b35;
	--risk-accepted-background: #eaf4ee;
	--risk-deferred-text: #715007;
	--risk-deferred-background: #fff4d8;
	--risk-rejected-text: #912b2b;
	--risk-rejected-background: #faeded;
}
* { box-sizing: border-box; }
body { margin: 0; }
main { max-width: 1480px; margin: 0 auto; padding: 24px; }
h1 { margin: 0 0 16px; font-size: 1.75rem; }
h2 { margin: 0 0 12px; font-size: 1.125rem; }
p { margin: 0 0 16px; }
section { margin-top: 28px; }
.notice {
	padding: 12px 16px;
	border-left: 4px solid #4b5563;
	background: #edf0f3;
	font-size: 0.875rem;
}
.breadcrumb { color: #4b5563; font-size: 0.875rem; }
.summary-grid {
	display: grid;
	grid-template-columns: repeat(2, minmax(0, 1fr));
	gap: 16px;
}
table { width: 100%; border-collapse: collapse; background: #ffffff; }
caption { padding: 0 0 8px; text-align: left; font-weight: 600; }
th, td {
	padding: 8px;
	border: 1px solid #cad0d7;
	text-align: left;
	vertical-align: top;
	overflow-wrap: anywhere;
}
th { font-weight: 600; background: #f0f2f4; white-space: nowrap; }
tbody tr { transition: background-color 160ms ease; }
tbody tr:hover { background-color: #f5f7f9; }
.table-scroll { overflow-x: auto; }
.records { min-width: 1200px; font-size: 0.8125rem; }
.fields th { width: 25%; }
.rationale { white-space: pre-wrap; }
.stamp { white-space: nowrap; }
.summary-grid td { font-variant-numeric: tabular-nums; }
ul { margin: 0; padding-left: 20px; }
a {
	display: inline-flex;
	align-items: center;
	justify-content: center;
	min-width: 24px;
	min-height: 24px;
	padding: 4px 8px;
	color: #174ea6;
	text-decoration: underline;
	white-space: nowrap;
	transition: color 180ms ease, background-color 180ms ease;
}
a:hover, a:focus-visible { background-color: #e8edf3; }
:focus-visible { outline: 3px solid #174ea6; outline-offset: 3px; }
.badge {
	display: inline-block;
	padding: 2px 8px;
	border: 1px solid transparent;
	border-radius: 4px;
	color: #18212b;
	background-color: #edf0f3;
	font-size: 0.875rem;
	white-space: nowrap;
	transition: border-color 150ms ease, background-color 150ms ease, color 150ms ease;
}
.badge:hover { border-color: currentColor; }
.standing-effective {
	color: var(--standing-effective-text);
	background-color: var(--standing-effective-background);
}
.standing-pending {
	color: var(--standing-pending-text);
	background-color: var(--standing-pending-background);
}
.standing-expired {
	color: var(--standing-expired-text);
	background-color: var(--standing-expired-background);
}
.standing-superseded {
	color: var(--standing-superseded-text);
	background-color: var(--standing-superseded-background);
}
.risk-accepted {
	color: var(--risk-accepted-text);
	background-color: var(--risk-accepted-background);
}
.risk-deferred {
	color: var(--risk-deferred-text);
	background-color: var(--risk-deferred-background);
}
.risk-rejected {
	color: var(--risk-rejected-text);
	background-color: var(--risk-rejected-background);
}
@media (max-width: 600px) {
	main { padding: 16px; }
	.summary-grid { grid-template-columns: 1fr; }
}
@media (prefers-reduced-motion: reduce) {
	a, .badge, tbody tr { transition-duration: 1ms; }
}
`

const badgeTemplates = `{{define "standingBadge"}}{{if eq . "effective"}}<span class="badge standing-effective">{{.}}</span>{{else if eq . "pending"}}<span class="badge standing-pending">{{.}}</span>{{else if eq . "expired"}}<span class="badge standing-expired">{{.}}</span>{{else if eq . "superseded"}}<span class="badge standing-superseded">{{.}}</span>{{else}}<span class="badge">{{.}}</span>{{end}}{{end}}{{define "riskDecisionBadge"}}{{if eq . "accepted"}}<span class="badge risk-accepted">{{.}}</span>{{else if eq . "deferred"}}<span class="badge risk-deferred">{{.}}</span>{{else if eq . "rejected"}}<span class="badge risk-rejected">{{.}}</span>{{else}}<span class="badge">{{.}}</span>{{end}}{{end}}`

const dashboardTemplate = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Ariadne governance dashboard</title>
<style>` + documentStyle + `</style>
</head>
<body>
<main>
<header>
<h1>Ariadne governance dashboard</h1>
<p class="notice">{{.Banner}}</p>
</header>
<section aria-labelledby="book-heading">
<h2 id="book-heading">Book observation</h2>
<table class="fields">
<tbody>
<tr><th scope="row">Records</th><td>{{.RecordCount}}</td></tr>
<tr><th scope="row">As of</th><td>{{.AsOf}}</td></tr>
<tr><th scope="row">Book head hash</th><td>{{.HeadHash}}</td></tr>
</tbody>
</table>
</section>
<section aria-labelledby="summary-heading">
<h2 id="summary-heading">Derived summary</h2>
<p>Counts are derived from the entries below, including expired and superseded declarations.</p>
<div class="summary-grid">
<table>
<caption>standing</caption>
<thead><tr><th scope="col">Standing</th><th scope="col">Count</th></tr></thead>
<tbody>
<tr><th scope="row">effective</th><td>{{.Summary.Effective}}</td></tr>
<tr><th scope="row">pending</th><td>{{.Summary.Pending}}</td></tr>
<tr><th scope="row">expired</th><td>{{.Summary.Expired}}</td></tr>
<tr><th scope="row">superseded</th><td>{{.Summary.Superseded}}</td></tr>
</tbody>
</table>
<table>
<caption>risk_decision</caption>
<thead><tr><th scope="col">Risk decision</th><th scope="col">Count</th></tr></thead>
<tbody>
<tr><th scope="row">accepted</th><td>{{.Summary.Accepted}}</td></tr>
<tr><th scope="row">deferred</th><td>{{.Summary.Deferred}}</td></tr>
<tr><th scope="row">rejected</th><td>{{.Summary.Rejected}}</td></tr>
</tbody>
</table>
</div>
</section>
<section aria-labelledby="records-heading">
<h2 id="records-heading">Decision records</h2>
{{if .Entries}}<div class="table-scroll" role="region" aria-label="Decision records table" tabindex="0">
<table class="records">
<thead>
<tr>
<th scope="col">sequence</th>
<th scope="col">subject_uid</th>
<th scope="col">container_class</th>
<th scope="col">container_name</th>
<th scope="col">vulnerability_id</th>
<th scope="col">risk_decision</th>
<th scope="col">decided_at</th>
<th scope="col">expires_at</th>
<th scope="col">standing</th>
<th scope="col">superseded_by</th>
<th scope="col">anomalies</th>
<th scope="col">detail</th>
</tr>
</thead>
<tbody>
{{range .Entries}}<tr>
<td><a href="/decision/{{.Sequence}}">{{.Sequence}}</a></td>
<td>{{.SubjectUID}}</td>
<td>{{.ContainerClass}}</td>
<td>{{.ContainerName}}</td>
<td>{{.VulnerabilityID}}</td>
<td>{{template "riskDecisionBadge" .RiskDecision}}</td>
<td class="stamp">{{.DecidedAt}}</td>
<td class="stamp">{{.ExpiresAt}}</td>
<td>{{template "standingBadge" .Standing}}</td>
<td>{{.SupersededBy}}</td>
<td>{{if .Anomalies}}<ul>{{range .Anomalies}}<li>{{if .}}{{.}}{{else}}null{{end}}</li>{{end}}</ul>{{else}}none{{end}}</td>
<td><a href="/decision/{{.Sequence}}">detail</a></td>
</tr>
{{end}}</tbody>
</table>
</div>{{else}}<p>No decision record is present (empty book).</p>{{end}}
</section>
<section aria-labelledby="limits-heading">
<h2 id="limits-heading">Limits</h2>
<p>This read-only view contains human risk_decision declarations and a derived validity view. Actors and timestamps are declarations. It does not authenticate actors or authorize an exception. Missing scalar values are shown as null; empty lists as none.</p>
</section>
</main>
</body>
</html>
`

const decisionTemplate = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Ariadne decision record</title>
<style>` + documentStyle + `</style>
</head>
<body>
<main>
<header>
<nav aria-label="Breadcrumb"><p class="breadcrumb"><a href="/">Dashboard</a> / Decision #{{.Sequence}}</p></nav>
<h1>Decision record #{{.Sequence}}</h1>
<p class="notice">{{.Banner}}</p>
</header>
<section aria-labelledby="declaration-heading">
<h2 id="declaration-heading">Declaration</h2>
<table class="fields">
<tbody>
<tr><th scope="row">sequence</th><td>{{.Sequence}}</td></tr>
<tr><th scope="row">hash</th><td>{{.Hash}}</td></tr>
<tr><th scope="row">previous_hash</th><td>{{.PreviousHash}}</td></tr>
<tr><th scope="row">risk_decision</th><td>{{template "riskDecisionBadge" .RiskDecision}}</td></tr>
<tr><th scope="row">owner</th><td>{{.Owner}}</td></tr>
<tr><th scope="row">approver</th><td>{{.Approver}}</td></tr>
<tr><th scope="row">rationale</th><td class="rationale">{{.Rationale}}</td></tr>
<tr><th scope="row">decided_at</th><td>{{.DecidedAt}}</td></tr>
<tr><th scope="row">expires_at</th><td>{{.ExpiresAt}}</td></tr>
</tbody>
</table>
</section>
<section aria-labelledby="scope-heading">
<h2 id="scope-heading">Scope</h2>
<table class="fields">
<tbody>
<tr><th scope="row">bundle_hash</th><td>{{.BundleHash}}</td></tr>
<tr><th scope="row">subject_uid</th><td>{{.SubjectUID}}</td></tr>
<tr><th scope="row">container_name</th><td>{{.ContainerName}}</td></tr>
<tr><th scope="row">container_class</th><td>{{.ContainerClass}}</td></tr>
<tr><th scope="row">vulnerability_id</th><td>{{.VulnerabilityID}}</td></tr>
<tr><th scope="row">result_fingerprint</th><td>{{.ResultFingerprint}}</td></tr>
</tbody>
</table>
</section>
<section aria-labelledby="controls-heading">
<h2 id="controls-heading">Controls</h2>
{{if .Controls}}<ul>{{range .Controls}}<li>{{if .}}{{.}}{{else}}null{{end}}</li>{{end}}</ul>{{else}}<p>none</p>{{end}}
</section>
<section aria-labelledby="validity-heading">
<h2 id="validity-heading">Derived validity view</h2>
<p>Standing is derived from declared validity and supersession. It does not change or approve the underlying declaration.</p>
<table class="fields">
<tbody>
<tr><th scope="row">standing</th><td>{{template "standingBadge" .Standing}}</td></tr>
<tr><th scope="row">superseded_by</th><td>{{.SupersededBy}}</td></tr>
<tr><th scope="row">anomalies</th><td>{{if .Anomalies}}<ul>{{range .Anomalies}}<li>{{if .}}{{.}}{{else}}null{{end}}</li>{{end}}</ul>{{else}}none{{end}}</td></tr>
</tbody>
</table>
</section>
</main>
</body>
</html>
`

var dashboardDocument = template.Must(template.New("dashboard").Parse(dashboardTemplate + badgeTemplates))
var decisionDocument = template.Must(template.New("decision").Parse(decisionTemplate + badgeTemplates))
