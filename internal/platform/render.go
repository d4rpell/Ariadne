package platform

import (
	"bytes"
	"html/template"
)

// banner is the fixed, visible limits notice of the pre-alpha platform. It is a
// constant of this package, never data from any file.
const banner = "read-only projection of one human decision record; not a risk acceptance, not an approval, not a security statement; not a source of truth"

// RenderDashboard returns the standalone dashboard document: a fixed header and
// one row per entry in append order. Every value is emitted in text context by
// html/template; the only link is /decision/{sequence}, built from the numeric
// Sequence inside the constant template, never from a UID, CVE, source or
// locator. The document is UTF-8, lang="en", has no JavaScript and references no
// external resource.
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
	Entries     []rowView
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
		AsOf:        model.AsOf,
		RecordCount: model.RecordCount,
		HeadHash:    explicitText(model.HeadHash),
		Entries:     make([]rowView, 0, len(model.Entries)),
	}
	for position := range model.Entries {
		entry := model.Entries[position]
		page.Entries = append(page.Entries, rowView{
			Sequence:        entry.Sequence,
			SubjectUID:      entry.Scope.SubjectUID,
			ContainerClass:  entry.Scope.ContainerClass,
			ContainerName:   entry.Scope.ContainerName,
			VulnerabilityID: entry.Scope.VulnerabilityID,
			RiskDecision:    entry.RiskDecision,
			DecidedAt:       entry.DecidedAt,
			ExpiresAt:       explicitPointer(entry.ExpiresAt),
			Standing:        entry.Standing,
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
		Hash:              entry.Hash,
		PreviousHash:      explicitPointer(entry.PreviousHash),
		RiskDecision:      entry.RiskDecision,
		Owner:             entry.Owner,
		Approver:          entry.Approver,
		Rationale:         entry.Rationale,
		DecidedAt:         entry.DecidedAt,
		ExpiresAt:         explicitPointer(entry.ExpiresAt),
		Standing:          entry.Standing,
		SupersededBy:      explicitPointer(entry.SupersededBy),
		Anomalies:         entry.Anomalies,
		BundleHash:        entry.Scope.BundleHash,
		SubjectUID:        entry.Scope.SubjectUID,
		ContainerName:     entry.Scope.ContainerName,
		ContainerClass:    entry.Scope.ContainerClass,
		VulnerabilityID:   entry.Scope.VulnerabilityID,
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
	return *value
}

const dashboardTemplate = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Ariadne governance dashboard</title>
<style>
body{font-family:system-ui,sans-serif;line-height:1.45;margin:2rem;max-width:90rem}
h1{font-size:1.4rem}h2{font-size:1.1rem;margin-top:1.8rem}
table{border-collapse:collapse;margin:0.6rem 0}th,td{border:1px solid #999;padding:0.25rem 0.5rem;text-align:left;vertical-align:top}
code{font-family:ui-monospace,monospace}
.pre-alpha{border:1px solid #999;padding:0.6rem;background:#f4f4f4}
.limits{color:#333}
</style>
</head>
<body>
<h1>Ariadne governance dashboard</h1>
<p class="pre-alpha">{{.Banner}}</p>
<table>
<tr><th>Records</th><td>{{.RecordCount}}</td></tr>
<tr><th>As of</th><td><code>{{.AsOf}}</code></td></tr>
<tr><th>Book head hash</th><td><code>{{.HeadHash}}</code></td></tr>
</table>
<h2>Decision records</h2>
<p>One row per declared human risk decision, in append order. The standing column is the derived validity view of the record at the as-of instant; it is not a product status and not an approval.</p>
{{if .Entries}}<table>
<tr><th>sequence</th><th>subject_uid</th><th>container_class</th><th>container_name</th><th>vulnerability_id</th><th>risk_decision</th><th>decided_at</th><th>expires_at</th><th>standing</th><th>superseded_by</th><th>anomalies</th><th>detail</th></tr>
{{range .Entries}}<tr><td><a href="/decision/{{.Sequence}}">{{.Sequence}}</a></td><td><code>{{.SubjectUID}}</code></td><td><code>{{.ContainerClass}}</code></td><td><code>{{.ContainerName}}</code></td><td><code>{{.VulnerabilityID}}</code></td><td><code>{{.RiskDecision}}</code></td><td><code>{{.DecidedAt}}</code></td><td><code>{{.ExpiresAt}}</code></td><td><code>{{.Standing}}</code></td><td><code>{{.SupersededBy}}</code></td><td>{{if .Anomalies}}{{range .Anomalies}}<code>{{.}}</code> {{end}}{{else}}none{{end}}</td><td><a href="/decision/{{.Sequence}}">detail</a></td></tr>
{{end}}</table>{{else}}<p>No decision record is present (empty book).</p>{{end}}
<p class="limits">Absence is shown as an explicit <code>null</code> or <code>none</code>. Only the human risk decision layer is shown; no product status and no exploitability value exists in this record and none is invented.</p>
</body>
</html>
`

const decisionTemplate = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Ariadne decision record</title>
<style>
body{font-family:system-ui,sans-serif;line-height:1.45;margin:2rem;max-width:90rem}
h1{font-size:1.4rem}h2{font-size:1.1rem;margin-top:1.8rem}
table{border-collapse:collapse;margin:0.6rem 0}th,td{border:1px solid #999;padding:0.25rem 0.5rem;text-align:left;vertical-align:top}
code{font-family:ui-monospace,monospace}
.pre-alpha{border:1px solid #999;padding:0.6rem;background:#f4f4f4}
</style>
</head>
<body>
<h1>Decision record</h1>
<p class="pre-alpha">{{.Banner}}</p>
<p><a href="/">Back to the dashboard</a></p>
<h2>Declaration</h2>
<table>
<tr><th>sequence</th><td>{{.Sequence}}</td></tr>
<tr><th>hash</th><td><code>{{.Hash}}</code></td></tr>
<tr><th>previous_hash</th><td><code>{{.PreviousHash}}</code></td></tr>
<tr><th>risk_decision</th><td><code>{{.RiskDecision}}</code></td></tr>
<tr><th>owner</th><td><code>{{.Owner}}</code></td></tr>
<tr><th>approver</th><td><code>{{.Approver}}</code></td></tr>
<tr><th>rationale</th><td><code>{{.Rationale}}</code></td></tr>
<tr><th>decided_at</th><td><code>{{.DecidedAt}}</code></td></tr>
<tr><th>expires_at</th><td><code>{{.ExpiresAt}}</code></td></tr>
</table>
<h2>Scope</h2>
<table>
<tr><th>bundle_hash</th><td><code>{{.BundleHash}}</code></td></tr>
<tr><th>subject_uid</th><td><code>{{.SubjectUID}}</code></td></tr>
<tr><th>container_name</th><td><code>{{.ContainerName}}</code></td></tr>
<tr><th>container_class</th><td><code>{{.ContainerClass}}</code></td></tr>
<tr><th>vulnerability_id</th><td><code>{{.VulnerabilityID}}</code></td></tr>
<tr><th>result_fingerprint</th><td><code>{{.ResultFingerprint}}</code></td></tr>
</table>
<h2>Controls</h2>
{{if .Controls}}<ul>{{range .Controls}}<li><code>{{.}}</code></li>{{end}}</ul>{{else}}<p>none</p>{{end}}
<h2>Derived validity view</h2>
<p>Derived at the as-of instant of the dashboard. It is a governance view, never a product status, an exploitability value or an approval.</p>
<table>
<tr><th>standing</th><td><code>{{.Standing}}</code></td></tr>
<tr><th>superseded_by</th><td><code>{{.SupersededBy}}</code></td></tr>
<tr><th>anomalies</th><td>{{if .Anomalies}}{{range .Anomalies}}<code>{{.}}</code> {{end}}{{else}}none{{end}}</td></tr>
</table>
</body>
</html>
`

var (
	dashboardDocument = template.Must(template.New("dashboard").Parse(dashboardTemplate))
	decisionDocument  = template.Must(template.New("decision").Parse(decisionTemplate))
)
