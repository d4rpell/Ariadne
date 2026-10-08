package report

import (
	"bytes"
	"fmt"
	"html/template"
)

// HTML returns the standalone HTML document of one validated report: UTF-8,
// lang="en", a static title, no JavaScript, no external resource and no URL
// built from data. Every value is emitted in text context by html/template; the
// identifiers of the internal links are derived from numeric occurrence
// positions, never from a CVE, UID, source or locator.
//
// The document reproduces the whole DTO — every field of every object, with
// explicit nulls for the optional ones and every duplicate occurrence of a
// reference — and adds no conclusion.
func HTML(report Report) ([]byte, error) {
	if !report.ok {
		return nil, problem(CodeInvalidReport)
	}
	var buffer bytes.Buffer
	if err := htmlDocument.Execute(&buffer, report.view()); err != nil {
		return nil, problem(CodeRenderFailure)
	}
	return buffer.Bytes(), nil
}

// evidenceRow is one catalog row with its occurrence identity. The identifier is
// the position of the occurrence in the catalog, so two rows citing the same
// item have distinct anchors; the link of a citation points at the first row of
// its index, as F0 §6 ratifies.
type evidenceRow struct {
	Anchor     string
	ItemIndex  int
	Type       string
	Source     string
	SourceHash string
	Locator    string
	ObservedAt string
	Confidence string
	Scope      ScopeDTO
}

type warningRow struct {
	Anchor        string
	Origin        string
	EvidenceIndex int
	WarningIndex  int
	Code          string
	Class         string
}

type referenceLink struct {
	ItemIndex int
	Anchor    string
}

// warningRefView reproduces one element of Result.WarningReferences in the order
// the result declares. The catalog carries the same occurrences in the ratified
// canonical order; without this list the declared order would be lost.
type warningRefView struct {
	Origin        string
	EvidenceIndex int
	WarningIndex  int
	Anchor        string
}

type sourcePinView struct {
	Role             string
	Source           string
	SourceHash       string
	AdvisoryID       string
	AdvisoryRevision string
}

// htmlView is the flattened document model. It carries every field the DTO
// declares, so the page is a faithful reproduction and not a summary: a member
// the DTO carries but the view drops would be presentation loss.
type htmlView struct {
	Result ResultDTO

	HasPrevious   bool
	Previous      PreviousDTO
	HasDomain     bool
	DomainTTL     int64
	DomainPins    []sourcePinView
	GlobalRefs    []referenceLink
	WarningRefs   []warningRefView
	WarningRows   []warningRow
	RuleViews     []ruleView
	CandidateView []candidateView
	EvidenceRows  []evidenceRow
}

type ruleView struct {
	RuleID              string
	State               string
	MissingRequirements []string
	Reasons             []string
	References          []referenceLink
	Checks              []checkView
}

type checkView struct {
	CheckID    string
	Outcome    string
	Reasons    []string
	References []referenceLink
}

type candidateView struct {
	RuleID        string
	ProductStatus string
	References    []referenceLink
}

func (r Report) view() htmlView {
	view := htmlView{
		Result:        r.result,
		GlobalRefs:    linksFor(r.result.EvidenceReferences, r.evidence),
		WarningRefs:   warningRefViews(r.result.WarningReferences, r.warnings),
		WarningRows:   warningRows(r.warnings),
		EvidenceRows:  evidenceRows(r.evidence),
		CandidateView: candidateViews(r.result.Candidates, r.evidence),
		RuleViews:     ruleViews(r.result.Rules, r.evidence),
	}
	if previous := r.result.Admission.Previous; previous != nil {
		view.HasPrevious = true
		view.Previous = *previous
	}
	if domain := r.result.Domain; domain != nil {
		view.HasDomain = true
		view.DomainTTL = domain.MaximumEvidenceAgeSeconds
		pins := make([]sourcePinView, 0, len(domain.SourcePins))
		for _, pin := range domain.SourcePins {
			pins = append(pins, sourcePinView{
				Role:             pin.Role,
				Source:           pin.Source,
				SourceHash:       pin.SourceHash,
				AdvisoryID:       nullText(pin.AdvisoryID),
				AdvisoryRevision: nullText(pin.AdvisoryRevision),
			})
		}
		view.DomainPins = pins
	}
	return view
}

// nullText renders an explicit null so the page states absence instead of
// leaving the reader to infer it from a blank cell.
func nullText(value *string) string {
	if value == nil {
		return "null"
	}
	return *value
}

func evidenceRows(rows []ResolvedEvidenceDTO) []evidenceRow {
	view := make([]evidenceRow, 0, len(rows))
	for position, row := range rows {
		view = append(view, evidenceRow{
			Anchor:     fmt.Sprintf("e-%d", position),
			ItemIndex:  row.Reference.ItemIndex,
			Type:       row.Type,
			Source:     row.Source,
			SourceHash: row.SourceHash,
			Locator:    row.Locator,
			ObservedAt: row.ObservedAt,
			Confidence: row.Confidence,
			Scope:      row.Scope,
		})
	}
	return view
}

func warningRows(rows []ResolvedWarningDTO) []warningRow {
	view := make([]warningRow, 0, len(rows))
	for position, row := range rows {
		view = append(view, warningRow{
			Anchor:        fmt.Sprintf("w-%d", position),
			Origin:        row.Reference.Origin,
			EvidenceIndex: row.Reference.EvidenceIndex,
			WarningIndex:  row.Reference.WarningIndex,
			Code:          row.Code,
			Class:         row.Class,
		})
	}
	return view
}

// linksFor points every citation at the first catalog row of its item index.
// The index of the row is the occurrence position, which is what makes two
// citations of the same item distinguishable.
func linksFor(references []ReferenceDTO, rows []ResolvedEvidenceDTO) []referenceLink {
	links := make([]referenceLink, 0, len(references))
	for _, reference := range references {
		links = append(links, referenceLink{
			ItemIndex: reference.ItemIndex,
			Anchor:    firstAnchorOf(reference.ItemIndex, rows),
		})
	}
	return links
}

func firstAnchorOf(itemIndex int, rows []ResolvedEvidenceDTO) string {
	for position, row := range rows {
		if row.Reference.ItemIndex == itemIndex {
			return fmt.Sprintf("e-%d", position)
		}
	}
	return ""
}

// warningRefViews reproduces the declared warning references in their own order,
// each one linked to the first catalog row that shares its tuple. The order of
// this list is data: it is the order the result declared, which the sorted
// catalog does not preserve.
func warningRefViews(references []WarningRefDTO, rows []ResolvedWarningDTO) []warningRefView {
	view := make([]warningRefView, 0, len(references))
	for _, reference := range references {
		view = append(view, warningRefView{
			Origin:        reference.Origin,
			EvidenceIndex: reference.EvidenceIndex,
			WarningIndex:  reference.WarningIndex,
			Anchor:        firstWarningAnchorOf(reference, rows),
		})
	}
	return view
}

func firstWarningAnchorOf(reference WarningRefDTO, rows []ResolvedWarningDTO) string {
	for position, row := range rows {
		if row.Reference == reference {
			return fmt.Sprintf("w-%d", position)
		}
	}
	return ""
}

func ruleViews(rules []RuleTraceDTO, rows []ResolvedEvidenceDTO) []ruleView {
	view := make([]ruleView, 0, len(rules))
	for _, rule := range rules {
		checks := make([]checkView, 0, len(rule.Checks))
		for _, check := range rule.Checks {
			checks = append(checks, checkView{
				CheckID:    check.CheckID,
				Outcome:    check.Outcome,
				Reasons:    check.Reasons,
				References: linksFor(check.EvidenceReferences, rows),
			})
		}
		view = append(view, ruleView{
			RuleID:              rule.RuleID,
			State:               rule.State,
			MissingRequirements: rule.MissingRequirements,
			Reasons:             rule.Reasons,
			References:          linksFor(rule.EvidenceReferences, rows),
			Checks:              checks,
		})
	}
	return view
}

func candidateViews(candidates []CandidateDTO, rows []ResolvedEvidenceDTO) []candidateView {
	view := make([]candidateView, 0, len(candidates))
	for _, candidate := range candidates {
		view = append(view, candidateView{
			RuleID:        candidate.RuleID,
			ProductStatus: candidate.ProductStatus,
			References:    linksFor(candidate.EvidenceReferences, rows),
		})
	}
	return view
}

const htmlTemplate = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Ariadne evaluation report</title>
<style>
body{font-family:system-ui,sans-serif;line-height:1.45;margin:2rem;max-width:80rem}
h1{font-size:1.4rem}h2{font-size:1.1rem;margin-top:1.8rem}h3{font-size:1rem;margin-top:1.2rem}
table{border-collapse:collapse;margin:0.6rem 0}th,td{border:1px solid #999;padding:0.25rem 0.5rem;text-align:left;vertical-align:top}
code{font-family:ui-monospace,monospace}
.notice{border:1px solid #999;padding:0.6rem;background:#f4f4f4}
.limits li{margin:0.2rem 0}
</style>
</head>
<body>
<h1>Ariadne evaluation report</h1>
<p class="notice">MVP complete presentation of one evaluation result. It is not a risk acceptance, not an approval and not a security statement. This document reproduces what the evaluator computed; it adds no conclusion.</p>

<h2>Evaluation identity</h2>
<table>
<tr><th>Engine version</th><td><code>{{.Result.EngineVersion}}</code></td></tr>
<tr><th>Profile</th><td><code>{{.Result.ProfileVersion}}</code></td></tr>
<tr><th>Bundle hash</th><td><code>{{.Result.BundleHash}}</code></td></tr>
<tr><th>Pack</th><td><code>{{.Result.PackID}}</code> version {{.Result.PackVersion}}, hash <code>{{.Result.PackHash}}</code></td></tr>
</table>

<h2>Decision layers</h2>
<p>The three layers are separate. A technical status is not an exploitability assessment and neither of them is a risk decision.</p>
<table>
<tr><th>Product status (technical)</th><td><code>{{.Result.ProductStatus}}</code></td></tr>
<tr><th>Exploitability (local profile, not a VEX field)</th><td><code>{{.Result.Exploitability}}</code></td></tr>
<tr><th>Risk decision (human governance)</th><td>No human risk decision is present in this evaluator result.</td></tr>
</table>

<h2>Target</h2>
<table>
<tr><th>Subject UID</th><td><code>{{.Result.Target.SubjectUID}}</code></td></tr>
<tr><th>Container</th><td><code>{{.Result.Target.ContainerClass}}</code> / <code>{{.Result.Target.ContainerName}}</code></td></tr>
<tr><th>Vulnerability</th><td><code>{{.Result.Target.VulnerabilityID}}</code></td></tr>
<tr><th>Row reference</th><td><code>{{.Result.Target.Source}}</code>, locator <code>{{.Result.Target.Locator}}</code>, source hash <code>{{.Result.Target.SourceHash}}</code>, observed at <code>{{.Result.Target.ObservedAt}}</code></td></tr>
</table>

<h2>Global reasons</h2>
{{if .Result.Reasons}}<ul>{{range .Result.Reasons}}<li><code>{{.}}</code></li>{{end}}</ul>{{else}}<p>No global reason was recorded (explicit empty array).</p>{{end}}

<h2>Candidates</h2>
<p>Each candidate is a branch the evaluation sustained, not a selected final decision. Several may coexist while the global status stays inconclusive.</p>
{{if .CandidateView}}<table>
<tr><th>Rule</th><th>Status</th><th>Evidence</th></tr>
{{range .CandidateView}}<tr><td><code>{{.RuleID}}</code></td><td><code>{{.ProductStatus}}</code></td><td>{{if .References}}{{range .References}}<a href="#{{.Anchor}}"><code>item_index {{.ItemIndex}}</code></a> {{end}}{{else}}none{{end}}</td></tr>
{{end}}</table>{{else}}<p>No affirmative candidate is present in this result (explicit empty array).</p>{{end}}

<h2>Rule traces</h2>
{{if .RuleViews}}{{range .RuleViews}}<h3><code>{{.RuleID}}</code> — <code>{{.State}}</code></h3>
<p>Missing requirements: {{if .MissingRequirements}}{{range .MissingRequirements}}<code>{{.}}</code> {{end}}{{else}}none (empty array){{end}}</p>
<p>Reasons: {{if .Reasons}}{{range .Reasons}}<code>{{.}}</code> {{end}}{{else}}none (empty array){{end}}</p>
<p>Rule evidence references: {{if .References}}{{range .References}}<a href="#{{.Anchor}}"><code>item_index {{.ItemIndex}}</code></a> {{end}}{{else}}none (empty array){{end}}</p>
{{if .Checks}}<table>
<tr><th>Check</th><th>Outcome</th><th>Reasons</th><th>Evidence</th></tr>
{{range .Checks}}<tr><td><code>{{.CheckID}}</code></td><td><code>{{.Outcome}}</code></td><td>{{if .Reasons}}{{range .Reasons}}<code>{{.}}</code> {{end}}{{else}}none (empty array){{end}}</td><td>{{if .References}}{{range .References}}<a href="#{{.Anchor}}"><code>item_index {{.ItemIndex}}</code></a> {{end}}{{else}}none (empty array){{end}}</td></tr>
{{end}}</table>{{else}}<p>No check ran for this rule (empty array).</p>{{end}}
{{end}}{{else}}<p>No rule trace is present in this result (explicit empty array).</p>{{end}}

<h2>Global evidence references</h2>
<p>The declared order is the one the result fixed; the catalog below is ordered by item index.</p>
{{if .GlobalRefs}}<ul>{{range .GlobalRefs}}<li><a href="#{{.Anchor}}"><code>item_index {{.ItemIndex}}</code></a></li>{{end}}</ul>{{else}}<p>None (explicit empty array).</p>{{end}}

<h2>Global warning references</h2>
<p>The declared order is the one the result fixed; the catalog below is ordered by the ratified tuple.</p>
{{if .WarningRefs}}<ul>{{range .WarningRefs}}<li><a href="#{{.Anchor}}"><code>{{.Origin}} evidence_index {{.EvidenceIndex}} warning_index {{.WarningIndex}}</code></a></li>{{end}}</ul>{{else}}<p>None (explicit empty array).</p>{{end}}

<h2>Evidence catalog</h2>
<p>Every row is a citation of the canonical bundle named by the bundle hash above, in the order the contract fixes, with every duplicate occurrence preserved. Values are not reproduced here; consult the referenced evidence bundle under its access policy.</p>
{{if .EvidenceRows}}<table>
<tr><th>Row</th><th>item_index</th><th>Type</th><th>Source</th><th>Source hash</th><th>Locator</th><th>Observed at</th><th>Confidence</th><th>Scope</th></tr>
{{range .EvidenceRows}}<tr id="{{.Anchor}}"><td><code>{{.Anchor}}</code></td><td><code>{{.ItemIndex}}</code></td><td><code>{{.Type}}</code></td><td><code>{{.Source}}</code></td><td><code>{{.SourceHash}}</code></td><td><code>{{.Locator}}</code></td><td><code>{{.ObservedAt}}</code></td><td><code>{{.Confidence}}</code></td><td><code>{{.Scope.SubjectUID}}</code> / <code>{{.Scope.ContainerName}}</code></td></tr>
{{end}}</table>{{else}}<p>No evidence item is referenced by this result (explicit empty array).</p>{{end}}

<h2>Warning catalog</h2>
<p>Every row is one warning occurrence, in the ratified order (origin, evidence_index, warning_index). Warning message omitted; consult the referenced evidence bundle under its access policy.</p>
{{if .WarningRows}}<table>
<tr><th>Row</th><th>Origin</th><th>evidence_index</th><th>warning_index</th><th>Code</th><th>Class</th><th>Message</th></tr>
{{range .WarningRows}}<tr id="{{.Anchor}}"><td><code>{{.Anchor}}</code></td><td><code>{{.Origin}}</code></td><td><code>{{.EvidenceIndex}}</code></td><td><code>{{.WarningIndex}}</code></td><td><code>{{.Code}}</code></td><td><code>{{.Class}}</code></td><td>null (omitted by presentation policy)</td></tr>
{{end}}</table>{{else}}<p>No warning is referenced by this result (explicit empty array).</p>{{end}}


<h2>Replay context</h2>
<p>The evaluation instant below is the replay parameter the caller supplied. It is not an issuance date, not a validity period and not a statement that the evidence is current.</p>
<table>
<tr><th>Evaluated at (replay parameter)</th><td><code>{{.Result.Admission.EvaluatedAt}}</code></td></tr>
<tr><th>Expected pack id</th><td><code>{{.Result.Admission.ExpectedPackID}}</code></td></tr>
<tr><th>Expected pack hash</th><td><code>{{.Result.Admission.ExpectedPackHash}}</code></td></tr>
<tr><th>Minimum version</th><td><code>{{.Result.Admission.MinimumVersion}}</code></td></tr>
<tr><th>Previously admitted</th><td>{{if .HasPrevious}}version <code>{{.Previous.Version}}</code>, hash <code>{{.Previous.Hash}}</code>{{else}}null{{end}}</td></tr>
<tr><th>Domain context</th><td>{{if .HasDomain}}maximum evidence age <code>{{.DomainTTL}}</code> seconds{{else}}null{{end}}</td></tr>
</table>
{{if .HasDomain}}<table>
<tr><th>Role</th><th>Source</th><th>Source hash</th><th>advisory_id</th><th>advisory_revision</th></tr>
{{range .DomainPins}}<tr><td><code>{{.Role}}</code></td><td><code>{{.Source}}</code></td><td><code>{{.SourceHash}}</code></td><td><code>{{.AdvisoryID}}</code></td><td><code>{{.AdvisoryRevision}}</code></td></tr>
{{end}}</table>{{end}}

<h2>Limits of this report</h2>
<ul class="limits">
<li>The bundle hash proves integrity of those bytes. It does not authenticate the origin or the cluster, and it does not prove that the sources are sufficient, exhaustive or current.</li>
<li>This presentation is not a second evaluator. Re-evaluating the semantics of a fabricated result is out of scope, so form validation does not establish that the evaluation was sound.</li>
<li>There is no universal secret detector. Identifiers and citations are included under the responsibility of the producer and the caller who holds the case.</li>
<li>Nothing here is safe, approved, risk-free or valid by implication, and no spreadsheet-import protection is claimed.</li>
</ul>
</body>
</html>
`

var htmlDocument = template.Must(template.New("report").Parse(htmlTemplate))
