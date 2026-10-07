package platform

import (
	"bytes"
	"flag"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/d4rpell/Ariadne/internal/casefile"
)

// updatePlatformRenderGoldens regenerates the byte-exact HTML goldens. It is off
// by default; the goldens are reviewed artifacts, not build outputs.
var updatePlatformRenderGoldens = flag.Bool(
	"update-platform-goldens",
	false,
	"regenerate platform HTML goldens",
)

func TestRenderDeterministic(t *testing.T) {
	model, err := BuildModel(loadGoldenBook(t), goldenAsOf)
	if err != nil {
		t.Fatal(err)
	}
	first, err := RenderDashboard(model)
	if err != nil {
		t.Fatal(err)
	}
	second, err := RenderDashboard(model)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(first, second) {
		t.Fatal("RenderDashboard is not deterministic")
	}
	firstDetail, found, err := RenderDecision(model, 4)
	if !found || err != nil {
		t.Fatal("decision 4 must render")
	}
	secondDetail, _, err := RenderDecision(model, 4)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(firstDetail, secondDetail) {
		t.Fatal("RenderDecision is not deterministic")
	}
}

func TestRenderGolden(t *testing.T) {
	model, err := BuildModel(loadGoldenBook(t), goldenAsOf)
	if err != nil {
		t.Fatal(err)
	}
	t.Run("dashboard", func(t *testing.T) {
		document, err := RenderDashboard(model)
		if err != nil {
			t.Fatal(err)
		}
		compareGolden(t, "dashboard.golden.html", document)
	})
	for _, sequence := range []uint64{1, 4, 6} {
		t.Run("decision "+itoa(sequence), func(t *testing.T) {
			document, found, err := RenderDecision(model, sequence)
			if !found || err != nil {
				t.Fatalf("decision %d: found=%v err=%v", sequence, found, err)
			}
			compareGolden(t, "decision-"+itoa(sequence)+".golden.html", document)
		})
	}
	t.Run("absent sequence", func(t *testing.T) {
		if _, found, err := RenderDecision(model, 999); found || err != nil {
			t.Fatalf("absent sequence: found=%v err=%v, want not found", found, err)
		}
	})
}

// TestRenderEscapesData proves the values are emitted in text context: a script
// or attribute payload declared in any field is escaped and never becomes
// markup, and no URL or attribute is built from string data.
func TestRenderEscapesData(t *testing.T) {
	book := casefile.NewBook()
	book = mustAppend(t, book, casefile.DecisionInput{
		RiskDecision: casefile.DecisionAccepted,
		Owner:        "<script>alert(1)</script>",
		Approver:     "approver & co",
		Rationale:    `rationale with "quotes" and <b>markup</b>`,
		Scope: casefile.Scope{
			BundleHash:      hex64('a'),
			SubjectUID:      "<uid>",
			ContainerName:   "<container>",
			ContainerClass:  casefile.ContainerRegular,
			VulnerabilityID: "CVE-2026-1",
		},
		Controls:  []string{`<img src=x onerror=alert(1)>`},
		DecidedAt: "2026-01-01T00:00:00Z",
	})
	model, err := BuildModel(book, goldenAsOf)
	if err != nil {
		t.Fatal(err)
	}
	dashboard, err := RenderDashboard(model)
	if err != nil {
		t.Fatal(err)
	}
	detail, found, err := RenderDecision(model, 1)
	if !found || err != nil {
		t.Fatal("the malicious record must render")
	}
	for name, document := range map[string][]byte{"dashboard": dashboard, "detail": detail} {
		text := string(document)
		for _, raw := range []string{"<script", "</script", "<img", "<b>"} {
			if strings.Contains(text, raw) {
				t.Fatalf("%s emitted raw markup %q", name, raw)
			}
		}
	}
	// The dashboard carries the identifier fields; the detail carries the actor
	// and rationale fields as well. Both are emitted in text context.
	if !strings.Contains(string(dashboard), "&lt;uid&gt;") {
		t.Fatal("dashboard did not escape the identifier payload")
	}
	if !strings.Contains(string(detail), "&lt;script&gt;") {
		t.Fatal("detail did not escape the script payload")
	}
	if !strings.Contains(string(detail), "&amp;") {
		t.Fatal("detail did not escape the ampersand")
	}
	if !strings.Contains(string(detail), "&lt;img src=x onerror=alert(1)&gt;") {
		t.Fatal("detail did not escape the control payload")
	}
	if !strings.Contains(string(detail), "&#34;") {
		t.Fatal("detail did not escape the quote in the rationale")
	}
}

// TestRenderAbsenceIsExplicit covers the presentation rule: an absent optional
// value is a literal null and an empty list is none, never a blank cell. It
// checks the dashboard, the detail document and a synthetic all-empty entry.
func TestRenderAbsenceIsExplicit(t *testing.T) {
	model, err := BuildModel(loadGoldenBook(t), goldenAsOf)
	if err != nil {
		t.Fatal(err)
	}
	document, err := RenderDashboard(model)
	if err != nil {
		t.Fatal(err)
	}
	text := string(document)
	if !strings.Contains(text, "<td>null</td>") {
		t.Fatal("an absent expires_at must render as an explicit null")
	}
	if !strings.Contains(text, ">none</td>") {
		t.Fatal("an empty anomaly list must render as none")
	}

	// The detail document must show the same explicit null for an absent
	// optional pointer (sequence 2 carries a nil expires_at in the golden book).
	// The assertion is anchored to the expires_at row, so another null field
	// elsewhere cannot satisfy it.
	detail, found, err := RenderDecision(model, 2)
	if !found || err != nil {
		t.Fatal("decision 2 must render")
	}
	if !strings.Contains(string(detail), `<tr><th scope="row">expires_at</th><td>null</td></tr>`) {
		t.Fatal("the detail document must render its absent expires_at row as null")
	}

	// A synthetic entry with empty strings and nil pointers must render null,
	// not a blank cell, in both scalar and list positions.
	synthetic := Model{
		AsOf:        goldenAsOf,
		RecordCount: 1,
		Entries:     []Entry{{Sequence: 1, Standing: "effective", RiskDecision: "accepted"}},
	}
	syntheticDocument, err := RenderDashboard(synthetic)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(syntheticDocument), `<td class="stamp">null</td>`) {
		t.Fatal("an absent expires_at must render as an explicit null")
	}
	if !strings.Contains(string(syntheticDocument), ">none</td>") {
		t.Fatal("an empty list must render as none")
	}
	syntheticDetail, found, err := RenderDecision(synthetic, 1)
	if !found || err != nil {
		t.Fatal("the synthetic decision must render")
	}
	if !strings.Contains(string(syntheticDetail), `<tr><th scope="row">expires_at</th><td>null</td></tr>`) {
		t.Fatal("the synthetic detail must render its absent expires_at row as null")
	}
	if !strings.Contains(string(syntheticDetail), "<td>null</td>") {
		t.Fatal("the synthetic detail must render empty scalars as null")
	}

	empty, err := RenderDashboard(mustBuild(t, casefile.NewBook()))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(empty), "No decision record is present") {
		t.Fatal("the empty book must state its emptiness")
	}
	if !strings.Contains(string(empty), "<td>null</td>") {
		t.Fatal("the empty book has no head and must render null")
	}
}

// TestRenderDerivedSummary fixes that the summary is a pure count over the
// projected entries: it adds no state and never invents a product status.
func TestRenderDerivedSummary(t *testing.T) {
	t.Run("golden book", func(t *testing.T) {
		model := modelForRenderContractTests(t)
		counts := map[string]int{
			"effective":  0,
			"pending":    0,
			"expired":    0,
			"superseded": 0,
			"accepted":   0,
			"deferred":   0,
			"rejected":   0,
		}
		for _, entry := range model.Entries {
			counts[entry.Standing]++
			counts[entry.RiskDecision]++
		}
		assertRenderedSummary(t, model, counts)
	})

	t.Run("empty entries", func(t *testing.T) {
		model := Model{
			AsOf:        goldenAsOf,
			RecordCount: 99,
		}
		assertRenderedSummary(t, model, map[string]int{})
	})

	t.Run("counts use entries", func(t *testing.T) {
		model := Model{
			AsOf:        goldenAsOf,
			RecordCount: 99,
			Entries: []Entry{
				{Sequence: 1, Standing: "effective", RiskDecision: "accepted"},
				{Sequence: 2, Standing: "effective", RiskDecision: "accepted"},
				{Sequence: 3, Standing: "pending", RiskDecision: "deferred"},
				{Sequence: 4, Standing: "expired", RiskDecision: "rejected"},
				{Sequence: 5, Standing: "superseded", RiskDecision: "accepted"},
				{Sequence: 6, Standing: "effective", RiskDecision: "deferred"},
				{Sequence: 7, Standing: "pending", RiskDecision: "rejected"},
			},
		}
		assertRenderedSummary(t, model, map[string]int{
			"effective":  3,
			"pending":    2,
			"expired":    1,
			"superseded": 1,
			"accepted":   3,
			"deferred":   2,
			"rejected":   2,
		})
	})
}

// TestRenderNoJavaScriptOrExternalAsset fixes the contract of A3-06: the HTML
// has no JavaScript and references no external resource, in both documents.
func TestRenderNoJavaScriptOrExternalAsset(t *testing.T) {
	dashboard, decision := documentsForRenderContractTests(t)
	for _, document := range []struct {
		name string
		body []byte
	}{
		{name: "dashboard", body: dashboard},
		{name: "decision", body: decision},
	} {
		t.Run(document.name, func(t *testing.T) {
			text := strings.ToLower(string(document.body))
			for _, forbidden := range []string{
				"<script",
				"src=",
				"http://",
				"https://",
				"@import",
			} {
				if strings.Contains(text, forbidden) {
					t.Errorf("document contains forbidden content %q", forbidden)
				}
			}
		})
	}
}

// TestRenderReducedMotion fixes the accessibility requirement: the reduced
// duration is declared INSIDE the reduced-motion media block, targets the
// animated selectors, and transitions are never disabled with transition:none
// (which would break transitionend handling).
func TestRenderReducedMotion(t *testing.T) {
	dashboard, decision := documentsForRenderContractTests(t)
	for _, document := range []struct {
		name string
		body []byte
	}{
		{name: "dashboard", body: dashboard},
		{name: "decision", body: decision},
	} {
		t.Run(document.name, func(t *testing.T) {
			text := string(document.body)
			block := reducedMotionBlock(t, text)
			if !strings.Contains(block, "transition-duration: 1ms;") {
				t.Error("the reduced duration is not declared inside the reduced-motion block")
			}
			if !strings.Contains(block, "a, .badge, tbody tr") {
				t.Error("the reduced-motion block does not target the animated selectors")
			}
			compact := strings.Join(strings.Fields(text), "")
			if strings.Contains(compact, "transition:none") {
				t.Error("document disables transitions instead of reducing duration")
			}
		})
	}
}

// TestRenderLinkTargetsAreLocal fixes that every href is a local path: the root
// or a /decision/{digits} path, never an external or data URL. The dashboard
// carries at least one link; the detail document carries exactly one back link.
func TestRenderLinkTargetsAreLocal(t *testing.T) {
	dashboard, decision := documentsForRenderContractTests(t)
	for _, document := range []struct {
		name    string
		body    []byte
		want    int
		exactly bool
	}{
		{name: "dashboard", body: dashboard, want: 1},
		{name: "decision", body: decision, want: 1, exactly: true},
	} {
		t.Run(document.name, func(t *testing.T) {
			count := 0
			rest := string(document.body)
			for {
				index := strings.Index(rest, "href=")
				if index < 0 {
					break
				}
				rest = rest[index+len("href="):]
				if rest == "" {
					t.Fatalf("%s: dangling href= at end of document", document.name)
				}
				quote := rest[0]
				if quote != '"' && quote != '\'' {
					t.Errorf("%s: unquoted href value starts with %q", document.name, string(quote))
					continue
				}
				body := rest[1:]
				end := strings.IndexByte(body, quote)
				if end < 0 {
					t.Fatalf("%s: unterminated href value", document.name)
				}
				target := body[:end]
				if target != "/" && !isDecisionPath(target) {
					t.Errorf("%s: non-local href %q", document.name, target)
				}
				count++
			}
			if document.exactly && count != document.want {
				t.Errorf("%s: got %d links, want exactly %d", document.name, count, document.want)
			}
			if !document.exactly && count < document.want {
				t.Errorf("%s: got %d links, want at least %d", document.name, count, document.want)
			}
		})
	}
}

func isDecisionPath(target string) bool {
	const prefix = "/decision/"
	if !strings.HasPrefix(target, prefix) {
		return false
	}
	digits := target[len(prefix):]
	if digits == "" {
		return false
	}
	for _, character := range digits {
		if character < '0' || character > '9' {
			return false
		}
	}
	return true
}

// reducedMotionBlock returns the body of the reduced-motion media query by
// brace matching, so an assertion proves the declaration sits inside the whole
// media block (balanced braces) rather than merely existing in the document.
func reducedMotionBlock(t *testing.T, text string) string {
	t.Helper()
	const marker = "@media (prefers-reduced-motion: reduce) {"
	index := strings.Index(text, marker)
	if index < 0 {
		t.Fatal("document lacks a reduced-motion media query")
	}
	rest := text[index+len(marker):]
	depth := 1
	for position := 0; position < len(rest); position++ {
		switch rest[position] {
		case '{':
			depth++
		case '}':
			depth--
			if depth == 0 {
				return rest[:position]
			}
		}
	}
	t.Fatal("reduced-motion media query is not closed")
	return ""
}

// TestRenderFocusVisible fixes the accessibility requirement: visible focus and
// link targets of at least 24 by 24 CSS pixels.
func TestRenderFocusVisible(t *testing.T) {
	dashboard, decision := documentsForRenderContractTests(t)
	for _, document := range []struct {
		name string
		body []byte
	}{
		{name: "dashboard", body: dashboard},
		{name: "decision", body: decision},
	} {
		t.Run(document.name, func(t *testing.T) {
			text := string(document.body)
			if !strings.Contains(text, ":focus-visible") {
				t.Error("document lacks focus-visible styling")
			}
			if !strings.Contains(text, "outline: 3px solid #174ea6;") {
				t.Error("document lacks the visible focus outline")
			}
			if !strings.Contains(text, "min-width: 24px;") ||
				!strings.Contains(text, "min-height: 24px;") {
				t.Error("document lacks minimum 24 by 24 pixel link targets")
			}
		})
	}
}

func modelForRenderContractTests(t *testing.T) Model {
	t.Helper()
	model, err := BuildModel(loadGoldenBook(t), goldenAsOf)
	if err != nil {
		t.Fatal(err)
	}
	return model
}

func documentsForRenderContractTests(t *testing.T) ([]byte, []byte) {
	t.Helper()
	model := modelForRenderContractTests(t)
	dashboard, err := RenderDashboard(model)
	if err != nil {
		t.Fatal(err)
	}
	decision, found, err := RenderDecision(model, 4)
	if err != nil {
		t.Fatal(err)
	}
	if !found {
		t.Fatal("decision 4 was not found")
	}
	return dashboard, decision
}

func assertRenderedSummary(t *testing.T, model Model, counts map[string]int) {
	t.Helper()
	document, err := RenderDashboard(model)
	if err != nil {
		t.Fatal(err)
	}
	_, remainder, found := strings.Cut(
		string(document),
		`<section aria-labelledby="summary-heading">`,
	)
	if !found {
		t.Fatal("dashboard lacks the derived summary section")
	}
	summary, _, found := strings.Cut(remainder, "</section>")
	if !found {
		t.Fatal("derived summary section is not closed")
	}
	for _, label := range []string{
		"effective",
		"pending",
		"expired",
		"superseded",
		"accepted",
		"deferred",
		"rejected",
	} {
		expected := `<tr><th scope="row">` + label +
			`</th><td>` + strconv.Itoa(counts[label]) + `</td></tr>`
		if strings.Count(summary, expected) != 1 {
			t.Errorf("summary must contain exactly one %s count of %d", label, counts[label])
		}
	}
}

func compareGolden(t *testing.T, name string, got []byte) {
	t.Helper()
	path := filepath.Join("testdata", name)
	if *updatePlatformRenderGoldens {
		if err := os.WriteFile(path, got, 0600); err != nil {
			t.Fatalf("write golden %s: %v", name, err)
		}
		return
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read golden %s: %v", name, err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("document differs from golden %s\n--- got ---\n%s", name, got)
	}
}

func mustBuild(t *testing.T, book casefile.Book) Model {
	t.Helper()
	model, err := BuildModel(book, goldenAsOf)
	if err != nil {
		t.Fatalf("BuildModel: %v", err)
	}
	return model
}

// itoa is the minimal deterministic decimal formatter used to name goldens.
func itoa(value uint64) string {
	if value == 0 {
		return "0"
	}
	var digits []byte
	for value > 0 {
		digits = append([]byte{byte('0' + value%10)}, digits...)
		value /= 10
	}
	return string(digits)
}
