package platform

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/d4rpell/Ariadne/internal/casefile"
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

func compareGolden(t *testing.T, name string, got []byte) {
	t.Helper()
	want, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatalf("read golden %s: %v", name, err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("document differs from golden %s\n--- got ---\n%s", name, got)
	}
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
// value is a literal null and an empty list is none, never a blank cell.
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
	if !strings.Contains(text, "<code>null</code>") {
		t.Fatal("an absent expires_at must render as an explicit null")
	}
	if !strings.Contains(text, ">none</td>") {
		t.Fatal("an empty anomaly list must render as none")
	}

	empty, err := RenderDashboard(mustBuild(t, casefile.NewBook()))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(empty), "No decision record is present") {
		t.Fatal("the empty book must state its emptiness")
	}
	if !strings.Contains(string(empty), "<code>null</code>") {
		t.Fatal("the empty book has no head and must render null")
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
