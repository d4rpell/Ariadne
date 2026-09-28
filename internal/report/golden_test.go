package report

import (
	"bytes"
	"flag"
	"os"
	"path/filepath"
	"testing"
)

var updateGolden = flag.Bool("update-report-golden", false, "rewrite the presentation goldens from the current renderer")

// The presentation goldens of ADR-0022 §D9: byte-exact output for committed
// fixtures. They are a reviewed oracle, not a self-comparison: a test that
// regenerates and compares its own output proves nothing, so a mismatch fails
// unless the update flag is passed explicitly and the change is reviewed.
//
// F09 covers the inconclusive presentation (missing evidence, no candidate) in
// both formats; F10 covers the affirmative one and is kept as JSON only, because
// its HTML page is derived from the same DTO and would add a large duplicate
// oracle without covering a different projection.
//
// They cover presentation only. Wire vectors stay frozen under docs/spec and
// the evaluation goldens remain deferred to the decision-record phase (A0-04
// D3).
func TestGoldenPresentationF09(t *testing.T) {
	result, bundle := loadEvaluated(t, "F09-unmapped-redhat-package")
	report := mustBuild(t, result, bundle)

	document, err := JSON(report)
	if err != nil {
		t.Fatalf("JSON: %v", err)
	}
	page, err := HTML(report)
	if err != nil {
		t.Fatalf("HTML: %v", err)
	}

	compareGolden(t, "f09.report.json", document)
	compareGolden(t, "f09.report.html", page)
}

func TestGoldenPresentationF10JSON(t *testing.T) {
	result, bundle := loadEvaluated(t, "F10-redhat-backport")
	report := mustBuild(t, result, bundle)

	document, err := JSON(report)
	if err != nil {
		t.Fatalf("JSON: %v", err)
	}
	compareGolden(t, "f10.report.json", document)
}

func compareGolden(t *testing.T, name string, got []byte) {
	t.Helper()
	path := filepath.Join("testdata", name)
	if *updateGolden {
		if err := os.WriteFile(path, got, 0o644); err != nil {
			t.Fatalf("write golden %s: %v", name, err)
		}
		return
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("golden %s: %v (run with -update-report-golden after reviewing the change)", name, err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("golden %s differs from the rendered bytes (run with -update-report-golden only after reviewing why)", name)
	}
}
