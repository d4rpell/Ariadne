package prismaacquire

import (
	"context"
	"strings"
	"testing"
)

// Incremento 8 de A2-08-F2: admisión compartida con F1 desde el conector
// (ADR-0028 §3.3, §7.10, §9.2). No existe un segundo parser: la página pasa por
// la misma admisión nativa y su rechazo se mapea al catálogo de adquisición.

func TestA208F2SharedNativeAdmission(t *testing.T) {
	// A page with an unknown key inside an interpreted object is rejected by F1
	// and surfaces as native_admission_failed with the native code preserved.
	page := `[{"type":"image","unknown_member":1,"packages":[],"vulnerabilities":[]}]`
	result, err := f2Run(t, f2Config(), f2Bearer(), f2Steps(page))
	if err == nil || err.Code != CodeNativeAdmissionFailed {
		t.Fatalf("err = %v, want %s", err, CodeNativeAdmissionFailed)
	}
	if err.NativeCode != "field_not_allowed" {
		t.Fatalf("native code = %q, want field_not_allowed", err.NativeCode)
	}
	if len(result.Pages) != 0 {
		t.Fatalf("pages = %d, want 0 (the rejected page is not delivered)", len(result.Pages))
	}
}

func TestA208F2NativeBudgetWiring(t *testing.T) {
	// The connector lowers the F1 image ceiling to the remaining accumulated
	// budget, so the shared admission itself stops an over-budget page.
	a := &acquirer{ctx: context.Background(), budget: budget{images: maxImageOccurrences - 1}}
	draft, err := a.admitPage([]byte(`[{"type":"image"},{"type":"image"}]`))
	if err == nil || err.Code != CodeObjectLimit {
		t.Fatalf("err = %v, want %s", err, CodeObjectLimit)
	}
	if len(draft.Records) != 0 {
		t.Fatal("a rejected partially-admitted page produced records")
	}
}

func TestA208F2NoScannerTimeReplacement(t *testing.T) {
	// acquired_at is the local acquisition instant; the scanner scanTime of the
	// record is preserved verbatim and never replaced.
	page := `[{"type":"image","id":"x","scanTime":"2020-01-01T00:00:00Z","packages":[],"vulnerabilities":[]}]`
	result, err := f2Run(t, f2Config(), f2Bearer(), f2Steps(page, "[]"))
	if err != nil {
		t.Fatalf("sequence failed: %v", err)
	}
	source := string(result.Pages[0].Artifacts.Source)
	if !strings.Contains(source, "2020-01-01T00:00:00Z") {
		t.Fatal("the scanner scanTime was replaced or dropped")
	}
	if result.Pages[0].AcquiredAt == "2020-01-01T00:00:00Z" {
		t.Fatal("acquired_at was taken from the scanner time")
	}
}
