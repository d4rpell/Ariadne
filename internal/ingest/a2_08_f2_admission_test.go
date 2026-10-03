package ingest

import (
	"testing"
)

// Incremento 4 de A2-08-F2: costura de admisión compartida (ADR-0028 §3.3, §7.10,
// §7.11). Comprueba que la admisión por bytes reutiliza el mismo parser que el
// camino offline 1.0, que la contabilidad es numérica y correcta, que los
// presupuestos adicionales acotan antes de crecer y que la cancelación se honra
// sin importar context en una raíz offline.

const a208F2MinimalJSON = `[{"type":"image","packages":[],"vulnerabilities":[]}]`

// TestA208F2SharedAdmissionProjectsIdentically asserts the connector admission
// (AdmitNativeJSON) and the offline 1.0 entry point (parsePrismaNativeJSON) run
// the same parser and produce byte-identical sources.
func TestA208F2SharedAdmissionProjectsIdentically(t *testing.T) {
	ctx := minimalNativeContext()
	offline, err := parsePrismaNativeJSON([]byte(a208F2MinimalJSON), ctx)
	if err != nil {
		t.Fatalf("offline admission failed: %v", err)
	}
	draft, err := AdmitNativeJSON([]byte(a208F2MinimalJSON), NativeAdmission{})
	if err != nil {
		t.Fatalf("shared admission failed: %v", err)
	}
	shared := draft.Source(jsonProfile(), ctx)
	if got, want := string(EncodeNativeSource(shared)), string(EncodeNativeSource(offline)); got != want {
		t.Fatalf("shared admission differs from offline:\n got: %s\nwant: %s", got, want)
	}
	if draft.Format != "json" || draft.OriginalBytes != uint64(len(a208F2MinimalJSON)) {
		t.Fatalf("draft metadata = %q/%d, want json/%d", draft.Format, draft.OriginalBytes, len(a208F2MinimalJSON))
	}
	if draft.Accounting.Images != 1 || draft.Accounting.Findings != 0 || draft.Accounting.Packages != 0 {
		t.Fatalf("accounting = %+v, want images=1 findings=0 packages=0", draft.Accounting)
	}
	if draft.Accounting.Bytes != uint64(len(a208F2MinimalJSON)) || draft.Accounting.Tokens == 0 {
		t.Fatalf("accounting = %+v, want bytes=%d tokens>0", draft.Accounting, len(a208F2MinimalJSON))
	}
}

// TestA208F2AdmissionCancellation asserts a closed Done channel aborts with the
// cancellation signal and that a nil channel leaves admission uncancellable.
func TestA208F2AdmissionCancellation(t *testing.T) {
	if _, err := AdmitNativeJSON([]byte(a208F2MinimalJSON), NativeAdmission{Done: nil}); err != nil {
		t.Fatalf("nil Done should not cancel: %v", err)
	}
	done := make(chan struct{})
	close(done)
	_, err := AdmitNativeJSON([]byte(a208F2MinimalJSON), NativeAdmission{Done: done})
	if !IsNativeCancelled(err) {
		t.Fatalf("closed Done: err = %v, want cancellation", err)
	}
	if err != nil && err.Error() == "" {
		t.Fatal("cancellation error must have a stable text")
	}
}

// TestA208F2AdmissionTokenBudget asserts the additional token budget lowers the
// F1 ceiling exactly: L-1 is rejected, L and L+1 are admitted.
func TestA208F2AdmissionTokenBudget(t *testing.T) {
	input := []byte(a208F2MinimalJSON)
	base, err := AdmitNativeJSON(input, NativeAdmission{})
	if err != nil {
		t.Fatalf("baseline admission failed: %v", err)
	}
	total := base.Accounting.Tokens
	if total < 2 {
		t.Fatalf("token count = %d, want >= 2", total)
	}
	cases := []struct {
		name   string
		tokens uint64
		ok     bool
	}{
		{"L-1", total - 1, false},
		{"L", total, true},
		{"L+1", total + 1, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := AdmitNativeJSON(input, NativeAdmission{Budget: NativeBudget{Tokens: tc.tokens}})
			if tc.ok && err != nil {
				t.Fatalf("budget %d: unexpected error %v", tc.tokens, err)
			}
			if !tc.ok {
				if err == nil || err.Code != NativeCodeTokenLimit {
					t.Fatalf("budget %d: err = %v, want %s", tc.tokens, err, NativeCodeTokenLimit)
				}
			}
		})
	}
}

// TestA208F2AdmissionImageBudget asserts the image ceiling is a hard cap before
// growth and reports collection_limit.
func TestA208F2AdmissionImageBudget(t *testing.T) {
	one := []byte(`[{"type":"image"}]`)
	two := []byte(`[{"type":"image"},{"type":"image"}]`)
	if _, err := AdmitNativeJSON(one, NativeAdmission{Budget: NativeBudget{Images: 1}}); err != nil {
		t.Fatalf("one image under budget = 1 failed: %v", err)
	}
	_, err := AdmitNativeJSON(two, NativeAdmission{Budget: NativeBudget{Images: 1}})
	if err == nil || err.Code != NativeCodeCollectionLimit {
		t.Fatalf("two images under budget = 1: err = %v, want %s", err, NativeCodeCollectionLimit)
	}
}

// TestA208F2AdmissionFindingBudget asserts the finding ceiling lowers the F1
// per-source vuln limit.
func TestA208F2AdmissionFindingBudget(t *testing.T) {
	two := []byte(`[{"type":"image","vulnerabilities":[{"cve":"CVE-2026-1","cvss":9.81},{"cve":"CVE-2026-2","cvss":7.5}]}]`)
	if _, err := AdmitNativeJSON(two, NativeAdmission{Budget: NativeBudget{Findings: 2}}); err != nil {
		t.Fatalf("two findings under budget = 2 failed: %v", err)
	}
	_, err := AdmitNativeJSON(two, NativeAdmission{Budget: NativeBudget{Findings: 1}})
	if err == nil || err.Code != NativeCodeCollectionLimit {
		t.Fatalf("two findings under budget = 1: err = %v, want %s", err, NativeCodeCollectionLimit)
	}
}

// TestA208F2AdmissionPackageBudget asserts the package ceiling lowers the F1
// per-source package limit.
func TestA208F2AdmissionPackageBudget(t *testing.T) {
	two := []byte(`[{"type":"image","packages":[{"pkgs":[{"name":"a","version":"1"}]},{"pkgs":[{"name":"b","version":"2"}]}]}]`)
	if _, err := AdmitNativeJSON(two, NativeAdmission{Budget: NativeBudget{Packages: 2}}); err != nil {
		t.Fatalf("two packages under budget = 2 failed: %v", err)
	}
	_, err := AdmitNativeJSON(two, NativeAdmission{Budget: NativeBudget{Packages: 1}})
	if err == nil || err.Code != NativeCodeCollectionLimit {
		t.Fatalf("two packages under budget = 1: err = %v, want %s", err, NativeCodeCollectionLimit)
	}
}

// TestA208F2DraftSourceIsIndependent asserts Source copies the records so the
// draft and the produced source never share a mutable slice (§3.6).
func TestA208F2DraftSourceIsIndependent(t *testing.T) {
	draft, err := AdmitNativeJSON([]byte(a208F2MinimalJSON), NativeAdmission{})
	if err != nil {
		t.Fatalf("admission failed: %v", err)
	}
	src := draft.Source(jsonProfile(), minimalNativeContext())
	if len(src.Records) != 1 {
		t.Fatalf("records = %d, want 1", len(src.Records))
	}
	draft.Records[0].Ordinal = 99
	if src.Records[0].Ordinal != 0 {
		t.Fatal("Source shares the records slice with the draft")
	}
}
