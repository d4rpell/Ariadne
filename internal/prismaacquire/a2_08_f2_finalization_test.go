package prismaacquire

import (
	"strings"
	"testing"
)

// Incremento 10 de A2-08-F2: finalización conjunta (ADR-0028 §8.18, §9, §10). El
// contexto final se fija antes del hash y todas las páginas comparten la misma
// terminación; las dimensiones se mantienen separadas.

func TestA208F2FinalContextPropagation(t *testing.T) {
	result, err := f2Run(t, f2Config(), f2Bearer(), f2Steps(f2DistinctPage(0, 3), f2DistinctPage(1, 2), "[]"))
	if err != nil {
		t.Fatalf("sequence failed: %v", err)
	}
	if len(result.Pages) != 3 {
		t.Fatalf("pages = %d, want 3", len(result.Pages))
	}
	for i, page := range result.Pages {
		ctx := page.Inventory.Context
		if ctx.CaptureTermination != TerminationFinished {
			t.Fatalf("page %d termination = %s, want finished", i, ctx.CaptureTermination)
		}
		if ctx.PagesExpected == nil || *ctx.PagesExpected != 3 {
			t.Fatalf("page %d pages_expected = %v, want 3", i, ctx.PagesExpected)
		}
		if ctx.PageOrdinal == nil || *ctx.PageOrdinal != i+1 {
			t.Fatalf("page %d ordinal = %v, want %d", i, ctx.PageOrdinal, i+1)
		}
		if ctx.AcquisitionKind != "compute_api" {
			t.Fatalf("page %d acquisition_kind = %s, want compute_api", i, ctx.AcquisitionKind)
		}
		if !strings.Contains(string(page.Artifacts.Source), `"version":"1.1"`) {
			t.Fatalf("page %d source does not carry version 1.1", i)
		}
		if !strings.Contains(string(page.Artifacts.Source), `"acquisition_kind":"compute_api"`) {
			t.Fatalf("page %d source lacks compute_api provenance", i)
		}
		if len(page.Artifacts.Digest) != 72 {
			t.Fatalf("page %d sidecar = %d bytes, want 72", i, len(page.Artifacts.Digest))
		}
	}
}

func TestA208F2PartialResult(t *testing.T) {
	script := f2Steps(f2DistinctPage(0, 50), f2DistinctPage(1, 50))
	script.steps = append(script.steps, f2SequencedStep{status: 500, header: nil, body: nil})
	result, err := f2Run(t, f2Config(), f2Bearer(), script)
	if err == nil || err.Code != CodeServerError {
		t.Fatalf("err = %v, want %s", err, CodeServerError)
	}
	if result.Termination != TerminationAborted || result.SequenceCompleteness != SequencePartial {
		t.Fatalf("termination = %s/%s, want aborted/partial", result.Termination, result.SequenceCompleteness)
	}
	if len(result.Pages) != 2 {
		t.Fatalf("pages = %d, want 2", len(result.Pages))
	}
	for i, page := range result.Pages {
		ctx := page.Inventory.Context
		if ctx.CaptureTermination != TerminationAborted {
			t.Fatalf("page %d termination = %s, want aborted", i, ctx.CaptureTermination)
		}
		if ctx.PagesExpected != nil {
			t.Fatalf("page %d pages_expected = %v, want nil", i, ctx.PagesExpected)
		}
	}
}

func TestA208F2ResultDimensions(t *testing.T) {
	t.Run("finished", func(t *testing.T) {
		result, err := f2Run(t, f2Config(), f2Bearer(), f2Steps("[]"))
		if err != nil {
			t.Fatalf("sequence failed: %v", err)
		}
		if result.Termination != TerminationFinished || result.SequenceCompleteness != SequenceComplete ||
			result.InventoryCoverage != InventoryCoverageUnknown || result.Consistency != ConsistencyNotAtomic ||
			result.RuntimeBinding != RuntimeBindingNotAttempted {
			t.Fatalf("dimensions collapsed: %s/%s/%s/%s/%s", result.Termination, result.SequenceCompleteness,
				result.InventoryCoverage, result.Consistency, result.RuntimeBinding)
		}
	})
	t.Run("aborted_without_pages", func(t *testing.T) {
		script := f2Sequenced{steps: []f2SequencedStep{{status: 403, header: nil, body: nil}}}
		result, err := f2Run(t, f2Config(), f2Bearer(), &script)
		if err == nil || err.Code != CodeForbidden {
			t.Fatalf("err = %v, want %s", err, CodeForbidden)
		}
		if result.Termination != TerminationAborted || result.SequenceCompleteness != SequenceUnknown {
			t.Fatalf("dimensions = %s/%s, want aborted/unknown", result.Termination, result.SequenceCompleteness)
		}
		if len(result.Pages) != 0 {
			t.Fatalf("pages = %d, want 0 (no fabricated empty source)", len(result.Pages))
		}
	})
}

func TestA208F2HashCoversFinalContext(t *testing.T) {
	// The manifest source_bytes and the source hash must describe the same final
	// bytes carried by the delivered artifacts.
	result, err := f2Run(t, f2Config(), f2Bearer(), f2Steps(f2DistinctPage(0, 2), "[]"))
	if err != nil {
		t.Fatalf("sequence failed: %v", err)
	}
	page := result.Pages[0]
	if page.Inventory.SourceBytes != uint64(len(page.Artifacts.Source)) {
		t.Fatalf("source_bytes = %d, want %d", page.Inventory.SourceBytes, len(page.Artifacts.Source))
	}
	if !strings.Contains(string(page.Artifacts.Manifest), page.Inventory.SourceHash) {
		t.Fatal("manifest does not reference the source hash")
	}
}
