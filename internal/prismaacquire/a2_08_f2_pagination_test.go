package prismaacquire

import (
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"
)

// Incremento 8 de A2-08-F2: paginación y terminación (ADR-0028 §8.1–§8.9, §13.4).
// El avance es exacto por número de registros, la página corta no cierra y solo
// una página vacía admitida finaliza.

// f2DistinctPage builds n records whose ids differ per page, so identical pages
// are never produced accidentally.
func f2DistinctPage(page, n int) string { return f2Page(n, fmt.Sprintf("p%d", page)) }

func TestA208F2PaginationSequences(t *testing.T) {
	t.Run("50_50_0", func(t *testing.T) {
		script := f2Steps(f2DistinctPage(0, 50), f2DistinctPage(1, 50), "[]")
		result, err := f2Run(t, f2Config(), f2Bearer(), script)
		if err != nil {
			t.Fatalf("sequence failed: %v", err)
		}
		if result.Termination != TerminationFinished || result.SequenceCompleteness != SequenceComplete {
			t.Fatalf("termination = %s/%s, want finished/complete", result.Termination, result.SequenceCompleteness)
		}
		if len(result.Pages) != 3 {
			t.Fatalf("pages = %d, want 3", len(result.Pages))
		}
		if result.Pages[0].Offset != 0 || result.Pages[1].Offset != 50 || result.Pages[2].Offset != 100 {
			t.Fatalf("offsets = %d,%d,%d, want 0,50,100", result.Pages[0].Offset, result.Pages[1].Offset, result.Pages[2].Offset)
		}
		if result.InventoryCoverage != InventoryCoverageUnknown || result.Consistency != ConsistencyNotAtomic {
			t.Fatalf("dimensions = %s/%s, want unknown/not_atomic", result.InventoryCoverage, result.Consistency)
		}
	})
	t.Run("17_50_0", func(t *testing.T) {
		script := f2Steps(f2DistinctPage(0, 17), f2DistinctPage(1, 50), "[]")
		result, err := f2Run(t, f2Config(), f2Bearer(), script)
		if err != nil {
			t.Fatalf("sequence failed: %v", err)
		}
		if result.Pages[0].Offset != 0 || result.Pages[1].Offset != 17 || result.Pages[2].Offset != 67 {
			t.Fatalf("offsets = %d,%d,%d, want 0,17,67", result.Pages[0].Offset, result.Pages[1].Offset, result.Pages[2].Offset)
		}
	})
	t.Run("empty_only", func(t *testing.T) {
		result, err := f2Run(t, f2Config(), f2Bearer(), f2Steps("[]"))
		if err != nil {
			t.Fatalf("empty sequence failed: %v", err)
		}
		if result.Termination != TerminationFinished || len(result.Pages) != 1 {
			t.Fatalf("termination/pages = %s/%d, want finished/1", result.Termination, len(result.Pages))
		}
		if result.Attempts.ImageGET != 1 {
			t.Fatalf("terminal GET not counted: %d", result.Attempts.ImageGET)
		}
	})
}

func TestA208F2RateLimitIsNotTerminalPage(t *testing.T) {
	script := f2Steps(f2DistinctPage(0, 50))
	script.steps = append(script.steps, f2SequencedStep{status: http.StatusTooManyRequests, header: http.Header{}, body: io.NopCloser(strings.NewReader(""))})
	result, err := f2Run(t, f2Config(), f2Bearer(), script)
	if err == nil || err.Code != CodeRateLimited {
		t.Fatalf("err = %v, want %s", err, CodeRateLimited)
	}
	if result.Termination != TerminationAborted || result.SequenceCompleteness != SequencePartial {
		t.Fatalf("termination = %s/%s, want aborted/partial", result.Termination, result.SequenceCompleteness)
	}
	if len(result.Pages) != 1 {
		t.Fatalf("pages = %d, want 1", len(result.Pages))
	}
	if result.Attempts.ImageGET != 2 {
		t.Fatalf("image GETs = %d, want 2", result.Attempts.ImageGET)
	}
}

func TestA208F2EmptyPageRequired(t *testing.T) {
	// A short page must not close the sequence: the connector issues another GET
	// and only a missing next response aborts it.
	script := f2Steps(f2DistinctPage(0, 10))
	result, err := f2Run(t, f2Config(), f2Bearer(), script)
	if err == nil {
		t.Fatal("a short page was treated as terminal")
	}
	if script.requestCount() != 2 {
		t.Fatalf("requests = %d, want 2", script.requestCount())
	}
	if len(result.Pages) != 1 {
		t.Fatalf("pages = %d, want 1", len(result.Pages))
	}
}

func TestA208F2PageSize(t *testing.T) {
	script := f2Steps(f2Page(51, "p0"))
	result, err := f2Run(t, f2Config(), f2Bearer(), script)
	if err == nil || err.Code != CodePageSizeExceeded {
		t.Fatalf("err = %v, want %s", err, CodePageSizeExceeded)
	}
	if result.Termination != TerminationAborted || len(result.Pages) != 0 {
		t.Fatalf("termination/pages = %s/%d, want aborted/0", result.Termination, len(result.Pages))
	}
}

func TestA208F2ExactImageLimitNeedsTerminalPage(t *testing.T) {
	pages := make([]string, 0, 101)
	for i := 0; i < 100; i++ {
		pages = append(pages, f2DistinctPage(i, 50))
	}
	pages = append(pages, "[]")
	result, err := f2Run(t, f2Config(), f2Bearer(), f2Steps(pages...))
	if err != nil {
		t.Fatalf("5000-image sequence failed: %v", err)
	}
	if result.Termination != TerminationFinished {
		t.Fatalf("termination = %s, want finished", result.Termination)
	}
	if result.Attempts.Images != 5000 {
		t.Fatalf("images = %d, want 5000", result.Attempts.Images)
	}
	if len(result.Pages) != 101 {
		t.Fatalf("pages = %d, want 101", len(result.Pages))
	}
}

func TestA208F2NoDigestDeduplication(t *testing.T) {
	page := `[
		{"type":"image","id":"a","repoDigests":["sha256:aaaa"],"packages":[],"vulnerabilities":[]},
		{"type":"image","id":"b","repoDigests":["sha256:aaaa"],"packages":[],"vulnerabilities":[]}
	]`
	result, err := f2Run(t, f2Config(), f2Bearer(), f2Steps(strings.Join(strings.Fields(page), ""), "[]"))
	if err != nil {
		t.Fatalf("sequence failed: %v", err)
	}
	if result.Pages[0].Inventory.RecordCount != 2 {
		t.Fatalf("records = %d, want 2 (no digest deduplication)", result.Pages[0].Inventory.RecordCount)
	}
}
