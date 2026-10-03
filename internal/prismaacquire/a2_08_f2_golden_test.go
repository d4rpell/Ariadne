package prismaacquire

import (
	"bytes"
	"testing"
)

// Incremento 11 de A2-08-F2: vector determinista de adquisición (ADR-0028
// §13.6). Dos adquisiciones con los mismos datos y el mismo reloj producen
// artefactos byte a byte idénticos; la fuente no lleva LF final y el sidecar sí.

func TestA208F2GoldenAcquisitionVectors(t *testing.T) {
	pages := []string{f2DistinctPage(0, 3), f2DistinctPage(1, 2), "[]"}
	first, err := f2Run(t, f2Config(), f2Bearer(), f2Steps(pages...))
	if err != nil {
		t.Fatalf("first run: %v", err)
	}
	second, err := f2Run(t, f2Config(), f2Bearer(), f2Steps(pages...))
	if err != nil {
		t.Fatalf("second run: %v", err)
	}
	if len(first.Pages) != len(second.Pages) {
		t.Fatalf("page counts differ: %d vs %d", len(first.Pages), len(second.Pages))
	}
	for i := range first.Pages {
		a, b := first.Pages[i], second.Pages[i]
		if !bytes.Equal(a.Artifacts.Source, b.Artifacts.Source) {
			t.Fatalf("page %d source is not deterministic", i)
		}
		if !bytes.Equal(a.Artifacts.Manifest, b.Artifacts.Manifest) {
			t.Fatalf("page %d manifest is not deterministic", i)
		}
		if !bytes.Equal(a.Artifacts.Digest, b.Artifacts.Digest) {
			t.Fatalf("page %d sidecar is not deterministic", i)
		}
		if bytes.HasSuffix(a.Artifacts.Source, []byte("\n")) {
			t.Fatalf("page %d source has a trailing LF", i)
		}
		if len(a.Artifacts.Digest) != 72 || a.Artifacts.Digest[71] != '\n' {
			t.Fatalf("page %d sidecar is not the 72-byte form", i)
		}
	}
	// The terminal empty page is conserved as a real source, not fabricated.
	empty := first.Pages[len(first.Pages)-1]
	if empty.Offset != 5 {
		t.Fatalf("terminal offset = %d, want 5", empty.Offset)
	}
	if empty.Inventory.RecordCount != 0 {
		t.Fatalf("terminal records = %d, want 0", empty.Inventory.RecordCount)
	}
}
