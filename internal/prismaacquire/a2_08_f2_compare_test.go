package prismaacquire

import "testing"

// Incremento 9 de A2-08-F2: repetición y drift (ADR-0028 §8.10–§8.14). La
// comparación usa solo datos sanitizados canónicos; el contexto y los offsets
// quedan excluidos.

func f2Image(id, distro string) string {
	return `{"type":"image","id":"` + id + `","distro":"` + distro + `","packages":[],"vulnerabilities":[]}`
}

func TestA208F2RepeatedPage(t *testing.T) {
	page := "[" + f2Image("x", "a") + "," + f2Image("y", "a") + "]"
	script := f2Steps(page, page)
	result, err := f2Run(t, f2Config(), f2Bearer(), script)
	if err == nil || err.Code != CodePageRepeated {
		t.Fatalf("err = %v, want %s", err, CodePageRepeated)
	}
	if len(result.Pages) != 2 {
		t.Fatalf("pages = %d, want 2 (both repeated pages conserved)", len(result.Pages))
	}
}

func TestA208F2RepeatedPageConfirmsCanonicalEquality(t *testing.T) {
	// Same sanitized records on two pages with different acquired_at and ordinal:
	// the excluded context must not hide the repetition.
	same := "[" + f2Image("x", "a") + "]"
	script := f2Steps(same, same)
	result, err := f2Run(t, f2Config(), f2Bearer(), script)
	if err == nil || err.Code != CodePageRepeated {
		t.Fatalf("identical records with a changed context: err = %v, want %s", err, CodePageRepeated)
	}
	if result.Pages[0].AcquiredAt == result.Pages[1].AcquiredAt {
		t.Fatal("test is not discriminating: both pages share a timestamp")
	}
}

func TestA208F2DriftAnchor(t *testing.T) {
	script := f2Steps("["+f2Image("x", "a")+"]", "["+f2Image("x", "b")+"]")
	result, err := f2Run(t, f2Config(), f2Bearer(), script)
	if err == nil || err.Code != CodePageDriftSuspected {
		t.Fatalf("err = %v, want %s", err, CodePageDriftSuspected)
	}
	if len(result.Pages) != 2 {
		t.Fatalf("pages = %d, want 2 (both pages conserved)", len(result.Pages))
	}
}

func TestA208F2DriftFirstPair(t *testing.T) {
	script := f2Steps(
		"["+f2Image("x", "a")+","+f2Image("y", "a")+"]",
		"["+f2Image("y", "b")+","+f2Image("x", "b")+"]",
	)
	_, err := f2Run(t, f2Config(), f2Bearer(), script)
	if err == nil || err.Code != CodePageDriftSuspected {
		t.Fatalf("err = %v, want %s", err, CodePageDriftSuspected)
	}
	if err.PreviousPage != 1 || err.PageOrdinal != 2 || err.FirstRecord != 1 || err.SecondRecord != 0 {
		t.Fatalf("pair = prev=%d cur=%d rec=%d/%d, want 1/2/1/0", err.PreviousPage, err.PageOrdinal, err.FirstRecord, err.SecondRecord)
	}
}

func TestA208F2DriftInsufficientAnchor(t *testing.T) {
	// No id, _id or complete repoTag: the records do not participate, so a
	// difference in other fields is not a drift.
	noAnchorA := `[{"type":"image","distro":"a","packages":[],"vulnerabilities":[]}]`
	noAnchorB := `[{"type":"image","distro":"b","packages":[],"vulnerabilities":[]}]`
	result, err := f2Run(t, f2Config(), f2Bearer(), f2Steps(noAnchorA, noAnchorB, "[]"))
	if err != nil {
		t.Fatalf("sequence failed: %v", err)
	}
	if result.Termination != TerminationFinished {
		t.Fatalf("termination = %s, want finished", result.Termination)
	}
}

func TestA208F2PaginationGuardPrecedence(t *testing.T) {
	// A page that exactly repeats a previous page is reported as repeated, the
	// first cause in the §8.14 order.
	page := "[" + f2Image("x", "a") + "]"
	_, err := f2Run(t, f2Config(), f2Bearer(), f2Steps(page, page))
	if err == nil || err.Code != CodePageRepeated {
		t.Fatalf("err = %v, want %s (repetition precedes drift)", err, CodePageRepeated)
	}
}
