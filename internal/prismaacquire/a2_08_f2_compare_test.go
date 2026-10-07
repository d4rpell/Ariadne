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

// f2RepoImage builds a record that carries no id/_id, so participation depends
// on the repoTag sufficiency predicate of §8.12.
func f2RepoImage(repoTag, distro string) string {
	return `{"type":"image","repoTag":` + repoTag + `,"distro":"` + distro + `","packages":[],"vulnerabilities":[]}`
}

// TestA208F2DriftRepoTagSuffices pins the sufficiency predicate of the §8.12
// anchor: a record without id/_id participates only when repoTag carries all of
// registry, repo and tag at once, and a partial repoTag never does.
func TestA208F2DriftRepoTagSuffices(t *testing.T) {
	complete := `{"registry":"reg","repo":"app","tag":"t"}`
	t.Run("complete_repoTag_participates", func(t *testing.T) {
		pageA := "[" + f2RepoImage(complete, "a") + "]"
		pageB := "[" + f2RepoImage(complete, "b") + "]"
		_, err := f2Run(t, f2Config(), f2Bearer(), f2Steps(pageA, pageB))
		if err == nil || err.Code != CodePageDriftSuspected {
			t.Fatalf("err = %v, want %s", err, CodePageDriftSuspected)
		}
		if err.PreviousPage != 1 || err.PageOrdinal != 2 || err.FirstRecord != 0 || err.SecondRecord != 0 {
			t.Fatalf("pair = prev=%d cur=%d rec=%d/%d, want 1/2/0/0", err.PreviousPage, err.PageOrdinal, err.FirstRecord, err.SecondRecord)
		}
	})
	for _, tc := range []struct {
		name    string
		repoTag string
	}{
		{"missing_tag", `{"registry":"reg","repo":"app"}`},
		{"missing_repo", `{"registry":"reg","tag":"t"}`},
		{"missing_registry", `{"repo":"app","tag":"t"}`},
		{"empty_tag", `{"registry":"reg","repo":"app","tag":""}`},
	} {
		t.Run(tc.name+"_does_not_participate", func(t *testing.T) {
			pageA := "[" + f2RepoImage(tc.repoTag, "a") + "]"
			pageB := "[" + f2RepoImage(tc.repoTag, "b") + "]"
			result, err := f2Run(t, f2Config(), f2Bearer(), f2Steps(pageA, pageB, "[]"))
			if err != nil {
				t.Fatalf("insufficient anchor must not drift: %v", err)
			}
			if result.Termination != TerminationFinished {
				t.Fatalf("termination = %s, want finished", result.Termination)
			}
		})
	}
	t.Run("same_id_different_repoTag_is_not_the_same_anchor", func(t *testing.T) {
		// §8.13: two records with the same digest and different repo/tag are not
		// the same record. The anchor carries the repoTag members, so differing
		// tags yield different anchors and no cross-page comparison.
		pageA := "[" + `{"type":"image","id":"x","repoTag":{"registry":"reg","repo":"app","tag":"t1"},"distro":"a","packages":[],"vulnerabilities":[]}` + "]"
		pageB := "[" + `{"type":"image","id":"x","repoTag":{"registry":"reg","repo":"app","tag":"t2"},"distro":"b","packages":[],"vulnerabilities":[]}` + "]"
		result, err := f2Run(t, f2Config(), f2Bearer(), f2Steps(pageA, pageB, "[]"))
		if err != nil {
			t.Fatalf("differing repoTag must not drift: %v", err)
		}
		if result.Termination != TerminationFinished {
			t.Fatalf("termination = %s, want finished", result.Termination)
		}
	})
}
