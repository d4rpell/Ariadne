package prismaacquire

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/d4rpell/Ariadne/internal/ingest"
	"github.com/d4rpell/Ariadne/internal/normalize"
	"github.com/d4rpell/Ariadne/internal/schema"
)

// Discriminating tests for the corrections of the independent review of the
// A2-08-F2 delta (0 P0, 4 P1, 9 P2). Each case fails before its correction and
// passes after it.

// f2EncodableSource builds one valid 1.1 API source with the real page context,
// exactly as finalizePages does, so the output-budget borders exercise the real
// canonical writer and the real manifest derivation.
func f2EncodableSource(t *testing.T, page string) ingest.NativeSource {
	t.Helper()
	draft, nativeErr := ingest.AdmitNativeJSON([]byte(page), ingest.NativeAdmission{})
	if nativeErr != nil {
		t.Fatalf("admission failed: %v", nativeErr)
	}
	a := &acquirer{cfg: f2Config()}
	ctx := a.pageContext(pageDraft{ordinal: 1, acquiredAt: "2026-10-03T00:00:00Z"}, TerminationFinished, nil)
	source := draft.Source(apiJSONProfile(), ctx)
	source.Version = schema.NativeFormatVersionV11
	return source
}

func f2GenerousBudget() *outputBudget {
	return &outputBudget{pageSource: 1 << 30, retained: 1 << 30, tokens: 1 << 30}
}

// P1-1: the F2 output budgets are connected to the shared writer with real
// L-1/L/L+1 borders for the per-page source, the accumulated retained artifacts
// and the accumulated derived tokens.
func TestA208F2OutputBudgetBorders(t *testing.T) {
	source := f2EncodableSource(t, f2DistinctPage(0, 3))
	base, err := encodePageArtifacts(source, f2GenerousBudget())
	if err != nil {
		t.Fatalf("baseline encoding failed: %v", err)
	}
	sourceBytes := uint64(len(base.Source))
	retained := uint64(len(base.Source) + len(base.Manifest) + len(base.Digest))
	tokens, ok := ingest.NativeSourceTokenCount(base.Source)
	if !ok || tokens == 0 {
		t.Fatalf("token count = %d/%v", tokens, ok)
	}

	cases := []struct {
		name    string
		budget  *outputBudget
		ok      bool
		wantErr string
	}{
		{"page_L-1", &outputBudget{pageSource: sourceBytes - 1, retained: retained, tokens: tokens}, false, CodeOutputLimit},
		{"page_L", &outputBudget{pageSource: sourceBytes, retained: retained, tokens: tokens}, true, ""},
		{"page_L+1", &outputBudget{pageSource: sourceBytes + 1, retained: retained, tokens: tokens}, true, ""},
		{"retained_L-1", &outputBudget{pageSource: sourceBytes, retained: retained - 1, tokens: tokens}, false, CodeOutputLimit},
		{"retained_L", &outputBudget{pageSource: sourceBytes, retained: retained, tokens: tokens}, true, ""},
		{"retained_L+1", &outputBudget{pageSource: sourceBytes, retained: retained + 1, tokens: tokens}, true, ""},
		{"tokens_L-1", &outputBudget{pageSource: sourceBytes, retained: retained, tokens: tokens - 1}, false, ingest.NativeCodeTokenLimit},
		{"tokens_L", &outputBudget{pageSource: sourceBytes, retained: retained, tokens: tokens}, true, ""},
		{"tokens_L+1", &outputBudget{pageSource: sourceBytes, retained: retained, tokens: tokens + 1}, true, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := encodePageArtifacts(source, tc.budget)
			if tc.ok {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				return
			}
			if err == nil || err.Code != tc.wantErr {
				t.Fatalf("err = %v, want %s", err, tc.wantErr)
			}
		})
	}
}

// P1-1: the retained budget accumulates across pages, so a second page that no
// longer fits is refused with output_limit and no page is published.
func TestA208F2RetainedBudgetAccumulates(t *testing.T) {
	source := f2EncodableSource(t, f2DistinctPage(0, 3))
	first, err := encodePageArtifacts(source, f2GenerousBudget())
	if err != nil {
		t.Fatalf("first page failed: %v", err)
	}
	page := uint64(len(first.Source) + len(first.Manifest) + len(first.Digest))
	// A budget that fits exactly one page and not two.
	budget := &outputBudget{pageSource: 1 << 30, retained: page + page - 1, tokens: 1 << 30}
	if _, err := encodePageArtifacts(source, budget); err != nil {
		t.Fatalf("first page under the shared budget failed: %v", err)
	}
	if _, err := encodePageArtifacts(source, budget); err == nil || err.Code != ingest.NativeCodeOutputLimit {
		t.Fatalf("second page: err = %v, want %s", err, ingest.NativeCodeOutputLimit)
	}
}

// P1-1: an output exhaustion during finalization is a finalization cause mapped
// to output_limit and a derived-token exhaustion to token_limit, not a silent
// success.
func TestA208F2OutputLimitMapping(t *testing.T) {
	mapped := finalizationFailure(outputLimitError())
	if mapped.Code != CodeOutputLimit || mapped.Phase != PhaseFinalization {
		t.Fatalf("mapped = %s/%s, want %s/%s", mapped.Code, mapped.Phase, CodeOutputLimit, PhaseFinalization)
	}
	if mapped.NativeCode != ingest.NativeCodeOutputLimit {
		t.Fatalf("native code = %q, want %q", mapped.NativeCode, ingest.NativeCodeOutputLimit)
	}
	token := finalizationFailure(&ingest.NativeError{Code: ingest.NativeCodeTokenLimit, Phase: ingest.NativePhaseProjection, OffsetSpace: ingest.NativeSpaceNone})
	if token.Code != CodeTokenLimit || token.NativeCode != ingest.NativeCodeTokenLimit {
		t.Fatalf("token mapped = %s/%s, want %s/%s", token.Code, token.NativeCode, CodeTokenLimit, ingest.NativeCodeTokenLimit)
	}
}

// P1-2: an active zero ceiling rejects the next element before it is built and
// still admits the empty array that closes the sequence.
func TestA208F2ActiveZeroCeilings(t *testing.T) {
	big := uint64(1 << 30)
	t.Run("images_zero_rejects_non_empty", func(t *testing.T) {
		_, err := ingest.AdmitNativeJSON([]byte(`[{"type":"image"}]`), ingest.NativeAdmission{
			Budget: ingest.NativeBudget{LimitsActive: true, Images: 0, PageImages: maxImagesPerPage, Tokens: big, Findings: big, Packages: big},
		})
		if err == nil || err.Code != ingest.NativeCodeCollectionLimit {
			t.Fatalf("err = %v, want %s", err, ingest.NativeCodeCollectionLimit)
		}
	})
	t.Run("images_zero_admits_empty_array", func(t *testing.T) {
		draft, err := ingest.AdmitNativeJSON([]byte(`[]`), ingest.NativeAdmission{
			Budget: ingest.NativeBudget{LimitsActive: true, Images: 0, PageImages: maxImagesPerPage, Tokens: big, Findings: big, Packages: big},
		})
		if err != nil {
			t.Fatalf("empty array rejected under an exhausted image budget: %v", err)
		}
		if len(draft.Records) != 0 {
			t.Fatalf("records = %d, want 0", len(draft.Records))
		}
	})
	t.Run("findings_zero_reserved_before_growth", func(t *testing.T) {
		page := `[{"type":"image","vulnerabilities":[{"cve":"CVE-2026-1"}]}]`
		_, err := ingest.AdmitNativeJSON([]byte(page), ingest.NativeAdmission{
			Budget: ingest.NativeBudget{LimitsActive: true, Images: big, PageImages: maxImagesPerPage, Tokens: big, Findings: 0, Packages: big},
		})
		if err == nil || err.Code != ingest.NativeCodeCollectionLimit {
			t.Fatalf("err = %v, want %s", err, ingest.NativeCodeCollectionLimit)
		}
	})
	t.Run("packages_zero_reserved_before_growth", func(t *testing.T) {
		page := `[{"type":"image","packages":[{"pkgs":[{"name":"a","version":"1"}]}]}]`
		_, err := ingest.AdmitNativeJSON([]byte(page), ingest.NativeAdmission{
			Budget: ingest.NativeBudget{LimitsActive: true, Images: big, PageImages: maxImagesPerPage, Tokens: big, Findings: big, Packages: 0},
		})
		if err == nil || err.Code != ingest.NativeCodeCollectionLimit {
			t.Fatalf("err = %v, want %s", err, ingest.NativeCodeCollectionLimit)
		}
	})
	t.Run("page_size_cap_is_distinct", func(t *testing.T) {
		page := f2Page(51, "p0")
		_, err := ingest.AdmitNativeJSON([]byte(page), ingest.NativeAdmission{
			Budget: ingest.NativeBudget{LimitsActive: true, Images: big, PageImages: maxImagesPerPage, Tokens: big, Findings: big, Packages: big},
		})
		if !ingest.IsNativePageSizeExceeded(err) {
			t.Fatalf("err = %v, want the page-size signal", err)
		}
	})
}

// P1-2: at the connector level, 5000 exact images followed by a non-empty page
// abort with object_limit without admitting the extra page; the empty array
// still closes the sequence.
func TestA208F2ExactImageLimitRejectsNextImage(t *testing.T) {
	pages := make([]string, 0, 102)
	for i := 0; i < 100; i++ {
		pages = append(pages, f2DistinctPage(i, 50))
	}
	pages = append(pages, f2DistinctPage(100, 1))
	result, err := f2Run(t, f2Config(), f2Bearer(), f2Steps(pages...))
	if err == nil || err.Code != CodeObjectLimit {
		t.Fatalf("err = %v, want %s", err, CodeObjectLimit)
	}
	if result.Termination != TerminationAborted || len(result.Pages) != 100 {
		t.Fatalf("termination/pages = %s/%d, want aborted/100", result.Termination, len(result.Pages))
	}
}

// P1-3: cancellation observed during finalization reconstructs the set as
// aborted (or delivers no artifacts), never as finished.
func TestA208F2FinalizationCancellationIsAborted(t *testing.T) {
	draft, nativeErr := ingest.AdmitNativeJSON([]byte(f2DistinctPage(0, 2)), ingest.NativeAdmission{})
	if nativeErr != nil {
		t.Fatalf("admission failed: %v", nativeErr)
	}
	parent, cancel := context.WithCancel(context.Background())
	cancel()
	a := &acquirer{
		parent: parent, ctx: context.Background(), cfg: f2Config(),
		now: newF2Clock().now, sleep: newF2Clock().sleep,
		comparer: newPageComparer(),
		pages:    []pageDraft{{ordinal: 1, offset: 0, acquiredAt: "2026-10-03T00:00:00Z", draft: draft}},
	}
	result, err := a.finish(nil)
	if result.Termination == TerminationFinished {
		t.Fatal("finalization returned finished after the caller cancelled")
	}
	if result.Termination != TerminationAborted {
		t.Fatalf("termination = %s, want aborted", result.Termination)
	}
	if err == nil || err.Code != CodeCancelled {
		t.Fatalf("err = %v, want %s", err, CodeCancelled)
	}
	if len(result.Pages) != 0 {
		t.Fatalf("pages = %d, want 0 (no incoherent subset)", len(result.Pages))
	}
}

// P1-4: a token that expires between pages aborts with credential_expired
// before the next request is sent, conserving the previous page as aborted.
func TestA208F2ExpiryBetweenPages(t *testing.T) {
	base := time.Date(2026, 10, 3, 12, 0, 0, 0, time.UTC)
	var calls int
	now := func() time.Time {
		calls++
		return base.Add(time.Duration(calls) * time.Second)
	}
	expiry := base.Add(5 * time.Second)
	cfg := f2Config()
	cfg.TokenExpiresAt = &expiry
	script := f2Steps(f2DistinctPage(0, 2), "[]")
	result, err := acquireWith(context.Background(), cfg, f2Bearer(),
		func([]byte) (http.RoundTripper, *AcquisitionError) { return script, nil },
		runtimeHooks{now: now, sleep: func(context.Context, time.Duration) error { return nil }})
	if err == nil || err.Code != CodeCredentialExpired {
		t.Fatalf("err = %v, want %s", err, CodeCredentialExpired)
	}
	if script.requestCount() != 1 {
		t.Fatalf("requests = %d, want 1 (the expired request must not be sent)", script.requestCount())
	}
	if result.Termination != TerminationAborted || len(result.Pages) != 1 {
		t.Fatalf("termination/pages = %s/%d, want aborted/1", result.Termination, len(result.Pages))
	}
}

// P2-1: drift keeps every variant of an anchor, so a conflict between a
// non-first variant of a page and a later page is still detected.
func TestA208F2DriftKeepsAnchorVariants(t *testing.T) {
	page1 := "[" + f2Image("A", "x") + "," + f2Image("A", "y") + "]"
	page2 := "[" + f2Image("A", "x") + "]"
	_, err := f2Run(t, f2Config(), f2Bearer(), f2Steps(page1, page2))
	if err == nil || err.Code != CodePageDriftSuspected {
		t.Fatalf("err = %v, want %s", err, CodePageDriftSuspected)
	}
	if err.PreviousPage != 1 || err.PageOrdinal != 2 || err.FirstRecord != 1 || err.SecondRecord != 0 {
		t.Fatalf("pair = %d/%d/%d/%d, want 1/2/1/0", err.PreviousPage, err.PageOrdinal, err.FirstRecord, err.SecondRecord)
	}
}

// P2-2: attempt availability is checked without consuming, and only delivery to
// the transport consumes it.
func TestA208F2AttemptConsumedAtDelivery(t *testing.T) {
	b := &budget{attempts: maxTotalAttempts}
	if err := b.ensureAttempt(); err == nil || err.Code != CodeRequestLimit {
		t.Fatalf("ensure at limit: err = %v, want %s", err, CodeRequestLimit)
	}
	if b.attempts != maxTotalAttempts {
		t.Fatalf("ensure consumed an attempt: %d", b.attempts)
	}
	if err := b.reserveAttempt(); err == nil || err.Code != CodeRequestLimit {
		t.Fatalf("reserve at limit: err = %v, want %s", err, CodeRequestLimit)
	}
	page := &budget{pageAttempts: maxImageGETAttempts}
	if err := page.ensurePage(); err == nil || err.Code != CodePageLimit {
		t.Fatalf("ensure page at limit: err = %v, want %s", err, CodePageLimit)
	}
	if page.pageAttempts != maxImageGETAttempts {
		t.Fatalf("ensurePage consumed a page: %d", page.pageAttempts)
	}

	// A request rejected by the local guard never reaches the transport and
	// consumes no attempt: the origin and the authority disagree.
	script := f2Steps("[]")
	clock := newF2Clock()
	a := &acquirer{
		parent: context.Background(), ctx: context.Background(), cfg: f2Config(),
		cred: f2Bearer(), origin: "https://other.example.test:8443", authority: "prisma.example.test:8443",
		token: "synthetic.token", now: clock.now, sleep: clock.sleep,
		comparer: newPageComparer(), client: newHTTPClient(script),
	}
	_, err := a.runPages()
	if err == nil || err.Code != CodeRequestNotAllowed {
		t.Fatalf("err = %v, want %s", err, CodeRequestNotAllowed)
	}
	if a.budget.attempts != 0 || a.budget.pageAttempts != 0 {
		t.Fatalf("a locally rejected request consumed attempts: total=%d page=%d", a.budget.attempts, a.budget.pageAttempts)
	}
	if script.requestCount() != 0 {
		t.Fatalf("requests = %d, want 0", script.requestCount())
	}
}

// P2-3: timeout, global budget and cancellation are classified from the
// connector's own state instead of being collapsed.
func TestA208F2DiagnosticsNotCollapsed(t *testing.T) {
	t.Run("body_timeout_is_request_timeout", func(t *testing.T) {
		a := &acquirer{parent: context.Background(), ctx: context.Background()}
		if err := a.classifyReadError(context.DeadlineExceeded); err == nil || err.Code != CodeRequestTimeout {
			t.Fatalf("err = %v, want %s", err, CodeRequestTimeout)
		}
	})
	t.Run("body_cancel_is_cancelled", func(t *testing.T) {
		a := &acquirer{parent: context.Background(), ctx: context.Background()}
		if err := a.classifyReadError(context.Canceled); err == nil || err.Code != CodeCancelled {
			t.Fatalf("err = %v, want %s", err, CodeCancelled)
		}
	})
	t.Run("global_deadline_is_time_limit", func(t *testing.T) {
		runCtx, cancel := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
		defer cancel()
		a := &acquirer{parent: context.Background(), ctx: runCtx}
		if err := a.classifyReadError(context.DeadlineExceeded); err == nil || err.Code != CodeTimeLimit {
			t.Fatalf("err = %v, want %s", err, CodeTimeLimit)
		}
	})
	t.Run("admission_deadline_is_time_limit", func(t *testing.T) {
		runCtx, cancel := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
		defer cancel()
		a := &acquirer{parent: context.Background(), ctx: runCtx, cfg: f2Config(), budget: budget{}}
		_, err := a.admitPage([]byte(`[{"type":"image"}]`))
		if err == nil || err.Code != CodeTimeLimit {
			t.Fatalf("err = %v, want %s", err, CodeTimeLimit)
		}
	})
	t.Run("admission_cancel_is_cancelled", func(t *testing.T) {
		runCtx, cancel := context.WithCancel(context.Background())
		cancel()
		a := &acquirer{parent: context.Background(), ctx: runCtx, cfg: f2Config(), budget: budget{}}
		_, err := a.admitPage([]byte(`[{"type":"image"}]`))
		if err == nil || err.Code != CodeCancelled {
			t.Fatalf("err = %v, want %s", err, CodeCancelled)
		}
	})
}

// P2-4: a page of 51 or 52 records is page_size_exceeded, never object_limit.
func TestA208F2PageSizePrecedence(t *testing.T) {
	t.Run("50_finishes", func(t *testing.T) {
		result, err := f2Run(t, f2Config(), f2Bearer(), f2Steps(f2Page(50, "p0"), "[]"))
		if err != nil {
			t.Fatalf("50 records: %v", err)
		}
		if result.Termination != TerminationFinished {
			t.Fatalf("termination = %s, want finished", result.Termination)
		}
	})
	for _, n := range []int{51, 52} {
		t.Run("page_"+strconv.Itoa(n), func(t *testing.T) {
			_, err := f2Run(t, f2Config(), f2Bearer(), f2Steps(f2Page(n, "p0")))
			if err == nil || err.Code != CodePageSizeExceeded {
				t.Fatalf("%d records: err = %v, want %s", n, err, CodePageSizeExceeded)
			}
		})
	}
}

// P2-5: the final guard verifies the mandatory query and header values and the
// authentication state of the sequence.
func TestA208F2GuardMandatoryValues(t *testing.T) {
	a := f2Acquirer(f2Config())
	req, _ := a.buildImageRequest(0)

	missingHeader := req.Clone(req.Context())
	missingHeader.Header.Del("Accept-Encoding")
	if err := a.guardRequest(missingHeader, http.MethodGet, imagesPath, true); err == nil || err.Code != CodeRequestNotAllowed {
		t.Fatalf("missing Accept-Encoding: err = %v, want %s", err, CodeRequestNotAllowed)
	}

	wrongAuth := req.Clone(req.Context())
	wrongAuth.Header.Set("Authorization", "Bearer other")
	if err := a.guardRequest(wrongAuth, http.MethodGet, imagesPath, true); err == nil || err.Code != CodeRequestNotAllowed {
		t.Fatalf("wrong Authorization: err = %v, want %s", err, CodeRequestNotAllowed)
	}

	incomplete := req.Clone(req.Context())
	q := incomplete.URL.Query()
	q.Del("limit")
	incomplete.URL.RawQuery = q.Encode()
	if err := a.guardRequest(incomplete, http.MethodGet, imagesPath, true); err == nil || err.Code != CodeRequestNotAllowed {
		t.Fatalf("incomplete query: err = %v, want %s", err, CodeRequestNotAllowed)
	}

	extra := req.Clone(req.Context())
	q = extra.URL.Query()
	q.Set("fields", "x")
	extra.URL.RawQuery = q.Encode()
	if err := a.guardRequest(extra, http.MethodGet, imagesPath, true); err == nil || err.Code != CodeRequestNotAllowed {
		t.Fatalf("extra query parameter: err = %v, want %s", err, CodeRequestNotAllowed)
	}

	unauthenticated := f2Acquirer(f2Config())
	unauthenticated.token = ""
	unauthReq, _ := unauthenticated.buildImageRequest(0)
	if err := unauthenticated.guardRequest(unauthReq, http.MethodGet, imagesPath, true); err == nil || err.Code != CodeRequestNotAllowed {
		t.Fatalf("unauthenticated GET: err = %v, want %s", err, CodeRequestNotAllowed)
	}
}

// P2-6: the civil comparison must not retain the monotonic reading.
func TestA208F2CivilComparisonStripsMonotonic(t *testing.T) {
	a := &acquirer{now: func() time.Time { return time.Now() }}
	if _, err := a.acquiredAt(); err != nil {
		t.Fatalf("first timestamp rejected: %v", err)
	}
	if strings.Contains(a.lastCivil.String(), " m=") {
		t.Fatalf("the civil comparison retained a monotonic reading: %q", a.lastCivil.String())
	}
}

// P2-7: the referenced configuration is captured at admission, so a mutation
// during the run cannot change the scope alias or the expiry.
func TestA208F2ConfigSnapshot(t *testing.T) {
	alias := "scope-a"
	future := time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)
	cfg := f2Config()
	cfg.ScopeAlias = &alias
	cfg.TokenExpiresAt = &future
	script := f2Steps("[]")
	clock := newF2Clock()
	factory := func([]byte) (http.RoundTripper, *AcquisitionError) {
		*cfg.ScopeAlias = "mutated"
		*cfg.TokenExpiresAt = time.Date(2000, 1, 1, 0, 0, 0, 0, time.UTC)
		return script, nil
	}
	result, err := acquireWith(context.Background(), cfg, f2Bearer(), factory, runtimeHooks{now: clock.now, sleep: clock.sleep})
	if err != nil {
		t.Fatalf("sequence failed: %v", err)
	}
	if result.ScopeAlias == nil || *result.ScopeAlias != "scope-a" {
		t.Fatalf("scope alias = %v, want the value captured at admission", result.ScopeAlias)
	}
	if result.Termination != TerminationFinished {
		t.Fatalf("termination = %s, want finished (the captured expiry must be used)", result.Termination)
	}
}

// P2-8: an alias outside the F1 grammar is rejected before any credential or
// transport use, with zero sends.
func TestA208F2AliasGrammarBeforeNetwork(t *testing.T) {
	bad := []string{"", ".leading", "-leading", "_leading", "a b", "a/b", strings.Repeat("a", 129)}
	for _, value := range bad {
		t.Run("origin", func(t *testing.T) {
			cfg := f2Config()
			cfg.OriginAlias = value
			if err := validateConfig(cfg); err == nil || err.Code != CodeInvalidConfig {
				t.Fatalf("origin alias %q: err = %v, want %s", value, err, CodeInvalidConfig)
			}
		})
		t.Run("scope", func(t *testing.T) {
			cfg := f2Config()
			cfg.ScopeAlias = &value
			if err := validateConfig(cfg); err == nil || err.Code != CodeInvalidConfig {
				t.Fatalf("scope alias %q: err = %v, want %s", value, err, CodeInvalidConfig)
			}
		})
	}
	// An invalid alias produces no request: the transport factory is never called.
	cfg := f2Config()
	cfg.OriginAlias = ".bad"
	called := false
	_, err := acquireWith(context.Background(), cfg, f2Bearer(),
		func([]byte) (http.RoundTripper, *AcquisitionError) { called = true; return f2Steps("[]"), nil },
		runtimeHooks{})
	if err == nil || err.Code != CodeInvalidConfig {
		t.Fatalf("err = %v, want %s", err, CodeInvalidConfig)
	}
	if called {
		t.Fatal("an invalid alias reached the transport")
	}
}

// P2-9: the golden vectors are checked against an independent SHA-256 oracle,
// the sidecar is verified and a tampered source is rejected.
func TestA208F2GoldenIndependentOracle(t *testing.T) {
	result, err := f2Run(t, f2Config(), f2Bearer(), f2Steps(f2DistinctPage(0, 3), f2DistinctPage(1, 2), "[]"))
	if err != nil {
		t.Fatalf("sequence failed: %v", err)
	}
	for i, page := range result.Pages {
		sourceSum := sha256.Sum256(page.Artifacts.Source)
		sourceHash := "sha256:" + hex.EncodeToString(sourceSum[:])
		if page.Inventory.SourceHash != sourceHash {
			t.Fatalf("page %d source hash = %s, want the independently recomputed %s", i, page.Inventory.SourceHash, sourceHash)
		}
		manifestSum := sha256.Sum256(page.Artifacts.Manifest)
		wantSidecar := "sha256:" + hex.EncodeToString(manifestSum[:]) + "\n"
		if string(page.Artifacts.Digest) != wantSidecar {
			t.Fatalf("page %d sidecar = %q, want %q", i, page.Artifacts.Digest, wantSidecar)
		}
		if !strings.Contains(string(page.Artifacts.Manifest), sourceHash) {
			t.Fatalf("page %d manifest does not reference its source hash", i)
		}
		if !strings.Contains(string(page.Artifacts.Source), `"version":"1.1"`) ||
			!strings.Contains(string(page.Artifacts.Source), `"acquisition_kind":"compute_api"`) {
			t.Fatalf("page %d does not carry the 1.1 compute_api provenance", i)
		}
	}
	// A tampered source no longer matches the manifest hash.
	page := result.Pages[0]
	tampered := append([]byte(nil), page.Artifacts.Source...)
	tampered[0] = '['
	tampered = append(tampered, ' ')
	sum := sha256.Sum256(tampered)
	if "sha256:"+hex.EncodeToString(sum[:]) == page.Inventory.SourceHash {
		t.Fatal("the independent oracle did not detect the tampered source")
	}
}

// M8 gap: a 401 aborts without reauthentication or renewal.
func TestA208F2NoRenewalAfter401(t *testing.T) {
	cfg := f2Config()
	cfg.AuthMode = AuthPasswordExchange
	cred := Credential{Reference: "cred-1", Username: "u", Password: "p"}
	script := &f2Sequenced{steps: []f2SequencedStep{
		{status: http.StatusOK, body: io.NopCloser(strings.NewReader(`{"token":"synthetic.token"}`))},
		{status: http.StatusUnauthorized, header: http.Header{}, body: io.NopCloser(strings.NewReader(""))},
	}}
	result, err := f2Run(t, cfg, cred, script)
	if err == nil || err.Code != CodeAuthFailed {
		t.Fatalf("err = %v, want %s", err, CodeAuthFailed)
	}
	if script.requestCount() != 2 {
		t.Fatalf("requests = %d, want 2 (no reauthentication POST)", script.requestCount())
	}
	if len(result.Pages) != 0 {
		t.Fatalf("pages = %d, want 0", len(result.Pages))
	}
}

// M14 gap: an excluded member value is never persisted in the artifacts.
func TestA208F2ExcludedValueNotPersisted(t *testing.T) {
	const marker = "MARKER14_EXCLUDED_VALUE"
	page := `[{"type":"image","hostname":"` + marker + `","packages":[],"vulnerabilities":[]}]`
	result, err := f2Run(t, f2Config(), f2Bearer(), f2Steps(page, "[]"))
	if err != nil {
		t.Fatalf("sequence failed: %v", err)
	}
	for i, p := range result.Pages {
		if strings.Contains(string(p.Artifacts.Source), marker) || strings.Contains(string(p.Artifacts.Manifest), marker) {
			t.Fatalf("page %d leaked an excluded value", i)
		}
	}
}

// M18 gap: the inventory context is interpreted from the same context that was
// serialized and hashed, not from a context mutated afterwards.
func TestA208F2InventoryContextMatchesSource(t *testing.T) {
	result, err := f2Run(t, f2Config(), f2Bearer(), f2Steps(f2DistinctPage(0, 2), "[]"))
	if err != nil {
		t.Fatalf("sequence failed: %v", err)
	}
	page := result.Pages[0]
	if page.Inventory.Context.AcquiredAt != page.AcquiredAt {
		t.Fatalf("inventory acquired_at = %q, want the source value %q", page.Inventory.Context.AcquiredAt, page.AcquiredAt)
	}
	if !strings.Contains(string(page.Artifacts.Source), `"acquired_at":"`+page.AcquiredAt+`"`) {
		t.Fatal("the source does not carry the inventory acquired_at")
	}
}

// R2-02: a cancellation that arrives during the construction of the last page —
// after the loop-entry checkpoint — must not yield `finished`. The hook cancels
// once the last page is built, before the set is published.
func TestA208F2CancellationDuringLastPageConstruction(t *testing.T) {
	draft, nativeErr := ingest.AdmitNativeJSON([]byte(f2DistinctPage(0, 2)), ingest.NativeAdmission{})
	if nativeErr != nil {
		t.Fatalf("admission failed: %v", nativeErr)
	}
	parent, cancel := context.WithCancel(context.Background())
	defer cancel()
	a := &acquirer{
		parent: parent, ctx: context.Background(), cfg: f2Config(),
		now: newF2Clock().now, sleep: newF2Clock().sleep,
		comparer: newPageComparer(),
		pages:    []pageDraft{{ordinal: 1, offset: 0, acquiredAt: "2026-10-03T00:00:00Z", draft: draft}},
	}
	a.finalizationHook = cancel
	result, err := a.finish(nil)
	if result.Termination == TerminationFinished {
		t.Fatal("a cancellation during the last page yielded finished")
	}
	if result.Termination != TerminationAborted {
		t.Fatalf("termination = %s, want aborted", result.Termination)
	}
	if err == nil || err.Code != CodeCancelled {
		t.Fatalf("err = %v, want %s", err, CodeCancelled)
	}
	if len(result.Pages) != 0 {
		t.Fatalf("pages = %d, want 0 (no incoherent subset)", len(result.Pages))
	}
}

// f2TruncatedBody returns a prefix and then io.ErrUnexpectedEOF, modelling a
// truncated response body.
type f2TruncatedBody struct {
	data []byte
	done bool
}

func (r *f2TruncatedBody) Read(p []byte) (int, error) {
	if !r.done {
		r.done = true
		return copy(p, r.data), io.ErrUnexpectedEOF
	}
	return 0, io.ErrUnexpectedEOF
}

// R2-04: a truncated body is body_read_failed/body, not transport_failed/request.
func TestA208F2TruncatedBodyIsBodyReadFailed(t *testing.T) {
	a := f2Acquirer(f2Config())
	a.parent = context.Background()
	resp := &http.Response{
		StatusCode: http.StatusOK,
		Header:     f2JSONHeader(),
		Body:       io.NopCloser(&f2TruncatedBody{data: []byte(f2DistinctPage(0, 2))}),
	}
	_, err := a.readResponse(resp, maxImageResponseBytes)
	if err == nil || err.Code != CodeBodyReadFailed || err.Phase != PhaseBody {
		t.Fatalf("err = %v, want %s/%s", err, CodeBodyReadFailed, PhaseBody)
	}
}

// R2-05: the declared expiry is revalidated before the authentication POST: a
// token that expires after admission but before the POST aborts with
// credential_expired and no request is sent.
func TestA208F2ExpiryBeforeAuthPost(t *testing.T) {
	cfg := f2Config()
	cfg.AuthMode = AuthPasswordExchange
	cred := Credential{Reference: "cred-1", Username: "u", Password: "p"}
	base := time.Date(2026, 10, 3, 12, 0, 0, 0, time.UTC)
	expiry := base.Add(10 * time.Second)
	cfg.TokenExpiresAt = &expiry
	advanced := false
	now := func() time.Time {
		if advanced {
			return base.Add(time.Hour)
		}
		return base.Add(time.Second)
	}
	script := f2Steps(f2DistinctPage(0, 2), "[]")
	result, err := acquireWith(context.Background(), cfg, cred,
		func([]byte) (http.RoundTripper, *AcquisitionError) { advanced = true; return script, nil },
		runtimeHooks{now: now, sleep: func(context.Context, time.Duration) error { return nil }})
	if err == nil || err.Code != CodeCredentialExpired {
		t.Fatalf("err = %v, want %s", err, CodeCredentialExpired)
	}
	if script.requestCount() != 0 {
		t.Fatalf("requests = %d, want 0 (the expired POST must not be sent)", script.requestCount())
	}
	if result.Termination != TerminationAborted {
		t.Fatalf("termination = %s, want aborted", result.Termination)
	}
}

// R2-06: an oversized CA is rejected without being duplicated first; an accepted
// CA is captured independently of the caller's slice.
func TestA208F2CAValidatedBeforeCopy(t *testing.T) {
	big := make([]byte, maxCAContentBytes+1)
	cfg := f2Config()
	cfg.CA = big
	snap := snapshotConfig(cfg)
	if len(snap.CA) != len(big) {
		t.Fatalf("oversized CA length = %d, want %d", len(snap.CA), len(big))
	}
	if &snap.CA[0] != &big[0] {
		t.Fatal("the oversized CA was duplicated before its length was checked")
	}
	if err := validateConfig(snap); err == nil || err.Code != CodeTLSConfigInvalid {
		t.Fatalf("err = %v, want %s", err, CodeTLSConfigInvalid)
	}

	ca := []byte("synthetic-ca")
	cfg2 := f2Config()
	cfg2.CA = ca
	snap2 := snapshotConfig(cfg2)
	if &snap2.CA[0] == &ca[0] {
		t.Fatal("an accepted CA was not captured")
	}
	ca[0] = 'X'
	if snap2.CA[0] == 'X' {
		t.Fatal("the captured CA shares memory with the caller")
	}
}

// R2-01: the 72-byte sidecar is reserved before the manifest limit is computed
// and before the sidecar is built.
func TestA208F2SidecarReservedBeforeManifest(t *testing.T) {
	const maxManifest = uint64(schema.NativeMaxManifestBytes)
	cases := []struct {
		name      string
		remaining uint64
		limit     uint64
		ok        bool
	}{
		{"zero", 0, 0, false},
		{"below_sidecar", sidecarBytes - 1, 0, false},
		{"sidecar_only", sidecarBytes, 0, false},
		{"sidecar_plus_5", sidecarBytes + 5, 5, true},
		{"caps_at_manifest_max", sidecarBytes + maxManifest, maxManifest, true},
		{"above_manifest_max", sidecarBytes + maxManifest + 99, maxManifest, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			limit, ok := manifestLimitAfterSidecar(tc.remaining)
			if ok != tc.ok || limit != tc.limit {
				t.Fatalf("limit/ok = %d/%v, want %d/%v", limit, ok, tc.limit, tc.ok)
			}
		})
	}
}

// f2BaseOfflineContext is the §11.12.1 offline context, replicated so the test
// can rebuild the published 1.0 source vector as its oracle base.
func f2BaseOfflineContext() ingest.NativeContext {
	f := false
	return ingest.NativeContext{
		OriginAlias:        "synthetic",
		SourceAlias:        "fixture",
		DeclaredEdition:    "compute_self_hosted",
		DeclaredRelease:    "34.04.145",
		VersionBasis:       "operator_declared",
		ReportKind:         "deployed_images",
		AcquisitionKind:    "synthetic_fixture",
		AcquiredAt:         "2026-10-02T00:00:00Z",
		CaptureTermination: "finished",
		ScopeMode:          "unfiltered_declared",
		FilterStatus:       "none_declared",
		Compact:            &f,
		NormalizedSeverity: &f,
		Layers:             &f,
		FieldsMode:         "unrestricted_declared",
		SelectedFields:     []string{},
		PageMode:           "export_declared",
		DataPolicyAck:      "prisma-native-offline-redaction-v1/1.0",
	}
}

// f2APIBaseSource rebuilds the published §11.12.1 1.0 JSON source vector and
// anchors it to its contract length and SHA-256. It is the independent oracle
// base: the 1.1 vectors are derived from it, never from the producer.
func f2APIBaseSource(t *testing.T) string {
	t.Helper()
	payload := `[{"type":"image","packages":[],"vulnerabilities":[]}]`
	src, err := ingest.ParsePrismaNative(strings.NewReader(payload),
		schema.NativeJSONSelector, schema.NativeInputVersion, schema.NativeJSONProfile, f2BaseOfflineContext())
	if err != nil {
		t.Fatalf("base 1.0 parse failed: %v", err)
	}
	got := string(ingest.EncodeNativeSource(src))
	if len(got) != 1187 || ingest.HashNativeSource([]byte(got)) != "sha256:25cb2426ee5cd817d410e554145042a0e010c121399e101e4bd4b9620fd19a15" {
		t.Fatalf("the published 1.0 base vector diverged (len=%d)", len(got))
	}
	return got
}

// f2ExpectedAPISource derives one 1.1 compute_api page source from the published
// 1.0 vector by applying the documented version/provenance substitutions and the
// fixed F2 page context (ADR-0028 §9.4–§9.5). The result is an independent
// oracle; the producer output is compared against it, never the reverse, so a
// deterministic change in any other field is caught.
func f2ExpectedAPISource(t *testing.T, base, sourceAlias, acquiredAt string, ordinal, pagesExpected int, empty bool) string {
	t.Helper()
	text := base
	subs := [][2]string{
		{`"version":"1.0"`, `"version":"1.1"`},
		{`"origin_alias":"synthetic"`, `"origin_alias":"origin-a"`},
		{`"source_alias":"fixture","declared_edition"`, `"source_alias":"` + sourceAlias + `","declared_edition"`},
		{`"acquisition_kind":"synthetic_fixture"`, `"acquisition_kind":"compute_api"`},
		{`"acquired_at":"2026-10-02T00:00:00Z"`, `"acquired_at":"` + acquiredAt + `"`},
		{`"scope_mode":"unfiltered_declared"`, `"scope_mode":"filtered_declared"`},
		{`"scope_alias":null`, `"scope_alias":"scope-a"`},
		{`"filter_status":"none_declared"`, `"filter_status":"present"`},
		{`"page_mode":"export_declared"`, `"page_mode":"single_page_declared"`},
		{`"page_ordinal":null`, `"page_ordinal":` + strconv.Itoa(ordinal)},
		{`"pages_expected":null`, `"pages_expected":` + strconv.Itoa(pagesExpected)},
		{`"input":{"source_alias":"fixture"`, `"input":{"source_alias":"` + sourceAlias + `"`},
	}
	for _, s := range subs {
		if !strings.Contains(text, s[0]) {
			t.Fatalf("substitution anchor missing: %s", s[0])
		}
		text = strings.ReplaceAll(text, s[0], s[1])
	}
	if empty {
		text = strings.Replace(text, `"original_bytes":53`, `"original_bytes":2`, 1)
		idx := strings.Index(text, `"records":[`)
		if idx < 0 {
			t.Fatal("records anchor missing")
		}
		text = text[:idx] + `"records":[]}`
	}
	return text
}

// R2-07: complete canonical vectors of the 1.1 API artifacts. The expected bytes
// are derived from the published 1.0 §11.12.1 vector with the documented
// version/provenance and F2 page-context substitutions, and the hashes and
// lengths are literal oracle values, so the whole content is fixed rather than a
// substring. The replay negatives of the second half are kept.
func TestA208F2GoldenExplicitVectorsAndReplay(t *testing.T) {
	base := f2APIBaseSource(t)
	const acquiredAt = "2026-10-03T00:00:00Z"
	fixed := time.Date(2026, 10, 3, 0, 0, 0, 0, time.UTC)
	hooks := runtimeHooks{now: func() time.Time { return fixed }, sleep: func(context.Context, time.Duration) error { return nil }}
	script := f2Steps(`[{"type":"image","packages":[],"vulnerabilities":[]}]`, "[]")
	result, err := acquireWith(context.Background(), f2Config(), f2Bearer(),
		func([]byte) (http.RoundTripper, *AcquisitionError) { return script, nil }, hooks)
	if err != nil {
		t.Fatalf("sequence failed: %v", err)
	}
	if result.Termination != TerminationFinished || len(result.Pages) != 2 {
		t.Fatalf("termination/pages = %s/%d, want finished/2", result.Termination, len(result.Pages))
	}

	cases := []struct {
		page           int
		ordinal        int
		alias          string
		empty          bool
		sourceLen      int
		sourceHash     string
		manifestLen    int
		manifestDigest string
	}{
		{0, 1, "prisma-page-000001", false, 1198,
			"sha256:8db5d416c42e6e0a44243cc530bb1c1be68a23a78e3e4c6a27a5128c70f75e23", 1038,
			"sha256:74382da371dd4a022bb8b75fd01310daed7fe9707b836cdd937ba8f884108ecb\n"},
		{1, 2, "prisma-page-000002", true, 1065,
			"sha256:fac2f1ef127c2e5fe3679719badebc11a5473377f21829486a6035ecb80063a5", 1017,
			"sha256:0e4c46260dc6e3e03a2d7ab739303f2db6e76ffea705e5234de5ec4d10da2cec\n"},
	}
	for _, tc := range cases {
		page := result.Pages[tc.page]
		want := f2ExpectedAPISource(t, base, tc.alias, acquiredAt, tc.ordinal, 2, tc.empty)
		if string(page.Artifacts.Source) != want {
			t.Fatalf("page %d source is not the independently derived 1.1 vector:\n got %s\nwant %s",
				tc.page, page.Artifacts.Source, want)
		}
		if len(page.Artifacts.Source) != tc.sourceLen {
			t.Fatalf("page %d source length = %d, want %d", tc.page, len(page.Artifacts.Source), tc.sourceLen)
		}
		if got := ingest.HashNativeSource(page.Artifacts.Source); got != tc.sourceHash {
			t.Fatalf("page %d source hash = %s, want %s", tc.page, got, tc.sourceHash)
		}
		if len(page.Artifacts.Manifest) != tc.manifestLen {
			t.Fatalf("page %d manifest length = %d, want %d", tc.page, len(page.Artifacts.Manifest), tc.manifestLen)
		}
		if string(page.Artifacts.Digest) != tc.manifestDigest {
			t.Fatalf("page %d sidecar = %q, want %q", tc.page, page.Artifacts.Digest, tc.manifestDigest)
		}
		if !bytes.Contains(page.Artifacts.Manifest, []byte(tc.sourceHash)) {
			t.Fatalf("page %d manifest does not reference its literal source hash", tc.page)
		}
		if page.Inventory.SourceHash != tc.sourceHash {
			t.Fatalf("page %d inventory source hash = %s, want %s", tc.page, page.Inventory.SourceHash, tc.sourceHash)
		}
	}

	page := result.Pages[0]

	replay := func(src []byte, man []byte, dig []byte) *ingest.NativeError {
		_, rerr := normalize.ReplayPrismaNative(
			bytes.NewReader(src), bytes.NewReader(man), bytes.NewReader(dig),
			schema.NativeSourceFormat, schema.NativeFormatVersionV11)
		return rerr
	}

	// Vector: capture_termination altered with the previous hash kept.
	mut := bytes.Replace(page.Artifacts.Source, []byte(`"capture_termination":"finished"`), []byte(`"capture_termination":"aborted"`), 1)
	if bytes.Equal(mut, page.Artifacts.Source) {
		t.Fatal("capture_termination vector anchor missing")
	}
	if rerr := replay(mut, page.Artifacts.Manifest, page.Artifacts.Digest); rerr == nil || rerr.Code != ingest.NativeCodeHashMismatch {
		t.Fatalf("capture_termination mutation: err = %v, want %s", rerr, ingest.NativeCodeHashMismatch)
	}

	// Vector: pages_expected altered with the previous hash kept.
	mut = bytes.Replace(page.Artifacts.Source, []byte(`"pages_expected":2`), []byte(`"pages_expected":1`), 1)
	if bytes.Equal(mut, page.Artifacts.Source) {
		t.Fatal("pages_expected vector anchor missing")
	}
	if rerr := replay(mut, page.Artifacts.Manifest, page.Artifacts.Digest); rerr == nil || rerr.Code != ingest.NativeCodeHashMismatch {
		t.Fatalf("pages_expected mutation: err = %v, want %s", rerr, ingest.NativeCodeHashMismatch)
	}

	// Vector: a 1.1 source paired with a 1.0 manifest is rejected as a version mix.
	declared, _, perr := ingest.ParseNativeManifestBytes(page.Artifacts.Manifest)
	if perr != nil {
		t.Fatalf("manifest parse failed: %v", perr)
	}
	declared.Version = schema.NativeFormatVersion
	offlineManifest := ingest.EncodeNativeManifest(declared)
	offlineDigest := ingest.NativeManifestSidecar(ingest.HashNativeManifest(offlineManifest))
	if rerr := replay(page.Artifacts.Source, offlineManifest, offlineDigest); rerr == nil || rerr.Code != ingest.NativeCodeUnsupportedVersion {
		t.Fatalf("1.1 source with 1.0 manifest: err = %v, want %s", rerr, ingest.NativeCodeUnsupportedVersion)
	}
}
