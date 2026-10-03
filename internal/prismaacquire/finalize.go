package prismaacquire

import (
	"bytes"
	"context"
	"errors"
	"fmt"

	"github.com/d4rpell/Ariadne/internal/ingest"
	"github.com/d4rpell/Ariadne/internal/normalize"
	"github.com/d4rpell/Ariadne/internal/schema"
)

// Joint finalization of §8.18, §9 and §10. Drafts are kept private during the
// read; only after the global termination is known are the contexts completed,
// the canonical sources built, their hashes computed and the manifests derived,
// so no context is modified after its hash. All pages share the same termination
// and, when finished, the same pages_expected.
//
// The derived-output budgets of §7.9 are applied here, where the final context
// is known: the shared writer is bounded before it grows, and the retained
// artifacts (source, manifest and sidecar) and the derived tokens are accounted
// across pages. A budget exhaustion is a finalization cause and reconstructs the
// whole set with the aborted termination.

// outputBudget is the private derived-output accounting of one finalization
// attempt (§7.9). It is reset for every reconstruction, so a failed attempt
// never leaves a page reserved.
type outputBudget struct {
	pageSource uint64
	retained   uint64
	tokens     uint64
}

func newOutputBudget() *outputBudget {
	return &outputBudget{
		pageSource: uint64(maxSanitizedSourcePage),
		retained:   uint64(maxRetainedArtifactsBytes),
		tokens:     uint64(maxDerivedTokens),
	}
}

// finish resolves the four independent dimensions and finalizes the page
// artifacts. A finalization failure is reported with finalization_failed and
// delivers no artifacts (§10.5). A cause discovered during construction
// reconstructs the whole set with the aborted termination (§8.18); if the
// reconstruction also fails, no artifacts are delivered.
func (a *acquirer) finish(cause *AcquisitionError) (*AcquisitionResult, *AcquisitionError) {
	termination := TerminationFinished
	if cause != nil {
		termination = TerminationAborted
	}
	pages, finalErr := a.finalizePages(termination)
	if finalErr != nil {
		// Reconstruct with the aborted termination when a finished set could not
		// be built; the fresh output budget of the new attempt is the only budget
		// that may re-emit the already admitted drafts (§8.18, E-3).
		if termination == TerminationFinished {
			termination = TerminationAborted
			pages, finalErr = a.finalizePages(TerminationAborted)
		}
		if finalErr != nil {
			pages = nil
			if cause == nil {
				cause = finalErr
			} else {
				a.diagnostics = append(a.diagnostics, finalErr)
			}
		}
	}
	result := a.result(termination, pages)
	if cause != nil {
		result.Diagnostics = append(result.Diagnostics, cause)
		return result, cause
	}
	return result, nil
}

// result assembles the typed result without collapsing the independent
// dimensions of §10.2.
func (a *acquirer) result(termination string, pages []PageResult) *AcquisitionResult {
	completeness := SequenceUnknown
	switch {
	case termination == TerminationFinished:
		completeness = SequenceComplete
	case len(pages) > 0:
		completeness = SequencePartial
	}
	return &AcquisitionResult{
		Selector:             AcquisitionSelector,
		Version:              AcquisitionVersion,
		Profile:              AcquisitionProfile,
		OriginAlias:          a.cfg.OriginAlias,
		ScopeAlias:           cloneAlias(a.cfg.ScopeAlias),
		AuthMode:             a.cfg.AuthMode,
		Termination:          termination,
		SequenceCompleteness: completeness,
		InventoryCoverage:    InventoryCoverageUnknown,
		Consistency:          ConsistencyNotAtomic,
		RuntimeBinding:       RuntimeBindingNotAttempted,
		Attempts: AttemptCounters{
			Total:     a.budget.attempts,
			Auth:      a.budget.authAttempts,
			ImageGET:  a.budget.pageAttempts,
			BodyBytes: a.budget.bodyBytes,
			Images:    a.budget.images,
			Findings:  a.budget.findings,
			Packages:  a.budget.packages,
			Tokens:    a.budget.tokens,
		},
		Pages:       pages,
		Diagnostics: append([]*AcquisitionError{}, a.diagnostics...),
	}
}

// finalizePages completes every admitted page into its three artifacts and its
// native inventory. The context is fixed before the source hash; a failure
// aborts the whole delivery. Cancellation and the global time budget are
// polled at bounded checkpoints between pages, and the derived-output budgets
// are applied to the final representation (§7.9–§7.11, §8.18).
func (a *acquirer) finalizePages(termination string) ([]PageResult, *AcquisitionError) {
	if len(a.pages) == 0 {
		return nil, nil
	}
	var pagesExpected *int
	if termination == TerminationFinished {
		total := len(a.pages)
		pagesExpected = &total
	}
	budget := newOutputBudget()
	out := make([]PageResult, 0, len(a.pages))
	for _, page := range a.pages {
		if err := a.finalizationCheckpoint(); err != nil {
			return nil, err
		}
		ctx := a.pageContext(page, termination, pagesExpected)
		source := page.draft.Source(apiJSONProfile(), ctx)
		source.Version = schema.NativeFormatVersionV11
		artifacts, nativeErr := encodePageArtifacts(source, budget)
		if nativeErr != nil {
			return nil, finalizationFailure(nativeErr)
		}
		sourceHash := ingest.HashNativeSource(artifacts.Source)
		// The delivered manifest and sidecar must describe the delivered source
		// bytes, so no stale hash is ever published (§8.18, §9.7).
		if !artifactsCoherent(artifacts, sourceHash) {
			return nil, acquireErr(CodeFinalizationFailed, PhaseFinalization)
		}
		inventory, nativeErr := normalize.InterpretPrismaNative(source, sourceHash, uint64(len(artifacts.Source)))
		if nativeErr != nil {
			return nil, finalizationFailure(nativeErr)
		}
		out = append(out, PageResult{
			Ordinal:     page.ordinal,
			Offset:      page.offset,
			SourceAlias: ctx.SourceAlias,
			AcquiredAt:  page.acquiredAt,
			Artifacts:   artifacts,
			Inventory:   inventory,
		})
		if a.finalizationHook != nil {
			a.finalizationHook()
		}
		// Poll again after the page is built and before the set is published, so a
		// cancellation that arrives during the construction of the last page (after
		// the loop-entry checkpoint) cannot yield `finished`; the first cause is
		// preserved and finish reconstructs the whole set as aborted (§7.11, §8.18).
		if err := a.finalizationCheckpoint(); err != nil {
			return nil, err
		}
	}
	return out, nil
}

// finalizationCheckpoint polls cancellation and the global time budget at a
// bounded point of the construction (§7.11).
func (a *acquirer) finalizationCheckpoint() *AcquisitionError {
	if a.parent.Err() != nil {
		if errors.Is(a.parent.Err(), context.Canceled) {
			return acquireErr(CodeCancelled, PhaseFinalization)
		}
		return acquireErr(CodeTimeLimit, PhaseFinalization)
	}
	if a.ctx.Err() == context.DeadlineExceeded {
		return acquireErr(CodeTimeLimit, PhaseFinalization)
	}
	return nil
}

// encodePageArtifacts produces the three artifacts of one page under the shared
// derived-output budget (§7.9–§7.10), mirroring the offline finalization but
// with the acquisition budgets. The byte budget bounds the shared writer before
// growth; the derived-token count is measured over the delivered canonical
// bytes; the manifest and sidecar are charged to the accumulated retained
// budget before the page is accepted.
func encodePageArtifacts(source ingest.NativeSource, budget *outputBudget) (normalize.NativeArtifacts, *ingest.NativeError) {
	if err := ingest.ValidateNativeValueShape(source); err != nil {
		return normalize.NativeArtifacts{}, err
	}
	if !ingest.NativeDerivedSizesWithinBudgets(source) {
		return normalize.NativeArtifacts{}, outputLimitError()
	}
	if err := ingest.ValidateNativeSource(source); err != nil {
		return normalize.NativeArtifacts{}, err
	}
	sourceBytes, tokens, budgetErr := ingest.EncodeNativeSourceBudgeted(source, ingest.NativeOutputBudget{
		PageSourceBytes: budget.pageSource,
		RetainedBytes:   budget.retained,
		DerivedTokens:   budget.tokens,
	})
	if budgetErr != nil {
		return normalize.NativeArtifacts{}, budgetErr
	}
	if _, err := ingest.ParseNativeSourceBytes(sourceBytes); err != nil {
		return normalize.NativeArtifacts{}, outputLimitError()
	}
	sourceHash := ingest.HashNativeSource(sourceBytes)
	manifest, err := normalize.BuildNativeManifest(source, sourceHash, uint64(len(sourceBytes)))
	if err != nil {
		return normalize.NativeArtifacts{}, err
	}
	// The 72-byte sidecar is reserved before the manifest limit is computed and
	// before the sidecar is built, so an over-budget set is refused before either
	// artifact grows (§7.9, §9.7).
	manifestLimit, ok := manifestLimitAfterSidecar(budget.retained - uint64(len(sourceBytes)))
	if !ok {
		return normalize.NativeArtifacts{}, outputLimitError()
	}
	manifestBytes, ok := ingest.EncodeNativeManifestBounded(manifest, int(manifestLimit))
	if !ok {
		return normalize.NativeArtifacts{}, outputLimitError()
	}
	if _, _, err := ingest.ParseNativeManifestBytes(manifestBytes); err != nil {
		return normalize.NativeArtifacts{}, outputLimitError()
	}
	digest := ingest.NativeManifestSidecar(ingest.HashNativeManifest(manifestBytes))
	total := uint64(len(sourceBytes)) + uint64(len(manifestBytes)) + uint64(len(digest))
	if total > budget.retained {
		return normalize.NativeArtifacts{}, outputLimitError()
	}
	budget.retained -= total
	budget.tokens -= tokens
	return normalize.NativeArtifacts{Source: sourceBytes, Manifest: manifestBytes, Digest: digest}, nil
}

// artifactsCoherent verifies that the manifest carries the source hash of the
// delivered source and that the sidecar is the digest of the delivered
// manifest, so an incoherent set is never published.
func artifactsCoherent(artifacts normalize.NativeArtifacts, sourceHash string) bool {
	if len(artifacts.Source) == 0 || len(artifacts.Manifest) == 0 || len(artifacts.Digest) != 72 {
		return false
	}
	if !bytes.Contains(artifacts.Manifest, []byte(sourceHash)) {
		return false
	}
	expected := ingest.NativeManifestSidecar(ingest.HashNativeManifest(artifacts.Manifest))
	return bytes.Equal(artifacts.Digest, expected)
}

// outputLimitError is the closed output_limit diagnostic of §7.14 and §11.9.1.
func outputLimitError() *ingest.NativeError {
	return &ingest.NativeError{
		Code: ingest.NativeCodeOutputLimit, Phase: ingest.NativePhaseProjection,
		OffsetSpace: ingest.NativeSpaceNone,
	}
}

func maxIntValue() int { return int(^uint(0) >> 1) }

// sidecarBytes is the fixed 72-byte size of native-manifest.sha256
// (sha256:<64 hex> plus LF). It is reserved before the sidecar is built.
const sidecarBytes = 72

// manifestLimitAfterSidecar returns the manifest byte limit once the 72-byte
// sidecar has been reserved out of the remaining retained budget. It reports
// false when the remaining budget cannot hold the sidecar and a non-empty
// manifest, so no over-budget set is built.
func manifestLimitAfterSidecar(remaining uint64) (uint64, bool) {
	if remaining <= sidecarBytes {
		return 0, false
	}
	available := remaining - sidecarBytes
	limit := uint64(schema.NativeMaxManifestBytes)
	if available < limit {
		limit = available
	}
	if limit == 0 || limit > uint64(maxIntValue()) {
		return 0, false
	}
	return limit, true
}

// pageContext builds the 21-member F1 context of §9.4 for one page. None of the
// excluded members (endpoint, host, project, credential, token, headers, status)
// is present.
func (a *acquirer) pageContext(page pageDraft, termination string, pagesExpected *int) ingest.NativeContext {
	falseValue := false
	ordinal := page.ordinal
	scopeMode := "unfiltered_declared"
	filterStatus := "none_declared"
	var scopeAlias *string
	if a.cfg.ScopeMode == ScopeProjectSelect {
		scopeMode = "filtered_declared"
		filterStatus = "present"
		scopeAlias = a.cfg.ScopeAlias
	}
	return ingest.NativeContext{
		OriginAlias:        a.cfg.OriginAlias,
		SourceAlias:        pageAlias(page.ordinal),
		DeclaredEdition:    a.cfg.Edition,
		DeclaredRelease:    a.cfg.Release,
		VersionBasis:       "operator_declared",
		ReportKind:         schema.NativeReportKindDeployed,
		AcquisitionKind:    schema.NativeAcquisitionKindAPI,
		AcquiredAt:         page.acquiredAt,
		CaptureTermination: termination,
		ScopeMode:          scopeMode,
		ScopeAlias:         scopeAlias,
		FilterStatus:       filterStatus,
		Compact:            &falseValue,
		NormalizedSeverity: &falseValue,
		Layers:             &falseValue,
		FieldsMode:         "unrestricted_declared",
		SelectedFields:     []string{},
		PageMode:           "single_page_declared",
		PageOrdinal:        &ordinal,
		PagesExpected:      pagesExpected,
		DataPolicyAck:      requiredDataPolicyAck,
	}
}

// pageAlias is the deterministic, sanitized page alias of §9.4. It never derives
// from the host, user, project or remote content.
func pageAlias(ordinal int) string {
	return fmt.Sprintf("prisma-page-%06d", ordinal)
}

// cloneAlias copies the optional scope alias so the result never shares mutable
// memory with the caller's configuration (§3.6).
func cloneAlias(alias *string) *string {
	if alias == nil {
		return nil
	}
	value := *alias
	return &value
}

// apiJSONProfile is the JSON input profile identity, unchanged from F1.
func apiJSONProfile() ingest.NativeProfile {
	return ingest.NativeProfile{
		Selector:         schema.NativeJSONSelector,
		InputVersion:     schema.NativeInputVersion,
		Name:             schema.NativeJSONProfile,
		RedactionPolicy:  schema.NativeRedactionPolicy,
		AdapterSemantics: schema.NativeAdapterSemantics,
	}
}

// finalizationFailure maps a native failure during finalization to the closed
// acquisition catalogue. An output exhaustion maps to output_limit and a derived
// token exhaustion to token_limit (§7.14).
func finalizationFailure(nativeErr *ingest.NativeError) *AcquisitionError {
	mapped := acquireErr(CodeFinalizationFailed, PhaseFinalization)
	if nativeErr != nil {
		mapped.NativeCode = nativeErr.Code
		switch nativeErr.Code {
		case ingest.NativeCodeOutputLimit:
			mapped = acquireErr(CodeOutputLimit, PhaseFinalization)
			mapped.NativeCode = nativeErr.Code
		case ingest.NativeCodeTokenLimit:
			mapped = acquireErr(CodeTokenLimit, PhaseFinalization)
			mapped.NativeCode = nativeErr.Code
		}
	}
	return mapped
}
