package collector

import (
	"context"
	"net/http"

	"github.com/d4rpell/Ariadne/internal/bundle"
	contract "github.com/d4rpell/Ariadne/pkg/evidence"
)

// Orchestration of one acquisition run (ADR-0026 A.5.3, A.9). The public entry
// point validates everything before touching the network; this seam exists so
// the tests can inject a scripted transport and a controlled clock, and it is
// private: Config has no transport, dial or clock hook.

// collectWithDependencies runs the acquisition with explicit dependencies.
// transport == nil builds the real private transport; clock == nil uses the
// system clock.
func collectWithDependencies(ctx context.Context, config Config, transport http.RoundTripper, clock collectionClock) (Result, error) {
	if ctx == nil {
		return Result{}, staticError(bundle.CodeInvalidConfig)
	}
	validated, err := validateConfig(config)
	if err != nil {
		return Result{}, staticError(invalidConfigCode(err))
	}
	if clock == nil {
		clock = newRealClock()
	}
	usedTransport := transport
	if usedTransport == nil {
		built := newTransport(validated)
		applyClientCertificate(built, validated)
		usedTransport = built
	}
	runCtx, cancel := clock.WithTimeout(ctx, acquisitionDeadline)
	defer cancel()
	state := &runState{
		config: validated,
		client: newHTTPClient(usedTransport),
		clock:  clock,
		budget: &budgetState{},
		runCtx: runCtx,
	}
	startSample := clock.Now()
	if clockInvalid(clockSample{}, startSample) {
		state.noteError(bundle.CodeClockInvalid)
		return state.finalize()
	}
	state.lastCivil = startSample
	state.started = mustTimestamp(startSample.UTC)
	state.terminat = contract.TerminationFinished

	// The plan lists every namespace in canonical order; an abort keeps the
	// pending ones visible in the result and never reduces the requested scope.
	for _, namespace := range validated.namespaces {
		if state.abortError != nil {
			state.pendingNamespaces = append(state.pendingNamespaces, namespace)
			continue
		}
		if err := state.listNamespace(runCtx, namespace); err != nil {
			state.pendingNamespaces = append(state.pendingNamespaces, namespace)
		}
	}
	// The inventory is built over every list capture the run retained, aborted
	// or not: a duplicated UID between two pages must invalidate both occurrences
	// even when a later failure closed the sequence early (ADR-0026 A.8.1).
	// When the inventory budget is exceeded the run aborts, but the exclusions
	// already established are kept: a duplicate can never be reintroduced by the
	// limit that closed the walk.
	inventory, inventoryDiagnostics, err := buildInventory(state.captures, state.budget)
	state.inventory = inventory
	state.diagnostics = append(state.diagnostics, inventoryDiagnostics...)
	if err != nil {
		state.noteError(bundle.CodeObjectLimit)
	} else {
		state.inventoryClosed = state.abortError == nil
		if state.abortError == nil {
			if err := state.reread(runCtx, inventory); err != nil {
				_ = err
			}
		}
	}
	comparisons, comparisonDiagnostics, err := compareCaptures(state.captures)
	if err == nil {
		state.comparisons = comparisons
		state.diagnostics = append(state.diagnostics, comparisonDiagnostics...)
	}
	return state.finalize()
}

// listNamespace walks every page of one namespace list, checking the opaque
// list resourceVersion by equality and refusing a repeated or oversized
// continuation token without sending another request.
func (r *runState) listNamespace(ctx context.Context, namespace contract.Namespace) error {
	page := uint64(1)
	continuation := ""
	seenTokens := map[string]bool{}
	firstResourceVersion := ""
	firstResourceVersionSeen := false
	resourceVersionCredited := true
	for {
		operation := operationSpec{verb: "list", namespace: namespace, page: page, cont: continuation}
		captureCount := len(r.captures)
		if err := r.acquire(ctx, operation); err != nil {
			// The sequence did not close: its remaining work has no known size
			// and must never be presented as a closed, fully known plan.
			r.pagesOpen = true
			return err
		}
		if len(r.captures) == captureCount {
			// No source was admitted: the run has no progress to preserve here.
			return staticError(bundle.CodeRedactionFailed)
		}
		capture := r.captures[len(r.captures)-1]
		// The list resourceVersion is opaque and contrasted by equality only.
		if capture.ListResourceVersionPresence {
			if !firstResourceVersionSeen {
				firstResourceVersion = capture.ListResourceVersion
				firstResourceVersionSeen = true
			} else if capture.ListResourceVersion != firstResourceVersion {
				r.noteError(bundle.CodePaginationInvalid)
				return staticError(bundle.CodePaginationInvalid)
			}
		} else if resourceVersionCredited {
			// Absence is visible and prevents presenting the sequence as
			// consistent; the listing itself may still finish.
			resourceVersionCredited = false
			r.noteDiagnostic(bundle.CollectionDiagnostic{Code: bundle.CodeResourceVersionMiss})
		}
		token := r.pendingContinuation
		r.pendingContinuation = ""
		r.pendingContinuationPresent = false
		if token == "" {
			r.pagesOpen = false
			r.completedNamespaces = append(r.completedNamespaces, namespace)
			return nil
		}
		if seenTokens[token] {
			// A repeated token would loop forever: it is refused before any new
			// request reaches the transport.
			r.noteError(bundle.CodePaginationInvalid)
			return staticError(bundle.CodePaginationInvalid)
		}
		if len(token) > maxContinuationBytes {
			r.noteError(bundle.CodePaginationInvalid)
			return staticError(bundle.CodePaginationInvalid)
		}
		seenTokens[token] = true
		continuation = token
		page++
	}
}

// reread performs the fixed get rounds over the closed inventory: the first
// round visits every target, then the second round repeats the whole list. A
// failure stops new requests and every target that was not completed stays
// counted as unfinished: the plan is never reduced silently.
func (r *runState) reread(ctx context.Context, inventory initialInventory) error {
	for round := uint8(1); round <= rereadRounds; round++ {
		for _, entry := range inventory.entries {
			if r.abortError != nil {
				r.unfinishedTargets++
				continue
			}
			operation := operationSpec{
				verb:      "get",
				namespace: entry.namespace,
				name:      entry.name,
				round:     round,
			}
			if err := r.acquire(ctx, operation); err != nil {
				r.unfinishedTargets++
			}
		}
	}
	return nil
}

// finalize closes the run and builds every bundle of the result. A run-wide
// failure propagates to each affected bundle with its specific error, and the
// coverage never ascends because a subject was selected.
func (r *runState) finalize() (Result, error) {
	endSample := r.clock.Now()
	ended := mustTimestamp(endSample.UTC)
	if clockInvalid(r.lastCivil, endSample) {
		// An unusable final reading leaves ended_at absent together with the
		// visible clock_invalid error: no value is clamped.
		ended = nil
		if r.abortError == nil {
			r.noteError(bundle.CodeClockInvalid)
		}
	} else {
		r.lastCivil = endSample
	}
	termination := contract.TerminationFinished
	if r.abortError != nil {
		if r.progress {
			termination = contract.TerminationAborted
		} else {
			termination = contract.TerminationUnknown
		}
	} else if !r.progress {
		// A finished run without any verifiable progress is not complete.
		termination = contract.TerminationUnknown
	}
	r.terminat = termination

	// The intermediate observations were admitted as each response arrived; the
	// global termination is only known now. Every capture is rebuilt from its
	// own sanitized bytes with that termination: bytes, alias, timestamps and
	// facts are never modified to propagate the abort.
	if termination != contract.TerminationFinished {
		for index := range r.captures {
			capture := &r.captures[index]
			if capture.Observation.ObservedAt == nil {
				continue
			}
			rebuilt, err := admitSource(capture.Bytes, admissionContext{
				sourceName:         capture.Alias,
				clusterAlias:       string(r.config.clusterAlias),
				namespace:          string(capture.Observation.Namespace),
				observedAt:         capture.Observation.ObservedAt.Time,
				captureTermination: termination,
			})
			if err != nil {
				continue
			}
			capture.Observation = rebuilt
		}
	}

	acquisition := bundle.CollectedAcquisition{
		Scope: bundle.CollectedScope{
			Selector:        r.config.selector,
			Version:         r.config.version,
			RedactionPolicy: r.config.redactionPolicy,
			ClusterAlias:    r.config.clusterAlias,
			Namespaces:      append([]contract.Namespace{}, r.config.namespaces...),
		},
		Plan: bundle.CollectedPlan{
			ListedNamespaces:        append([]contract.Namespace{}, r.completedNamespaces...),
			PendingNamespaces:       append([]contract.Namespace{}, r.pendingNamespaces...),
			Targets:                 inventoryTargets(r.inventory),
			PlannedReReadsPerTarget: rereadRounds,
			UnfinishedTargets:       r.unfinishedTargets,
			RequestedOps:            r.budget.requests,
			ContinuationOpen:        r.pagesOpen,
			PagesKnown:              !r.pagesOpen,
			InventoryClosed:         r.inventoryClosed,
		},
		Operations:   append([]bundle.CollectedOperation{}, r.operations...),
		Captures:     append([]bundle.CollectedCapture{}, r.captures...),
		Comparisons:  append([]bundle.CollectedComparison{}, r.comparisons...),
		Diagnostics:  append([]bundle.CollectionDiagnostic{}, r.diagnostics...),
		StartedAt:    r.started,
		EndedAt:      ended,
		Termination:  termination,
		GlobalErrors: append([]string{}, r.globalErrors...),
	}
	acquisition.GlobalWarnings = acquisitionWarnings(r.abortError != nil, termination)
	acquisition.Stats = bundle.CollectedBudgetStats{
		RequestsAttempted:   r.budget.requests,
		ResponsesFinished:   r.budget.responsesFinished,
		ResponsesFailed:     r.budget.responsesFailed,
		BytesRead:           r.budget.totalBodyBytes,
		PodOccurrences:      r.budget.podOccurrences,
		InitialUIDs:         r.budget.initialUIDs,
		RetainedSourceBytes: r.budget.retainedSource,
		MaxConcurrency:      1,
		Elapsed:             endSample.Elapsed,
	}

	result := Result{Acquisition: acquisition}
	for _, capture := range r.captures {
		for subjectIndex, subject := range capture.Observation.Subjects {
			// A uid duplicated in the initial inventory invalidates every one of
			// its occurrences: none of them is projected, and the omission is
			// already stated by the identity_conflict diagnostic.
			if r.inventoryDropped(capture.Ordinal, subject.ItemIndex, subject.UID) {
				continue
			}
			// Every remaining subject of every admitted capture gets its own
			// bundle; the live builder validates the whole selection before
			// emitting bytes.
			built, diagnostics, err := bundle.BuildCollectedObservation(bundle.CollectedObservationInput{
				Acquisition:    acquisition,
				CaptureOrdinal: capture.Ordinal,
				SubjectIndex:   subjectIndex,
				Result:         capture.Observation,
			})
			if err != nil {
				// An incoherent build is a defect of the integration, not a subject
				// to skip: it stops the whole result with its static diagnostic
				// instead of silently dropping a bundle.
				return Result{Acquisition: acquisition}, staticError(bundle.CodeProjectionFailed)
			}
			result.Bundles = append(result.Bundles, CollectedBundle{
				CaptureOrdinal: capture.Ordinal,
				ItemIndex:      subject.ItemIndex,
				Bundle:         built,
				Diagnostics:    diagnostics,
			})
		}
	}
	result.Incomplete = len(result.Bundles) == 0 || anyIncomplete(result.Bundles)
	if r.abortError != nil {
		return result, r.abortError
	}
	return result, nil
}

// inventoryTargets renders the ordered addresses of the closed inventory.
func inventoryTargets(inventory initialInventory) []bundle.CollectedTarget {
	targets := make([]bundle.CollectedTarget, 0, len(inventory.entries))
	for _, entry := range inventory.entries {
		targets = append(targets, bundle.CollectedTarget{
			UID:            entry.uid,
			Namespace:      entry.namespace,
			Name:           entry.name,
			CaptureOrdinal: entry.capture,
			ItemIndex:      entry.itemIndex,
		})
	}
	return targets
}

// inventoryDropped reports whether one subject of one capture is a duplicated
// occurrence of the initial inventory. Such an occurrence is omitted from the
// projection; it is never chosen by order and never projected twice under the
// same uid.
func (r *runState) inventoryDropped(captureOrdinal uint64, itemIndex int, uid contract.UID) bool {
	occurrences, duplicated := r.inventory.duplicateUIDs[uid]
	if !duplicated {
		return false
	}
	for _, occurrence := range occurrences {
		if occurrence.capture == captureOrdinal && occurrence.itemIndex == itemIndex {
			return true
		}
	}
	return false
}

// acquisitionWarnings renders the wire warnings every affected bundle keeps.
func acquisitionWarnings(aborted bool, termination contract.CoverageTermination) []contract.Warning {
	warnings := []contract.Warning{}
	if aborted {
		warnings = append(warnings, contract.Warning{
			Code:    "tool_failure",
			Class:   contract.WarningContradictory,
			Message: "collector acquisition did not complete",
		})
	}
	if termination != contract.TerminationFinished {
		warnings = append(warnings, contract.Warning{
			Code:    "partial_observation",
			Class:   contract.WarningContradictory,
			Message: "container observation is incomplete",
		})
	}
	return warnings
}

// anyIncomplete reports whether any bundle of the result is not complete.
func anyIncomplete(bundles []CollectedBundle) bool {
	for _, bundle := range bundles {
		if bundle.Bundle.Provenance.Completeness != contract.CompletenessComplete {
			return true
		}
	}
	return false
}
