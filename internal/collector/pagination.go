package collector

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/d4rpell/Ariadne/internal/bundle"
	"github.com/d4rpell/Ariadne/internal/normalize"
	contract "github.com/d4rpell/Ariadne/pkg/evidence"
)

// Paginated acquisition and the run state (ADR-0026 A.5.3, A.9). The state
// preserves every admitted capture, its operations and the comparison results;
// the abort of any stage stops new requests and keeps what was admitted.

// runState is the private state of one acquisition run.
type runState struct {
	config   validatedConfig
	client   *http.Client
	clock    collectionClock
	budget   *budgetState
	started  *contract.Timestamp
	terminat contract.CoverageTermination

	operations     []bundle.CollectedOperation
	captures       []bundle.CollectedCapture
	comparisons    []bundle.CollectedComparison
	diagnostics    []bundle.CollectionDiagnostic
	globalErrors   []string
	globalWarnings []contract.Warning

	lastCivil clockSample
	// runCtx is the global context of the run (with the acquisition deadline).
	// It lets a failure attributable to the global bound keep time_limit.
	runCtx context.Context
	// abortError keeps the first static error of the run.
	abortError error
	// requestOrdinal counts every admitted request of the transport.
	requestOrdinal uint64
	// captureOrdinal counts every admitted sanitized source.
	captureOrdinal uint64
	// progress records whether any subject of any capture was observed: an abort
	// without verifiable progress is unknown, never partial.
	progress bool
	// unfinishedTargets counts inventoried re-reads that were not completed.
	unfinishedTargets uint64
	// pendingNamespaces lists namespaces whose listing did not finish.
	pendingNamespaces []contract.Namespace
	// completedNamespaces lists namespaces whose listing closed cleanly.
	completedNamespaces []contract.Namespace
	// pagesOpen reports whether some continuation of the run stayed open.
	pagesOpen bool
	// inventory stays private until the closed acquisition record is published.
	inventory initialInventory
	// inventoryClosed records that the initial inventory closed successfully.
	inventoryClosed bool
	// pendingContinuation carries the token of the page just admitted to the
	// list loop. The token is consumed immediately and never retained.
	pendingContinuation        string
	pendingContinuationPresent bool
}

// closeOperation stamps the end of one attempted operation with a fresh clock
// sample. Every path that leaves the operation after its start closes the
// record here, so no admitted operation reaches the result without its window.
func (r *runState) closeOperation(record *bundle.CollectedOperation, start clockSample) {
	endSample, err := r.sample()
	if err != nil {
		return
	}
	record.EndedAt = mustTimestamp(endSample.UTC)
	record.Elapsed = endSample.Elapsed - start.Elapsed
}

// noteError records the first run-wide failure and its static message.
func (r *runState) noteError(code bundle.CollectionCode) {
	if r.abortError == nil {
		r.abortError = staticError(code)
		message := bundle.CollectionMessage(code)
		r.globalErrors = append(r.globalErrors, message)
	}
}

// noteDiagnostic appends one publishable diagnostic of the run.
func (r *runState) noteDiagnostic(diagnostic bundle.CollectionDiagnostic) {
	r.diagnostics = append(r.diagnostics, diagnostic)
}

// noteCancellation distinguishes a caller cancellation from a budget guard: a
// guard already fired keeps its own diagnosis.
func (r *runState) noteCancellation(ctx context.Context) {
	if r.budget.exhausted() {
		return
	}
	if ctx.Err() != nil {
		r.noteError(bundle.CodeCancelled)
	}
}

// acquire performs one allowed request and stores the admitted capture when the
// response was complete and valid. Every path closes the body and accounts the
// request; a request refused before the transport consumes no attempt.
func (r *runState) acquire(ctx context.Context, operation operationSpec) error {
	client := r.client
	if client == nil {
		return staticError(bundle.CodeTransportFailed)
	}
	// The request is built and guarded first: a refusal here never reaches the
	// transport and therefore consumes no request budget.
	request, err := newRequest(ctx, r.config, operation)
	if err != nil {
		r.noteError(bundle.CodeRequestNotAllowed)
		return staticError(bundle.CodeRequestNotAllowed)
	}
	if err := r.budget.beforeRequest(ctx, r.clock); err != nil {
		code := diagnosticCode(err, bundle.CodeCancelled)
		r.noteError(code)
		return staticError(code)
	}
	// The per-request deadline starts once the attempt is admitted: the spacing
	// wait is not charged against the request itself.
	requestCtx, cancel := r.clock.WithTimeout(ctx, oneRequestTimeout())
	defer cancel()
	request = request.WithContext(requestCtx)
	r.requestOrdinal++
	record := bundle.CollectedOperation{
		Verb:           operation.verb,
		Namespace:      operation.namespace,
		Name:           operation.name,
		Page:           operation.page,
		Round:          operation.round,
		RequestOrdinal: r.requestOrdinal,
		State:          bundle.OperationAttempted,
	}
	startSample, err := r.sample()
	if err != nil {
		// The attempt was already counted when it was admitted: the failed
		// attempt is recorded so the accounting stays coherent, without
		// inventing the instant that could not be sampled.
		record.State = bundle.OperationFailed
		record.Diagnostic = bundle.CodeClockInvalid
		r.operations = append(r.operations, record)
		r.budget.noteResponse(false)
		return err
	}
	startedAt := mustTimestamp(startSample.UTC)
	record.StartedAt = startedAt
	response, transportErr := client.Do(request)
	if transportErr != nil {
		code := r.classifyFailure(transportErr, requestCtx)
		if code == "" {
			code = bundle.CodeTransportFailed
		}
		r.closeOperation(&record, startSample)
		record.State = bundle.OperationFailed
		record.Diagnostic = code
		r.operations = append(r.operations, record)
		r.budget.noteResponse(false)
		r.noteError(code)
		return staticError(code)
	}
	defer response.Body.Close()
	if code := headerProblem(response); code != "" {
		r.closeOperation(&record, startSample)
		record.State = bundle.OperationFailed
		record.Diagnostic = code
		r.operations = append(r.operations, record)
		r.budget.noteResponse(false)
		r.noteError(code)
		return staticError(code)
	}
	record.StatusCode = responseStatus(response)
	if code := classifyStatus(record.StatusCode); code != "" {
		r.closeOperation(&record, startSample)
		record.State = bundle.OperationFailed
		record.Diagnostic = code
		r.operations = append(r.operations, record)
		r.budget.noteResponse(false)
		r.noteError(code)
		return staticError(code)
	}
	raw, readErr := readResponse(requestCtx, response, r.budget)
	if readErr != nil {
		code := r.classifyFailure(readErr, requestCtx)
		if code == bundle.CodeCancelled || code == "" {
			code = diagnosticCode(readErr, bundle.CodeBodyReadFailed)
		}
		r.closeOperation(&record, startSample)
		record.State = bundle.OperationFailed
		record.Diagnostic = code
		r.operations = append(r.operations, record)
		r.budget.noteResponse(false)
		r.noteError(code)
		return staticError(code)
	}
	// The response is complete only now: observed_at is the local instant at
	// which its whole body was read, never the instant of its headers.
	endSample, err := r.sample()
	if err != nil {
		// The request was already counted when it started; leaving without a
		// record would make the accounting incoherent and turn an acquisition
		// failure into a projection failure. The failed attempt is recorded with
		// its own diagnostic and no invented timestamp.
		r.closeOperation(&record, startSample)
		record.State = bundle.OperationFailed
		record.Diagnostic = bundle.CodeClockInvalid
		r.operations = append(r.operations, record)
		r.budget.noteResponse(false)
		r.noteError(bundle.CodeClockInvalid)
		return staticError(bundle.CodeClockInvalid)
	}
	endedAt := mustTimestamp(endSample.UTC)
	record.EndedAt = endedAt
	record.Elapsed = endSample.Elapsed - startSample.Elapsed
	record.BytesRead = uint64(len(raw))
	projection, projectionErr := projectResponse(ctx, raw, operation, r.budget)
	if projectionErr != nil {
		// The projection route preserves the run-wide cause: a global deadline
		// that expires while the body is projected keeps time_limit, a caller
		// cancellation is cancelled, and a guard that already fired keeps its own
		// code. The per-request deadline is deliberately not consulted: it bounds
		// the exchange, not the local projection, and it never caused this
		// failure, so an elapsed request deadline cannot replace the static code
		// the projection really produced.
		code := r.classifyFailure(projectionErr, nil)
		if code == "" {
			code = diagnosticCode(projectionErr, bundle.CodeResponseInvalid)
		}
		r.closeOperation(&record, startSample)
		record.State = bundle.OperationFailed
		record.Diagnostic = code
		r.operations = append(r.operations, record)
		r.budget.noteResponse(false)
		r.noteError(code)
		return staticError(code)
	}
	record.State = bundle.OperationFinished
	// The response must address exactly the requested identity: another
	// namespace or name is a scope mismatch, and the foreign document never
	// becomes a source of this run.
	if code := scopeProblem(operation, projection); code != "" {
		r.closeOperation(&record, startSample)
		record.State = bundle.OperationFailed
		record.Diagnostic = code
		r.operations = append(r.operations, record)
		r.budget.noteResponse(false)
		r.noteError(code)
		return staticError(code)
	}
	// Every admitted response becomes one sanitized source with its own alias.
	r.captureOrdinal++
	alias := captureAlias(r.requestOrdinal)
	normalized, admitErr := admitSource(projection.source, admissionContext{
		sourceName:         alias,
		clusterAlias:       string(r.config.clusterAlias),
		namespace:          string(operation.namespace),
		observedAt:         endSample.UTC,
		captureTermination: contract.TerminationFinished,
	})
	if admitErr != nil {
		code := diagnosticCode(admitErr, bundle.CodeRedactionFailed)
		r.closeOperation(&record, startSample)
		record.State = bundle.OperationFailed
		record.Diagnostic = code
		r.operations = append(r.operations, record)
		r.budget.noteResponse(false)
		r.noteError(code)
		return staticError(code)
	}
	if err := r.budget.retainSource(uint64(len(projection.source))); err != nil {
		r.operations = append(r.operations, record)
		r.budget.noteResponse(false)
		r.noteError(bundle.CodeOutputLimit)
		return staticError(bundle.CodeOutputLimit)
	}
	sourceHash := bundle.HashSource(projection.source)
	items := make([]bundle.CollectedItem, 0, len(projection.items))
	for _, item := range projection.items {
		items = append(items, bundle.CollectedItem{
			UID:       contract.UID(item.uid),
			Namespace: contract.Namespace(item.namespace),
			Name:      item.name,
		})
	}
	capture := bundle.CollectedCapture{
		Ordinal:                     r.captureOrdinal,
		RequestOrdinal:              r.requestOrdinal,
		Verb:                        operation.verb,
		Alias:                       alias,
		Bytes:                       append([]byte{}, projection.source...),
		Hash:                        sourceHash,
		Observation:                 normalized,
		Items:                       items,
		ListResourceVersionPresence: projection.listRVPresent,
		ContinuationPending:         projection.continuationPresent,
	}
	if projection.listRVPresent {
		capture.ListResourceVersion = projection.listResourceVersion
	}
	r.captures = append(r.captures, capture)
	r.operations = append(r.operations, record)
	r.budget.noteResponse(true)
	if normalized.RejectedItems > 0 {
		// A rejected Pod of an admitted source stays visible in the record.
		captureOrdinal := r.captureOrdinal
		requestOrdinal := r.requestOrdinal
		r.noteDiagnostic(bundle.CollectionDiagnostic{
			Code:           bundle.CodePodRejected,
			RequestOrdinal: &requestOrdinal,
			CaptureOrdinal: &captureOrdinal,
		})
	}
	for _, subject := range normalized.Subjects {
		// Verifiable progress is an observed category or an inventoried image:
		// knowing a UID alone is not progress (ADR-0026 A.9).
		progress := normalize.ProgressOf(subject)
		if progress.CategoryObserved || progress.ImageInventoried {
			r.progress = true
		}
	}
	// The continuation of this page stays in the run state until the list loop
	// consumes it; the token is never retained in the capture or in the result.
	r.pendingContinuation = projection.continuation
	r.pendingContinuationPresent = projection.continuationPresent
	if projection.continuationPresent {
		r.pagesOpen = true
	}
	return nil
}

// scopeProblem checks that every projected Pod addresses exactly the requested
// identity. A document of another namespace, another name or with no usable
// identity is refused before it becomes a source of this run. An empty list is
// a valid observation; a get must carry exactly one Pod.
func scopeProblem(operation operationSpec, projection projectedResponse) bundle.CollectionCode {
	if operation.verb == "get" && len(projection.items) != 1 {
		return bundle.CodeScopeMismatch
	}
	for _, item := range projection.items {
		if item.namespace != string(operation.namespace) {
			return bundle.CodeScopeMismatch
		}
		if operation.verb == "get" {
			if item.name != operation.name {
				return bundle.CodeScopeMismatch
			}
			continue
		}
		// A list element without a usable name cannot be inventoried or
		// re-read: it is not an identity this profile can act on.
		if !validPodName(item.name) {
			return bundle.CodeScopeMismatch
		}
	}
	return ""
}

// sample reads the clock and refuses an unusable civil value. An invalid or
// regressing civil reading stops the run with clock_invalid: no value is
// clamped and no previous instant is substituted for a new observation.
func (r *runState) sample() (clockSample, error) {
	current := r.clock.Now()
	if clockInvalid(r.lastCivil, current) {
		r.noteError(bundle.CodeClockInvalid)
		return clockSample{}, staticError(bundle.CodeClockInvalid)
	}
	r.lastCivil = current
	return current, nil
}

// classifyFailure chooses the code of a failed stage. The run-wide deadline
// owns its own diagnosis: a failure caused by the global context is time_limit,
// never a per-request timeout or a plain cancellation. The per-request context
// is consulted so an expired individual deadline keeps its own cause instead of
// being flattened into a generic body-read failure. A guard that already fired
// keeps its cause.
func (r *runState) classifyFailure(err error, requestCtx context.Context) bundle.CollectionCode {
	if r.budget.exhausted() {
		return r.budget.abortCode
	}
	if r.runCtx != nil && r.runCtx.Err() != nil {
		if errors.Is(r.runCtx.Err(), context.DeadlineExceeded) {
			return bundle.CodeTimeLimit
		}
		return bundle.CodeCancelled
	}
	if requestCtx != nil && requestCtx.Err() != nil {
		if errors.Is(requestCtx.Err(), context.DeadlineExceeded) {
			return bundle.CodeRequestTimeout
		}
		if errors.Is(requestCtx.Err(), context.Canceled) {
			return bundle.CodeCancelled
		}
	}
	if code := diagnosticCode(err, ""); code != "" {
		return code
	}
	return classifyTransportError(err)
}

// diagnosticCode extracts the closed code of one static error.
func diagnosticCode(err error, fallback bundle.CollectionCode) bundle.CollectionCode {
	if err == nil {
		return fallback
	}
	for _, code := range bundle.Codes() {
		if code != "" && bundle.CollectionCodeKnown(code) && err.Error() == bundle.CollectionMessage(code) {
			return code
		}
	}
	return fallback
}

// mustTimestamp converts one civil instant to a contract timestamp. The clock
// sample already rejected invalid instants, so a failure here is impossible and
// is surfaced as a nil timestamp.
func mustTimestamp(value time.Time) *contract.Timestamp {
	converted, err := contract.NewTimestamp(value)
	if err != nil {
		return nil
	}
	return &converted
}
