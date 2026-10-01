package bundle

import (
	"bytes"
	"errors"
	"fmt"
	"reflect"

	"github.com/d4rpell/Ariadne/internal/ingest"
	"github.com/d4rpell/Ariadne/internal/normalize"
	"github.com/d4rpell/Ariadne/internal/schema"
	contract "github.com/d4rpell/Ariadne/pkg/evidence"
)

// Validation of the live-collection input (ADR-0026 A.7.3, A.9, A.11). The
// builder never trusts its intermediate value: source bytes, normalized DTO,
// operation, times, selection, comparisons, diagnostics and termination are
// cross-checked before a single byte of a bundle is constructed. An incoherent
// input yields no bundle and the closed diagnostic projection_failed.

var errCollectedInput = errors.New("bundle: collected observation input is not coherent")

// collectedFailure is the static error every incoherent DTO produces.
func collectedFailure() error {
	return errors.New(CollectionMessage(CodeProjectionFailed))
}

// collectedAliasOf renders the only admitted alias of one capture.
func collectedAliasOf(requestOrdinal uint64) string {
	return fmt.Sprintf("capture-%06d.json", requestOrdinal)
}

// validateCollectedInput applies the twelve coherence checks of the handoff and
// returns nil only when the input can produce a valid bundle.
func validateCollectedInput(input CollectedObservationInput) error {
	acquisition := input.Acquisition
	if err := validateCollectedScope(acquisition); err != nil {
		return err
	}
	capture, err := collectedCaptureOf(acquisition, input.CaptureOrdinal)
	if err != nil {
		return err
	}
	if err := validateCollectedSource(capture, input.Result); err != nil {
		return err
	}
	if err := validateCollectedSelection(input); err != nil {
		return err
	}
	if err := validateCollectedOperation(acquisition, capture, input); err != nil {
		return err
	}
	if err := validateCollectedTimes(acquisition, capture); err != nil {
		return err
	}
	if err := validateCollectedTermination(acquisition); err != nil {
		return err
	}
	if err := validateCollectedComparisons(acquisition); err != nil {
		return err
	}
	if err := validateCollectedDiagnostics(acquisition); err != nil {
		return err
	}
	if err := validateCollectedPublication(acquisition); err != nil {
		return err
	}
	if err := validateCollectedAccounting(acquisition); err != nil {
		return err
	}
	return validateCollectedAdmission(input, capture)
}

// collectedWireWarningText maps the frozen wire vocabulary of this producer to
// its exact message. The table is closed: any other code or text is refused, so
// a caller cannot inject free text into a bundle through a warning.
var collectedWireWarningText = map[string]string{
	"partial_observation": "container observation is incomplete",
	"tool_failure":        "collector acquisition did not complete",
	"uid_changed":         "Pod UID changed between collection observations",
	"source_conflict":     "collection observations contain differing projected content",
	"stale_observation":   "status freshness could not be established after a spec change",
	"redaction_applied":   "collector applied the admitted Pod field projection",
	"scope_mismatch":      "scope collision across container classes",
}

// validateCollectedPublication refuses any run-wide error or warning that is
// not exactly one entry of the closed catalog: the provenance copies these
// values verbatim, so free text, a truncated code or a foreign message would
// become publishable content (ADR-0026 A.10, A.14).
func validateCollectedPublication(acquisition CollectedAcquisition) error {
	for _, message := range acquisition.GlobalErrors {
		if !collectionMessageIsStatic(message) {
			return errCollectedInput
		}
	}
	for _, warning := range acquisition.GlobalWarnings {
		if !collectedWarningIsStatic(warning) {
			return errCollectedInput
		}
	}
	return nil
}

// collectionMessageIsStatic reports whether one string is exactly the message of
// one code of the closed catalog.
func collectionMessageIsStatic(message string) bool {
	if message == "" {
		return false
	}
	for _, code := range collectionCodes {
		if message == "collector: "+string(code) {
			return true
		}
	}
	return false
}

// collectedGlobalError reports whether one exact code of the closed catalog is
// visible among the run-wide errors the provenance copies verbatim.
func collectedGlobalError(acquisition CollectedAcquisition, code CollectionCode) bool {
	message := CollectionMessage(code)
	if message == "" {
		return false
	}
	for _, failure := range acquisition.GlobalErrors {
		if failure == message {
			return true
		}
	}
	return false
}

// collectedOperationFailureCodes is the closed set of causes a failed operation
// can carry: exactly the codes the acquisition really writes as the diagnostic
// of a failed attempt (pagination.go: the clock, the transport and status
// classifiers, the read, the projection — the oversized continuation token
// included —, the scope and the admission). A refusal that aborts the run
// before the attempt is recorded (the request guard and the request budget), a
// guard that closes the run after a finished attempt (the retained-source
// budget), a comparison code, a pure diagnostic and the integration failure of
// the builder are not causes of a failed operation and never appear here.
var collectedOperationFailureCodes = map[CollectionCode]bool{
	CodeAuthFailed:        true,
	CodeForbidden:         true,
	CodeNotFound:          true,
	CodePaginationExpired: true,
	CodePaginationInvalid: true,
	CodeRateLimited:       true,
	CodeServerError:       true,
	CodeUnexpectedStatus:  true,
	CodeRedirectRefused:   true,
	CodeTLSFailed:         true,
	CodeTransportFailed:   true,
	CodeRequestTimeout:    true,
	CodeBodyReadFailed:    true,
	CodeResponseInvalid:   true,
	CodeResponseLimit:     true,
	CodeByteLimit:         true,
	CodeObjectLimit:       true,
	CodeScopeMismatch:     true,
	CodeRedactionFailed:   true,
	CodeTimeLimit:         true,
	CodeCancelled:         true,
	CodeClockInvalid:      true,
}

// collectedOperationFailureCode reports whether one code belongs to that closed
// set. The preserved cause of a failed operation belongs to the vocabulary the
// acquisition really produces, never to a label the run could not have written.
func collectedOperationFailureCode(code CollectionCode) bool {
	return collectedOperationFailureCodes[code]
}

// collectedWarningIsStatic reports whether one warning belongs to the frozen
// vocabulary: an admitted code, its exact class and its exact message (the
// collision warning carries the affected classes, validated separately).
func collectedWarningIsStatic(warning contract.Warning) bool {
	expected, known := collectedWireWarningText[warning.Code]
	if !known {
		return false
	}
	if warning.Code == "scope_mismatch" {
		// The collision message names the affected classes. The only admissible
		// messages are the program constant plus one non-empty subset of the
		// three container classes in canonical order: any other suffix would be
		// free text copied verbatim into the bundle (ADR-0026 A.10, A.14).
		if !identifierOK(warning.Message) || len(warning.Message) > 256 {
			return false
		}
		if !collisionMessageIsClosed(warning.Message) {
			return false
		}
	} else if warning.Message != expected {
		return false
	}
	switch warning.Code {
	case "partial_observation", "tool_failure", "uid_changed", "source_conflict", "stale_observation", "scope_mismatch":
		return warning.Class == contract.WarningContradictory
	default:
		return warning.Class == contract.WarningInformational
	}
}

// collisionMessageIsClosed reports whether one scope_mismatch message is exactly
// the program constant plus one non-empty combination of the container classes
// in canonical order. The seven admissible combinations are enumerated by the
// caller-independent generator below; nothing else can pass.
func collisionMessageIsClosed(message string) bool {
	const prefix = "scope collision across container classes: "
	if !hasPrefix(message, prefix) {
		return false
	}
	suffix := message[len(prefix):]
	return suffix == "regular" ||
		suffix == "init" ||
		suffix == "ephemeral" ||
		suffix == "regular, init" ||
		suffix == "regular, ephemeral" ||
		suffix == "init, ephemeral" ||
		suffix == "regular, init, ephemeral"
}

// hasPrefix is a local helper so the check never depends on the strings package
// of an untrusted value.
func hasPrefix(value, prefix string) bool {
	return len(value) >= len(prefix) && value[:len(prefix)] == prefix
}

// validateCollectedScope checks that the run declares exactly the admitted
// acquisition profile, a usable alias and the bounded namespace allowlist.
func validateCollectedScope(acquisition CollectedAcquisition) error {
	scope := acquisition.Scope
	if scope.Selector != collectedSelector || scope.Version != collectedVersion ||
		scope.RedactionPolicy != collectedRedactionPolicy {
		return errCollectedInput
	}
	if !identifierOK(string(scope.ClusterAlias)) {
		return errCollectedInput
	}
	if len(scope.Namespaces) == 0 || len(scope.Namespaces) > 16 {
		return errCollectedInput
	}
	seen := map[contract.Namespace]bool{}
	for _, namespace := range scope.Namespaces {
		if !identifierOK(string(namespace)) || seen[namespace] {
			return errCollectedInput
		}
		seen[namespace] = true
	}
	// Every operation of the run must stay inside the declared allowlist: a
	// namespace that was exercised without being part of the requested scope
	// would let the record claim permissions it never declared.
	for _, operation := range acquisition.Operations {
		if !seen[operation.Namespace] {
			return errCollectedInput
		}
	}
	for _, target := range acquisition.Plan.Targets {
		if !seen[target.Namespace] {
			return errCollectedInput
		}
	}
	for _, pending := range acquisition.Plan.PendingNamespaces {
		if !seen[pending] {
			return errCollectedInput
		}
	}
	for _, listed := range acquisition.Plan.ListedNamespaces {
		if !seen[listed] {
			return errCollectedInput
		}
	}
	return nil
}

// collectedCaptureOf returns the capture identified by the ordinal. The
// ordinal must identify exactly one capture.
func collectedCaptureOf(acquisition CollectedAcquisition, ordinal uint64) (CollectedCapture, error) {
	capture := CollectedCapture{}
	found := false
	for _, candidate := range acquisition.Captures {
		if candidate.Ordinal != ordinal {
			continue
		}
		if found {
			return CollectedCapture{}, errCollectedInput
		}
		capture = candidate
		found = true
	}
	if !found {
		return CollectedCapture{}, errCollectedInput
	}
	return capture, nil
}

// validateCollectedSource re-hashes the retained bytes and requires the alias,
// hash and length to agree with the normalized result: an input whose hash
// describes bytes it does not carry is refused.
func validateCollectedSource(capture CollectedCapture, result normalize.ObservationResult) error {
	if len(capture.Bytes) == 0 || capture.RequestOrdinal == 0 {
		return errCollectedInput
	}
	if capture.Alias != collectedAliasOf(capture.RequestOrdinal) {
		return errCollectedInput
	}
	if !isSha256(string(capture.Hash)) || capture.Hash != HashSource(capture.Bytes) {
		return errCollectedInput
	}
	if result.Source.Name != capture.Alias || result.Source.Hash != capture.Hash {
		return errCollectedInput
	}
	if result.Source.ByteCount != uint64(len(capture.Bytes)) {
		return errCollectedInput
	}
	return nil
}

// validateCollectedSelection checks the selected subject exists, is not omitted
// by a conflict and carries a coherent identity.
func validateCollectedSelection(input CollectedObservationInput) error {
	result := input.Result
	if input.SubjectIndex < 0 || input.SubjectIndex >= len(result.Subjects) {
		return errCollectedInput
	}
	if len(result.Subjects) == 0 || result.TotalItems < result.RejectedItems ||
		uint64(len(result.Subjects)) != result.TotalItems-result.RejectedItems {
		return errCollectedInput
	}
	// A name shared by two different uids is a visible conflict, not a rejected
	// subject: the two subjects stay separate, keep their bundles and carry the
	// uid_changed comparison and the conflict defect. Rejecting them here would
	// silently drop evidence the contract requires to keep.
	subject := result.Subjects[input.SubjectIndex]
	if !identifierOK(string(subject.UID)) || !identifierOK(subject.Name) {
		return errCollectedInput
	}
	if subject.ItemIndex < 0 || subject.Namespace != result.Namespace {
		return errCollectedInput
	}
	return nil
}

// validateCollectedOperation requires the capture to be supported by an
// operation really attempted for exactly that identity and response shape.
func validateCollectedOperation(acquisition CollectedAcquisition, capture CollectedCapture, input CollectedObservationInput) error {
	matches := 0
	finished := false
	for _, operation := range acquisition.Operations {
		if operation.RequestOrdinal != capture.RequestOrdinal {
			continue
		}
		matches++
		switch operation.State {
		case OperationAttempted, OperationFinished, OperationFailed:
		default:
			return errCollectedInput
		}
		if operation.State == OperationFinished {
			// A capture can only be supported by an operation that really produced
			// a valid response: an attempted or failed request cannot carry a
			// source, and a failed one must not be presented as its origin.
			if operation.StatusCode != 200 {
				return errCollectedInput
			}
			finished = true
		} else {
			return errCollectedInput
		}
		if operation.Verb != "list" && operation.Verb != "get" {
			return errCollectedInput
		}
		if operation.Namespace != input.Result.Namespace {
			return errCollectedInput
		}
		if operation.Verb == "get" {
			if operation.Name != input.Result.Subjects[input.SubjectIndex].Name {
				return errCollectedInput
			}
			if operation.Round < 1 || operation.Round > 2 {
				return errCollectedInput
			}
		}
		if operation.StartedAt == nil || operation.EndedAt == nil {
			return errCollectedInput
		}
	}
	if matches != 1 || !finished {
		return errCollectedInput
	}
	if !collectedNamespaceAttempted(acquisition, input.Result.Namespace) {
		return errCollectedInput
	}
	return nil
}

// collectedNamespaceAttempted reports whether one namespace was really
// addressed by an attempted operation of the run.
func collectedNamespaceAttempted(acquisition CollectedAcquisition, namespace contract.Namespace) bool {
	for _, operation := range acquisition.Operations {
		if operation.Namespace == namespace {
			return true
		}
	}
	return false
}

// validateCollectedTimes requires coherent instants: a started instant, an
// optional ended instant that never contradicts it, a capture observed inside
// that window, and no operation left without a reading unless the failing clock
// is visible in the run-wide record.
//
// An operation may lack its start or its end only as the artifact of a sampler
// that failed: the attempt was counted, the sampling that would have stamped
// the operation failed, and no instant is invented to fill the gap. Such a gap
// binds the whole record: the run must be aborted and must carry the global
// clock_invalid error, so a finished run can never present an unstamped
// operation and an unexplained gap is refused.
func validateCollectedTimes(acquisition CollectedAcquisition, capture CollectedCapture) error {
	if acquisition.StartedAt == nil {
		return errCollectedInput
	}
	if acquisition.EndedAt == nil && len(acquisition.GlobalErrors) == 0 && acquisition.Termination == contract.TerminationFinished {
		return errCollectedInput
	}
	clockGap := false
	for _, operation := range acquisition.Operations {
		if operation.StartedAt == nil {
			// A start reading that never arrived: only a failed attempt whose
			// own diagnostic is the clock failure may lack it.
			if operation.State != OperationFailed || operation.Diagnostic != CodeClockInvalid ||
				operation.EndedAt != nil || operation.Elapsed != 0 {
				return errCollectedInput
			}
			clockGap = true
			continue
		}
		if operation.EndedAt == nil {
			// A closing reading that never arrived: the operation really failed,
			// with a cause compatible with a failed request, and the sampling
			// that would have closed it failed. The visible global clock failure
			// below is the only admissible explanation of the gap.
			if operation.State != OperationFailed || operation.Elapsed != 0 ||
				!collectedOperationFailureCode(operation.Diagnostic) {
				return errCollectedInput
			}
			clockGap = true
			continue
		}
		if operation.StartedAt.After(operation.EndedAt.Time) {
			return errCollectedInput
		}
		if operation.Elapsed < 0 {
			return errCollectedInput
		}
	}
	if clockGap {
		if acquisition.Termination != contract.TerminationAborted ||
			!collectedGlobalError(acquisition, CodeClockInvalid) {
			return errCollectedInput
		}
	}
	if capture.Observation.ObservedAt == nil {
		return errCollectedInput
	}
	if capture.Observation.ObservedAt.Before(acquisition.StartedAt.Time) {
		return errCollectedInput
	}
	if acquisition.EndedAt != nil {
		if acquisition.StartedAt.After(acquisition.EndedAt.Time) {
			return errCollectedInput
		}
		if capture.Observation.ObservedAt.After(acquisition.EndedAt.Time) {
			return errCollectedInput
		}
	}
	return nil
}

// validateCollectedTermination applies the termination rules of A.9: a finished
// run has no open work and no errors; an aborted run keeps at least one visible
// error.
func validateCollectedTermination(acquisition CollectedAcquisition) error {
	switch acquisition.Termination {
	case contract.TerminationFinished:
		if len(acquisition.GlobalErrors) != 0 {
			return errCollectedInput
		}
		if len(acquisition.Plan.PendingNamespaces) != 0 || acquisition.Plan.UnfinishedTargets != 0 ||
			!acquisition.Plan.InventoryClosed || acquisition.Plan.ContinuationOpen {
			return errCollectedInput
		}
	case contract.TerminationAborted:
		if len(acquisition.GlobalErrors) == 0 {
			return errCollectedInput
		}
	case contract.TerminationUnknown:
	default:
		return errCollectedInput
	}
	return nil
}

// validateCollectedComparisons requires every comparison to reference existing
// captures and observed original item positions, using only the closed
// comparison codes, and to state a condition that the referenced observations
// really carry: the two ends are real subjects of their captures, an
// observation_changed needs differing projected content, a stale_status
// suspected needs the bounded F07 pattern, and a uid_changed needs two distinct
// UIDs of the same namespace/name. The position of a reference is the original
// item index of the admitted document, never a compacted position of the
// accepted subjects: rejecting one item must not shift the identity of the
// next one.
func validateCollectedComparisons(acquisition CollectedAcquisition) error {
	type located struct {
		subject normalize.ObservationSubject
	}
	byCapture := map[uint64]map[int]located{}
	captureByOrdinal := map[uint64]CollectedCapture{}
	for _, capture := range acquisition.Captures {
		if _, present := captureByOrdinal[capture.Ordinal]; present {
			return errCollectedInput
		}
		captureByOrdinal[capture.Ordinal] = capture
		items := map[int]located{}
		for _, subject := range capture.Observation.Subjects {
			if subject.ItemIndex < 0 {
				return errCollectedInput
			}
			if _, present := items[subject.ItemIndex]; present {
				return errCollectedInput
			}
			items[subject.ItemIndex] = located{subject: subject}
		}
		byCapture[capture.Ordinal] = items
	}
	// Every capture cited by a comparison is re-admitted from its own retained
	// bytes: a comparison that trusted a DTO nobody verified could attest a
	// difference between observations that never happened.
	verified := map[uint64]bool{}
	verify := func(ordinal uint64) error {
		if verified[ordinal] {
			return nil
		}
		capture, known := captureByOrdinal[ordinal]
		if !known {
			return errCollectedInput
		}
		if err := validateCollectedCaptureAdmission(acquisition, capture); err != nil {
			return err
		}
		verified[ordinal] = true
		return nil
	}
	for _, comparison := range acquisition.Comparisons {
		switch comparison.Code {
		case CodeUIDChanged, CodeObservationChanged, CodeStaleStatusSuspected:
		default:
			return errCollectedInput
		}
		previous, known := byCapture[comparison.Previous.CaptureOrdinal]
		if !known {
			return errCollectedInput
		}
		before, known := previous[comparison.Previous.ItemIndex]
		if !known {
			return errCollectedInput
		}
		current, known := byCapture[comparison.Current.CaptureOrdinal]
		if !known {
			return errCollectedInput
		}
		after, known := current[comparison.Current.ItemIndex]
		if !known {
			return errCollectedInput
		}
		if comparison.Previous == comparison.Current {
			// A comparison of a subject with itself cannot state a difference.
			return errCollectedInput
		}
		switch comparison.Code {
		case CodeUIDChanged:
			// The replacement is between two real subjects that share the
			// namespace/name address with different UIDs.
			if before.subject.UID == "" || after.subject.UID == "" ||
				before.subject.UID == after.subject.UID ||
				before.subject.Namespace != after.subject.Namespace ||
				before.subject.Name != after.subject.Name {
				return errCollectedInput
			}
			if err := verify(comparison.Previous.CaptureOrdinal); err != nil {
				return err
			}
			if err := verify(comparison.Current.CaptureOrdinal); err != nil {
				return err
			}
		case CodeObservationChanged:
			// The change is a real difference of the projected content of the
			// same subject: same non-empty UID and address, ordered captures,
			// both DTOs re-admitted from their own bytes.
			if before.subject.UID == "" || before.subject.UID != after.subject.UID ||
				before.subject.Namespace != after.subject.Namespace ||
				before.subject.Name != after.subject.Name {
				return errCollectedInput
			}
			if comparison.Previous.CaptureOrdinal >= comparison.Current.CaptureOrdinal {
				return errCollectedInput
			}
			if err := verify(comparison.Previous.CaptureOrdinal); err != nil {
				return err
			}
			if err := verify(comparison.Current.CaptureOrdinal); err != nil {
				return err
			}
			if normalize.ContentSignature(before.subject) == normalize.ContentSignature(after.subject) {
				return errCollectedInput
			}
		case CodeStaleStatusSuspected:
			// The bounded pattern of A.8.3 holds between two ordered captures
			// of the same subject, both re-admitted from their own bytes.
			if before.subject.UID == "" || before.subject.UID != after.subject.UID ||
				before.subject.Namespace != after.subject.Namespace ||
				before.subject.Name != after.subject.Name {
				return errCollectedInput
			}
			if comparison.Previous.CaptureOrdinal >= comparison.Current.CaptureOrdinal {
				return errCollectedInput
			}
			if err := verify(comparison.Previous.CaptureOrdinal); err != nil {
				return err
			}
			if err := verify(comparison.Current.CaptureOrdinal); err != nil {
				return err
			}
			if normalize.ContentSignature(before.subject) == normalize.ContentSignature(after.subject) ||
				!normalize.StaleStatusPattern(before.subject, after.subject) {
				return errCollectedInput
			}
		}
	}
	return nil
}

// validateCollectedDiagnostics refuses codes outside the closed catalog and any
// position that does not exist in the acquisition record.
func validateCollectedDiagnostics(acquisition CollectedAcquisition) error {
	captures := map[uint64]bool{}
	items := map[uint64]int{}
	for _, capture := range acquisition.Captures {
		captures[capture.Ordinal] = true
		items[capture.Ordinal] = len(capture.Observation.Subjects)
	}
	requests := map[uint64]bool{}
	for _, operation := range acquisition.Operations {
		requests[operation.RequestOrdinal] = true
	}
	for _, diagnostic := range acquisition.Diagnostics {
		if !CollectionCodeKnown(diagnostic.Code) {
			return errCollectedInput
		}
		if diagnostic.RequestOrdinal != nil && !requests[*diagnostic.RequestOrdinal] {
			return errCollectedInput
		}
		if diagnostic.CaptureOrdinal != nil && !captures[*diagnostic.CaptureOrdinal] {
			return errCollectedInput
		}
		if diagnostic.ItemIndex != nil {
			if *diagnostic.ItemIndex < 0 {
				return errCollectedInput
			}
			if diagnostic.CaptureOrdinal != nil && *diagnostic.ItemIndex >= items[*diagnostic.CaptureOrdinal] {
				return errCollectedInput
			}
		}
		if diagnostic.FieldLocator != "" && !ingest.PodListLocatorValid(diagnostic.FieldLocator) {
			return errCollectedInput
		}
	}
	return nil
}

// validateCollectedAccounting requires the declared counters to match the
// operations really attempted and the shape of one execution: no phantom
// request, no second parallel request and no invented permission.
func validateCollectedAccounting(acquisition CollectedAcquisition) error {
	if acquisition.Stats.RequestsAttempted != uint64(len(acquisition.Operations)) {
		return errCollectedInput
	}
	if acquisition.Stats.MaxConcurrency > 1 {
		return errCollectedInput
	}
	if acquisition.Stats.ResponsesFinished+acquisition.Stats.ResponsesFailed > acquisition.Stats.RequestsAttempted {
		return errCollectedInput
	}
	if acquisition.Plan.RequestedOps != acquisition.Stats.RequestsAttempted {
		return errCollectedInput
	}
	return nil
}

// validateCollectedAdmission re-admits the retained bytes with the real A2-01
// machinery and requires both the caller-provided DTO and the capture record to
// be exactly the result of that admission. The check is the only way to prove a
// DTO corresponds to the bytes it claims: matching shapes, hashes or locators
// alone would not.
func validateCollectedAdmission(input CollectedObservationInput, capture CollectedCapture) error {
	result := input.Result
	if result.ObservedAt == nil || !result.Termination.Valid() {
		return errCollectedInput
	}
	// The effective termination of the run is the only termination the bundle may
	// declare: a capture cannot present itself as finished while the run aborted.
	if result.Termination != input.Acquisition.Termination {
		return errCollectedInput
	}
	if result.ClusterAlias != input.Acquisition.Scope.ClusterAlias {
		return errCollectedInput
	}
	// The rebuild of an aborted run re-admits the same bytes with the run
	// termination: bytes, alias and observation time are never modified.
	if capture.Observation.ObservedAt == nil || !capture.Observation.ObservedAt.Time.Equal(result.ObservedAt.Time) {
		return errCollectedInput
	}
	readmitted, err := readmitCollectedCapture(input.Acquisition, capture)
	if err != nil {
		return err
	}
	// Neither the presented DTO nor the observation kept by the capture can claim
	// bytes they do not describe: both must be the admitted result itself.
	if !reflect.DeepEqual(readmitted, result) || !reflect.DeepEqual(readmitted, capture.Observation) {
		return errCollectedInput
	}
	return nil
}

// readmitCollectedCapture parses and normalizes one capture's own retained bytes
// with the real A2-01 machinery and returns the result of that admission. The
// capture must be coherent with the run: same effective termination and same
// cluster alias.
func readmitCollectedCapture(acquisition CollectedAcquisition, capture CollectedCapture) (normalize.ObservationResult, error) {
	result := capture.Observation
	if result.ObservedAt == nil || !result.Termination.Valid() {
		return normalize.ObservationResult{}, errCollectedInput
	}
	if result.Termination != acquisition.Termination {
		return normalize.ObservationResult{}, errCollectedInput
	}
	if result.ClusterAlias != acquisition.Scope.ClusterAlias {
		return normalize.ObservationResult{}, errCollectedInput
	}
	parsed, err := ingest.ParseSanitizedPodList(bytes.NewReader(capture.Bytes), ingest.PodListContext{
		Selector:           schema.SanitizedPodListSelector,
		Version:            schema.SanitizedPodListVersion,
		RedactionPolicy:    schema.SanitizedPodListRedactionPolicy,
		SourceName:         capture.Alias,
		ClusterAlias:       string(result.ClusterAlias),
		Namespace:          string(result.Namespace),
		ObservedAt:         result.ObservedAt.Time,
		CaptureTermination: result.Termination,
	})
	if err != nil || !parsed.PodListAccepted() {
		return normalize.ObservationResult{}, errCollectedInput
	}
	readmitted, err := normalize.NormalizePodList(parsed)
	if err != nil {
		return normalize.ObservationResult{}, errCollectedInput
	}
	return readmitted, nil
}

// validateCollectedCaptureAdmission verifies one capture cited by a comparison:
// its alias, hash and length must agree with its own retained bytes, and those
// bytes must reproduce exactly the observation it carries. A comparison whose
// cited capture lies about its hash would otherwise be published with an
// adulterated input in the provenance.
func validateCollectedCaptureAdmission(acquisition CollectedAcquisition, capture CollectedCapture) error {
	if err := validateCollectedCaptureBytes(capture); err != nil {
		return err
	}
	readmitted, err := readmitCollectedCapture(acquisition, capture)
	if err != nil {
		return err
	}
	if !reflect.DeepEqual(readmitted, capture.Observation) {
		return errCollectedInput
	}
	return nil
}

// validateCollectedCaptureBytes re-hashes the retained bytes of one capture and
// requires the alias, hash, length and normalized source header to agree with
// them, without prescribing the specific capture it belongs to: the same rule
// applies to the selected capture and to every capture cited by a comparison.
func validateCollectedCaptureBytes(capture CollectedCapture) error {
	if len(capture.Bytes) == 0 || capture.RequestOrdinal == 0 {
		return errCollectedInput
	}
	if capture.Alias != collectedAliasOf(capture.RequestOrdinal) {
		return errCollectedInput
	}
	if !isSha256(string(capture.Hash)) || capture.Hash != HashSource(capture.Bytes) {
		return errCollectedInput
	}
	result := capture.Observation
	if result.Source.Name != capture.Alias || result.Source.Hash != capture.Hash {
		return errCollectedInput
	}
	if result.Source.ByteCount != uint64(len(capture.Bytes)) {
		return errCollectedInput
	}
	return nil
}
