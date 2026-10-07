package main

import (
	"errors"
	"fmt"
	"io"

	"github.com/d4rpell/Ariadne/internal/casefile"
)

// The casefile book persistence commands of ADR-0037 (task A3-11): `book`
// writes the canonical empty book and `append` reads one verified book, adds
// exactly one declared decision and writes the resulting book to a new file.
// The on-disk format is exactly casefile.Encode: no second format exists and
// Verify is the only way back. No file is ever overwritten — every write is an
// exclusive creation — so the append-only history is never the file being
// written. The order follows the ratified shape: arguments, read, verify, the
// library call in memory, encode, the exclusive write, and only then the
// receipt. Nothing here reads a clock: every instant is a declared literal.

// runBook delivers the canonical empty book. The encode of NewBook cannot
// fail; a failure would be an internal inconsistency, never a delivery one.
func runBook(call invocation, stdout io.Writer, cwd string) *cliError {
	document, err := casefile.Encode(casefile.NewBook())
	if err != nil {
		return newFailure(stageInternal, codeInternalFailure)
	}
	if failure := writeOutput(call.value("out"), document, cwd); failure != nil {
		return failure
	}
	return deliverStdout(stdout, "{\"records\":0}\n")
}

// runAppend executes one declared append end to end. The receipt names the
// resulting record count and head hash, and is emitted only after the new
// book is fully delivered; a partial file never has a receipt, and the book
// it was derived from stays byte-for-byte intact.
func runAppend(call invocation, stdout io.Writer, cwd string) *cliError {
	bookBytes, failure := readInput(call.value("casebook"), stageBundleRead, casefile.MaxBookBytes, true, cwd)
	if failure != nil {
		return failure
	}
	book, err := casefile.Verify(bookBytes)
	if err != nil {
		// The casebook is the primary canonical input of this command, exactly
		// as it is for serve: the same stage and code travel.
		return newFailure(stageBundleDecode, codeInvalidBundle)
	}
	grown, err := casefile.Append(book, appendInput(call))
	if err != nil {
		return casefileFailure(err)
	}
	document, err := casefile.Encode(grown)
	if err != nil {
		// Append returned an admitted book, so Encode cannot fail; fail closed
		// instead of classifying an impossible state as a delivery problem.
		return newFailure(stageInternal, codeInternalFailure)
	}
	// The receipt is prepared before the destination is opened: Records and
	// HeadHash are checked here — they cannot fail on an admitted book, but they
	// are never ignored — so a delivery failure is never confused with a
	// composition failure and no byte reaches disk before the receipt exists.
	records, err := casefile.Records(grown)
	if err != nil {
		return newFailure(stageInternal, codeInternalFailure)
	}
	head, err := casefile.HeadHash(grown)
	if err != nil {
		return newFailure(stageInternal, codeInternalFailure)
	}
	receipt := fmt.Sprintf("{\"records\":%d,\"head_hash\":%q}\n", len(records), head)
	if failure := writeOutput(call.value("out"), document, cwd); failure != nil {
		return failure
	}
	return deliverStdout(stdout, receipt)
}

// appendInput builds the declared decision from the argv literals. The parser
// already decided every vocabulary, hash and instant: this translation cannot
// fail, so it asserts its own precondition instead of inventing a recovery.
func appendInput(call invocation) casefile.DecisionInput {
	input := casefile.DecisionInput{
		RiskDecision: casefile.Decision(call.value("decision")),
		Owner:        call.value("owner"),
		Approver:     call.value("approver"),
		Rationale:    call.value("rationale"),
		Scope: casefile.Scope{
			BundleHash:      call.value("bundle-hash"),
			SubjectUID:      call.value("subject-uid"),
			ContainerName:   call.value("container-name"),
			ContainerClass:  casefile.ContainerClass(call.value("container-class")),
			VulnerabilityID: call.value("vulnerability-id"),
		},
		DecidedAt: call.value("decided-at"),
	}
	if call.value("expires-at") != "" {
		instant := call.value("expires-at")
		input.ExpiresAt = &instant
	}
	if call.value("supersedes") != "" {
		reference := call.value("supersedes")
		input.Supersedes = &reference
	}
	if call.value("result-fingerprint") != "" {
		fingerprint := call.value("result-fingerprint")
		input.Scope.ResultFingerprint = &fingerprint
	}
	if controls, ok := parseControls(call.value("controls")); ok {
		input.Controls = controls
	}
	return input
}

// casefileFailure maps one library failure to the declared-decision stage with
// its code verbatim; an error outside the typed set fails closed.
func casefileFailure(err error) *cliError {
	var failure *casefile.Error
	if errors.As(err, &failure) {
		return newFailure(stageCasefile, string(failure.Code))
	}
	return newFailure(stageInternal, codeInternalFailure)
}
