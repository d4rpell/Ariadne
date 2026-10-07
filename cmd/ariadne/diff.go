package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"

	"github.com/d4rpell/Ariadne/internal/casefile"
)

// The validity-diff command of ADR-0038 (task A3-10): `diff` reads one verified
// casefile book, compares it at two declared instants and writes the
// deterministic document to a new exclusive file. The order follows the ratified
// shape: arguments, read, verify, the library call in memory, the receipt
// composed before the destination is opened, the document, the exclusive write,
// and only then the receipt. Nothing here reads a clock: every instant is a
// declared literal.

// diffDocumentView is the frozen output document. Key order is the declaration
// order; every slice is initialized so an empty collection renders as [] and
// never as null. Only head_hash may be null (the empty book has no head).
type diffDocumentView struct {
	Since        string            `json:"since"`
	AsOf         string            `json:"as_of"`
	Records      int               `json:"records"`
	HeadHash     *string           `json:"head_hash"`
	Declarations []string          `json:"declarations"`
	Subjects     []diffSubjectView `json:"subjects"`
	Anomalies    []diffAnomalyView `json:"anomalies"`
}

type diffSubjectView struct {
	SubjectUID      string          `json:"subject_uid"`
	ContainerName   string          `json:"container_name"`
	ContainerClass  string          `json:"container_class"`
	VulnerabilityID string          `json:"vulnerability_id"`
	Since           diffInstantView `json:"since"`
	AsOf            diffInstantView `json:"as_of"`
	Change          string          `json:"change"`
}

type diffInstantView struct {
	Effective bool     `json:"effective"`
	Hashes    []string `json:"hashes"`
}

type diffAnomalyView struct {
	Sequence uint64 `json:"sequence"`
	Anomaly  string `json:"anomaly"`
}

// runDiff executes one validity diff end to end. The receipt is composed before
// the destination is opened, so a delivery failure is never confused with a
// composition failure and no byte reaches disk before the receipt exists.
func runDiff(call invocation, stdout io.Writer, cwd string) *cliError {
	bookBytes, failure := readInput(call.value("casebook"), stageBundleRead, casefile.MaxBookBytes, true, cwd)
	if failure != nil {
		return failure
	}
	book, err := casefile.Verify(bookBytes)
	if err != nil {
		// The casebook is the primary canonical input of this command: the same
		// stage and code travel as for serve and append.
		return newFailure(stageBundleDecode, codeInvalidBundle)
	}
	view, err := casefile.Diff(book, call.value("since"), call.value("as-of"))
	if err != nil {
		// Diff cannot fail on a verified book with grammar-validated instants;
		// fail closed instead of classifying an impossible state as delivery.
		return newFailure(stageInternal, codeInternalFailure)
	}
	entries, err := view.Entries()
	if err != nil {
		return newFailure(stageInternal, codeInternalFailure)
	}
	declarations, err := view.Declarations()
	if err != nil {
		return newFailure(stageInternal, codeInternalFailure)
	}
	anomalies, err := view.Anomalies()
	if err != nil {
		return newFailure(stageInternal, codeInternalFailure)
	}
	records, err := casefile.Records(book)
	if err != nil {
		return newFailure(stageInternal, codeInternalFailure)
	}
	head, err := casefile.HeadHash(book)
	if err != nil {
		return newFailure(stageInternal, codeInternalFailure)
	}
	document, err := encodeDiff(composeDiffDocument(call.value("since"), call.value("as-of"), len(records), head, declarations, entries, anomalies))
	if err != nil {
		return newFailure(stageInternal, codeInternalFailure)
	}
	receipt := fmt.Sprintf("{\"subjects\":%d,\"changed\":%d}\n", len(entries), changedSubjects(entries))
	if failure := writeOutput(call.value("out"), document, cwd); failure != nil {
		return failure
	}
	return deliverStdout(stdout, receipt)
}

// composeDiffDocument projects the pure DiffView into the frozen document. Every
// slice is non-nil; head_hash is null only for the empty book.
func composeDiffDocument(since, asOf string, records int, head string, declarations []string, entries []casefile.DiffEntry, anomalies []casefile.DiffAnomaly) diffDocumentView {
	var headPointer *string
	if head != "" {
		copied := head
		headPointer = &copied
	}
	document := diffDocumentView{
		Since:        since,
		AsOf:         asOf,
		Records:      records,
		HeadHash:     headPointer,
		Declarations: append([]string{}, declarations...),
		Subjects:     make([]diffSubjectView, 0, len(entries)),
		Anomalies:    make([]diffAnomalyView, 0, len(anomalies)),
	}
	for index := range entries {
		entry := &entries[index]
		document.Subjects = append(document.Subjects, diffSubjectView{
			SubjectUID:      entry.Subject.SubjectUID,
			ContainerName:   entry.Subject.ContainerName,
			ContainerClass:  string(entry.Subject.ContainerClass),
			VulnerabilityID: entry.Subject.VulnerabilityID,
			Since:           diffInstantView{Effective: len(entry.SinceHashes) > 0, Hashes: append([]string{}, entry.SinceHashes...)},
			AsOf:            diffInstantView{Effective: len(entry.AsOfHashes) > 0, Hashes: append([]string{}, entry.AsOfHashes...)},
			Change:          string(entry.Change),
		})
	}
	for index := range anomalies {
		document.Anomalies = append(document.Anomalies, diffAnomalyView{Sequence: anomalies[index].Sequence, Anomaly: string(anomalies[index].Anomaly)})
	}
	return document
}

func changedSubjects(entries []casefile.DiffEntry) int {
	changed := 0
	for index := range entries {
		if entries[index].Change != casefile.ChangeUnchanged {
			changed++
		}
	}
	return changed
}

// encodeDiff renders the compact UTF-8 document: the declared key order, no
// whitespace outside tokens, no BOM and no trailing newline, exactly as
// report.JSON. encoding/json escapes every U+0000–U+001F control and invalid
// UTF-8, so the document does not depend on the text validation of casefile.
func encodeDiff(document diffDocumentView) ([]byte, error) {
	var buffer bytes.Buffer
	encoder := json.NewEncoder(&buffer)
	encoder.SetEscapeHTML(true)
	if err := encoder.Encode(document); err != nil {
		return nil, err
	}
	return bytes.TrimSuffix(buffer.Bytes(), []byte("\n")), nil
}
