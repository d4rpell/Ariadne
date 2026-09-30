package ingest

import (
	"errors"
	"strings"
	"testing"
	"time"

	contract "github.com/d4rpell/Ariadne/pkg/evidence"
)

// Test support of the sanitized PodList ingestion. The helpers build documents
// deterministically in memory and compare the complete diagnostic: the closed
// code, the verified byte offset and the literal message of the contract, never
// a prefix or a substring.

func a201Context() PodListContext {
	return PodListContext{
		Selector:           "sanitized-podlist-v1",
		Version:            "1.0",
		RedactionPolicy:    "sanitized-podlist-v1/1.0",
		SourceName:         "sanitized-pods.json",
		ClusterAlias:       "cluster-a",
		Namespace:          "payments",
		ObservedAt:         time.Date(2026, 9, 30, 12, 0, 0, 0, time.UTC),
		CaptureTermination: contract.TerminationFinished,
	}
}

func a201ContextWith(mutate func(context *PodListContext)) PodListContext {
	context := a201Context()
	mutate(&context)
	return context
}

func a201Parse(t *testing.T, document string) (PodListResult, error) {
	t.Helper()
	return ParseSanitizedPodList(strings.NewReader(document), a201Context())
}

func a201ParseWith(t *testing.T, document string, context PodListContext) (PodListResult, error) {
	t.Helper()
	return ParseSanitizedPodList(strings.NewReader(document), context)
}

// a201List wraps items in the admitted root object.
func a201List(items ...string) string {
	return `{"apiVersion":"v1","kind":"PodList","items":[` + strings.Join(items, ",") + `]}`
}

// a201Pod builds one items element with the three spec and status categories
// explicitly present and one declared container per category.
func a201Pod(uid, name string, specContainers, statusContainers string) string {
	return `{"apiVersion":"v1","kind":"Pod",` +
		`"metadata":{"uid":"` + uid + `","namespace":"payments","name":"` + name + `"},` +
		`"spec":{"containers":[` + specContainers + `],"initContainers":[],"ephemeralContainers":[]},` +
		`"status":{"containerStatuses":[` + statusContainers + `],"initContainerStatuses":[],"ephemeralContainerStatuses":[]}}`
}

// a201CompletePod is the shape the termination × collision matrix starts from:
// one container whose declaration and status are present and joined.
func a201CompletePod(uid, name, imageID string) string {
	return a201Pod(uid, name,
		`{"name":"api","image":"registry.example/app:release"}`,
		`{"name":"api","imageID":"`+imageID+`"}`)
}

// a201Problem returns the typed diagnostic of one failure.
func a201Problem(t *testing.T, err error) PodListDiagnostic {
	t.Helper()
	if err == nil {
		t.Fatalf("expected a failure, got none")
	}
	var problem *PodListError
	if !errors.As(err, &problem) {
		t.Fatalf("failure type = %T, want *PodListError", err)
	}
	return problem.Diagnostic
}

// a201WantFailure asserts the parsed failure against the complete literal
// message of the contract.
func a201WantFailure(t *testing.T, err error, want string) PodListDiagnostic {
	t.Helper()
	diagnostic := a201Problem(t, err)
	if err.Error() != want {
		t.Fatalf("failure = %q, want %q", err.Error(), want)
	}
	return diagnostic
}

// a201Literal renders the expected message of one code at one offset, so tests
// state the whole expectation instead of comparing a fragment.
func a201Literal(offset uint64, message string) string {
	return "ingest: sanitized-podlist-v1: byte/" + itoaTest(offset) + ": " + message
}

func itoaTest(value uint64) string {
	if value == 0 {
		return "0"
	}
	digits := []byte{}
	for value > 0 {
		digits = append([]byte{byte('0' + value%10)}, digits...)
		value /= 10
	}
	return string(digits)
}

// a201MustParse requires an admitted source and returns its result.
func a201MustParse(t *testing.T, document string) PodListResult {
	t.Helper()
	result, err := a201Parse(t, document)
	if err != nil {
		t.Fatalf("ParseSanitizedPodList: %v", err)
	}
	return result
}
