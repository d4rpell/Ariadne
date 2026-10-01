package bundle_test

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"
	"time"

	"github.com/d4rpell/Ariadne/internal/bundle"
	"github.com/d4rpell/Ariadne/internal/ingest"
	"github.com/d4rpell/Ariadne/internal/normalize"
	contract "github.com/d4rpell/Ariadne/pkg/evidence"
)

// Harness of the A2-02 bundle tests (handoff §4.1 and §4.5). Every document,
// identity and instant is synthetic; the acquisition carriers are built here
// with the production types, never with a second set of definitions.

const (
	a202Alias     = "cluster-synthetic"
	a202Namespace = "payments"
	a202Image     = "registry.example/app:release"
	a202ImageID   = "sha256:" + "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	a202Moment    = "2026-10-01T10:00:00Z"
)

// a202Source is one admitted sanitized source with its normalized observation.
type a202Source struct {
	Bytes       []byte
	Hash        contract.SourceHash
	Alias       string
	Termination contract.CoverageTermination
	Observation normalize.ObservationResult
}

// a202BuildSource admits one synthetic document through the real pipeline.
func a202BuildSource(t *testing.T, document, alias string, termination contract.CoverageTermination) a202Source {
	t.Helper()
	moment, err := time.Parse(time.RFC3339, a202Moment)
	if err != nil {
		t.Fatalf("parse synthetic instant: %v", err)
	}
	parsed, err := ingest.ParseSanitizedPodList(strings.NewReader(document), ingest.PodListContext{
		Selector:           "sanitized-podlist-v1",
		Version:            "1.0",
		RedactionPolicy:    "sanitized-podlist-v1/1.0",
		SourceName:         alias,
		ClusterAlias:       a202Alias,
		Namespace:          a202Namespace,
		ObservedAt:         moment.UTC(),
		CaptureTermination: termination,
	})
	if err != nil {
		t.Fatalf("parse sanitized podlist: %v", err)
	}
	normalized, err := normalize.NormalizePodList(parsed)
	if err != nil {
		t.Fatalf("normalize podlist: %v", err)
	}
	return a202Source{
		Bytes:       []byte(document),
		Hash:        contract.SourceHash(a202IndependentHash([]byte(document))),
		Alias:       alias,
		Termination: termination,
		Observation: normalized,
	}
}

// a202IndependentHash is the independent SHA-256 oracle of these tests.
func a202IndependentHash(data []byte) string {
	digest := sha256.Sum256(data)
	return "sha256:" + hex.EncodeToString(digest[:])
}

// a202Pod builds one complete synthetic Pod.
func a202Pod(uid, name string) string {
	return `{"apiVersion":"v1","kind":"Pod","metadata":{"uid":"` + uid + `","namespace":"` + a202Namespace + `","name":"` + name + `"},` +
		`"spec":{"containers":[{"name":"api","image":"` + a202Image + `"}],"initContainers":[],"ephemeralContainers":[]},` +
		`"status":{"containerStatuses":[{"name":"api","imageID":"` + a202ImageID + `","image":"` + a202Image + `","ready":true,"state":{"running":{}},"restartCount":0}],` +
		`"initContainerStatuses":[],"ephemeralContainerStatuses":[]}}`
}

// a202PodWithImageID is one complete Pod whose status imageID is the argument:
// the projected content differs from a202Pod exactly there.
func a202PodWithImageID(uid, name, imageID string) string {
	return `{"apiVersion":"v1","kind":"Pod","metadata":{"uid":"` + uid + `","namespace":"` + a202Namespace + `","name":"` + name + `"},` +
		`"spec":{"containers":[{"name":"api","image":"` + a202Image + `"}],"initContainers":[],"ephemeralContainers":[]},` +
		`"status":{"containerStatuses":[{"name":"api","imageID":"` + imageID + `","image":"` + a202Image + `","ready":true,"state":{"running":{}},"restartCount":0}],` +
		`"initContainerStatuses":[],"ephemeralContainerStatuses":[]}}`
}

// a202PodRequestedImage is one complete Pod whose requested image is the
// argument while its whole projected status tuple stays identical: the F07
// shape when two captures differ only there.
func a202PodRequestedImage(uid, name, requested string) string {
	return `{"apiVersion":"v1","kind":"Pod","metadata":{"uid":"` + uid + `","namespace":"` + a202Namespace + `","name":"` + name + `"},` +
		`"spec":{"containers":[{"name":"api","image":"` + requested + `"}],"initContainers":[],"ephemeralContainers":[]},` +
		`"status":{"containerStatuses":[{"name":"api","imageID":"` + a202ImageID + `","image":"` + a202Image + `","ready":true,"state":{"running":{}},"restartCount":0}],` +
		`"initContainerStatuses":[],"ephemeralContainerStatuses":[]}}`
}

func a202Document(pods ...string) string {
	joined := ""
	for index, pod := range pods {
		if index > 0 {
			joined += ","
		}
		joined += pod
	}
	return `{"apiVersion":"v1","kind":"PodList","metadata":{"resourceVersion":"100"},"items":[` + joined + `]}`
}

// a202Acquisition assembles one publishable acquisition record over the given
// sources: one list operation and one get operation per source, all finished.
func a202Acquisition(t *testing.T, sources []a202Source, termination contract.CoverageTermination, globalErrors []string) bundle.CollectedAcquisition {
	t.Helper()
	moment := time.Date(2026, 10, 1, 10, 0, 0, 0, time.UTC)
	started, err := contract.NewTimestamp(moment)
	if err != nil {
		t.Fatalf("started timestamp: %v", err)
	}
	ended, err := contract.NewTimestamp(moment.Add(time.Second))
	if err != nil {
		t.Fatalf("ended timestamp: %v", err)
	}
	acquisition := bundle.CollectedAcquisition{
		Scope: bundle.CollectedScope{
			Selector:        "k8s-pod-read-v1",
			Version:         "1.0",
			RedactionPolicy: "k8s-pod-read-v1/1.0",
			ClusterAlias:    a202Alias,
			Namespaces:      []contract.Namespace{a202Namespace},
		},
		Plan: bundle.CollectedPlan{
			ListedNamespaces:        []contract.Namespace{a202Namespace},
			InventoryClosed:         true,
			PagesKnown:              true,
			PlannedReReadsPerTarget: 2,
		},
		StartedAt:   &started,
		EndedAt:     &ended,
		Termination: termination,
		GlobalErrors: func() []string {
			if globalErrors == nil {
				return []string{}
			}
			return globalErrors
		}(),
	}
	ordinal := uint64(0)
	for index, source := range sources {
		ordinal++
		requestOrdinal := uint64(index + 1)
		verb := "list"
		if index > 0 {
			verb = "get"
		}
		operation := bundle.CollectedOperation{
			Verb:           verb,
			Namespace:      a202Namespace,
			RequestOrdinal: requestOrdinal,
			State:          bundle.OperationFinished,
			StatusCode:     200,
			StartedAt:      &started,
			EndedAt:        &ended,
			Elapsed:        time.Second,
			BytesRead:      uint64(len(source.Bytes)),
		}
		if verb == "get" {
			operation.Name = source.Observation.Subjects[0].Name
			operation.Round = 1
		}
		capture := bundle.CollectedCapture{
			Ordinal:        ordinal,
			RequestOrdinal: requestOrdinal,
			Verb:           verb,
			Alias:          source.Alias,
			Bytes:          append([]byte{}, source.Bytes...),
			Hash:           source.Hash,
			Observation:    source.Observation,
		}
		for itemIndex, subject := range source.Observation.Subjects {
			capture.Items = append(capture.Items, bundle.CollectedItem{
				UID:       subject.UID,
				Namespace: subject.Namespace,
				Name:      subject.Name,
			})
			_ = itemIndex
		}
		acquisition.Operations = append(acquisition.Operations, operation)
		acquisition.Captures = append(acquisition.Captures, capture)
	}
	acquisition.Stats = bundle.CollectedBudgetStats{
		RequestsAttempted:   uint64(len(acquisition.Operations)),
		ResponsesFinished:   uint64(len(acquisition.Operations)),
		BytesRead:           uint64(len(sources)),
		PodOccurrences:      uint64(len(sources)),
		InitialUIDs:         uint64(len(sources)),
		RetainedSourceBytes: uint64(len(sources)),
		MaxConcurrency:      1,
		Elapsed:             time.Second,
	}
	acquisition.Plan.RequestedOps = acquisition.Stats.RequestsAttempted
	acquisition.GlobalWarnings = []contract.Warning{}
	if termination != contract.TerminationFinished {
		acquisition.GlobalWarnings = append(acquisition.GlobalWarnings, contract.Warning{
			Code:    "tool_failure",
			Class:   contract.WarningContradictory,
			Message: "collector acquisition did not complete",
		})
	}
	return acquisition
}

// a202Input is the build input of one subject of one capture.
func a202Input(acquisition bundle.CollectedAcquisition, captureOrdinal uint64, subjectIndex int) bundle.CollectedObservationInput {
	capture := acquisition.Captures[captureOrdinal-1]
	return bundle.CollectedObservationInput{
		Acquisition:    acquisition,
		CaptureOrdinal: captureOrdinal,
		SubjectIndex:   subjectIndex,
		Result:         capture.Observation,
	}
}

// a202AcquisitionFor builds an acquisition over one source with an explicit
// termination.
func a202AcquisitionFor(t *testing.T, source a202Source, termination contract.CoverageTermination) bundle.CollectedAcquisition {
	t.Helper()
	errors := []string{}
	if termination == contract.TerminationAborted {
		errors = []string{"collector: forbidden"}
	}
	return a202Acquisition(t, []a202Source{source}, termination, errors)
}

// a202CollisionDocument builds one Pod whose container name appears in two
// classes: the admitted grammar records the collision and omits both.
func a202CollisionDocument(uid, name string) string {
	return `{"apiVersion":"v1","kind":"Pod","metadata":{"uid":"` + uid + `","namespace":"` + a202Namespace + `","name":"` + name + `"},` +
		`"spec":{"containers":[{"name":"api","image":"` + a202Image + `"}],"initContainers":[{"name":"api","image":"registry.example/init:release"}],"ephemeralContainers":[]},` +
		`"status":{"containerStatuses":[{"name":"api","imageID":"` + a202ImageID + `"}],"initContainerStatuses":[{"name":"api","imageID":"sha256:bbbb"}],"ephemeralContainerStatuses":[]}}`
}

// a202IncompleteDocumentRaw is the raw API response of one Pod with spec and
// status explicitly empty: a subject with no observed category.
func a202IncompleteDocumentRaw() string {
	return a202Document(`{"apiVersion":"v1","kind":"Pod","metadata":{"uid":"u1","namespace":"` + a202Namespace + `","name":"n1"},"spec":{},"status":{}}`)
}

// a202RejectedPeerDocument builds one Pod whose status names a container that
// its spec does not declare: the sanitized grammar rejects that item and the
// rejection is visible while the rest of the source is admitted.
func a202RejectedPeerDocument() string {
	return `{"apiVersion":"v1","kind":"Pod","metadata":{"uid":"u9","namespace":"` + a202Namespace + `","name":"n9"},` +
		`"spec":{"containers":[{"name":"api","image":"` + a202Image + `"}]},` +
		`"status":{"containerStatuses":[{"name":"ghost","imageID":"` + a202ImageID + `"}]}}`
}

// a202IncompleteDocument builds one Pod whose status categories are absent.
func a202IncompleteDocument(uid, name string) string {
	return `{"apiVersion":"v1","kind":"Pod","metadata":{"uid":"` + uid + `","namespace":"` + a202Namespace + `","name":"` + name + `"},` +
		`"spec":{"containers":[{"name":"api","image":"` + a202Image + `"}]}}`
}

// a202UIDOnlyDocument builds one Pod with identity but neither spec nor status.
func a202UIDOnlyDocument(uid, name string) string {
	return `{"apiVersion":"v1","kind":"Pod","metadata":{"uid":"` + uid + `","namespace":"` + a202Namespace + `","name":"` + name + `"}}`
}

// a202IdentityOnlyDocument builds one Pod whose spec and status are present but
// empty: the subject is admitted without any observed category or image, the
// exact shape that carries identity and no verifiable progress.
func a202IdentityOnlyDocument(uid, name string) string {
	return `{"apiVersion":"v1","kind":"Pod","metadata":{"uid":"` + uid + `","namespace":"` + a202Namespace + `","name":"` + name + `"},"spec":{},"status":{}}`
}

// a202HasWarning reports whether one exact warning is present.
func a202HasWarning(warnings []contract.Warning, code, class, message string) bool {
	for _, warning := range warnings {
		if warning.Code == code && warning.Class == contract.WarningClass(class) && warning.Message == message {
			return true
		}
	}
	return false
}

// a202HasError reports whether one exact error text is present.
func a202HasError(errors []string, message string) bool {
	for _, failure := range errors {
		if failure == message {
			return true
		}
	}
	return false
}
