package ingest

import (
	"strings"
	"testing"

	contract "github.com/d4rpell/Ariadne/pkg/evidence"
)

// Document admission: resource, allowlist and pagination (ADR-0025 A.3.2,
// A.3.3, A.10.3 §6–§7). A field outside the allowlist is refused before its
// value is examined, and a foreign resource invalidates the whole document
// instead of being filtered.

func TestA201Resources(t *testing.T) {
	pod := a201CompletePod("uid-1", "api", "sha256:aaaa")

	t.Run("admitted resource", func(t *testing.T) {
		result := a201MustParse(t, a201List(pod))
		if result.Accepted != 1 || result.Rejected != 0 {
			t.Fatalf("accounting = %d/%d, want 1/0", result.Accepted, result.Rejected)
		}
	})

	t.Run("root apiVersion missing", func(t *testing.T) {
		document := `{"kind":"PodList","items":[]}`
		_, err := a201Parse(t, document)
		a201WantFailure(t, err, a201Literal(0, "required field is missing"))
	})
	t.Run("root kind missing", func(t *testing.T) {
		document := `{"apiVersion":"v1","items":[]}`
		_, err := a201Parse(t, document)
		a201WantFailure(t, err, a201Literal(0, "required field is missing"))
	})
	t.Run("root items missing", func(t *testing.T) {
		document := `{"apiVersion":"v1","kind":"PodList"}`
		_, err := a201Parse(t, document)
		a201WantFailure(t, err, a201Literal(0, "required field is missing"))
	})
	t.Run("root apiVersion with the wrong type", func(t *testing.T) {
		document := `{"apiVersion":1,"kind":"PodList","items":[]}`
		_, err := a201Parse(t, document)
		a201WantFailure(t, err, a201Literal(at(t, document, "1,"), "invalid field type"))
	})
	t.Run("root metadata with the wrong type", func(t *testing.T) {
		document := `{"apiVersion":"v1","kind":"PodList","metadata":[],"items":[]}`
		_, err := a201Parse(t, document)
		a201WantFailure(t, err, a201Literal(uint64(strings.Index(document, "[]")), "invalid field type"))
	})
	t.Run("alternative apiVersion", func(t *testing.T) {
		document := `{"apiVersion":"apps/v1","kind":"PodList","items":[]}`
		_, err := a201Parse(t, document)
		a201WantFailure(t, err, a201Literal(at(t, document, `"apps/v1"`), "unsupported resource kind or API version"))
	})
	t.Run("alternative kind", func(t *testing.T) {
		document := `{"apiVersion":"v1","kind":"List","items":[]}`
		_, err := a201Parse(t, document)
		a201WantFailure(t, err, a201Literal(at(t, document, `"List"`), "unsupported resource kind or API version"))
	})
	t.Run("bare Pod document without extra keys", func(t *testing.T) {
		document := `{"apiVersion":"v1","kind":"Pod","items":[]}`
		_, err := a201Parse(t, document)
		a201WantFailure(t, err, a201Literal(at(t, document, `"Pod"`), "unsupported resource kind or API version"))
	})
	t.Run("bare Pod document with a spec key", func(t *testing.T) {
		// The Pod spec key is not admitted at the root path, and the structural
		// allowlist is examined before the root object closes: the first
		// detectable failure is the prohibited key (ADR-0025 A.11).
		document := `{"apiVersion":"v1","kind":"Pod","metadata":{},"spec":{}}`
		_, err := a201Parse(t, document)
		a201WantFailure(t, err, a201Literal(at(t, document, `"spec"`), "field is not allowed by the redaction profile"))
	})
	t.Run("items is not an array", func(t *testing.T) {
		document := `{"apiVersion":"v1","kind":"PodList","items":"x"}`
		_, err := a201Parse(t, document)
		a201WantFailure(t, err, a201Literal(at(t, document, `"x"`), "invalid field type"))
	})
	t.Run("items is null", func(t *testing.T) {
		document := `{"apiVersion":"v1","kind":"PodList","items":null}`
		_, err := a201Parse(t, document)
		a201WantFailure(t, err, a201Literal(at(t, document, "null"), "invalid field type"))
	})
	t.Run("element is not an object", func(t *testing.T) {
		document := `{"apiVersion":"v1","kind":"PodList","items":["x"]}`
		_, err := a201Parse(t, document)
		a201WantFailure(t, err, a201Literal(at(t, document, `"x"`), "invalid field type"))
	})
	t.Run("element without apiVersion", func(t *testing.T) {
		document := `{"apiVersion":"v1","kind":"PodList","items":[{"kind":"Pod"}]}`
		_, err := a201Parse(t, document)
		a201WantFailure(t, err, a201Literal(at(t, document, `{"kind":"Pod"}`), "required field is missing"))
	})
	t.Run("mixed list", func(t *testing.T) {
		document := a201List(pod, `{"apiVersion":"apps/v1","kind":"Deployment","metadata":{"uid":"uid-2"}}`)
		_, err := a201Parse(t, document)
		a201WantFailure(t, err, a201Literal(at(t, document, `"apps/v1"`), "unsupported resource kind or API version"))
	})
	t.Run("element of the wrong kind", func(t *testing.T) {
		document := a201List(`{"apiVersion":"v1","kind":"Node"}`)
		_, err := a201Parse(t, document)
		a201WantFailure(t, err, a201Literal(at(t, document, `"Node"`), "unsupported resource kind or API version"))
	})
	t.Run("empty list is admitted with a zero accounting", func(t *testing.T) {
		result := a201MustParse(t, a201List())
		if result.TotalItems == nil || *result.TotalItems != 0 {
			t.Fatalf("total items = %v, want a known zero", result.TotalItems)
		}
		if result.Accepted != 0 || result.Rejected != 0 {
			t.Fatalf("accounting = %d/%d, want 0/0", result.Accepted, result.Rejected)
		}
		if len(result.Subjects) != 0 {
			t.Fatal("an empty list invented a subject")
		}
	})
}

func TestA201Allowlist(t *testing.T) {
	t.Run("every admitted key in its own path", func(t *testing.T) {
		document := `{"apiVersion":"v1","kind":"PodList","metadata":{"resourceVersion":"42","continue":"","remainingItemCount":0},"items":[{` +
			`"apiVersion":"v1","kind":"Pod","metadata":{"uid":"uid-1","namespace":"payments","name":"api","resourceVersion":"7",` +
			`"ownerReferences":[{"apiVersion":"apps/v1","kind":"ReplicaSet","name":"rs","uid":"uid-rs","controller":true,"blockOwnerDeletion":false}]},` +
			`"spec":{"containers":[{"name":"api","image":"registry.example/app:release"}],"initContainers":[],"ephemeralContainers":[]},` +
			`"status":{"containerStatuses":[{"name":"api","imageID":"sha256:aaaa","image":"registry.example/app@sha256:bbbb","ready":false,` +
			`"state":{"running":{}},"restartCount":0}],"initContainerStatuses":[],"ephemeralContainerStatuses":[]}}]}`
		result, err := a201Parse(t, document)
		if err != nil {
			t.Fatalf("the complete admitted shape was refused: %v", err)
		}
		if result.Accepted != 1 {
			t.Fatalf("accepted = %d, want 1", result.Accepted)
		}
		subject := result.Subjects[0]
		if subject.ResourceVersion.Value != "7" || subject.ResourceVersion.Present != PresenceValue {
			t.Fatalf("resourceVersion = %+v, want the declared value", subject.ResourceVersion)
		}
		if len(subject.OwnerReferences) != 1 || subject.OwnerReferences[0].Kind != "ReplicaSet" {
			t.Fatalf("owner references = %+v, want the declared reference", subject.OwnerReferences)
		}
		status := subject.StatusContainers[contract.ContainerRegular]
		if len(status) != 1 || status[0].State.Category != "running" {
			t.Fatalf("status = %+v, want the running category", status)
		}
		if status[0].Ready.Present != PresenceValue || status[0].Ready.Value {
			t.Fatalf("ready = %+v, want an explicit false", status[0].Ready)
		}
	})

	wrongPath := []struct {
		name     string
		key      string
		document string
	}{
		{name: "uid at the root", key: `"uid"`, document: `{"apiVersion":"v1","kind":"PodList","uid":"x","items":[]}`},
		{name: "image in Pod metadata", key: `"image"`, document: a201List(`{"apiVersion":"v1","kind":"Pod","metadata":{"uid":"u","namespace":"payments","name":"n","image":"x"},"spec":{}}`)},
		{name: "ready in a spec container", key: `"ready"`, document: a201List(`{"apiVersion":"v1","kind":"Pod","metadata":{"uid":"u","namespace":"payments","name":"n"},"spec":{"containers":[{"name":"api","ready":true}]}}`)},
		{name: "imageID in a spec container", key: `"imageID"`, document: a201List(`{"apiVersion":"v1","kind":"Pod","metadata":{"uid":"u","namespace":"payments","name":"n"},"spec":{"containers":[{"name":"api","imageID":"x"}]}}`)},
		{name: "restartCount in spec", key: `"restartCount"`, document: a201List(`{"apiVersion":"v1","kind":"Pod","metadata":{"uid":"u","namespace":"payments","name":"n"},"spec":{"restartCount":1}}`)},
		{name: "status keys in spec", key: `"containerStatuses"`, document: a201List(`{"apiVersion":"v1","kind":"Pod","metadata":{"uid":"u","namespace":"payments","name":"n"},"spec":{"containerStatuses":[]}}`)},
		{name: "spec keys in status", key: `"containers"`, document: a201List(`{"apiVersion":"v1","kind":"Pod","metadata":{"uid":"u","namespace":"payments","name":"n"},"spec":{},"status":{"containers":[]}}`)},
		{name: "ownerReferences in PodList metadata", key: `"ownerReferences"`, document: `{"apiVersion":"v1","kind":"PodList","metadata":{"ownerReferences":[]},"items":[]}`},
		{name: "labels", key: `"labels"`, document: a201List(`{"apiVersion":"v1","kind":"Pod","metadata":{"uid":"u","namespace":"payments","name":"n","labels":{"a":"b"}},"spec":{}}`)},
		{name: "annotations", key: `"annotations"`, document: a201List(`{"apiVersion":"v1","kind":"Pod","metadata":{"uid":"u","namespace":"payments","name":"n","annotations":{"a":"b"}},"spec":{}}`)},
		{name: "managedFields", key: `"managedFields"`, document: a201List(`{"apiVersion":"v1","kind":"Pod","metadata":{"uid":"u","namespace":"payments","name":"n","managedFields":[]},"spec":{}}`)},
		{name: "env", key: `"env"`, document: a201List(`{"apiVersion":"v1","kind":"Pod","metadata":{"uid":"u","namespace":"payments","name":"n"},"spec":{"containers":[{"name":"api","env":[{"name":"A","value":"B"}]}]}}`)},
		{name: "args", key: `"args"`, document: a201List(`{"apiVersion":"v1","kind":"Pod","metadata":{"uid":"u","namespace":"payments","name":"n"},"spec":{"containers":[{"name":"api","args":["a"]}]}}`)},
		{name: "volumes", key: `"volumes"`, document: a201List(`{"apiVersion":"v1","kind":"Pod","metadata":{"uid":"u","namespace":"payments","name":"n"},"spec":{"containers":[],"volumes":[]}}`)},
		{name: "serviceAccountName", key: `"serviceAccountName"`, document: a201List(`{"apiVersion":"v1","kind":"Pod","metadata":{"uid":"u","namespace":"payments","name":"n"},"spec":{"serviceAccountName":"default"}}`)},
		{name: "nodeName", key: `"nodeName"`, document: a201List(`{"apiVersion":"v1","kind":"Pod","metadata":{"uid":"u","namespace":"payments","name":"n"},"spec":{"nodeName":"node-1"}}`)},
		{name: "lastState", key: `"lastState"`, document: a201List(`{"apiVersion":"v1","kind":"Pod","metadata":{"uid":"u","namespace":"payments","name":"n"},"spec":{},"status":{"containerStatuses":[{"name":"api","lastState":{}}]}}`)},
		{name: "message in a state variant", key: `"message"`, document: a201List(`{"apiVersion":"v1","kind":"Pod","metadata":{"uid":"u","namespace":"payments","name":"n"},"spec":{"containers":[{"name":"api"}]},"status":{"containerStatuses":[{"name":"api","state":{"waiting":{"message":"m"}}}]}}`)},
		{name: "containerID in a status", key: `"containerID"`, document: a201List(`{"apiVersion":"v1","kind":"Pod","metadata":{"uid":"u","namespace":"payments","name":"n"},"spec":{"containers":[{"name":"api"}]},"status":{"containerStatuses":[{"name":"api","containerID":"docker://x"}]}}`)},
	}
	for _, testCase := range wrongPath {
		t.Run(testCase.name, func(t *testing.T) {
			_, err := a201Parse(t, testCase.document)
			a201WantFailure(t, err, a201Literal(at(t, testCase.document, testCase.key), "field is not allowed by the redaction profile"))
		})
	}

	t.Run("a prohibited field before a valid Pod", func(t *testing.T) {
		document := `{"apiVersion":"v1","kind":"PodList","env":{"A":"B"},"items":[` + a201CompletePod("uid-1", "api", "sha256:a") + `]}`
		result, err := a201Parse(t, document)
		a201WantFailure(t, err, a201Literal(at(t, document, `"env"`), "field is not allowed by the redaction profile"))
		a201NoPublication(t, result)
	})
	t.Run("a prohibited field after a valid Pod", func(t *testing.T) {
		document := `{"apiVersion":"v1","kind":"PodList","items":[` + a201CompletePod("uid-1", "api", "sha256:a") + `],"env":{"A":"B"}}`
		result, err := a201Parse(t, document)
		a201WantFailure(t, err, a201Literal(at(t, document, `"env"`), "field is not allowed by the redaction profile"))
		a201NoPublication(t, result)
	})
	t.Run("a prohibited field inside a Pod after a valid one", func(t *testing.T) {
		document := a201List(a201CompletePod("uid-1", "api", "sha256:a"),
			`{"apiVersion":"v1","kind":"Pod","metadata":{"uid":"uid-2","namespace":"payments","name":"b"},"spec":{"containers":[{"name":"api","imagePullSecrets":[]}]}}`)
		_, err := a201Parse(t, document)
		a201WantFailure(t, err, a201Literal(at(t, document, `"imagePullSecrets"`), "field is not allowed by the redaction profile"))
	})
	t.Run("the value of a prohibited key is never examined", func(t *testing.T) {
		document := `{"apiVersion":"v1","kind":"PodList","env": "\q","items":[]}`
		_, err := a201Parse(t, document)
		a201WantFailure(t, err, a201Literal(at(t, document, `"env"`), "field is not allowed by the redaction profile"))
	})
}

func TestA201Pagination(t *testing.T) {
	root := func(metadata string) string {
		return `{"apiVersion":"v1","kind":"PodList","metadata":{` + metadata + `},"items":[]}`
	}
	t.Run("no pagination fields", func(t *testing.T) {
		if _, err := a201Parse(t, root("")); err != nil {
			t.Fatalf("an export without pagination fields was refused: %v", err)
		}
	})
	t.Run("empty continue", func(t *testing.T) {
		if _, err := a201Parse(t, root(`"continue":""`)); err != nil {
			t.Fatalf("an empty continue was refused: %v", err)
		}
	})
	t.Run("non-empty continue", func(t *testing.T) {
		document := root(`"continue":"token"`)
		_, err := a201Parse(t, document)
		a201WantFailure(t, err, a201Literal(at(t, document, `"token"`), "paginated export is not supported"))
	})
	t.Run("continue with the wrong type", func(t *testing.T) {
		document := root(`"continue":null`)
		_, err := a201Parse(t, document)
		a201WantFailure(t, err, a201Literal(at(t, document, "null"), "invalid field type"))
	})
	t.Run("zero remainder", func(t *testing.T) {
		if _, err := a201Parse(t, root(`"remainingItemCount":0`)); err != nil {
			t.Fatalf("a zero remainder was refused: %v", err)
		}
	})
	t.Run("positive remainder", func(t *testing.T) {
		document := root(`"remainingItemCount":3`)
		_, err := a201Parse(t, document)
		a201WantFailure(t, err, a201Literal(at(t, document, "3"), "paginated export is not supported"))
	})
	t.Run("remainder with the wrong type", func(t *testing.T) {
		document := root(`"remainingItemCount":null`)
		_, err := a201Parse(t, document)
		a201WantFailure(t, err, a201Literal(at(t, document, "null"), "invalid field type"))
	})
	t.Run("resourceVersion type", func(t *testing.T) {
		document := root(`"resourceVersion":1`)
		_, err := a201Parse(t, document)
		a201WantFailure(t, err, a201Literal(at(t, document, "1}"), "invalid field type"))
	})
	t.Run("pagination is refused before the items are examined", func(t *testing.T) {
		// The metadata closes before items are walked, so the pagination failure
		// is the first detectable one.
		document := `{"apiVersion":"v1","kind":"PodList","metadata":{"continue":"token"},"items":[{"env":1}]}`
		_, err := a201Parse(t, document)
		a201WantFailure(t, err, a201Literal(at(t, document, `"token"`), "paginated export is not supported"))
	})
}
