package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/d4rpell/Ariadne/internal/identity"
)

// Decoder-level tests of the `--bindings` document (ADR-0036 §3). Every
// rejection is the exact CLI diagnostic: the decoder has no error surface of
// its own, so the tests go through the pipeline and assert the ratified
// stage/code/exit of each malformed document.

func decodeBindingsForTest(t *testing.T, document string) (bindingsDocument, error) {
	t.Helper()
	return decodeBindings([]byte(document))
}

func TestImportBindingsDecodeValid(t *testing.T) {
	document, err := decodeBindingsForTest(t, validBindingsFixture)
	if err != nil {
		t.Fatalf("valid document rejected: %v", err)
	}
	if document.subject.UID != "pod-uid-1" {
		t.Fatalf("subject uid = %q", document.subject.UID)
	}
	if len(document.containers) != 1 || len(document.links) != 1 {
		t.Fatalf("containers/links = %d/%d, want 1/1", len(document.containers), len(document.links))
	}
	container := document.containers[0]
	if container.image.InputKind != identity.InputContainerObservation {
		t.Fatalf("InputKind = %q, want container_observation", container.image.InputKind)
	}
	if container.image.ObservedAt == nil {
		t.Fatalf("observed_at = nil, want the declared instant")
	}
}

func TestImportBindingsRejectsDuplicateKeys(t *testing.T) {
	duplicate := strings.Replace(validBindingsFixture, `"version": "1.0",`, `"version": "1.0", "format": "case-import-bindings-v1",`, 1)
	document, err := decodeBindingsForTest(t, duplicate)
	if err == nil {
		t.Fatalf("duplicate top-level member accepted: %+v", document)
	}
}

func TestImportBindingsRejectsBOM(t *testing.T) {
	document, err := decodeBindingsForTest(t, "\ufeff"+validBindingsFixture)
	if err == nil {
		t.Fatalf("BOM document accepted: %+v", document)
	}
}

func TestImportBindingsRejectsNonCanonicalNumbers(t *testing.T) {
	for _, index := range []string{"01", "1.0", "+1", `"1"`} {
		document := strings.Replace(validBindingsFixture, `"finding_index": 0`, `"finding_index": `+index, 1)
		if _, err := decodeBindingsForTest(t, document); err == nil {
			t.Fatalf("finding_index %s accepted", index)
		}
	}
	// Index zero is a real row: it must stay admitted.
	document := strings.Replace(validBindingsFixture, `"finding_index": 0`, `"finding_index": 0`, 1)
	if _, err := decodeBindingsForTest(t, document); err != nil {
		t.Fatalf("finding_index 0 rejected: %v", err)
	}
}

func TestImportBindingsRejectsDuplicateJSONKeys(t *testing.T) {
	nested := strings.Replace(validBindingsFixture,
		`"container_name": "api", "container_class": "regular",`,
		`"container_name": "api", "container_name": "api", "container_class": "regular",`, 1)
	if _, err := decodeBindingsForTest(t, nested); err == nil {
		t.Fatalf("duplicate member inside a container accepted")
	}
}

func TestImportBindingsLimitsBytes(t *testing.T) {
	long := strings.Repeat("a", maxImportStringBytes+1)
	document := strings.Replace(validBindingsFixture, `"locator": "items[0].status.containerStatuses[0].imageID"`, `"locator": "`+long+`"`, 1)
	if _, err := decodeBindingsForTest(t, document); err == nil {
		t.Fatalf("string above the byte bound accepted")
	}
}

func TestImportBindingsLimitsDepth(t *testing.T) {
	dir := t.TempDir()
	deep := strings.Repeat(`{"k":`, maxInputDepth+1) + `"v"` + strings.Repeat("}", maxInputDepth+1)
	path := filepath.Join(dir, "deep.json")
	if err := os.WriteFile(path, []byte(deep), 0o600); err != nil {
		t.Fatalf("write deep document: %v", err)
	}
	expectRejection(t, importArgs(t, dir, "testdata/import/fixture.csv", path), stageBindingsRead, codeInputLimit, 3)
}

func TestImportBindingsRequiresSubject(t *testing.T) {
	for old, new := range map[string]string{
		`"uid": "pod-uid-1"`:           `"uid": ""`,
		`"cluster_alias": "cluster-a"`: `"cluster_alias": ""`,
		`"kind": "Pod"`:                `"kind": ""`,
	} {
		document := strings.Replace(validBindingsFixture, old, new, 1)
		if _, err := decodeBindingsForTest(t, document); err == nil {
			t.Fatalf("subject without %s accepted", old)
		}
	}
}

func TestImportBindingsRejectsDuplicateContainerKeys(t *testing.T) {
	// Two declarations for the same uid + class + name carry conflicting
	// observations: the decoder refuses the document instead of letting the
	// map overwrite one with the other (ADR-0010).
	head := validBindingsFixture[:strings.Index(validBindingsFixture, `"containers": [`)]
	document := head + `"containers": [
    {
      "container_name": "api", "container_class": "regular",
      "observed_at": "2026-10-07T09:00:00Z",
      "platform": {"status": "unknown"},
      "source_name": "sanitized-pods.json",
      "source_hash": "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
      "locator": "items[0].status.containerStatuses[0].imageID"
    },
    {
      "container_name": "api", "container_class": "regular",
      "observed_at": "2026-10-07T10:00:00Z",
      "platform": {"status": "unknown"},
      "source_name": "other.json",
      "source_hash": "sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
      "locator": "items[1].status.containerStatuses[0].imageID"
    }
  ],
  "bindings": []
}`
	// The document is otherwise well formed: a control with distinct container
	// names must decode, proving the rejection is the duplicate key itself.
	control := strings.Replace(document,
		`"container_name": "api", "container_class": "regular",
      "observed_at": "2026-10-07T10:00:00Z"`,
		`"container_name": "sidecar", "container_class": "regular",
      "observed_at": "2026-10-07T10:00:00Z"`, 1)
	if _, err := decodeBindingsForTest(t, control); err != nil {
		t.Fatalf("control document with distinct keys rejected: %v", err)
	}
	if _, err := decodeBindingsForTest(t, document); err == nil {
		t.Fatalf("duplicate container key accepted (silent overwrite risk)")
	}
}

func TestImportBindingsRejectsWhitespaceUID(t *testing.T) {
	for _, uid := range []string{" pod-uid-1", "pod-uid-1 "} {
		document := strings.Replace(validBindingsFixture, `"uid": "pod-uid-1"`, `"uid": "`+uid+`"`, 1)
		if _, err := decodeBindingsForTest(t, document); err == nil {
			t.Fatalf("uid %q accepted", uid)
		}
	}
}

func TestImportBindingsOwnerChainAbsentIsNull(t *testing.T) {
	absent := strings.Replace(validBindingsFixture, `, "owner_chain": "deployments/payments-api"`, ``, 1)
	if _, err := decodeBindingsForTest(t, absent); err != nil {
		t.Fatalf("absent owner_chain rejected: %v", err)
	}
	dir := t.TempDir()
	bindingsPath := writeBindings(t, dir, absent)
	argv := importArgs(t, dir, "testdata/import/fixture.csv", bindingsPath)
	if exit, _, stderr := runCLI(t, argv); exit != 0 {
		t.Fatalf("import exit=%d stderr=%q", exit, stderr)
	}
	envelope := readTemp(t, filepath.Join(dir, "bundle-envelope.json"))
	var document struct {
		Subject struct {
			OwnerChain *string `json:"owner_chain"`
		} `json:"subject"`
	}
	if err := json.Unmarshal(envelope, &document); err != nil {
		t.Fatalf("envelope is not JSON: %v", err)
	}
	if document.Subject.OwnerChain != nil {
		t.Fatalf("owner_chain = %v, want canonical null", document.Subject.OwnerChain)
	}
}

func TestImportBindingsRequiresObservationProvenance(t *testing.T) {
	for old, new := range map[string]string{
		`"source_name": "sanitized-pods.json"`:                      `"source_name": ""`,
		`"locator": "items[0].status.containerStatuses[0].imageID"`: `"locator": ""`,
	} {
		document := strings.Replace(validBindingsFixture, old, new, 1)
		if _, err := decodeBindingsForTest(t, document); err == nil {
			t.Fatalf("observation without provenance accepted: removed %s", old)
		}
	}
	document := strings.Replace(validBindingsFixture, `"source_hash": "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"`, `"source_hash": "sha256:short"`, 1)
	if _, err := decodeBindingsForTest(t, document); err == nil {
		t.Fatalf("malformed source_hash accepted")
	}
}

func TestImportBindingsValidatesRequestedImage(t *testing.T) {
	for _, tag := range []string{"1x", "-x", "x y"} {
		document := strings.Replace(validBindingsFixture,
			`"observed_at": "2026-10-07T09:00:00Z",`,
			`"observed_at": "2026-10-07T09:00:00Z", "requested_image": {"registry": "registry.example", "repository": "payments/api", "tag": "`+tag+`"},`, 1)
		if _, err := decodeBindingsForTest(t, document); err == nil {
			t.Fatalf("requested_image with tag %q accepted", tag)
		}
	}
	valid := strings.Replace(validBindingsFixture,
		`"observed_at": "2026-10-07T09:00:00Z",`,
		`"observed_at": "2026-10-07T09:00:00Z", "requested_image": {"registry": "registry.example", "repository": "payments/api", "tag": "release"},`, 1)
	if _, err := decodeBindingsForTest(t, valid); err != nil {
		t.Fatalf("composable requested_image rejected: %v", err)
	}
}

func TestImportBindingsValidatesDigest(t *testing.T) {
	for _, digest := range []string{"sha256:short", "sha256:" + strings.Repeat("A", 64), "not-a-digest"} {
		document := strings.Replace(validBindingsFixture,
			`"locator": "items[0].status.containerStatuses[0].imageID"`,
			`"locator": "items[0].status.containerStatuses[0].imageID", "normalized_digest": "`+digest+`"`, 1)
		if _, err := decodeBindingsForTest(t, document); err == nil {
			t.Fatalf("digest %q accepted", digest)
		}
	}
	valid := strings.Replace(validBindingsFixture,
		`"locator": "items[0].status.containerStatuses[0].imageID"`,
		`"locator": "items[0].status.containerStatuses[0].imageID", "normalized_digest": "sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"`, 1)
	if _, err := decodeBindingsForTest(t, valid); err != nil {
		t.Fatalf("well-formed digest rejected: %v", err)
	}
}

func TestImportBindingsValidatesPlatform(t *testing.T) {
	base := `"platform": {"status": "unknown"}`
	incomplete := []string{
		`{"status": "known"}`,
		`{"status": "known", "os": "linux"}`,
	}
	for _, platform := range incomplete {
		document := strings.Replace(validBindingsFixture, base, `"platform": `+platform, 1)
		if _, err := decodeBindingsForTest(t, document); err == nil {
			t.Fatalf("incomplete known platform accepted: %s", platform)
		}
	}
	document := strings.Replace(validBindingsFixture, base, `"platform": {"status": "unknown", "os": "linux"}`, 1)
	if _, err := decodeBindingsForTest(t, document); err == nil {
		t.Fatalf("unknown platform with os accepted")
	}
	known := strings.Replace(validBindingsFixture, base, `"platform": {"status": "known", "os": "linux", "architecture": "amd64"}`, 1)
	if _, err := decodeBindingsForTest(t, known); err != nil {
		t.Fatalf("known platform rejected: %v", err)
	}
}

func TestImportBindingsRejectsUnknownInputKind(t *testing.T) {
	// InputKind is a constant of the pipeline, not a document member: an
	// operator cannot name it, and a synthetic kind is unreachable from the CLI.
	document := strings.Replace(validBindingsFixture, `"container_name": "api"`, `"input_kind": "synthetic", "container_name": "api"`, 1)
	if _, err := decodeBindingsForTest(t, document); err == nil {
		t.Fatalf("unknown member accepted beside the fixed InputKind")
	}
}

func TestImportBindingsRejectsUnknownFormatOrVersion(t *testing.T) {
	for old, new := range map[string]string{
		`"format": "case-import-bindings-v1"`: `"format": "case-import-bindings-v2"`,
		`"version": "1.0"`:                    `"version": "1.1"`,
	} {
		document := strings.Replace(validBindingsFixture, old, new, 1)
		if _, err := decodeBindingsForTest(t, document); err == nil {
			t.Fatalf("document accepted with %s", new)
		}
	}
}
