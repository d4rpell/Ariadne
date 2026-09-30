package ingest

import (
	"strings"
	"testing"

	contract "github.com/d4rpell/Ariadne/pkg/evidence"
)

// Per-Pod semantics (ADR-0025 A.7.2, A.7.3, A.8.1, A.10.3 §8): identity,
// rejections with a single primary reason, the status join by name inside its
// class, and the accumulated context that never becomes evidence.

// a201RejectionOf returns the single rejection of an admitted source.
func a201RejectionOf(t *testing.T, result PodListResult) PodListRejection {
	t.Helper()
	if len(result.Rejections) != 1 {
		t.Fatalf("rejections = %d, want exactly 1", len(result.Rejections))
	}
	return result.Rejections[0]
}

func TestA201PodIdentity(t *testing.T) {
	t.Run("uid missing", func(t *testing.T) {
		document := a201List(`{"apiVersion":"v1","kind":"Pod","metadata":{"namespace":"payments","name":"n"},"spec":{}}`)
		result := a201MustParse(t, document)
		rejection := a201RejectionOf(t, result)
		if rejection.Code != PodListCodeMissingRequiredField {
			t.Fatalf("code = %s, want missing_required_field", rejection.Code)
		}
		if rejection.Offset != uint64(strings.Index(document, `"metadata":{`)+len(`"metadata":`)) {
			t.Fatalf("offset = %d, want the metadata object anchor", rejection.Offset)
		}
	})
	t.Run("uid empty", func(t *testing.T) {
		document := a201List(`{"apiVersion":"v1","kind":"Pod","metadata":{"uid":"","namespace":"payments","name":"n"},"spec":{}}`)
		result := a201MustParse(t, document)
		if a201RejectionOf(t, result).Code != PodListCodeInvalidIdentifier {
			t.Fatalf("code = %s, want invalid_identifier", result.Rejections[0].Code)
		}
	})
	t.Run("uid with surrounding whitespace", func(t *testing.T) {
		document := a201List(`{"apiVersion":"v1","kind":"Pod","metadata":{"uid":" uid-1 ","namespace":"payments","name":"n"},"spec":{}}`)
		result := a201MustParse(t, document)
		if a201RejectionOf(t, result).Code != PodListCodeInvalidIdentifier {
			t.Fatalf("code = %s, want invalid_identifier", result.Rejections[0].Code)
		}
	})
	t.Run("uid at the identifier budget", func(t *testing.T) {
		document := a201List(`{"apiVersion":"v1","kind":"Pod","metadata":{"uid":"` + strings.Repeat("u", 1024) + `","namespace":"payments","name":"n"},"spec":{}}`)
		if _, err := a201Parse(t, document); err != nil {
			t.Fatalf("an identifier at the budget was refused: %v", err)
		}
	})
	t.Run("uid above the identifier budget", func(t *testing.T) {
		uid := strings.Repeat("u", 1025)
		document := a201List(`{"apiVersion":"v1","kind":"Pod","metadata":{"uid":"` + uid + `","namespace":"payments","name":"n"},"spec":{}}`)
		result := a201MustParse(t, document)
		rejection := a201RejectionOf(t, result)
		if rejection.Code != PodListCodeIdentifierLimit {
			t.Fatalf("code = %s, want identifier_limit", rejection.Code)
		}
		if rejection.Offset != at(t, document, `"`+uid+`"`) {
			t.Fatalf("offset = %d, want the opening quote of the identifier", rejection.Offset)
		}
	})
	t.Run("uid above the budget with surrounding whitespace", func(t *testing.T) {
		uid := " " + strings.Repeat("u", 1025) + " "
		document := a201List(`{"apiVersion":"v1","kind":"Pod","metadata":{"uid":"` + uid + `","namespace":"payments","name":"n"},"spec":{}}`)
		result := a201MustParse(t, document)
		if a201RejectionOf(t, result).Code != PodListCodeIdentifierLimit {
			t.Fatalf("code = %s, want identifier_limit, not invalid_identifier", result.Rejections[0].Code)
		}
	})
	t.Run("namespace outside the declared scope", func(t *testing.T) {
		document := a201List(`{"apiVersion":"v1","kind":"Pod","metadata":{"uid":"uid-1","namespace":"other","name":"n"},"spec":{}}`)
		result := a201MustParse(t, document)
		rejection := a201RejectionOf(t, result)
		if rejection.Code != PodListCodeNamespaceMismatch {
			t.Fatalf("code = %s, want namespace_mismatch", rejection.Code)
		}
		if rejection.Offset != at(t, document, `"other"`) {
			t.Fatalf("offset = %d, want the namespace value", rejection.Offset)
		}
	})
	t.Run("name missing", func(t *testing.T) {
		document := a201List(`{"apiVersion":"v1","kind":"Pod","metadata":{"uid":"uid-1","namespace":"payments"},"spec":{}}`)
		result := a201MustParse(t, document)
		if a201RejectionOf(t, result).Code != PodListCodeMissingRequiredField {
			t.Fatalf("code = %s, want missing_required_field", result.Rejections[0].Code)
		}
	})
	t.Run("metadata missing", func(t *testing.T) {
		document := a201List(`{"apiVersion":"v1","kind":"Pod","spec":{}}`)
		result := a201MustParse(t, document)
		rejection := a201RejectionOf(t, result)
		if rejection.Code != PodListCodeMissingRequiredField {
			t.Fatalf("code = %s, want missing_required_field", rejection.Code)
		}
		if rejection.Offset != at(t, document, `{"apiVersion":"v1","kind":"Pod",`) {
			t.Fatalf("offset = %d, want the Pod object anchor", rejection.Offset)
		}
	})
	t.Run("spec missing", func(t *testing.T) {
		document := a201List(`{"apiVersion":"v1","kind":"Pod","metadata":{"uid":"uid-1","namespace":"payments","name":"n"}}`)
		result := a201MustParse(t, document)
		if a201RejectionOf(t, result).Code != PodListCodeMissingRequiredField {
			t.Fatalf("code = %s, want missing_required_field", result.Rejections[0].Code)
		}
	})
	t.Run("spec with the wrong type", func(t *testing.T) {
		document := a201List(`{"apiVersion":"v1","kind":"Pod","metadata":{"uid":"uid-1","namespace":"payments","name":"n"},"spec":[]}`)
		result := a201MustParse(t, document)
		rejection := a201RejectionOf(t, result)
		if rejection.Code != PodListCodeInvalidFieldType {
			t.Fatalf("code = %s, want invalid_field_type", rejection.Code)
		}
		if rejection.Offset != at(t, document, "[]") {
			t.Fatalf("offset = %d, want the wrong-typed value", rejection.Offset)
		}
	})

	t.Run("identical repeated uid invalidates every occurrence", func(t *testing.T) {
		pod := func(item string) string {
			return `{"apiVersion":"v1","kind":"Pod","metadata":{"uid":"uid-1","namespace":"payments","name":"` + item + `"},"spec":{}}`
		}
		document := a201List(pod("a"), pod("b"))
		result := a201MustParse(t, document)
		if result.Accepted != 0 || result.Rejected != 2 || *result.TotalItems != 2 {
			t.Fatalf("accounting = %d/%d of %d, want 0/2 of 2", result.Accepted, result.Rejected, *result.TotalItems)
		}
		first := uint64(strings.Index(document, `"uid-1"`))
		second := uint64(strings.LastIndex(document, `"uid-1"`))
		if result.Rejections[0].Code != PodListCodeDuplicateUID || result.Rejections[0].Offset != first {
			t.Fatalf("first rejection = %s at %d, want duplicate_uid at the first uid", result.Rejections[0].Code, result.Rejections[0].Offset)
		}
		if result.Rejections[1].Code != PodListCodeDuplicateUID || result.Rejections[1].Offset != second {
			t.Fatalf("second rejection = %s at %d, want duplicate_uid at the second uid", result.Rejections[1].Code, result.Rejections[1].Offset)
		}
	})
	t.Run("a repeated uid overrides another primary reason", func(t *testing.T) {
		document := a201List(
			`{"apiVersion":"v1","kind":"Pod","metadata":{"uid":"uid-1","namespace":"payments","name":"a"},"spec":{}}`,
			// The second occurrence is also outside the declared namespace.
			`{"apiVersion":"v1","kind":"Pod","metadata":{"uid":"uid-1","namespace":"other","name":"b"},"spec":{}}`,
		)
		result := a201MustParse(t, document)
		if len(result.Rejections) != 2 {
			t.Fatalf("rejections = %d, want 2", len(result.Rejections))
		}
		for _, rejection := range result.Rejections {
			if rejection.Code != PodListCodeDuplicateUID {
				t.Fatalf("rejection code = %s, want duplicate_uid to replace the primary reason", rejection.Code)
			}
		}
	})
	t.Run("an unusable uid never takes part in the duplicate pass", func(t *testing.T) {
		// Two empty uids are identity failures, not a duplicate pair.
		document := a201List(
			`{"apiVersion":"v1","kind":"Pod","metadata":{"uid":"","namespace":"payments","name":"a"},"spec":{}}`,
			`{"apiVersion":"v1","kind":"Pod","metadata":{"uid":"","namespace":"payments","name":"b"},"spec":{}}`,
		)
		result := a201MustParse(t, document)
		for _, rejection := range result.Rejections {
			if rejection.Code == PodListCodeDuplicateUID {
				t.Fatal("an empty uid was treated as a usable identity")
			}
		}
	})

	t.Run("same name with different uids stays separate", func(t *testing.T) {
		document := a201List(
			a201CompletePod("uid-a", "api", "sha256:a"),
			a201CompletePod("uid-b", "api", "sha256:b"),
		)
		result := a201MustParse(t, document)
		if len(result.Subjects) != 2 || result.Accepted != 2 {
			t.Fatalf("subjects = %d, accepted = %d, want 2 and 2", len(result.Subjects), result.Accepted)
		}
		if result.Subjects[0].UID == result.Subjects[1].UID {
			t.Fatal("two different uids were merged")
		}
		for index, subject := range result.Subjects {
			conflict := false
			for _, diagnostic := range subject.Diagnostics {
				if diagnostic.Code == PodListCodeSubjectContextConflict {
					conflict = true
					// The conflict anchors at each affected Pod's own name value.
					needle := `"payments","name":`
					expected := uint64(strings.Index(document, needle) + len(needle))
					if index == 1 {
						expected = uint64(strings.LastIndex(document, needle) + len(needle))
					}
					if diagnostic.ByteOffset != expected {
						t.Fatalf("conflict anchor = %d, want the name of the affected Pod %d", diagnostic.ByteOffset, index)
					}
				}
			}
			if !conflict {
				t.Fatalf("subject %d carries no visible conflict", index)
			}
		}
	})
	t.Run("a container change stays a different subject", func(t *testing.T) {
		document := a201List(
			a201CompletePod("uid-a", "api", "sha256:a"),
			a201CompletePod("uid-b", "api", "sha256:b"),
		)
		result := a201MustParse(t, document)
		if result.Subjects[0].UID == result.Subjects[1].UID {
			t.Fatal("subjects were merged by name")
		}
	})

	t.Run("duplicate container inside a category", func(t *testing.T) {
		document := a201List(`{"apiVersion":"v1","kind":"Pod","metadata":{"uid":"u","namespace":"payments","name":"n"},` +
			`"spec":{"containers":[{"name":"api"},{"name":"api"}]}}`)
		result := a201MustParse(t, document)
		rejection := a201RejectionOf(t, result)
		if rejection.Code != PodListCodeDuplicateContainer {
			t.Fatalf("code = %s, want duplicate_container", rejection.Code)
		}
		repeated := strings.LastIndex(document, `"name":`) + len(`"name":`)
		if rejection.Offset != uint64(repeated) {
			t.Fatalf("offset = %d, want the value of the repeated name", rejection.Offset)
		}
	})
	t.Run("duplicate status inside its array", func(t *testing.T) {
		document := a201List(`{"apiVersion":"v1","kind":"Pod","metadata":{"uid":"u","namespace":"payments","name":"n"},` +
			`"spec":{"containers":[{"name":"api"}]},` +
			`"status":{"containerStatuses":[{"name":"api"},{"name":"api"}]}}`)
		result := a201MustParse(t, document)
		if a201RejectionOf(t, result).Code != PodListCodeDuplicateStatus {
			t.Fatalf("code = %s, want duplicate_status", result.Rejections[0].Code)
		}
	})
	t.Run("orphan status", func(t *testing.T) {
		document := a201List(`{"apiVersion":"v1","kind":"Pod","metadata":{"uid":"u","namespace":"payments","name":"n"},` +
			`"spec":{"containers":[{"name":"api"}]},` +
			`"status":{"containerStatuses":[{"name":"sidecar"}]}}`)
		result := a201MustParse(t, document)
		rejection := a201RejectionOf(t, result)
		if rejection.Code != PodListCodeOrphanStatus {
			t.Fatalf("code = %s, want orphan_status", rejection.Code)
		}
		if rejection.Offset != at(t, document, `"sidecar"`) {
			t.Fatalf("offset = %d, want the orphan name", rejection.Offset)
		}
	})
	t.Run("status name that only exists in another class", func(t *testing.T) {
		document := a201List(`{"apiVersion":"v1","kind":"Pod","metadata":{"uid":"u","namespace":"payments","name":"n"},` +
			`"spec":{"containers":[{"name":"api"}],"initContainers":[{"name":"setup"}]},` +
			`"status":{"containerStatuses":[{"name":"setup"}]}}`)
		result := a201MustParse(t, document)
		if a201RejectionOf(t, result).Code != PodListCodeOrphanStatus {
			t.Fatalf("code = %s, want orphan_status for a name of another class", result.Rejections[0].Code)
		}
	})
	t.Run("status without its declaration", func(t *testing.T) {
		document := a201List(`{"apiVersion":"v1","kind":"Pod","metadata":{"uid":"u","namespace":"payments","name":"n"},` +
			`"spec":{},` +
			`"status":{"containerStatuses":[{"name":"api"}]}}`)
		result := a201MustParse(t, document)
		if a201RejectionOf(t, result).Code != PodListCodeOrphanStatus {
			t.Fatalf("code = %s, want orphan_status when the category was never declared", result.Rejections[0].Code)
		}
	})

	t.Run("permuted statuses join by name", func(t *testing.T) {
		document := a201List(`{"apiVersion":"v1","kind":"Pod","metadata":{"uid":"u","namespace":"payments","name":"n"},` +
			`"spec":{"containers":[{"name":"api"},{"name":"worker"}]},` +
			`"status":{"containerStatuses":[{"name":"worker","imageID":"sha256:w"},{"name":"api","imageID":"sha256:a"}]}}`)
		result := a201MustParse(t, document)
		if result.Accepted != 1 {
			t.Fatalf("accepted = %d, want 1", result.Accepted)
		}
		statuses := result.Subjects[0].StatusContainers[contract.ContainerRegular]
		if len(statuses) != 2 {
			t.Fatalf("statuses = %d, want 2 in their source order", len(statuses))
		}
		if statuses[0].Name != "worker" || statuses[0].ImageID.Value != "sha256:w" {
			t.Fatalf("first status = %+v, want the worker observation in place", statuses[0])
		}
	})
}

func TestA201CategoryPresence(t *testing.T) {
	metadata := `"metadata":{"uid":"u","namespace":"payments","name":"n"}`
	t.Run("omitted category is not observed", func(t *testing.T) {
		document := a201List(`{"apiVersion":"v1","kind":"Pod",` + metadata + `,"spec":{}}`)
		result := a201MustParse(t, document)
		subject := result.Subjects[0]
		for _, class := range podListClasses {
			if subject.SpecPresent[class] {
				t.Fatalf("class %s was reported as observed", class)
			}
			if len(subject.SpecContainers[class]) != 0 {
				t.Fatalf("class %s invented a declaration", class)
			}
		}
		unobserved := 0
		for _, diagnostic := range subject.Diagnostics {
			if diagnostic.Code == PodListCodeCategoryUnobserved {
				unobserved++
				if diagnostic.ByteOffset != uint64(strings.Index(document, `"spec":{`)+len(`"spec":`)) {
					t.Fatalf("category anchor = %d, want the spec object", diagnostic.ByteOffset)
				}
			}
		}
		if unobserved != 3 {
			t.Fatalf("category_unobserved diagnostics = %d, want 3", unobserved)
		}
	})
	t.Run("explicit empty category is observed empty", func(t *testing.T) {
		document := a201List(`{"apiVersion":"v1","kind":"Pod",` + metadata + `,"spec":{"containers":[]}}`)
		result := a201MustParse(t, document)
		subject := result.Subjects[0]
		if !subject.SpecPresent[contract.ContainerRegular] {
			t.Fatal("an explicit empty array was not observed")
		}
		if len(subject.SpecContainers[contract.ContainerRegular]) != 0 {
			t.Fatal("an explicit empty array invented declarations")
		}
		if subject.SpecPresent[contract.ContainerInit] {
			t.Fatal("an omitted category was reported as observed")
		}
	})
	t.Run("null category rejects the Pod", func(t *testing.T) {
		document := a201List(`{"apiVersion":"v1","kind":"Pod",` + metadata + `,"spec":{"containers":null}}`)
		result := a201MustParse(t, document)
		rejection := a201RejectionOf(t, result)
		if rejection.Code != PodListCodeInvalidFieldType {
			t.Fatalf("code = %s, want invalid_field_type", rejection.Code)
		}
		if rejection.Offset != at(t, document, "null") {
			t.Fatalf("offset = %d, want the null value", rejection.Offset)
		}
	})
	t.Run("non-empty spec without status keeps the identity", func(t *testing.T) {
		document := a201List(`{"apiVersion":"v1","kind":"Pod",` + metadata + `,"spec":{"containers":[{"name":"api"}]}}`)
		result := a201MustParse(t, document)
		if result.Accepted != 1 || result.Rejected != 0 {
			t.Fatalf("accounting = %d/%d, want 1/0", result.Accepted, result.Rejected)
		}
		subject := result.Subjects[0]
		if subject.Name != "n" || subject.UID != "u" {
			t.Fatalf("identity = %s/%s, want the declared one", subject.UID, subject.Name)
		}
		found := false
		for _, diagnostic := range subject.Diagnostics {
			if diagnostic.Code == PodListCodeStatusUnobserved {
				found = true
				// The status object is absent: the anchor is the Pod object.
				if diagnostic.ByteOffset != at(t, document, `{"apiVersion":"v1","kind":"Pod",`) {
					t.Fatalf("status anchor = %d, want the Pod object when status is absent", diagnostic.ByteOffset)
				}
			}
		}
		if !found {
			t.Fatal("an incomplete category produced no visible diagnostic")
		}
	})
	t.Run("status present without the array keeps a different anchor", func(t *testing.T) {
		document := a201List(`{"apiVersion":"v1","kind":"Pod",` + metadata + `,"spec":{"containers":[{"name":"api"}]},"status":{}}`)
		result := a201MustParse(t, document)
		found := false
		for _, diagnostic := range result.Subjects[0].Diagnostics {
			if diagnostic.Code == PodListCodeStatusUnobserved {
				found = true
				if diagnostic.ByteOffset != uint64(strings.Index(document, `"status":{`)+len(`"status":`)) {
					t.Fatalf("status anchor = %d, want the status object", diagnostic.ByteOffset)
				}
			}
		}
		if !found {
			t.Fatal("a missing status array produced no visible diagnostic")
		}
	})
	t.Run("status array without one association keeps the array anchor", func(t *testing.T) {
		document := a201List(`{"apiVersion":"v1","kind":"Pod",` + metadata + `,"spec":{"containers":[{"name":"api"},{"name":"worker"}]},` +
			`"status":{"containerStatuses":[{"name":"api"}]}}`)
		result := a201MustParse(t, document)
		found := false
		for _, diagnostic := range result.Subjects[0].Diagnostics {
			if diagnostic.Code == PodListCodeStatusUnobserved {
				found = true
				if diagnostic.ByteOffset != at(t, document, `[{"name":"api"}]`) {
					t.Fatalf("status anchor = %d, want the status array", diagnostic.ByteOffset)
				}
			}
		}
		if !found {
			t.Fatal("an incomplete association produced no visible diagnostic")
		}
	})
	t.Run("requested image unavailable keeps its anchor", func(t *testing.T) {
		document := a201List(`{"apiVersion":"v1","kind":"Pod",` + metadata + `,"spec":{"containers":[{"name":"api"}],"initContainers":[{"name":"setup","image":""}]}}`)
		result := a201MustParse(t, document)
		anchors := map[uint64]bool{}
		for _, diagnostic := range result.Subjects[0].Diagnostics {
			if diagnostic.Code == PodListCodeRequestedImageUnavailable {
				anchors[diagnostic.ByteOffset] = true
			}
		}
		// The omitted image anchors at the container object, the empty one at its
		// value.
		if !anchors[at(t, document, `{"name":"api"}`)] {
			t.Fatal("the container without an image was not diagnosed at its object")
		}
		if !anchors[at(t, document, `""`)] {
			t.Fatal("the empty image was not diagnosed at its own quote")
		}
	})
	t.Run("empty category needs both arrays to be complete", func(t *testing.T) {
		document := a201List(a201Pod("u", "n", ``, ``))
		result := a201MustParse(t, document)
		subject := result.Subjects[0]
		if len(subject.Diagnostics) != 0 {
			t.Fatalf("diagnostics = %+v, want none for three complete empty categories", subject.Diagnostics)
		}
	})
}

func TestA201ContextFields(t *testing.T) {
	metadata := `"metadata":{"uid":"u","namespace":"payments","name":"n"}`
	t.Run("ready absent and false are different", func(t *testing.T) {
		absent := a201MustParse(t, a201List(`{"apiVersion":"v1","kind":"Pod",`+metadata+`,"spec":{"containers":[{"name":"api"}]},`+
			`"status":{"containerStatuses":[{"name":"api"}]}}`))
		if absent.Subjects[0].StatusContainers[contract.ContainerRegular][0].Ready.Present != PresenceAbsent {
			t.Fatal("an absent ready was recorded as present")
		}
		explicit := a201MustParse(t, a201List(`{"apiVersion":"v1","kind":"Pod",`+metadata+`,"spec":{"containers":[{"name":"api"}]},`+
			`"status":{"containerStatuses":[{"name":"api","ready":false}]}}`))
		ready := explicit.Subjects[0].StatusContainers[contract.ContainerRegular][0].Ready
		if ready.Present != PresenceValue || ready.Value {
			t.Fatalf("ready = %+v, want an explicit false", ready)
		}
	})
	t.Run("ready null is a type error", func(t *testing.T) {
		document := a201List(`{"apiVersion":"v1","kind":"Pod",` + metadata + `,"spec":{"containers":[{"name":"api"}]},` +
			`"status":{"containerStatuses":[{"name":"api","ready":null}]}}`)
		result := a201MustParse(t, document)
		rejection := a201RejectionOf(t, result)
		if rejection.Code != PodListCodeInvalidFieldType {
			t.Fatalf("code = %s, want invalid_field_type", rejection.Code)
		}
		if rejection.Offset != at(t, document, "null") {
			t.Fatalf("offset = %d, want the null value", rejection.Offset)
		}
	})
	t.Run("state categories", func(t *testing.T) {
		for _, category := range []string{"waiting", "running", "terminated"} {
			document := a201List(`{"apiVersion":"v1","kind":"Pod",` + metadata + `,"spec":{"containers":[{"name":"api"}]},` +
				`"status":{"containerStatuses":[{"name":"api","state":{"` + category + `":{}}}]}}`)
			result := a201MustParse(t, document)
			state := result.Subjects[0].StatusContainers[contract.ContainerRegular][0].State
			if state.Category != category {
				t.Fatalf("state = %q, want %q", state.Category, category)
			}
		}
	})
	t.Run("empty state object means not informed", func(t *testing.T) {
		document := a201List(`{"apiVersion":"v1","kind":"Pod",` + metadata + `,"spec":{"containers":[{"name":"api"}]},` +
			`"status":{"containerStatuses":[{"name":"api","state":{}}]}}`)
		result := a201MustParse(t, document)
		if state := result.Subjects[0].StatusContainers[contract.ContainerRegular][0].State; state.Category != "" {
			t.Fatalf("state = %q, want an empty category", state.Category)
		}
	})
	t.Run("two state variants are ambiguous", func(t *testing.T) {
		document := a201List(`{"apiVersion":"v1","kind":"Pod",` + metadata + `,"spec":{"containers":[{"name":"api"}]},` +
			`"status":{"containerStatuses":[{"name":"api","state":{"waiting":{},"running":{}}}]}}`)
		result := a201MustParse(t, document)
		rejection := a201RejectionOf(t, result)
		if rejection.Code != PodListCodeInvalidState {
			t.Fatalf("code = %s, want invalid_state", rejection.Code)
		}
		if rejection.Offset != at(t, document, `"running"`) {
			t.Fatalf("offset = %d, want the second variant", rejection.Offset)
		}
	})
	t.Run("state variant with a member is a global rejection", func(t *testing.T) {
		document := a201List(`{"apiVersion":"v1","kind":"Pod",` + metadata + `,"spec":{"containers":[{"name":"api"}]},` +
			`"status":{"containerStatuses":[{"name":"api","state":{"waiting":{"reason":"x"}}}]}}`)
		_, err := a201Parse(t, document)
		a201WantFailure(t, err, a201Literal(at(t, document, `"reason"`), "field is not allowed by the redaction profile"))
	})
	t.Run("state variant with the wrong type", func(t *testing.T) {
		document := a201List(`{"apiVersion":"v1","kind":"Pod",` + metadata + `,"spec":{"containers":[{"name":"api"}]},` +
			`"status":{"containerStatuses":[{"name":"api","state":{"waiting":5}}]}}`)
		result := a201MustParse(t, document)
		if a201RejectionOf(t, result).Code != PodListCodeInvalidFieldType {
			t.Fatalf("code = %s, want invalid_field_type", result.Rejections[0].Code)
		}
	})
	t.Run("restartCount is context, not a promotion", func(t *testing.T) {
		document := a201List(`{"apiVersion":"v1","kind":"Pod",` + metadata + `,"spec":{"containers":[{"name":"api"}]},` +
			`"status":{"containerStatuses":[{"name":"api","restartCount":0}]}}`)
		result := a201MustParse(t, document)
		restart := result.Subjects[0].StatusContainers[contract.ContainerRegular][0].Restart
		if restart.Present != PresenceValue || restart.Value != 0 {
			t.Fatalf("restartCount = %+v, want an explicit zero", restart)
		}
	})
	t.Run("owner references are preserved", func(t *testing.T) {
		document := a201List(`{"apiVersion":"v1","kind":"Pod","metadata":{"uid":"u","namespace":"payments","name":"n",` +
			`"ownerReferences":[{"apiVersion":"apps/v1","kind":"ReplicaSet","name":"rs","uid":"rs-1","controller":false},` +
			`{"apiVersion":"v1","kind":"Pod","name":"owner","uid":"o-1","blockOwnerDeletion":true}]},"spec":{}}`)
		result := a201MustParse(t, document)
		references := result.Subjects[0].OwnerReferences
		if len(references) != 2 {
			t.Fatalf("references = %d, want 2", len(references))
		}
		if references[0].OwnerController.Present != PresenceValue || references[0].OwnerController.Value {
			t.Fatalf("controller = %+v, want an explicit false", references[0].OwnerController)
		}
		if references[1].BlockOwnerDeletion.Present != PresenceValue || !references[1].BlockOwnerDeletion.Value {
			t.Fatalf("blockOwnerDeletion = %+v, want an explicit true", references[1].BlockOwnerDeletion)
		}
	})
	t.Run("empty owner reference array is admitted", func(t *testing.T) {
		document := a201List(`{"apiVersion":"v1","kind":"Pod","metadata":{"uid":"u","namespace":"payments","name":"n","ownerReferences":[]},"spec":{}}`)
		if _, err := a201Parse(t, document); err != nil {
			t.Fatalf("an empty owner reference array was refused: %v", err)
		}
	})
	t.Run("incomplete owner reference", func(t *testing.T) {
		document := a201List(`{"apiVersion":"v1","kind":"Pod","metadata":{"uid":"u","namespace":"payments","name":"n",` +
			`"ownerReferences":[{"apiVersion":"apps/v1","kind":"ReplicaSet","name":"rs"}]},"spec":{}}`)
		result := a201MustParse(t, document)
		rejection := a201RejectionOf(t, result)
		if rejection.Code != PodListCodeMissingRequiredField {
			t.Fatalf("code = %s, want missing_required_field", rejection.Code)
		}
		if rejection.Offset != at(t, document, `{"apiVersion":"apps/v1"`) {
			t.Fatalf("offset = %d, want the owner reference object", rejection.Offset)
		}
	})
	t.Run("resourceVersion is opaque and can be empty", func(t *testing.T) {
		document := a201List(`{"apiVersion":"v1","kind":"Pod","metadata":{"uid":"u","namespace":"payments","name":"n","resourceVersion":""},"spec":{}}`)
		result := a201MustParse(t, document)
		version := result.Subjects[0].ResourceVersion
		if version.Present != PresenceEmpty {
			t.Fatalf("resourceVersion = %+v, want an empty present value", version)
		}
	})
	t.Run("opaque resourceVersion is never parsed as an order", func(t *testing.T) {
		document := a201List(`{"apiVersion":"v1","kind":"Pod","metadata":{"uid":"u","namespace":"payments","name":"n","resourceVersion":"zz-9"},"spec":{}}`)
		result := a201MustParse(t, document)
		if result.Subjects[0].ResourceVersion.Value != "zz-9" {
			t.Fatalf("resourceVersion = %q, want it preserved verbatim", result.Subjects[0].ResourceVersion.Value)
		}
	})
}

// TestA201SemanticPhaseOrder follows A.10.3 §8: identity and namespace, then the
// repetitions and associations of the categories, and only then the remaining
// fields. A defect in a later phase never hides an earlier one.
func TestA201SemanticPhaseOrder(t *testing.T) {
	t.Run("a repeated container outranks a remaining field", func(t *testing.T) {
		document := a201List(`{"apiVersion":"v1","kind":"Pod","metadata":{"uid":"u","namespace":"payments","name":"n",` +
			`"resourceVersion":0},` +
			`"spec":{"containers":[{"name":"api"},{"name":"api"}]}}`)
		result := a201MustParse(t, document)
		if a201RejectionOf(t, result).Code != PodListCodeDuplicateContainer {
			t.Fatalf("code = %s, want duplicate_container before the resource version type", result.Rejections[0].Code)
		}
	})
	t.Run("an orphan status outranks a remaining field", func(t *testing.T) {
		document := a201List(`{"apiVersion":"v1","kind":"Pod","metadata":{"uid":"u","namespace":"payments","name":"n",` +
			`"resourceVersion":0},` +
			`"spec":{"containers":[{"name":"api"}]},` +
			`"status":{"containerStatuses":[{"name":"other"}]}}`)
		result := a201MustParse(t, document)
		if a201RejectionOf(t, result).Code != PodListCodeOrphanStatus {
			t.Fatalf("code = %s, want orphan_status before the resource version type", result.Rejections[0].Code)
		}
	})
	t.Run("identity still outranks a repetition", func(t *testing.T) {
		document := a201List(`{"apiVersion":"v1","kind":"Pod","metadata":{"uid":"","namespace":"payments","name":"n"},` +
			`"spec":{"containers":[{"name":"api"},{"name":"api"}]}}`)
		result := a201MustParse(t, document)
		if a201RejectionOf(t, result).Code != PodListCodeInvalidIdentifier {
			t.Fatalf("code = %s, want the identity defect first", result.Rejections[0].Code)
		}
	})
	t.Run("the remaining field is still reported when nothing precedes it", func(t *testing.T) {
		document := a201List(`{"apiVersion":"v1","kind":"Pod","metadata":{"uid":"u","namespace":"payments","name":"n",` +
			`"resourceVersion":0},"spec":{}}`)
		result := a201MustParse(t, document)
		if a201RejectionOf(t, result).Code != PodListCodeInvalidFieldType {
			t.Fatalf("code = %s, want invalid_field_type for the resource version", result.Rejections[0].Code)
		}
	})
}

// TestA201IncompletenessOrder follows A.10.3 §10: the diagnostics of one subject
// are ordered by class first, not grouped by code.
func TestA201IncompletenessOrder(t *testing.T) {
	// regular declared without its status, init omitted entirely: the class order
	// puts regular before init even though the codes differ.
	document := a201List(`{"apiVersion":"v1","kind":"Pod","metadata":{"uid":"u","namespace":"payments","name":"n"},` +
		`"spec":{"containers":[{"name":"api"}],"ephemeralContainers":[]}}`)
	result := a201MustParse(t, document)
	codes := []string{}
	for _, diagnostic := range result.Subjects[0].Diagnostics {
		codes = append(codes, string(diagnostic.Code))
	}
	want := []string{
		string(PodListCodeStatusUnobserved),          // regular: declared, no status
		string(PodListCodeRequestedImageUnavailable), // regular: no requested image
		string(PodListCodeCategoryUnobserved),        // init: never declared
		string(PodListCodeStatusUnobserved),          // ephemeral: declared, no status
	}
	if len(codes) != len(want) {
		t.Fatalf("diagnostics = %v, want %v", codes, want)
	}
	for index, code := range want {
		if codes[index] != code {
			t.Fatalf("diagnostics = %v, want the class order %v", codes, want)
		}
	}
}
