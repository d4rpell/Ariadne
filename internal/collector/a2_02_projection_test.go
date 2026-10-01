package collector

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/d4rpell/Ariadne/internal/bundle"
	contract "github.com/d4rpell/Ariadne/pkg/evidence"
)

// Projection cases of the A2-02 plan (handoff §4.2 rows "Allowlist de
// proyección", "Presencia" and "TypeMeta"): only allowlisted fields survive,
// presence is never collapsed and TypeMeta is derived only where authorized.

// a202ProjectList projects one list response over a synthetic budget.
func a202ProjectList(t *testing.T, document string) (projectedResponse, error) {
	t.Helper()
	return projectResponse(context.Background(), []byte(document), operationSpec{verb: "list", namespace: a202Namespace}, &budgetState{})
}

// TestA202ProjectionContext is the B04 correction: the projection observes an
// expired run context cooperatively, before the walk and again before it
// admits its result, and never turns a cancelled run into an admitted source.
func TestA202ProjectionContext(t *testing.T) {
	document := a202Document(a202CompletePod("u1", "n1"))
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := projectResponse(cancelled, []byte(document), operationSpec{verb: "list", namespace: a202Namespace}, &budgetState{}); err == nil || err.Error() != "collector: cancelled" {
		t.Fatalf("err = %v, want collector: cancelled", err)
	}
	// A context that expires before the walk is refused; the same document is
	// admitted with a live context, so the guard is what makes the difference.
	if _, err := a202ProjectList(t, document); err != nil {
		t.Fatalf("the same document was refused with a live context: %v", err)
	}
}

func TestA202ProjectionAllowlist(t *testing.T) {
	// each_allowed_path: one explicit row per field of the §1.8 allowlist. Each
	// row writes exactly the member under test inside the object that admits it.
	const identity = `"metadata":{"uid":"u1","namespace":"payments","name":"n1"}`
	identityOwners := `"metadata":{"uid":"u1","namespace":"payments","name":"n1","resourceVersion":"9","ownerReferences":[`
	members := map[string]string{
		"items[].apiVersion":                                    `"apiVersion":"v1"`,
		"items[].kind":                                          `"kind":"Pod"`,
		"items[].metadata.uid":                                  identity,
		"items[].metadata.namespace":                            identity,
		"items[].metadata.name":                                 identity,
		"items[].metadata.resourceVersion":                      `"metadata":{"uid":"u1","namespace":"payments","name":"n1","resourceVersion":"9"}`,
		"items[].metadata.ownerReferences[].apiVersion":         identityOwners + `{"apiVersion":"apps/v1"}]}`,
		"items[].metadata.ownerReferences[].kind":               identityOwners + `{"kind":"ReplicaSet"}]}`,
		"items[].metadata.ownerReferences[].name":               identityOwners + `{"name":"rs-1"}]}`,
		"items[].metadata.ownerReferences[].uid":                identityOwners + `{"uid":"owner-1"}]}`,
		"items[].metadata.ownerReferences[].controller":         identityOwners + `{"controller":true}]}`,
		"items[].metadata.ownerReferences[].blockOwnerDeletion": identityOwners + `{"blockOwnerDeletion":false}]}`,
		"items[].spec.containers[].name":                        `"spec":{"containers":[{"name":"api"}]}`,
		"items[].spec.containers[].image":                       `"spec":{"containers":[{"image":"registry.example/app:release"}]}`,
		"items[].spec.initContainers[].name":                    `"spec":{"initContainers":[{"name":"setup"}]}`,
		"items[].spec.initContainers[].image":                   `"spec":{"initContainers":[{"image":"registry.example/setup:release"}]}`,
		"items[].spec.ephemeralContainers[].name":               `"spec":{"ephemeralContainers":[{"name":"debug"}]}`,
		"items[].spec.ephemeralContainers[].image":              `"spec":{"ephemeralContainers":[{"image":"registry.example/debug:release"}]}`,
		"items[].status.containerStatuses[].name":               `"status":{"containerStatuses":[{"name":"api"}]}`,
		"items[].status.containerStatuses[].imageID":            `"status":{"containerStatuses":[{"imageID":"sha256:aa"}]}`,
		"items[].status.containerStatuses[].image":              `"status":{"containerStatuses":[{"image":"registry.example/app:release"}]}`,
		"items[].status.containerStatuses[].ready":              `"status":{"containerStatuses":[{"ready":true}]}`,
		"items[].status.containerStatuses[].restartCount":       `"status":{"containerStatuses":[{"restartCount":3}]}`,
		"items[].status.containerStatuses[].state":              `"status":{"containerStatuses":[{"state":{"running":{}}}]}`,
		"items[].status.initContainerStatuses[].name":           `"status":{"initContainerStatuses":[{"name":"setup"}]}`,
		"items[].status.ephemeralContainerStatuses[].name":      `"status":{"ephemeralContainerStatuses":[{"name":"debug"}]}`,
		"metadata.resourceVersion":                              `"metadata":{"resourceVersion":"42"}`,
	}
	for path, member := range members {
		t.Run("each_allowed_path/"+path, func(t *testing.T) {
			var document string
			switch path {
			case "metadata.resourceVersion":
				document = `{"apiVersion":"v1","kind":"PodList",` + member + `,"items":[` + a202CompletePod("u1", "n1") + `]}`
			case "items[].apiVersion", "items[].kind":
				// The row writes exactly the member under test: the other
				// TypeMeta half is derived by the profile.
				document = a202Document(`{` + member + `}`)
			default:
				document = a202Document(`{"apiVersion":"v1","kind":"Pod",` + member + `}`)
			}
			projection, err := a202ProjectList(t, document)
			if err != nil {
				t.Fatalf("allowed path %q refused: %v", path, err)
			}
			if len(projection.source) == 0 {
				t.Fatal("the projection produced no source")
			}
		})
	}
	t.Run("wrong_path", func(t *testing.T) {
		// A key admitted elsewhere is discarded in the wrong object, and the
		// document still projects: the allowlist is per path, never global.
		pod := `{"apiVersion":"v1","kind":"Pod","metadata":{"uid":"u1","namespace":"payments","name":"n1"},"spec":{"image":"registry.example/app:release","containers":[{"name":"api","image":"registry.example/app:release"}]},` +
			`"status":{"containerStatuses":[{"name":"api","imageID":"sha256:aa","image":"registry.example/app:release"}]}}`
		projection, err := a202ProjectList(t, a202Document(pod))
		if err != nil {
			t.Fatalf("wrong-path document refused: %v", err)
		}
		source := string(projection.source)
		if strings.Contains(source, `"spec":{"image"`) {
			t.Fatal("a spec key admitted elsewhere survived in spec")
		}
	})
	t.Run("discarded_members_never_reach_the_projection", func(t *testing.T) {
		// Every discarded member below carries a distinct marker: none may
		// appear in the projected source, which is the output of this stage
		// before the admission would refuse any of them.
		pod := `{"apiVersion":"v1","kind":"Pod","metadata":{"uid":"u1","namespace":"payments","name":"n1","annotations":{"note":"` + a202MarkerForeign + `"}},` +
			`"spec":{"serviceAccountName":"` + a202MarkerEndpoint + `","containers":[{"name":"api","image":"registry.example/app:release",` +
			`"env":[{"name":"TOKEN","value":"` + a202MarkerToken + `"}],"args":["--secret=` + a202MarkerToken + `"]}],` +
			`"volumes":[{"name":"v","secret":{"secretName":"` + a202MarkerForeign + `"}}]},` +
			`"status":{"message":"` + a202MarkerForeign + `","containerStatuses":[{"name":"api","imageID":"sha256:aa","containerID":"containerd://` + a202MarkerToken + `"}]}}`
		projection, err := a202ProjectList(t, a202Document(pod))
		if err != nil {
			t.Fatalf("the document with discarded members was refused: %v", err)
		}
		source := string(projection.source)
		for name, marker := range map[string]string{
			"annotations":     a202MarkerForeign,
			"service_account": a202MarkerEndpoint,
			"env":             a202MarkerToken,
			"args":            a202MarkerToken,
			"volumes":         a202MarkerForeign,
			"status_message":  a202MarkerForeign,
			"container_id":    a202MarkerToken,
		} {
			if strings.Contains(source, marker) {
				t.Fatalf("the discarded member %s reached the projected source", name)
			}
		}
		// The admitted members of the same document do survive.
		for _, literal := range []string{"registry.example/app:release", "sha256:aa"} {
			if !strings.Contains(source, literal) {
				t.Fatalf("the admitted value %q did not survive", literal)
			}
		}
	})
	t.Run("forbidden_before", func(t *testing.T) {
		pod := `{"apiVersion":"v1","kind":"Pod","metadata":{"uid":"u1","namespace":"payments","name":"n1"},"spec":{"containers":[{"name":"api","image":"registry.example/app:release","env":[{"name":"TOKEN","value":"` + a202MarkerToken + `"}]}]},` +
			`"status":{"containerStatuses":[{"name":"api","imageID":"sha256:aa"}]}}`
		projection, err := a202ProjectList(t, a202Document(pod))
		if err != nil {
			t.Fatalf("document with a forbidden field refused: %v", err)
		}
		if strings.Contains(string(projection.source), a202MarkerToken) {
			t.Fatal("a discarded env value reached the projected source")
		}
	})
	t.Run("forbidden_after", func(t *testing.T) {
		pod := `{"status":{"containerStatuses":[{"name":"api","imageID":"sha256:aa"}]},"spec":{"containers":[{"name":"api","image":"registry.example/app:release"}]},` +
			`"metadata":{"uid":"u1","namespace":"payments","name":"n1"},"apiVersion":"v1","kind":"Pod",` +
			`"annotations":{"note":"` + a202MarkerForeign + `"},"args":["--token=` + a202MarkerToken + `"]}`
		projection, err := a202ProjectList(t, a202Document(pod))
		if err != nil {
			t.Fatalf("document with trailing forbidden fields refused: %v", err)
		}
		for _, marker := range []string{a202MarkerToken, a202MarkerForeign} {
			if strings.Contains(string(projection.source), marker) {
				t.Fatalf("discarded marker %q reached the projected source", marker)
			}
		}
	})
	t.Run("state_details_removed", func(t *testing.T) {
		pod := `{"apiVersion":"v1","kind":"Pod","metadata":{"uid":"u1","namespace":"payments","name":"n1"},"spec":{"containers":[{"name":"api","image":"registry.example/app:release"}]},` +
			`"status":{"containerStatuses":[{"name":"api","imageID":"sha256:aa","state":{"terminated":{"exitCode":137,"reason":"OOMKilled","message":"` + a202MarkerForeign + `"}}}]}}`
		projection, err := a202ProjectList(t, a202Document(pod))
		if err != nil {
			t.Fatalf("state document refused: %v", err)
		}
		source := string(projection.source)
		if !strings.Contains(source, `"state":{"terminated":{}}`) {
			t.Fatalf("state category not projected as an empty object: %s", source)
		}
		for _, marker := range []string{a202MarkerForeign, "OOMKilled", `"exitCode"`, `"reason"`, `"message"`} {
			if strings.Contains(source, marker) {
				t.Fatalf("state detail %q survived", marker)
			}
		}
	})
	t.Run("owners_not_followed", func(t *testing.T) {
		pod := `{"apiVersion":"v1","kind":"Pod","metadata":{"uid":"u1","namespace":"payments","name":"n1",` +
			`"ownerReferences":[{"apiVersion":"apps/v1","kind":"ReplicaSet","name":"rs-1","uid":"owner-1","controller":true,"blockOwnerDeletion":true,` +
			`"spec":{"containers":[]}}]},"spec":{"containers":[{"name":"api","image":"registry.example/app:release"}]}}`
		projection, err := a202ProjectList(t, a202Document(pod))
		if err != nil {
			t.Fatalf("owner document refused: %v", err)
		}
		source := string(projection.source)
		if strings.Contains(source, `"ownerReferences":[{"apiVersion":"apps/v1","kind":"ReplicaSet","name":"rs-1","uid":"owner-1","controller":true,"blockOwnerDeletion":true}]`) == false {
			t.Fatalf("owner reference not projected with the fixed key order: %s", source)
		}
	})
	t.Run("discarded_member_is_walked_not_decoded", func(t *testing.T) {
		// A discarded member with a deeply nested, syntactically valid value is
		// walked structurally: it neither fails nor contributes a representation.
		pod := `{"apiVersion":"v1","kind":"Pod","metadata":{"uid":"u1","namespace":"payments","name":"n1"},"spec":{"containers":[{"name":"api","image":"registry.example/app:release","resources":{"limits":{"memory":"1Gi","nested":{"deep":[1,2,{"x":null}]}}}}]}}`
		projection, err := a202ProjectList(t, a202Document(pod))
		if err != nil {
			t.Fatalf("nested discarded value refused: %v", err)
		}
		if strings.Contains(string(projection.source), "memory") {
			t.Fatal("a discarded nested value reached the source")
		}
	})
}

// a202WrapPod places one Pod member inside a minimal admitted Pod wrapper.
func a202WrapPod(member string) string {
	inner := strings.TrimSuffix(strings.TrimPrefix(member, "{"), "}")
	return a202Document(`{"metadata":{"uid":"u1","namespace":"payments","name":"n1"},` + inner + `}`)
}

func TestA202ProjectionPresence(t *testing.T) {
	// Each family is exercised with absent, null, empty, false/zero and value.
	// The builders below write one optional member explicitly, so absence is
	// expressed by omitting it from the document.
	type familyCase struct {
		pod       func(value string) string // value is the literal member, or "" for absence
		unitNull  string
		unitEmpty string
		unitValue string
		category  bool // an omitted category must stay omitted
		memberKey string
	}
	families := map[string]familyCase{
		"regular": {
			memberKey: "containers", category: true,
			pod: func(value string) string {
				return a202PodWithCategory("containers", value, `"containerStatuses":[{"name":"api","imageID":"sha256:aa"}]`)
			},
			unitNull: "null", unitEmpty: "[]", unitValue: `[{"name":"api","image":"registry.example/app:release"}]`,
		},
		"init": {
			memberKey: "initContainers", category: true,
			pod: func(value string) string {
				return a202PodWithCategory("initContainers", value, `"initContainerStatuses":[{"name":"setup","imageID":"sha256:bb"}]`)
			},
			unitNull: "null", unitEmpty: "[]", unitValue: `[{"name":"setup","image":"registry.example/setup:release"}]`,
		},
		"ephemeral": {
			memberKey: "ephemeralContainers", category: true,
			pod: func(value string) string {
				return a202PodWithCategory("ephemeralContainers", value, `"ephemeralContainerStatuses":[{"name":"debug","imageID":"sha256:cc"}]`)
			},
			unitNull: "null", unitEmpty: "[]", unitValue: `[{"name":"debug","image":"registry.example/debug:release"}]`,
		},
		"ready": {
			memberKey: "ready",
			pod: func(value string) string {
				return a202PodWithSpecStatus("", `"status":{"containerStatuses":[{"name":"api","imageID":"sha256:aa"`+a202Member(value, "ready")+`}]}`)
			},
			unitNull: "null", unitEmpty: "false", unitValue: "true",
		},
		"restart_count": {
			memberKey: "restartCount",
			pod: func(value string) string {
				return a202PodWithSpecStatus("", `"status":{"containerStatuses":[{"name":"api","imageID":"sha256:aa"`+a202Member(value, "restartCount")+`}]}`)
			},
			unitNull: "null", unitEmpty: "0", unitValue: "7",
		},
		"image_fields": {
			memberKey: "image",
			pod: func(value string) string {
				return a202PodWithSpecStatus("", `"status":{"containerStatuses":[{"name":"api","imageID":"sha256:aa"`+a202Member(value, "image")+`}]}`)
			},
			unitNull: "null", unitEmpty: `""`, unitValue: `"registry.example/app:status"`,
		},
		"state": {
			memberKey: "state",
			pod: func(value string) string {
				return a202PodWithSpecStatus("", `"status":{"containerStatuses":[{"name":"api","imageID":"sha256:aa"`+a202Member(value, "state")+`}]}`)
			},
			unitNull: "null", unitEmpty: "{}", unitValue: `{"running":{}}`,
		},
		"resource_version": {
			memberKey: "resourceVersion",
			pod: func(value string) string {
				return `{"apiVersion":"v1","kind":"Pod","metadata":{"uid":"u1","namespace":"payments","name":"n1"` + a202Member(value, "resourceVersion") + `}}`
			},
			unitNull: "null", unitEmpty: `""`, unitValue: `"9"`,
		},
	}
	for family, testCase := range families {
		t.Run(family+"/absent", func(t *testing.T) {
			projection, err := a202ProjectList(t, a202Document(testCase.pod("")))
			if err != nil {
				t.Fatalf("an omitted member was refused: %v", err)
			}
			source := string(projection.source)
			if testCase.category {
				// An omitted category is never materialized as an empty array.
				if strings.Contains(source, `"`+testCase.memberKey+`"`) {
					t.Fatalf("the omitted category %q was materialized", testCase.memberKey)
				}
				return
			}
			if strings.Contains(source, `"`+testCase.memberKey+`":null`) {
				t.Fatalf("absence was written as null for %q", testCase.memberKey)
			}
		})
		t.Run(family+"/null", func(t *testing.T) {
			projection, err := a202ProjectList(t, a202Document(testCase.pod("null")))
			if err != nil {
				// Where the projection cannot type null, the closed refusal is
				// response_invalid and no source is produced.
				if err.Error() != "collector: response_invalid" {
					t.Fatalf("null was refused with %q, want collector: response_invalid", err)
				}
				if len(projection.source) != 0 {
					t.Fatal("a refused null produced a source")
				}
				return
			}
			// Where null is carried, the literal survives: it is never rewritten
			// as an empty value or as a zero.
			if !strings.Contains(string(projection.source), "null") {
				t.Fatalf("null was neither carried nor refused for %q", testCase.memberKey)
			}
			if strings.Contains(string(projection.source), `"`+testCase.memberKey+`":""`) {
				t.Fatalf("null was rewritten as an empty value for %q", testCase.memberKey)
			}
		})
		for name, value := range map[string]string{
			"empty_or_false_or_zero": testCase.unitEmpty,
			"value":                  testCase.unitValue,
		} {
			t.Run(family+"/"+name, func(t *testing.T) {
				projection, err := a202ProjectList(t, a202Document(testCase.pod(value)))
				if err != nil {
					t.Fatalf("a present member was refused: %v", err)
				}
				source := string(projection.source)
				// The empty value is preserved literally: an empty array, an
				// empty string, false or zero are values, never absences.
				expected := value
				if !strings.Contains(source, expected) {
					t.Fatalf("the literal %s did not survive in the projected source: %s", expected, source)
				}
			})
		}
	}
	t.Run("image_fields_separate", func(t *testing.T) {
		// Requested image, status.image and imageID are independent: none is
		// filled from another.
		document := a202Document(`{"apiVersion":"v1","kind":"Pod","metadata":{"uid":"u1","namespace":"payments","name":"n1"},` +
			`"spec":{"containers":[{"name":"api","image":"registry.example/app:requested"}]},` +
			`"status":{"containerStatuses":[{"name":"api","image":"registry.example/app:status","imageID":"sha256:observed"}]}}`)
		projection, err := a202ProjectList(t, document)
		if err != nil {
			t.Fatalf("document refused: %v", err)
		}
		source := string(projection.source)
		for _, literal := range []string{"registry.example/app:requested", "registry.example/app:status", "sha256:observed"} {
			if !strings.Contains(source, literal) {
				t.Fatalf("literal %q did not survive", literal)
			}
		}
	})
}

// a202PodWithCategory builds one Pod with a spec category and its status
// counterpart. An empty value omits the whole spec object, which is the
// absence of the category.
func a202PodWithCategory(category, value, statusMembers string) string {
	// The spec object is always present: an empty value omits only the category
	// array, which is exactly the absence under test.
	spec := `"spec":{}`
	if value != "" {
		spec = `"spec":{"` + category + `":` + value + `}`
	}
	return a202PodWithSpecStatus(spec, `"status":{`+statusMembers+`}`)
}

// a202Member renders one optional member with its leading comma, or nothing at
// all when the member is absent.
func a202Member(value, key string) string {
	if value == "" {
		return ""
	}
	return `,"` + key + `":` + value
}

// a202PodWithSpecStatus builds one Pod with the supplied spec and status
// fragments. An empty fragment is omitted.
func a202PodWithSpecStatus(spec, status string) string {
	document := `{"apiVersion":"v1","kind":"Pod","metadata":{"uid":"u1","namespace":"payments","name":"n1"}`
	if spec != "" {
		document += "," + spec
	}
	if status != "" {
		document += "," + status
	}
	return document + "}"
}

func TestA202TypeMeta(t *testing.T) {
	t.Run("list", func(t *testing.T) {
		projection, err := a202ProjectList(t, a202CompleteDocument("u1", "n1"))
		if err != nil {
			t.Fatalf("list refused: %v", err)
		}
		if !strings.Contains(string(projection.source), `{"apiVersion":"v1","kind":"PodList"`) {
			t.Fatalf("the wrapper is not a v1 PodList: %s", projection.source)
		}
	})
	t.Run("list_item_missing", func(t *testing.T) {
		pod := `{"metadata":{"uid":"u1","namespace":"payments","name":"n1"},"spec":{"containers":[{"name":"api","image":"registry.example/app:release"}]}}`
		projection, err := a202ProjectList(t, a202Document(pod))
		if err != nil {
			t.Fatalf("list item without TypeMeta refused: %v", err)
		}
		if !strings.Contains(string(projection.source), `{"apiVersion":"v1","kind":"Pod","metadata"`) {
			t.Fatalf("the item TypeMeta was not materialized from the endpoint: %s", projection.source)
		}
	})
	t.Run("list_item_conflict", func(t *testing.T) {
		pod := `{"apiVersion":"v1","kind":"Service","metadata":{"uid":"u1","namespace":"payments","name":"n1"}}`
		if _, err := a202ProjectList(t, a202Document(pod)); err == nil {
			t.Fatal("a contradictory item TypeMeta was admitted")
		}
	})
	t.Run("get", func(t *testing.T) {
		pod := `{"apiVersion":"v1","kind":"Pod","metadata":{"uid":"u1","namespace":"payments","name":"n1"},"spec":{"containers":[{"name":"api","image":"registry.example/app:release"}]}}`
		projection, err := projectResponse(context.Background(), []byte(pod), operationSpec{verb: "get", namespace: a202Namespace, name: "n1"}, &budgetState{})
		if err != nil {
			t.Fatalf("get refused: %v", err)
		}
		if !strings.Contains(string(projection.source), `{"apiVersion":"v1","kind":"PodList","items":[{"apiVersion":"v1","kind":"Pod"`) {
			t.Fatalf("get did not produce a one-element PodList: %s", projection.source)
		}
	})
	t.Run("get_wrong_kind", func(t *testing.T) {
		pod := `{"apiVersion":"v1","kind":"PodList","items":[]}`
		if _, err := projectResponse(context.Background(), []byte(pod), operationSpec{verb: "get", namespace: a202Namespace, name: "n1"}, &budgetState{}); err == nil {
			t.Fatal("a get returning another kind was admitted")
		}
	})
	t.Run("identity_not_synthesized", func(t *testing.T) {
		// A list carrying an item without a uid projects, but no uid, namespace
		// or name is invented: the identity facts stay empty.
		pod := `{"apiVersion":"v1","kind":"Pod","spec":{"containers":[{"name":"api","image":"registry.example/app:release"}]}}`
		projection, err := a202ProjectList(t, a202Document(pod))
		if err != nil {
			t.Fatalf("identity-less item refused: %v", err)
		}
		if len(projection.items) != 1 || projection.items[0].uid != "" {
			t.Fatalf("an identity was synthesized: %+v", projection.items)
		}
		if strings.Contains(string(projection.source), `"uid"`) {
			t.Fatal("a uid was written into the source")
		}
	})
}

// TestA202ProjectionFailureCause is the T05 correction: the projection route
// preserves the run-wide cause. A global deadline that expires while the body
// is projected keeps time_limit, a caller cancellation is cancelled, a guard
// that already fired keeps its own code, and an elapsed per-request deadline
// never replaces the static code the projection really produced.
func TestA202ProjectionFailureCause(t *testing.T) {
	document := a202Document(a202CompletePod("u1", "n1"))
	cases := []struct {
		name  string
		cause error
		code  bundle.CollectionCode
	}{
		{"global_deadline_keeps_time_limit", context.DeadlineExceeded, bundle.CodeTimeLimit},
		{"global_cancellation_keeps_cancelled", context.Canceled, bundle.CodeCancelled},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			// The run context expires exactly when the response body has been
			// consumed — the last read delivers its bytes together with io.EOF, so
			// no further read can observe the expiry — and the projection is the
			// stage that observes it. The projection route must classify the failure
			// with the global cause instead of flattening it.
			config := a202Config(t)
			clock := newA202ArmedClock(t, a202StartMoment)
			step := a202JSONResponse(document)
			step.eofWithData = true
			step.onExhaust = clock.expire(testCase.cause)
			transport := newA202ScriptedTransport(step)
			result, err := collectWithDependencies(context.Background(), config, transport, clock)
			if err == nil || err.Error() != bundle.CollectionMessage(testCase.code) {
				t.Fatalf("err = %v, want %s", err, bundle.CollectionMessage(testCase.code))
			}
			if !a202HasError(result.Acquisition.GlobalErrors, bundle.CollectionMessage(testCase.code)) {
				t.Fatalf("global errors = %v, want the global cause", result.Acquisition.GlobalErrors)
			}
			// No capture was admitted: the run has no verifiable progress and its
			// termination stays unknown.
			if result.Acquisition.Termination != contract.TerminationUnknown {
				t.Fatalf("termination = %q, want unknown", result.Acquisition.Termination)
			}
			if len(result.Acquisition.Captures) != 0 || len(result.Bundles) != 0 {
				t.Fatalf("captures = %d, bundles = %d, want none", len(result.Acquisition.Captures), len(result.Bundles))
			}
			if transport.callCount() != 1 {
				t.Fatalf("requests = %d, want 1", transport.callCount())
			}
			bodies := transport.recordedBodies()
			if len(bodies) != 1 || bodies[0].pos != len(bodies[0].data) {
				t.Fatalf("the response body was not consumed: %+v", bodies)
			}
			// The failure happened after a complete read: the operation carries the
			// bytes it really read (a read failure would carry none) plus the window
			// it sampled, so the record proves the projection route.
			failed := false
			for _, operation := range result.Acquisition.Operations {
				if operation.State == bundle.OperationFailed {
					failed = true
					if operation.Diagnostic != testCase.code || operation.StartedAt == nil || operation.EndedAt == nil {
						t.Fatalf("the failed operation is not coherent: %+v", operation)
					}
					if operation.BytesRead != uint64(len(document)) {
						t.Fatalf("the failed operation read %d bytes, want the whole response: %+v", operation.BytesRead, operation)
					}
				}
			}
			if !failed {
				t.Fatalf("the failed attempt was not recorded: %+v", result.Acquisition.Operations)
			}
		})
	}
	t.Run("expired_request_context_keeps_response_invalid", func(t *testing.T) {
		// The individual deadline elapses when the body is closed, after the whole
		// exchange: the malformed document the projection refuses keeps its static
		// code instead of being relabelled request_timeout, because that deadline
		// did not cause the refusal.
		config := a202Config(t)
		clock := newA202ArmedClock(t, a202StartMoment)
		step := a202JSONResponse(`{"apiVersion":"v1","kind":"PodList"}` + "\x00")
		step.onClose = clock.expireRequest(context.DeadlineExceeded)
		transport := newA202ScriptedTransport(step)
		result, err := collectWithDependencies(context.Background(), config, transport, clock)
		if err == nil || err.Error() != "collector: response_invalid" {
			t.Fatalf("err = %v, want collector: response_invalid", err)
		}
		diagnostic := bundle.CollectionCode("")
		for _, operation := range result.Acquisition.Operations {
			if operation.State == bundle.OperationFailed {
				diagnostic = operation.Diagnostic
			}
		}
		if diagnostic != bundle.CodeResponseInvalid {
			t.Fatalf("operation diagnostic = %q, want response_invalid", diagnostic)
		}
	})
	t.Run("expired_request_context_keeps_response_limit", func(t *testing.T) {
		// The same rule for a raw limit refused by the scanner: the elapsed
		// individual deadline cannot turn response_limit into request_timeout.
		config := a202Config(t)
		clock := newA202ArmedClock(t, a202StartMoment)
		var nested strings.Builder
		for index := 0; index < int(maxRawDepth)+8; index++ {
			nested.WriteString("[")
		}
		for index := 0; index < int(maxRawDepth)+8; index++ {
			nested.WriteString("]")
		}
		step := a202JSONResponse(`{"apiVersion":"v1","kind":"PodList","items":[],"discarded":` + nested.String() + `}`)
		step.onClose = clock.expireRequest(context.DeadlineExceeded)
		transport := newA202ScriptedTransport(step)
		result, err := collectWithDependencies(context.Background(), config, transport, clock)
		if err == nil || err.Error() != "collector: response_limit" {
			t.Fatalf("err = %v, want collector: response_limit", err)
		}
		diagnostic := bundle.CollectionCode("")
		for _, operation := range result.Acquisition.Operations {
			if operation.State == bundle.OperationFailed {
				diagnostic = operation.Diagnostic
			}
		}
		if diagnostic != bundle.CodeResponseLimit {
			t.Fatalf("operation diagnostic = %q, want response_limit", diagnostic)
		}
	})
	t.Run("budget_guard_keeps_its_code", func(t *testing.T) {
		// The pod-occurrence budget trips inside the projection of one response
		// with a healthy context: the budget cause survives this route as
		// object_limit instead of being flattened into a generic projection code.
		var pods strings.Builder
		for index := 0; index < int(maxPodOccurrences)+1; index++ {
			if index > 0 {
				pods.WriteString(",")
			}
			pods.WriteString(a202CompletePod("u"+itoaSmall(index), "n"+itoaSmall(index)))
		}
		config := a202Config(t)
		transport := newA202ScriptedTransport(a202JSONResponse(a202Document(pods.String())))
		result, err := collectWithDependencies(context.Background(), config, transport, newA202Clock(t, a202StartMoment))
		if err == nil || err.Error() != "collector: object_limit" {
			t.Fatalf("err = %v, want collector: object_limit", err)
		}
		if result.Acquisition.Stats.PodOccurrences != maxPodOccurrences {
			t.Fatalf("occurrences = %d, want %d", result.Acquisition.Stats.PodOccurrences, maxPodOccurrences)
		}
	})
	t.Run("fired_guard_keeps_its_cause_over_the_expired_run", func(t *testing.T) {
		// The priority rule of the route, exercised directly: a guard that already
		// fired owns the diagnosis even when the run context expired meanwhile.
		runCtx, expire := context.WithCancelCause(context.Background())
		expire(context.DeadlineExceeded)
		state := &runState{runCtx: runCtx, budget: &budgetState{abortCode: bundle.CodeObjectLimit}}
		if code := state.classifyFailure(errors.New(bundle.CollectionMessage(bundle.CodeCancelled)), nil); code != bundle.CodeObjectLimit {
			t.Fatalf("code = %q, want object_limit", code)
		}
	})
}

var _ = bundle.CodeResponseInvalid
