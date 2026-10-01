package collector

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/d4rpell/Ariadne/internal/bundle"
	"github.com/d4rpell/Ariadne/internal/normalize"
	contract "github.com/d4rpell/Ariadne/pkg/evidence"
)

// Pagination, inventory, re-read and F07 cases of the A2-02 plan (handoff
// §4.2 rows "Paginación", "Identidad/inventario", "Relecturas" and "F07"). The
// scripted transport is the only network seam: the sequences below are exactly
// the ones a real API server would produce for a synthetic cluster.

// a202Collect runs one acquisition over the scripted transport and the fixed
// clock, with the validity of the configuration already proven.
func a202Collect(t *testing.T, config Config, steps []a202RoundTrip) (Result, error, *a202ScriptedTransport) {
	t.Helper()
	transport := newA202ScriptedTransport(steps...)
	clock := newA202Clock(t, a202StartMoment)
	clock.advance(time.Second)
	result, err := collectWithDependencies(context.Background(), config, transport, clock)
	return result, err, transport
}

func TestA202Pagination(t *testing.T) {
	t.Run("single_page", func(t *testing.T) {
		config := a202Config(t)
		document := a202Document(a202CompletePod("u1", "n1"))
		result, err, transport := a202Collect(t, config, []a202RoundTrip{
			a202JSONResponse(document),
			a202JSONResponse(`{"apiVersion":"v1","kind":"Pod","metadata":{"uid":"u1","namespace":"payments","name":"n1"},"spec":{"containers":[{"name":"api","image":"` + a202Image + `"}]},"status":{"containerStatuses":[{"name":"api","imageID":"` + a202ImageID + `"}]}}`),
			a202JSONResponse(`{"apiVersion":"v1","kind":"Pod","metadata":{"uid":"u1","namespace":"payments","name":"n1"},"spec":{"containers":[{"name":"api","image":"` + a202Image + `"}]},"status":{"containerStatuses":[{"name":"api","imageID":"` + a202ImageID + `"}]}}`),
		})
		if err != nil {
			t.Fatalf("collect: %v", err)
		}
		if transport.callCount() != 3 {
			t.Fatalf("requests = %d, want 1 list + 2 gets", transport.callCount())
		}
		if len(result.Acquisition.Captures) != 3 {
			t.Fatalf("captures = %d, want 3", len(result.Acquisition.Captures))
		}
		if result.Acquisition.Termination != contract.TerminationFinished {
			t.Fatalf("termination = %q", result.Acquisition.Termination)
		}
	})
	t.Run("multiple_pages", func(t *testing.T) {
		config := a202Config(t)
		page1 := `{"apiVersion":"v1","kind":"PodList","metadata":{"resourceVersion":"7","continue":"token-2"},"items":[` + a202CompletePod("u1", "n1") + `]}`
		page2 := `{"apiVersion":"v1","kind":"PodList","metadata":{"resourceVersion":"7"},"items":[` + a202CompletePod("u2", "n2") + `]}`
		get := func(uid, name string) string {
			return `{"apiVersion":"v1","kind":"Pod","metadata":{"uid":"` + uid + `","namespace":"payments","name":"` + name + `"},"spec":{"containers":[{"name":"api","image":"` + a202Image + `"}]},"status":{"containerStatuses":[{"name":"api","imageID":"` + a202ImageID + `"}]}}`
		}
		steps := []a202RoundTrip{a202JSONResponse(page1), a202JSONResponse(page2)}
		// Two catalogued targets times two rounds, in inventory order.
		for _, target := range []string{"n1", "n2", "n1", "n2"} {
			steps = append(steps, a202JSONResponse(get("u"+map[string]string{"n1": "1", "n2": "2"}[target], target)))
		}
		result, err, transport := a202Collect(t, config, steps)
		if err != nil {
			t.Fatalf("collect: %v", err)
		}
		if transport.callCount() != 6 {
			t.Fatalf("requests = %d, want 6", transport.callCount())
		}
		urls := transport.requestURLs()
		if !strings.Contains(urls[1], "continue=token-2") || !strings.Contains(urls[1], "limit=100") {
			t.Fatalf("second page query = %q", urls[1])
		}
		if len(result.Acquisition.Captures) != 6 {
			t.Fatalf("captures = %d", len(result.Acquisition.Captures))
		}
	})
	t.Run("empty_page_with_continue", func(t *testing.T) {
		config := a202Config(t)
		page1 := `{"apiVersion":"v1","kind":"PodList","metadata":{"resourceVersion":"7","continue":"token-2"},"items":[]}`
		page2 := `{"apiVersion":"v1","kind":"PodList","metadata":{"resourceVersion":"7"},"items":[]}`
		result, err, transport := a202Collect(t, config, []a202RoundTrip{a202JSONResponse(page1), a202JSONResponse(page2)})
		if err != nil {
			t.Fatalf("collect: %v", err)
		}
		if transport.callCount() != 2 {
			t.Fatalf("requests = %d, want the empty page not to end the list", transport.callCount())
		}
		if len(result.Bundles) != 0 {
			t.Fatal("an empty list produced a bundle")
		}
	})
	t.Run("repeated_token", func(t *testing.T) {
		config := a202Config(t)
		page := `{"apiVersion":"v1","kind":"PodList","metadata":{"resourceVersion":"7","continue":"token-x"},"items":[]}`
		result, err, transport := a202Collect(t, config, []a202RoundTrip{a202JSONResponse(page), a202JSONResponse(page)})
		if err == nil || err.Error() != "collector: pagination_invalid" {
			t.Fatalf("err = %v, want collector: pagination_invalid", err)
		}
		if transport.callCount() != 2 {
			t.Fatalf("requests = %d, want the repeated token detected before another request", transport.callCount())
		}
		if a202HasError(result.Acquisition.GlobalErrors, "collector: pagination_invalid") == false {
			t.Fatalf("the run-wide failure is missing: %v", result.Acquisition.GlobalErrors)
		}
	})
	t.Run("oversized_token", func(t *testing.T) {
		config := a202Config(t)
		token := strings.Repeat("t", maxContinuationBytes+1)
		page := `{"apiVersion":"v1","kind":"PodList","metadata":{"resourceVersion":"7","continue":"` + token + `"},"items":[]}`
		_, err, transport := a202Collect(t, config, []a202RoundTrip{a202JSONResponse(page)})
		if err == nil || err.Error() != "collector: pagination_invalid" {
			t.Fatalf("err = %v, want collector: pagination_invalid", err)
		}
		if transport.callCount() != 1 {
			t.Fatalf("requests = %d, want 1", transport.callCount())
		}
	})
	t.Run("gone_410", func(t *testing.T) {
		config := a202Config(t)
		page := "{\"apiVersion\":\"v1\",\"kind\":\"PodList\",\"metadata\":{\"resourceVersion\":\"7\",\"continue\":\"token-2\"},\"items\":[]}"
		_, err, transport := a202Collect(t, config, []a202RoundTrip{a202JSONResponse(page), a202RoundTrip{status: 410, body: `{"kind":"Status","reason":"Expired"}`}})
		if err == nil || err.Error() != "collector: pagination_expired" {
			t.Fatalf("err = %v, want collector: pagination_expired", err)
		}
		if transport.callCount() != 2 {
			t.Fatalf("requests = %d, want no restart after 410", transport.callCount())
		}
	})
	t.Run("rv_changed", func(t *testing.T) {
		config := a202Config(t)
		page1 := `{"apiVersion":"v1","kind":"PodList","metadata":{"resourceVersion":"7","continue":"token-2"},"items":[]}`
		page2 := `{"apiVersion":"v1","kind":"PodList","metadata":{"resourceVersion":"8"},"items":[]}`
		_, err, _ := a202Collect(t, config, []a202RoundTrip{a202JSONResponse(page1), a202JSONResponse(page2)})
		if err == nil || err.Error() != "collector: pagination_invalid" {
			t.Fatalf("err = %v, want collector: pagination_invalid", err)
		}
	})
	t.Run("rv_missing", func(t *testing.T) {
		config := a202Config(t)
		page := `{"apiVersion":"v1","kind":"PodList","items":[]}`
		result, err, _ := a202Collect(t, config, []a202RoundTrip{a202JSONResponse(page)})
		if err != nil {
			t.Fatalf("a list without resourceVersion is a visible diagnostic, not an abort: %v", err)
		}
		found := false
		for _, diagnostic := range result.Acquisition.Diagnostics {
			if diagnostic.Code == bundle.CodeResourceVersionMiss {
				found = true
			}
		}
		if !found {
			t.Fatalf("the missing list resourceVersion produced no diagnostic: %+v", result.Acquisition.Diagnostics)
		}
	})
	t.Run("failure_after_page", func(t *testing.T) {
		config := a202Config(t)
		page1 := `{"apiVersion":"v1","kind":"PodList","metadata":{"resourceVersion":"7","continue":"token-2"},"items":[` + a202CompletePod("u1", "n1") + `]}`
		result, err, _ := a202Collect(t, config, []a202RoundTrip{a202JSONResponse(page1), {status: 403, body: "{}"}})
		if err == nil || err.Error() != "collector: forbidden" {
			t.Fatalf("err = %v, want collector: forbidden", err)
		}
		// The admitted page survives; no source of the failed page exists.
		if len(result.Acquisition.Captures) != 1 {
			t.Fatalf("captures = %d, want the admitted page preserved", len(result.Acquisition.Captures))
		}
		if result.Acquisition.Termination != contract.TerminationAborted {
			t.Fatalf("termination = %q, want aborted", result.Acquisition.Termination)
		}
		if !result.Acquisition.Plan.ContinuationOpen {
			t.Fatal("the open continuation was not declared")
		}
	})
}

func TestA202InventoryIdentity(t *testing.T) {
	get := func(uid, name string) string {
		return `{"apiVersion":"v1","kind":"Pod","metadata":{"uid":"` + uid + `","namespace":"payments","name":"` + name + `"},"spec":{"containers":[{"name":"api","image":"` + a202Image + `"}]},"status":{"containerStatuses":[{"name":"api","imageID":"` + a202ImageID + `"}]}}`
	}
	t.Run("uid_replaced", func(t *testing.T) {
		config := a202Config(t)
		steps := []a202RoundTrip{
			a202JSONResponse(a202Document(a202CompletePod("u1", "n1"))),
			a202JSONResponse(get("u2", "n1")),
			a202JSONResponse(get("u2", "n1")),
		}
		result, err, _ := a202Collect(t, config, steps)
		if err != nil {
			t.Fatalf("collect: %v", err)
		}
		found := false
		for _, comparison := range result.Acquisition.Comparisons {
			if comparison.Code == bundle.CodeUIDChanged {
				found = true
			}
		}
		if !found {
			t.Fatalf("a uid replacement produced no comparison: %+v", result.Acquisition.Comparisons)
		}
		if len(result.Bundles) < 2 {
			t.Fatalf("a replacement must stay a separate subject: %d bundles", len(result.Bundles))
		}
	})
	t.Run("duplicate_across_pages", func(t *testing.T) {
		config := a202Config(t)
		page1 := `{"apiVersion":"v1","kind":"PodList","metadata":{"resourceVersion":"7","continue":"token-2"},"items":[` + a202CompletePod("u1", "n1") + `]}`
		page2 := `{"apiVersion":"v1","kind":"PodList","metadata":{"resourceVersion":"7"},"items":[` + a202CompletePod("u1", "n2") + `]}`
		result, err, _ := a202Collect(t, config, []a202RoundTrip{a202JSONResponse(page1), a202JSONResponse(page2)})
		if err != nil {
			t.Fatalf("collect: %v", err)
		}
		// Both occurrences are omitted: none wins by order.
		if len(result.Bundles) != 0 {
			t.Fatalf("a duplicated uid produced %d bundles", len(result.Bundles))
		}
		found := false
		for _, diagnostic := range result.Acquisition.Diagnostics {
			if diagnostic.Code == bundle.CodeIdentityConflict {
				found = true
			}
		}
		if !found {
			t.Fatalf("no identity_conflict diagnostic: %+v", result.Acquisition.Diagnostics)
		}
	})
	t.Run("duplicate_with_rejected_peer", func(t *testing.T) {
		config := a202Config(t)
		// The first occurrence is semantically rejected by the sanitized
		// grammar (a status without its declared container); the uid duplicate
		// is still detected and both occurrences stay out.
		rejected := `{"apiVersion":"v1","kind":"Pod","metadata":{"uid":"u1","namespace":"payments","name":"n1"},"spec":{"containers":[{"name":"api","image":"` + a202Image + `"}]},"status":{"containerStatuses":[{"name":"ghost","imageID":"` + a202ImageID + `"}]}}`
		page1 := `{"apiVersion":"v1","kind":"PodList","metadata":{"resourceVersion":"7","continue":"token-2"},"items":[` + rejected + `]}`
		page2 := `{"apiVersion":"v1","kind":"PodList","metadata":{"resourceVersion":"7"},"items":[` + a202CompletePod("u1", "n2") + `]}`
		result, err, _ := a202Collect(t, config, []a202RoundTrip{a202JSONResponse(page1), a202JSONResponse(page2),
			a202JSONResponse(get("u1", "n2")), a202JSONResponse(get("u1", "n2")), a202JSONResponse(get("u1", "n2")), a202JSONResponse(get("u1", "n2"))})
		if err != nil {
			t.Fatalf("collect: %v", err)
		}
		if len(result.Bundles) != 0 {
			t.Fatalf("a duplicated uid with a rejected peer produced %d bundles", len(result.Bundles))
		}
	})
	t.Run("temporal_repeat", func(t *testing.T) {
		config := a202Config(t)
		steps := []a202RoundTrip{
			a202JSONResponse(a202Document(a202CompletePod("u1", "n1"))),
			a202JSONResponse(get("u1", "n1")),
			a202JSONResponse(get("u1", "n1")),
		}
		result, err, _ := a202Collect(t, config, steps)
		if err != nil {
			t.Fatalf("collect: %v", err)
		}
		// Two temporal captures of the same uid are not a duplicate: they stay
		// separate captures and produce separate bundles.
		if len(result.Bundles) != 3 {
			t.Fatalf("bundles = %d, want one per capture", len(result.Bundles))
		}
		for _, comparison := range result.Acquisition.Comparisons {
			if comparison.Code == bundle.CodeIdentityConflict {
				t.Fatal("a temporal repetition was classified as an identity conflict")
			}
		}
	})
	t.Run("duplicate_survives_inventory_budget_exhaustion", func(t *testing.T) {
		// The inventory budget closes the walk after both pages were scanned:
		// the duplicate uid they share must still invalidate every one of its
		// occurrences, because the limit that closed the walk cannot
		// reintroduce an occurrence it already charged. The budget is seeded to
		// its last admitted unit so the second occurrence trips it.
		captures := []bundle.CollectedCapture{
			{
				Ordinal: 1,
				Verb:    "list",
				Observation: normalize.ObservationResult{
					Termination: contract.TerminationFinished,
				},
				Items: []bundle.CollectedItem{{UID: "u1", Namespace: a202Namespace, Name: "n1"}},
			},
			{
				Ordinal: 2,
				Verb:    "list",
				Observation: normalize.ObservationResult{
					Termination: contract.TerminationFinished,
				},
				Items: []bundle.CollectedItem{{UID: "u1", Namespace: a202Namespace, Name: "n2"}},
			},
		}
		budget := &budgetState{initialUIDs: maxInitialUIDs - 1}
		inventory, diagnostics, err := buildInventory(captures, budget)
		if err == nil || err.Error() != "collector: object_limit" {
			t.Fatalf("err = %v, want collector: object_limit", err)
		}
		if len(inventory.entries) != 0 {
			t.Fatalf("the duplicated occurrence stayed in the inventory: %+v", inventory.entries)
		}
		if _, duplicated := inventory.duplicateUIDs["u1"]; !duplicated {
			t.Fatal("the duplicate exclusion was lost when the budget closed the walk")
		}
		conflict := false
		for _, diagnostic := range diagnostics {
			if diagnostic.Code == bundle.CodeIdentityConflict {
				conflict = true
			}
		}
		if !conflict {
			t.Fatalf("the duplicate was not reported: %+v", diagnostics)
		}
	})
	t.Run("same_name_different_uid", func(t *testing.T) {
		config := a202Config(t)
		// Two subjects sharing namespace/name but not uid stay separate.
		page := `{"apiVersion":"v1","kind":"PodList","metadata":{"resourceVersion":"7"},"items":[` + a202CompletePod("u1", "n1") + `,` + a202CompletePod("u2", "n1") + `]}`
		steps := []a202RoundTrip{a202JSONResponse(page)}
		for _, uid := range []string{"u1", "u2", "u1", "u2"} {
			steps = append(steps, a202JSONResponse(get(uid, "n1")))
		}
		result, err, _ := a202Collect(t, config, steps)
		if err != nil {
			t.Fatalf("collect: %v", err)
		}
		// One list capture plus the two get rounds of each target: the two
		// different uids sharing a name are two separate targets, never merged.
		if len(result.Acquisition.Captures) != 5 {
			t.Fatalf("captures = %d, want 1 list + 4 gets", len(result.Acquisition.Captures))
		}
		if len(result.Acquisition.Plan.Targets) != 2 {
			t.Fatalf("targets = %d, want both uids inventoried", len(result.Acquisition.Plan.Targets))
		}
		subjects := result.Acquisition.Captures[0].Observation.Subjects
		if len(subjects) != 2 {
			t.Fatalf("subjects = %d, want both subjects kept apart", len(subjects))
		}
	})
	t.Run("wrong_namespace", func(t *testing.T) {
		config := a202Config(t)
		// The response addresses another namespace: the source is refused and
		// nothing of the foreign document is published.
		foreign := `{"apiVersion":"v1","kind":"PodList","metadata":{"resourceVersion":"7"},"items":[` +
			`{"apiVersion":"v1","kind":"Pod","metadata":{"uid":"u1","namespace":"other","name":"n1"},"spec":{"containers":[{"name":"api","image":"` + a202MarkerForeign + `"}]}}]}`
		result, err, transport := a202Collect(t, config, []a202RoundTrip{a202JSONResponse(foreign)})
		if err == nil || err.Error() != "collector: scope_mismatch" {
			t.Fatalf("err = %v, want collector: scope_mismatch", err)
		}
		if transport.callCount() != 1 {
			t.Fatalf("requests = %d, want no further request", transport.callCount())
		}
		if len(result.Acquisition.Captures) != 0 {
			t.Fatal("a foreign namespace became a source")
		}
	})
	t.Run("wrong_get_name", func(t *testing.T) {
		config := a202Config(t)
		steps := []a202RoundTrip{
			a202JSONResponse(a202Document(a202CompletePod("u1", "n1"))),
			a202JSONResponse(get("u1", "other-name")),
		}
		result, err, _ := a202Collect(t, config, steps)
		if err == nil || err.Error() != "collector: scope_mismatch" {
			t.Fatalf("err = %v, want collector: scope_mismatch", err)
		}
		if len(result.Acquisition.Captures) != 1 {
			t.Fatalf("captures = %d, want only the admitted list preserved", len(result.Acquisition.Captures))
		}
	})
}

func TestA202RereadComparisons(t *testing.T) {
	// The helpers below script one list page and the two get rounds.
	a202RereadCase := func(t *testing.T, first, second string) (Result, error) {
		t.Helper()
		config := a202Config(t)
		steps := []a202RoundTrip{
			a202JSONResponse(a202Document(a202CompletePod("u1", "n1"))),
			a202JSONResponse(first),
			a202JSONResponse(second),
		}
		result, err, _ := a202Collect(t, config, steps)
		return result, err
	}
	base := func(uid, name, image, imageID string) string {
		return `{"apiVersion":"v1","kind":"Pod","metadata":{"uid":"` + uid + `","namespace":"payments","name":"` + name + `"},` +
			`"spec":{"containers":[{"name":"api","image":"` + image + `"}],"initContainers":[],"ephemeralContainers":[]},` +
			`"status":{"containerStatuses":[{"name":"api","imageID":"` + imageID + `","image":"` + image + `","ready":true,"state":{"running":{}},"restartCount":0}],"initContainerStatuses":[],"ephemeralContainerStatuses":[]}}`
	}
	t.Run("uid", func(t *testing.T) {
		result, err := a202RereadCase(t, base("u2", "n1", a202Image, a202ImageID), base("u2", "n1", a202Image, a202ImageID))
		if err != nil {
			t.Fatalf("collect: %v", err)
		}
		if len(result.Bundles) != 3 {
			t.Fatalf("bundles = %d, want one per capture", len(result.Bundles))
		}
	})
	t.Run("spec", func(t *testing.T) {
		result, err := a202RereadCase(t, base("u1", "n1", "registry.example/app:second", a202ImageID), base("u1", "n1", "registry.example/app:second", a202ImageID))
		if err != nil {
			t.Fatalf("collect: %v", err)
		}
		if len(result.Acquisition.Comparisons) == 0 {
			t.Fatal("a spec change produced no comparison")
		}
	})
	t.Run("status_image", func(t *testing.T) {
		first := base("u1", "n1", a202Image, a202ImageID)
		second := strings.Replace(first, `"image":"`+a202Image+`","ready"`, `"image":"registry.example/app:new","ready"`, 1)
		result, err := a202RereadCase(t, second, second)
		if err != nil {
			t.Fatalf("collect: %v", err)
		}
		found := false
		for _, comparison := range result.Acquisition.Comparisons {
			if comparison.Code == bundle.CodeObservationChanged {
				found = true
			}
		}
		if !found {
			t.Fatalf("a status change produced no observation_changed: %+v", result.Acquisition.Comparisons)
		}
	})
	t.Run("ready", func(t *testing.T) {
		first := base("u1", "n1", a202Image, a202ImageID)
		second := strings.Replace(first, `"ready":true`, `"ready":false`, 1)
		result, err := a202RereadCase(t, second, second)
		if err != nil {
			t.Fatalf("collect: %v", err)
		}
		found := false
		for _, comparison := range result.Acquisition.Comparisons {
			if comparison.Code == bundle.CodeObservationChanged {
				found = true
			}
		}
		if !found {
			t.Fatalf("a readiness change produced no comparison: %+v", result.Acquisition.Comparisons)
		}
	})
	t.Run("restart_count", func(t *testing.T) {
		first := base("u1", "n1", a202Image, a202ImageID)
		second := strings.Replace(first, `"restartCount":0`, `"restartCount":5`, 1)
		result, err := a202RereadCase(t, second, second)
		if err != nil {
			t.Fatalf("collect: %v", err)
		}
		found := false
		for _, comparison := range result.Acquisition.Comparisons {
			if comparison.Code == bundle.CodeObservationChanged {
				found = true
			}
		}
		if !found {
			t.Fatalf("a restart-count change produced no comparison: %+v", result.Acquisition.Comparisons)
		}
	})
	t.Run("rv_only", func(t *testing.T) {
		config := a202Config(t)
		first := base("u1", "n1", a202Image, a202ImageID)
		second := strings.Replace(first, `"uid":"u1"`, `"uid":"u1","resourceVersion":"9"`, 1)
		steps := []a202RoundTrip{
			a202JSONResponse(a202Document(a202CompletePod("u1", "n1"))),
			a202JSONResponse(second),
			a202JSONResponse(second),
		}
		result, err, _ := a202Collect(t, config, steps)
		// A resourceVersion that only appears is opaque context: it proves no
		// content change and must not produce an observation_changed. The
		// comparison list is asserted before the run outcome, because the bogus
		// comparison is the direct evidence of the guard under test.
		for _, comparison := range result.Acquisition.Comparisons {
			if comparison.Code == bundle.CodeObservationChanged {
				t.Fatalf("a resourceVersion-only difference produced a content change: %+v", comparison)
			}
		}
		if err != nil {
			t.Fatalf("collect: %v", err)
		}
	})
	t.Run("same_rv_changed_content", func(t *testing.T) {
		first := base("u1", "n1", a202Image, a202ImageID)
		second := strings.Replace(first, `"restartCount":0`, `"restartCount":9`, 1)
		result, err := a202RereadCase(t, second, second)
		if err != nil {
			t.Fatalf("collect: %v", err)
		}
		found := false
		for _, comparison := range result.Acquisition.Comparisons {
			if comparison.Code == bundle.CodeObservationChanged {
				found = true
			}
		}
		if !found {
			t.Fatalf("differing content produced no source conflict: %+v", result.Acquisition.Comparisons)
		}
	})
	t.Run("ephemeral_added", func(t *testing.T) {
		config := a202Config(t)
		first := base("u1", "n1", a202Image, a202ImageID)
		second := strings.Replace(first, `"ephemeralContainers":[]`, `"ephemeralContainers":[{"name":"debug","image":"registry.example/debug:release"}]`, 1)
		steps := []a202RoundTrip{
			a202JSONResponse(a202Document(a202CompletePod("u1", "n1"))),
			a202JSONResponse(second),
			a202JSONResponse(second),
		}
		result, err, _ := a202Collect(t, config, steps)
		if err != nil {
			t.Fatalf("collect: %v", err)
		}
		if len(result.Acquisition.Captures) != 3 {
			t.Fatalf("captures = %d: the added ephemeral container must not merge captures", len(result.Acquisition.Captures))
		}
	})
	t.Run("not_found", func(t *testing.T) {
		config := a202Config(t)
		steps := []a202RoundTrip{
			a202JSONResponse(a202Document(a202CompletePod("u1", "n1"))),
			a202RoundTrip{status: 404, body: `{"kind":"Status"}`},
		}
		result, err, _ := a202Collect(t, config, steps)
		if err == nil || err.Error() != "collector: not_found" {
			t.Fatalf("err = %v, want collector: not_found", err)
		}
		// A 404 is not a permanent deletion and not a subject: the admitted list
		// survives with its global failure.
		if len(result.Acquisition.Captures) != 1 {
			t.Fatalf("captures = %d", len(result.Acquisition.Captures))
		}
		if result.Acquisition.Termination != contract.TerminationAborted {
			t.Fatalf("termination = %q", result.Acquisition.Termination)
		}
	})
}

func TestA202F07(t *testing.T) {
	// a202F07Case scripts one list page and two get rounds.
	a202F07Case := func(t *testing.T, first, second, third string) Result {
		t.Helper()
		config := a202Config(t)
		steps := []a202RoundTrip{
			a202JSONResponse(a202Document(a202CompletePod("u1", "n1"))),
			a202JSONResponse(first),
			a202JSONResponse(second),
		}
		if third != "" {
			steps = append(steps, a202JSONResponse(third))
		}
		result, err, _ := a202Collect(t, config, steps)
		if err != nil {
			t.Fatalf("collect: %v", err)
		}
		return result
	}
	// base scripts one Pod whose requested image and status image are the two
	// arguments: the whole projected status tuple (imageID, status.image,
	// ready, state, restartCount and their presence) follows them, so a caller
	// can keep it identical or change it deliberately.
	base := func(image, statusImage string, ready bool, restart int) string {
		readyText := "true"
		if !ready {
			readyText = "false"
		}
		return `{"apiVersion":"v1","kind":"Pod","metadata":{"uid":"u1","namespace":"payments","name":"n1"},` +
			`"spec":{"containers":[{"name":"api","image":"` + image + `"}],"initContainers":[],"ephemeralContainers":[]},` +
			`"status":{"containerStatuses":[{"name":"api","imageID":"` + a202ImageID + `","image":"` + statusImage + `","ready":` + readyText + `,"state":{"running":{}},"restartCount":` + itoaSmall(restart) + `}],"initContainerStatuses":[],"ephemeralContainerStatuses":[]}}`
	}
	t.Run("spec_changed_status_same", func(t *testing.T) {
		result := a202F07Case(t, base("registry.example/app:second", a202Image, true, 0), base("registry.example/app:second", a202Image, true, 0), "")
		found := false
		for _, comparison := range result.Acquisition.Comparisons {
			if comparison.Code == bundle.CodeStaleStatusSuspected {
				found = true
			}
		}
		if !found {
			t.Fatalf("the F07 pattern produced no stale_status_suspected: %+v", result.Acquisition.Comparisons)
		}
		for _, candidate := range result.Bundles {
			if !a202HasWarning(candidate.Bundle.Provenance.Warnings, "stale_observation", contract.WarningContradictory, "status freshness could not be established after a spec change") {
				continue
			}
			return
		}
		t.Fatalf("no bundle carries the stale_observation warning")
	})
	t.Run("later_capture_status_changed", func(t *testing.T) {
		// The profile fixes exactly two get rounds (A.5.1), so the run has two
		// get captures of the inventoried target: the list plus the two rounds.
		// The pattern detected between the list and the first get must not be
		// erased by the later capture whose status moved: the scripted sequence
		// is consumed completely and both codes stay in the record, with their
		// exact references to the captures that carry the discrepancy.
		config := a202Config(t)
		steps := []a202RoundTrip{
			// Capture 1 (list): status still old.
			a202JSONResponse(a202Document(a202CompletePod("u1", "n1"))),
			// Capture 2 (first get): requested image changed, status identical.
			a202JSONResponse(base("registry.example/app:second", a202Image, true, 0)),
			// Capture 3 (second get): requested image changed, status now moves.
			a202JSONResponse(base("registry.example/app:second", a202Image, true, 4)),
		}
		result, err, transport := a202Collect(t, config, steps)
		if err != nil {
			t.Fatalf("collect: %v", err)
		}
		if transport.callCount() != 3 {
			t.Fatalf("requests = %d, want the list and the two fixed get rounds", transport.callCount())
		}
		if transport.rejects != 0 {
			t.Fatalf("the script was not consumed completely: %d unexpected requests", transport.rejects)
		}
		// The stale pattern stays anchored to the list and the first get, and no
		// later capture removes it.
		staleFound := false
		for _, comparison := range result.Acquisition.Comparisons {
			if comparison.Code != bundle.CodeStaleStatusSuspected {
				continue
			}
			staleFound = true
			if comparison.Previous.CaptureOrdinal != 1 || comparison.Current.CaptureOrdinal != 2 {
				t.Fatalf("stale comparison references %+v", comparison)
			}
		}
		if !staleFound {
			t.Fatalf("the later capture erased the stale pattern: %+v", result.Acquisition.Comparisons)
		}
		observationChanged := false
		for _, comparison := range result.Acquisition.Comparisons {
			if comparison.Code == bundle.CodeObservationChanged {
				observationChanged = true
			}
		}
		if !observationChanged {
			t.Fatalf("the content change between captures was not recorded: %+v", result.Acquisition.Comparisons)
		}
		// The warning of the bounded pattern reaches the bundle of the subjects
		// it references, exactly once and with its frozen text.
		warned := false
		for _, candidate := range result.Bundles {
			if a202HasWarning(candidate.Bundle.Provenance.Warnings, "stale_observation", contract.WarningContradictory, "status freshness could not be established after a spec change") {
				warned = true
			}
		}
		if !warned {
			t.Fatal("the preserved pattern produced no stale_observation warning")
		}
	})
	t.Run("single_spec_status_mismatch", func(t *testing.T) {
		// Every capture shows requested and status.image differing, and the
		// status image moves with the requested one: the projection does not
		// infer staleness from that inequality.
		result := a202F07Case(t,
			base("registry.example/app:second", "registry.example/app:second", true, 0),
			base("registry.example/app:second", "registry.example/app:second", true, 0), "")
		for _, comparison := range result.Acquisition.Comparisons {
			if comparison.Code == bundle.CodeStaleStatusSuspected {
				t.Fatalf("an isolated spec/status mismatch produced stale: %+v", comparison)
			}
		}
	})
	t.Run("ready_false_only", func(t *testing.T) {
		result := a202F07Case(t, base(a202Image, a202Image, false, 0), base(a202Image, a202Image, false, 0), "")
		for _, comparison := range result.Acquisition.Comparisons {
			if comparison.Code == bundle.CodeStaleStatusSuspected {
				t.Fatalf("ready=false alone produced stale: %+v", comparison)
			}
		}
	})
	t.Run("restart_only", func(t *testing.T) {
		result := a202F07Case(t, base(a202Image, a202Image, true, 3), base(a202Image, a202Image, true, 3), "")
		for _, comparison := range result.Acquisition.Comparisons {
			if comparison.Code == bundle.CodeStaleStatusSuspected {
				t.Fatalf("a restart count alone produced stale: %+v", comparison)
			}
		}
	})
	t.Run("equivalent_image_alias_does_not_prove_delay", func(t *testing.T) {
		// Different reference spellings are not normalised into equality or
		// difference: the pattern needs the requested image to change and the
		// status tuple to stay identical.
		result := a202F07Case(t,
			base("registry.example/app:release", a202Image, true, 0),
			base("registry.example/app:release", a202Image, true, 0),
			"")
		for _, comparison := range result.Acquisition.Comparisons {
			if comparison.Code == bundle.CodeStaleStatusSuspected {
				t.Fatalf("an unchanged reference produced stale: %+v", comparison)
			}
		}
	})
	t.Run("presence_changed", func(t *testing.T) {
		// The requested image changes and the only difference of the status side
		// is the presence of the status object itself, which carries an empty
		// tuple: the tuple is not identical, so the pattern does not fire.
		withoutStatus := `{"apiVersion":"v1","kind":"Pod","metadata":{"uid":"u1","namespace":"payments","name":"n1"},` +
			`"spec":{"containers":[{"name":"api","image":"registry.example/app:second"}],"initContainers":[],"ephemeralContainers":[]}}`
		withStatus := `{"apiVersion":"v1","kind":"Pod","metadata":{"uid":"u1","namespace":"payments","name":"n1"},` +
			`"spec":{"containers":[{"name":"api","image":"registry.example/app:third"}],"initContainers":[],"ephemeralContainers":[]},` +
			`"status":{"containerStatuses":[{"name":"api"}],"initContainerStatuses":[],"ephemeralContainerStatuses":[]}}`
		result := a202F07Case(t, withoutStatus, withStatus, "")
		if withStatus == withoutStatus {
			t.Fatal("the fixtures are identical")
		}
		for _, comparison := range result.Acquisition.Comparisons {
			if comparison.Code == bundle.CodeStaleStatusSuspected {
				t.Fatalf("a changed presence produced stale: %+v", comparison)
			}
		}
	})
	t.Run("state_presence_change_is_a_content_change", func(t *testing.T) {
		// The requested image changes and the only status difference is the
		// presence of the state object itself: going from an omitted state to an
		// empty state ({}) keeps the same category but is a real change of the
		// projected content, so observation_changed must be recorded and the
		// stale pattern must not fire (the tuples differ).
		stateAbsent := `{"apiVersion":"v1","kind":"Pod","metadata":{"uid":"u1","namespace":"payments","name":"n1"},` +
			`"spec":{"containers":[{"name":"api","image":"registry.example/app:second"}],"initContainers":[],"ephemeralContainers":[]},` +
			`"status":{"containerStatuses":[{"name":"api","imageID":"` + a202ImageID + `","image":"` + a202Image + `","ready":true,"restartCount":0}],"initContainerStatuses":[],"ephemeralContainerStatuses":[]}}`
		stateEmpty := `{"apiVersion":"v1","kind":"Pod","metadata":{"uid":"u1","namespace":"payments","name":"n1"},` +
			`"spec":{"containers":[{"name":"api","image":"registry.example/app:second"}],"initContainers":[],"ephemeralContainers":[]},` +
			`"status":{"containerStatuses":[{"name":"api","imageID":"` + a202ImageID + `","image":"` + a202Image + `","ready":true,"state":{},"restartCount":0}],"initContainerStatuses":[],"ephemeralContainerStatuses":[]}}`
		// The list capture carries the requested image unchanged, so the only
		// possible observation_changed is between the two get rounds.
		config := a202Config(t)
		steps := []a202RoundTrip{
			a202JSONResponse(a202Document(a202CompletePod("u1", "n1"))),
			a202JSONResponse(stateAbsent),
			a202JSONResponse(stateEmpty),
		}
		result, err, transport := a202Collect(t, config, steps)
		if err != nil {
			t.Fatalf("collect: %v", err)
		}
		if transport.callCount() != 3 {
			t.Fatalf("requests = %d", transport.callCount())
		}
		changed := false
		for _, comparison := range result.Acquisition.Comparisons {
			if comparison.Code == bundle.CodeObservationChanged &&
				comparison.Previous.CaptureOrdinal == 2 && comparison.Current.CaptureOrdinal == 3 {
				changed = true
			}
			if comparison.Code == bundle.CodeStaleStatusSuspected {
				t.Fatalf("a state presence change produced stale: %+v", comparison)
			}
		}
		if !changed {
			t.Fatalf("the state presence change was not recorded as a content change: %+v", result.Acquisition.Comparisons)
		}
	})
	t.Run("multi_container_sidecar_unchanged", func(t *testing.T) {
		// A pre-existing sidecar stays completely unchanged while the api
		// container satisfies the pattern: the sidecar must neither erase nor
		// fabricate the pattern, and the containers are matched by class and
		// name, never by position. The list capture carries both containers, so
		// the sidecar really is pre-existing.
		twoContainers := func(apiImage, sidecarImage string, apiRestart int) string {
			return `{"apiVersion":"v1","kind":"Pod","metadata":{"uid":"u1","namespace":"payments","name":"n1"},` +
				`"spec":{"containers":[` +
				`{"name":"api","image":"` + apiImage + `"},` +
				`{"name":"sidecar","image":"` + sidecarImage + `"}` +
				`],"initContainers":[],"ephemeralContainers":[]},` +
				`"status":{"containerStatuses":[` +
				`{"name":"api","imageID":"` + a202ImageID + `","image":"` + a202Image + `","ready":true,"state":{"running":{}},"restartCount":` + itoaSmall(apiRestart) + `},` +
				`{"name":"sidecar","imageID":"sha256:` + strings.Repeat("c", 64) + `","image":"registry.example/sidecar:release","ready":true,"state":{"running":{}},"restartCount":0}` +
				`],"initContainerStatuses":[],"ephemeralContainerStatuses":[]}}`
		}
		config := a202Config(t)
		steps := []a202RoundTrip{
			// List: both containers, api with its original requested image.
			a202JSONResponse(a202Document(twoContainers(a202Image, "registry.example/sidecar:release", 0))),
			// First get: only the api requested image changed; sidecar untouched.
			a202JSONResponse(twoContainers("registry.example/app:second", "registry.example/sidecar:release", 0)),
			// Second get: identical to the first one.
			a202JSONResponse(twoContainers("registry.example/app:second", "registry.example/sidecar:release", 0)),
		}
		result, err, transport := a202Collect(t, config, steps)
		if err != nil {
			t.Fatalf("collect: %v", err)
		}
		if transport.callCount() != 3 {
			t.Fatalf("requests = %d", transport.callCount())
		}
		found := false
		for _, comparison := range result.Acquisition.Comparisons {
			if comparison.Code == bundle.CodeStaleStatusSuspected {
				found = true
			}
		}
		if !found {
			t.Fatalf("the unchanged sidecar erased the pattern of the changed container: %+v", result.Acquisition.Comparisons)
		}
	})
	t.Run("container_order_permuted", func(t *testing.T) {
		// The list and the get carry the same two containers in opposite order:
		// the pattern between them holds only when the containers are matched by
		// class and name, because matching by position would pair the container
		// that changed with the one that did not.
		twoContainers := func(apiImage string, apiFirst bool) string {
			api := `{"name":"api","image":"` + apiImage + `"}`
			sidecar := `{"name":"sidecar","image":"registry.example/sidecar:release"}`
			spec := api + `,` + sidecar
			if !apiFirst {
				spec = sidecar + `,` + api
			}
			return `{"apiVersion":"v1","kind":"Pod","metadata":{"uid":"u1","namespace":"payments","name":"n1"},` +
				`"spec":{"containers":[` + spec + `],"initContainers":[],"ephemeralContainers":[]},` +
				`"status":{"containerStatuses":[` +
				`{"name":"api","imageID":"` + a202ImageID + `","image":"` + a202Image + `","ready":true,"state":{"running":{}},"restartCount":0},` +
				`{"name":"sidecar","imageID":"sha256:` + strings.Repeat("c", 64) + `","image":"registry.example/sidecar:release","ready":true,"state":{"running":{}},"restartCount":0}` +
				`],"initContainerStatuses":[],"ephemeralContainerStatuses":[]}}`
		}
		config := a202Config(t)
		steps := []a202RoundTrip{
			// List: the api container first, requested image old.
			a202JSONResponse(a202Document(twoContainers(a202Image, true))),
			// First get: the sidecar first, only the api requested image changed.
			a202JSONResponse(twoContainers("registry.example/app:second", false)),
			// Second get: identical to the first one.
			a202JSONResponse(twoContainers("registry.example/app:second", false)),
		}
		result, err, transport := a202Collect(t, config, steps)
		if err != nil {
			t.Fatalf("collect: %v", err)
		}
		if transport.callCount() != 3 {
			t.Fatalf("requests = %d", transport.callCount())
		}
		found := false
		for _, comparison := range result.Acquisition.Comparisons {
			if comparison.Code == bundle.CodeStaleStatusSuspected {
				found = true
			}
		}
		if !found {
			t.Fatalf("a permutation of the containers erased the pattern: %+v", result.Acquisition.Comparisons)
		}
	})
	t.Run("contradicting_container_does_not_veto_other_container", func(t *testing.T) {
		// In the same pair of captures one container satisfies the pattern (its
		// requested image changed while its status tuple stayed identical) and
		// another moved its spec and status together. The pattern is per
		// container: the evolution of the sidecar neither establishes nor erases
		// the freshness gap of the api container.
		pod := func(apiImage, sidecarImage string, sidecarRestart int) string {
			return `{"apiVersion":"v1","kind":"Pod","metadata":{"uid":"u1","namespace":"payments","name":"n1"},` +
				`"spec":{"containers":[` +
				`{"name":"api","image":"` + apiImage + `"},` +
				`{"name":"sidecar","image":"` + sidecarImage + `"}` +
				`],"initContainers":[],"ephemeralContainers":[]},` +
				`"status":{"containerStatuses":[` +
				`{"name":"api","imageID":"` + a202ImageID + `","image":"` + a202Image + `","ready":true,"state":{"running":{}},"restartCount":0},` +
				`{"name":"sidecar","imageID":"sha256:` + strings.Repeat("c", 64) + `","image":"registry.example/sidecar:release","ready":true,"state":{"running":{}},"restartCount":` + itoaSmall(sidecarRestart) + `}` +
				`],"initContainerStatuses":[],"ephemeralContainerStatuses":[]}}`
		}
		config := a202Config(t)
		steps := []a202RoundTrip{
			// List: both containers in their initial state.
			a202JSONResponse(a202Document(pod(a202Image, "registry.example/sidecar:release", 0))),
			// First get: the api container satisfies the pattern; the sidecar
			// changed its requested image AND its status (restart count moves).
			a202JSONResponse(pod("registry.example/app:second", "registry.example/sidecar:second", 7)),
			// Second get: identical to the first one.
			a202JSONResponse(pod("registry.example/app:second", "registry.example/sidecar:second", 7)),
		}
		result, err, transport := a202Collect(t, config, steps)
		if err != nil {
			t.Fatalf("collect: %v", err)
		}
		if transport.callCount() != 3 {
			t.Fatalf("requests = %d", transport.callCount())
		}
		found := false
		for _, comparison := range result.Acquisition.Comparisons {
			if comparison.Code == bundle.CodeStaleStatusSuspected {
				found = true
			}
		}
		if !found {
			t.Fatalf("the moved sidecar erased the pattern of the api container: %+v", result.Acquisition.Comparisons)
		}
	})
	t.Run("disappearing_container_does_not_erase_other_pattern", func(t *testing.T) {
		// The sidecar of the list capture disappears from the first get while the
		// api container keeps its identity, changes its requested image and keeps
		// its whole status tuple. The pair of the api container establishes the
		// pattern, and the disappearance of a foreign container — a container that
		// only exists on one end — neither establishes nor erases it.
		pod := func(apiImage string, withSidecar bool) string {
			sidecarSpec := ""
			sidecarStatus := ""
			if withSidecar {
				sidecarSpec = `,{"name":"sidecar","image":"registry.example/sidecar:release"}`
				sidecarStatus = `,{"name":"sidecar","imageID":"sha256:` + strings.Repeat("c", 64) + `","image":"registry.example/sidecar:release","ready":true,"state":{"running":{}},"restartCount":0}`
			}
			return `{"apiVersion":"v1","kind":"Pod","metadata":{"uid":"u1","namespace":"payments","name":"n1"},` +
				`"spec":{"containers":[` +
				`{"name":"api","image":"` + apiImage + `"}` + sidecarSpec +
				`],"initContainers":[],"ephemeralContainers":[]},` +
				`"status":{"containerStatuses":[` +
				`{"name":"api","imageID":"` + a202ImageID + `","image":"` + a202Image + `","ready":true,"state":{"running":{}},"restartCount":0}` + sidecarStatus +
				`],"initContainerStatuses":[],"ephemeralContainerStatuses":[]}}`
		}
		config := a202Config(t)
		steps := []a202RoundTrip{
			// List: both containers in their initial state.
			a202JSONResponse(a202Document(pod(a202Image, true))),
			// First get: the sidecar is gone; only the api requested image changed
			// and the api status tuple stayed identical.
			a202JSONResponse(pod("registry.example/app:second", false)),
			// Second get: identical to the first one.
			a202JSONResponse(pod("registry.example/app:second", false)),
		}
		result, err, transport := a202Collect(t, config, steps)
		if err != nil {
			t.Fatalf("collect: %v", err)
		}
		if transport.callCount() != 3 {
			t.Fatalf("requests = %d", transport.callCount())
		}
		found := false
		for _, comparison := range result.Acquisition.Comparisons {
			if comparison.Code == bundle.CodeStaleStatusSuspected {
				found = true
			}
		}
		if !found {
			t.Fatalf("the disappeared sidecar erased the pattern of the api container: %+v", result.Acquisition.Comparisons)
		}
	})
	t.Run("same_container_spec_status_move_erases_pattern", func(t *testing.T) {
		// The contradicting change belongs to the same container: its requested
		// image and its status tuple move together, so no freshness gap is
		// established for it and the pattern does not fire.
		pod := func(image, statusImage string, restart int) string {
			return `{"apiVersion":"v1","kind":"Pod","metadata":{"uid":"u1","namespace":"payments","name":"n1"},` +
				`"spec":{"containers":[{"name":"api","image":"` + image + `"}],"initContainers":[],"ephemeralContainers":[]},` +
				`"status":{"containerStatuses":[{"name":"api","imageID":"` + a202ImageID + `","image":"` + statusImage + `","ready":true,"state":{"running":{}},"restartCount":` + itoaSmall(restart) + `}],"initContainerStatuses":[],"ephemeralContainerStatuses":[]}}`
		}
		result := a202F07Case(t,
			pod(a202Image, a202Image, 0),
			pod("registry.example/app:second", "registry.example/app:second", 4),
			"")
		for _, comparison := range result.Acquisition.Comparisons {
			if comparison.Code == bundle.CodeStaleStatusSuspected {
				t.Fatalf("a container whose spec and status moved together produced stale: %+v", comparison)
			}
		}
	})
}

// itoaSmall renders a small non-negative integer without importing strconv.
func itoaSmall(value int) string {
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
