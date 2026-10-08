package schema

import "testing"

// The sanitized-podlist-v1 profile is a closed contract (ADR-0025 A.3.1, A.3.3
// and A.4). These tests contrast it against the literal values of the ADR so a
// silent edit of selector, version, policy, a budget or an allowlist path fails
// the suite instead of widening the admitted input.

func a201SameFieldSet(got, want []string) bool {
	gotSet := make(map[string]int, len(got))
	for _, field := range got {
		gotSet[field]++
	}
	wantSet := make(map[string]int, len(want))
	for _, field := range want {
		wantSet[field]++
	}
	if len(gotSet) != len(wantSet) {
		return false
	}
	for field, count := range wantSet {
		if gotSet[field] != count {
			return false
		}
	}
	return true
}

func TestA201SchemaProfile(t *testing.T) {
	if SanitizedPodListSelector != "sanitized-podlist-v1" {
		t.Fatalf("SanitizedPodListSelector = %q, want %q", SanitizedPodListSelector, "sanitized-podlist-v1")
	}
	if SanitizedPodListVersion != "1.0" {
		t.Fatalf("SanitizedPodListVersion = %q, want %q", SanitizedPodListVersion, "1.0")
	}
	if SanitizedPodListRedactionPolicy != "sanitized-podlist-v1/1.0" {
		t.Fatalf("SanitizedPodListRedactionPolicy = %q, want %q", SanitizedPodListRedactionPolicy, "sanitized-podlist-v1/1.0")
	}

	limits := []struct {
		name  string
		value int
		want  int
	}{
		{"SanitizedPodListMaxSourceBytes", SanitizedPodListMaxSourceBytes, 67108864},
		{"SanitizedPodListMaxDepth", SanitizedPodListMaxDepth, 16},
		{"SanitizedPodListMaxTokens", SanitizedPodListMaxTokens, 2000000},
		{"SanitizedPodListMaxItems", SanitizedPodListMaxItems, 10000},
		{"SanitizedPodListMaxPodBytes", SanitizedPodListMaxPodBytes, 1048576},
		{"SanitizedPodListMaxObjectMembers", SanitizedPodListMaxObjectMembers, 32},
		{"SanitizedPodListMaxValueRawBytes", SanitizedPodListMaxValueRawBytes, 65536},
		{"SanitizedPodListMaxKeyRawBytes", SanitizedPodListMaxKeyRawBytes, 256},
		{"SanitizedPodListMaxKeyDecodedBytes", SanitizedPodListMaxKeyDecodedBytes, 128},
		{"SanitizedPodListMaxIdentifierBytes", SanitizedPodListMaxIdentifierBytes, 1024},
		{"SanitizedPodListMaxSpecEntriesPerPod", SanitizedPodListMaxSpecEntriesPerPod, 1024},
		{"SanitizedPodListMaxStatusEntriesPod", SanitizedPodListMaxStatusEntriesPod, 1024},
		{"SanitizedPodListMaxSpecEntriesSource", SanitizedPodListMaxSpecEntriesSource, 100000},
		{"SanitizedPodListMaxStatusEntriesSour", SanitizedPodListMaxStatusEntriesSour, 100000},
		{"SanitizedPodListMaxOwnerReferences", SanitizedPodListMaxOwnerReferences, 32},
		{"SanitizedPodListMaxNoProgressReads", SanitizedPodListMaxNoProgressReads, 100},
	}
	for _, limit := range limits {
		if limit.value != limit.want {
			t.Errorf("%s = %d, want %d", limit.name, limit.value, limit.want)
		}
	}

	wantAllowlist := map[string][]string{
		"":                                       {"apiVersion", "kind", "metadata", "items"},
		"metadata":                               {"resourceVersion", "continue", "remainingItemCount"},
		"items[]":                                {"apiVersion", "kind", "metadata", "spec", "status"},
		"items[].metadata":                       {"uid", "namespace", "name", "resourceVersion", "ownerReferences"},
		"items[].metadata.ownerReferences[]":     {"apiVersion", "kind", "name", "uid", "controller", "blockOwnerDeletion"},
		"items[].spec":                           {"containers", "initContainers", "ephemeralContainers"},
		"items[].spec.containers[]":              {"name", "image"},
		"items[].spec.initContainers[]":          {"name", "image"},
		"items[].spec.ephemeralContainers[]":     {"name", "image"},
		"items[].status":                         {"containerStatuses", "initContainerStatuses", "ephemeralContainerStatuses"},
		"items[].status.containerStatuses[]":     {"name", "imageID", "image", "ready", "state", "restartCount"},
		"items[].status.initContainerStatuses[]": {"name", "imageID", "image", "ready", "state", "restartCount"},
		"items[].status.ephemeralContainerStatuses[]":       {"name", "imageID", "image", "ready", "state", "restartCount"},
		"items[].status.containerStatuses[].state":          {"waiting", "running", "terminated"},
		"items[].status.initContainerStatuses[].state":      {"waiting", "running", "terminated"},
		"items[].status.ephemeralContainerStatuses[].state": {"waiting", "running", "terminated"},
	}
	gotAllowlist := SanitizedPodListAllowlist()
	if len(gotAllowlist) != len(wantAllowlist) {
		t.Errorf("allowlist has %d paths, want %d", len(gotAllowlist), len(wantAllowlist))
	}
	for path, wantFields := range wantAllowlist {
		gotFields, found := gotAllowlist[path]
		if !found {
			t.Errorf("allowlist is missing path %q", path)
			continue
		}
		if !a201SameFieldSet(gotFields, wantFields) {
			t.Errorf("allowlist[%q] = %v, want the exact field set %v", path, gotFields, wantFields)
		}
	}
	for path := range gotAllowlist {
		if _, found := wantAllowlist[path]; !found {
			t.Errorf("allowlist has an unexpected path %q", path)
		}
	}

	fieldFunctions := []struct {
		name string
		got  []string
		want []string
	}{
		{"SanitizedPodListRootFields", SanitizedPodListRootFields(), []string{"apiVersion", "kind", "metadata", "items"}},
		{"SanitizedPodListMetadataFields", SanitizedPodListMetadataFields(), []string{"resourceVersion", "continue", "remainingItemCount"}},
		{"SanitizedPodListPodFields", SanitizedPodListPodFields(), []string{"apiVersion", "kind", "metadata", "spec", "status"}},
		{"SanitizedPodListPodMetadataFields", SanitizedPodListPodMetadataFields(), []string{"uid", "namespace", "name", "resourceVersion", "ownerReferences"}},
		{"SanitizedPodListOwnerReferenceFields", SanitizedPodListOwnerReferenceFields(), []string{"apiVersion", "kind", "name", "uid", "controller", "blockOwnerDeletion"}},
		{"SanitizedPodListSpecFields", SanitizedPodListSpecFields(), []string{"containers", "initContainers", "ephemeralContainers"}},
		{"SanitizedPodListSpecContainerFields", SanitizedPodListSpecContainerFields(), []string{"name", "image"}},
		{"SanitizedPodListStatusFields", SanitizedPodListStatusFields(), []string{"containerStatuses", "initContainerStatuses", "ephemeralContainerStatuses"}},
		{"SanitizedPodListContainerStatusFields", SanitizedPodListContainerStatusFields(), []string{"name", "imageID", "image", "ready", "state", "restartCount"}},
		{"SanitizedPodListStateFields", SanitizedPodListStateFields(), []string{"waiting", "running", "terminated"}},
	}
	for _, fieldFunction := range fieldFunctions {
		if !a201SameFieldSet(fieldFunction.got, fieldFunction.want) {
			t.Errorf("%s() = %v, want the exact field set %v", fieldFunction.name, fieldFunction.got, fieldFunction.want)
		}
	}
}

func TestA201SchemaOwnership(t *testing.T) {
	mutated := SanitizedPodListAllowlist()
	independent := SanitizedPodListAllowlist()
	mutated["injected-path"] = []string{"injected"}
	mutated["metadata"][0] = "injected"
	mutated["items[]"] = append(mutated["items[]"], "injected")
	if _, found := independent["injected-path"]; found {
		t.Fatal("a second allowlist call returned the mutated map")
	}
	if independent["metadata"][0] != "resourceVersion" {
		t.Fatalf("mutating one allowlist changed another: metadata[0] = %q", independent["metadata"][0])
	}
	if len(independent["items[]"]) != 5 {
		t.Fatalf("mutating one allowlist changed another: items[] = %v", independent["items[]"])
	}
	reloaded := SanitizedPodListAllowlist()
	if _, found := reloaded["injected-path"]; found {
		t.Fatal("the shared allowlist was mutated through a returned copy")
	}
	if reloaded["metadata"][0] != "resourceVersion" {
		t.Fatalf("the shared allowlist kept a mutation made through a returned copy: metadata[0] = %q", reloaded["metadata"][0])
	}
	if len(reloaded["items[]"]) != 5 {
		t.Fatalf("the shared allowlist kept a mutation made through a returned copy: items[] = %v", reloaded["items[]"])
	}

	fieldFunctions := []struct {
		name string
		fn   func() []string
		want []string
	}{
		{"SanitizedPodListRootFields", SanitizedPodListRootFields, []string{"apiVersion", "kind", "metadata", "items"}},
		{"SanitizedPodListMetadataFields", SanitizedPodListMetadataFields, []string{"resourceVersion", "continue", "remainingItemCount"}},
		{"SanitizedPodListPodFields", SanitizedPodListPodFields, []string{"apiVersion", "kind", "metadata", "spec", "status"}},
		{"SanitizedPodListPodMetadataFields", SanitizedPodListPodMetadataFields, []string{"uid", "namespace", "name", "resourceVersion", "ownerReferences"}},
		{"SanitizedPodListOwnerReferenceFields", SanitizedPodListOwnerReferenceFields, []string{"apiVersion", "kind", "name", "uid", "controller", "blockOwnerDeletion"}},
		{"SanitizedPodListSpecFields", SanitizedPodListSpecFields, []string{"containers", "initContainers", "ephemeralContainers"}},
		{"SanitizedPodListSpecContainerFields", SanitizedPodListSpecContainerFields, []string{"name", "image"}},
		{"SanitizedPodListStatusFields", SanitizedPodListStatusFields, []string{"containerStatuses", "initContainerStatuses", "ephemeralContainerStatuses"}},
		{"SanitizedPodListContainerStatusFields", SanitizedPodListContainerStatusFields, []string{"name", "imageID", "image", "ready", "state", "restartCount"}},
		{"SanitizedPodListStateFields", SanitizedPodListStateFields, []string{"waiting", "running", "terminated"}},
	}
	for _, fieldFunction := range fieldFunctions {
		first := fieldFunction.fn()
		second := fieldFunction.fn()
		if first[0] == "injected" {
			t.Fatalf("%s() returned an already injected slice", fieldFunction.name)
		}
		first[0] = "injected"
		_ = append(first, "injected")
		if !a201SameFieldSet(second, fieldFunction.want) {
			t.Fatalf("two %s() calls share mutable state: second = %v, want %v", fieldFunction.name, second, fieldFunction.want)
		}
		reloaded := fieldFunction.fn()
		if !a201SameFieldSet(reloaded, fieldFunction.want) {
			t.Fatalf("%s() kept a mutation made through a returned slice: %v, want %v", fieldFunction.name, reloaded, fieldFunction.want)
		}
	}
}
