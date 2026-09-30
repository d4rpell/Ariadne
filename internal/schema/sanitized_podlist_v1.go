package schema

// The sanitized-podlist-v1 profile is the closed input contract of ADR-0025
// (sanitized PodList ingestion). It admits one strict JSON document already
// sanitized by the operator, with a per-path allowlist, fixed budgets and an
// explicit observation context. Nothing here parses input: this file fixes the
// vocabulary and the limits that the ingest reader enforces.

// SanitizedPodListSelector is the adapter name that selects the profile.
const SanitizedPodListSelector = "sanitized-podlist-v1"

// SanitizedPodListVersion is the only supported input version.
const SanitizedPodListVersion = "1.0"

// SanitizedPodListRedactionPolicy is the only acknowledged redaction policy.
const SanitizedPodListRedactionPolicy = "sanitized-podlist-v1/1.0"

// Hard input budgets of ADR-0025 A.4. Values are counted over the raw bytes of
// the admitted source, never over decoded content, and each guard is checked
// before the buffer or collection that would exceed it grows.
const (
	SanitizedPodListMaxSourceBytes       = 64 * 1024 * 1024
	SanitizedPodListMaxDepth             = 16
	SanitizedPodListMaxTokens            = 2_000_000
	SanitizedPodListMaxItems             = 10_000
	SanitizedPodListMaxPodBytes          = 1 * 1024 * 1024
	SanitizedPodListMaxObjectMembers     = 32
	SanitizedPodListMaxValueRawBytes     = 64 * 1024
	SanitizedPodListMaxKeyRawBytes       = 256
	SanitizedPodListMaxKeyDecodedBytes   = 128
	SanitizedPodListMaxIdentifierBytes   = 1024
	SanitizedPodListMaxSpecEntriesPerPod = 1024
	SanitizedPodListMaxStatusEntriesPod  = 1024
	SanitizedPodListMaxSpecEntriesSource = 100_000
	SanitizedPodListMaxStatusEntriesSour = 100_000
	SanitizedPodListMaxOwnerReferences   = 32
	SanitizedPodListMaxNoProgressReads   = 100
)

// SanitizedPodListRootFields is the allowlist of the root object.
func SanitizedPodListRootFields() []string {
	return []string{"apiVersion", "kind", "metadata", "items"}
}

// SanitizedPodListMetadataFields is the allowlist of the PodList metadata.
func SanitizedPodListMetadataFields() []string {
	return []string{"resourceVersion", "continue", "remainingItemCount"}
}

// SanitizedPodListPodFields is the allowlist of each Pod object.
func SanitizedPodListPodFields() []string {
	return []string{"apiVersion", "kind", "metadata", "spec", "status"}
}

// SanitizedPodListPodMetadataFields is the allowlist of Pod.metadata.
func SanitizedPodListPodMetadataFields() []string {
	return []string{"uid", "namespace", "name", "resourceVersion", "ownerReferences"}
}

// SanitizedPodListOwnerReferenceFields is the allowlist of one owner reference.
func SanitizedPodListOwnerReferenceFields() []string {
	return []string{"apiVersion", "kind", "name", "uid", "controller", "blockOwnerDeletion"}
}

// SanitizedPodListSpecFields is the allowlist of Pod.spec.
func SanitizedPodListSpecFields() []string {
	return []string{"containers", "initContainers", "ephemeralContainers"}
}

// SanitizedPodListSpecContainerFields is the allowlist of one spec container.
func SanitizedPodListSpecContainerFields() []string {
	return []string{"name", "image"}
}

// SanitizedPodListStatusFields is the allowlist of Pod.status.
func SanitizedPodListStatusFields() []string {
	return []string{"containerStatuses", "initContainerStatuses", "ephemeralContainerStatuses"}
}

// SanitizedPodListContainerStatusFields is the allowlist of one container status.
func SanitizedPodListContainerStatusFields() []string {
	return []string{"name", "imageID", "image", "ready", "state", "restartCount"}
}

// SanitizedPodListStateFields is the allowlist of the state object.
func SanitizedPodListStateFields() []string {
	return []string{"waiting", "running", "terminated"}
}

// sanitizedPodListAllowlist maps each admitted object path to its field set.
// The ingest reader walks the input against this table and refuses every key
// that is not present for its exact path: a field admitted elsewhere is not
// admitted here.
var sanitizedPodListAllowlist = map[string][]string{
	"":                                       SanitizedPodListRootFields(),
	"metadata":                               SanitizedPodListMetadataFields(),
	"items[]":                                SanitizedPodListPodFields(),
	"items[].metadata":                       SanitizedPodListPodMetadataFields(),
	"items[].metadata.ownerReferences[]":     SanitizedPodListOwnerReferenceFields(),
	"items[].spec":                           SanitizedPodListSpecFields(),
	"items[].spec.containers[]":              SanitizedPodListSpecContainerFields(),
	"items[].spec.initContainers[]":          SanitizedPodListSpecContainerFields(),
	"items[].spec.ephemeralContainers[]":     SanitizedPodListSpecContainerFields(),
	"items[].status":                         SanitizedPodListStatusFields(),
	"items[].status.containerStatuses[]":     SanitizedPodListContainerStatusFields(),
	"items[].status.initContainerStatuses[]": SanitizedPodListContainerStatusFields(),
	"items[].status.ephemeralContainerStatuses[]":       SanitizedPodListContainerStatusFields(),
	"items[].status.containerStatuses[].state":          SanitizedPodListStateFields(),
	"items[].status.initContainerStatuses[].state":      SanitizedPodListStateFields(),
	"items[].status.ephemeralContainerStatuses[].state": SanitizedPodListStateFields(),
}

// SanitizedPodListAllowlist returns a copy of the allowlist table so callers
// cannot mutate the shared profile.
func SanitizedPodListAllowlist() map[string][]string {
	copied := make(map[string][]string, len(sanitizedPodListAllowlist))
	for path, fields := range sanitizedPodListAllowlist {
		copied[path] = append([]string{}, fields...)
	}
	return copied
}
