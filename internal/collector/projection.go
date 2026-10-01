package collector

import (
	"context"
	"strings"

	"github.com/d4rpell/Ariadne/internal/bundle"
)

// Projection of one API response onto the sanitized PodList grammar
// (ADR-0026 A.6). The collector reads complete API responses, keeps only the
// allowlisted fields, preserves absence, empty and value, materializes TypeMeta
// only where the profile authorizes it, and serializes one compact source per
// admitted response.

// projectedItem carries the identity facts of one projected Pod, kept only to
// validate scope and build the inventory. They are never published by
// themselves.
type projectedItem struct {
	uid       string
	namespace string
	name      string
}

// projectedResponse is the sanitized source of one admitted response plus the
// operational facts needed to validate pagination and scope. The continuation
// token is returned separately and never becomes part of the source.
type projectedResponse struct {
	source              []byte
	items               []projectedItem
	listResourceVersion string
	listRVPresent       bool
	continuation        string
	continuationPresent bool
}

// projectionError carries a closed diagnostic for a projection failure.
type projectionError struct {
	code bundle.CollectionCode
}

func (e projectionError) Error() string { return bundle.CollectionMessage(e.code) }

func projectionFail(code bundle.CollectionCode) error { return projectionError{code: code} }

// projectResponse projects one response body. The operation decides the
// expected response kind and the wrapper of the generated document.
func projectResponse(ctx context.Context, raw []byte, operation operationSpec, budget *budgetState) (projectedResponse, error) {
	// Cooperative cancellation: the projection of a long body checks the global
	// context before it starts, during the walk and before its result is
	// admitted, and never turns a cancelled run into an admitted source.
	if err := ctx.Err(); err != nil {
		return projectedResponse{}, projectionFail(bundle.CodeCancelled)
	}
	scanner := newRawScanner(raw)
	// The scanner consults the run context at every consumed token: a large
	// discarded value cannot be walked to its end after the caller gave up.
	scanner.ctx = ctx
	projector := &projector{ctx: ctx, scanner: scanner, operation: operation, budget: budget}
	if err := projector.projectDocument(); err != nil {
		// A walk stopped by the expired run context is cancelled; a projection
		// failure caused by a budget of the raw structure (depth, tokens or
		// members) is a limit (A.10.2 response_limit); every other refusal stays
		// the malformed-representation code the projector chose.
		if scanner.cancelledHit {
			return projectedResponse{}, projectionFail(bundle.CodeCancelled)
		}
		if scanner.limitHit {
			return projectedResponse{}, projectionFail(bundle.CodeResponseLimit)
		}
		return projectedResponse{}, err
	}
	if err := ctx.Err(); err != nil {
		return projectedResponse{}, projectionFail(bundle.CodeCancelled)
	}
	if !scanner.atEnd() {
		// Trailing data after the single document: concatenated or truncated JSON
		// never becomes a source. A tail the run context stopped is the closed
		// code cancelled, never a malformed representation.
		if scanner.cancelledHit {
			return projectedResponse{}, projectionFail(bundle.CodeCancelled)
		}
		return projectedResponse{}, projectionFail(bundle.CodeResponseInvalid)
	}
	// The final checks run after the whole document, its trailing whitespace
	// included, was consumed: a context that expired while that tail was walked
	// never becomes an admitted source.
	if scanner.cancelledHit {
		return projectedResponse{}, projectionFail(bundle.CodeCancelled)
	}
	if err := ctx.Err(); err != nil {
		return projectedResponse{}, projectionFail(bundle.CodeCancelled)
	}
	return projector.projection, nil
}

// cancelled reports whether the run context expired during the walk, mapping
// the stop to its closed code.
func (p *projector) cancelled() error {
	if p.ctx == nil {
		return nil
	}
	if err := p.ctx.Err(); err != nil {
		return projectionFail(bundle.CodeCancelled)
	}
	return nil
}

// projector walks one raw response with the closed per-path projection.
type projector struct {
	ctx        context.Context
	scanner    *rawScanner
	operation  operationSpec
	budget     *budgetState
	projection projectedResponse
	// depth counts the containers currently open in the raw document, the root
	// object included. It is the absolute depth every discard walk receives, so
	// no field resets or under-counts the nesting of the response.
	depth int
}

// projectDocument walks the root object of one response. A list response is a
// PodList whose items are projected in place; a get response is a single Pod
// that becomes the only element of the generated PodList wrapper. The
// generated document always carries the fixed key order apiVersion, kind,
// metadata, items.
func (p *projector) projectDocument() error {
	if p.operation.verb == "get" {
		item, err := p.projectPodRoot()
		if err != nil {
			return err
		}
		p.projection.source = []byte(`{"apiVersion":"v1","kind":"PodList","items":[` + item + `]}`)
		return nil
	}
	if !p.expect('{') {
		return projectionFail(bundle.CodeResponseInvalid)
	}
	seen := map[string]bool{}
	kindSeen, apiSeen := false, false
	kindOK, apiOK := true, true
	itemsDone, metadataDone := false, false
	var metadata, items string
	p.skipWhitespace()
	for p.peek() != '}' {
		key, err := p.key(seen)
		if err != nil {
			return err
		}
		if !p.expect(':') {
			return projectionFail(bundle.CodeResponseInvalid)
		}
		switch key {
		case "apiVersion":
			_, decoded, err := p.captureString()
			if err != nil {
				return err
			}
			apiSeen = true
			apiOK = decoded == "v1"
		case "kind":
			_, decoded, err := p.captureString()
			if err != nil {
				return err
			}
			kindSeen = true
			kindOK = decoded == "PodList"
		case "metadata":
			if metadataDone {
				return projectionFail(bundle.CodeResponseInvalid)
			}
			metadataDone = true
			projected, err := p.projectListMetadata()
			if err != nil {
				return err
			}
			metadata = projected
		case "items":
			if itemsDone {
				return projectionFail(bundle.CodeResponseInvalid)
			}
			itemsDone = true
			projected, err := p.projectItems()
			if err != nil {
				return err
			}
			items = projected
		default:
			if !p.skipValue() {
				return projectionFail(bundle.CodeResponseInvalid)
			}
		}
		if err := p.memberSeparator(seen); err != nil {
			return err
		}
	}
	if !p.expect('}') {
		return projectionFail(bundle.CodeResponseInvalid)
	}
	if kindSeen && !kindOK || apiSeen && !apiOK {
		return projectionFail(bundle.CodeResponseInvalid)
	}
	// The response itself must declare its own TypeMeta: the derivation of
	// missing TypeMeta is authorized only for elements of a list (A.6.3), never
	// for the root document.
	if !kindSeen || !apiSeen {
		return projectionFail(bundle.CodeResponseInvalid)
	}
	if !itemsDone {
		// A list without items is an invalid representation, not an empty list:
		// an empty list carries an explicit empty array.
		return projectionFail(bundle.CodeResponseInvalid)
	}
	document := `{"apiVersion":"v1","kind":"PodList"`
	if metadata != "" {
		document += `,"metadata":` + metadata
	}
	document += `,"items":` + items + `}`
	p.projection.source = []byte(document)
	return nil
}

// projectListMetadata walks the list metadata object. Only resourceVersion
// survives; continue is used operationally and never retained, and
// remainingItemCount is discarded.
func (p *projector) projectListMetadata() (string, error) {
	if !p.expect('{') {
		return "", projectionFail(bundle.CodeResponseInvalid)
	}
	seen := map[string]bool{}
	p.skipWhitespace()
	empty := p.peek() == '}'
	var resourceVersion string
	rvSeen := false
	for !empty {
		key, err := p.key(seen)
		if err != nil {
			return "", err
		}
		if !p.expect(':') {
			return "", projectionFail(bundle.CodeResponseInvalid)
		}
		switch key {
		case "resourceVersion":
			raw, decoded, err := p.captureString()
			if err != nil {
				return "", err
			}
			resourceVersion = raw
			rvSeen = true
			p.projection.listResourceVersion = decoded
			p.projection.listRVPresent = true
		case "continue":
			_, decoded, err := p.captureString()
			if err != nil {
				return "", err
			}
			if len(decoded) > maxContinuationBytes {
				return "", projectionFail(bundle.CodePaginationInvalid)
			}
			p.projection.continuation = decoded
			p.projection.continuationPresent = decoded != ""
		default:
			// remainingItemCount and any other metadata field are discarded.
			if !p.skipValue() {
				return "", projectionFail(bundle.CodeResponseInvalid)
			}
		}
		if err := p.memberSeparator(seen); err != nil {
			return "", err
		}
		empty = p.peek() == '}'
	}
	if !p.expect('}') {
		return "", projectionFail(bundle.CodeResponseInvalid)
	}
	if !rvSeen {
		return "", nil
	}
	return `{"resourceVersion":` + resourceVersion + `}`, nil
}

// projectItems walks the items array and returns the projected array body.
func (p *projector) projectItems() (string, error) {
	if !p.expect('[') {
		return "", projectionFail(bundle.CodeResponseInvalid)
	}
	p.skipWhitespace()
	empty := p.peek() == ']'
	var items []string
	for !empty {
		// Cooperative cancellation: a long item list must observe an expired
		// context instead of walking every remaining element.
		if err := p.cancelled(); err != nil {
			return "", err
		}
		item, err := p.projectPod()
		if err != nil {
			return "", err
		}
		items = append(items, item)
		if err := p.elementSeparator(); err != nil {
			return "", err
		}
		empty = p.peek() == ']'
	}
	if !p.expect(']') {
		return "", projectionFail(bundle.CodeResponseInvalid)
	}
	return "[" + strings.Join(items, ",") + "]", nil
}

// projectPodRoot walks the root Pod of a get response. Unlike a list element,
// the root document must declare its own TypeMeta: nothing is derived for it.
func (p *projector) projectPodRoot() (string, error) {
	start := p.scanner.pos
	if !p.expect('{') {
		return "", projectionFail(bundle.CodeResponseInvalid)
	}
	seen := map[string]bool{}
	apiSeen, kindSeen := false, false
	apiOK, kindOK := true, true
	identity := projectedItem{}
	var apiRaw, kindRaw, metadata, spec, status string
	metadataDone, specDone, statusDone := false, false, false
	p.skipWhitespace()
	empty := p.peek() == '}'
	for !empty {
		key, err := p.key(seen)
		if err != nil {
			return "", err
		}
		if !p.expect(':') {
			return "", projectionFail(bundle.CodeResponseInvalid)
		}
		switch key {
		case "apiVersion":
			raw, decoded, err := p.captureString()
			if err != nil {
				return "", err
			}
			apiSeen = true
			apiOK = decoded == "v1"
			apiRaw = raw
		case "kind":
			raw, decoded, err := p.captureString()
			if err != nil {
				return "", err
			}
			kindSeen = true
			kindOK = decoded == "Pod"
			kindRaw = raw
		case "metadata":
			if metadataDone {
				return "", projectionFail(bundle.CodeResponseInvalid)
			}
			metadataDone = true
			projected, err := p.projectPodMetadata(&identity)
			if err != nil {
				return "", err
			}
			metadata = projected
		case "spec":
			if specDone {
				return "", projectionFail(bundle.CodeResponseInvalid)
			}
			specDone = true
			projected, err := p.projectSpec()
			if err != nil {
				return "", err
			}
			spec = projected
		case "status":
			if statusDone {
				return "", projectionFail(bundle.CodeResponseInvalid)
			}
			statusDone = true
			projected, err := p.projectStatus()
			if err != nil {
				return "", err
			}
			status = projected
		default:
			if !p.skipValue() {
				return "", projectionFail(bundle.CodeResponseInvalid)
			}
		}
		if err := p.memberSeparator(seen); err != nil {
			return "", err
		}
		empty = p.peek() == '}'
	}
	if !p.expect('}') {
		return "", projectionFail(bundle.CodeResponseInvalid)
	}
	if !apiSeen || !apiOK || !kindSeen || !kindOK {
		return "", projectionFail(bundle.CodeResponseInvalid)
	}
	if p.scanner.pos-start > maxRawPodBytes {
		return "", projectionFail(bundle.CodeResponseLimit)
	}
	if err := p.budget.addPodOccurrence(); err != nil {
		return "", projectionFail(bundle.CodeObjectLimit)
	}
	p.projection.items = append(p.projection.items, identity)
	parts := []string{`"apiVersion":` + apiRaw, `"kind":` + kindRaw}
	if metadataDone {
		parts = append(parts, `"metadata":`+metadata)
	}
	if specDone {
		parts = append(parts, `"spec":`+spec)
	}
	if statusDone {
		parts = append(parts, `"status":`+status)
	}
	return "{" + strings.Join(parts, ",") + "}", nil
}

// projectPod walks one Pod object and returns its projected representation.
func (p *projector) projectPod() (string, error) {
	start := p.scanner.pos
	if !p.expect('{') {
		return "", projectionFail(bundle.CodeResponseInvalid)
	}
	seen := map[string]bool{}
	apiSeen, kindSeen := false, false
	apiOK, kindOK := true, true
	identity := projectedItem{}
	var apiRaw, kindRaw, metadata, spec, status string
	metadataDone, specDone, statusDone := false, false, false
	p.skipWhitespace()
	empty := p.peek() == '}'
	for !empty {
		key, err := p.key(seen)
		if err != nil {
			return "", err
		}
		if !p.expect(':') {
			return "", projectionFail(bundle.CodeResponseInvalid)
		}
		switch key {
		case "apiVersion":
			raw, decoded, err := p.captureString()
			if err != nil {
				return "", err
			}
			apiSeen = true
			apiOK = decoded == "v1"
			apiRaw = raw
		case "kind":
			raw, decoded, err := p.captureString()
			if err != nil {
				return "", err
			}
			kindSeen = true
			kindOK = decoded == "Pod"
			kindRaw = raw
		case "metadata":
			if metadataDone {
				return "", projectionFail(bundle.CodeResponseInvalid)
			}
			metadataDone = true
			projected, err := p.projectPodMetadata(&identity)
			if err != nil {
				return "", err
			}
			metadata = projected
		case "spec":
			if specDone {
				return "", projectionFail(bundle.CodeResponseInvalid)
			}
			specDone = true
			projected, err := p.projectSpec()
			if err != nil {
				return "", err
			}
			spec = projected
		case "status":
			if statusDone {
				return "", projectionFail(bundle.CodeResponseInvalid)
			}
			statusDone = true
			projected, err := p.projectStatus()
			if err != nil {
				return "", err
			}
			status = projected
		default:
			if !p.skipValue() {
				return "", projectionFail(bundle.CodeResponseInvalid)
			}
		}
		if err := p.memberSeparator(seen); err != nil {
			return "", err
		}
		empty = p.peek() == '}'
	}
	if !p.expect('}') {
		return "", projectionFail(bundle.CodeResponseInvalid)
	}
	if apiSeen && !apiOK || kindSeen && !kindOK {
		// An explicit contradiction of the requested resource is never repaired.
		return "", projectionFail(bundle.CodeResponseInvalid)
	}
	if p.scanner.pos-start > maxRawPodBytes {
		return "", projectionFail(bundle.CodeResponseLimit)
	}
	if err := p.budget.addPodOccurrence(); err != nil {
		return "", projectionFail(bundle.CodeObjectLimit)
	}
	p.projection.items = append(p.projection.items, identity)
	parts := []string{}
	if apiSeen {
		parts = append(parts, `"apiVersion":`+apiRaw)
	} else {
		// TypeMeta of a list element is materialized from the endpoint and the
		// validated response type: bounded derived context, never identity.
		parts = append(parts, `"apiVersion":"v1"`)
	}
	if kindSeen {
		parts = append(parts, `"kind":`+kindRaw)
	} else {
		parts = append(parts, `"kind":"Pod"`)
	}
	if metadataDone {
		parts = append(parts, `"metadata":`+metadata)
	}
	if specDone {
		parts = append(parts, `"spec":`+spec)
	}
	if statusDone {
		parts = append(parts, `"status":`+status)
	}
	return "{" + strings.Join(parts, ",") + "}", nil
}

// projectPodMetadata walks Pod.metadata and fills the identity facts.
func (p *projector) projectPodMetadata(identity *projectedItem) (string, error) {
	if !p.expect('{') {
		return "", projectionFail(bundle.CodeResponseInvalid)
	}
	seen := map[string]bool{}
	members := map[string]string{}
	ownersDone := false
	p.skipWhitespace()
	empty := p.peek() == '}'
	for !empty {
		key, err := p.key(seen)
		if err != nil {
			return "", err
		}
		if !p.expect(':') {
			return "", projectionFail(bundle.CodeResponseInvalid)
		}
		switch key {
		case "uid":
			raw, decoded, err := p.captureString()
			if err != nil {
				return "", err
			}
			identity.uid = decoded
			members["uid"] = raw
		case "namespace":
			raw, decoded, err := p.captureString()
			if err != nil {
				return "", err
			}
			identity.namespace = decoded
			members["namespace"] = raw
		case "name":
			raw, decoded, err := p.captureString()
			if err != nil {
				return "", err
			}
			identity.name = decoded
			members["name"] = raw
		case "resourceVersion":
			raw, _, err := p.captureString()
			if err != nil {
				return "", err
			}
			members["resourceVersion"] = raw
		case "ownerReferences":
			if ownersDone {
				return "", projectionFail(bundle.CodeResponseInvalid)
			}
			ownersDone = true
			projected, err := p.projectOwnerReferences()
			if err != nil {
				return "", err
			}
			members["ownerReferences"] = projected
		default:
			// labels, annotations, managedFields and generation are discarded.
			if !p.skipValue() {
				return "", projectionFail(bundle.CodeResponseInvalid)
			}
		}
		if err := p.memberSeparator(seen); err != nil {
			return "", err
		}
		empty = p.peek() == '}'
	}
	if !p.expect('}') {
		return "", projectionFail(bundle.CodeResponseInvalid)
	}
	return orderMembers(members, []string{"uid", "namespace", "name", "resourceVersion", "ownerReferences"}), nil
}

// projectOwnerReferences walks the owner reference array, kept as context only.
func (p *projector) projectOwnerReferences() (string, error) {
	if !p.expect('[') {
		return "", projectionFail(bundle.CodeResponseInvalid)
	}
	p.skipWhitespace()
	empty := p.peek() == ']'
	var owners []string
	for !empty {
		owner, err := p.projectOwnerReference()
		if err != nil {
			return "", err
		}
		owners = append(owners, owner)
		if err := p.elementSeparator(); err != nil {
			return "", err
		}
		empty = p.peek() == ']'
	}
	if !p.expect(']') {
		return "", projectionFail(bundle.CodeResponseInvalid)
	}
	return "[" + strings.Join(owners, ",") + "]", nil
}

// projectOwnerReference walks one owner reference object.
func (p *projector) projectOwnerReference() (string, error) {
	if !p.expect('{') {
		return "", projectionFail(bundle.CodeResponseInvalid)
	}
	seen := map[string]bool{}
	members := map[string]string{}
	p.skipWhitespace()
	empty := p.peek() == '}'
	for !empty {
		key, err := p.key(seen)
		if err != nil {
			return "", err
		}
		if !p.expect(':') {
			return "", projectionFail(bundle.CodeResponseInvalid)
		}
		switch key {
		case "apiVersion", "kind", "name", "uid":
			raw, _, err := p.captureString()
			if err != nil {
				return "", err
			}
			members[key] = raw
		case "controller", "blockOwnerDeletion":
			raw, _, err := p.captureBool()
			if err != nil {
				return "", err
			}
			members[key] = raw
		default:
			if !p.skipValue() {
				return "", projectionFail(bundle.CodeResponseInvalid)
			}
		}
		if err := p.memberSeparator(seen); err != nil {
			return "", err
		}
		empty = p.peek() == '}'
	}
	if !p.expect('}') {
		return "", projectionFail(bundle.CodeResponseInvalid)
	}
	return orderMembers(members, []string{"apiVersion", "kind", "name", "uid", "controller", "blockOwnerDeletion"}), nil
}

// projectSpec walks Pod.spec, keeping the three container categories.
func (p *projector) projectSpec() (string, error) {
	if !p.expect('{') {
		return "", projectionFail(bundle.CodeResponseInvalid)
	}
	seen := map[string]bool{}
	members := map[string]string{}
	done := map[string]bool{}
	p.skipWhitespace()
	empty := p.peek() == '}'
	for !empty {
		key, err := p.key(seen)
		if err != nil {
			return "", err
		}
		if !p.expect(':') {
			return "", projectionFail(bundle.CodeResponseInvalid)
		}
		switch key {
		case "containers", "initContainers", "ephemeralContainers":
			if done[key] {
				return "", projectionFail(bundle.CodeResponseInvalid)
			}
			done[key] = true
			projected, err := p.projectSpecContainers()
			if err != nil {
				return "", err
			}
			members[key] = projected
		default:
			// serviceAccountName, nodeName, volumes, tolerations and every other
			// spec field are discarded structurally.
			if !p.skipValue() {
				return "", projectionFail(bundle.CodeResponseInvalid)
			}
		}
		if err := p.memberSeparator(seen); err != nil {
			return "", err
		}
		empty = p.peek() == '}'
	}
	if !p.expect('}') {
		return "", projectionFail(bundle.CodeResponseInvalid)
	}
	return orderMembers(members, []string{"containers", "initContainers", "ephemeralContainers"}), nil
}

// projectSpecContainers walks one spec container array.
func (p *projector) projectSpecContainers() (string, error) {
	if !p.expect('[') {
		return "", projectionFail(bundle.CodeResponseInvalid)
	}
	p.skipWhitespace()
	empty := p.peek() == ']'
	var containers []string
	for !empty {
		container, err := p.projectSpecContainer()
		if err != nil {
			return "", err
		}
		containers = append(containers, container)
		if err := p.elementSeparator(); err != nil {
			return "", err
		}
		empty = p.peek() == ']'
	}
	if !p.expect(']') {
		return "", projectionFail(bundle.CodeResponseInvalid)
	}
	return "[" + strings.Join(containers, ",") + "]", nil
}

// projectSpecContainer walks one declared container: name and image only.
func (p *projector) projectSpecContainer() (string, error) {
	if !p.expect('{') {
		return "", projectionFail(bundle.CodeResponseInvalid)
	}
	seen := map[string]bool{}
	members := map[string]string{}
	p.skipWhitespace()
	empty := p.peek() == '}'
	for !empty {
		key, err := p.key(seen)
		if err != nil {
			return "", err
		}
		if !p.expect(':') {
			return "", projectionFail(bundle.CodeResponseInvalid)
		}
		switch key {
		case "name", "image":
			raw, _, err := p.captureString()
			if err != nil {
				return "", err
			}
			members[key] = raw
		default:
			// env, envFrom, command, args, ports, resources, volumeMounts and
			// every other declared field are discarded.
			if !p.skipValue() {
				return "", projectionFail(bundle.CodeResponseInvalid)
			}
		}
		if err := p.memberSeparator(seen); err != nil {
			return "", err
		}
		empty = p.peek() == '}'
	}
	if !p.expect('}') {
		return "", projectionFail(bundle.CodeResponseInvalid)
	}
	return orderMembers(members, []string{"name", "image"}), nil
}

// projectStatus walks Pod.status, keeping the three status categories.
func (p *projector) projectStatus() (string, error) {
	if !p.expect('{') {
		return "", projectionFail(bundle.CodeResponseInvalid)
	}
	seen := map[string]bool{}
	members := map[string]string{}
	done := map[string]bool{}
	p.skipWhitespace()
	empty := p.peek() == '}'
	for !empty {
		key, err := p.key(seen)
		if err != nil {
			return "", err
		}
		if !p.expect(':') {
			return "", projectionFail(bundle.CodeResponseInvalid)
		}
		switch key {
		case "containerStatuses", "initContainerStatuses", "ephemeralContainerStatuses":
			if done[key] {
				return "", projectionFail(bundle.CodeResponseInvalid)
			}
			done[key] = true
			projected, err := p.projectContainerStatuses()
			if err != nil {
				return "", err
			}
			members[key] = projected
		default:
			// phase, conditions, podIP, hostIP, startTime, message and every other
			// status field are discarded.
			if !p.skipValue() {
				return "", projectionFail(bundle.CodeResponseInvalid)
			}
		}
		if err := p.memberSeparator(seen); err != nil {
			return "", err
		}
		empty = p.peek() == '}'
	}
	if !p.expect('}') {
		return "", projectionFail(bundle.CodeResponseInvalid)
	}
	return orderMembers(members, []string{"containerStatuses", "initContainerStatuses", "ephemeralContainerStatuses"}), nil
}

// projectContainerStatuses walks one status container array.
func (p *projector) projectContainerStatuses() (string, error) {
	if !p.expect('[') {
		return "", projectionFail(bundle.CodeResponseInvalid)
	}
	p.skipWhitespace()
	empty := p.peek() == ']'
	var statuses []string
	for !empty {
		status, err := p.projectContainerStatus()
		if err != nil {
			return "", err
		}
		statuses = append(statuses, status)
		if err := p.elementSeparator(); err != nil {
			return "", err
		}
		empty = p.peek() == ']'
	}
	if !p.expect(']') {
		return "", projectionFail(bundle.CodeResponseInvalid)
	}
	return "[" + strings.Join(statuses, ",") + "]", nil
}

// projectContainerStatus walks one container status: name, imageID, image,
// ready, state and restartCount only. state is transformed to its category
// object; the rest of the observed details are discarded.
func (p *projector) projectContainerStatus() (string, error) {
	if !p.expect('{') {
		return "", projectionFail(bundle.CodeResponseInvalid)
	}
	seen := map[string]bool{}
	members := map[string]string{}
	p.skipWhitespace()
	empty := p.peek() == '}'
	for !empty {
		key, err := p.key(seen)
		if err != nil {
			return "", err
		}
		if !p.expect(':') {
			return "", projectionFail(bundle.CodeResponseInvalid)
		}
		switch key {
		case "name", "imageID", "image":
			raw, _, err := p.captureString()
			if err != nil {
				return "", err
			}
			members[key] = raw
		case "ready":
			raw, _, err := p.captureBool()
			if err != nil {
				return "", err
			}
			members[key] = raw
		case "restartCount":
			raw, err := p.captureNumber()
			if err != nil {
				return "", err
			}
			members[key] = raw
		case "state":
			projected, err := p.projectState()
			if err != nil {
				return "", err
			}
			members[key] = projected
		default:
			// containerID, started, lastState, allocatedResources and every other
			// observed detail are discarded.
			if !p.skipValue() {
				return "", projectionFail(bundle.CodeResponseInvalid)
			}
		}
		if err := p.memberSeparator(seen); err != nil {
			return "", err
		}
		empty = p.peek() == '}'
	}
	if !p.expect('}') {
		return "", projectionFail(bundle.CodeResponseInvalid)
	}
	return orderMembers(members, []string{"name", "imageID", "image", "ready", "state", "restartCount"}), nil
}

// projectState transforms one state object into its admitted category object:
// the category survives as an empty object, and every nested detail is
// discarded.
func (p *projector) projectState() (string, error) {
	if !p.expect('{') {
		return "", projectionFail(bundle.CodeResponseInvalid)
	}
	seen := map[string]bool{}
	present := map[string]bool{}
	p.skipWhitespace()
	empty := p.peek() == '}'
	for !empty {
		key, err := p.key(seen)
		if err != nil {
			return "", err
		}
		if !p.expect(':') {
			return "", projectionFail(bundle.CodeResponseInvalid)
		}
		switch key {
		case "waiting", "running", "terminated":
			// The category value must be an object; its details never survive.
			if !p.expect('{') {
				return "", projectionFail(bundle.CodeResponseInvalid)
			}
			if err := p.skipObjectBody(); err != nil {
				return "", err
			}
			present[key] = true
		default:
			if !p.skipValue() {
				return "", projectionFail(bundle.CodeResponseInvalid)
			}
		}
		if err := p.memberSeparator(seen); err != nil {
			return "", err
		}
		empty = p.peek() == '}'
	}
	if !p.expect('}') {
		return "", projectionFail(bundle.CodeResponseInvalid)
	}
	parts := []string{}
	for _, category := range []string{"waiting", "running", "terminated"} {
		if present[category] {
			parts = append(parts, `"`+category+`":{}`)
		}
	}
	return "{" + strings.Join(parts, ",") + "}", nil
}

// skipObjectBody walks an already-open object until its closing brace,
// discarding every member.
func (p *projector) skipObjectBody() error {
	seen := map[string]bool{}
	p.skipWhitespace()
	if p.peek() == '}' {
		if !p.expect('}') {
			return projectionFail(bundle.CodeResponseInvalid)
		}
		return nil
	}
	for {
		if _, err := p.key(seen); err != nil {
			return err
		}
		if !p.expect(':') {
			return projectionFail(bundle.CodeResponseInvalid)
		}
		if !p.skipValue() {
			return projectionFail(bundle.CodeResponseInvalid)
		}
		if err := p.memberSeparator(seen); err != nil {
			return err
		}
		if p.peek() == '}' {
			if !p.expect('}') {
				return projectionFail(bundle.CodeResponseInvalid)
			}
			return nil
		}
	}
}

// orderMembers renders the captured members in the canonical key order of the
// allowlist. Only allowlisted keys reach this point.
func orderMembers(members map[string]string, order []string) string {
	parts := make([]string, 0, len(members))
	for _, key := range order {
		if value, present := members[key]; present {
			parts = append(parts, `"`+key+`":`+value)
		}
	}
	return "{" + strings.Join(parts, ",") + "}"
}

// ---- scanner helpers ----

func (p *projector) skipWhitespace() { p.scanner.skipWhitespace() }

func (p *projector) peek() byte {
	if p.scanner.pos >= len(p.scanner.data) {
		return 0
	}
	return p.scanner.data[p.scanner.pos]
}

// expect consumes one punctuation character, enforcing the token budget and
// maintaining the absolute depth of the document.
func (p *projector) expect(character byte) bool {
	p.skipWhitespace()
	if p.scanner.pos >= len(p.scanner.data) || p.scanner.data[p.scanner.pos] != character {
		return false
	}
	if !p.scanner.scanToken() {
		return false
	}
	switch character {
	case '{', '[':
		p.depth++
	case '}', ']':
		if p.depth > 0 {
			p.depth--
		}
	}
	return true
}

// skipValue walks one discarded value at the absolute depth of the document,
// so no field resets or under-counts the nesting of the response. The walk
// consults the run context at every consumed token.
func (p *projector) skipValue() bool { return p.scanner.skipValue(p.depth) }

// key reads one object key, detecting duplicates after escape resolution and
// enforcing the member budget.
func (p *projector) key(seen map[string]bool) (string, error) {
	p.skipWhitespace()
	if p.peek() != '"' {
		return "", projectionFail(bundle.CodeResponseInvalid)
	}
	decoded, ok := p.scanner.scanString(true)
	if !ok {
		return "", projectionFail(bundle.CodeResponseInvalid)
	}
	if seen[decoded] {
		return "", projectionFail(bundle.CodeResponseInvalid)
	}
	if len(seen) >= maxRawObjectMembers {
		return "", projectionFail(bundle.CodeResponseLimit)
	}
	seen[decoded] = true
	return decoded, nil
}

// captureString reads one string value and returns its raw JSON bytes and its
// decoded text. The raw bytes are re-emitted verbatim; the decoded text is
// never published beyond identity facts of the run.
func (p *projector) captureString() (string, string, error) {
	p.skipWhitespace()
	if p.peek() != '"' {
		return "", "", projectionFail(bundle.CodeResponseInvalid)
	}
	start := p.scanner.pos
	decoded, ok := p.scanner.scanString(true)
	if !ok {
		return "", "", projectionFail(bundle.CodeResponseInvalid)
	}
	return string(p.scanner.data[start:p.scanner.pos]), decoded, nil
}

// captureBool reads one boolean value.
func (p *projector) captureBool() (string, bool, error) {
	p.skipWhitespace()
	start := p.scanner.pos
	if p.scanner.pos+4 <= len(p.scanner.data) && string(p.scanner.data[p.scanner.pos:p.scanner.pos+4]) == "true" {
		for index := 0; index < 4; index++ {
			if !p.scanner.scanToken() {
				return "", false, projectionFail(bundle.CodeResponseLimit)
			}
		}
		return string(p.scanner.data[start:p.scanner.pos]), true, nil
	}
	if p.scanner.pos+5 <= len(p.scanner.data) && string(p.scanner.data[p.scanner.pos:p.scanner.pos+5]) == "false" {
		for index := 0; index < 5; index++ {
			if !p.scanner.scanToken() {
				return "", false, projectionFail(bundle.CodeResponseLimit)
			}
		}
		return string(p.scanner.data[start:p.scanner.pos]), false, nil
	}
	return "", false, projectionFail(bundle.CodeResponseInvalid)
}

// captureNumber reads one number token with the general JSON grammar.
func (p *projector) captureNumber() (string, error) {
	p.skipWhitespace()
	start := p.scanner.pos
	if !p.scanner.skipNumber() {
		return "", projectionFail(bundle.CodeResponseInvalid)
	}
	return string(p.scanner.data[start:p.scanner.pos]), nil
}

// memberSeparator consumes the comma or the end of one object body.
func (p *projector) memberSeparator(seen map[string]bool) error {
	p.skipWhitespace()
	switch p.peek() {
	case ',':
		if !p.expect(',') {
			return projectionFail(bundle.CodeResponseInvalid)
		}
		// A comma must be followed by another member: a trailing comma is
		// invalid JSON and is never repaired.
		p.skipWhitespace()
		if p.peek() == '}' {
			return projectionFail(bundle.CodeResponseInvalid)
		}
		return nil
	case '}':
		return nil
	default:
		return projectionFail(bundle.CodeResponseInvalid)
	}
}

// elementSeparator consumes the comma or the end of one array body.
func (p *projector) elementSeparator() error {
	p.skipWhitespace()
	switch p.peek() {
	case ',':
		if !p.expect(',') {
			return projectionFail(bundle.CodeResponseInvalid)
		}
		// A comma must be followed by another element: a trailing comma is
		// invalid JSON and is never repaired.
		p.skipWhitespace()
		if p.peek() == ']' {
			return projectionFail(bundle.CodeResponseInvalid)
		}
		return nil
	case ']':
		return nil
	default:
		return projectionFail(bundle.CodeResponseInvalid)
	}
}
