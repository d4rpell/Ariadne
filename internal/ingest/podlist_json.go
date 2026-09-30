package ingest

import (
	"github.com/d4rpell/Ariadne/internal/schema"
)

// Private structural walk of the sanitized PodList profile (ADR-0025 A.3, A.4,
// A.5.2, A.10.3 §3–§7). The walk is strict JSON: keys are validated by path,
// duplicates and the allowlist are resolved before the value is examined, and
// every budget is checked before the bytes or collections that would exceed it
// grow. Nothing here decodes a rejected value or interprets a Pod: the typed
// semantics live in the validation stage.

// podListValueKind is the JSON shape of one scanned value.
type podListValueKind uint8

const (
	podListValueObject podListValueKind = iota
	podListValueArray
	podListValueString
	podListValueNumber
	podListValueBool
	podListValueNull
)

// podListValue is one scanned JSON value with its original byte interval and,
// for objects, its members in document order.
type podListValue struct {
	Kind     podListValueKind
	Offset   uint64
	End      uint64
	Text     string
	Digits   string
	Bool     bool
	Members  []podListMember
	Elements []podListValue
}

// podListMember is one object member: decoded key, opening quote and value.
type podListMember struct {
	Key       string
	KeyOffset uint64
	Value     podListValue
}

// member returns one member of an object value. Members are compared by their
// decoded key, exactly as the duplicate pass resolved them.
func (value podListValue) member(name string) (podListValue, bool) {
	for _, member := range value.Members {
		if member.Key == name {
			return member.Value, true
		}
	}
	return podListValue{}, false
}

// podListDocument is the structurally admitted document: the root object and the
// items array, when it is an array. A rejected source never reaches this type.
type podListDocument struct {
	Root        podListValue
	RootOffset  uint64
	Items       []podListValue
	ItemsOffset uint64
}

// podListAllowlistPaths is the per-path allowlist the walk enforces, built once
// from the published schema table so the reader and the profile cannot drift
// apart silently.
var podListAllowlistPaths = func() map[string]map[string]bool {
	paths := map[string]map[string]bool{}
	for path, fields := range schema.SanitizedPodListAllowlist() {
		admitted := make(map[string]bool, len(fields))
		for _, field := range fields {
			admitted[field] = true
		}
		paths[path] = admitted
	}
	return paths
}()

// podListAllowedKeys returns the admitted keys of one object path. A path the
// profile does not enumerate admits no key at all: a state variant, whose value
// must be the empty object, rejects every member this way.
func podListAllowedKeys(path string) map[string]bool {
	return podListAllowlistPaths[path]
}

// podListScanner walks one source. The byte slice is the complete admitted
// source; positions are raw byte offsets, never indices into decoded text.
type podListScanner struct {
	data   []byte
	pos    int
	tokens uint64

	specPerPod      uint64
	statusPerPod    uint64
	specPerSource   uint64
	statusPerSource uint64
	ownersPerPod    uint64

	// podStart is the opening brace of the Pod being walked, or -1.
	podStart int64
}

func newPodListScanner(data []byte) *podListScanner {
	return &podListScanner{data: data, podStart: -1}
}

func (s *podListScanner) skipSpace() {
	for s.pos < len(s.data) {
		switch s.data[s.pos] {
		case ' ', '\t', '\n', '\r':
			s.pos++
		default:
			return
		}
	}
}

// scanDocument walks the complete source. The BOM is refused before any other
// examination; trailing content after the root value is refused at its own byte.
func (s *podListScanner) scanDocument() (*podListDocument, *PodListError) {
	if len(s.data) >= 3 && s.data[0] == 0xEF && s.data[1] == 0xBB && s.data[2] == 0xBF {
		return nil, failure(PodListCodeBOM, 0)
	}
	root, problem := s.scanValue("", 1)
	if problem != nil {
		return nil, problem
	}
	if root.Kind != podListValueObject {
		// The profile admits the Kubernetes object form only: a scalar or array
		// root is a wrong-typed document, not a parseable one.
		return nil, failure(PodListCodeInvalidFieldType, root.Offset)
	}
	s.skipSpace()
	if s.pos != len(s.data) {
		return nil, failure(PodListCodeInvalidJSON, uint64(s.pos))
	}
	document := &podListDocument{Root: root, RootOffset: root.Offset}
	if items, present := root.member("items"); present && items.Kind == podListValueArray {
		document.Items = items.Elements
		document.ItemsOffset = items.Offset
	}
	return document, nil
}

// scanValue scans one JSON value of any shape at the given path and depth. The
// path is the object path whose allowlist applies to this value's members;
// arrays append "[]" so their elements are checked against the element path.
func (s *podListScanner) scanValue(path string, depth int) (podListValue, *PodListError) {
	s.skipSpace()
	offset := uint64(s.pos)
	if problem := s.checkPodBudget(offset); problem != nil {
		return podListValue{}, problem
	}
	if s.pos >= len(s.data) {
		return podListValue{}, failure(PodListCodeInvalidJSON, uint64(len(s.data)))
	}
	if depth > schema.SanitizedPodListMaxDepth {
		return podListValue{}, failure(PodListCodeDepthLimit, offset)
	}
	character := s.data[s.pos]
	switch {
	case character == '{':
		return s.scanObject(path, depth, offset)
	case character == '[':
		return s.scanArray(path, depth, offset)
	case character == '"':
		if problem := s.countToken(offset); problem != nil {
			return podListValue{}, problem
		}
		text, problem := s.scanStringToken(offset, uint64(schema.SanitizedPodListMaxValueRawBytes), 0, PodListCodeStringLimit)
		if problem != nil {
			return podListValue{}, problem
		}
		return podListValue{Kind: podListValueString, Offset: offset, End: uint64(s.pos - 1), Text: text}, nil
	case character == 't' || character == 'f':
		return s.scanBool(offset, character == 't')
	case character == 'n':
		return s.scanNull(offset)
	case character == '-' || character == '+' || character == '.' || (character >= '0' && character <= '9'):
		return s.scanNumber(offset)
	default:
		return podListValue{}, failure(PodListCodeInvalidJSON, offset)
	}
}

// scanObject scans one object: member budget first, then per-key budgets,
// lexical checks, duplicate resolution and the allowlist, and only then the
// value. The Pod interval and the per-Pod collection counters are tracked while
// the Pod is open.
func (s *podListScanner) scanObject(path string, depth int, offset uint64) (podListValue, *PodListError) {
	if problem := s.countToken(offset); problem != nil {
		return podListValue{}, problem
	}
	value := podListValue{Kind: podListValueObject, Offset: offset}
	admitted := podListAllowedKeys(path)
	podElement := path == "items[]"
	if podElement {
		s.podStart = int64(offset)
		s.specPerPod, s.statusPerPod, s.ownersPerPod = 0, 0, 0
	}
	s.pos++
	s.skipSpace()
	if s.pos < len(s.data) && s.data[s.pos] == '}' {
		// The closing brace is an advance point like any other: the Pod budget is checked
		// before it is consumed, even when the object is empty and will be refused later
		// for a missing field.
		if problem := s.checkPodBudget(uint64(s.pos)); problem != nil {
			return podListValue{}, problem
		}
		if problem := s.closeObject(&value); problem != nil {
			return podListValue{}, problem
		}
		return s.finishObject(path, value)
	}
	seen := make(map[string]bool, 8)
	for {
		s.skipSpace()
		if problem := s.checkPodBudget(uint64(s.pos)); problem != nil {
			return podListValue{}, problem
		}
		if s.pos >= len(s.data) {
			return podListValue{}, failure(PodListCodeInvalidJSON, uint64(len(s.data)))
		}
		if uint64(len(value.Members)) >= schema.SanitizedPodListMaxObjectMembers {
			return podListValue{}, failure(PodListCodeMemberLimit, uint64(s.pos))
		}
		if s.data[s.pos] != '"' {
			return podListValue{}, failure(PodListCodeInvalidJSON, uint64(s.pos))
		}
		keyOffset := uint64(s.pos)
		if problem := s.countToken(keyOffset); problem != nil {
			return podListValue{}, problem
		}
		key, problem := s.scanStringToken(keyOffset, uint64(schema.SanitizedPodListMaxKeyRawBytes), uint64(schema.SanitizedPodListMaxKeyDecodedBytes), PodListCodeKeyLimit)
		if problem != nil {
			return podListValue{}, problem
		}
		if seen[key] {
			return podListValue{}, failure(PodListCodeDuplicateKey, keyOffset)
		}
		seen[key] = true
		if !admitted[key] {
			// The value is never examined: the key alone rejects the source.
			return podListValue{}, failure(PodListCodeFieldNotAllowed, keyOffset)
		}
		s.skipSpace()
		if s.pos >= len(s.data) {
			return podListValue{}, failure(PodListCodeInvalidJSON, uint64(len(s.data)))
		}
		if s.data[s.pos] != ':' {
			return podListValue{}, failure(PodListCodeInvalidJSON, uint64(s.pos))
		}
		if problem := s.countToken(uint64(s.pos)); problem != nil {
			return podListValue{}, problem
		}
		s.pos++
		childPath := key
		if path != "" {
			childPath = path + "." + key
		}
		member, problem := s.scanValue(childPath, depth+1)
		if problem != nil {
			return podListValue{}, problem
		}
		value.Members = append(value.Members, podListMember{Key: key, KeyOffset: keyOffset, Value: member})
		s.skipSpace()
		if problem := s.checkPodBudget(uint64(s.pos)); problem != nil {
			return podListValue{}, problem
		}
		if s.pos >= len(s.data) {
			return podListValue{}, failure(PodListCodeInvalidJSON, uint64(len(s.data)))
		}
		switch s.data[s.pos] {
		case ',':
			if problem := s.countToken(uint64(s.pos)); problem != nil {
				return podListValue{}, problem
			}
			s.pos++
		case '}':
			if problem := s.closeObject(&value); problem != nil {
				return podListValue{}, problem
			}
			return s.finishObject(path, value)
		default:
			return podListValue{}, failure(PodListCodeInvalidJSON, uint64(s.pos))
		}
	}
}

func (s *podListScanner) closeObject(value *podListValue) *PodListError {
	if problem := s.countToken(uint64(s.pos)); problem != nil {
		return problem
	}
	s.pos++
	value.End = uint64(s.pos - 1)
	return nil
}

// finishObject applies the close-time admission of the object that just ended:
// the root document, the PodList metadata, each Pod element of items and every
// Pod nested elsewhere. A failure is fatal and no prefix is published.
func (s *podListScanner) finishObject(path string, value podListValue) (podListValue, *PodListError) {
	switch path {
	case "":
		if problem := admitPodListRoot(value); problem != nil {
			return podListValue{}, problem
		}
	case "metadata":
		if problem := admitPodListMetadata(value); problem != nil {
			return podListValue{}, problem
		}
	case "items[]":
		// The Pod interval ends with its closing brace; the element admission was
		// already applied by the items array.
		s.podStart = -1
	}
	return value, nil
}

// scanArray scans one array. The element budgets are checked at the element
// start, before its type is known: an element that exceeds a budget is reported
// even when it would have been rejected as a value afterwards.
func (s *podListScanner) scanArray(path string, depth int, offset uint64) (podListValue, *PodListError) {
	if problem := s.countToken(offset); problem != nil {
		return podListValue{}, problem
	}
	value := podListValue{Kind: podListValueArray, Offset: offset}
	elementPath := path + "[]"
	items := path == "items"
	s.pos++
	s.skipSpace()
	if s.pos < len(s.data) && s.data[s.pos] == ']' {
		if problem := s.countToken(uint64(s.pos)); problem != nil {
			return podListValue{}, problem
		}
		s.pos++
		value.End = uint64(s.pos - 1)
		return value, nil
	}
	for {
		s.skipSpace()
		if problem := s.checkPodBudget(uint64(s.pos)); problem != nil {
			return podListValue{}, problem
		}
		if s.pos >= len(s.data) {
			return podListValue{}, failure(PodListCodeInvalidJSON, uint64(len(s.data)))
		}
		if items && uint64(len(value.Elements)) >= schema.SanitizedPodListMaxItems {
			return podListValue{}, failure(PodListCodeItemLimit, uint64(s.pos))
		}
		if problem := s.countCollectionEntry(elementPath, uint64(s.pos)); problem != nil {
			return podListValue{}, problem
		}
		element, problem := s.scanValue(elementPath, depth+1)
		if problem != nil {
			return podListValue{}, problem
		}
		if items {
			// Each element of items is admitted at its own close, before the root
			// object is closed: a foreign or malformed element invalidates the
			// document instead of being filtered or rejected as a Pod.
			if problem := admitPodListElement(element); problem != nil {
				return podListValue{}, problem
			}
		}
		value.Elements = append(value.Elements, element)
		s.skipSpace()
		if problem := s.checkPodBudget(uint64(s.pos)); problem != nil {
			return podListValue{}, problem
		}
		if s.pos >= len(s.data) {
			return podListValue{}, failure(PodListCodeInvalidJSON, uint64(len(s.data)))
		}
		switch s.data[s.pos] {
		case ',':
			if problem := s.countToken(uint64(s.pos)); problem != nil {
				return podListValue{}, problem
			}
			s.pos++
		case ']':
			if problem := s.countToken(uint64(s.pos)); problem != nil {
				return podListValue{}, problem
			}
			s.pos++
			value.End = uint64(s.pos - 1)
			return value, nil
		default:
			return podListValue{}, failure(PodListCodeInvalidJSON, uint64(s.pos))
		}
	}
}

// scanBool scans one boolean literal. A literal that cannot be completed at EOF
// anchors at the total of bytes received; any other mismatch anchors at the byte
// that broke the literal. The Pod budget is checked for every byte the literal
// would consume.
func (s *podListScanner) scanBool(offset uint64, truth bool) (podListValue, *PodListError) {
	word := "false"
	if truth {
		word = "true"
	}
	if problem := s.countToken(offset); problem != nil {
		return podListValue{}, problem
	}
	for index := 0; index < len(word); index++ {
		if s.pos+index >= len(s.data) {
			return podListValue{}, failure(PodListCodeInvalidJSON, uint64(len(s.data)))
		}
		if problem := s.checkPodBudget(uint64(s.pos + index)); problem != nil {
			return podListValue{}, problem
		}
		if s.data[s.pos+index] != word[index] {
			return podListValue{}, failure(PodListCodeInvalidJSON, uint64(s.pos+index))
		}
	}
	s.pos += len(word)
	return podListValue{Kind: podListValueBool, Offset: offset, End: uint64(s.pos - 1), Bool: truth}, nil
}

func (s *podListScanner) scanNull(offset uint64) (podListValue, *PodListError) {
	const word = "null"
	if problem := s.countToken(offset); problem != nil {
		return podListValue{}, problem
	}
	for index := 0; index < len(word); index++ {
		if s.pos+index >= len(s.data) {
			return podListValue{}, failure(PodListCodeInvalidJSON, uint64(len(s.data)))
		}
		if problem := s.checkPodBudget(uint64(s.pos + index)); problem != nil {
			return podListValue{}, problem
		}
		if s.data[s.pos+index] != word[index] {
			return podListValue{}, failure(PodListCodeInvalidJSON, uint64(s.pos+index))
		}
	}
	s.pos += len(word)
	return podListValue{Kind: podListValueNull, Offset: offset, End: uint64(s.pos - 1)}, nil
}

// scanNumber scans one number token. The only admitted grammar is
// `0 | [1-9][0-9]*`: a sign, a leading zero, a fraction or an exponent is
// non-canonical and is refused at the start of the token, including its sign.
// Every byte the token would consume is checked against the Pod budget.
func (s *podListScanner) scanNumber(offset uint64) (podListValue, *PodListError) {
	if problem := s.countToken(offset); problem != nil {
		return podListValue{}, problem
	}
	if character := s.data[s.pos]; character == '-' || character == '+' {
		if s.pos+1 >= len(s.data) || !podListDigit(s.data[s.pos+1]) {
			return podListValue{}, failure(PodListCodeInvalidJSON, offset)
		}
		if problem := s.checkPodBudget(uint64(s.pos + 1)); problem != nil {
			return podListValue{}, problem
		}
		return podListValue{}, failure(PodListCodeNoncanonicalNumber, offset)
	}
	digitsStart := s.pos
	for s.pos < len(s.data) && podListDigit(s.data[s.pos]) {
		if problem := s.checkPodBudget(uint64(s.pos)); problem != nil {
			return podListValue{}, problem
		}
		s.pos++
	}
	if s.pos == digitsStart {
		return podListValue{}, failure(PodListCodeInvalidJSON, offset)
	}
	if s.pos < len(s.data) {
		switch s.data[s.pos] {
		case '.', 'e', 'E':
			if problem := s.checkPodBudget(uint64(s.pos)); problem != nil {
				return podListValue{}, problem
			}
			return podListValue{}, failure(PodListCodeNoncanonicalNumber, offset)
		}
	}
	digits := string(s.data[digitsStart:s.pos])
	if len(digits) > 1 && digits[0] == '0' {
		return podListValue{}, failure(PodListCodeNoncanonicalNumber, offset)
	}
	return podListValue{Kind: podListValueNumber, Offset: offset, End: uint64(s.pos - 1), Digits: digits}, nil
}

func podListDigit(character byte) bool {
	return character >= '0' && character <= '9'
}

// countToken counts one JSON token and enforces the token budget.
func (s *podListScanner) countToken(offset uint64) *PodListError {
	s.tokens++
	if s.tokens > uint64(schema.SanitizedPodListMaxTokens) {
		return failure(PodListCodeTokenLimit, offset)
	}
	return nil
}

// checkPodBudget enforces the raw byte interval of the Pod being walked:
// from its opening brace to its closing brace inclusive.
func (s *podListScanner) checkPodBudget(offset uint64) *PodListError {
	if s.podStart < 0 {
		return nil
	}
	if offset-uint64(s.podStart)+1 > uint64(schema.SanitizedPodListMaxPodBytes) {
		return failure(PodListCodePodLimit, uint64(s.podStart))
	}
	return nil
}

// countCollectionEntry enforces the entry budgets of the spec and status
// categories and of the owner references, per Pod and per source. The anchor is
// the element that exceeds the budget, in the physical order of the document.
func (s *podListScanner) countCollectionEntry(elementPath string, offset uint64) *PodListError {
	switch elementPath {
	case "items[].spec.containers[]", "items[].spec.initContainers[]", "items[].spec.ephemeralContainers[]":
		s.specPerPod++
		s.specPerSource++
		if s.specPerPod > uint64(schema.SanitizedPodListMaxSpecEntriesPerPod) ||
			s.specPerSource > uint64(schema.SanitizedPodListMaxSpecEntriesSource) {
			return failure(PodListCodeCollectionLimit, offset)
		}
	case "items[].status.containerStatuses[]", "items[].status.initContainerStatuses[]", "items[].status.ephemeralContainerStatuses[]":
		s.statusPerPod++
		s.statusPerSource++
		if s.statusPerPod > uint64(schema.SanitizedPodListMaxStatusEntriesPod) ||
			s.statusPerSource > uint64(schema.SanitizedPodListMaxStatusEntriesSour) {
			return failure(PodListCodeCollectionLimit, offset)
		}
	case "items[].metadata.ownerReferences[]":
		s.ownersPerPod++
		if s.ownersPerPod > uint64(schema.SanitizedPodListMaxOwnerReferences) {
			return failure(PodListCodeCollectionLimit, offset)
		}
	}
	return nil
}

// admitPodListRoot applies the close-time admission of the root object in the
// field order of A.3.3: presence first, then type, then the admitted value. The
// optional root metadata must be an object when it exists; a non-object shape is
// refused here because the closed metadata checks only run for real objects.
func admitPodListRoot(root podListValue) *PodListError {
	if problem := admitResourceField(root, "apiVersion", "v1"); problem != nil {
		return problem
	}
	if problem := admitResourceField(root, "kind", "PodList"); problem != nil {
		return problem
	}
	if metadata, present := root.member("metadata"); present && metadata.Kind != podListValueObject {
		return failure(PodListCodeInvalidFieldType, metadata.Offset)
	}
	items, present := root.member("items")
	if !present {
		return failure(PodListCodeMissingRequiredField, root.Offset)
	}
	if items.Kind != podListValueArray {
		return failure(PodListCodeInvalidFieldType, items.Offset)
	}
	return nil
}

// admitPodListElement applies the close-time admission of one items element: a
// Pod is the only admitted resource. The document is refused, never filtered.
func admitPodListElement(element podListValue) *PodListError {
	if element.Kind != podListValueObject {
		return failure(PodListCodeInvalidFieldType, element.Offset)
	}
	if problem := admitResourceField(element, "apiVersion", "v1"); problem != nil {
		return problem
	}
	return admitResourceField(element, "kind", "Pod")
}

func admitResourceField(object podListValue, field, admitted string) *PodListError {
	value, present := object.member(field)
	if !present {
		return failure(PodListCodeMissingRequiredField, object.Offset)
	}
	if value.Kind != podListValueString {
		return failure(PodListCodeInvalidFieldType, value.Offset)
	}
	if value.Text != admitted {
		return failure(PodListCodeUnsupportedResource, value.Offset)
	}
	return nil
}

// admitPodListMetadata applies the close-time admission of the PodList metadata:
// object type, the opaque resource version and the two pagination fields, in the
// field order of A.3.3.
func admitPodListMetadata(metadata podListValue) *PodListError {
	if metadata.Kind != podListValueObject {
		return failure(PodListCodeInvalidFieldType, metadata.Offset)
	}
	if value, present := metadata.member("resourceVersion"); present {
		if value.Kind != podListValueString {
			return failure(PodListCodeInvalidFieldType, value.Offset)
		}
		if uint64(len(value.Text)) > uint64(schema.SanitizedPodListMaxIdentifierBytes) {
			return failure(PodListCodeIdentifierLimit, value.Offset)
		}
		if value.Text != "" && podListWhitespaceSurrounded(value.Text) {
			return failure(PodListCodeInvalidIdentifier, value.Offset)
		}
	}
	if value, present := metadata.member("continue"); present {
		if value.Kind != podListValueString {
			return failure(PodListCodeInvalidFieldType, value.Offset)
		}
		if value.Text != "" {
			return failure(PodListCodePaginationNotSupported, value.Offset)
		}
	}
	if value, present := metadata.member("remainingItemCount"); present {
		if value.Kind != podListValueNumber {
			return failure(PodListCodeInvalidFieldType, value.Offset)
		}
		if value.Digits != "0" {
			return failure(PodListCodePaginationNotSupported, value.Offset)
		}
	}
	return nil
}
