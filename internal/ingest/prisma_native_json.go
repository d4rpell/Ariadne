package ingest

import (
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/d4rpell/Ariadne/internal/schema"
)

// Private JSON reader of ADR-0027 §6.3 and §7.2–§7.5. It admits exactly one
// UTF-8 array of image objects, walks each object against the closed disposition
// table, projects only the conserved members (with the number/redaction
// wrappers) and discards excluded subtrees after validating their structure,
// Unicode, duplicate keys and budgets. encoding/json is deliberately not used.

// nativeMaxNumberRawBytes bounds every JSON number token of §6.2.
const nativeMaxNumberRawBytes = 128

type nativeJSONParser struct {
	data        []byte
	pos         int
	tokens      uint64
	tokenLimit  uint64
	rootItems   uint64
	sourceVulns uint64
	sourcePkgs  uint64
	imagePkgs   uint64
	keyRaw      int
	keyDecoded  int
	stringRaw   int
	// adm carries the acquisition control of the shared admission seam (§3.3).
	// The zero value (no budget, nil Done) reproduces the offline 1.0 path
	// exactly: the F1 limits are already in force and have no extra ceiling.
	adm NativeAdmission
}

// tokenCeiling is the effective lexical-token ceiling: the F1 limit, lowered by
// an additional acquisition budget when one is set.
func (p *nativeJSONParser) tokenCeiling() uint64 {
	limit := p.tokenLimit
	if limit == 0 {
		limit = schema.NativeMaxTokens
	}
	if b := p.adm.Budget.Tokens; b > 0 && b < limit {
		limit = b
	}
	return limit
}

// imageCeiling is the effective per-admission image ceiling.
func (p *nativeJSONParser) imageCeiling() uint64 {
	limit := uint64(schema.NativeMaxRootItems)
	if b := p.adm.Budget.Images; b > 0 && b < limit {
		limit = b
	}
	return limit
}

// findingCeiling and packageCeiling are the effective occurrence ceilings.
func (p *nativeJSONParser) findingCeiling() uint64 {
	limit := uint64(schema.NativeMaxVulnsPerSource)
	if b := p.adm.Budget.Findings; b > 0 && b < limit {
		limit = b
	}
	return limit
}

func (p *nativeJSONParser) packageCeiling() uint64 {
	limit := uint64(schema.NativeMaxPackagesPerSource)
	if b := p.adm.Budget.Packages; b > 0 && b < limit {
		limit = b
	}
	return limit
}

// checkpoint polls the caller's cancellation channel at a bounded point. It is
// O(1). A nil channel means "not cancellable" and is skipped.
func (p *nativeJSONParser) checkpoint() *NativeError {
	if p.adm.Done == nil {
		return nil
	}
	select {
	case <-p.adm.Done:
		return nativeCancelled
	default:
		return nil
	}
}

// Native-per-artifact lexical budgets. The native admission path and the
// derived replay path admit different raw/decoded key and string sizes
// (§6.2 vs §11.9.1), so the parser carries them per call; zero means the
// native budget.
type nativeLexicalLimits struct {
	keyRaw     int
	keyDecoded int
	stringRaw  int
}

func (p *nativeJSONParser) keyRawLimit() int {
	if p.keyRaw > 0 {
		return p.keyRaw
	}
	return schema.NativeMaxKeyRawBytes
}

func (p *nativeJSONParser) keyDecodedLimit() int {
	if p.keyDecoded > 0 {
		return p.keyDecoded
	}
	return schema.NativeMaxKeyDecodedBytes
}

func (p *nativeJSONParser) stringRawLimit() int {
	if p.stringRaw > 0 {
		return p.stringRaw
	}
	return schema.NativeMaxStringRawBytes
}

// tickToken counts one lexeme and enforces the parser's token budget.
func (p *nativeJSONParser) tickToken() *NativeError {
	p.tokens++
	limit := p.tokenLimit
	if limit == 0 {
		limit = schema.NativeMaxTokens
	}
	if p.tokens > limit {
		return p.fail(NativeCodeTokenLimit)
	}
	return nil
}

// parsePrismaNativeJSON admits one native JSON document and returns the derived
// source, or a fatal diagnostic. It is the offline 1.0 entry point: it runs the
// shared admission with no additional acquisition control and finalizes with the
// JSON profile. The original bytes are never retained.
func parsePrismaNativeJSON(data []byte, ctx NativeContext) (NativeSource, *NativeError) {
	draft, err := admitNativeJSON(data, NativeAdmission{})
	if err != nil {
		return NativeSource{}, err
	}
	return draft.Source(jsonProfile(), ctx), nil
}

// admitNativeJSON is the single JSON admission shared by the offline adapters
// and the acquisition connector (§3.3). It validates the document, walks it
// against the closed disposition table, projects the conserved members and
// returns a private draft with numeric accounting. The acquisition control
// lowers the F1 ceilings and polls cancellation at bounded checkpoints; the zero
// control reproduces the 1.0 behaviour byte for byte.
func admitNativeJSON(data []byte, adm NativeAdmission) (NativeDraft, *NativeError) {
	if !utf8.Valid(data) {
		return NativeDraft{}, nativeFailure(NativeCodeInvalidUTF8, NativePhaseAdmission, NativeSpaceNative, 0)
	}
	if len(data) >= 3 && data[0] == 0xEF && data[1] == 0xBB && data[2] == 0xBF {
		return NativeDraft{}, nativeFailure(NativeCodeInvalidJSON, NativePhaseAdmission, NativeSpaceNative, 0)
	}
	p := &nativeJSONParser{data: data, adm: adm}
	p.skipWS()
	if !p.eat('[') {
		return NativeDraft{}, p.fail(NativeCodeInvalidJSON)
	}
	if err := p.tick(); err != nil {
		return NativeDraft{}, err
	}
	imageNode := schema.NativeNode{Kind: schema.NativeObject, Disposition: schema.NativeConserved}
	var records []NativeRecord
	for {
		p.skipWS()
		if p.peek() == ']' {
			p.pos++
			break
		}
		if p.rootItems >= p.imageCeiling() {
			return NativeDraft{}, p.fail(NativeCodeCollectionLimit)
		}
		if err := p.checkpoint(); err != nil {
			return NativeDraft{}, err
		}
		start := p.pos
		p.imagePkgs = 0
		value, err := p.parseProjected("", imageNode, 2)
		if err != nil {
			return NativeDraft{}, err
		}
		if err := checkImageScope(value); err != nil {
			return NativeDraft{}, err
		}
		end := p.pos
		records = append(records, NativeRecord{
			Ordinal:       len(records),
			OriginLocator: NativeOriginLocator("json", len(records), uint64(start), uint64(end)),
			OriginStart:   uint64(start),
			OriginEnd:     uint64(end),
			Data:          value,
		})
		p.rootItems++
		if end-start > schema.NativeMaxImageObjectBytes {
			return NativeDraft{}, p.fail(NativeCodeRecordLimit)
		}
		p.skipWS()
		if p.peek() == ',' {
			p.pos++
			if err := p.tick(); err != nil {
				return NativeDraft{}, err
			}
			p.skipWS()
			if p.peek() == ']' || p.peek() == ',' {
				return NativeDraft{}, p.fail(NativeCodeInvalidJSON)
			}
			continue
		}
		if p.peek() == ']' {
			p.pos++
			if err := p.tick(); err != nil {
				return NativeDraft{}, err
			}
			break
		}
		return NativeDraft{}, p.fail(NativeCodeInvalidJSON)
	}
	p.skipWS()
	if p.pos != len(p.data) {
		return NativeDraft{}, p.fail(NativeCodeInvalidJSON)
	}
	return NativeDraft{
		Format:        "json",
		OriginalBytes: uint64(len(data)),
		Records:       records,
		Accounting: NativeAccounting{
			Tokens:   p.tokens,
			Bytes:    uint64(len(data)),
			Images:   p.rootItems,
			Findings: p.sourceVulns,
			Packages: p.sourcePkgs,
		},
	}, nil
}

// jsonProfile is the JSON profile identity of §4.1.
func jsonProfile() NativeProfile {
	return NativeProfile{
		Selector:         schema.NativeJSONSelector,
		InputVersion:     schema.NativeInputVersion,
		Name:             schema.NativeJSONProfile,
		RedactionPolicy:  schema.NativeRedactionPolicy,
		AdapterSemantics: schema.NativeAdapterSemantics,
	}
}

// csvProfile is the CSV profile identity of §4.1.
func csvProfile() NativeProfile {
	return NativeProfile{
		Selector:         schema.NativeCSVSelector,
		InputVersion:     schema.NativeInputVersion,
		Name:             schema.NativeCSVProfile,
		RedactionPolicy:  schema.NativeRedactionPolicy,
		AdapterSemantics: schema.NativeAdapterSemantics,
	}
}

// checkImageScope enforces the §4.3 report-scope rule on the image `type`.
func checkImageScope(value NativeValue) *NativeError {
	obj, ok := value.(NativeObject)
	if !ok {
		return nativeFailure(NativeCodeInvalidJSON, NativePhaseAdmission, NativeSpaceNative, 0)
	}
	for i, key := range obj.Keys {
		if key != "type" {
			continue
		}
		if s, ok := obj.Values[i].(NativeString); ok && s != "" && string(s) != "image" {
			return nativeFailure(NativeCodeUnsupportedReportScope, NativePhaseAdmission, NativeSpaceNative, 0)
		}
	}
	return nil
}

func (p *nativeJSONParser) fail(code string) *NativeError {
	return nativeFailure(code, NativePhaseAdmission, NativeSpaceNative, uint64(p.pos))
}

// failAt reports a fatal admission diagnostic anchored to an earlier token
// start, so a rejected key points at its opening quote, not at the cursor.
func (p *nativeJSONParser) failAt(offset int, code string) *NativeError {
	return nativeFailure(code, NativePhaseAdmission, NativeSpaceNative, uint64(offset))
}

func (p *nativeJSONParser) peek() byte {
	if p.pos < len(p.data) {
		return p.data[p.pos]
	}
	return 0
}

func (p *nativeJSONParser) eat(b byte) bool {
	if p.pos < len(p.data) && p.data[p.pos] == b {
		p.pos++
		return true
	}
	return false
}

func (p *nativeJSONParser) skipWS() {
	for p.pos < len(p.data) {
		switch p.data[p.pos] {
		case ' ', '\t', '\n', '\r':
			p.pos++
		default:
			return
		}
	}
}

func (p *nativeJSONParser) tick() *NativeError {
	p.tokens++
	if p.tokens > p.tokenCeiling() {
		return p.fail(NativeCodeTokenLimit)
	}
	return p.checkpoint()
}

// parseProjected admits and projects one conserved node. Null is not accepted
// here: an array element must have the indicated type (§7.1); a conserved
// member present with null is handled by parseMember.
func (p *nativeJSONParser) parseProjected(path string, node schema.NativeNode, depth int) (NativeValue, *NativeError) {
	if depth > schema.NativeMaxDepth {
		return nil, p.fail(NativeCodeDepthLimit)
	}
	if node.Disposition == schema.NativeExcludedValue {
		return p.parseWitness(depth)
	}
	switch node.Kind {
	case schema.NativeObject:
		return p.parseProjectedObject(path, depth)
	case schema.NativeArray:
		return p.parseProjectedArray(path, depth)
	case schema.NativeBOOL:
		return p.parseBoolValue()
	case schema.NativeINT20, schema.NativeNUM32:
		p.skipWS()
		if c := p.peek(); c != '-' && !(c >= '0' && c <= '9') {
			return nil, p.fail(NativeCodeInvalidFieldType)
		}
		return p.parseNumberValue(node.MaxBytes)
	default:
		return p.parseStringValue(node.Kind, node.MaxBytes, false)
	}
}

// parseProjectedObject walks an interpreted object against the closed table.
func (p *nativeJSONParser) parseProjectedObject(path string, depth int) (NativeValue, *NativeError) {
	if err := p.tick(); err != nil {
		return nil, err
	}
	if !p.eat('{') {
		return nil, p.fail(NativeCodeInvalidFieldType)
	}
	obj := NativeObject{}
	seen := map[string]struct{}{}
	members := 0
	p.skipWS()
	if p.eat('}') {
		if err := p.tick(); err != nil {
			return nil, err
		}
		return obj, nil
	}
	for {
		if members >= schema.NativeMaxObjectMembers {
			return nil, p.fail(NativeCodeMemberLimit)
		}
		p.skipWS()
		keyStart := p.pos
		key, err := p.parseKey()
		if err != nil {
			return nil, err
		}
		if _, dup := seen[key]; dup {
			return nil, p.failAt(keyStart, NativeCodeDuplicateKey)
		}
		seen[key] = struct{}{}
		childPath := key
		if path != "" {
			childPath = path + "." + key
		}
		node, ok := schema.NativeRecordNode(childPath)
		if !ok || strings.ContainsAny(key, ".[") {
			return nil, p.failAt(keyStart, NativeCodeFieldNotAllowed)
		}
		p.skipWS()
		if err := p.tick(); err != nil {
			return nil, err
		}
		if p.eat(':') {
		} else {
			return nil, p.fail(NativeCodeInvalidJSON)
		}
		p.skipWS()
		value, err := p.parseMember(childPath, node, depth+1)
		if err != nil {
			return nil, err
		}
		obj.Keys = append(obj.Keys, key)
		obj.Values = append(obj.Values, value)
		members++
		p.skipWS()
		if p.eat(',') {
			if err := p.tick(); err != nil {
				return nil, err
			}
			continue
		}
		if p.eat('}') {
			if err := p.tick(); err != nil {
				return nil, err
			}
			return obj, nil
		}
		return nil, p.fail(NativeCodeInvalidJSON)
	}
}

// parseMember projects one member, applying the special `err` rule of §11.3 and
// admitting a conserved member present with null (§11.3).
func (p *nativeJSONParser) parseMember(path string, node schema.NativeNode, depth int) (NativeValue, *NativeError) {
	if path == "err" {
		return p.parseErrWitness()
	}
	if node.Disposition != schema.NativeExcludedValue {
		p.skipWS()
		if p.peek() == 'n' {
			if err := p.tick(); err != nil {
				return nil, err
			}
			if p.matchLiteral("null") {
				return NativeNull{}, nil
			}
			return nil, p.fail(NativeCodeInvalidFieldType)
		}
	}
	return p.parseProjected(path, node, depth)
}

// parseProjectedArray admits an array, projecting each element by its element
// node. Absent element nodes in the closed table are a schema gap.
func (p *nativeJSONParser) parseProjectedArray(path string, depth int) (NativeValue, *NativeError) {
	if err := p.tick(); err != nil {
		return nil, err
	}
	if !p.eat('[') {
		return nil, p.fail(NativeCodeInvalidFieldType)
	}
	elemPath := path + "[]"
	elemNode, ok := schema.NativeRecordNode(elemPath)
	if !ok {
		return nil, p.fail(NativeCodeInvalidFieldType)
	}
	arr := NativeArray{}
	p.skipWS()
	if p.eat(']') {
		if err := p.tick(); err != nil {
			return nil, err
		}
		return arr, nil
	}
	cap := nativeArrayElementCap(path)
	elemLimit := nativeArrayElementByteLimit(path)
	for {
		if uint64(len(arr.Items)) >= cap {
			return nil, p.fail(NativeCodeCollectionLimit)
		}
		p.skipWS()
		start := p.pos
		item, err := p.parseProjected(elemPath, elemNode, depth+1)
		if err != nil {
			return nil, err
		}
		if elemLimit > 0 && p.pos-start > elemLimit {
			return nil, p.fail(NativeCodeRecordLimit)
		}
		arr.Items = append(arr.Items, item)
		if err := p.countCollection(path); err != nil {
			return nil, err
		}
		p.skipWS()
		if p.eat(',') {
			if err := p.tick(); err != nil {
				return nil, err
			}
			continue
		}
		if p.eat(']') {
			if err := p.tick(); err != nil {
				return nil, err
			}
			return arr, nil
		}
		return nil, p.fail(NativeCodeInvalidJSON)
	}
}

// nativeArrayElementCap returns the local element cap for one conserved array.
func nativeArrayElementCap(path string) uint64 {
	switch path {
	case "vulnerabilities":
		return schema.NativeMaxVulnsPerImage
	case "packages":
		return schema.NativeMaxPackageGroupsPerImage
	case "packages[].pkgs":
		return schema.NativeMaxPackagesPerImage
	case "vulnerabilities[].vulnerabilityDataSources":
		return schema.NativeMaxDataSourcesPerVuln
	case "tags", "instances", "clusters", "namespaces", "repoDigests":
		return schema.NativeMaxContextListPerImage
	default:
		return schema.NativeMaxArrayElements
	}
}

// nativeArrayElementByteLimit returns the raw byte cap of one element object, or
// zero when the path has no per-element byte budget.
func nativeArrayElementByteLimit(path string) int {
	switch path {
	case "vulnerabilities":
		return schema.NativeMaxVulnerabilityBytes
	case "packages[].pkgs":
		return schema.NativeMaxPackageBytes
	default:
		return 0
	}
}

// countCollection enforces the source-level cardinality budgets of §6.2.
func (p *nativeJSONParser) countCollection(arrayPath string) *NativeError {
	switch arrayPath {
	case "vulnerabilities":
		p.sourceVulns++
		if p.sourceVulns > p.findingCeiling() {
			return p.fail(NativeCodeCollectionLimit)
		}
	case "packages[].pkgs":
		p.sourcePkgs++
		p.imagePkgs++
		if p.sourcePkgs > p.packageCeiling() || p.imagePkgs > schema.NativeMaxPackagesPerImage {
			return p.fail(NativeCodeCollectionLimit)
		}
	}
	return nil
}

func (p *nativeJSONParser) parseBoolValue() (NativeValue, *NativeError) {
	if err := p.tick(); err != nil {
		return nil, err
	}
	switch {
	case p.matchLiteral("true"):
		return NativeBool(true), nil
	case p.matchLiteral("false"):
		return NativeBool(false), nil
	}
	return nil, p.fail(NativeCodeInvalidFieldType)
}

func (p *nativeJSONParser) matchLiteral(lit string) bool {
	if p.pos+len(lit) <= len(p.data) && string(p.data[p.pos:p.pos+len(lit)]) == lit {
		p.pos += len(lit)
		return true
	}
	return false
}

// parseNumberValue reads a number token and rejects it if it exceeds the raw
// byte budget of its route (20 for INT20, 32 for NUM32, 128 in discarded
// subtrees). The token bytes are preserved verbatim inside the number wrapper.
func (p *nativeJSONParser) parseNumberValue(maxBytes int) (NativeValue, *NativeError) {
	if err := p.tick(); err != nil {
		return nil, err
	}
	if maxBytes <= 0 || maxBytes > nativeMaxNumberRawBytes {
		maxBytes = nativeMaxNumberRawBytes
	}
	start := p.pos
	if err := p.scanNumber(); err != nil {
		return nil, err
	}
	if p.pos-start > maxBytes {
		return nil, p.failAt(start, NativeCodeNumberLimit)
	}
	return NativeNumber{Token: string(p.data[start:p.pos])}, nil
}

// scanNumber validates the JSON number grammar and advances the cursor.
func (p *nativeJSONParser) scanNumber() *NativeError {
	if p.peek() == '-' {
		p.pos++
	}
	if p.peek() == '0' {
		p.pos++
	} else if p.peek() >= '1' && p.peek() <= '9' {
		for p.pos < len(p.data) && p.data[p.pos] >= '0' && p.data[p.pos] <= '9' {
			p.pos++
		}
	} else {
		return p.fail(NativeCodeInvalidJSON)
	}
	if p.peek() == '.' {
		p.pos++
		if !(p.peek() >= '0' && p.peek() <= '9') {
			return p.fail(NativeCodeInvalidJSON)
		}
		for p.pos < len(p.data) && p.data[p.pos] >= '0' && p.data[p.pos] <= '9' {
			p.pos++
		}
	}
	if p.peek() == 'e' || p.peek() == 'E' {
		p.pos++
		if p.peek() == '+' || p.peek() == '-' {
			p.pos++
		}
		if !(p.peek() >= '0' && p.peek() <= '9') {
			return p.fail(NativeCodeInvalidJSON)
		}
		for p.pos < len(p.data) && p.data[p.pos] >= '0' && p.data[p.pos] <= '9' {
			p.pos++
		}
	}
	return nil
}

// parseStringValue reads a conserved string, enforces its decoded limit and the
// §7.1 forbidden-character policy and returns it verbatim.
func (p *nativeJSONParser) parseStringValue(kind schema.NativeKind, maxBytes int, text bool) (NativeValue, *NativeError) {
	if err := p.tick(); err != nil {
		return nil, err
	}
	if p.peek() != '"' {
		return nil, p.fail(NativeCodeInvalidFieldType)
	}
	rawStart := p.pos
	decoded, err := p.parseString()
	if err != nil {
		return nil, err
	}
	if maxBytes > 0 && len(decoded) > maxBytes {
		return nil, p.failAt(rawStart, NativeCodeStringLimit)
	}
	allowCRLF := kind == schema.NativeT4096
	if bad := forbiddenConservedRune(decoded, allowCRLF); bad {
		return nil, p.failAt(rawStart, NativeCodeForbiddenText)
	}
	return NativeString(decoded), nil
}

// parseErrWitness projects the `err` member as a redaction witness.
func (p *nativeJSONParser) parseErrWitness() (NativeValue, *NativeError) {
	if err := p.tick(); err != nil {
		return nil, err
	}
	switch p.peek() {
	case 'n':
		if p.matchLiteral("null") {
			return NativeRedacted{Kind: "null"}, nil
		}
		return nil, p.fail(NativeCodeInvalidFieldType)
	case '"':
		quoteStart := p.pos
		decoded, err := p.parseString()
		if err != nil {
			return nil, err
		}
		if bad := forbiddenConservedRune(decoded, false); bad {
			return nil, p.failAt(quoteStart, NativeCodeForbiddenText)
		}
		if decoded == "" {
			return NativeRedacted{Kind: "empty"}, nil
		}
		return NativeRedacted{Kind: "value"}, nil
	default:
		return nil, p.fail(NativeCodeInvalidFieldType)
	}
}

// parseWitness consumes any structurally valid value and returns its witness.
func (p *nativeJSONParser) parseWitness(depth int) (NativeValue, *NativeError) {
	if depth > schema.NativeMaxDepth {
		return nil, p.fail(NativeCodeDepthLimit)
	}
	if err := p.tick(); err != nil {
		return nil, err
	}
	switch p.peek() {
	case 'n':
		if p.matchLiteral("null") {
			return NativeRedacted{Kind: "null"}, nil
		}
		return nil, p.fail(NativeCodeInvalidJSON)
	case 't':
		if p.matchLiteral("true") {
			return NativeRedacted{Kind: "value"}, nil
		}
		return nil, p.fail(NativeCodeInvalidJSON)
	case 'f':
		if p.matchLiteral("false") {
			return NativeRedacted{Kind: "value"}, nil
		}
		return nil, p.fail(NativeCodeInvalidJSON)
	case '"':
		decoded, err := p.parseString()
		if err != nil {
			return nil, err
		}
		if decoded == "" {
			return NativeRedacted{Kind: "empty"}, nil
		}
		return NativeRedacted{Kind: "value"}, nil
	case '[':
		n, err := p.parseStructuralArray(depth)
		if err != nil {
			return nil, err
		}
		if n == 0 {
			return NativeRedacted{Kind: "empty"}, nil
		}
		return NativeRedacted{Kind: "value"}, nil
	case '{':
		n, err := p.parseStructuralObject(depth)
		if err != nil {
			return nil, err
		}
		if n == 0 {
			return NativeRedacted{Kind: "empty"}, nil
		}
		return NativeRedacted{Kind: "value"}, nil
	default:
		start := p.pos
		if err := p.scanNumber(); err != nil {
			return nil, err
		}
		if p.pos-start > nativeMaxNumberRawBytes {
			return nil, p.failAt(start, NativeCodeNumberLimit)
		}
		return NativeRedacted{Kind: "value"}, nil
	}
}

// parseStructuralArray validates a discarded array, returning its element count.
func (p *nativeJSONParser) parseStructuralArray(depth int) (int, *NativeError) {
	if !p.eat('[') {
		return 0, p.fail(NativeCodeInvalidJSON)
	}
	count := 0
	p.skipWS()
	if p.eat(']') {
		if err := p.tick(); err != nil {
			return 0, err
		}
		return 0, nil
	}
	for {
		if count >= schema.NativeMaxArrayElements {
			return 0, p.fail(NativeCodeCollectionLimit)
		}
		p.skipWS()
		if _, err := p.parseStructuralValue(depth + 1); err != nil {
			return 0, err
		}
		count++
		p.skipWS()
		if p.eat(',') {
			if err := p.tick(); err != nil {
				return 0, err
			}
			continue
		}
		if p.eat(']') {
			if err := p.tick(); err != nil {
				return 0, err
			}
			return count, nil
		}
		return 0, p.fail(NativeCodeInvalidJSON)
	}
}

// parseStructuralObject validates a discarded object, returning its member count.
func (p *nativeJSONParser) parseStructuralObject(depth int) (int, *NativeError) {
	if !p.eat('{') {
		return 0, p.fail(NativeCodeInvalidJSON)
	}
	seen := map[string]struct{}{}
	count := 0
	p.skipWS()
	if p.eat('}') {
		if err := p.tick(); err != nil {
			return 0, err
		}
		return 0, nil
	}
	for {
		if count >= schema.NativeMaxObjectMembers {
			return 0, p.fail(NativeCodeMemberLimit)
		}
		p.skipWS()
		keyStart := p.pos
		key, err := p.parseStructuralKey()
		if err != nil {
			return 0, err
		}
		if _, dup := seen[key]; dup {
			return 0, p.failAt(keyStart, NativeCodeDuplicateKey)
		}
		seen[key] = struct{}{}
		p.skipWS()
		if err := p.tick(); err != nil {
			return 0, err
		}
		if !p.eat(':') {
			return 0, p.fail(NativeCodeInvalidJSON)
		}
		p.skipWS()
		if _, err := p.parseStructuralValue(depth + 1); err != nil {
			return 0, err
		}
		count++
		p.skipWS()
		if p.eat(',') {
			if err := p.tick(); err != nil {
				return 0, err
			}
			continue
		}
		if p.eat('}') {
			if err := p.tick(); err != nil {
				return 0, err
			}
			return count, nil
		}
		return 0, p.fail(NativeCodeInvalidJSON)
	}
}

// parseStructuralValue validates one arbitrary JSON value without projecting it.
func (p *nativeJSONParser) parseStructuralValue(depth int) (NativeValue, *NativeError) {
	if depth > schema.NativeMaxDepth {
		return nil, p.fail(NativeCodeDepthLimit)
	}
	if err := p.tick(); err != nil {
		return nil, err
	}
	switch p.peek() {
	case '{':
		if _, err := p.parseStructuralObject(depth); err != nil {
			return nil, err
		}
		return NativeNull{}, nil
	case '[':
		if _, err := p.parseStructuralArray(depth); err != nil {
			return nil, err
		}
		return NativeNull{}, nil
	case '"':
		if _, err := p.parseString(); err != nil {
			return nil, err
		}
		return NativeNull{}, nil
	case 't':
		if p.matchLiteral("true") {
			return NativeNull{}, nil
		}
		return nil, p.fail(NativeCodeInvalidJSON)
	case 'f':
		if p.matchLiteral("false") {
			return NativeNull{}, nil
		}
		return nil, p.fail(NativeCodeInvalidJSON)
	case 'n':
		if p.matchLiteral("null") {
			return NativeNull{}, nil
		}
		return nil, p.fail(NativeCodeInvalidJSON)
	default:
		start := p.pos
		if err := p.scanNumber(); err != nil {
			return nil, err
		}
		if p.pos-start > nativeMaxNumberRawBytes {
			return nil, p.failAt(start, NativeCodeNumberLimit)
		}
		return NativeNull{}, nil
	}
}

// parseKey reads an interpreted object key, enforcing the raw/decoded key
// limits and rejecting an empty decoded key (a structurally valid empty key is
// only admitted inside a discarded subtree, per parseStructuralKey).
func (p *nativeJSONParser) parseKey() (string, *NativeError) {
	quoteStart := p.pos
	decoded, err := p.parseStructuralKey()
	if err != nil {
		return "", err
	}
	if decoded == "" {
		return "", p.failAt(quoteStart, NativeCodeFieldNotAllowed)
	}
	return decoded, nil
}

// parseStructuralKey reads any object key, enforcing the raw and decoded limits
// while reading it (before the decoder buffer grows) and admitting an empty
// decoded key. It counts the key with tickToken so replay uses its own token
// budget (§11.9.1), not only the native one.
func (p *nativeJSONParser) parseStructuralKey() (string, *NativeError) {
	if err := p.tickToken(); err != nil {
		return "", err
	}
	decoded, _, err := p.parseStringWith(p.keyRawLimit(), p.keyDecodedLimit(), NativeCodeKeyLimit)
	if err != nil {
		return "", err
	}
	return decoded, nil
}

// parseString decodes one JSON string literal under the parser's string budget.
func (p *nativeJSONParser) parseString() (string, *NativeError) {
	decoded, _, err := p.parseStringWith(p.stringRawLimit(), 0, NativeCodeStringLimit)
	return decoded, err
}

// parseStringWith decodes one JSON string literal, validating escapes and
// rejecting NUL and lone surrogates. It stops with overCode anchored at the
// opening quote as soon as the raw span (quotes included) would exceed rawLimit
// or the decoded contents would exceed decodedLimit (when decodedLimit > 0), so
// an over-budget literal never grows the buffer past its budget. It returns the
// decoded string and the raw span in bytes.
func (p *nativeJSONParser) parseStringWith(rawLimit, decodedLimit int, overCode string) (string, int, *NativeError) {
	quoteStart := p.pos
	if !p.eat('"') {
		return "", 0, p.failAt(quoteStart, NativeCodeInvalidJSON)
	}
	start := p.pos
	if p.pos-start+2 > rawLimit {
		return "", p.pos - quoteStart, p.failAt(quoteStart, overCode)
	}
	over := func() *NativeError {
		return p.failAt(quoteStart, overCode)
	}
	var out []byte
	for {
		if p.pos >= len(p.data) {
			return "", p.pos - quoteStart, p.fail(NativeCodeInvalidJSON)
		}
		if p.pos-start+2 > rawLimit {
			return "", p.pos - quoteStart, over()
		}
		b := p.data[p.pos]
		switch {
		case b == '"':
			p.pos++
			if p.pos-start+1 > rawLimit {
				return "", p.pos - quoteStart, over()
			}
			return string(out), p.pos - quoteStart, nil
		case b == '\\':
			p.pos++
			r, err := p.parseEscape()
			if err != nil {
				return "", p.pos - quoteStart, err
			}
			if r == 0 {
				return "", p.pos - quoteStart, p.failAt(quoteStart, NativeCodeForbiddenText)
			}
			if n := utf8.RuneLen(r); decodedLimit > 0 && len(out)+n > decodedLimit {
				return "", p.pos - quoteStart, over()
			}
			out = utf8.AppendRune(out, r)
		case b < 0x20:
			return "", p.pos - quoteStart, p.failAt(quoteStart, NativeCodeInvalidJSON)
		case b < 0x80:
			if decodedLimit > 0 && len(out)+1 > decodedLimit {
				return "", p.pos - quoteStart, over()
			}
			out = append(out, b)
			p.pos++
		default:
			r, size := utf8.DecodeRune(p.data[p.pos:])
			if r == utf8.RuneError && size == 1 {
				return "", p.pos - quoteStart, p.failAt(quoteStart, NativeCodeInvalidUTF8)
			}
			if decodedLimit > 0 && len(out)+size > decodedLimit {
				return "", p.pos - quoteStart, over()
			}
			out = append(out, p.data[p.pos:p.pos+size]...)
			p.pos += size
		}
	}
}

// parseEscape reads one escape sequence after the backslash and returns the
// decoded rune. NUL decodes to 0 so the caller can reject it globally.
func (p *nativeJSONParser) parseEscape() (rune, *NativeError) {
	if p.pos >= len(p.data) {
		return 0, p.fail(NativeCodeInvalidJSON)
	}
	c := p.data[p.pos]
	p.pos++
	switch c {
	case '"', '\\', '/':
		return rune(c), nil
	case 'b':
		return '\b', nil
	case 'f':
		return '\f', nil
	case 'n':
		return '\n', nil
	case 'r':
		return '\r', nil
	case 't':
		return '\t', nil
	case 'u':
		return p.parseUnicodeEscape()
	default:
		return 0, p.fail(NativeCodeInvalidUnicode)
	}
}

// parseUnicodeEscape reads \uXXXX and, for a high surrogate, the required low
// surrogate, returning the combined rune. Lone surrogates are rejected.
func (p *nativeJSONParser) parseUnicodeEscape() (rune, *NativeError) {
	hi, err := p.readHex4()
	if err != nil {
		return 0, err
	}
	if hi >= 0xD800 && hi <= 0xDBFF {
		if p.pos+1 >= len(p.data) || p.data[p.pos] != '\\' || p.data[p.pos+1] != 'u' {
			return 0, p.fail(NativeCodeInvalidUnicode)
		}
		p.pos += 2
		lo, err := p.readHex4()
		if err != nil {
			return 0, err
		}
		if lo < 0xDC00 || lo > 0xDFFF {
			return 0, p.fail(NativeCodeInvalidUnicode)
		}
		return rune(0x10000 + (hi-0xD800)<<10 + (lo - 0xDC00)), nil
	}
	if hi >= 0xDC00 && hi <= 0xDFFF {
		return 0, p.fail(NativeCodeInvalidUnicode)
	}
	return rune(hi), nil
}

func (p *nativeJSONParser) readHex4() (int, *NativeError) {
	if p.pos+4 > len(p.data) {
		return 0, p.fail(NativeCodeInvalidUnicode)
	}
	value := 0
	for i := 0; i < 4; i++ {
		c := p.data[p.pos+i]
		d := hexValue(c)
		if d < 0 {
			return 0, p.fail(NativeCodeInvalidUnicode)
		}
		value = value*16 + d
	}
	p.pos += 4
	return value, nil
}

func hexValue(c byte) int {
	switch {
	case c >= '0' && c <= '9':
		return int(c - '0')
	case c >= 'a' && c <= 'f':
		return int(c-'a') + 10
	case c >= 'A' && c <= 'F':
		return int(c-'A') + 10
	default:
		return -1
	}
}

// forbiddenConservedRune reports whether a conserved string contains a rune
// forbidden by §7.1: NUL, TAB, DEL, C1, Cf, or C0 other than CR/LF in T4096.
func forbiddenConservedRune(value string, allowCRLF bool) bool {
	for _, r := range value {
		switch {
		case r == 0:
			return true
		case r == '\t':
			return true
		case r == 0x7F:
			return true
		case r >= 0x80 && r <= 0x9F:
			return true
		case r < 0x20:
			if allowCRLF && (r == '\n' || r == '\r') {
				continue
			}
			return true
		case unicode.Is(unicode.Cf, r):
			return true
		}
	}
	return false
}
