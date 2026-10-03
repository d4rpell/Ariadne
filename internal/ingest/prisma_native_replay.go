package ingest

import (
	"io"
	"strings"
	"unicode/utf8"

	"github.com/d4rpell/Ariadne/internal/schema"
)

// Replay of the derived artifacts (ADR-0027 §11.10). It reads native-source.json,
// native-manifest.json and native-manifest.sha256, checks their canonical
// serialization, verifies the hashes, recomputes the manifest facts from the
// source and rejects any divergence. The original native file is never
// consulted, and no caller-supplied counter or offset is trusted.

// nativeTree is a generic JSON tree used only for reading the derived artifacts.
type nativeTree struct {
	kind     byte // 'o' object, 'a' array, 's' string, 'n' number, 'b' bool, 'z' null
	str      string
	num      string
	boolean  bool
	arr      []nativeTree
	keys     []string
	vals     []nativeTree
	valStart []uint64 // per object member: byte offset of its value
	keyStart []uint64 // per object member: byte offset of its key
}

func (t nativeTree) member(name string) (nativeTree, bool) {
	for i, key := range t.keys {
		if key == name {
			return t.vals[i], true
		}
	}
	return nativeTree{}, false
}

// memberValueOffset returns the byte offset of one object member's value, used
// to anchor replay-verification diagnostics (§12.4.2).
func (t nativeTree) memberValueOffset(name string) (uint64, bool) {
	for i, key := range t.keys {
		if key == name {
			return t.valStart[i], true
		}
	}
	return 0, false
}

// Replay helpers of the derived artifacts (ADR-0027 §11.10). These readers
// strictly validate native-source.json and native-manifest.json (closed schema,
// key order, canonical serialization) and verify the source hash. The replay
// orchestration and the manifest recomputation live in internal/normalize.

// AcquireNativeArtifact reads one bounded artifact (ADR-0027 §11.10 step 2).
func AcquireNativeArtifact(reader io.Reader, limit uint64, space string) ([]byte, *NativeError) {
	return acquireNativeArtifact(reader, limit, space)
}

// ReadPrismaNativeSource reads and validates native-source.json, including its
// canonical serialization, and returns the source it encodes.
func ReadPrismaNativeSource(reader io.Reader) (NativeSource, *NativeError) {
	sourceBytes, err := acquireNativeArtifact(reader, schema.NativeMaxDerivedSourceBytes, NativeSpaceSource)
	if err != nil {
		return NativeSource{}, err
	}
	return ParseNativeSourceBytes(sourceBytes)
}

// ParseNativeSourceBytes validates already acquired source bytes.
func ParseNativeSourceBytes(sourceBytes []byte) (NativeSource, *NativeError) {
	var p nativeJSONParser
	sourceTree, err := p.parseTree(sourceBytes, schema.NativeMaxDerivedSourceDepth, schema.NativeMaxDerivedSourceTokens, sourceLexicalLimits())
	if err != nil {
		return NativeSource{}, artifactErrorSpace(err.Code, NativeSpaceSource, err.Offset)
	}
	parsed, err := readNativeSourceTree(sourceTree)
	if err != nil {
		return NativeSource{}, err
	}
	if canonical := EncodeNativeSource(parsed); string(canonical) != string(sourceBytes) {
		return NativeSource{}, artifactError(NativeCodeInvalidArtifact, firstDifference(canonical, sourceBytes))
	}
	if err := validateNativeSourceMetadata(parsed); err != nil {
		return NativeSource{}, err
	}
	if err := validateNativeSourceSchema(parsed); err != nil {
		return NativeSource{}, err
	}
	return parsed, nil
}

// validateNativeSourceMetadata checks the internal coherence of the declared
// original metadata (ADR-0027 §11.2, §11.9.2). It uses the declared numbers; the
// original bytes are never re-examined.
func validateNativeSourceMetadata(src NativeSource) *NativeError {
	bad := func() *NativeError { return artifactError(NativeCodeInvalidArtifact, 0) }
	if src.Input.SourceAlias != src.Context.SourceAlias {
		return bad()
	}
	isCSV := src.Profile.Selector == schema.NativeCSVSelector
	expectedFormat := "json"
	if isCSV {
		expectedFormat = "csv"
	}
	if src.Input.NativeFormat != expectedFormat {
		return bad()
	}
	if src.Input.OriginalBytes > schema.NativeMaxSourceBytes {
		return bad()
	}
	if isCSV {
		if src.Input.OriginalBytes < 388 {
			return bad()
		}
	} else if src.Input.OriginalBytes < 2 {
		return bad()
	}
	for _, field := range src.Context.SelectedFields {
		if !schema.NativeValidateSelection(src.Profile.Selector, field) {
			return bad()
		}
	}
	previousEnd := uint64(0)
	for i, record := range src.Records {
		if record.Ordinal != i {
			return bad()
		}
		if !(record.OriginStart < record.OriginEnd && record.OriginEnd <= src.Input.OriginalBytes) {
			return bad()
		}
		if i > 0 && previousEnd >= record.OriginStart {
			return bad()
		}
		if record.OriginLocator != NativeOriginLocator(nativeFormatName(isCSV), i, record.OriginStart, record.OriginEnd) {
			return bad()
		}
		if isCSV {
			if record.OriginEnd-record.OriginStart > schema.NativeMaxCSVRecordBytes {
				return bad()
			}
			if i == 0 && record.OriginStart < 389 {
				return bad()
			}
		} else {
			if record.OriginEnd-record.OriginStart > schema.NativeMaxImageObjectBytes {
				return bad()
			}
			if record.OriginStart < 1 || record.OriginEnd >= src.Input.OriginalBytes {
				return bad()
			}
		}
		previousEnd = record.OriginEnd
	}
	return nil
}

func nativeFormatName(isCSV bool) string {
	if isCSV {
		return "csv"
	}
	return "json"
}

// validateNativeSourceSchema revalidates each projected record against the
// closed disposition table of §7.3–§7.5, so replay rejects content that the
// initial projection would never have produced (for example a string where a
// redaction witness belongs).
// nativeDerivedSizesWithinBudgets applies the §11.9.1 derived size budgets
// (context 64 KiB, record 16 MiB / CSV record 1 MiB) without materializing an
// over-budget buffer.
func nativeDerivedSizesWithinBudgets(src NativeSource) bool {
	if !NativeContextFits(src.Context, schema.NativeMaxDerivedContextBytes) {
		return false
	}
	isCSV := src.Profile.Selector == schema.NativeCSVSelector
	for _, record := range src.Records {
		limit := schema.NativeMaxDerivedRecordBytes
		if isCSV {
			limit = schema.NativeMaxDerivedCSVRecordBytes
		}
		if !NativeRecordFits(record, limit) {
			return false
		}
	}
	return true
}

// NativeDerivedSizesWithinBudgets reports whether a source respects the §11.9.1
// derived size budgets. Production uses it to fail with output_limit instead of
// propagating the replay-admission schema rejection of an over-budget record.
func NativeDerivedSizesWithinBudgets(src NativeSource) bool {
	return nativeDerivedSizesWithinBudgets(src)
}

func validateNativeSourceSchema(src NativeSource) *NativeError {
	isCSV := src.Profile.Selector == schema.NativeCSVSelector
	if !isCSV && uint64(len(src.Records)) > schema.NativeMaxRootItems {
		return artifactError(NativeCodeInvalidArtifact, 0)
	}
	if !nativeDerivedSizesWithinBudgets(src) {
		return artifactError(NativeCodeInvalidArtifact, 0)
	}
	var sourceVulns, sourcePkgs uint64
	for _, record := range src.Records {
		obj, ok := record.Data.(NativeObject)
		if !ok {
			return artifactError(NativeCodeInvalidArtifact, 0)
		}
		if isCSV {
			if err := validateCSVRowSchema(obj); err != nil {
				return err
			}
			if uint64(len(src.Records)) > schema.NativeMaxCSVDataRecords {
				return artifactError(NativeCodeInvalidArtifact, 0)
			}
			continue
		}
		vulns, groups, pkgs := derivedCounts(obj)
		if vulns > schema.NativeMaxVulnsPerImage || groups > schema.NativeMaxPackageGroupsPerImage || pkgs > schema.NativeMaxPackagesPerImage {
			return artifactError(NativeCodeInvalidArtifact, 0)
		}
		sourceVulns += vulns
		sourcePkgs += pkgs
		if sourceVulns > schema.NativeMaxVulnsPerSource || sourcePkgs > schema.NativeMaxPackagesPerSource {
			return artifactError(NativeCodeInvalidArtifact, 0)
		}
		for i, key := range obj.Keys {
			if key == "err" {
				if !validErrWitness(obj.Values[i]) {
					return artifactError(NativeCodeInvalidArtifact, 0)
				}
				continue
			}
			node, ok := schema.NativeRecordNode(key)
			if !ok || strings.ContainsAny(key, ".[") {
				return artifactError(NativeCodeInvalidArtifact, 0)
			}
			if err := validateProjectedValue(key, node, obj.Values[i], true); err != nil {
				return err
			}
			if key == "type" {
				if s, isStr := obj.Values[i].(NativeString); isStr && s != "" && string(s) != "image" {
					return nativeFailure(NativeCodeUnsupportedReportScope, NativePhaseReplayAdmission, NativeSpaceSource, 0)
				}
			}
		}
	}
	return nil
}

// validateCSVRowSchema checks the closed 39-column projection of §11.3.
func validateCSVRowSchema(row NativeObject) *NativeError {
	columns := schema.NativeCSVColumns()
	if len(row.Keys) != len(columns) {
		return artifactError(NativeCodeInvalidArtifact, 0)
	}
	byName := map[string]schema.CSVColumn{}
	for _, col := range columns {
		byName[col.Name] = col
	}
	for i, key := range row.Keys {
		col, ok := byName[key]
		if !ok {
			return artifactError(NativeCodeInvalidArtifact, 0)
		}
		if col.Disposition == schema.NativeExcludedValue {
			witness, ok := row.Values[i].(NativeRedacted)
			if !ok || (witness.Kind != "empty" && witness.Kind != "value") {
				return artifactError(NativeCodeInvalidArtifact, 0)
			}
			continue
		}
		s, ok := row.Values[i].(NativeString)
		if !ok {
			return artifactError(NativeCodeInvalidArtifact, 0)
		}
		if forbiddenConservedRune(string(s), false) {
			return artifactError(NativeCodeInvalidArtifact, 0)
		}
		if col.MaxBytes > 0 && len(s) > col.MaxBytes {
			return artifactError(NativeCodeInvalidArtifact, 0)
		}
	}
	return nil
}

// validateProjectedValue checks one projected value against its closed node.
// allowNull admits a conserved member present with null (a member context), but
// not a null array element.
func validateProjectedValue(path string, node schema.NativeNode, value NativeValue, allowNull bool) *NativeError {
	bad := func() *NativeError { return artifactError(NativeCodeInvalidArtifact, 0) }
	if node.Disposition == schema.NativeExcludedValue {
		witness, ok := value.(NativeRedacted)
		if !ok || (witness.Kind != "null" && witness.Kind != "empty" && witness.Kind != "value") {
			return bad()
		}
		return nil
	}
	if _, isNull := value.(NativeNull); isNull {
		if allowNull {
			return nil
		}
		return bad()
	}
	switch node.Kind {
	case schema.NativeObject:
		obj, ok := value.(NativeObject)
		if !ok {
			return bad()
		}
		switch path {
		case "vulnerabilities[]":
			if NativeValueSize(obj) > schema.NativeMaxDerivedVulnBytes {
				return bad()
			}
		case "packages[].pkgs[]":
			if NativeValueSize(obj) > schema.NativeMaxDerivedPackageBytes {
				return bad()
			}
		}
		for i, key := range obj.Keys {
			if strings.ContainsAny(key, ".[") {
				return bad()
			}
			childPath := key
			if path != "" {
				childPath = path + "." + key
			}
			if childPath == "err" {
				if !validErrWitness(obj.Values[i]) {
					return bad()
				}
				continue
			}
			child, ok := schema.NativeRecordNode(childPath)
			if !ok {
				return bad()
			}
			if err := validateProjectedValue(childPath, child, obj.Values[i], true); err != nil {
				return err
			}
		}
		return nil
	case schema.NativeArray:
		arr, ok := value.(NativeArray)
		if !ok {
			return bad()
		}
		elemPath := path + "[]"
		elem, ok := schema.NativeRecordNode(elemPath)
		if !ok {
			return bad()
		}
		if uint64(len(arr.Items)) > nativeArrayElementCap(path) {
			return bad()
		}
		for _, item := range arr.Items {
			if err := validateProjectedValue(elemPath, elem, item, false); err != nil {
				return err
			}
		}
		return nil
	case schema.NativeBOOL:
		if _, ok := value.(NativeBool); !ok {
			return bad()
		}
		return nil
	case schema.NativeINT20, schema.NativeNUM32:
		num, ok := value.(NativeNumber)
		if !ok || !isJSONNumberToken(num.Token) || len(num.Token) > node.MaxBytes {
			return bad()
		}
		return nil
	default:
		s, ok := value.(NativeString)
		if !ok {
			return bad()
		}
		if node.MaxBytes > 0 && len(s) > node.MaxBytes {
			return bad()
		}
		if forbiddenConservedRune(string(s), node.Kind == schema.NativeT4096) {
			return bad()
		}
		return nil
	}
}

// validErrWitness reports whether an `err` member carries a legal §11.3 witness.
func validErrWitness(value NativeValue) bool {
	witness, ok := value.(NativeRedacted)
	if !ok {
		return false
	}
	return witness.Kind == "null" || witness.Kind == "empty" || witness.Kind == "value"
}

// isJSONNumberToken validates the JSON number grammar of a wrapper token.
func isJSONNumberToken(token string) bool {
	if token == "" {
		return false
	}
	p := &nativeJSONParser{data: []byte(token)}
	if err := p.scanNumber(); err != nil {
		return false
	}
	return p.pos == len(token)
}

// ReadPrismaNativeManifest reads and validates native-manifest.json, returning
// the manifest it encodes together with its raw bytes for hash verification.
func ReadPrismaNativeManifest(reader io.Reader) (NativeManifest, []byte, *NativeError) {
	manifestBytes, err := acquireNativeArtifact(reader, schema.NativeMaxManifestBytes, NativeSpaceManifest)
	if err != nil {
		return NativeManifest{}, nil, err
	}
	return ParseNativeManifestBytes(manifestBytes)
}

// ParseNativeManifestBytes validates already acquired manifest bytes.
func ParseNativeManifestBytes(manifestBytes []byte) (NativeManifest, []byte, *NativeError) {
	var mp nativeJSONParser
	manifestTree, err := mp.parseTree(manifestBytes, schema.NativeMaxManifestDepth, schema.NativeMaxManifestTokens, manifestLexicalLimits())
	if err != nil {
		return NativeManifest{}, nil, artifactErrorSpace(err.Code, NativeSpaceManifest, err.Offset)
	}
	declared, err := readNativeManifestTree(manifestTree)
	if err != nil {
		return NativeManifest{}, nil, err
	}
	if canonical := EncodeNativeManifest(declared); string(canonical) != string(manifestBytes) {
		return NativeManifest{}, nil, artifactErrorSpace(NativeCodeInvalidArtifact, NativeSpaceManifest, firstDifference(canonical, manifestBytes))
	}
	return declared, manifestBytes, nil
}

// ReadPrismaNativeDigest reads the 72-byte sidecar.
func ReadPrismaNativeDigest(reader io.Reader) ([]byte, *NativeError) {
	return acquireNativeArtifact(reader, 72, NativeSpaceDigest)
}

// firstDifference returns the offset of the first byte that differs between the
// two documents, or the length of the common prefix.
func firstDifference(a, b []byte) uint64 {
	limit := len(a)
	if len(b) < limit {
		limit = len(b)
	}
	for i := 0; i < limit; i++ {
		if a[i] != b[i] {
			return uint64(i)
		}
	}
	return uint64(limit)
}

// sourceLexicalLimits and manifestLexicalLimits fix the §11.9.1 derived key and
// string budgets for each derived artifact. They are separate from the native
// budgets because a derived size is never compared against a raw native one.
func sourceLexicalLimits() nativeLexicalLimits {
	return nativeLexicalLimits{
		keyRaw:     schema.NativeMaxDerivedKeyRawBytes,
		keyDecoded: schema.NativeMaxDerivedKeyDecodedBytes,
		stringRaw:  schema.NativeMaxDerivedStringRawBytes,
	}
}

func manifestLexicalLimits() nativeLexicalLimits {
	return nativeLexicalLimits{
		keyRaw:     schema.NativeMaxDerivedKeyRawBytes,
		keyDecoded: schema.NativeMaxDerivedKeyDecodedBytes,
		stringRaw:  schema.NativeMaxManifestStringRawBytes,
	}
}

// NativeManifestMemberValueOffset returns the byte offset of a canonical
// manifest member's value, so replay can anchor `hash_mismatch` and
// `manifest_mismatch` at the offending member (§12.4.2). The manifest must have
// already passed ParseNativeManifestBytes.
func NativeManifestMemberValueOffset(manifestBytes []byte, member string) (uint64, bool) {
	var p nativeJSONParser
	tree, err := p.parseTree(manifestBytes, schema.NativeMaxManifestDepth, schema.NativeMaxManifestTokens, manifestLexicalLimits())
	if err != nil {
		return 0, false
	}
	return tree.memberValueOffset(member)
}

func artifactError(code string, offset uint64) *NativeError {
	return artifactErrorSpace(code, NativeSpaceSource, offset)
}

func artifactErrorSpace(code, space string, offset uint64) *NativeError {
	return nativeFailure(code, NativePhaseReplayAdmission, space, offset)
}

// acquireNativeArtifact reads one bounded artifact to EOF.
func acquireNativeArtifact(reader io.Reader, limit uint64, space string) ([]byte, *NativeError) {
	if isNilNativeReader(reader) {
		return nil, nativeFailure(NativeCodeNilReader, NativePhaseContext, NativeSpaceNone, 0)
	}
	data := make([]byte, 0, nativeReadChunk)
	buffer := make([]byte, nativeReadChunk)
	progress := 0
	read := uint64(0)
	for {
		want := uint64(nativeReadChunk)
		if remaining := limit + 1 - read; remaining < want {
			want = remaining
		}
		n, err := reader.Read(buffer[:want])
		if n > 0 {
			data = append(data, buffer[:n]...)
			read += uint64(n)
			progress = 0
		}
		if read > limit {
			return nil, nativeFailure(NativeCodeSourceLimit, NativePhaseAcquisition, space, limit)
		}
		switch {
		case err == io.EOF:
			return data, nil
		case err != nil:
			return nil, nativeFailure(NativeCodeReadFailed, NativePhaseAcquisition, space, read)
		}
		if n == 0 {
			progress++
			if progress > schema.NativeMaxNoProgressReads {
				return nil, nativeFailure(NativeCodeReadFailed, NativePhaseAcquisition, space, read)
			}
		}
	}
}

// parseTree reads one complete document into a generic tree, rejecting
// duplicates, trailing data, depth overflow and token overflow.
func (p *nativeJSONParser) parseTree(data []byte, maxDepth int, tokenLimit uint64, limits nativeLexicalLimits) (nativeTree, *NativeError) {
	p.data = data
	p.pos = 0
	p.tokenLimit = tokenLimit
	p.keyRaw = limits.keyRaw
	p.keyDecoded = limits.keyDecoded
	p.stringRaw = limits.stringRaw
	tree, err := p.parseTreeValue(maxDepth)
	if err != nil {
		return nativeTree{}, err
	}
	p.skipWS()
	if p.pos != len(p.data) {
		return nativeTree{}, p.fail(NativeCodeInvalidJSON)
	}
	return tree, nil
}

func (p *nativeJSONParser) parseTreeValue(depth int) (nativeTree, *NativeError) {
	if depth <= 0 {
		return nativeTree{}, p.fail(NativeCodeDepthLimit)
	}
	if err := p.tickToken(); err != nil {
		return nativeTree{}, err
	}
	p.skipWS()
	switch p.peek() {
	case '{':
		p.pos++
		node := nativeTree{kind: 'o'}
		seen := map[string]struct{}{}
		p.skipWS()
		if p.eat('}') {
			if err := p.tickToken(); err != nil {
				return nativeTree{}, err
			}
			return node, nil
		}
		for {
			if len(node.keys) >= schema.NativeMaxDerivedObjectMembers {
				return nativeTree{}, p.fail(NativeCodeMemberLimit)
			}
			p.skipWS()
			keyStart := p.pos
			key, err := p.parseStructuralKey()
			if err != nil {
				return nativeTree{}, err
			}
			if _, dup := seen[key]; dup {
				return nativeTree{}, p.failAt(keyStart, NativeCodeDuplicateKey)
			}
			seen[key] = struct{}{}
			p.skipWS()
			if err := p.tickToken(); err != nil {
				return nativeTree{}, err
			}
			if !p.eat(':') {
				return nativeTree{}, p.fail(NativeCodeInvalidJSON)
			}
			p.skipWS()
			valueStart := p.pos
			value, err := p.parseTreeValue(depth - 1)
			if err != nil {
				return nativeTree{}, err
			}
			node.keys = append(node.keys, key)
			node.vals = append(node.vals, value)
			node.valStart = append(node.valStart, uint64(valueStart))
			node.keyStart = append(node.keyStart, uint64(keyStart))
			p.skipWS()
			if p.eat(',') {
				if err := p.tickToken(); err != nil {
					return nativeTree{}, err
				}
				p.skipWS()
				if p.peek() == '}' || p.peek() == ',' {
					return nativeTree{}, p.fail(NativeCodeInvalidJSON)
				}
				continue
			}
			if p.eat('}') {
				if err := p.tickToken(); err != nil {
					return nativeTree{}, err
				}
				return node, nil
			}
			return nativeTree{}, p.fail(NativeCodeInvalidJSON)
		}
	case '[':
		p.pos++
		node := nativeTree{kind: 'a'}
		p.skipWS()
		if p.eat(']') {
			if err := p.tickToken(); err != nil {
				return nativeTree{}, err
			}
			return node, nil
		}
		for {
			if uint64(len(node.arr)) >= schema.NativeMaxArrayElements {
				return nativeTree{}, p.fail(NativeCodeCollectionLimit)
			}
			value, err := p.parseTreeValue(depth - 1)
			if err != nil {
				return nativeTree{}, err
			}
			node.arr = append(node.arr, value)
			p.skipWS()
			if p.eat(',') {
				if err := p.tickToken(); err != nil {
					return nativeTree{}, err
				}
				p.skipWS()
				if p.peek() == ']' || p.peek() == ',' {
					return nativeTree{}, p.fail(NativeCodeInvalidJSON)
				}
				continue
			}
			if p.eat(']') {
				if err := p.tickToken(); err != nil {
					return nativeTree{}, err
				}
				return node, nil
			}
			return nativeTree{}, p.fail(NativeCodeInvalidJSON)
		}
	case '"':
		s, err := p.parseString()
		if err != nil {
			return nativeTree{}, err
		}
		return nativeTree{kind: 's', str: s}, nil
	case 't':
		if p.matchLiteral("true") {
			return nativeTree{kind: 'b', boolean: true}, nil
		}
		return nativeTree{}, p.fail(NativeCodeInvalidJSON)
	case 'f':
		if p.matchLiteral("false") {
			return nativeTree{kind: 'b', boolean: false}, nil
		}
		return nativeTree{}, p.fail(NativeCodeInvalidJSON)
	case 'n':
		if p.matchLiteral("null") {
			return nativeTree{kind: 'z'}, nil
		}
		return nativeTree{}, p.fail(NativeCodeInvalidJSON)
	default:
		start := p.pos
		if err := p.scanNumber(); err != nil {
			return nativeTree{}, err
		}
		if p.pos-start > schema.NativeMaxDerivedNumberToken {
			return nativeTree{}, p.failAt(start, NativeCodeNumberLimit)
		}
		return nativeTree{kind: 'n', num: string(p.data[start:p.pos])}, nil
	}
}

// readNativeSourceTree maps the source tree into NativeSource with strict keys.
func readNativeSourceTree(t nativeTree) (NativeSource, *NativeError) {
	if t.kind != 'o' {
		return NativeSource{}, artifactError(NativeCodeInvalidArtifact, 0)
	}
	if !hasKeys(t, "format", "version", "profile", "context", "input", "records") {
		return NativeSource{}, artifactError(NativeCodeInvalidArtifact, 0)
	}
	format, _ := t.member("format")
	version, _ := t.member("version")
	if (format.str != schema.NativeSourceFormat && format.str != schema.NativeRegistrySourceFormat) || !validArtifactVersion(version.str) {
		return NativeSource{}, artifactError(NativeCodeInvalidArtifact, 0)
	}
	profileNode, _ := t.member("profile")
	profile, err := readNativeProfileTree(profileNode, NativeSpaceSource)
	if err != nil {
		return NativeSource{}, err
	}
	if format.str != nativeSourceFormat(profile) {
		return NativeSource{}, artifactError(NativeCodeInvalidArtifact, 0)
	}
	if !validFamilyVersion(profile, version.str) {
		// The artifact version must match the profile family in both directions
		// (ADR-0029 §4.7): a registry profile is the 2.0 line only and a deployed
		// profile is the 1.x line, with 1.1 reserved to the JSON profile.
		return NativeSource{}, artifactError(NativeCodeInvalidArtifact, 0)
	}
	contextNode, _ := t.member("context")
	context, err := readNativeContextTree(contextNode, version.str)
	if err != nil {
		return NativeSource{}, err
	}
	inputNode, _ := t.member("input")
	input, err := readNativeInputTree(inputNode)
	if err != nil {
		return NativeSource{}, err
	}
	recordsNode, _ := t.member("records")
	if recordsNode.kind != 'a' {
		return NativeSource{}, artifactError(NativeCodeInvalidArtifact, 0)
	}
	records := make([]NativeRecord, 0, len(recordsNode.arr))
	for _, rn := range recordsNode.arr {
		record, err := readNativeRecordTree(rn)
		if err != nil {
			return NativeSource{}, err
		}
		records = append(records, record)
	}
	return NativeSource{Profile: profile, Context: context, Input: input, Records: records, Version: version.str}, nil
}

// validArtifactVersion reports whether v is one of the artifact provenance
// versions of ADR-0028 §9.5.
func validArtifactVersion(v string) bool {
	return v == schema.NativeFormatVersion || v == schema.NativeFormatVersionV11 || v == schema.NativeRegistryInputVersion
}

func readNativeProfileTree(t nativeTree, space string) (NativeProfile, *NativeError) {
	if t.kind != 'o' || !hasKeys(t, "selector", "input_version", "name", "redaction_policy", "adapter_semantics") {
		return NativeProfile{}, artifactErrorSpace(NativeCodeInvalidArtifact, space, 0)
	}
	selector, _ := t.member("selector")
	version, _ := t.member("input_version")
	name, _ := t.member("name")
	policy, _ := t.member("redaction_policy")
	semantics, _ := t.member("adapter_semantics")
	profile := NativeProfile{
		Selector: selector.str, InputVersion: version.str, Name: name.str,
		RedactionPolicy: policy.str, AdapterSemantics: semantics.str,
	}
	if !knownNativeProfile(profile) {
		return NativeProfile{}, artifactErrorSpace(NativeCodeInvalidArtifact, space, 0)
	}
	return profile, nil
}

func readNativeContextTree(t nativeTree, version string) (NativeContext, *NativeError) {
	names := []string{
		"origin_alias", "source_alias", "declared_edition", "declared_release",
		"version_basis", "report_kind", "acquisition_kind", "acquired_at",
		"capture_termination", "scope_mode", "scope_alias", "filter_status",
		"compact", "normalized_severity", "layers", "fields_mode",
		"selected_fields", "page_mode", "page_ordinal", "pages_expected",
		"data_policy_ack",
	}
	if t.kind != 'o' {
		return NativeContext{}, artifactError(NativeCodeInvalidArtifact, 0)
	}
	if !hasKeys(t, names...) {
		// An unknown context key (e.g. deployment_scope) is anchored at the start
		// of that key (ADR-0027 §12.4.2); a missing required member keeps offset 0.
		if off, ok := firstUnknownKeyOffset(t, names); ok {
			return NativeContext{}, &NativeError{
				Code: NativeCodeInvalidArtifact, Phase: NativePhaseReplayAdmission,
				OffsetSpace: NativeSpaceSource, Offset: off,
			}
		}
		return NativeContext{}, artifactError(NativeCodeInvalidArtifact, 0)
	}
	ctx := NativeContext{}
	get := func(k string) nativeTree { v, _ := t.member(k); return v }
	ctx.OriginAlias = get("origin_alias").str
	ctx.SourceAlias = get("source_alias").str
	ctx.DeclaredEdition = get("declared_edition").str
	ctx.DeclaredRelease = get("declared_release").str
	ctx.VersionBasis = get("version_basis").str
	ctx.ReportKind = get("report_kind").str
	ctx.AcquisitionKind = get("acquisition_kind").str
	ctx.AcquiredAt = get("acquired_at").str
	ctx.CaptureTermination = get("capture_termination").str
	ctx.ScopeMode = get("scope_mode").str
	if v := get("scope_alias"); v.kind == 's' {
		s := v.str
		ctx.ScopeAlias = &s
	}
	ctx.FilterStatus = get("filter_status").str
	ctx.Compact = optBoolFromTree(get("compact"))
	ctx.NormalizedSeverity = optBoolFromTree(get("normalized_severity"))
	ctx.Layers = optBoolFromTree(get("layers"))
	ctx.FieldsMode = get("fields_mode").str
	if v := get("selected_fields"); v.kind == 'a' {
		for _, item := range v.arr {
			ctx.SelectedFields = append(ctx.SelectedFields, item.str)
		}
	}
	if ctx.SelectedFields == nil {
		ctx.SelectedFields = []string{}
	}
	ctx.PageMode = get("page_mode").str
	ctx.PageOrdinal = optIntFromTree(get("page_ordinal"))
	ctx.PagesExpected = optIntFromTree(get("pages_expected"))
	ctx.DataPolicyAck = get("data_policy_ack").str
	if err := validateNativeContextVersion(ctx, version); err != nil {
		return NativeContext{}, artifactError(NativeCodeInvalidArtifact, 0)
	}
	return ctx, nil
}

func readNativeInputTree(t nativeTree) (NativeInput, *NativeError) {
	if t.kind != 'o' || !hasKeys(t, "source_alias", "native_format", "original_bytes", "local_eof", "original_hash") {
		return NativeInput{}, artifactError(NativeCodeInvalidArtifact, 0)
	}
	alias, _ := t.member("source_alias")
	format, _ := t.member("native_format")
	original, _ := t.member("original_bytes")
	eof, _ := t.member("local_eof")
	hash, _ := t.member("original_hash")
	if eof.kind != 'b' || !eof.boolean || hash.kind != 'z' {
		return NativeInput{}, artifactError(NativeCodeInvalidArtifact, 0)
	}
	n, ok := parseCanonicalUint(original.num)
	if !ok {
		return NativeInput{}, artifactError(NativeCodeInvalidArtifact, 0)
	}
	return NativeInput{SourceAlias: alias.str, NativeFormat: format.str, OriginalBytes: n}, nil
}

func readNativeRecordTree(t nativeTree) (NativeRecord, *NativeError) {
	if t.kind != 'o' || !hasKeys(t, "ordinal", "origin_locator", "origin_start", "origin_end", "data") {
		return NativeRecord{}, artifactError(NativeCodeInvalidArtifact, 0)
	}
	ordinalNode, _ := t.member("ordinal")
	locatorNode, _ := t.member("origin_locator")
	startNode, _ := t.member("origin_start")
	endNode, _ := t.member("origin_end")
	dataNode, _ := t.member("data")
	ordinal, ok := parseCanonicalUint(ordinalNode.num)
	if !ok {
		return NativeRecord{}, artifactError(NativeCodeInvalidArtifact, 0)
	}
	start, ok := parseCanonicalUint(startNode.num)
	if !ok {
		return NativeRecord{}, artifactError(NativeCodeInvalidArtifact, 0)
	}
	end, ok := parseCanonicalUint(endNode.num)
	if !ok {
		return NativeRecord{}, artifactError(NativeCodeInvalidArtifact, 0)
	}
	data, err := readNativeValueTree(dataNode)
	if err != nil {
		return NativeRecord{}, err
	}
	return NativeRecord{Ordinal: int(ordinal), OriginLocator: locatorNode.str, OriginStart: start, OriginEnd: end, Data: data}, nil
}

// readNativeValueTree maps a projected data tree into a NativeValue.
func readNativeValueTree(t nativeTree) (NativeValue, *NativeError) {
	switch t.kind {
	case 'z':
		return NativeNull{}, nil
	case 'b':
		return NativeBool(t.boolean), nil
	case 's':
		return NativeString(t.str), nil
	case 'n':
		return nil, artifactError(NativeCodeInvalidArtifact, 0)
	case 'a':
		arr := NativeArray{}
		for _, item := range t.arr {
			v, err := readNativeValueTree(item)
			if err != nil {
				return nil, err
			}
			arr.Items = append(arr.Items, v)
		}
		return arr, nil
	case 'o':
		if len(t.keys) == 1 && t.keys[0] == "number" {
			return NativeNumber{Token: t.vals[0].str}, nil
		}
		if len(t.keys) == 1 && t.keys[0] == "redacted" {
			return NativeRedacted{Kind: t.vals[0].str}, nil
		}
		obj := NativeObject{Keys: append([]string{}, t.keys...)}
		for _, item := range t.vals {
			v, err := readNativeValueTree(item)
			if err != nil {
				return nil, err
			}
			obj.Values = append(obj.Values, v)
		}
		return obj, nil
	default:
		return nil, artifactError(NativeCodeInvalidArtifact, 0)
	}
}

// readNativeManifestTree maps the manifest tree into NativeManifest with strict keys.
func readNativeManifestTree(t nativeTree) (NativeManifest, *NativeError) {
	if t.kind != 'o' || !hasKeys(t, "format", "version", "source_name", "source_hash",
		"source_bytes", "original_bytes", "original_hash", "profile", "counts", "losses", "limitations") {
		return NativeManifest{}, artifactErrorSpace(NativeCodeInvalidArtifact, NativeSpaceManifest, 0)
	}
	format, _ := t.member("format")
	version, _ := t.member("version")
	name, _ := t.member("source_name")
	hash, _ := t.member("source_hash")
	sourceBytesNode, _ := t.member("source_bytes")
	originalBytesNode, _ := t.member("original_bytes")
	originalHash, _ := t.member("original_hash")
	manBad := func() *NativeError { return artifactErrorSpace(NativeCodeInvalidArtifact, NativeSpaceManifest, 0) }
	if (format.str != schema.NativeManifestFormat && format.str != schema.NativeRegistryManifestFormat) || !validArtifactVersion(version.str) || name.str != schema.NativeSourceName {
		return NativeManifest{}, manBad()
	}
	if !validSourceHashLiteral(hash.str) {
		return NativeManifest{}, manBad()
	}
	if originalHash.kind != 'z' {
		return NativeManifest{}, artifactErrorSpace(NativeCodeInvalidArtifact, NativeSpaceManifest, 0)
	}
	sourceBytes, ok := parseCanonicalUint(sourceBytesNode.num)
	if !ok {
		return NativeManifest{}, artifactErrorSpace(NativeCodeInvalidArtifact, NativeSpaceManifest, 0)
	}
	originalBytes, ok := parseCanonicalUint(originalBytesNode.num)
	if !ok || sourceBytes == 0 || sourceBytes > 134_217_728 || originalBytes > schema.NativeMaxSourceBytes {
		return NativeManifest{}, artifactErrorSpace(NativeCodeInvalidArtifact, NativeSpaceManifest, 0)
	}
	profileNode, _ := t.member("profile")
	profile, err := readNativeProfileTree(profileNode, NativeSpaceManifest)
	if err != nil {
		return NativeManifest{}, err
	}
	if format.str != nativeManifestFormat(profile) {
		return NativeManifest{}, manBad()
	}
	if !validFamilyVersion(profile, version.str) {
		// The manifest version must match the profile family, in both directions
		// (ADR-0029 §4.7).
		return NativeManifest{}, manBad()
	}
	countsNode, _ := t.member("counts")
	counts, err := readNativeCountsTree(countsNode, NativeSpaceManifest)
	if err != nil {
		return NativeManifest{}, err
	}
	lossesNode, _ := t.member("losses")
	if lossesNode.kind != 'a' {
		return NativeManifest{}, artifactErrorSpace(NativeCodeInvalidArtifact, NativeSpaceManifest, 0)
	}
	losses := make([]NativeLoss, 0, len(lossesNode.arr))
	for _, ln := range lossesNode.arr {
		loss, err := readNativeLossTree(ln, NativeSpaceManifest)
		if err != nil {
			return NativeManifest{}, err
		}
		losses = append(losses, loss)
	}
	limitationsNode, _ := t.member("limitations")
	if limitationsNode.kind != 'a' {
		return NativeManifest{}, artifactErrorSpace(NativeCodeInvalidArtifact, NativeSpaceManifest, 0)
	}
	limitations := []string{}
	for _, ln := range limitationsNode.arr {
		limitations = append(limitations, ln.str)
	}
	return NativeManifest{
		SourceHash: hash.str, SourceBytes: sourceBytes, OriginalBytes: originalBytes,
		Profile: profile, Counts: counts, Losses: losses, Limitations: limitations,
		Version: version.str,
	}, nil
}

func readNativeCountsTree(t nativeTree, space string) (NativeCounts, *NativeError) {
	names := []string{"records", "finding_occurrences", "cve_occurrences",
		"opaque_identifier_occurrences", "unidentified_occurrences", "package_inventory_occurrences"}
	if t.kind != 'o' || !hasKeys(t, names...) {
		return NativeCounts{}, artifactErrorSpace(NativeCodeInvalidArtifact, space, 0)
	}
	var counts NativeCounts
	fields := []*uint64{&counts.Records, &counts.FindingOccurrences, &counts.CVEOccurrences,
		&counts.OpaqueIdentifierOccurrences, &counts.UnidentifiedOccurrences, &counts.PackageInventoryOccurrences}
	for i, name := range names {
		v, _ := t.member(name)
		n, ok := parseCanonicalUint(v.num)
		if !ok {
			return NativeCounts{}, artifactErrorSpace(NativeCodeInvalidArtifact, space, 0)
		}
		*fields[i] = n
	}
	return counts, nil
}

func readNativeLossTree(t nativeTree, space string) (NativeLoss, *NativeError) {
	if t.kind != 'o' || !hasKeys(t, "path", "reason", "occurrences") {
		return NativeLoss{}, artifactErrorSpace(NativeCodeInvalidArtifact, space, 0)
	}
	path, _ := t.member("path")
	reason, _ := t.member("reason")
	occurrences, _ := t.member("occurrences")
	n, ok := parseCanonicalUint(occurrences.num)
	if !ok || n < 1 || n > 4_294_967_295 {
		return NativeLoss{}, artifactErrorSpace(NativeCodeInvalidArtifact, space, 0)
	}
	return NativeLoss{Path: path.str, Reason: reason.str, Occurrences: n}, nil
}

// hasKeys reports whether a tree is an object whose members are exactly names,
// in order.
func hasKeys(t nativeTree, names ...string) bool {
	if t.kind != 'o' || len(t.keys) != len(names) {
		return false
	}
	for i, name := range names {
		if t.keys[i] != name {
			return false
		}
	}
	return true
}

// firstUnknownKeyOffset returns the byte offset of the first object member whose
// key is not in names, if any.
func firstUnknownKeyOffset(t nativeTree, names []string) (uint64, bool) {
	known := make(map[string]struct{}, len(names))
	for _, n := range names {
		known[n] = struct{}{}
	}
	for i, k := range t.keys {
		if _, ok := known[k]; !ok {
			if i < len(t.keyStart) {
				return t.keyStart[i], true
			}
			return 0, true
		}
	}
	return 0, false
}

// parseCanonicalUint parses a canonical non-negative decimal integer.
func parseCanonicalUint(token string) (uint64, bool) {
	if token == "" {
		return 0, false
	}
	if token == "0" {
		return 0, true
	}
	if token[0] == '0' {
		return 0, false
	}
	var value uint64
	for i := 0; i < len(token); i++ {
		c := token[i]
		if c < '0' || c > '9' {
			return 0, false
		}
		next := value*10 + uint64(c-'0')
		if next < value {
			return 0, false
		}
		value = next
	}
	return value, true
}

func optBoolFromTree(t nativeTree) *bool {
	if t.kind == 'b' {
		v := t.boolean
		return &v
	}
	return nil
}

func optIntFromTree(t nativeTree) *int {
	if t.kind == 'n' {
		if n, ok := parseCanonicalUint(t.num); ok && n <= 10_000 {
			v := int(n)
			return &v
		}
	}
	return nil
}

// derivedCounts returns the per-image vulnerability occurrences, package groups
// and package occurrences of one validated record (§6.2 cardinality budgets).
func derivedCounts(obj NativeObject) (vulns, groups, pkgs uint64) {
	for i, key := range obj.Keys {
		switch key {
		case "vulnerabilities":
			if arr, ok := obj.Values[i].(NativeArray); ok {
				vulns = uint64(len(arr.Items))
			}
		case "packages":
			arr, ok := obj.Values[i].(NativeArray)
			if !ok {
				continue
			}
			groups = uint64(len(arr.Items))
			for _, item := range arr.Items {
				group, ok := item.(NativeObject)
				if !ok {
					continue
				}
				for gi, gk := range group.Keys {
					if gk != "pkgs" {
						continue
					}
					if parr, ok := group.Values[gi].(NativeArray); ok {
						pkgs += uint64(len(parr.Items))
					}
				}
			}
		}
	}
	return vulns, groups, pkgs
}

// ValidateNativeValueShape checks that every record's projected value keeps
// Keys and Values in step (and carries valid strings and witnesses). Production
// calls it before measuring a record, so a mutated DTO cannot panic the encoder.
func ValidateNativeValueShape(src NativeSource) *NativeError {
	for _, record := range src.Records {
		if err := validateValueShape(record.Data); err != nil {
			return err
		}
	}
	return nil
}

// ValidateNativeSource revalidates a source DTO (metadata coherence and closed
// projection schema) so an encoder cannot publish a mutated or empty DTO
// (ADR-0027 §6.5 steps 5-7, §11.3).
func ValidateNativeSource(src NativeSource) *NativeError {
	if !knownNativeProfile(src.Profile) {
		return artifactError(NativeCodeInvalidArtifact, 0)
	}
	if !validFamilyVersion(src.Profile, canonicalArtifactVersion(src.Version)) {
		return artifactError(NativeCodeInvalidArtifact, 0)
	}
	if err := validateNativeContextVersion(src.Context, canonicalArtifactVersion(src.Version)); err != nil {
		return err
	}
	for _, record := range src.Records {
		if err := validateValueShape(record.Data); err != nil {
			return err
		}
	}
	if err := validateNativeSourceMetadata(src); err != nil {
		return err
	}
	return validateNativeSourceSchema(src)
}

// validateValueShape checks that every projected object keeps Keys and Values in
// step, so a mutated DTO cannot panic the encoder.
func validateValueShape(value NativeValue) *NativeError {
	switch t := value.(type) {
	case NativeObject:
		if len(t.Keys) != len(t.Values) {
			return artifactError(NativeCodeInvalidArtifact, 0)
		}
		seen := make(map[string]struct{}, len(t.Keys))
		for i, key := range t.Keys {
			if _, dup := seen[key]; dup {
				return artifactError(NativeCodeInvalidArtifact, 0)
			}
			seen[key] = struct{}{}
			if err := validateValueShape(t.Values[i]); err != nil {
				return err
			}
		}
	case NativeArray:
		for _, item := range t.Items {
			if err := validateValueShape(item); err != nil {
				return err
			}
		}
	case NativeString:
		if !utf8.ValidString(string(t)) {
			return artifactError(NativeCodeInvalidArtifact, 0)
		}
	case NativeRedacted:
		if t.Kind != "null" && t.Kind != "empty" && t.Kind != "value" {
			return artifactError(NativeCodeInvalidArtifact, 0)
		}
	}
	return nil
}

// validSourceHashLiteral checks the manifest source_hash literal
// sha256:[0-9a-f]{64} of ADR-0027 §11.7.
func validSourceHashLiteral(value string) bool {
	if len(value) != 71 || value[:7] != "sha256:" {
		return false
	}
	for i := 7; i < 71; i++ {
		c := value[i]
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}
