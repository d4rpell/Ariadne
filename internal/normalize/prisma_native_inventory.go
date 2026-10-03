package normalize

import (
	"crypto/sha256"
	"encoding/hex"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/d4rpell/Ariadne/internal/ingest"
	"github.com/d4rpell/Ariadne/internal/schema"
)

// Typed interpretation result of ADR-0027 §10.1 and §12. The inventory keeps the
// aggregate facts of the manifest (counts, losses, limitations), the typed
// diagnostics with their coordinates over the canonical sanitized source, and
// never a subject, a decision state or a runtime binding.

// NativeInventory is the in-memory interpretation result. It contains no
// subject, product_status, exploitability, risk_decision, evaluation or Result.
type NativeInventory struct {
	SourceHash     string
	SourceBytes    uint64
	Profile        ingest.NativeProfile
	RecordCount    int
	Counts         ingest.NativeCounts
	Losses         []ingest.NativeLoss
	Limitations    []string
	Diagnostics    []ingest.NativeDiagnostic
	Facts          []NativeFact
	Context        ingest.NativeContext
	RuntimeBinding string
}

// InterpretPrismaNative interprets a validated source and returns the typed
// inventory, including diagnostics anchored to the canonical source offsets.
func InterpretPrismaNative(source ingest.NativeSource, sourceHash string, sourceBytes uint64) (NativeInventory, *ingest.NativeError) {
	manifest, err := BuildNativeManifest(source, sourceHash, sourceBytes)
	if err != nil {
		return NativeInventory{}, err
	}
	sourceBytesCanonical := ingest.EncodeNativeSource(source)
	offsets := nativePointerOffsets(sourceBytesCanonical)
	diagnostics := nativeDiagnostics(source, offsets)
	return NativeInventory{
		SourceHash:     sourceHash,
		SourceBytes:    sourceBytes,
		Profile:        source.Profile,
		RecordCount:    len(source.Records),
		Counts:         manifest.Counts,
		Losses:         manifest.Losses,
		Limitations:    manifest.Limitations,
		Diagnostics:    diagnostics,
		Facts:          nativeFacts(source),
		Context:        ingest.CloneNativeContext(source.Context),
		RuntimeBinding: "not_attempted",
	}, nil
}

// nativeDiagnosticBuilder accumulates diagnostics and resolves their offsets.
type nativeDiagnosticBuilder struct {
	offsets    map[string]uint64
	acquiredAt string
	out        []ingest.NativeDiagnostic
}

func (b *nativeDiagnosticBuilder) emit(code, path, locator string) {
	offset, ok := b.offsets[locator]
	if !ok {
		offset, ok = b.offsets[path]
	}
	pathCopy := path
	locatorCopy := locator
	b.out = append(b.out, ingest.NativeDiagnostic{
		Code: code, Phase: ingest.NativePhaseInterpretation,
		Path: &pathCopy, Locator: &locatorCopy,
		OffsetSpace: ingest.NativeSpaceSource, Offset: offset,
	})
}

// nativeDiagnostics walks the source and emits the interpretation diagnostics
// with concrete JSON pointers (§12.4.3). Presence rows carry the parent object
// as locator; value rows carry the value itself.
func nativeDiagnostics(source ingest.NativeSource, offsets map[string]uint64) []ingest.NativeDiagnostic {
	b := &nativeDiagnosticBuilder{offsets: offsets, acquiredAt: source.Context.AcquiredAt}
	b.emit("no_runtime_binding", "/records", "/records")
	diagContext(b, source.Context)
	isCSV := source.Profile.Selector == schema.NativeCSVSelector
	for i, record := range source.Records {
		obj, ok := record.Data.(ingest.NativeObject)
		if !ok {
			continue
		}
		ptr := "/records/" + strconv.Itoa(i) + "/data"
		if isCSV {
			diagCSVRow(b, ptr, obj)
		} else {
			diagImage(b, ptr, obj)
		}
	}
	sort.SliceStable(b.out, func(i, j int) bool {
		ri, pi, ci := diagnosticOrderKey(&b.out[i])
		rj, pj, cj := diagnosticOrderKey(&b.out[j])
		if ri != rj {
			return ri < rj
		}
		if pi != pj {
			return pi < pj
		}
		return ci < cj
	})
	return b.out
}

// diagnosticOrderKey returns (record ordinal, path, code) for the §12.4.5 order:
// global conditions first, then records by ordinal, then path, then code.
func diagnosticOrderKey(d *ingest.NativeDiagnostic) (int, string, string) {
	path := ""
	if d.Path != nil {
		path = *d.Path
	}
	ordinal := -1
	if strings.HasPrefix(path, "/records/") {
		rest := path[len("/records/"):]
		if end := strings.IndexByte(rest, '/'); end > 0 {
			if n, err := strconv.Atoi(rest[:end]); err == nil {
				ordinal = n
			}
		}
	}
	return ordinal, path, d.Code
}

func diagPresence(b *nativeDiagnosticBuilder, ptr, name string, value ingest.NativeValue) {
	switch t := value.(type) {
	case ingest.NativeNull:
		b.emit("field_null", ptr+"/"+name, ptr+"/"+name)
	case ingest.NativeString:
		if t == "" {
			b.emit("field_empty", ptr+"/"+name, ptr+"/"+name)
		}
	case ingest.NativeArray:
		if len(t.Items) == 0 {
			b.emit("field_empty", ptr+"/"+name, ptr+"/"+name)
		}
	case ingest.NativeObject:
		if len(t.Keys) == 0 {
			b.emit("field_empty", ptr+"/"+name, ptr+"/"+name)
		}
	}
}

func diagImage(b *nativeDiagnosticBuilder, ptr string, obj ingest.NativeObject) {
	present := indexObject(obj)
	scan, scanOK := instantOf(present, "scanTime")
	for _, name := range schema.NativeKMembers("") {
		value, ok := present[name]
		if !ok {
			b.emit("field_absent", ptr+"/"+name, ptr)
			if name == "type" {
				b.emit("scope_unknown", ptr+"/type", ptr)
			}
			continue
		}
		switch name {
		case "vulnerabilities":
			diagPresence(b, ptr, name, value)
			for j, item := range asArray(value) {
				if finding, isObj := item.(ingest.NativeObject); isObj {
					diagFinding(b, ptr+"/vulnerabilities/"+strconv.Itoa(j), finding, scan, scanOK)
				}
			}
		case "packages":
			diagPresence(b, ptr, name, value)
			for j, item := range asArray(value) {
				if group, isObj := item.(ingest.NativeObject); isObj {
					diagGroup(b, ptr+"/packages/"+strconv.Itoa(j), group)
				}
			}
		case "scanTime", "firstScanTime":
			diagPresence(b, ptr, name, value)
			diagTimeString(b, ptr+"/"+name, value)
		case "clusters", "namespaces", "repoDigests":
			diagPresence(b, ptr, name, value)
			for j, item := range asArray(value) {
				if str, isStr := item.(ingest.NativeString); isStr && str == "" {
					b.emit("field_empty", ptr+"/"+name+"/"+strconv.Itoa(j), ptr+"/"+name+"/"+strconv.Itoa(j))
				}
			}
		case "type":
			diagPresence(b, ptr, name, value)
			if unconfirmedJSONType(value) {
				b.emit("scope_unknown", ptr+"/type", ptr+"/type")
			}
		case "scanID", "errCode":
			diagPresence(b, ptr, name, value)
			diagINT(b, ptr+"/"+name, ptr+"/"+name+"/number", value, false)
		case "vulnerabilitiesCount":
			diagPresence(b, ptr, name, value)
			diagINT(b, ptr+"/"+name, ptr+"/"+name+"/number", value, true)
			if num, isNum := value.(ingest.NativeNumber); isNum {
				st := interpretINT20(num.Token)
				if vulns, isArr := present["vulnerabilities"].(ingest.NativeArray); isArr && st.state == "valid" && st.value >= 0 && uint64(st.value) != uint64(len(vulns.Items)) {
					b.emit("declared_count_difference", ptr+"/vulnerabilitiesCount", ptr+"/vulnerabilitiesCount/number")
				}
			}
		case "missingDistroVulnCoverage":
			diagPresence(b, ptr, name, value)
			if flag, isBool := value.(ingest.NativeBool); isBool && bool(flag) {
				b.emit("distro_coverage_missing", ptr+"/missingDistroVulnCoverage", ptr+"/missingDistroVulnCoverage")
			}
		case "repoTag":
			diagPresence(b, ptr, name, value)
			if object, isObj := value.(ingest.NativeObject); isObj {
				diagAux(b, ptr+"/repoTag", "repoTag", object)
			}
		case "tags", "instances":
			diagPresence(b, ptr, name, value)
			for j, item := range asArray(value) {
				if object, isObj := item.(ingest.NativeObject); isObj {
					diagAux(b, ptr+"/"+name+"/"+strconv.Itoa(j), name+"[]", object)
				}
			}
		default:
			diagPresence(b, ptr, name, value)
		}
	}
	if v, ok := present["err"]; ok {
		b.emit("excluded_by_policy", ptr+"/err", ptr+"/err/redacted")
		if witness, isR := v.(ingest.NativeRedacted); isR && witness.Kind == "value" {
			b.emit("scan_error_reported", ptr+"/err", ptr+"/err/redacted")
		}
	}
	for _, name := range schema.NativeExcludedMembers("") {
		if _, ok := present[name]; ok {
			b.emit("excluded_by_policy", ptr+"/"+name, ptr+"/"+name+"/redacted")
		}
	}
	first, firstOK := instantOf(present, "firstScanTime")
	if acquired, ok := parseNativeInstant(b.acquiredAt); ok && scanOK && scan.After(acquired) {
		b.emit("scan_after_acquisition", ptr+"/scanTime", ptr+"/scanTime")
	}
	if scanOK && firstOK && first.After(scan) {
		b.emit("temporal_order_conflict", ptr+"/firstScanTime", ptr+"/firstScanTime")
	}
}

func diagFinding(b *nativeDiagnosticBuilder, ptr string, finding ingest.NativeObject, scanInstant time.Time, scanOK bool) {
	present := indexObject(finding)
	for _, name := range schema.NativeKMembers("vulnerabilities[]") {
		value, ok := present[name]
		if !ok {
			b.emit("field_absent", ptr+"/"+name, ptr)
			if name == "cve" {
				b.emit("identifier_unavailable", ptr+"/cve", ptr)
			}
			continue
		}
		switch name {
		case "cve":
			diagPresence(b, ptr, name, value)
			if !identifierDiagnostic(b, ptr+"/cve", value) {
				// presence already emitted
			}
		case "cvss":
			diagPresence(b, ptr, name, value)
			if num, isNum := value.(ingest.NativeNumber); isNum {
				if code := scoreDiagnosticCode(num.Token); code != "" {
					b.emit(code, ptr+"/cvss", ptr+"/cvss/number")
				}
			}
		case "vecStr":
			diagPresence(b, ptr, name, value)
			if str, isStr := value.(ingest.NativeString); isStr && str != "" {
				if code := vectorDiagnosticCode(string(str)); code != "" {
					b.emit(code, ptr+"/vecStr", ptr+"/vecStr")
				}
			}
		case "discovered":
			diagPresence(b, ptr, name, value)
			diagTimeString(b, ptr+"/discovered", value)
			if scanOK {
				if disc, ok := parseNativeInstant(stringifyString(value)); ok && disc.After(scanInstant) {
					b.emit("temporal_order_conflict", ptr+"/discovered", ptr+"/discovered")
				}
			}
		case "published", "fixDate":
			diagPresence(b, ptr, name, value)
			diagINT(b, ptr+"/"+name, ptr+"/"+name+"/number", value, false)
			diagUnix(b, ptr+"/"+name, ptr+"/"+name+"/number", value)
		case "id", "layerTime":
			diagPresence(b, ptr, name, value)
			diagINT(b, ptr+"/"+name, ptr+"/"+name+"/number", value, false)
		default:
			diagPresence(b, ptr, name, value)
		}
	}
	if _, hasCvss := present["cvss"].(ingest.NativeNumber); hasCvss {
		if str, isStr := present["vecStr"].(ingest.NativeString); isStr && str != "" {
			b.emit("cvss_consistency_not_verified", ptr, ptr)
		}
	}
	for _, name := range schema.NativeExcludedMembers("vulnerabilities[]") {
		if _, ok := present[name]; ok {
			b.emit("excluded_by_policy", ptr+"/"+name, ptr+"/"+name+"/redacted")
		}
	}
	diagProcedure(b, ptr, finding)
}

// diagAux emits the presence and discard rows of one auxiliary object.
func diagAux(b *nativeDiagnosticBuilder, ptr, path string, obj ingest.NativeObject) {
	present := indexObject(obj)
	for _, name := range schema.NativeKMembers(path) {
		value, ok := present[name]
		if !ok {
			b.emit("field_absent", ptr+"/"+name, ptr)
			continue
		}
		diagPresence(b, ptr, name, value)
		if name == "modified" {
			diagTimeString(b, ptr+"/modified", value)
		}
	}
	for _, name := range schema.NativeExcludedMembers(path) {
		if _, ok := present[name]; ok {
			b.emit("excluded_by_policy", ptr+"/"+name, ptr+"/"+name+"/redacted")
		}
	}
}

func diagCSVRow(b *nativeDiagnosticBuilder, ptr string, row ingest.NativeObject) {
	b.emit("row_semantics_unverified", ptr, ptr)
	present := indexObject(row)
	for _, col := range schema.NativeCSVColumns() {
		value, ok := present[col.Name]
		if !ok {
			continue
		}
		if col.Disposition == schema.NativeExcludedValue {
			b.emit("excluded_by_policy", ptr+"/"+col.Name, ptr+"/"+col.Name+"/redacted")
			continue
		}
		s, isStr := value.(ingest.NativeString)
		if col.Name == "CVE ID" {
			if isStr && identifierDiagnostic(b, ptr+"/CVE ID", value) {
				continue
			}
		}
		if col.Name == "CVSS" && isStr && s != "" {
			if code := scoreDiagnosticCode(string(s)); code != "" {
				b.emit(code, ptr+"/CVSS", ptr+"/CVSS")
			}
			continue
		}
		if isCSVTimeColumn(col.Name) && isStr && s != "" {
			b.emit("time_uninterpretable", ptr+"/"+col.Name, ptr+"/"+col.Name)
			continue
		}
		diagPresence(b, ptr, col.Name, value)
	}
}

// identifierDiagnostic emits the identifier rows and reports whether the value
// was a non-empty CVE (no diagnostic in that case).
func identifierDiagnostic(b *nativeDiagnosticBuilder, ptr string, value ingest.NativeValue) bool {
	switch t := value.(type) {
	case ingest.NativeNull:
		b.emit("identifier_unavailable", ptr, ptr)
	case ingest.NativeString:
		if t == "" {
			b.emit("identifier_unavailable", ptr, ptr)
			return false
		}
		if !isCVE(string(t)) {
			b.emit("identifier_uninterpreted", ptr, ptr)
		}
		return true
	}
	return false
}

func diagTimeNode(b *nativeDiagnosticBuilder, ptr, name string, value ingest.NativeValue) {
	s, ok := value.(ingest.NativeString)
	if !ok || s == "" {
		return
	}
	if _, valid := parseNativeInstant(string(s)); !valid {
		b.emit("time_uninterpretable", ptr+"/"+name, ptr+"/"+name)
	}
}

func scoreDiagnosticCode(token string) string {
	switch interpretScore(token).state {
	case "invalid":
		return "scalar_invalid"
	case "uninterpretable":
		return "scalar_uninterpretable"
	}
	return ""
}

func vectorDiagnosticCode(value string) string {
	switch interpretVector(value) {
	case vectorInvalidSyntax:
		return "vector_syntax_invalid"
	case vectorVersionUnknown, vectorSemanticsChecked:
		return "vector_semantics_unverified"
	}
	return ""
}

// nativePointerOffsets scans canonical JSON bytes and returns the byte offset of
// the first token of every value, keyed by its RFC 6901 JSON pointer.
func nativePointerOffsets(data []byte) map[string]uint64 {
	offsets := map[string]uint64{}
	var walk func(pos int, ptr string) int
	walk = func(pos int, ptr string) int {
		for pos < len(data) && (data[pos] == ' ' || data[pos] == '\t' || data[pos] == '\n' || data[pos] == '\r') {
			pos++
		}
		if pos >= len(data) {
			return pos
		}
		offsets[ptr] = uint64(pos)
		switch data[pos] {
		case '{':
			pos++
			for pos < len(data) && (data[pos] == ' ' || data[pos] == '\t' || data[pos] == '\n' || data[pos] == '\r') {
				pos++
			}
			if pos < len(data) && data[pos] == '}' {
				return pos + 1
			}
			for {
				for pos < len(data) && data[pos] != '"' {
					pos++
				}
				key, next := scanJSONString(data, pos)
				pos = next
				for pos < len(data) && data[pos] != ':' {
					pos++
				}
				pos++
				pos = walk(pos, ptr+"/"+escapePointer(key))
				for pos < len(data) && data[pos] != ',' && data[pos] != '}' {
					pos++
				}
				if pos < len(data) && data[pos] == ',' {
					pos++
					continue
				}
				return pos + 1
			}
		case '[':
			pos++
			for pos < len(data) && (data[pos] == ' ' || data[pos] == '\t' || data[pos] == '\n' || data[pos] == '\r') {
				pos++
			}
			if pos < len(data) && data[pos] == ']' {
				return pos + 1
			}
			index := 0
			for {
				pos = walk(pos, ptr+"/"+strconv.Itoa(index))
				index++
				for pos < len(data) && data[pos] != ',' && data[pos] != ']' {
					pos++
				}
				if pos < len(data) && data[pos] == ',' {
					pos++
					continue
				}
				return pos + 1
			}
		case '"':
			_, next := scanJSONString(data, pos)
			return next
		default:
			for pos < len(data) && data[pos] != ',' && data[pos] != '}' && data[pos] != ']' {
				pos++
			}
			return pos
		}
	}
	walk(0, "")
	return offsets
}

// scanJSONString returns the decoded string at pos (which must be '"') and the
// position after the closing quote.
func scanJSONString(data []byte, pos int) (string, int) {
	pos++
	start := pos
	var out []byte
	for pos < len(data) {
		c := data[pos]
		if c == '\\' {
			out = append(out, data[start:pos]...)
			pos++
			if pos < len(data) {
				out = append(out, data[pos])
				pos++
			}
			start = pos
			continue
		}
		if c == '"' {
			out = append(out, data[start:pos]...)
			return string(out), pos + 1
		}
		pos++
	}
	return string(data[start:pos]), pos
}

// escapePointer applies the RFC 6901 escapes for a JSON pointer segment.
func escapePointer(segment string) string {
	segment = strings.ReplaceAll(segment, "~", "~0")
	return strings.ReplaceAll(segment, "/", "~1")
}

// NativeFact is one conserved scalar declaration with its presence state, its
// original token or value, its interpretation state, its locator and its scalar
// hash (ADR-0027 §7.1, §10.1). It is not an EvidenceItem.value_hash.
type NativeFact struct {
	Path        string
	Presence    string
	Kind        string
	Original    string
	State       string
	Locator     string
	ValueHash   string
	DerivedInt  *int64
	Deciseconds *int
	InstantUTC  string
	VectorVer   string
}

// nativeFacts collects the scalar facts of every conserved member.
func nativeFacts(source ingest.NativeSource) []NativeFact {
	var facts []NativeFact
	isCSV := source.Profile.Selector == schema.NativeCSVSelector
	for i, record := range source.Records {
		obj, ok := record.Data.(ingest.NativeObject)
		if !ok {
			continue
		}
		ptr := "/records/" + strconv.Itoa(i) + "/data"
		if isCSV {
			facts = append(facts, csvFacts(ptr, obj)...)
			continue
		}
		facts = append(facts, imageFacts(ptr, obj)...)
	}
	return facts
}

func nodeKind(kind schema.NativeKind) string {
	switch kind {
	case schema.NativeBOOL:
		return "bool"
	case schema.NativeINT20, schema.NativeNUM32:
		return "number"
	case schema.NativeObject:
		return "object"
	case schema.NativeArray:
		return "array"
	case schema.NativeExcluded:
		return "redacted"
	default:
		return "string"
	}
}

func scalarFact(path, locator string, node schema.NativeNode, value ingest.NativeValue) NativeFact {
	fact := NativeFact{Path: path, Locator: locator, Kind: nodeKind(node.Kind)}
	switch t := value.(type) {
	case ingest.NativeNull:
		fact.Presence = "null"
	case ingest.NativeString:
		fact.Presence = "value"
		fact.Original = string(t)
		if t == "" {
			fact.Presence = "empty"
		}
		fact.ValueHash = scalarHash([]byte(t))
	case ingest.NativeNumber:
		fact.Presence = "value"
		fact.Original = t.Token
		fact.ValueHash = scalarHash([]byte(t.Token))
		fact.Locator = locator + "/number"
		if st := interpretINT20(t.Token); st.state == "valid" && !(strings.HasSuffix(path, "/vulnerabilitiesCount") && st.value < 0) {
			v := st.value
			fact.DerivedInt = &v
		}
		if node.Kind == schema.NativeNUM32 || strings.HasSuffix(path, "/cvss") {
			if sc := interpretScore(t.Token); sc.state == "valid" {
				d := sc.deciseconds
				fact.Deciseconds = &d
			}
		}
		if strings.HasSuffix(path, "/published") || strings.HasSuffix(path, "/fixDate") {
			if st := interpretINT20(t.Token); st.state == "valid" && st.value != 0 {
				if instant, ok := unixInstant(st.value); ok {
					fact.InstantUTC = instant.UTC().Format(time.RFC3339Nano)
				}
			}
		}
	case ingest.NativeBool:
		fact.Presence = "value"
		if bool(t) {
			fact.Original = "true"
		} else {
			fact.Original = "false"
		}
		fact.ValueHash = scalarHash([]byte(fact.Original))
	case ingest.NativeRedacted:
		fact.Kind = "redacted"
		fact.Presence = t.Kind
	}
	fact.State = factState(path, node, value)
	if str, ok := value.(ingest.NativeString); ok {
		if fact.State == "interpreted" {
			if instant, ok := parseNativeInstant(string(str)); ok {
				fact.InstantUTC = instant.UTC().Format(time.RFC3339Nano)
			}
		}
		if strings.HasSuffix(path, "/vecStr") {
			for _, prefix := range []string{"CVSS:3.0/", "CVSS:3.1/", "CVSS:4.0/"} {
				if strings.HasPrefix(string(str), prefix) {
					fact.VectorVer = strings.TrimSuffix(prefix, "/")
				}
			}
		}
	}
	return fact
}

func factState(path string, node schema.NativeNode, value ingest.NativeValue) string {
	switch v := value.(type) {
	case ingest.NativeNumber:
		switch node.Kind {
		case schema.NativeINT20:
			if strings.HasSuffix(path, "/cvss") {
				return interpretScore(v.Token).state
			}
			if strings.HasSuffix(path, "/published") || strings.HasSuffix(path, "/fixDate") {
				return unixFactState(v.Token)
			}
			if strings.HasSuffix(path, "/vulnerabilitiesCount") && interpretINT20(v.Token).state == "valid" {
				if interpretINT20(v.Token).value < 0 {
					return "invalid"
				}
			}
			return interpretINT20(v.Token).state
		case schema.NativeNUM32:
			return interpretScore(v.Token).state
		}
	case ingest.NativeString:
		if strings.HasSuffix(path, "/vecStr") {
			if v == "" {
				return ""
			}
			switch interpretVector(string(v)) {
			case vectorInvalidSyntax:
				return "invalid_syntax"
			case vectorVersionUnknown:
				return "version_unknown"
			case vectorSemanticsChecked:
				return "syntax_checked_semantics_unverified"
			}
		}
		if strings.HasSuffix(path, "/vecStr") {
			switch interpretVector(string(v)) {
			case vectorInvalidSyntax:
				return "invalid_syntax"
			case vectorVersionUnknown:
				return "version_unknown"
			case vectorSemanticsChecked:
				return "syntax_checked_semantics_unverified"
			}
		}
		if strings.HasSuffix(path, "/scanTime") || strings.HasSuffix(path, "/firstScanTime") ||
			strings.HasSuffix(path, "/discovered") || strings.HasSuffix(path, "/modified") {
			if _, ok := parseNativeInstant(string(v)); ok {
				return "interpreted"
			}
			return "uninterpretable"
		}
	}
	return ""
}

func imageFacts(ptr string, obj ingest.NativeObject) []NativeFact {
	var facts []NativeFact
	present := indexObject(obj)
	for _, name := range schema.NativeKMembers("") {
		node, _ := schema.NativeRecordNode(name)
		value, ok := present[name]
		if !ok {
			facts = append(facts, NativeFact{Path: ptr + "/" + name, Presence: "absent", Kind: nodeKind(node.Kind), Locator: ptr})
			continue
		}
		switch node.Kind {
		case schema.NativeObject, schema.NativeArray:
			continue
		}
		facts = append(facts, scalarFact(ptr+"/"+name, ptr+"/"+name, node, value))
	}
	if value, ok := present["vulnerabilities"]; ok {
		for j, item := range asArray(value) {
			if finding, isObj := item.(ingest.NativeObject); isObj {
				facts = append(facts, findingFacts(ptr+"/vulnerabilities/"+strconv.Itoa(j), finding)...)
			}
		}
	}
	if value, ok := present["packages"]; ok {
		for g, item := range asArray(value) {
			if group, isObj := item.(ingest.NativeObject); isObj {
				facts = append(facts, groupFacts(ptr+"/packages/"+strconv.Itoa(g), group)...)
			}
		}
	}
	for _, name := range []string{"clusters", "namespaces", "repoDigests"} {
		value, ok := present[name]
		if !ok {
			continue
		}
		node, _ := schema.NativeRecordNode(name + "[]")
		for j, item := range asArray(value) {
			lp := ptr + "/" + name + "/" + strconv.Itoa(j)
			facts = append(facts, scalarFact(lp, lp, node, item))
		}
	}
	for _, name := range []string{"repoTag", "instances"} {
		if value, ok := present[name]; ok {
			if name == "repoTag" {
				if obj, isObj := value.(ingest.NativeObject); isObj {
					facts = append(facts, auxFacts(ptr+"/repoTag", "repoTag", obj)...)
				}
				continue
			}
			for j, item := range asArray(value) {
				if obj, isObj := item.(ingest.NativeObject); isObj {
					facts = append(facts, auxFacts(ptr+"/instances/"+strconv.Itoa(j), "instances[]", obj)...)
				}
			}
		}
	}
	if value, ok := present["tags"]; ok {
		for j, item := range asArray(value) {
			if obj, isObj := item.(ingest.NativeObject); isObj {
				facts = append(facts, auxFacts(ptr+"/tags/"+strconv.Itoa(j), "tags[]", obj)...)
			}
		}
	}
	return facts
}

// groupFacts collects the scalar facts of one package group and its packages.
func groupFacts(ptr string, group ingest.NativeObject) []NativeFact {
	var facts []NativeFact
	present := indexObject(group)
	for _, name := range schema.NativeKMembers("packages[]") {
		node, _ := schema.NativeRecordNode("packages[]." + name)
		value, ok := present[name]
		if !ok {
			facts = append(facts, NativeFact{Path: ptr + "/" + name, Presence: "absent", Kind: nodeKind(node.Kind), Locator: ptr})
			continue
		}
		if name == "pkgs" {
			for j, item := range asArray(value) {
				if pkg, isObj := item.(ingest.NativeObject); isObj {
					facts = append(facts, packageFacts(ptr+"/pkgs/"+strconv.Itoa(j), pkg)...)
				}
			}
			continue
		}
		if node.Kind == schema.NativeObject || node.Kind == schema.NativeArray {
			continue
		}
		facts = append(facts, scalarFact(ptr+"/"+name, ptr+"/"+name, node, value))
	}
	return facts
}

// packageFacts collects the scalar facts of one inventory package.
func packageFacts(ptr string, pkg ingest.NativeObject) []NativeFact {
	var facts []NativeFact
	present := indexObject(pkg)
	for _, name := range schema.NativeKMembers("packages[].pkgs[]") {
		node, _ := schema.NativeRecordNode("packages[].pkgs[]." + name)
		value, ok := present[name]
		if !ok {
			facts = append(facts, NativeFact{Path: ptr + "/" + name, Presence: "absent", Kind: nodeKind(node.Kind), Locator: ptr})
			continue
		}
		if node.Kind == schema.NativeObject || node.Kind == schema.NativeArray {
			continue
		}
		facts = append(facts, scalarFact(ptr+"/"+name, ptr+"/"+name, node, value))
	}
	return facts
}

// auxFacts collects the scalar facts of one auxiliary object.
func auxFacts(ptr, path string, obj ingest.NativeObject) []NativeFact {
	var facts []NativeFact
	present := indexObject(obj)
	for _, name := range schema.NativeKMembers(path) {
		node, _ := schema.NativeRecordNode(path + "." + name)
		value, ok := present[name]
		if !ok {
			facts = append(facts, NativeFact{Path: ptr + "/" + name, Presence: "absent", Kind: nodeKind(node.Kind), Locator: ptr})
			continue
		}
		if node.Kind == schema.NativeObject || node.Kind == schema.NativeArray {
			continue
		}
		facts = append(facts, scalarFact(ptr+"/"+name, ptr+"/"+name, node, value))
	}
	return facts
}

func findingFacts(ptr string, finding ingest.NativeObject) []NativeFact {
	var facts []NativeFact
	present := indexObject(finding)
	for _, name := range schema.NativeKMembers("vulnerabilities[]") {
		node, _ := schema.NativeRecordNode("vulnerabilities[]." + name)
		value, ok := present[name]
		if !ok {
			facts = append(facts, NativeFact{Path: ptr + "/" + name, Presence: "absent", Kind: nodeKind(node.Kind), Locator: ptr})
			continue
		}
		if node.Kind == schema.NativeObject || node.Kind == schema.NativeArray {
			continue
		}
		fact := scalarFact(ptr+"/"+name, ptr+"/"+name, node, value)
		if name == "cve" {
			fact.State = identifierState(value)
		}
		facts = append(facts, fact)
	}
	if value, ok := present["vulnerabilityDataSources"]; ok {
		for d, item := range asArray(value) {
			pair, isObj := item.(ingest.NativeObject)
			if !isObj {
				continue
			}
			fields := indexObject(pair)
			for _, member := range []string{"attribute", "source"} {
				val, ok := fields[member]
				if !ok {
					continue
				}
				n, _ := schema.NativeRecordNode("vulnerabilities[].vulnerabilityDataSources[]." + member)
				facts = append(facts, scalarFact(ptr+"/vulnerabilityDataSources/"+strconv.Itoa(d)+"/"+member, ptr+"/vulnerabilityDataSources/"+strconv.Itoa(d)+"/"+member, n, val))
			}
		}
	}
	return facts
}

func csvFacts(ptr string, row ingest.NativeObject) []NativeFact {
	var facts []NativeFact
	present := indexObject(row)
	for _, col := range schema.NativeCSVColumns() {
		if col.Disposition == schema.NativeExcludedValue {
			continue
		}
		node := schema.NativeNode{Kind: schema.NativeS4096}
		value, ok := present[col.Name]
		if !ok {
			facts = append(facts, NativeFact{Path: ptr + "/" + col.Name, Presence: "absent", Kind: "string", Locator: ptr})
			continue
		}
		fact := scalarFact(ptr+"/"+col.Name, ptr+"/"+col.Name, node, value)
		if col.Name == "CVSS" && fact.Original != "" {
			fact.State = interpretScore(fact.Original).state
			if sc := interpretScore(fact.Original); sc.state == "valid" {
				d := sc.deciseconds
				fact.Deciseconds = &d
			}
		}
		if col.Name == "CVE ID" {
			fact.State = identifierState(value)
		}
		facts = append(facts, fact)
	}
	return facts
}

func identifierState(value ingest.NativeValue) string {
	s, ok := value.(ingest.NativeString)
	if !ok || s == "" {
		return "unavailable"
	}
	if isCVE(string(s)) {
		return "cve"
	}
	return "uninterpreted"
}

func scalarHash(preimage []byte) string {
	digest := sha256.Sum256(preimage)
	return "sha256:" + hex.EncodeToString(digest[:])
}

// diagContext emits the context and coverage diagnostics of §12.5.5.
func diagContext(b *nativeDiagnosticBuilder, ctx ingest.NativeContext) {
	switch ctx.CaptureTermination {
	case "aborted":
		b.emit("capture_aborted", "/context/capture_termination", "/context/capture_termination")
	case "unknown":
		b.emit("capture_unknown", "/context/capture_termination", "/context/capture_termination")
	}
	if ctx.DeclaredEdition == "unknown" || ctx.DeclaredRelease == "unknown" {
		path := "/context/declared_edition"
		if ctx.DeclaredRelease == "unknown" {
			path = "/context/declared_release"
		}
		b.emit("origin_version_unknown", path, path)
	}
	if ctx.ScopeMode == "unknown" {
		b.emit("scope_unknown", "/context/scope_mode", "/context/scope_mode")
	}
	if ctx.FieldsMode == "unknown" {
		b.emit("scope_unknown", "/context/fields_mode", "/context/fields_mode")
	}
	for _, member := range []struct {
		name  string
		value *bool
	}{{"compact", ctx.Compact}, {"normalized_severity", ctx.NormalizedSeverity}, {"layers", ctx.Layers}} {
		if member.value == nil {
			b.emit("scope_unknown", "/context/"+member.name, "/context/"+member.name)
		}
	}
	if ctx.ScopeMode == "filtered_declared" {
		b.emit("selection_restricted", "/context/scope_mode", "/context/scope_mode")
	}
	if ctx.FieldsMode == "restricted_declared" {
		b.emit("selection_restricted", "/context/fields_mode", "/context/fields_mode")
	}
	if ctx.Compact != nil && *ctx.Compact {
		b.emit("selection_restricted", "/context/compact", "/context/compact")
	}
	if ctx.PageMode == "single_page_declared" || ctx.PageMode == "unknown" {
		b.emit("page_scope_unverified", "/context/page_mode", "/context/page_mode")
	}
}

// diagGroup emits the diagnostics of one package group.
func diagGroup(b *nativeDiagnosticBuilder, ptr string, group ingest.NativeObject) {
	present := indexObject(group)
	for _, name := range schema.NativeKMembers("packages[]") {
		value, ok := present[name]
		if !ok {
			b.emit("field_absent", ptr+"/"+name, ptr)
			continue
		}
		if name == "pkgs" {
			diagPresence(b, ptr, name, value)
			for j, item := range asArray(value) {
				if pkg, isObj := item.(ingest.NativeObject); isObj {
					diagPackage(b, ptr+"/pkgs/"+strconv.Itoa(j), pkg)
				}
			}
			continue
		}
		diagPresence(b, ptr, name, value)
	}
}

// diagPackage emits the diagnostics of one inventory package.
func diagPackage(b *nativeDiagnosticBuilder, ptr string, pkg ingest.NativeObject) {
	present := indexObject(pkg)
	for _, name := range schema.NativeKMembers("packages[].pkgs[]") {
		value, ok := present[name]
		if !ok {
			b.emit("field_absent", ptr+"/"+name, ptr)
			continue
		}
		diagPresence(b, ptr, name, value)
		if name == "layerTime" {
			diagINT(b, ptr+"/layerTime", ptr+"/layerTime/number", value, false)
		}
	}
	for _, name := range schema.NativeExcludedMembers("packages[].pkgs[]") {
		if _, ok := present[name]; ok {
			b.emit("excluded_by_policy", ptr+"/"+name, ptr+"/"+name+"/redacted")
		}
	}
}

// unixFactState maps a Unix integer token to its temporal interpretation state.
func unixFactState(token string) string {
	st := interpretINT20(token)
	if st.state != "valid" {
		return st.state
	}
	if st.value == 0 {
		return "zero_unspecified"
	}
	if _, ok := unixInstant(st.value); !ok {
		return "uninterpretable"
	}
	return "interpreted"
}

// diagINT emits the §12.5.3 integer rows for one INT20 node.
func diagINT(b *nativeDiagnosticBuilder, path, locator string, value ingest.NativeValue, nonNegative bool) {
	num, ok := value.(ingest.NativeNumber)
	if !ok {
		return
	}
	st := interpretINT20(num.Token)
	switch {
	case st.state == "invalid", nonNegative && st.state == "valid" && st.value < 0:
		b.emit("scalar_invalid", path, locator)
	case st.state == "uninterpretable":
		b.emit("scalar_uninterpretable", path, locator)
	}
}

// diagUnix emits the §12.5.4 rows for a Unix-integer finding time.
func diagUnix(b *nativeDiagnosticBuilder, path, locator string, value ingest.NativeValue) {
	num, ok := value.(ingest.NativeNumber)
	if !ok {
		return
	}
	st := interpretINT20(num.Token)
	if st.state != "valid" {
		return
	}
	if st.value == 0 {
		b.emit("time_zero_unspecified", path, locator)
		return
	}
	if _, ok := unixInstant(st.value); !ok {
		b.emit("time_uninterpretable", path, locator)
	}
}

// diagTimeString emits the §12.5.4 row for a JSON date-time node.
func diagTimeString(b *nativeDiagnosticBuilder, path string, value ingest.NativeValue) {
	s, ok := value.(ingest.NativeString)
	if !ok || s == "" {
		return
	}
	if _, valid := parseNativeInstant(string(s)); !valid {
		b.emit("time_uninterpretable", path, path)
	}
}

// diagProcedure emits the presence, INT and conflict rows of the procedure
// pairs of one finding.
func diagProcedure(b *nativeDiagnosticBuilder, ptr string, finding ingest.NativeObject) {
	value, ok := indexObject(finding)["vulnerabilityDataSources"]
	if !ok {
		return
	}
	arr, isArr := value.(ingest.NativeArray)
	if !isArr {
		return
	}
	type pairIdx struct {
		index  int
		source int64
	}
	byAttribute := map[int64][]pairIdx{}
	for d, item := range arr.Items {
		pair, isObj := item.(ingest.NativeObject)
		if !isObj {
			continue
		}
		pairPtr := ptr + "/vulnerabilityDataSources/" + strconv.Itoa(d)
		fields := indexObject(pair)
		for _, member := range []string{"attribute", "source"} {
			val, ok := fields[member]
			if !ok {
				b.emit("field_absent", pairPtr+"/"+member, pairPtr)
				continue
			}
			diagPresence(b, pairPtr, member, val)
			diagINT(b, pairPtr+"/"+member, pairPtr+"/"+member+"/number", val, false)
		}
		attribute, aok := asValidInt(fields["attribute"])
		source, sok := asValidInt(fields["source"])
		if !aok || !sok {
			continue
		}
		byAttribute[attribute] = append(byAttribute[attribute], pairIdx{index: d, source: source})
	}
	for _, pairs := range byAttribute {
		first := pairs[0].source
		for _, p := range pairs[1:] {
			if p.source != first {
				loc := ptr + "/vulnerabilityDataSources/" + strconv.Itoa(p.index) + "/source"
				b.emit("attribute_source_conflict", loc, loc+"/number")
				break
			}
		}
	}
}

// stringifyString returns the decoded value of a NativeString, or "".
func stringifyString(value ingest.NativeValue) string {
	if s, ok := value.(ingest.NativeString); ok {
		return string(s)
	}
	return ""
}
