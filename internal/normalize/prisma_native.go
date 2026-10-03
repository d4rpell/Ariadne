package normalize

import (
	"io"
	"sort"
	"strings"
	"time"

	"github.com/d4rpell/Ariadne/internal/ingest"
	"github.com/d4rpell/Ariadne/internal/schema"
)

// Conservative interpretation of a native source and derivation of its
// manifest (ADR-0027 §7–§12). The interpretation keeps only structural
// associations, distinguishes presence states and never promotes a scanner
// declaration into a runtime binding or a decision state. This first cut covers
// the presence, discard, identifier and context rows of §12.5.2 and §12.5.5 and
// the exhaustive limitation list of §12.5.6; the CVSS, vector, time and
// procedural-conflict rows of §12.5.3–§12.5.4 are pending and are recorded as a
// declared gap, not as "no diagnostic".

const nativeRecordRootPath = "/records/[]/data"
const nativeVulnerabilityPath = "/records/[]/data/vulnerabilities/[]"

// NativeArtifacts is the three-artifact output of §11.1, in memory.
type NativeArtifacts struct {
	Source   []byte
	Manifest []byte
	Digest   []byte
}

// nativeAccumulator gathers the aggregate manifest facts.
type nativeAccumulator struct {
	counts      ingest.NativeCounts
	losses      map[nativeLossKey]uint64
	limitations map[string]bool
}

type nativeLossKey struct{ path, reason string }

func newNativeAccumulator() *nativeAccumulator {
	return &nativeAccumulator{
		losses:      map[nativeLossKey]uint64{},
		limitations: map[string]bool{},
	}
}

func (a *nativeAccumulator) activate(code string) { a.limitations[code] = true }

func (a *nativeAccumulator) addLoss(path, reason string, n uint64) {
	a.losses[nativeLossKey{path: path, reason: reason}] += n
}

// EncodePrismaNativeImport produces the three artifacts of §11.1 from a
// validated source. The counts, losses and limitations are recomputed here; no
// caller-supplied manifest fact is trusted.
func EncodePrismaNativeImport(source ingest.NativeSource) (NativeArtifacts, *ingest.NativeError) {
	if err := ingest.ValidateNativeValueShape(source); err != nil {
		return NativeArtifacts{}, err
	}
	if !ingest.NativeDerivedSizesWithinBudgets(source) {
		return NativeArtifacts{}, outputLimit()
	}
	if err := ingest.ValidateNativeSource(source); err != nil {
		return NativeArtifacts{}, err
	}
	sourceBytes, sourceOK := ingest.EncodeNativeSourceBounded(source, schema.NativeMaxDerivedSourceBytes)
	if !sourceOK {
		return NativeArtifacts{}, outputLimit()
	}
	if _, err := ingest.ParseNativeSourceBytes(sourceBytes); err != nil {
		return NativeArtifacts{}, outputLimit()
	}
	sourceHash := ingest.HashNativeSource(sourceBytes)
	manifest, err := BuildNativeManifest(source, sourceHash, uint64(len(sourceBytes)))
	if err != nil {
		return NativeArtifacts{}, err
	}
	manifestBytes, manifestOK := ingest.EncodeNativeManifestBounded(manifest, schema.NativeMaxManifestBytes)
	if !manifestOK {
		return NativeArtifacts{}, outputLimit()
	}
	if _, _, err := ingest.ParseNativeManifestBytes(manifestBytes); err != nil {
		return NativeArtifacts{}, outputLimit()
	}
	digest := ingest.NativeManifestSidecar(ingest.HashNativeManifest(manifestBytes))
	return NativeArtifacts{Source: sourceBytes, Manifest: manifestBytes, Digest: digest}, nil
}

// outputLimit is the fatal projection diagnostic of §11.9.1 / §12.5.7.
func outputLimit() *ingest.NativeError {
	return &ingest.NativeError{
		Code: ingest.NativeCodeOutputLimit, Phase: ingest.NativePhaseProjection,
		OffsetSpace: ingest.NativeSpaceNone,
	}
}

// BuildNativeManifest interprets the source and derives its complete manifest.
func BuildNativeManifest(source ingest.NativeSource, sourceHash string, sourceBytes uint64) (ingest.NativeManifest, *ingest.NativeError) {
	acc := newNativeAccumulator()
	isCSV := source.Profile.Selector == schema.NativeCSVSelector

	acc.activate("documentary_profile")
	if isCSV {
		acc.activate("csv_header_unverified")
	}
	acc.activate("origin_not_authenticated")
	acc.activate("inventory_not_verified")
	acc.activate("no_runtime_binding")
	acc.activate("cvss_consistency_not_verified")
	acc.activate("original_content_not_retained")
	acc.counts.Records = uint64(len(source.Records))

	interpretContext(acc, source.Context)
	acquired, _ := parseNativeInstant(source.Context.AcquiredAt)

	for _, record := range source.Records {
		obj, ok := record.Data.(ingest.NativeObject)
		if !ok {
			continue
		}
		if isCSV {
			interpretCSVRow(acc, obj)
		} else {
			interpretImage(acc, obj, acquired)
		}
	}

	manifest := ingest.NativeManifest{
		SourceHash:    sourceHash,
		SourceBytes:   sourceBytes,
		OriginalBytes: source.Input.OriginalBytes,
		Profile:       source.Profile,
		Counts:        acc.counts,
		Limitations:   orderedLimitations(acc.limitations),
		Version:       source.Version,
	}
	losses, err := orderedLosses(acc.losses)
	if err != nil {
		return ingest.NativeManifest{}, err
	}
	manifest.Losses = losses
	return manifest, nil
}

// interpretContext activates the context and coverage limitations of §12.5.5
// together with their declared losses.
func interpretContext(acc *nativeAccumulator, ctx ingest.NativeContext) {
	switch ctx.CaptureTermination {
	case "aborted":
		acc.activate("capture_aborted")
		acc.addLoss("/context/capture_termination", "coverage_unavailable", 1)
	case "unknown":
		acc.activate("capture_unknown")
		acc.addLoss("/context/capture_termination", "coverage_unavailable", 1)
	}
	if ctx.DeclaredEdition == "unknown" || ctx.DeclaredRelease == "unknown" {
		acc.activate("origin_version_unknown")
		if ctx.DeclaredRelease == "unknown" {
			acc.addLoss("/context/declared_release", "coverage_unavailable", 1)
		} else {
			acc.addLoss("/context/declared_edition", "coverage_unavailable", 1)
		}
	}
	if ctx.ScopeMode == "unknown" {
		acc.activate("scope_unknown")
		acc.addLoss("/context/scope_mode", "coverage_unavailable", 1)
	}
	if ctx.FieldsMode == "unknown" {
		acc.activate("scope_unknown")
		acc.addLoss("/context/fields_mode", "coverage_unavailable", 1)
	}
	for _, member := range []struct {
		name  string
		value *bool
	}{{"compact", ctx.Compact}, {"normalized_severity", ctx.NormalizedSeverity}, {"layers", ctx.Layers}} {
		if member.value == nil {
			acc.activate("scope_unknown")
			acc.addLoss("/context/"+member.name, "coverage_unavailable", 1)
		}
	}
	if ctx.ScopeMode == "filtered_declared" {
		acc.activate("selection_restricted")
		acc.addLoss("/context/scope_mode", "coverage_unavailable", 1)
	}
	if ctx.FieldsMode == "restricted_declared" {
		acc.activate("selection_restricted")
		acc.addLoss("/context/fields_mode", "coverage_unavailable", 1)
	}
	if ctx.Compact != nil && *ctx.Compact {
		acc.activate("selection_restricted")
		acc.addLoss("/context/compact", "coverage_unavailable", 1)
	}
	if ctx.PageMode == "single_page_declared" || ctx.PageMode == "unknown" {
		acc.activate("page_scope_unverified")
		acc.addLoss("/context/page_mode", "coverage_unavailable", 1)
	}
}

// interpretImage walks one JSON image object (family K/X of §12.5.1).
func interpretImage(acc *nativeAccumulator, obj ingest.NativeObject, acquired time.Time) {
	present := indexObject(obj)
	scanInstant, scanOK := instantOf(present, "scanTime")
	for _, name := range schema.NativeKMembers("") {
		value, ok := present[name]
		if !ok {
			acc.activate("fields_incomplete")
			continue
		}
		nativePresenceValue(acc, value)
		switch name {
		case "vulnerabilities":
			for _, item := range asArray(value) {
				finding, ok := item.(ingest.NativeObject)
				if !ok {
					continue
				}
				acc.counts.FindingOccurrences++
				interpretFinding(acc, finding, scanInstant, scanOK)
			}
		case "packages":
			for _, item := range asArray(value) {
				group, ok := item.(ingest.NativeObject)
				if !ok {
					continue
				}
				interpretGroup(acc, group)
			}
		case "scanTime", "firstScanTime":
			interpretTimeNode(acc, nativeRecordRootPath+"/"+name, value)
		case "clusters", "namespaces", "repoDigests":
			for _, item := range asArray(value) {
				nativePresenceValue(acc, item)
			}
		case "scanID", "errCode":
			interpretINTNode(acc, nativeRecordRootPath+"/"+name, value, false)
		case "vulnerabilitiesCount":
			interpretINTNode(acc, nativeRecordRootPath+"/"+name, value, true)
		case "type":
			if unconfirmedJSONType(value) {
				acc.activate("scope_unknown")
				acc.addLoss(nativeRecordRootPath+"/type", "coverage_unavailable", 1)
			}
		case "repoTag":
			if obj, isObj := value.(ingest.NativeObject); isObj {
				interpretAuxObject(acc, "repoTag", obj)
			}
		case "tags", "instances":
			for _, item := range asArray(value) {
				if obj, isObj := item.(ingest.NativeObject); isObj {
					interpretAuxObject(acc, name+"[]", obj)
				}
			}
		default:
			nativePresenceValue(acc, value)
		}
	}
	firstInstant, firstOK := instantOf(present, "firstScanTime")
	for _, coll := range []string{"vulnerabilities", "packages"} {
		value, ok := present[coll]
		if !ok {
			acc.addLoss(nativeRecordRootPath+"/"+coll, "coverage_unavailable", 1)
			continue
		}
		if _, isNull := value.(ingest.NativeNull); isNull {
			acc.addLoss(nativeRecordRootPath+"/"+coll, "coverage_unavailable", 1)
		}
	}
	if _, ok := present["type"]; !ok {
		acc.activate("scope_unknown")
		acc.addLoss(nativeRecordRootPath+"/type", "coverage_unavailable", 1)
	}
	if scanOK && !acquired.IsZero() && scanInstant.After(acquired) {
		acc.addLoss(nativeRecordRootPath+"/scanTime", "semantics_unverified", 1)
		acc.activate("temporal_conflict")
	}
	if firstOK && scanOK && firstInstant.After(scanInstant) {
		acc.addLoss(nativeRecordRootPath+"/firstScanTime", "semantics_unverified", 1)
		acc.activate("temporal_conflict")
	}
	for _, name := range schema.NativeExcludedMembers("") {
		if _, ok := present[name]; ok {
			acc.addLoss(nativeRecordRootPath+"/"+name, "excluded_by_policy", 1)
			acc.activate("data_excluded")
		}
	}
	if _, ok := present["err"]; ok {
		acc.addLoss(nativeRecordRootPath+"/err", "redacted_error", 1)
		acc.activate("data_excluded")
		if witness, isRedacted := present["err"].(ingest.NativeRedacted); isRedacted && witness.Kind == "value" {
			acc.addLoss(nativeRecordRootPath+"/err", "coverage_unavailable", 1)
			acc.activate("scan_error_reported")
		}
	}
	if value, ok := present["missingDistroVulnCoverage"]; ok {
		if flag, isBool := value.(ingest.NativeBool); isBool && bool(flag) {
			acc.addLoss(nativeRecordRootPath+"/missingDistroVulnCoverage", "coverage_unavailable", 1)
			acc.activate("distro_coverage_missing")
		}
	}
	if count, ok := present["vulnerabilitiesCount"]; ok {
		if num, isNum := count.(ingest.NativeNumber); isNum {
			st := interpretINT20(num.Token)
			if vulns, isArr := present["vulnerabilities"].(ingest.NativeArray); isArr && st.state == "valid" && st.value >= 0 {
				if uint64(st.value) != uint64(len(vulns.Items)) {
					acc.addLoss(nativeRecordRootPath+"/vulnerabilitiesCount", "coverage_unavailable", 1)
					acc.activate("declared_count_difference")
				}
			}
		}
	}
}

// interpretGroup walks one JSON package group.
func interpretGroup(acc *nativeAccumulator, group ingest.NativeObject) {
	present := indexObject(group)
	for _, name := range schema.NativeKMembers("packages[]") {
		value, ok := present[name]
		if !ok {
			acc.activate("fields_incomplete")
			if name == "pkgs" {
				acc.addLoss("/records/[]/data/packages/[]/pkgs", "coverage_unavailable", 1)
			}
			continue
		}
		nativePresenceValue(acc, value)
		if name == "pkgs" {
			if _, isNull := value.(ingest.NativeNull); isNull {
				acc.addLoss("/records/[]/data/packages/[]/pkgs", "coverage_unavailable", 1)
				continue
			}
			for _, item := range asArray(value) {
				pkg, ok := item.(ingest.NativeObject)
				if !ok {
					continue
				}
				acc.counts.PackageInventoryOccurrences++
				interpretPackage(acc, pkg)
			}
			continue
		}
		nativePresenceValue(acc, value)
	}
}

// interpretPackage walks one JSON package in the inventory of §7.4.
func interpretPackage(acc *nativeAccumulator, pkg ingest.NativeObject) {
	const pkgPath = "/records/[]/data/packages/[]/pkgs/[]"
	present := indexObject(pkg)
	for _, name := range schema.NativeKMembers("packages[].pkgs[]") {
		value, ok := present[name]
		if !ok {
			acc.activate("fields_incomplete")
			continue
		}
		nativePresenceValue(acc, value)
		if name == "layerTime" {
			interpretINTNode(acc, pkgPath+"/layerTime", value, false)
			continue
		}
		nativePresenceValue(acc, value)
	}
	for _, name := range schema.NativeExcludedMembers("packages[].pkgs[]") {
		if _, ok := present[name]; ok {
			acc.addLoss(pkgPath+"/"+name, "excluded_by_policy", 1)
			acc.activate("data_excluded")
		}
	}
}

// unconfirmedJSONType reports whether the image `type` is null or empty.
func unconfirmedJSONType(value ingest.NativeValue) bool {
	switch t := value.(type) {
	case ingest.NativeNull:
		return true
	case ingest.NativeString:
		return t == ""
	}
	return false
}

// interpretAuxObject walks one JSON auxiliary object (repoTag, tags[],
// instances[]) applying its K/X rows of §7.5.
func interpretAuxObject(acc *nativeAccumulator, path string, obj ingest.NativeObject) {
	present := indexObject(obj)
	base := nativeRecordRootPath + "/" + strings.ReplaceAll(path, "[]", "/[]")
	for _, name := range schema.NativeKMembers(path) {
		value, ok := present[name]
		if !ok {
			acc.activate("fields_incomplete")
			continue
		}
		nativePresenceValue(acc, value)
		if name == "modified" {
			interpretTimeNode(acc, base+"/modified", value)
			continue
		}
		nativePresenceValue(acc, value)
	}
	for _, name := range schema.NativeExcludedMembers(path) {
		if _, ok := present[name]; ok {
			acc.addLoss(base+"/"+name, "excluded_by_policy", 1)
			acc.activate("data_excluded")
		}
	}
}

// interpretFinding walks one JSON vulnerability object.
func interpretFinding(acc *nativeAccumulator, finding ingest.NativeObject, scanInstant time.Time, scanOK bool) {
	present := indexObject(finding)
	for _, name := range schema.NativeKMembers("vulnerabilities[]") {
		value, ok := present[name]
		if !ok {
			acc.activate("fields_incomplete")
			continue
		}
		nativePresenceValue(acc, value)
		switch name {
		case "cve":
			classifyJSONIdentifier(acc, value)
		case "discovered":
			interpretTimeNode(acc, nativeVulnerabilityPath+"/discovered", value)
		case "published", "fixDate":
			interpretUnixNode(acc, nativeVulnerabilityPath+"/"+name, value)
		case "id", "layerTime":
			interpretINTNode(acc, nativeVulnerabilityPath+"/"+name, value, false)
		default:
			nativePresenceValue(acc, value)
		}
	}
	if _, ok := present["cve"]; !ok {
		acc.counts.UnidentifiedOccurrences++
		acc.addLoss(nativeVulnerabilityPath+"/cve", "coverage_unavailable", 1)
	}
	if scanOK {
		if inst, ok := instantOf(present, "discovered"); ok && inst.After(scanInstant) {
			acc.addLoss(nativeVulnerabilityPath+"/discovered", "semantics_unverified", 1)
			acc.activate("temporal_conflict")
		}
	}
	for _, name := range schema.NativeExcludedMembers("vulnerabilities[]") {
		if _, ok := present[name]; ok {
			acc.addLoss(nativeVulnerabilityPath+"/"+name, "excluded_by_policy", 1)
			acc.activate("data_excluded")
		}
	}
	interpretVulnerabilityScalars(acc, finding, present)
}

// instantOf returns the parsed instant of a conserved date-time member, if any.
func instantOf(present map[string]ingest.NativeValue, name string) (time.Time, bool) {
	value, ok := present[name]
	if !ok {
		return time.Time{}, false
	}
	s, ok := value.(ingest.NativeString)
	if !ok || s == "" {
		return time.Time{}, false
	}
	return parseNativeInstant(string(s))
}

// interpretCSVRow walks one H39 data row.
func interpretCSVRow(acc *nativeAccumulator, row ingest.NativeObject) {
	acc.counts.FindingOccurrences++
	acc.addLoss(nativeRecordRootPath, "semantics_unverified", 1)
	acc.activate("csv_header_unverified")
	present := indexObject(row)
	for _, col := range schema.NativeCSVColumns() {
		value, ok := present[col.Name]
		if !ok {
			continue
		}
		if col.Disposition == schema.NativeExcludedValue {
			acc.addLoss(nativeRecordRootPath+"/"+col.Name, "excluded_by_policy", 1)
			acc.activate("data_excluded")
			continue
		}
		if col.Name == "CVE ID" {
			classifyCSVIdentifier(acc, value)
			continue
		}
		if col.Name == "CVSS" {
			s, isStr := value.(ingest.NativeString)
			if !isStr || s == "" {
				nativePresenceValue(acc, value)
				continue
			}
			switch interpretScore(string(s)).state {
			case "invalid":
				acc.addLoss(nativeRecordRootPath+"/CVSS", "invalid_value", 1)
				acc.activate("values_invalid")
			case "uninterpretable":
				acc.addLoss(nativeRecordRootPath+"/CVSS", "semantics_unverified", 1)
				acc.activate("values_uninterpretable")
			}
			continue
		}
		if isCSVTimeColumn(col.Name) {
			if s, isStr := value.(ingest.NativeString); isStr && s != "" {
				acc.addLoss(nativeRecordRootPath+"/"+col.Name, "semantics_unverified", 1)
				acc.activate("values_uninterpretable")
			} else {
				nativePresenceValue(acc, value)
			}
			continue
		}
		nativePresenceValue(acc, value)
	}
}

// isCSVTimeColumn reports whether a column carries an unverified CSV date
// (ADR-0027 §9.4: Fix Date, Published, Discovered, Start Time stay literal).
func isCSVTimeColumn(name string) bool {
	switch name {
	case "Fix Date", "Published", "Discovered", "Start Time":
		return true
	}
	return false
}

// presenceValue applies the presence rows of §12.5.2 to a conserved member.
func nativePresenceValue(acc *nativeAccumulator, value ingest.NativeValue) {
	switch t := value.(type) {
	case ingest.NativeNull:
		acc.activate("fields_incomplete")
	case ingest.NativeString:
		if t == "" {
			acc.activate("fields_incomplete")
		}
	case ingest.NativeArray:
		// empty or not: no additional limitation on an array.
	case ingest.NativeObject:
		// no additional limitation on an object.
	}
}

// classifyJSONIdentifier classifies the finding `cve` and applies the
// identifier rows of §12.5.2.
func classifyJSONIdentifier(acc *nativeAccumulator, value ingest.NativeValue) {
	switch t := value.(type) {
	case ingest.NativeNull:
		acc.counts.UnidentifiedOccurrences++
		acc.addLoss(nativeVulnerabilityPath+"/cve", "coverage_unavailable", 1)
		acc.activate("fields_incomplete")
	case ingest.NativeString:
		if t == "" {
			acc.counts.UnidentifiedOccurrences++
			acc.addLoss(nativeVulnerabilityPath+"/cve", "coverage_unavailable", 1)
			acc.activate("fields_incomplete")
			return
		}
		if isCVE(string(t)) {
			acc.counts.CVEOccurrences++
			return
		}
		acc.counts.OpaqueIdentifierOccurrences++
		acc.addLoss(nativeVulnerabilityPath+"/cve", "semantics_unverified", 1)
		acc.activate("values_uninterpretable")
	}
}

// classifyCSVIdentifier classifies the row `CVE ID` cell.
func classifyCSVIdentifier(acc *nativeAccumulator, value ingest.NativeValue) {
	s, ok := value.(ingest.NativeString)
	if !ok {
		return
	}
	if s == "" {
		acc.counts.UnidentifiedOccurrences++
		acc.addLoss(nativeRecordRootPath+"/CVE ID", "coverage_unavailable", 1)
		acc.activate("fields_incomplete")
		return
	}
	if isCVE(string(s)) {
		acc.counts.CVEOccurrences++
		return
	}
	acc.counts.OpaqueIdentifierOccurrences++
	acc.addLoss(nativeRecordRootPath+"/CVE ID", "semantics_unverified", 1)
	acc.activate("values_uninterpretable")
}

// isCVE matches the anchored CVE grammar CVE-[0-9]{4}-[0-9]{4,} (§10.3).
func isCVE(value string) bool {
	if len(value) < 12 || value[0] != 'C' || value[1] != 'V' || value[2] != 'E' || value[3] != '-' {
		return false
	}
	i := 4
	for n := 0; n < 4; n++ {
		if i >= len(value) || value[i] < '0' || value[i] > '9' {
			return false
		}
		i++
	}
	if i >= len(value) || value[i] != '-' {
		return false
	}
	i++
	digits := 0
	for i < len(value) && value[i] >= '0' && value[i] <= '9' {
		i++
		digits++
	}
	return i == len(value) && digits >= 4
}

// indexObject maps member names to values.
func indexObject(obj ingest.NativeObject) map[string]ingest.NativeValue {
	out := make(map[string]ingest.NativeValue, len(obj.Keys))
	for i, key := range obj.Keys {
		out[key] = obj.Values[i]
	}
	return out
}

func asArray(value ingest.NativeValue) []ingest.NativeValue {
	if arr, ok := value.(ingest.NativeArray); ok {
		return arr.Items
	}
	return nil
}

// orderedLosses returns the losses sorted by path then reason, capped at 512.
func orderedLosses(losses map[nativeLossKey]uint64) ([]ingest.NativeLoss, *ingest.NativeError) {
	keys := make([]nativeLossKey, 0, len(losses))
	for key := range losses {
		keys = append(keys, key)
	}
	sort.Slice(keys, func(i, j int) bool {
		if keys[i].path != keys[j].path {
			return keys[i].path < keys[j].path
		}
		return keys[i].reason < keys[j].reason
	})
	if len(keys) > schema.NativeMaxLossEntries {
		return nil, &ingest.NativeError{
			Code: ingest.NativeCodeOutputLimit, Phase: ingest.NativePhaseProjection,
			OffsetSpace: ingest.NativeSpaceNone,
		}
	}
	out := make([]ingest.NativeLoss, 0, len(keys))
	for _, key := range keys {
		out = append(out, ingest.NativeLoss{Path: key.path, Reason: key.reason, Occurrences: losses[key]})
	}
	return out, nil
}

// orderedLimitations returns the activated limitations in contract order.
func orderedLimitations(set map[string]bool) []string {
	out := []string{}
	for _, code := range schema.NativeLimitations() {
		if set[code] {
			out = append(out, code)
		}
	}
	return out
}

// ReplayPrismaNative verifies the three derived artifacts and returns the
// recomputed manifest (ADR-0027 §11.10). Canonical serialization and the source
// hash are validated by the ingest readers; here the sidecar digest is checked,
// the manifest facts are recomputed from the source and compared, and any
// divergence is a fatal diagnostic. No caller-supplied counter is trusted.
func ReplayPrismaNative(source, manifest, digest io.Reader, artifactSelector, artifactVersion string) (NativeInventory, *ingest.NativeError) {
	if artifactSelector != schema.NativeSourceFormat {
		return NativeInventory{}, &ingest.NativeError{
			Code: ingest.NativeCodeUnsupportedSelector, Phase: ingest.NativePhaseContext, OffsetSpace: ingest.NativeSpaceNone,
		}
	}
	if artifactVersion != schema.NativeFormatVersion && artifactVersion != schema.NativeFormatVersionV11 {
		return NativeInventory{}, &ingest.NativeError{
			Code: ingest.NativeCodeUnsupportedVersion, Phase: ingest.NativePhaseContext, OffsetSpace: ingest.NativeSpaceNone,
		}
	}
	if ingest.IsNilNativeReader(source) || ingest.IsNilNativeReader(manifest) || ingest.IsNilNativeReader(digest) {
		return NativeInventory{}, &ingest.NativeError{
			Code: ingest.NativeCodeNilReader, Phase: ingest.NativePhaseContext, OffsetSpace: ingest.NativeSpaceNone,
		}
	}
	sourceBytes, err := ingest.AcquireNativeArtifact(source, schema.NativeMaxDerivedSourceBytes, ingest.NativeSpaceSource)
	if err != nil {
		return NativeInventory{}, err
	}
	manifestBytes, err := ingest.AcquireNativeArtifact(manifest, schema.NativeMaxManifestBytes, ingest.NativeSpaceManifest)
	if err != nil {
		return NativeInventory{}, err
	}
	digestBytes, err := ingest.AcquireNativeArtifact(digest, 72, ingest.NativeSpaceDigest)
	if err != nil {
		return NativeInventory{}, err
	}
	parsed, err := ingest.ParseNativeSourceBytes(sourceBytes)
	if err != nil {
		return NativeInventory{}, err
	}
	declared, manifestBytes, err := ingest.ParseNativeManifestBytes(manifestBytes)
	if err != nil {
		return NativeInventory{}, err
	}
	// The requested version must match the version carried by both artifacts, so
	// a 1.1 source is never replayed as 1.0 or the reverse (§9.5).
	if parsed.Version != artifactVersion || declared.Version != artifactVersion {
		return NativeInventory{}, &ingest.NativeError{
			Code: ingest.NativeCodeUnsupportedVersion, Phase: ingest.NativePhaseContext, OffsetSpace: ingest.NativeSpaceNone,
		}
	}
	if !validManifestSidecar(digestBytes) {
		return NativeInventory{}, &ingest.NativeError{
			Code: ingest.NativeCodeInvalidArtifact, Phase: ingest.NativePhaseReplayAdmission, OffsetSpace: ingest.NativeSpaceDigest,
		}
	}
	if string(ingest.NativeManifestSidecar(ingest.HashNativeManifest(manifestBytes))) != string(digestBytes) {
		return NativeInventory{}, replayFailure(ingest.NativeCodeHashMismatch, ingest.NativeSpaceDigest)
	}
	canonicalSource := ingest.EncodeNativeSource(parsed)
	sourceHash := ingest.HashNativeSource(canonicalSource)
	if declared.SourceHash != sourceHash {
		offset, _ := ingest.NativeManifestMemberValueOffset(manifestBytes, "source_hash")
		return NativeInventory{}, &ingest.NativeError{
			Code: ingest.NativeCodeHashMismatch, Phase: ingest.NativePhaseReplayVerification,
			OffsetSpace: ingest.NativeSpaceManifest, Offset: offset,
		}
	}
	recomputed, rerr := BuildNativeManifest(parsed, sourceHash, uint64(len(canonicalSource)))
	if rerr != nil {
		return NativeInventory{}, rerr
	}
	if member, differs := firstDiscrepantManifestMember(declared, recomputed); differs {
		offset, _ := ingest.NativeManifestMemberValueOffset(manifestBytes, member)
		return NativeInventory{}, &ingest.NativeError{
			Code: ingest.NativeCodeManifestMismatch, Phase: ingest.NativePhaseReplayVerification,
			OffsetSpace: ingest.NativeSpaceManifest, Offset: offset,
		}
	}
	return InterpretPrismaNative(parsed, sourceHash, uint64(len(canonicalSource)))
}

func replayFailure(code, space string) *ingest.NativeError {
	return &ingest.NativeError{Code: code, Phase: ingest.NativePhaseReplayVerification, OffsetSpace: space}
}

// firstDiscrepantManifestMember returns the first member, in the §11.7
// contractual order, on which the received manifest and the recomputed one
// disagree. source_hash is handled separately as a `hash_mismatch`.
func firstDiscrepantManifestMember(a, b ingest.NativeManifest) (string, bool) {
	switch {
	case a.Version != b.Version:
		return "version", true
	case a.SourceBytes != b.SourceBytes:
		return "source_bytes", true
	case a.OriginalBytes != b.OriginalBytes:
		return "original_bytes", true
	case a.Profile != b.Profile:
		return "profile", true
	case a.Counts != b.Counts:
		return "counts", true
	case !nativeLossesEqual(a.Losses, b.Losses):
		return "losses", true
	case !nativeLimitationsEqual(a.Limitations, b.Limitations):
		return "limitations", true
	}
	return "", false
}

func nativeLossesEqual(a, b []ingest.NativeLoss) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func nativeLimitationsEqual(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// validManifestSidecar reports whether the sidecar is the exact 72-byte
// "sha256:" + 64 lower hex + LF of §11.8.
func validManifestSidecar(digest []byte) bool {
	if len(digest) != 72 || digest[71] != '\n' {
		return false
	}
	if string(digest[:7]) != "sha256:" {
		return false
	}
	for _, c := range digest[7:71] {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}
