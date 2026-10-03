package schema

import (
	"sort"
	"strings"
)

// The prisma-native offline profiles are the closed input contracts of
// ADR-0027: CSV and JSON reports of deployed images from Prisma Cloud Compute,
// sanitized offline into a derived source plus a verifiable manifest. Nothing
// here parses input; this file fixes the selectors, the closed field
// disposition tables, the budgets and the closed diagnostic vocabulary that the
// ingest and normalize readers enforce. The normative text is
// .internal/design-A2-07-adaptadores-nativos-offline.md (sections 4 to 12).

// Selectors and profile identity of ADR-0027 §4.1.
const (
	NativeJSONSelector     = "prisma-native-images-json-v1"
	NativeCSVSelector      = "prisma-native-images-csv-v1"
	NativeInputVersion     = "1.0"
	NativeJSONProfile      = "compute-sh-34.04.145-images-json"
	NativeCSVProfile       = "compute-sh-34.04.145-images-csv-h39-candidate"
	NativeRedactionPolicy  = "prisma-native-offline-redaction-v1/1.0"
	NativeAdapterSemantics = "prisma-native-offline/1.0"
)

// Native source and manifest format identity of ADR-0027 §11.2 and §11.7.
const (
	NativeSourceFormat   = "prisma-native-source-v1"
	NativeManifestFormat = "prisma-native-manifest-v1"
	NativeFormatVersion  = "1.0"
	// NativeFormatVersionV11 is the artifact provenance version reserved, by
	// ADR-0028 §9.5, for compute_api sources and manifests. The version 1.0
	// artifacts keep their bytes unchanged.
	NativeFormatVersionV11 = "1.1"
	NativeSourceName       = "native-source.json"
)

// Acquisition provenance literals of ADR-0027 §5 and ADR-0028 §9.5. Version 1.0
// admits the offline kinds; version 1.1 admits only compute_api.
const (
	NativeAcquisitionKindExport    = "operator_export"
	NativeAcquisitionKindSynthetic = "synthetic_fixture"
	NativeAcquisitionKindAPI       = "compute_api"
)

// Registry-image family of ADR-0029: a separate report class with its own
// report_kind, artifact version and formats. It reuses the deployed-image field
// disposition and budgets unchanged; only the report class, the artifact family
// and the CI-oriented semantics differ. The CSV selector/profile are reserved
// (ES-R1 open) and are not admitted.
const (
	NativeRegistryJSONSelector     = "prisma-native-registry-json-v1"
	NativeRegistryCSVSelector      = "prisma-native-registry-csv-v1"
	NativeRegistryInputVersion     = "2.0"
	NativeRegistryJSONProfile      = "compute-sh-34.04.145-registry-json"
	NativeRegistryCSVProfile       = "compute-sh-34.04.145-registry-csv-candidate"
	NativeRegistryAdapterSemantics = "prisma-native-offline-registry/1.0"
	NativeRegistrySourceFormat     = "prisma-native-registry-source-v1"
	NativeRegistryManifestFormat   = "prisma-native-registry-manifest-v1"
)

// Report class literals of the native context (ADR-0027 §5, ADR-0029 §4.7).
const (
	NativeReportKindDeployed = "deployed_images"
	NativeReportKindRegistry = "registry_images"
)

// Native budget limits of ADR-0027 §6.2. Each guard is checked before the
// buffer or collection that would exceed it grows; L is admitted and L+1 is
// rejected.
const (
	NativeMaxSourceBytes           = 64 * 1024 * 1024
	NativeMaxNoProgressReads       = 100
	NativeMaxDepth                 = 32
	NativeMaxTokens                = 8_000_000
	NativeMaxRootItems             = 10_000
	NativeMaxImageObjectBytes      = 8 * 1024 * 1024
	NativeMaxObjectMembers         = 128
	NativeMaxKeyRawBytes           = 256
	NativeMaxKeyDecodedBytes       = 128
	NativeMaxStringRawBytes        = 64 * 1024
	NativeMaxNumberTokenBytes      = 128
	NativeMaxArrayElements         = 100_000
	NativeMaxVulnsPerImage         = 10_000
	NativeMaxVulnsPerSource        = 100_000
	NativeMaxVulnerabilityBytes    = 256 * 1024
	NativeMaxPackageGroupsPerImage = 64
	NativeMaxPackagesPerImage      = 20_000
	NativeMaxPackagesPerSource     = 100_000
	NativeMaxPackageBytes          = 256 * 1024
	NativeMaxContextListPerImage   = 1024
	NativeMaxDataSourcesPerVuln    = 128
	NativeMaxCSVDataRecords        = 100_000
	NativeMaxCSVStructuralFields   = 64
	NativeMaxCSVFieldBytes         = 64 * 1024
	NativeMaxCSVRecordBytes        = 512 * 1024
)

// Native derived budgets of ADR-0027 §11.9.1. They govern the produced
// native-source.json / native-manifest.json and their replay, and are separate
// from the native budgets above: a derived size is never compared against a raw
// native budget because they share an entity name.
const (
	NativeMaxDerivedSourceBytes     = 128 * 1024 * 1024
	NativeMaxDerivedSourceDepth     = 40
	NativeMaxDerivedSourceTokens    = 16_000_000
	NativeMaxDerivedObjectMembers   = 128
	NativeMaxDerivedKeyRawBytes     = 512
	NativeMaxDerivedKeyDecodedBytes = 256
	NativeMaxDerivedStringRawBytes  = 128 * 1024
	NativeMaxDerivedNumberToken     = 10
	NativeMaxDerivedRecordBytes     = 16 * 1024 * 1024
	NativeMaxDerivedCSVRecordBytes  = 1 * 1024 * 1024
	NativeMaxDerivedVulnBytes       = 512 * 1024
	NativeMaxDerivedPackageBytes    = 512 * 1024
	NativeMaxDerivedContextBytes    = 64 * 1024
	NativeMaxManifestBytes          = 64 * 1024
	NativeMaxManifestDepth          = 12
	NativeMaxManifestTokens         = 32_768
	NativeMaxManifestStringRawBytes = 2 * 1024
	NativeMaxLossEntries            = 512
	NativeMaxContextSelectedFields  = 128
	NativeMaxPageNumber             = 10_000
)

// NativeStringLimit returns the decoded byte limit of a conserved string kind
// of ADR-0027 §7.1.
func NativeStringLimit(kind NativeKind) int {
	switch kind {
	case NativeS128:
		return 128
	case NativeS256:
		return 256
	case NativeS1024:
		return 1024
	case NativeS4096:
		return 4096
	case NativeT4096:
		return 4096
	case NativeTIME128:
		return 128
	default:
		return 0
	}
}

// NativeKind is the value class of a conserved path (ADR-0027 §7.1).
type NativeKind int

const (
	NativeS128 NativeKind = iota
	NativeS256
	NativeS1024
	NativeS4096
	NativeT4096
	NativeNUM32
	NativeINT20
	NativeBOOL
	NativeTIME128
	NativeArray
	NativeObject
	NativeExcluded
)

// NativeDisposition is the per-path disposition of ADR-0027 §7.1: C conserved,
// T transformed, N conserved-but-not-interpretable, X excluded.
type NativeDisposition int

const (
	NativeConserved NativeDisposition = iota
	NativeTransformed
	NativeNonInterpretable
	NativeExcludedValue
)

// NativeNode fixes the kind, disposition and decoded limit of one conserved
// path. For arrays the element path appends "[]"; the element node carries the
// kind of the elements.
type NativeNode struct {
	Kind        NativeKind
	Disposition NativeDisposition
	MaxBytes    int // decoded limit for string/text/time; token bytes for numbers
}

// nativeRecordNodes is the closed disposition table of ADR-0027 §7.2–§7.5,
// keyed by the path of a conserved member relative to the record data root
// (`records[].data`). Array elements use the "[]" suffix. A path absent from
// this table inside an interpreted object is a `field_not_allowed` failure; the
// excluded members are present here with NativeExcluded disposition so the
// reader can walk them structurally without keeping a value.
var nativeRecordNodes = map[string]NativeNode{
	// §7.2 image object, conserved members.
	"id":                          {Kind: NativeS4096, Disposition: NativeConserved, MaxBytes: 4096},
	"_id":                         {Kind: NativeS4096, Disposition: NativeConserved, MaxBytes: 4096},
	"repoTag":                     {Kind: NativeObject, Disposition: NativeConserved},
	"tags":                        {Kind: NativeArray, Disposition: NativeConserved},
	"tags[]":                      {Kind: NativeObject, Disposition: NativeConserved},
	"repoDigests":                 {Kind: NativeArray, Disposition: NativeConserved},
	"repoDigests[]":               {Kind: NativeS4096, Disposition: NativeNonInterpretable, MaxBytes: 4096},
	"instances":                   {Kind: NativeArray, Disposition: NativeConserved},
	"instances[]":                 {Kind: NativeObject, Disposition: NativeConserved},
	"distro":                      {Kind: NativeS1024, Disposition: NativeConserved, MaxBytes: 1024},
	"osDistro":                    {Kind: NativeS1024, Disposition: NativeConserved, MaxBytes: 1024},
	"osDistroVersion":             {Kind: NativeS1024, Disposition: NativeConserved, MaxBytes: 1024},
	"osDistroRelease":             {Kind: NativeS1024, Disposition: NativeConserved, MaxBytes: 1024},
	"additionalDistroReleaseData": {Kind: NativeS1024, Disposition: NativeConserved, MaxBytes: 1024},
	"underlyingDistro":            {Kind: NativeS1024, Disposition: NativeConserved, MaxBytes: 1024},
	"underlyingDistroRelease":     {Kind: NativeS1024, Disposition: NativeConserved, MaxBytes: 1024},
	"clusters":                    {Kind: NativeArray, Disposition: NativeConserved},
	"clusters[]":                  {Kind: NativeS1024, Disposition: NativeConserved, MaxBytes: 1024},
	"namespaces":                  {Kind: NativeArray, Disposition: NativeConserved},
	"namespaces[]":                {Kind: NativeS1024, Disposition: NativeConserved, MaxBytes: 1024},
	"isARM64":                     {Kind: NativeBOOL, Disposition: NativeNonInterpretable},
	"scanTime":                    {Kind: NativeTIME128, Disposition: NativeConserved, MaxBytes: 128},
	"firstScanTime":               {Kind: NativeTIME128, Disposition: NativeConserved, MaxBytes: 128},
	"scanID":                      {Kind: NativeINT20, Disposition: NativeNonInterpretable, MaxBytes: 20},
	"scanVersion":                 {Kind: NativeS128, Disposition: NativeNonInterpretable, MaxBytes: 128},
	"type":                        {Kind: NativeS128, Disposition: NativeTransformed, MaxBytes: 128},
	"vulnerabilities":             {Kind: NativeArray, Disposition: NativeConserved},
	"packages":                    {Kind: NativeArray, Disposition: NativeConserved},
	"vulnerabilitiesCount":        {Kind: NativeINT20, Disposition: NativeTransformed, MaxBytes: 20},
	"err":                         {Kind: NativeS4096, Disposition: NativeTransformed, MaxBytes: 4096},
	"errCode":                     {Kind: NativeINT20, Disposition: NativeNonInterpretable, MaxBytes: 20},
	"missingDistroVulnCoverage":   {Kind: NativeBOOL, Disposition: NativeTransformed},

	// §7.3 vulnerability object.
	"vulnerabilities[]":                            {Kind: NativeObject, Disposition: NativeConserved},
	"vulnerabilities[].cve":                        {Kind: NativeS256, Disposition: NativeTransformed, MaxBytes: 256},
	"vulnerabilities[].id":                         {Kind: NativeINT20, Disposition: NativeNonInterpretable, MaxBytes: 20},
	"vulnerabilities[].packageName":                {Kind: NativeS1024, Disposition: NativeConserved, MaxBytes: 1024},
	"vulnerabilities[].packageVersion":             {Kind: NativeS1024, Disposition: NativeConserved, MaxBytes: 1024},
	"vulnerabilities[].packageType":                {Kind: NativeS128, Disposition: NativeNonInterpretable, MaxBytes: 128},
	"vulnerabilities[].rpmModule":                  {Kind: NativeS1024, Disposition: NativeConserved, MaxBytes: 1024},
	"vulnerabilities[].severity":                   {Kind: NativeS128, Disposition: NativeNonInterpretable, MaxBytes: 128},
	"vulnerabilities[].cvss":                       {Kind: NativeNUM32, Disposition: NativeTransformed, MaxBytes: 32},
	"vulnerabilities[].vecStr":                     {Kind: NativeS4096, Disposition: NativeTransformed, MaxBytes: 4096},
	"vulnerabilities[].vulnerabilityDataSources":   {Kind: NativeArray, Disposition: NativeConserved},
	"vulnerabilities[].vulnerabilityDataSources[]": {Kind: NativeObject, Disposition: NativeConserved},
	"vulnerabilities[].status":                     {Kind: NativeT4096, Disposition: NativeNonInterpretable, MaxBytes: 4096},
	"vulnerabilities[].published":                  {Kind: NativeINT20, Disposition: NativeTransformed, MaxBytes: 20},
	"vulnerabilities[].fixDate":                    {Kind: NativeINT20, Disposition: NativeTransformed, MaxBytes: 20},
	"vulnerabilities[].discovered":                 {Kind: NativeTIME128, Disposition: NativeTransformed, MaxBytes: 128},
	"vulnerabilities[].layerTime":                  {Kind: NativeINT20, Disposition: NativeNonInterpretable, MaxBytes: 20},
	"vulnerabilities[].type":                       {Kind: NativeS128, Disposition: NativeNonInterpretable, MaxBytes: 128},
	"vulnerabilities[].custom":                     {Kind: NativeBOOL, Disposition: NativeNonInterpretable},
	"vulnerabilities[].twistlock":                  {Kind: NativeBOOL, Disposition: NativeNonInterpretable},
	"vulnerabilities[].cri":                        {Kind: NativeBOOL, Disposition: NativeNonInterpretable},

	// §7.4 package group and package.
	"packages[]":                          {Kind: NativeObject, Disposition: NativeConserved},
	"packages[].pkgsType":                 {Kind: NativeS128, Disposition: NativeNonInterpretable, MaxBytes: 128},
	"packages[].pkgs":                     {Kind: NativeArray, Disposition: NativeConserved},
	"packages[].pkgs[]":                   {Kind: NativeObject, Disposition: NativeConserved},
	"packages[].pkgs[].name":              {Kind: NativeS1024, Disposition: NativeConserved, MaxBytes: 1024},
	"packages[].pkgs[].version":           {Kind: NativeS1024, Disposition: NativeConserved, MaxBytes: 1024},
	"packages[].pkgs[].originPackageName": {Kind: NativeS1024, Disposition: NativeConserved, MaxBytes: 1024},
	"packages[].pkgs[].rpmModule":         {Kind: NativeS1024, Disposition: NativeConserved, MaxBytes: 1024},
	"packages[].pkgs[].path":              {Kind: NativeS4096, Disposition: NativeNonInterpretable, MaxBytes: 4096},
	"packages[].pkgs[].purl":              {Kind: NativeS4096, Disposition: NativeNonInterpretable, MaxBytes: 4096},
	"packages[].pkgs[].osPackage":         {Kind: NativeBOOL, Disposition: NativeNonInterpretable},
	"packages[].pkgs[].layerTime":         {Kind: NativeINT20, Disposition: NativeNonInterpretable, MaxBytes: 20},

	// §7.5 auxiliary objects.
	"repoTag.registry": {Kind: NativeS4096, Disposition: NativeNonInterpretable, MaxBytes: 4096},
	"repoTag.repo":     {Kind: NativeS4096, Disposition: NativeNonInterpretable, MaxBytes: 4096},
	"repoTag.tag":      {Kind: NativeS4096, Disposition: NativeNonInterpretable, MaxBytes: 4096},
	"repoTag.id":       {Kind: NativeS4096, Disposition: NativeNonInterpretable, MaxBytes: 4096},
	"repoTag.digest":   {Kind: NativeS4096, Disposition: NativeNonInterpretable, MaxBytes: 4096},

	"tags[].registry": {Kind: NativeS4096, Disposition: NativeNonInterpretable, MaxBytes: 4096},
	"tags[].repo":     {Kind: NativeS4096, Disposition: NativeNonInterpretable, MaxBytes: 4096},
	"tags[].tag":      {Kind: NativeS4096, Disposition: NativeNonInterpretable, MaxBytes: 4096},
	"tags[].id":       {Kind: NativeS4096, Disposition: NativeNonInterpretable, MaxBytes: 4096},
	"tags[].digest":   {Kind: NativeS4096, Disposition: NativeNonInterpretable, MaxBytes: 4096},

	"instances[].registry": {Kind: NativeS4096, Disposition: NativeNonInterpretable, MaxBytes: 4096},
	"instances[].repo":     {Kind: NativeS4096, Disposition: NativeNonInterpretable, MaxBytes: 4096},
	"instances[].tag":      {Kind: NativeS4096, Disposition: NativeNonInterpretable, MaxBytes: 4096},
	"instances[].image":    {Kind: NativeS4096, Disposition: NativeNonInterpretable, MaxBytes: 4096},
	"instances[].modified": {Kind: NativeTIME128, Disposition: NativeTransformed, MaxBytes: 128},
	"instances[].host":     {Kind: NativeExcluded, Disposition: NativeExcludedValue},

	"vulnerabilities[].vulnerabilityDataSources[].attribute": {Kind: NativeINT20, Disposition: NativeNonInterpretable, MaxBytes: 20},
	"vulnerabilities[].vulnerabilityDataSources[].source":    {Kind: NativeINT20, Disposition: NativeNonInterpretable, MaxBytes: 20},
}

// nativeImageExcluded is the closed set of image-object members of ADR-0027
// §7.2 excluded as X(*): every descendant of the branch is excluded too.
var nativeImageExcluded = []string{
	"agentless", "aisUUID", "allCompliance", "appEmbedded", "applications",
	"baseImage", "binaries", "caasSpecReferencesLaunchTypes",
	"caasSpecReferencesServiceTypes", "caasSpecReferencesTotal", "cloudMetadata",
	"clusterType", "collections", "complianceDistribution", "complianceIssues",
	"complianceIssuesCount", "complianceRiskScore", "compressed",
	"compressedLayerTimes", "creationTime", "csa", "csaDisplayHostname",
	"csaWindows", "ecsClusterName", "externalLabels", "files",
	"firewallProtection", "foundSecrets", "history", "hostDevices", "hostname",
	"hostRuntimeEnabled", "hosts", "image", "installedProducts", "k8sClusterAddr",
	"labels", "layers", "malwareAnalyzedTime", "packageManager", "pullDuration",
	"pushTime", "redHatNonRPMImage", "registryNamespace", "registryTags",
	"registryType", "rhelRepos", "rhelReposRelativeURLs", "riskFactors",
	"scanBuildDate", "scanDuration", "Secrets", "secretScanMetrics",
	"startupBinaries", "stopped", "topLayer", "trustResult", "trustStatus",
	"twistlockImage", "vulnerabilityDistribution", "vulnerabilityRiskScore",
	"wildFireUsage",
}

// nativeVulnerabilityExcluded is the closed set of vulnerability members of
// ADR-0027 §7.3 excluded as X(*).
var nativeVulnerabilityExcluded = []string{
	"applicableRules", "binaryPkgs", "block", "cause", "description", "exploit",
	"exploits", "fixLink", "functionLayer", "gracePeriodDays", "link",
	"riskFactors", "secret", "templates", "text", "title", "vulnTagInfos",
	"wildfireMalware",
}

// nativePackageExcluded is the closed set of package members of ADR-0027 §7.4
// excluded as X(*).
var nativePackageExcluded = []string{
	"author", "binaryIdx", "binaryPkgs", "cveCount", "defaultGem", "files",
	"functionLayer", "goPkg", "jarIdentifier", "license", "md5",
	"securityRepoPkg", "symbols",
}

// init registers every excluded member of ADR-0027 §7.2–§7.4 in the closed
// disposition table so the reader admits it as an X node (structural discard
// with a witness) instead of rejecting it as an unknown key.
func init() {
	for _, name := range nativeImageExcluded {
		nativeRecordNodes[name] = NativeNode{Kind: NativeExcluded, Disposition: NativeExcludedValue}
	}
	for _, name := range nativeVulnerabilityExcluded {
		nativeRecordNodes["vulnerabilities[]."+name] = NativeNode{Kind: NativeExcluded, Disposition: NativeExcludedValue}
	}
	for _, name := range nativePackageExcluded {
		nativeRecordNodes["packages[].pkgs[]."+name] = NativeNode{Kind: NativeExcluded, Disposition: NativeExcludedValue}
	}
}

// NativeRecordNode returns the closed-table node for a path relative to the
// record data root and whether it is admitted (conserved or excluded).
func NativeRecordNode(path string) (NativeNode, bool) {
	node, ok := nativeRecordNodes[path]
	return node, ok
}

// NativeKMembers returns the sorted names of the directly conserved members of
// one interpreted object path (ADR-0027 §12.5.1 family K), excluding element
// paths and the special `err` member. `parent` is a path relative to the record
// data root; "" is the image object.
func NativeKMembers(parent string) []string { return directMembers(parent, false) }

// NativeExcludedMembers returns the sorted names of the directly excluded
// members of one interpreted object path (family X).
func NativeExcludedMembers(parent string) []string { return directMembers(parent, true) }

func directMembers(parent string, excluded bool) []string {
	prefix := parent
	if prefix != "" {
		prefix += "."
	}
	var out []string
	for key, node := range nativeRecordNodes {
		var rest string
		if prefix == "" {
			rest = key
		} else if strings.HasPrefix(key, prefix) {
			rest = key[len(prefix):]
		} else {
			continue
		}
		if rest == "" || strings.ContainsAny(rest, ".[") {
			continue
		}
		isExcluded := node.Disposition == NativeExcludedValue
		if excluded && isExcluded {
			out = append(out, rest)
		}
		if !excluded && !isExcluded && rest != "err" {
			out = append(out, rest)
		}
	}
	sort.Strings(out)
	return out
}

// NativeExcludedCSVColumns returns the names of the X columns of H39, in order.
func NativeExcludedCSVColumns() []string {
	var out []string
	for _, col := range NativeCSVColumns() {
		if col.Disposition == NativeExcludedValue {
			out = append(out, col.Name)
		}
	}
	return out
}

// NativeValidateSelection reports whether a declared selection belongs to the
// profile of the given selector (ADR-0027 §5, §11.2): an H39 column name for the
// CSV profile, or a known §7 path for the JSON profile.
func NativeValidateSelection(selector, field string) bool {
	if selector == NativeCSVSelector {
		for _, name := range NativeCSVHeader() {
			if name == field {
				return true
			}
		}
		return false
	}
	if (selector != NativeJSONSelector && selector != NativeRegistryJSONSelector) || len(field) < 2 || field[0] != '/' {
		return false
	}
	current := ""
	for _, segment := range strings.Split(field[1:], "/") {
		if segment == "[]" {
			node, ok := nativeRecordNodes[current]
			if !ok || node.Kind != NativeArray {
				return false
			}
			current += "[]"
			continue
		}
		if segment == "" || strings.ContainsAny(segment, ".[") {
			return false
		}
		child := segment
		if current != "" {
			child = current + "." + segment
		}
		if _, ok := nativeRecordNodes[child]; !ok {
			return false
		}
		current = child
	}
	return true
}

// NativeImageExcludedFields returns a copy of the excluded image members.
func NativeImageExcludedFields() []string { return append([]string{}, nativeImageExcluded...) }

// NativeVulnerabilityExcludedFields returns a copy of the excluded vulnerability members.
func NativeVulnerabilityExcludedFields() []string {
	return append([]string{}, nativeVulnerabilityExcluded...)
}

// NativePackageExcludedFields returns a copy of the excluded package members.
func NativePackageExcludedFields() []string { return append([]string{}, nativePackageExcluded...) }

// NativeCSVHeader is the exact H39 header of ADR-0027 §4.4, in order.
func NativeCSVHeader() []string {
	return []string{
		"Registry", "Repository", "Tag", "Id", "Distro", "Hosts", "Layer",
		"CVE ID", "Compliance", "Result", "Type", "Severity", "Packages",
		"Source Package", "Package Version", "Package License", "CVSS",
		"Fix Status", "Fix Date", "Grace Days", "Risk Factors",
		"Vulnerability Tags", "Description", "Cause", "Containers",
		"Custom Labels", "Published", "Discovered", "Binaries", "Clusters",
		"Namespaces", "Collections", "Digest", "Vulnerability Link", "Apps",
		"Package Path", "Start Time", "PURL", "Defender Hosts",
	}
}

// CSVColumn is the disposition of one H39 column of ADR-0027 §7.6.
type CSVColumn struct {
	Name        string
	Disposition NativeDisposition
	MaxBytes    int // decoded limit when conserved; 0 when excluded (raw limits still apply)
}

// NativeCSVColumns is the closed disposition matrix of the 39 H39 columns, in
// order. A column not in this list, a reordered list or an alias is a failure.
func NativeCSVColumns() []CSVColumn {
	return []CSVColumn{
		{"Registry", NativeNonInterpretable, 4096},
		{"Repository", NativeNonInterpretable, 4096},
		{"Tag", NativeNonInterpretable, 4096},
		{"Id", NativeNonInterpretable, 4096},
		{"Distro", NativeNonInterpretable, 1024},
		{"Hosts", NativeExcludedValue, 0},
		{"Layer", NativeNonInterpretable, 4096},
		{"CVE ID", NativeTransformed, 256},
		{"Compliance", NativeNonInterpretable, 256},
		{"Result", NativeNonInterpretable, 1024},
		{"Type", NativeNonInterpretable, 128},
		{"Severity", NativeNonInterpretable, 128},
		{"Packages", NativeNonInterpretable, 4096},
		{"Source Package", NativeNonInterpretable, 4096},
		{"Package Version", NativeNonInterpretable, 1024},
		{"Package License", NativeExcludedValue, 0},
		{"CVSS", NativeTransformed, 32},
		{"Fix Status", NativeNonInterpretable, 4096},
		{"Fix Date", NativeNonInterpretable, 128},
		{"Grace Days", NativeExcludedValue, 0},
		{"Risk Factors", NativeExcludedValue, 0},
		{"Vulnerability Tags", NativeExcludedValue, 0},
		{"Description", NativeExcludedValue, 0},
		{"Cause", NativeExcludedValue, 0},
		{"Containers", NativeExcludedValue, 0},
		{"Custom Labels", NativeExcludedValue, 0},
		{"Published", NativeNonInterpretable, 128},
		{"Discovered", NativeNonInterpretable, 128},
		{"Binaries", NativeExcludedValue, 0},
		{"Clusters", NativeNonInterpretable, 4096},
		{"Namespaces", NativeNonInterpretable, 4096},
		{"Collections", NativeExcludedValue, 0},
		{"Digest", NativeNonInterpretable, 4096},
		{"Vulnerability Link", NativeExcludedValue, 0},
		{"Apps", NativeExcludedValue, 0},
		{"Package Path", NativeNonInterpretable, 4096},
		{"Start Time", NativeNonInterpretable, 128},
		{"PURL", NativeNonInterpretable, 4096},
		{"Defender Hosts", NativeExcludedValue, 0},
	}
}

// NativeFatalCodes is the closed set of fatal diagnostic codes (§12.3).
func NativeFatalCodes() []string {
	return []string{
		"invalid_context", "unsupported_selector", "unsupported_version",
		"unsupported_profile", "redaction_policy_required", "nil_reader",
		"read_failed", "source_limit", "depth_limit", "token_limit",
		"member_limit", "key_limit", "string_limit", "number_limit",
		"collection_limit", "record_limit", "field_limit", "invalid_utf8",
		"invalid_unicode", "forbidden_text", "invalid_json", "duplicate_key",
		"field_not_allowed", "invalid_field_type", "invalid_csv",
		"invalid_header", "field_count", "unsupported_report_scope",
		"output_limit", "invalid_artifact", "hash_mismatch", "manifest_mismatch",
	}
}

// NativeInterpretationCodes is the closed set of interpretation and coverage
// diagnostic codes (§12.3).
func NativeInterpretationCodes() []string {
	return []string{
		"field_absent", "field_null", "field_empty", "identifier_uninterpreted",
		"identifier_unavailable", "row_semantics_unverified", "scalar_invalid",
		"scalar_uninterpretable", "vector_syntax_invalid",
		"vector_semantics_unverified", "cvss_consistency_not_verified",
		"attribute_source_conflict", "time_uninterpretable",
		"time_zero_unspecified", "scan_after_acquisition",
		"temporal_order_conflict", "capture_aborted", "capture_unknown",
		"origin_version_unknown", "scope_unknown", "selection_restricted",
		"page_scope_unverified", "scan_error_reported", "distro_coverage_missing",
		"declared_count_difference", "no_runtime_binding", "excluded_by_policy",
	}
}

// NativePhases is the closed set of diagnostic phases (§12.3).
func NativePhases() []string {
	return []string{
		"context", "acquisition", "admission", "projection", "interpretation",
		"replay_admission", "replay_verification",
	}
}

// NativeOffsetSpaces is the closed set of diagnostic offset spaces (§12.3).
func NativeOffsetSpaces() []string {
	return []string{"none", "native", "source", "manifest", "digest"}
}

// NativeLossReasons is the closed set of loss reasons (§11.7).
func NativeLossReasons() []string {
	return []string{
		"excluded_by_policy", "redacted_error", "semantics_unverified",
		"invalid_value", "coverage_unavailable",
	}
}

// NativeLimitations is the exhaustive, ordered limitation vocabulary of
// ADR-0027 §12.5.6. The manifest contains exactly the activated subset in this
// order; extra, missing, duplicated or reordered codes are rejected.
func NativeLimitations() []string {
	return []string{
		"documentary_profile", "csv_header_unverified", "origin_version_unknown",
		"origin_not_authenticated", "inventory_not_verified", "no_runtime_binding",
		"cvss_consistency_not_verified", "original_content_not_retained",
		"data_excluded", "fields_incomplete", "values_invalid",
		"values_uninterpretable", "capture_aborted", "capture_unknown",
		"scope_unknown", "selection_restricted", "page_scope_unverified",
		"scan_error_reported", "distro_coverage_missing", "temporal_conflict",
		"attribute_source_conflict", "declared_count_difference",
	}
}

// NativeRegistryLimitations is the ordered limitation catalogue of the
// registry-image family (ADR-0029 §11.6): the deployed-image catalogue with
// registry_profile inserted at position 2 and registry_not_deployment at
// position 4, for 24 codes. A registry manifest emits only the activated
// subset, in this order; for a JSON source csv_header_unverified is inactive, so
// registry_not_deployment appears at position 3 of the emitted array.
func NativeRegistryLimitations() []string {
	return []string{
		"documentary_profile", "registry_profile", "csv_header_unverified",
		"registry_not_deployment", "origin_version_unknown",
		"origin_not_authenticated", "inventory_not_verified", "no_runtime_binding",
		"cvss_consistency_not_verified", "original_content_not_retained",
		"data_excluded", "fields_incomplete", "values_invalid",
		"values_uninterpretable", "capture_aborted", "capture_unknown",
		"scope_unknown", "selection_restricted", "page_scope_unverified",
		"scan_error_reported", "distro_coverage_missing", "temporal_conflict",
		"attribute_source_conflict", "declared_count_difference",
	}
}
