package evidence

import (
	"testing"
	"time"
)

func testTimestamp(t *testing.T) Timestamp {
	t.Helper()
	timestamp, err := NewTimestamp(time.Date(2026, 9, 23, 12, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatalf("NewTimestamp: %v", err)
	}
	return timestamp
}

func testSubject() Subject {
	return Subject{
		ClusterAlias: ClusterAlias("cluster-a"),
		Namespace:    Namespace("payments"),
		Kind:         "Pod",
		Name:         "payments-api-7f4d",
		UID:          UID("pod-uid-1"),
		OwnerChain:   OwnerChain("deployments/payments-api"),
	}
}

func testImage(t *testing.T) ImageIdentity {
	t.Helper()
	requested := RequestedImage("registry.example/app:release")
	raw := RawImageID("registry.example/app@sha256:aaa")
	normalized := NormalizedDigest("sha256:aaa")
	observedAt := testTimestamp(t)
	return ImageIdentity{
		ContainerClass:   ContainerRegular,
		ContainerName:    ContainerName("api"),
		RequestedImage:   &requested,
		RawImageID:       &raw,
		NormalizedDigest: &normalized,
		Platform:         Platform{OS: "linux", Architecture: "amd64", Status: PlatformKnown},
		ObservedAt:       &observedAt,
	}
}

func testItem(t *testing.T) EvidenceItem {
	t.Helper()
	value := "sha256:aaa"
	valueHash := ValueHash("sha256:bbb")
	observedAt := testTimestamp(t)
	return EvidenceItem{
		Type:       "container_status.image_id",
		Source:     "sanitized-pods.json",
		SourceHash: SourceHash("sha256:ccc"),
		Locator:    SourceLocator("items[3].status.containerStatuses[0].imageID"),
		Value:      &value,
		ValueHash:  &valueHash,
		ObservedAt: &observedAt,
		Confidence: ProvenanceObserved,
		Scope:      Scope{SubjectUID: UID("pod-uid-1"), ContainerName: ContainerName("api")},
		Warnings:   []Warning{},
	}
}

// testProvenance is the container observation path of ADR-0006 §7(a): rows are
// null, the three container classes are required for complete and the API scope
// is declared.
func testProvenance(t *testing.T) RunProvenance {
	t.Helper()
	startedAt := testTimestamp(t)
	endedAt := testTimestamp(t)
	return RunProvenance{
		CollectorVersion: "0.1",
		ParserVersion:    "kubectl-v1.2",
		Ruleset:          RulesetRef{Path: "rules/", Hash: SourceHash("sha256:ddd"), Version: "2026-09"},
		ArgvSanitized:    []string{"get", "pods", "-o", "json"},
		Inputs:           []InputRef{{Path: "sanitized-pods.json", Hash: SourceHash("sha256:eee")}},
		APIScope:         APIScope{Namespaces: []Namespace{"payments"}, Verbs: []string{"get", "list"}, Resources: []string{"pods"}},
		StartedAt:        &startedAt,
		EndedAt:          &endedAt,
		Budget:           Budget{WallClock: "5m", Requests: 1000, Objects: 5000, Bytes: 52428800},
		Coverage:         Coverage{Method: CoverageContainerObservation, Termination: TerminationFinished},
		Completeness:     CompletenessComplete,
		Consistency:      ConsistencyPointObservation,
		RedactionPolicy:  "default-v1",
		Warnings:         []Warning{},
		Errors:           []string{},
	}
}

// testBundle is the legacy fixture of schema version 0.1. The version stays
// literal on purpose: binding it to SchemaVersionSupported would move every
// existing regression to the new version the day the ceiling changes.
func testBundle(t *testing.T) Bundle {
	t.Helper()
	return Bundle{
		SchemaVersion:            "0.1",
		Subject:                  testSubject(),
		Images:                   []ImageIdentity{testImage(t)},
		Evidence:                 []EvidenceItem{testItem(t)},
		ObservedContainerClasses: []ContainerClass{ContainerEphemeral, ContainerInit, ContainerRegular},
		Provenance:               testProvenance(t),
	}
}

// testImportBundle is the findings import path: one hash-identified input, no
// container inventory and no container API scope.
func testImportBundle(t *testing.T) Bundle {
	t.Helper()
	total := uint64(3)
	bundle := testBundle(t)
	bundle.ObservedContainerClasses = []ContainerClass{}
	bundle.Provenance.ArgvSanitized = []string{"import", "findings.csv", "--schema", "prisma-v1"}
	bundle.Provenance.APIScope = APIScope{Namespaces: []Namespace{}, Verbs: []string{}, Resources: []string{}}
	bundle.Provenance.Coverage = Coverage{
		Method:      CoverageFindingsImport,
		Termination: TerminationFinished,
		Rows:        &CoverageRows{Total: &total, Accepted: 3, Rejected: 0},
	}
	return bundle
}

func TestValidateBundleAcceptsContractShapedBundle(t *testing.T) {
	if err := ValidateBundle(testBundle(t)); err != nil {
		t.Fatalf("ValidateBundle rejected a bundle that follows the contract: %v", err)
	}
	if err := ValidateBundle(testImportBundle(t)); err != nil {
		t.Fatalf("ValidateBundle rejected a findings import that follows the contract: %v", err)
	}
}

func TestValidateSchemaVersion(t *testing.T) {
	for _, version := range []string{"0.2", "0.1", "0.0"} {
		if err := ValidateSchemaVersion(version); err != nil {
			t.Errorf("ValidateSchemaVersion rejected %q: %v", version, err)
		}
	}
	rejected := map[string]string{
		"empty":              "",
		"padded":             " 0.1",
		"three parts":        "0.1.0",
		"single number":      "0",
		"other major":        "1.0",
		"newer minor":        "0.3",
		"leading zero major": "01.1",
		"leading zero minor": "0.01",
		"missing minor":      "0.",
		"missing major":      ".1",
		"not a number":       "zero.one",
		"negative":           "-1.0",
		"overflow":           "0.99999999999999999999999",
	}
	for name, version := range rejected {
		t.Run(name, func(t *testing.T) {
			if err := ValidateSchemaVersion(version); err == nil {
				t.Fatalf("ValidateSchemaVersion accepted %q", version)
			}
		})
	}
}

// TestValidateBundleVersionMatrix walks the version matrix of ADR-0016 §6.1: the
// updated reader accepts every known version it used to accept plus 0.2, and the
// first unsupported minor is 0.3.
func TestValidateBundleVersionMatrix(t *testing.T) {
	for _, version := range []string{"0.0", "0.1", "0.2"} {
		t.Run("accepts/"+version, func(t *testing.T) {
			bundle := testBundle(t)
			bundle.SchemaVersion = version
			if err := ValidateBundle(bundle); err != nil {
				t.Fatalf("ValidateBundle rejected schema_version %q: %v", version, err)
			}
		})
	}
	for name, version := range map[string]string{
		"future minor": "0.3",
		"other major":  "1.0",
		"malformed":    "0.1.0",
	} {
		t.Run("rejects/"+name, func(t *testing.T) {
			bundle := testBundle(t)
			bundle.SchemaVersion = version
			if err := ValidateBundle(bundle); err == nil {
				t.Fatalf("ValidateBundle accepted schema_version %q", version)
			}
		})
	}
}

// TestWireCarrierRemainsOpen fixes ADR-0016 §6.2: the evidence type stays a
// carrier without a universal allowlist, so a bundle 0.2 with a type outside the
// product catalog is still transportable, and the closed enums keep rejecting
// values outside their vocabulary.
func TestWireCarrierRemainsOpen(t *testing.T) {
	foreign := testBundle(t)
	foreign.SchemaVersion = "0.2"
	foreign.Evidence[0].Type = "product_v1.vendor.vulnerable_code_id"
	if err := ValidateBundle(foreign); err != nil {
		t.Fatalf("a product_v1 type must be transportable in 0.2: %v", err)
	}
	unknown := testBundle(t)
	unknown.Evidence[0].Type = "third_party.carrier.field"
	if err := ValidateBundle(unknown); err != nil {
		t.Fatalf("an unknown but well formed type must stay transportable: %v", err)
	}
	enums := testBundle(t)
	enums.Provenance.Consistency = Consistency("eventual")
	if err := ValidateBundle(enums); err == nil {
		t.Fatal("a value outside the closed Consistency enum was accepted")
	}
}

func TestValidateBundleRejectsUnsupportedSchemaVersion(t *testing.T) {
	for name, version := range map[string]string{
		"legacy patch form": "0.1.0",
		"other major":       "1.1",
		"newer minor":       "0.9",
		"empty":             "",
	} {
		t.Run(name, func(t *testing.T) {
			bundle := testBundle(t)
			bundle.SchemaVersion = version
			if err := ValidateBundle(bundle); err == nil {
				t.Fatalf("ValidateBundle accepted schema_version %q", version)
			}
		})
	}
}

func TestValidateBundleRejectsNilContractualCollections(t *testing.T) {
	mutations := map[string]func(*Bundle){
		"images":                     func(b *Bundle) { b.Images = nil },
		"evidence":                   func(b *Bundle) { b.Evidence = nil },
		"observed_container_classes": func(b *Bundle) { b.ObservedContainerClasses = nil },
		"provenance.argv_sanitized":  func(b *Bundle) { b.Provenance.ArgvSanitized = nil },
		"provenance.inputs":          func(b *Bundle) { b.Provenance.Inputs = nil },
		"provenance.warnings":        func(b *Bundle) { b.Provenance.Warnings = nil },
		"provenance.errors":          func(b *Bundle) { b.Provenance.Errors = nil },
		"api_scope.namespaces":       func(b *Bundle) { b.Provenance.APIScope.Namespaces = nil },
		"api_scope.verbs":            func(b *Bundle) { b.Provenance.APIScope.Verbs = nil },
		"api_scope.resources":        func(b *Bundle) { b.Provenance.APIScope.Resources = nil },
		"evidence.warnings":          func(b *Bundle) { b.Evidence[0].Warnings = nil },
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			bundle := testBundle(t)
			mutate(&bundle)
			if err := ValidateBundle(bundle); err == nil {
				t.Fatalf("ValidateBundle accepted nil %s instead of an array", name)
			}
		})
	}
}

func TestValidateBundleAcceptsEmptyContractualArrays(t *testing.T) {
	bundle := testImportBundle(t)
	bundle.Provenance.Errors = []string{}
	bundle.Provenance.Warnings = []Warning{}
	if err := ValidateBundle(bundle); err != nil {
		t.Fatalf("empty arrays must be representable: %v", err)
	}
	observation := testBundle(t)
	observation.Provenance.Warnings = []Warning{}
	if err := ValidateBundle(observation); err != nil {
		t.Fatalf("empty warnings must be representable: %v", err)
	}
}

func TestValidateBundleRejectsSubjectWithoutUID(t *testing.T) {
	bundle := testBundle(t)
	bundle.Subject.UID = ""
	if err := ValidateBundle(bundle); err == nil {
		t.Fatal("ValidateBundle accepted an identity without metadata.uid")
	}
}

func TestValidateBundleRejectsNamespaceNameAsIdentity(t *testing.T) {
	bundle := testBundle(t)
	bundle.Subject.UID = ""
	bundle.Subject.Namespace = Namespace("payments")
	bundle.Subject.Name = "payments-api-7f4d"
	if err := ValidateBundle(bundle); err == nil {
		t.Fatal("namespace/name without a UID must not identify a subject")
	}
}

func TestValidateBundleRejectsEvidenceOfAnotherSubject(t *testing.T) {
	bundle := testBundle(t)
	bundle.Evidence[0].Scope.SubjectUID = UID("pod-uid-2")
	if err := ValidateBundle(bundle); err == nil {
		t.Fatal("evidence scoped to another uid was accepted for this subject")
	}
}

func TestValidateSubjectRejectsEmptyIdentityFields(t *testing.T) {
	fields := map[string]func(*Subject){
		"cluster_alias": func(s *Subject) { s.ClusterAlias = "" },
		"namespace":     func(s *Subject) { s.Namespace = "" },
		"kind":          func(s *Subject) { s.Kind = "" },
		"name":          func(s *Subject) { s.Name = "" },
		"uid":           func(s *Subject) { s.UID = "" },
	}
	for name, mutate := range fields {
		t.Run(name, func(t *testing.T) {
			subject := testSubject()
			mutate(&subject)
			if err := validateSubject(subject); err == nil {
				t.Fatalf("empty %s was accepted", name)
			}
		})
	}
}

func TestValidateRejectsInvalidUTF8(t *testing.T) {
	invalid := "pod-\xff-uid"
	mutations := map[string]func(*Bundle){
		"subject uid":     func(b *Bundle) { b.Subject.UID = UID(invalid) },
		"owner chain":     func(b *Bundle) { b.Subject.OwnerChain = OwnerChain(invalid) },
		"evidence source": func(b *Bundle) { b.Evidence[0].Source = invalid },
		"warning message": func(b *Bundle) {
			b.Evidence[0].Warnings = []Warning{{Code: "tool_failure", Class: WarningInformational, Message: invalid}}
		},
		"provenance error":  func(b *Bundle) { b.Provenance.Errors = []string{invalid} },
		"argv element":      func(b *Bundle) { b.Provenance.ArgvSanitized = []string{invalid} },
		"budget wall clock": func(b *Bundle) { b.Provenance.Budget.WallClock = invalid },
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			bundle := testBundle(t)
			mutate(&bundle)
			if err := ValidateBundle(bundle); err == nil {
				t.Fatalf("invalid UTF-8 in %s was accepted", name)
			}
		})
	}
}

func TestValidateImageIdentityRejectsUnknownContainerClass(t *testing.T) {
	image := testImage(t)
	image.ContainerClass = ContainerClass("sidecar")
	if err := validateImageIdentity(image); err == nil {
		t.Fatal("an unknown container class was accepted")
	}
}

func TestValidateImageIdentityAcceptsTagWithoutProvenDigest(t *testing.T) {
	image := testImage(t)
	image.NormalizedDigest = nil
	image.Platform = Platform{Status: PlatformUnknown}
	if err := validateImageIdentity(image); err != nil {
		t.Fatalf("a tag without a proven digest must be representable: %v", err)
	}
	if image.NormalizedDigest != nil {
		t.Fatal("a missing digest was turned into a normalized digest")
	}
	if image.RawImageID == nil || string(*image.RawImageID) != "registry.example/app@sha256:aaa" {
		t.Fatal("the raw image id was not preserved")
	}
	if image.RequestedImage == nil || string(*image.RequestedImage) != "registry.example/app:release" {
		t.Fatal("the requested image was not preserved")
	}
}

func TestValidateImageIdentityRejectsKnownPlatformWithoutProvenDigest(t *testing.T) {
	image := testImage(t)
	image.NormalizedDigest = nil
	if err := validateImageIdentity(image); err == nil {
		t.Fatal("platform known was accepted without a digest proven by the parser")
	}
}

func TestValidateImageIdentityRejectsKnownPlatformWithoutObservation(t *testing.T) {
	image := testImage(t)
	image.Platform.OS = ""
	if err := validateImageIdentity(image); err == nil {
		t.Fatal("platform known was accepted without an observed os")
	}
}

func TestValidateImageIdentityRejectsUnknownPlatformWithObservation(t *testing.T) {
	image := testImage(t)
	image.Platform.Status = PlatformUnknown
	if err := validateImageIdentity(image); err == nil {
		t.Fatal("platform unknown was accepted while carrying an observed os and architecture")
	}
}

func TestValidateImageIdentityRejectsZeroObservedAt(t *testing.T) {
	image := testImage(t)
	zero := Timestamp{}
	image.ObservedAt = &zero
	if err := validateImageIdentity(image); err == nil {
		t.Fatal("a zero observed_at was accepted")
	}
}

func TestValidateRejectsTimestampsOutsideCanonicalUTC(t *testing.T) {
	madrid := time.FixedZone("CEST", 2*60*60)
	offset := Timestamp{Time: time.Date(2026, 9, 23, 14, 0, 0, 0, madrid)}
	zeroOffset := Timestamp{Time: time.Date(2026, 9, 23, 12, 0, 0, 0, time.FixedZone("UTC", 0))}
	image := testImage(t)
	image.ObservedAt = &offset
	if err := validateImageIdentity(image); err == nil {
		t.Fatal("an image identity accepted a timestamp outside canonical UTC")
	}
	item := testItem(t)
	item.ObservedAt = &offset
	if err := ValidateEvidenceItem(item, testSubject()); err == nil {
		t.Fatal("an evidence item accepted a timestamp outside canonical UTC")
	}
	provenance := testProvenance(t)
	provenance.StartedAt = &offset
	if err := validateRunProvenance(provenance); err == nil {
		t.Fatal("a provenance accepted a timestamp outside canonical UTC")
	}
	provenance = testProvenance(t)
	provenance.EndedAt = &zeroOffset
	if err := validateRunProvenance(provenance); err == nil {
		t.Fatal("a provenance accepted a non canonical location with a zero offset")
	}
}

func TestValidateRunProvenanceRejectsInvertedRunTimes(t *testing.T) {
	provenance := testProvenance(t)
	earlier, err := NewTimestamp(time.Date(2026, 9, 23, 11, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatalf("NewTimestamp: %v", err)
	}
	provenance.EndedAt = &earlier
	if err := validateRunProvenance(provenance); err == nil {
		t.Fatal("a run was accepted with started_at after ended_at")
	}
}

// TestValidateRunProvenanceAcceptsAbsentRunTimestamps fixes the optionality of
// ADR-0006 §2: started_at and ended_at are optional, so a run that recorded no
// times, or only one of them, is representable.
func TestValidateRunProvenanceAcceptsAbsentRunTimestamps(t *testing.T) {
	withoutTimes := testProvenance(t)
	withoutTimes.StartedAt = nil
	withoutTimes.EndedAt = nil
	if err := validateRunProvenance(withoutTimes); err != nil {
		t.Fatalf("a run without started_at and ended_at must be representable: %v", err)
	}

	onlyStarted := testProvenance(t)
	onlyStarted.EndedAt = nil
	if err := validateRunProvenance(onlyStarted); err != nil {
		t.Fatalf("a run with only started_at must be representable: %v", err)
	}

	onlyEnded := testProvenance(t)
	onlyEnded.StartedAt = nil
	if err := validateRunProvenance(onlyEnded); err != nil {
		t.Fatalf("a run with only ended_at must be representable: %v", err)
	}
}

func TestValidateEvidenceItemRejectsIncompleteItems(t *testing.T) {
	empty := ""
	mutations := map[string]func(*EvidenceItem){
		"empty type":          func(i *EvidenceItem) { i.Type = "" },
		"empty source":        func(i *EvidenceItem) { i.Source = "" },
		"empty source_hash":   func(i *EvidenceItem) { i.SourceHash = "" },
		"empty locator":       func(i *EvidenceItem) { i.Locator = "" },
		"missing observed_at": func(i *EvidenceItem) { i.ObservedAt = nil },
		"zero observed_at":    func(i *EvidenceItem) { i.ObservedAt = &Timestamp{} },
		"unknown provenance":  func(i *EvidenceItem) { i.Confidence = ProvenanceKind("") },
		"empty value":         func(i *EvidenceItem) { i.Value = &empty },
		"value without hash":  func(i *EvidenceItem) { i.ValueHash = nil },
		"empty value_hash":    func(i *EvidenceItem) { hash := ValueHash(""); i.ValueHash = &hash },
		"empty scope uid":     func(i *EvidenceItem) { i.Scope.SubjectUID = "" },
		"empty container":     func(i *EvidenceItem) { i.Scope.ContainerName = "" },
		"another uid":         func(i *EvidenceItem) { i.Scope.SubjectUID = UID("pod-uid-2") },
		"empty warning code": func(i *EvidenceItem) {
			i.Warnings = []Warning{{Code: "", Class: WarningInformational, Message: "message"}}
		},
		"unknown warning class": func(i *EvidenceItem) {
			i.Warnings = []Warning{{Code: "tool_failure", Class: WarningClass("critical"), Message: "message"}}
		},
		"empty warning message": func(i *EvidenceItem) {
			i.Warnings = []Warning{{Code: "tool_failure", Class: WarningInformational, Message: ""}}
		},
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			item := testItem(t)
			mutate(&item)
			if err := ValidateEvidenceItem(item, testSubject()); err == nil {
				t.Fatalf("an evidence item with %s was accepted", name)
			}
		})
	}
}

func TestValidateEvidenceItemAcceptsUnavailableWithoutValue(t *testing.T) {
	item := testItem(t)
	item.Confidence = ProvenanceUnavailable
	item.Value = nil
	if err := ValidateEvidenceItem(item, testSubject()); err != nil {
		t.Fatalf("unavailable evidence must be representable: %v", err)
	}
}

// TestValidateEvidenceItemRequiresObservedAtForUnavailable fixes ADR-0006 §2:
// the optional timestamps are only those of the image and the run, never the one
// of an evidence item.
func TestValidateEvidenceItemRequiresObservedAtForUnavailable(t *testing.T) {
	item := testItem(t)
	item.Confidence = ProvenanceUnavailable
	item.Value = nil
	item.ValueHash = nil
	item.ObservedAt = nil
	if err := ValidateEvidenceItem(item, testSubject()); err == nil {
		t.Fatal("unavailable evidence was accepted without observed_at")
	}
}

func TestValidateEvidenceItemKeepsUnknownWarningCodes(t *testing.T) {
	item := testItem(t)
	item.Warnings = []Warning{{Code: "future_code", Class: WarningInformational, Message: "uninterpretable by this version"}}
	if err := ValidateEvidenceItem(item, testSubject()); err != nil {
		t.Fatalf("an unknown warning code must be preserved, not rejected: %v", err)
	}
	if item.Warnings[0].CodeKnown() {
		t.Fatal("schema version 0.1 must not claim to know a future warning code")
	}
	known := Warning{Code: "uid_changed", Class: WarningContradictory, Message: "uid changed"}
	if !known.CodeKnown() {
		t.Fatal("uid_changed is part of the schema version 0.1 code set")
	}
}

func TestValidateScopeRejectsMismatch(t *testing.T) {
	scope := Scope{SubjectUID: UID("pod-uid-1"), ContainerName: ContainerName("api")}
	if err := ValidateScope(scope, UID("pod-uid-1"), ContainerName("api")); err != nil {
		t.Fatalf("ValidateScope rejected a matching scope: %v", err)
	}
	if err := ValidateScope(scope, UID("pod-uid-2"), ContainerName("api")); err == nil {
		t.Fatal("a scope from another uid was accepted")
	}
	if err := ValidateScope(scope, UID("pod-uid-1"), ContainerName("sidecar")); err == nil {
		t.Fatal("a scope from another container was accepted")
	}
	if err := ValidateScope(Scope{}, UID("pod-uid-1"), ContainerName("api")); err == nil {
		t.Fatal("an empty scope was accepted")
	}
}

func TestValidateRunProvenanceRejectsUnknownEnums(t *testing.T) {
	provenance := testProvenance(t)
	provenance.Completeness = Completeness("")
	provenance.Consistency = Consistency("")
	if err := validateRunProvenance(provenance); err == nil {
		t.Fatal("a provenance without known completeness/consistency was accepted")
	}
}

func TestValidateRunProvenanceRequiresVisibleErrorsWhenIncomplete(t *testing.T) {
	provenance := testProvenance(t)
	provenance.Completeness = CompletenessPartial
	if err := validateRunProvenance(provenance); err == nil {
		t.Fatal("a partial run without visible errors was accepted")
	}
	provenance.Errors = []string{"budget aborted the collection"}
	if err := validateRunProvenance(provenance); err != nil {
		t.Fatalf("a partial run with visible errors was rejected: %v", err)
	}
}

func TestValidateRunProvenanceRejectsEmptyRequiredFields(t *testing.T) {
	mutations := map[string]func(*RunProvenance){
		"empty collector_version": func(p *RunProvenance) { p.CollectorVersion = "" },
		"empty parser_version":    func(p *RunProvenance) { p.ParserVersion = "" },
		"empty redaction_policy":  func(p *RunProvenance) { p.RedactionPolicy = "" },
		"empty input path":        func(p *RunProvenance) { p.Inputs[0].Path = "" },
		"empty input hash":        func(p *RunProvenance) { p.Inputs[0].Hash = "" },
		"empty ruleset path":      func(p *RunProvenance) { p.Ruleset.Path = "" },
		"empty ruleset hash":      func(p *RunProvenance) { p.Ruleset.Hash = "" },
		"empty ruleset version":   func(p *RunProvenance) { p.Ruleset.Version = "" },
		"empty namespace":         func(p *RunProvenance) { p.APIScope.Namespaces[0] = "" },
		"empty verb":              func(p *RunProvenance) { p.APIScope.Verbs[0] = "" },
		"empty resource":          func(p *RunProvenance) { p.APIScope.Resources[0] = "" },
		"zero started_at":         func(p *RunProvenance) { zero := Timestamp{}; p.StartedAt = &zero },
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			provenance := testProvenance(t)
			mutate(&provenance)
			if err := validateRunProvenance(provenance); err == nil {
				t.Fatalf("a provenance with %s was accepted", name)
			}
		})
	}
}

// TestValidateFindingsImportMatrix walks the fixtures of ADR-0006 §7(a) for the
// import path: EOF, accounting and errors decide completeness.
func TestValidateFindingsImportMatrix(t *testing.T) {
	rows := func(total *uint64, accepted, rejected uint64) *CoverageRows {
		return &CoverageRows{Total: total, Accepted: accepted, Rejected: rejected}
	}
	known := func(value uint64) *uint64 { return &value }

	accepted := map[string]func(*Bundle){
		"import-complete": func(b *Bundle) {},
		"import-header-only": func(b *Bundle) {
			b.Provenance.Coverage.Rows = rows(known(0), 0, 0)
		},
		"import-duplicates": func(b *Bundle) {
			b.Provenance.Coverage.Rows = rows(known(2), 2, 0)
		},
		"import-rejected-row": func(b *Bundle) {
			b.Provenance.Coverage.Rows = rows(known(3), 2, 1)
			b.Provenance.Completeness = CompletenessPartial
			b.Provenance.Errors = []string{"row 2 rejected: unknown selector"}
		},
		"import-budget-abort": func(b *Bundle) {
			b.Provenance.Coverage.Termination = TerminationAborted
			b.Provenance.Coverage.Rows = rows(nil, 1, 0)
			b.Provenance.Completeness = CompletenessPartial
			b.Provenance.Errors = []string{"budget aborted the import"}
		},
		"import-unreadable": func(b *Bundle) {
			b.Provenance.Coverage.Termination = TerminationUnknown
			b.Provenance.Coverage.Rows = rows(nil, 0, 0)
			b.Provenance.Completeness = CompletenessUnknown
			b.Provenance.Errors = []string{"source identity cannot be established"}
		},
		"import-malformed-record": func(b *Bundle) {
			b.Provenance.Coverage.Termination = TerminationAborted
			b.Provenance.Coverage.Rows = rows(nil, 1, 0)
			b.Provenance.Completeness = CompletenessPartial
			b.Provenance.Errors = []string{"record 2 is not delimited"}
		},
		"import-abort-with-progress": func(b *Bundle) {
			b.Provenance.Coverage.Termination = TerminationAborted
			b.Provenance.Coverage.Rows = rows(known(3), 1, 0)
			b.Provenance.Completeness = CompletenessPartial
			b.Provenance.Errors = []string{"budget aborted the import"}
		},
		"import-abort-without-progress": func(b *Bundle) {
			b.Provenance.Coverage.Termination = TerminationAborted
			b.Provenance.Coverage.Rows = rows(nil, 0, 0)
			b.Provenance.Completeness = CompletenessUnknown
			b.Provenance.Errors = []string{"the source could not be read"}
		},
	}
	for name, mutate := range accepted {
		t.Run(name, func(t *testing.T) {
			bundle := testImportBundle(t)
			mutate(&bundle)
			if err := ValidateBundle(bundle); err != nil {
				t.Fatalf("ValidateBundle rejected the ratified fixture %s: %v", name, err)
			}
		})
	}

	rejected := map[string]func(*Bundle){
		"complete with a rejected row": func(b *Bundle) {
			b.Provenance.Coverage.Rows = rows(known(3), 2, 1)
		},
		"complete with a visible error": func(b *Bundle) {
			b.Provenance.Errors = []string{"unexpected"}
		},
		"complete after an abort": func(b *Bundle) {
			b.Provenance.Coverage.Termination = TerminationAborted
		},
		"unknown termination while complete": func(b *Bundle) {
			b.Provenance.Coverage.Termination = TerminationUnknown
		},
		"aborted with progress declared unknown": func(b *Bundle) {
			b.Provenance.Coverage.Termination = TerminationAborted
			b.Provenance.Coverage.Rows = rows(nil, 1, 0)
			b.Provenance.Completeness = CompletenessUnknown
			b.Provenance.Errors = []string{"budget aborted the import"}
		},
		"aborted without progress declared partial": func(b *Bundle) {
			b.Provenance.Coverage.Termination = TerminationAborted
			b.Provenance.Coverage.Rows = rows(nil, 0, 0)
			b.Provenance.Completeness = CompletenessPartial
			b.Provenance.Errors = []string{"budget aborted the import"}
		},
		"finished without a known total": func(b *Bundle) {
			b.Provenance.Coverage.Rows = rows(nil, 3, 0)
		},
		"finished with a mismatched total": func(b *Bundle) {
			b.Provenance.Coverage.Rows = rows(known(4), 3, 0)
		},
		"counted rows above the total": func(b *Bundle) {
			b.Provenance.Coverage.Rows = rows(known(2), 2, 1)
			b.Provenance.Completeness = CompletenessPartial
			b.Provenance.Errors = []string{"row 3 rejected"}
		},
		"empty rows": func(b *Bundle) {
			b.Provenance.Coverage.Rows = nil
		},
		"unknown method": func(b *Bundle) {
			b.Provenance.Coverage.Method = CoverageMethod("")
		},
		"unknown termination": func(b *Bundle) {
			b.Provenance.Coverage.Termination = CoverageTermination("")
		},
		"two inputs": func(b *Bundle) {
			b.Provenance.Inputs = append(b.Provenance.Inputs, InputRef{Path: "other.csv", Hash: SourceHash("sha256:fff")})
		},
		"declared container classes": func(b *Bundle) {
			b.ObservedContainerClasses = []ContainerClass{ContainerRegular}
		},
		"declared api scope": func(b *Bundle) {
			b.Provenance.APIScope = APIScope{Namespaces: []Namespace{"payments"}, Verbs: []string{}, Resources: []string{}}
		},
	}
	for name, mutate := range rejected {
		t.Run(name, func(t *testing.T) {
			bundle := testImportBundle(t)
			mutate(&bundle)
			if err := ValidateBundle(bundle); err == nil {
				t.Fatalf("ValidateBundle accepted an invalid import: %s", name)
			}
		})
	}
}

// TestValidateContainerObservationMatrix walks the observation path: the three
// container classes are required for complete and an abort can never be complete.
func TestValidateContainerObservationMatrix(t *testing.T) {
	accepted := map[string]func(*Bundle){
		"observation-complete-empty-classes": func(b *Bundle) {},
		"observation-missing-class": func(b *Bundle) {
			b.ObservedContainerClasses = []ContainerClass{ContainerRegular}
			b.Provenance.Completeness = CompletenessPartial
			b.Provenance.Errors = []string{"ephemeral containers were not observed"}
		},
		"observation-abort-after-classes": func(b *Bundle) {
			b.Provenance.Coverage.Termination = TerminationAborted
			b.Provenance.Completeness = CompletenessPartial
			b.Provenance.Errors = []string{"budget aborted the collection"}
		},
		"observation-abort-without-progress": func(b *Bundle) {
			b.ObservedContainerClasses = []ContainerClass{}
			b.Images = []ImageIdentity{}
			b.Provenance.Coverage.Termination = TerminationAborted
			b.Provenance.Completeness = CompletenessUnknown
			b.Provenance.Errors = []string{"the collection could not be established"}
		},
	}
	for name, mutate := range accepted {
		t.Run(name, func(t *testing.T) {
			bundle := testBundle(t)
			mutate(&bundle)
			if err := ValidateBundle(bundle); err != nil {
				t.Fatalf("ValidateBundle rejected the ratified fixture %s: %v", name, err)
			}
		})
	}

	rejected := map[string]func(*Bundle){
		"complete with a missing class": func(b *Bundle) {
			b.ObservedContainerClasses = []ContainerClass{ContainerRegular}
		},
		"complete after an abort": func(b *Bundle) {
			b.Provenance.Coverage.Termination = TerminationAborted
		},
		"rows on an observation": func(b *Bundle) {
			total := uint64(1)
			b.Provenance.Coverage.Rows = &CoverageRows{Total: &total, Accepted: 1, Rejected: 0}
		},
		"duplicated class": func(b *Bundle) {
			b.ObservedContainerClasses = []ContainerClass{ContainerRegular, ContainerEphemeral, ContainerInit, ContainerRegular}
		},
		"unknown class": func(b *Bundle) {
			b.ObservedContainerClasses = []ContainerClass{ContainerClass("sidecar")}
		},
		"image outside the observed classes": func(b *Bundle) {
			b.ObservedContainerClasses = []ContainerClass{ContainerInit}
			b.Provenance.Completeness = CompletenessPartial
			b.Provenance.Errors = []string{"regular containers were not observed"}
		},
		"unknown termination while complete": func(b *Bundle) {
			b.Provenance.Coverage.Termination = TerminationUnknown
		},
		"aborted observation declared unknown": func(b *Bundle) {
			b.Provenance.Coverage.Termination = TerminationAborted
			b.Provenance.Completeness = CompletenessUnknown
			b.Provenance.Errors = []string{"budget aborted the collection"}
		},
		"aborted observation without progress declared partial": func(b *Bundle) {
			b.ObservedContainerClasses = []ContainerClass{}
			b.Images = []ImageIdentity{}
			b.Provenance.Coverage.Termination = TerminationAborted
			b.Provenance.Completeness = CompletenessPartial
			b.Provenance.Errors = []string{"budget aborted the collection"}
		},
	}
	for name, mutate := range rejected {
		t.Run(name, func(t *testing.T) {
			bundle := testBundle(t)
			mutate(&bundle)
			if err := ValidateBundle(bundle); err == nil {
				t.Fatalf("ValidateBundle accepted an invalid observation: %s", name)
			}
		})
	}
}

func TestValidateCoverageReportsOverflow(t *testing.T) {
	bundle := testImportBundle(t)
	total := ^uint64(0)
	bundle.Provenance.Coverage.Rows = &CoverageRows{Total: &total, Accepted: ^uint64(0), Rejected: 1}
	bundle.Provenance.Completeness = CompletenessPartial
	bundle.Provenance.Errors = []string{"counted rows overflow"}
	if err := ValidateBundle(bundle); err == nil {
		t.Fatal("an overflowing accepted plus rejected was accepted")
	}
}

// TestValidateKeepsFreeTextWhitespace fixes the decision on free text: its bytes
// are hashed as written, so surrounding whitespace is kept and only emptiness or
// invalid UTF-8 are rejected. Identifiers keep the stricter rule.
func TestValidateKeepsFreeTextWhitespace(t *testing.T) {
	warned := testBundle(t)
	warned.Evidence[0].Warnings = []Warning{{
		Code:    "tool_failure",
		Class:   WarningInformational,
		Message: "  collector retried the request\n",
	}}
	if err := ValidateBundle(warned); err != nil {
		t.Fatalf("a warning message with surrounding whitespace must be representable: %v", err)
	}

	partial := testBundle(t)
	partial.ObservedContainerClasses = []ContainerClass{ContainerRegular}
	partial.Provenance.Completeness = CompletenessPartial
	partial.Provenance.Errors = []string{" budget aborted the collection "}
	if err := ValidateBundle(partial); err != nil {
		t.Fatalf("an error with surrounding whitespace must be representable: %v", err)
	}

	empty := testBundle(t)
	empty.ObservedContainerClasses = []ContainerClass{ContainerRegular}
	empty.Provenance.Completeness = CompletenessPartial
	empty.Provenance.Errors = []string{""}
	if err := ValidateBundle(empty); err == nil {
		t.Fatal("an empty error string was accepted as a visible error")
	}

	blank := testBundle(t)
	blank.ObservedContainerClasses = []ContainerClass{ContainerRegular}
	blank.Provenance.Completeness = CompletenessPartial
	blank.Provenance.Errors = []string{"   "}
	if err := ValidateBundle(blank); err == nil {
		t.Fatal("a whitespace-only error was accepted as a visible error")
	}

	blankWarning := testBundle(t)
	blankWarning.Evidence[0].Warnings = []Warning{{Code: "tool_failure", Class: WarningInformational, Message: "\t"}}
	if err := ValidateBundle(blankWarning); err == nil {
		t.Fatal("a whitespace-only warning message was accepted")
	}

	padded := testBundle(t)
	padded.Subject.UID = UID(" pod-uid-1 ")
	if err := ValidateBundle(padded); err == nil {
		t.Fatal("an identifier with surrounding whitespace was accepted")
	}
}
