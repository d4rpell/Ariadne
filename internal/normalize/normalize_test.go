package normalize

import (
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/d4rpell/Ariadne/internal/identity"
	"github.com/d4rpell/Ariadne/internal/ingest"
	contract "github.com/d4rpell/Ariadne/pkg/evidence"
)

const (
	syntheticHeader = "schema_version,vulnerability_id,package_name,installed_version,fix_status," +
		"image_registry,image_repository,image_tag,package_type,package_id,path,severity," +
		"description,published_date,discovery_date"
	syntheticMarker = "SYNTHETIC_PRIVATE_MARKER"
)

func syntheticRowFor(vulnerabilityID, registry, repository, tag, severity, description string) string {
	return strings.Join([]string{
		"1.0", vulnerabilityID, "pkg-a", "1.2.3-1", "not fixed", registry, repository, tag,
		"rpm", "pkgid", "/usr/lib/a", severity, description, "2024-01-02", "2024-01-03",
	}, ",")
}

func validRow(vulnerabilityID string) string {
	return syntheticRowFor(vulnerabilityID, "reg.example", "app", "release", "High", "text")
}

func rejectedRow() string {
	return syntheticRowFor("CVE-2024-01", "reg.example", "app", "release", "High", "text")
}

func parseImport(t *testing.T, rows ...string) ingest.Result {
	t.Helper()
	var builder strings.Builder
	builder.WriteString(syntheticHeader)
	for _, row := range rows {
		builder.WriteString("\r\n")
		builder.WriteString(row)
	}
	builder.WriteString("\r\n")
	result, err := ingest.ParsePrismaV1(strings.NewReader(builder.String()))
	if err != nil {
		t.Fatalf("ParsePrismaV1: unexpected error: %v", err)
	}
	return result
}

func containerKey(name string) identity.ContainerKey {
	return identity.ContainerKey{
		SubjectUID:     contract.UID("uid-0001"),
		ContainerClass: contract.ContainerRegular,
		ContainerName:  contract.ContainerName(name),
	}
}

func syntheticBinding(name string) identity.ImageBinding {
	return identity.ImageBinding{
		Key:       containerKey(name),
		InputKind: identity.InputSynthetic,
		Platform:  contract.PlatformUnknown,
	}
}

func bindingFor(index int, binding identity.ImageBinding) Binding {
	return Binding{FindingIndex: index, ContainerKey: binding.Key, Image: binding}
}

func requestedImage(value string) *contract.RequestedImage {
	image := contract.RequestedImage(value)
	return &image
}

func rawImageID(value string) *contract.RawImageID {
	image := contract.RawImageID(value)
	return &image
}

func guaranteedDigest(t *testing.T, value string) *contract.NormalizedDigest {
	t.Helper()
	digest, err := identity.NewGuaranteedDigest(value)
	if err != nil {
		t.Fatalf("NewGuaranteedDigest(%q): unexpected error: %v", value, err)
	}
	return &digest
}

func TestNormalizeConsumesOnlyAcceptedFindings(t *testing.T) {
	imported := parseImport(t, validRow("CVE-2024-0001"), rejectedRow(), validRow("CVE-2024-0002"))
	if len(imported.Findings) != 2 || len(imported.Rejections) != 1 {
		t.Fatalf("parser fixture: findings = %d, rejections = %d", len(imported.Findings), len(imported.Rejections))
	}

	result, err := Normalize(Input{Import: imported})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result.Findings) != len(imported.Findings) {
		t.Fatalf("findings = %d, want %d: a rejected record is never promoted", len(result.Findings), len(imported.Findings))
	}
	for i, finding := range result.Findings {
		if !reflect.DeepEqual(finding.Source, imported.Findings[i]) {
			t.Fatalf("finding %d not preserved verbatim", i)
		}
	}
	if len(result.Diagnostics.Rejections) != 1 {
		t.Fatalf("rejections = %d, want 1", len(result.Diagnostics.Rejections))
	}
	if !reflect.DeepEqual(result.Diagnostics.Rejections[0], imported.Rejections[0]) {
		t.Fatal("rejection locator or reason altered")
	}
	if result.Diagnostics.Rejections[0].Locator.Record != 2 {
		t.Fatalf("rejection record = %d, want 2 (header excluded, rejected records counted)", result.Diagnostics.Rejections[0].Locator.Record)
	}
}

func TestNormalizeKeepsDuplicateRowsPerOccurrence(t *testing.T) {
	imported := parseImport(t, validRow("CVE-2024-0001"), validRow("CVE-2024-0001"))
	result, err := Normalize(Input{Import: imported})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result.Findings) != 2 {
		t.Fatalf("findings = %d, want 2: duplicated rows count by occurrence", len(result.Findings))
	}
	firstRow, secondRow := result.Findings[0].Source, result.Findings[1].Source
	if firstRow.Locator.Record != 1 || secondRow.Locator.Record != 2 {
		t.Fatalf("locators = %d/%d, want 1/2: each occurrence keeps its own record ordinal", firstRow.Locator.Record, secondRow.Locator.Record)
	}
	firstRow.Locator, secondRow.Locator = ingest.Locator{}, ingest.Locator{}
	if !reflect.DeepEqual(firstRow, secondRow) {
		t.Fatal("duplicated rows were altered beyond their locator")
	}
}

func TestNormalizeDeclaredImageVerbatim(t *testing.T) {
	row := syntheticRowFor("CVE-2024-0001", "REG.example", "Team/App", "", "high", "MiXeD text")
	imported := parseImport(t, row)
	result, err := Normalize(Input{Import: imported})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	declared := result.Findings[0].DeclaredImage
	want := DeclaredImage{Registry: "REG.example", Repository: "Team/App", Tag: ""}
	if declared != want {
		t.Fatalf("declared image = %+v, want %+v verbatim", declared, want)
	}
	source := result.Findings[0].Source
	if source.Severity != "high" || source.FixStatus != "not fixed" || source.InstalledVersion != "1.2.3-1" {
		t.Fatalf("source facts not verbatim: %+v", source)
	}
	if source.Description != "MiXeD text" {
		t.Fatalf("description = %q, want verbatim", source.Description)
	}
	fields := reflect.TypeOf(DeclaredImage{})
	if fields.NumField() != 3 {
		t.Fatalf("DeclaredImage has %d fields: no single composed string is allowed before its grammar is ratified", fields.NumField())
	}
}

func TestNormalizeUnboundFindingStaysUnbound(t *testing.T) {
	imported := parseImport(t, validRow("CVE-2024-0001"))
	result, err := Normalize(Input{Import: imported})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	finding := result.Findings[0]
	if finding.State != NormalizationUnbound {
		t.Fatalf("state = %q, want %q", finding.State, NormalizationUnbound)
	}
	if finding.Binding != nil || finding.Resolution != nil {
		t.Fatal("identity fabricated for a finding without a binding")
	}
}

func TestNormalizeMapsResolutionStates(t *testing.T) {
	imported := parseImport(t, validRow("CVE-2024-0001"), validRow("CVE-2024-0002"), validRow("CVE-2024-0003"))

	tagOnly := syntheticBinding("tag-only")
	tagOnly.RequestedImage = requestedImage("reg.example/app:release")
	rawOnly := syntheticBinding("raw-only")
	rawOnly.RawImageID = rawImageID("reg.example/app@sha256:" + strings.Repeat("ab", 32))
	withDigest := syntheticBinding("with-digest")
	withDigest.GuaranteedDigest = guaranteedDigest(t, "sha256:"+strings.Repeat("cd", 32))

	result, err := Normalize(Input{
		Import:   imported,
		Bindings: []Binding{bindingFor(0, tagOnly), bindingFor(1, rawOnly), bindingFor(2, withDigest)},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Findings[0].State != NormalizationUnresolved {
		t.Fatalf("tag only: state = %q, want %q", result.Findings[0].State, NormalizationUnresolved)
	}
	if result.Findings[0].Resolution.Binding.GuaranteedDigest != nil {
		t.Fatal("tag only: digest fabricated from a mutable tag")
	}
	if result.Findings[1].State != NormalizationBound {
		t.Fatalf("raw only: state = %q, want %q", result.Findings[1].State, NormalizationBound)
	}
	if result.Findings[1].Resolution.Binding.GuaranteedDigest != nil {
		t.Fatal("raw only: guaranteed digest inferred from the observed image ID")
	}
	if result.Findings[2].State != NormalizationBound {
		t.Fatalf("digest: state = %q, want %q", result.Findings[2].State, NormalizationBound)
	}
	if result.Findings[2].Resolution.Key.ContainerName != "with-digest" {
		t.Fatalf("resolution key = %q", result.Findings[2].Resolution.Key.ContainerName)
	}
}

func TestNormalizeSeparatesContainerClasses(t *testing.T) {
	imported := parseImport(t, validRow("CVE-2024-0001"), validRow("CVE-2024-0002"), validRow("CVE-2024-0003"))
	classes := []contract.ContainerClass{contract.ContainerRegular, contract.ContainerInit, contract.ContainerEphemeral}
	bindings := make([]Binding, 0, len(classes))
	for i, class := range classes {
		binding := syntheticBinding("api")
		binding.Key.ContainerClass = class
		binding.GuaranteedDigest = guaranteedDigest(t, "sha256:"+strings.Repeat(string(rune('a'+i)), 64))
		bindings = append(bindings, bindingFor(i, binding))
	}
	result, err := Normalize(Input{Import: imported, Bindings: bindings})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	seen := map[contract.ContainerClass]bool{}
	for i, finding := range result.Findings {
		if finding.State != NormalizationBound {
			t.Fatalf("finding %d: state = %q, want %q", i, finding.State, NormalizationBound)
		}
		seen[finding.Resolution.Key.ContainerClass] = true
	}
	for _, class := range classes {
		if !seen[class] {
			t.Fatalf("class %q lost during normalization", class)
		}
	}

	sidecar := syntheticBinding("api")
	sidecar.Key.ContainerClass = "sidecar"
	if _, err := Normalize(Input{Import: imported, Bindings: []Binding{bindingFor(0, sidecar)}}); err == nil {
		t.Fatal("unknown container class accepted, want rejection")
	}
}

func TestNormalizeRejectsUnusableBindings(t *testing.T) {
	imported := parseImport(t, validRow("CVE-2024-0001"))
	cases := map[string][]Binding{
		"index out of range": {bindingFor(1, syntheticBinding("api"))},
		"negative index":     {bindingFor(-1, syntheticBinding("api"))},
		"duplicate index": {
			bindingFor(0, syntheticBinding("api")),
			bindingFor(0, syntheticBinding("worker")),
		},
		"key mismatch": {{
			FindingIndex: 0,
			ContainerKey: containerKey("other"),
			Image:        syntheticBinding("api"),
		}},
		"unsupported input kind": {bindingFor(0, func() identity.ImageBinding {
			binding := syntheticBinding("api")
			binding.InputKind = identity.InputContainerObservation
			binding.GuaranteedDigest = guaranteedDigest(t, "sha256:"+strings.Repeat("ab", 32))
			return binding
		}())},
	}
	for name, bindings := range cases {
		result, err := Normalize(Input{Import: imported, Bindings: bindings})
		if err == nil {
			t.Errorf("%s: expected error, got none", name)
		}
		if len(result.Findings) != 0 {
			t.Errorf("%s: unusable binding produced partial results", name)
		}
	}
}

func TestNormalizeRefusesConflictAcrossFindings(t *testing.T) {
	imported := parseImport(t, validRow("CVE-2024-0001"), validRow("CVE-2024-0002"))
	first := syntheticBinding("api")
	first.SourceName = "sanitized-pods.json"
	first.SourceHash = contract.SourceHash("sha256:" + strings.Repeat("a", 64))
	first.Locator = contract.SourceLocator("items[0].status.containerStatuses[0].imageID")
	first.RawImageID = rawImageID("reg.example/app@sha256:" + strings.Repeat("cd", 32))
	second := first
	second.RawImageID = rawImageID("reg.example/app@sha256:" + strings.Repeat("ef", 32))

	result, err := Normalize(Input{Import: imported, Bindings: []Binding{bindingFor(0, first), bindingFor(1, second)}})
	if err == nil {
		t.Fatal("contradictory observations accepted silently")
	}
	if !strings.Contains(err.Error(), identity.ConflictSourceConflict) {
		t.Fatalf("error %q does not name the conflict", err)
	}
	if len(result.Findings) != 0 {
		t.Fatal("conflicting input produced results")
	}
}

func TestNormalizeReusesIdenticalObservationAcrossFindings(t *testing.T) {
	imported := parseImport(t,
		syntheticRowFor("CVE-2024-0001", "registry.example", "app", "release", "High", "first"),
		syntheticRowFor("CVE-2024-0002", "registry.example", "app", "stable", "Critical", "second"),
	)
	observation := syntheticBinding("api")
	observation.SourceName = "sanitized-pods.json"
	observation.SourceHash = contract.SourceHash("sha256:" + strings.Repeat("a", 64))
	observation.Locator = contract.SourceLocator("items[0].status.containerStatuses[0].imageID")
	observation.RawImageID = rawImageID("reg.example/app@sha256:" + strings.Repeat("cd", 32))

	result, err := Normalize(Input{Import: imported, Bindings: []Binding{bindingFor(0, observation), bindingFor(1, observation)}})
	if err != nil {
		t.Fatalf("identical observation rejected: %v", err)
	}
	if len(result.Findings) != 2 {
		t.Fatalf("findings = %d, want 2", len(result.Findings))
	}
	for i, finding := range result.Findings {
		if finding.State != NormalizationBound {
			t.Fatalf("finding %d state = %q, want %q", i, finding.State, NormalizationBound)
		}
		if finding.Binding == nil || finding.Binding.RawImageID == nil || *finding.Binding.RawImageID != *observation.RawImageID {
			t.Fatalf("finding %d lost shared observation", i)
		}
		if finding.Source.VulnerabilityID == result.Findings[1-i].Source.VulnerabilityID {
			t.Fatal("source findings collapsed while reusing the observation")
		}
	}
	if result.Findings[0].DeclaredImage == result.Findings[1].DeclaredImage {
		t.Fatal("distinct requested image declarations collapsed while reusing the observation")
	}
	if result.Findings[0].Source.Description != "first" || result.Findings[1].Source.Description != "second" {
		t.Fatalf("source descriptions were not preserved: %q / %q", result.Findings[0].Source.Description, result.Findings[1].Source.Description)
	}
}

func TestNormalizeComposesRequestedImagePerFinding(t *testing.T) {
	imported := parseImport(t,
		syntheticRowFor("CVE-2024-0001", "registry.example", "app", "release", "High", "first"),
		syntheticRowFor("CVE-2024-0002", "registry.example", "app", "stable", "Critical", "second"),
	)
	result, err := Normalize(Input{Import: imported})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	want := []string{"registry.example/app:release", "registry.example/app:stable"}
	for i, finding := range result.Findings {
		if finding.RequestedImage == nil {
			t.Fatalf("finding %d: requested image not composed", i)
		}
		if string(*finding.RequestedImage) != want[i] {
			t.Fatalf("finding %d: requested image = %q, want %q", i, *finding.RequestedImage, want[i])
		}
		if strings.Contains(string(*finding.RequestedImage), "@") {
			t.Fatalf("finding %d: composed reference carries a digest", i)
		}
	}
	if result.Findings[0].DeclaredImage == result.Findings[1].DeclaredImage {
		t.Fatal("distinct declarations collapsed while composing the reference")
	}
	if result.Findings[0].DeclaredImage.Tag != "release" || result.Findings[1].DeclaredImage.Tag != "stable" {
		t.Fatal("declared tags were rewritten instead of preserved verbatim")
	}
}

func TestNormalizeLeavesRequestedImageUnrepresented(t *testing.T) {
	registry := "my registry"
	imported := parseImport(t, syntheticRowFor("CVE-2024-0001", registry, "app", "release", "High", "text"))
	if len(imported.Findings) != 1 {
		t.Fatalf("parser fixture: findings = %d, want 1", len(imported.Findings))
	}
	result, err := Normalize(Input{Import: imported})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	finding := result.Findings[0]
	if finding.RequestedImage != nil {
		t.Fatalf("declaration outside the canonical grammar produced %q", *finding.RequestedImage)
	}
	if finding.DeclaredImage.Registry != registry || finding.DeclaredImage.Repository != "app" || finding.DeclaredImage.Tag != "release" {
		t.Fatalf("declared components not preserved for diagnosis: %+v", finding.DeclaredImage)
	}
	if finding.Source.VulnerabilityID != "CVE-2024-0001" {
		t.Fatal("source fact lost while the reference stayed unrepresented")
	}
}

// TestNormalizeDetachesObservationPointers pins the no-alias rule: the result
// must not change under a caller that keeps writing to the observation it passed
// in, and the caller must not be able to rewrite what the result asserts.
func TestNormalizeDetachesObservationPointers(t *testing.T) {
	imported := parseImport(t, validRow("CVE-2024-0001"))
	observedAt, err := contract.NewTimestamp(time.Date(2026, 9, 25, 12, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatalf("NewTimestamp: %v", err)
	}
	binding := syntheticBinding("api")
	binding.RequestedImage = requestedImage("reg.example/app:release")
	binding.RawImageID = rawImageID("reg.example/app@sha256:" + strings.Repeat("ab", 32))
	binding.GuaranteedDigest = guaranteedDigest(t, "sha256:"+strings.Repeat("cd", 32))
	binding.ObservedAt = &observedAt
	failure := &ingest.FileError{Offset: 7, Reason: ingest.ReasonBOM}

	result, err := Normalize(Input{Import: imported, StructuralError: failure, Bindings: []Binding{bindingFor(0, binding)}})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	finding := result.Findings[0]
	if finding.Binding == nil || finding.Binding.RequestedImage == nil || finding.Binding.RawImageID == nil || finding.Binding.GuaranteedDigest == nil || finding.Binding.ObservedAt == nil {
		t.Fatalf("observation not preserved: %+v", finding.Binding)
	}
	if finding.Binding.RequestedImage == binding.RequestedImage ||
		finding.Binding.RawImageID == binding.RawImageID ||
		finding.Binding.GuaranteedDigest == binding.GuaranteedDigest ||
		finding.Binding.ObservedAt == binding.ObservedAt {
		t.Fatal("binding pointers alias the caller's observation")
	}
	if result.Diagnostics.StructuralError == failure {
		t.Fatal("structural error aliases the caller's value")
	}

	keptRequested := *finding.Binding.RequestedImage
	keptRaw := *finding.Binding.RawImageID
	keptDigest := *finding.Binding.GuaranteedDigest
	keptOffset := result.Diagnostics.StructuralError.Offset
	*binding.RequestedImage = contract.RequestedImage("mutated")
	*binding.RawImageID = contract.RawImageID("mutated")
	*binding.GuaranteedDigest = contract.NormalizedDigest("mutated")
	failure.Offset = 999
	if *finding.Binding.RequestedImage != keptRequested || *finding.Binding.RawImageID != keptRaw || *finding.Binding.GuaranteedDigest != keptDigest {
		t.Fatal("result changed after the caller rewrote its observation")
	}
	if result.Diagnostics.StructuralError.Offset != keptOffset {
		t.Fatal("structural error changed after the caller rewrote it")
	}
}

func TestNormalizeRejectsForeignCoverageMethod(t *testing.T) {
	imported := parseImport(t, validRow("CVE-2024-0001"))
	imported.Coverage.Method = contract.CoverageContainerObservation
	if _, err := Normalize(Input{Import: imported}); err == nil {
		t.Fatal("container observation accepted as a findings import")
	}
}

func TestNormalizeRejectsUndeclaredCompleteness(t *testing.T) {
	imported := parseImport(t, validRow("CVE-2024-0001"))
	imported.Completeness = ""
	if _, err := Normalize(Input{Import: imported}); err == nil {
		t.Fatal("undeclared completeness accepted")
	}
}

func TestNormalizeNeverPromotesCompleteness(t *testing.T) {
	complete := parseImport(t, validRow("CVE-2024-0001"))
	result, err := Normalize(Input{Import: complete})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Completeness != contract.CompletenessComplete {
		t.Fatalf("completeness = %q, want %q", result.Completeness, contract.CompletenessComplete)
	}

	partial := parseImport(t, validRow("CVE-2024-0001"), rejectedRow())
	result, err = Normalize(Input{Import: partial})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Completeness != contract.CompletenessPartial {
		t.Fatalf("completeness = %q, want %q: an import with rejections is never complete", result.Completeness, contract.CompletenessPartial)
	}
	if result.Coverage.Rows == nil || *result.Coverage.Rows.Total != 2 || result.Coverage.Rows.Accepted != 1 || result.Coverage.Rows.Rejected != 1 {
		t.Fatalf("coverage rows altered: %+v", result.Coverage.Rows)
	}

	empty := parseImport(t)
	result, err = Normalize(Input{Import: empty})
	if err != nil {
		t.Fatalf("empty import: unexpected error: %v", err)
	}
	if len(result.Findings) != 0 || result.Completeness != contract.CompletenessComplete {
		t.Fatalf("empty import: findings = %d, completeness = %q", len(result.Findings), result.Completeness)
	}
}

func TestNormalizePreservesStructuralError(t *testing.T) {
	aborted, parseErr := ingest.ParsePrismaV1(strings.NewReader("\uFEFF" + syntheticHeader + "\r\n"))
	var fileErr *ingest.FileError
	if !errors.As(parseErr, &fileErr) {
		t.Fatalf("expected *ingest.FileError, got %v", parseErr)
	}
	result, err := Normalize(Input{Import: aborted, StructuralError: fileErr})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Diagnostics.StructuralError == nil {
		t.Fatal("structural failure dropped")
	}
	if result.Diagnostics.StructuralError.Offset != fileErr.Offset || result.Diagnostics.StructuralError.Reason != ingest.ReasonBOM {
		t.Fatalf("structural error altered: %+v", result.Diagnostics.StructuralError)
	}
	if result.Completeness != contract.CompletenessUnknown {
		t.Fatalf("completeness = %q, want %q for an aborted import", result.Completeness, contract.CompletenessUnknown)
	}
}

func TestIncompleteEvidenceNeverAffirmative(t *testing.T) {
	partial := parseImport(t, validRow("CVE-2024-0001"), rejectedRow())
	withDigest := syntheticBinding("api")
	withDigest.GuaranteedDigest = guaranteedDigest(t, "sha256:"+strings.Repeat("ab", 32))

	result, err := Normalize(Input{Import: partial, Bindings: []Binding{bindingFor(0, withDigest)}})
	if err != nil {
		t.Fatalf("partial import: unexpected error: %v", err)
	}
	if result.Findings[0].State == NormalizationBound {
		t.Fatal("partial import produced an affirmative state")
	}
	if result.Findings[0].State != NormalizationUnknown {
		t.Fatalf("partial import: state = %q, want %q", result.Findings[0].State, NormalizationUnknown)
	}
	if result.Findings[0].Binding == nil || result.Findings[0].Resolution == nil {
		t.Fatal("evidence discarded instead of kept without assertion")
	}

	unbound, err := Normalize(Input{Import: partial})
	if err != nil {
		t.Fatalf("unbound partial import: unexpected error: %v", err)
	}
	if unbound.Findings[0].State != NormalizationUnbound {
		t.Fatalf("unbound partial import: state = %q, want %q", unbound.Findings[0].State, NormalizationUnbound)
	}

	complete := parseImport(t, validRow("CVE-2024-0001"))
	tagOnly := syntheticBinding("api")
	tagOnly.RequestedImage = requestedImage("reg.example/app:release")
	unresolved, err := Normalize(Input{Import: complete, Bindings: []Binding{bindingFor(0, tagOnly)}})
	if err != nil {
		t.Fatalf("tag only: unexpected error: %v", err)
	}
	if unresolved.Findings[0].State != NormalizationUnresolved {
		t.Fatalf("tag only: state = %q, want %q", unresolved.Findings[0].State, NormalizationUnresolved)
	}

	aborted, parseErr := ingest.ParsePrismaV1(&failingReader{data: syntheticHeader + "\r\n" + validRow("CVE-2024-0001") + "\r\n"})
	var fileErr *ingest.FileError
	if !errors.As(parseErr, &fileErr) {
		t.Fatalf("expected a structural failure, got %v", parseErr)
	}
	if len(aborted.Findings) != 1 {
		t.Fatalf("aborted fixture: findings = %d, want the verified prefix", len(aborted.Findings))
	}
	withRaw := syntheticBinding("api")
	withRaw.RawImageID = rawImageID("reg.example/app@sha256:" + strings.Repeat("cd", 32))
	result, err = Normalize(Input{Import: aborted, StructuralError: fileErr, Bindings: []Binding{bindingFor(0, withRaw)}})
	if err != nil {
		t.Fatalf("aborted import: unexpected error: %v", err)
	}
	if result.Completeness != contract.CompletenessPartial {
		t.Fatalf("aborted import: completeness = %q, want %q for a verified prefix after a failure", result.Completeness, contract.CompletenessPartial)
	}
	for i, finding := range result.Findings {
		if finding.State == NormalizationBound {
			t.Fatalf("aborted import: finding %d reached an affirmative state", i)
		}
	}
	if result.Findings[0].State != NormalizationUnknown {
		t.Fatalf("aborted import: state = %q, want %q", result.Findings[0].State, NormalizationUnknown)
	}
}

// failingReader delivers its data and then fails, so the parser reports a
// structural failure after a verified prefix.
type failingReader struct {
	data      string
	delivered bool
}

func (r *failingReader) Read(p []byte) (int, error) {
	if !r.delivered {
		r.delivered = true
		return copy(p, r.data), nil
	}
	return 0, errors.New("synthetic read failure")
}

func TestNormalizeDoesNotMutateOrAliasInput(t *testing.T) {
	imported := parseImport(t, validRow("CVE-2024-0001"), rejectedRow())
	binding := syntheticBinding("api")
	binding.RawImageID = rawImageID("reg.example/app@sha256:" + strings.Repeat("ab", 32))

	beforeFindings := append([]ingest.Finding{}, imported.Findings...)
	beforeRejections := append([]ingest.Rejection{}, imported.Rejections...)
	beforeAccepted := imported.Coverage.Rows.Accepted

	result, err := Normalize(Input{Import: imported, Bindings: []Binding{bindingFor(0, binding)}})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !reflect.DeepEqual(imported.Findings, beforeFindings) ||
		!reflect.DeepEqual(imported.Rejections, beforeRejections) ||
		imported.Coverage.Rows.Accepted != beforeAccepted {
		t.Fatal("Normalize mutated its input")
	}
	if result.Coverage.Rows == imported.Coverage.Rows {
		t.Fatal("coverage rows aliased: one consumer could rewrite another's counters")
	}
	if result.Coverage.Rows.Total == imported.Coverage.Rows.Total {
		t.Fatal("coverage total aliased: the counted total is shared with the parser result")
	}
	keptReason := result.Diagnostics.Rejections[0].Reason
	keptAccepted := result.Coverage.Rows.Accepted
	keptTotal := *result.Coverage.Rows.Total
	imported.Rejections[0].Reason = ingest.ReasonNUL
	imported.Coverage.Rows.Accepted = 99
	*imported.Coverage.Rows.Total = 99
	if result.Diagnostics.Rejections[0].Reason != keptReason {
		t.Fatal("rejections aliased the caller's slice")
	}
	if result.Coverage.Rows.Accepted != keptAccepted {
		t.Fatal("coverage counters aliased the caller's rows")
	}
	if *result.Coverage.Rows.Total != keptTotal {
		t.Fatal("coverage total aliased the caller's value")
	}
}

func TestNormalizeErrorsAreStatic(t *testing.T) {
	imported := parseImport(t, syntheticRowFor("CVE-2024-0001", "reg.example", "app", "release", "High", syntheticMarker))
	binding := syntheticBinding(syntheticMarker)
	binding.Key.SubjectUID = contract.UID(syntheticMarker)

	_, err := Normalize(Input{Import: imported, Bindings: []Binding{
		bindingFor(0, binding),
		bindingFor(0, syntheticBinding("api")),
	}})
	if err == nil {
		t.Fatal("expected error")
	}
	if strings.Contains(err.Error(), syntheticMarker) {
		t.Fatalf("error %q leaks input data", err)
	}

	_, err = Normalize(Input{Import: imported, Bindings: []Binding{bindingFor(3, binding)}})
	if err == nil {
		t.Fatal("expected error")
	}
	if strings.Contains(err.Error(), syntheticMarker) {
		t.Fatalf("error %q leaks input data", err)
	}
}

func TestNormalizeIsDeterministic(t *testing.T) {
	imported := parseImport(t, validRow("CVE-2024-0001"), rejectedRow())
	binding := syntheticBinding("api")
	binding.GuaranteedDigest = guaranteedDigest(t, "sha256:"+strings.Repeat("ab", 32))
	input := Input{Import: imported, Bindings: []Binding{bindingFor(0, binding)}}

	first, err := Normalize(input)
	if err != nil {
		t.Fatalf("first call: unexpected error: %v", err)
	}
	second, err := Normalize(input)
	if err != nil {
		t.Fatalf("second call: unexpected error: %v", err)
	}
	if !reflect.DeepEqual(first, second) {
		t.Fatal("normalization is not deterministic")
	}
}

// TestNormalizeNeverBuildsWire pins the boundary of A1-02: no type of this
// package carries the bundle or an evidence item, and an import is never read as
// an inventory of observed container classes.
func TestNormalizeNeverBuildsWire(t *testing.T) {
	wireTypes := []reflect.Type{
		reflect.TypeOf(contract.Bundle{}),
		reflect.TypeOf(contract.EvidenceItem{}),
		reflect.TypeOf(contract.ImageIdentity{}),
		reflect.TypeOf(contract.RunProvenance{}),
	}
	targets := []reflect.Type{
		reflect.TypeOf(Result{}),
		reflect.TypeOf(NormalizedFinding{}),
		reflect.TypeOf(Diagnostics{}),
		reflect.TypeOf(DeclaredImage{}),
	}
	for _, target := range targets {
		if _, found := target.FieldByName("ObservedContainerClasses"); found {
			t.Errorf("%s exposes observed_container_classes: findings_import observes no containers", target)
		}
		for i := 0; i < target.NumField(); i++ {
			field := target.Field(i)
			for _, wire := range wireTypes {
				if field.Type == wire {
					t.Errorf("%s.%s carries %s: the bundle is built in A1-03", target, field.Name, wire)
				}
			}
		}
	}
}
