package normalize

import (
	"reflect"
	"strings"
	"testing"

	"github.com/d4rpell/Ariadne/internal/identity"
	"github.com/d4rpell/Ariadne/internal/ingest"
	contract "github.com/d4rpell/Ariadne/pkg/evidence"
)

// a108GuaranteedDigest builds a proven digest for the normalize tests.
func a108GuaranteedDigest(t *testing.T, letter string) *contract.NormalizedDigest {
	t.Helper()
	body := strings.Repeat(letter, 64)
	return guaranteedDigest(t, "sha256:"+body)
}

// a108ObservedBinding is a complete synthetic observation for one container.
func a108ObservedBinding(t *testing.T, name string) identity.ImageBinding {
	t.Helper()
	binding := syntheticBinding(name)
	binding.RawImageID = rawImageID("reg.example/app@sha256:" + strings.Repeat("b", 64))
	binding.GuaranteedDigest = a108GuaranteedDigest(t, "c")
	binding.Platform = contract.PlatformKnown
	binding.PlatformOS = "linux"
	binding.PlatformArchitecture = "amd64"
	return binding
}

// TestA108Bindings covers B01: identity reaches findings only through explicit
// bindings, and the binding key must agree with the observation key.
func TestA108Bindings(t *testing.T) {
	t.Run("no binding leaves the finding unbound", func(t *testing.T) {
		imported := parseImport(t, validRow("CVE-2024-0001"))
		result, err := Normalize(Input{Import: imported})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(result.Findings) != 1 {
			t.Fatalf("findings = %d", len(result.Findings))
		}
		finding := result.Findings[0]
		if finding.State != NormalizationUnbound {
			t.Fatalf("state = %q, want unbound", finding.State)
		}
		if finding.Binding != nil || finding.Resolution != nil {
			t.Fatal("an unbound finding must not carry identity")
		}
		if finding.RequestedImage == nil {
			t.Fatal("a representable declaration must still compose its requested image")
		}
	})

	t.Run("explicit binding carries identity to the right finding", func(t *testing.T) {
		imported := parseImport(t, validRow("CVE-2024-0001"), validRow("CVE-2024-0002"))
		binding := a108ObservedBinding(t, "api")
		result, err := Normalize(Input{
			Import:   imported,
			Bindings: []Binding{bindingFor(1, binding)},
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if result.Findings[0].State != NormalizationUnbound {
			t.Fatalf("finding 0 state = %q, want unbound", result.Findings[0].State)
		}
		if result.Findings[1].State != NormalizationBound {
			t.Fatalf("finding 1 state = %q, want bound", result.Findings[1].State)
		}
		if result.Findings[1].Binding.Key.ContainerName != contract.ContainerName("api") {
			t.Fatalf("binding = %+v", result.Findings[1].Binding.Key)
		}
	})

	t.Run("an incomplete import never produces bound", func(t *testing.T) {
		// One valid row plus a rejected one: completeness is partial, so even a
		// perfectly resolved binding yields an inconclusive normalized state.
		imported := parseImport(t, validRow("CVE-2024-0001"), rejectedRow())
		binding := a108ObservedBinding(t, "api")
		result, err := Normalize(Input{
			Import:   imported,
			Bindings: []Binding{bindingFor(0, binding)},
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if imported.Completeness != contract.CompletenessPartial {
			t.Fatalf("fixture completeness = %q, want partial", imported.Completeness)
		}
		if result.Findings[0].State != NormalizationUnknown {
			t.Fatalf("state = %q, want unknown for a partial import", result.Findings[0].State)
		}
	})

	t.Run("binding key must match the observation key", func(t *testing.T) {
		imported := parseImport(t, validRow("CVE-2024-0001"))
		binding := a108ObservedBinding(t, "api")
		foreign := bindingFor(0, binding)
		foreign.ContainerKey = containerKey("other")
		if _, err := Normalize(Input{Import: imported, Bindings: []Binding{foreign}}); err == nil {
			t.Fatal("a mismatched binding key must be refused")
		}
	})

	t.Run("out of range and duplicated binding indices are refused", func(t *testing.T) {
		imported := parseImport(t, validRow("CVE-2024-0001"))
		binding := a108ObservedBinding(t, "api")
		outOfRange := bindingFor(1, binding)
		if _, err := Normalize(Input{Import: imported, Bindings: []Binding{outOfRange}}); err == nil {
			t.Fatal("an out of range binding must be refused")
		}
		duplicated := []Binding{bindingFor(0, binding), bindingFor(0, binding)}
		if _, err := Normalize(Input{Import: imported, Bindings: duplicated}); err == nil {
			t.Fatal("a duplicated binding must be refused")
		}
	})

	t.Run("unsupported coverage method is refused", func(t *testing.T) {
		imported := parseImport(t, validRow("CVE-2024-0001"))
		imported.Coverage.Method = contract.CoverageContainerObservation
		if _, err := Normalize(Input{Import: imported}); err == nil {
			t.Fatal("a foreign coverage method must be refused")
		}
	})

	t.Run("declared image components stay verbatim", func(t *testing.T) {
		imported := parseImport(t, validRow("CVE-2024-0001"))
		result, err := Normalize(Input{Import: imported})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		declared := result.Findings[0].DeclaredImage
		if declared.Registry != "reg.example" || declared.Repository != "app" || declared.Tag != "release" {
			t.Fatalf("declared image = %+v", declared)
		}
		if result.Findings[0].RequestedImage == nil || string(*result.Findings[0].RequestedImage) != "reg.example/app:release" {
			t.Fatalf("requested image = %v", result.Findings[0].RequestedImage)
		}
	})

	t.Run("unrepresentable declaration blocks the requested image but keeps the facts", func(t *testing.T) {
		// A leading dot in the tag makes the declaration non-representable under
		// the ADR-0009 grammar while the row itself stays schema-valid.
		row := syntheticRowFor("CVE-2024-0001", "reg.example", "app", ".bad-tag", "High", "text")
		imported := parseImport(t, row)
		if len(imported.Findings) != 1 {
			t.Fatalf("fixture: findings = %d, rejections = %d", len(imported.Findings), len(imported.Rejections))
		}
		result, err := Normalize(Input{Import: imported})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		finding := result.Findings[0]
		if finding.RequestedImage != nil {
			t.Fatalf("requested image = %v, want nil for an unrepresentable declaration", *finding.RequestedImage)
		}
		if finding.DeclaredImage.Registry != "reg.example" || finding.DeclaredImage.Repository != "app" || finding.DeclaredImage.Tag != ".bad-tag" {
			t.Fatalf("declared components must stay verbatim: %+v", finding.DeclaredImage)
		}
		if finding.Source.PackageName != "pkg-a" {
			t.Fatalf("source facts must survive: %+v", finding.Source)
		}
	})
}

// TestA108IncompleteImports covers B02: only accepted findings are normalized,
// duplicates are preserved per occurrence, and an incomplete import never
// produces an affirmative state.
func TestA108IncompleteImports(t *testing.T) {
	t.Run("rejected rows are counted, never promoted", func(t *testing.T) {
		imported := parseImport(t, validRow("CVE-2024-0001"), rejectedRow(), validRow("CVE-2024-0002"))
		result, err := Normalize(Input{Import: imported})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(result.Findings) != 2 {
			t.Fatalf("findings = %d, want 2", len(result.Findings))
		}
		if len(result.Diagnostics.Rejections) != 1 {
			t.Fatalf("rejections = %d, want 1", len(result.Diagnostics.Rejections))
		}
		if !reflect.DeepEqual(result.Diagnostics.Rejections[0], imported.Rejections[0]) {
			t.Fatal("diagnostics must preserve the rejection verbatim")
		}
	})

	t.Run("duplicates are preserved per occurrence", func(t *testing.T) {
		imported := parseImport(t, validRow("CVE-2024-0001"), validRow("CVE-2024-0001"))
		result, err := Normalize(Input{Import: imported})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(result.Findings) != 2 {
			t.Fatalf("findings = %d, want 2 occurrences", len(result.Findings))
		}
		if result.Findings[0].Source.Locator == result.Findings[1].Source.Locator {
			t.Fatal("duplicate occurrences must keep distinct locators")
		}
	})

	t.Run("structural error is preserved for provenance", func(t *testing.T) {
		failure := &ingest.FileError{Offset: 42, Reason: ingest.ReasonInvalidCSV}
		imported := parseImport(t, validRow("CVE-2024-0001"))
		imported.Completeness = contract.CompletenessPartial
		result, err := Normalize(Input{Import: imported, StructuralError: failure})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if result.Diagnostics.StructuralError == nil || *result.Diagnostics.StructuralError != *failure {
			t.Fatalf("structural error = %+v, want %+v", result.Diagnostics.StructuralError, failure)
		}
		if result.Diagnostics.StructuralError == failure {
			t.Fatal("the structural error must be detached from the caller")
		}
	})

	t.Run("aborted import is not complete and stays unknown", func(t *testing.T) {
		failure := &ingest.FileError{Offset: 10, Reason: ingest.ReasonInvalidCSV}
		imported := parseImport(t, validRow("CVE-2024-0001"))
		imported.Completeness = contract.CompletenessPartial
		binding := a108ObservedBinding(t, "api")
		result, err := Normalize(Input{
			Import:          imported,
			StructuralError: failure,
			Bindings:        []Binding{bindingFor(0, binding)},
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if result.Completeness != contract.CompletenessPartial {
			t.Fatalf("completeness = %q", result.Completeness)
		}
		if result.Findings[0].State == NormalizationBound {
			t.Fatal("an aborted import must never produce a bound state")
		}
	})

	t.Run("coverage totals are detached from the caller", func(t *testing.T) {
		imported := parseImport(t, validRow("CVE-2024-0001"))
		result, err := Normalize(Input{Import: imported})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if result.Coverage.Rows == nil || imported.Coverage.Rows == nil {
			t.Fatal("coverage rows must be present")
		}
		if result.Coverage.Rows == imported.Coverage.Rows {
			t.Fatal("coverage rows must be detached")
		}
		*imported.Coverage.Rows.Total = 999
		if *result.Coverage.Rows.Total == 999 {
			t.Fatal("a caller mutation reached the normalized result")
		}
	})

	t.Run("scope collisions are reported without merging classes", func(t *testing.T) {
		imported := parseImport(t, validRow("CVE-2024-0001"), validRow("CVE-2024-0002"))
		regular := a108ObservedBinding(t, "api")
		initBinding := a108ObservedBinding(t, "api")
		initBinding.Key.ContainerClass = contract.ContainerInit
		result, err := Normalize(Input{
			Import: imported,
			Bindings: []Binding{
				bindingFor(0, regular),
				bindingFor(1, initBinding),
			},
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		collisions := ScopeCollisions(result)
		if len(collisions) != 1 {
			t.Fatalf("collisions = %+v, want exactly one", collisions)
		}
		collision := collisions[0]
		if collision.SubjectUID != contract.UID("uid-0001") || collision.ContainerName != contract.ContainerName("api") {
			t.Fatalf("collision = %+v", collision)
		}
		if len(collision.Classes) != 2 ||
			collision.Classes[0] != contract.ContainerRegular || collision.Classes[1] != contract.ContainerInit {
			t.Fatalf("classes = %+v, want regular then init in first-appearance order", collision.Classes)
		}
	})
}
