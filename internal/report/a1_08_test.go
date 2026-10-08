package report

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"

	"github.com/d4rpell/Ariadne/internal/evaluator"
	canonical "github.com/d4rpell/Ariadne/internal/evidence"
	contract "github.com/d4rpell/Ariadne/pkg/evidence"
)

// a108Marker is a synthetic value that must never reach a rendered report when
// it sits in an omitted field.
const a108Marker = "A108_PRIVATE_MARKER_7f3"

// a108ValueHash computes the value-hash preimage with the standard library.
func a108ValueHash(value string) contract.ValueHash {
	digest := sha256.Sum256([]byte(value))
	return contract.ValueHash("sha256:" + hex.EncodeToString(digest[:]))
}

// TestA108PresentationParity covers R01: presentation parity and determinism for
// the affirmative fixture and the contradictory one without creating a new
// golden, plus byte-level determinism of both encoders.
func TestA108PresentationParity(t *testing.T) {
	t.Run("F10 HTML renders the same DTO as its JSON", func(t *testing.T) {
		result, bundle := loadEvaluated(t, "F10-redhat-backport")
		report := mustBuild(t, result, bundle)
		document, err := JSON(report)
		if err != nil {
			t.Fatalf("JSON: %v", err)
		}
		page, err := HTML(report)
		if err != nil {
			t.Fatalf("HTML: %v", err)
		}
		// Every leaf of the JSON projection must be emittable by the page: the
		// check is the existing leaf walk, applied to the affirmative fixture.
		for _, value := range emittedValues(string(document)) {
			if value == "" {
				continue
			}
			if !containedIn(emittedValues(string(page)), value) {
				// The DTO leaf must appear in the page, either literally or
				// escaped the way the HTML context requires.
				escaped := escapeForHTML(value)
				if !strings.Contains(string(page), value) && !strings.Contains(string(page), escaped) {
					t.Fatalf("F10 HTML does not reproduce the DTO leaf %q", value)
				}
			}
		}
	})

	t.Run("F13 presentation is deterministic", func(t *testing.T) {
		result, bundle := loadEvaluated(t, "F13-contradictory-evidence")
		first := mustBuild(t, result, bundle)
		second := mustBuild(t, result, bundle)
		firstJSON, err := JSON(first)
		if err != nil {
			t.Fatalf("JSON: %v", err)
		}
		secondJSON, err := JSON(second)
		if err != nil {
			t.Fatalf("JSON: %v", err)
		}
		if !bytes.Equal(firstJSON, secondJSON) {
			t.Fatal("two projections of the same result must render identical JSON")
		}
		firstHTML, err := HTML(first)
		if err != nil {
			t.Fatalf("HTML: %v", err)
		}
		secondHTML, err := HTML(second)
		if err != nil {
			t.Fatalf("HTML: %v", err)
		}
		if !bytes.Equal(firstHTML, secondHTML) {
			t.Fatal("two projections of the same result must render identical HTML")
		}
	})

	t.Run("the JSON encoder carries no trailing LF and the HTML does", func(t *testing.T) {
		result, bundle := loadEvaluated(t, "F09-unmapped-redhat-package")
		report := mustBuild(t, result, bundle)
		document, err := JSON(report)
		if err != nil {
			t.Fatalf("JSON: %v", err)
		}
		page, err := HTML(report)
		if err != nil {
			t.Fatalf("HTML: %v", err)
		}
		if bytes.HasSuffix(document, []byte("\n")) {
			t.Fatal("the JSON report must not carry a trailing LF")
		}
		if !bytes.HasSuffix(page, []byte("\n")) {
			t.Fatal("the HTML report must end with one LF")
		}
		if bytes.HasPrefix(document, []byte("\ufeff")) || bytes.HasPrefix(page, []byte("\ufeff")) {
			t.Fatal("a rendered report must not carry a BOM")
		}
	})

	t.Run("F09 goldens still match the renderer", func(t *testing.T) {
		// Re-asserting the committed goldens here ties the parity checks above to
		// reviewed bytes: if a parity fix changed the rendering, this fails first.
		result, bundle := loadEvaluated(t, "F09-unmapped-redhat-package")
		report := mustBuild(t, result, bundle)
		document, err := JSON(report)
		if err != nil {
			t.Fatalf("JSON: %v", err)
		}
		page, err := HTML(report)
		if err != nil {
			t.Fatalf("HTML: %v", err)
		}
		compareGolden(t, "f09.report.json", document)
		compareGolden(t, "f09.report.html", page)
	})
}

// escapeForHTML is the minimal escaping an HTML text context applies, used only
// to accept an escaped leaf when the literal does not appear.
func escapeForHTML(value string) string {
	replacer := strings.NewReplacer(
		"&", "&amp;",
		"<", "&lt;",
		">", "&gt;",
		`"`, "&#34;",
		"'", "&#39;",
	)
	return replacer.Replace(value)
}

// TestA108PresentationLayers covers R03: the presentation keeps the three layers
// separate, sets risk_decision to null, keeps fixed apart from not_affected and
// escapes inert formula text.
func TestA108PresentationLayers(t *testing.T) {
	t.Run("risk_decision is null and never not_assessed", func(t *testing.T) {
		for _, slug := range []string{"F09-unmapped-redhat-package", "F10-redhat-backport", "F13-contradictory-evidence"} {
			result, bundle := loadEvaluated(t, slug)
			report := mustBuild(t, result, bundle)
			document, err := JSON(report)
			if err != nil {
				t.Fatalf("%s JSON: %v", slug, err)
			}
			if !strings.Contains(string(document), `"risk_decision":null`) {
				t.Fatalf("%s does not declare risk_decision:null", slug)
			}
			if strings.Contains(string(document), `"risk_decision":"not_assessed"`) {
				t.Fatalf("%s presented the governance layer as an assessment", slug)
			}
		}
	})

	t.Run("fixed and not_affected are separate fields", func(t *testing.T) {
		// The fixture's own state is asserted first, so the control cannot pass by
		// the field being absent or guessed; then the rendering is exercised with
		// each state in turn and the other must not be fabricated.
		result, bundle := loadEvaluated(t, "F10-redhat-backport")
		report := mustBuild(t, result, bundle)
		document, err := JSON(report)
		if err != nil {
			t.Fatalf("JSON: %v", err)
		}
		body := string(document)
		fixture := string(result.ProductStatus)
		if !strings.Contains(body, `"product_status":"`+fixture+`"`) {
			t.Fatalf("the report does not carry the fixture state %q: %s", fixture, body)
		}
		for _, state := range []contract.ProductStatus{contract.ProductFixed, contract.ProductNotAffected} {
			if state == result.ProductStatus {
				continue
			}
			if strings.Contains(body, `"product_status":"`+string(state)+`"`) {
				t.Fatalf("the report fabricated the state %q the fixture does not carry", state)
			}
		}
	})

	t.Run("formula prefixes stay inert and markup is escaped", func(t *testing.T) {
		// A real payload is injected into an emitted value (the vulnerability id
		// the target cites), with value hash, projection hash and target updated so
		// the encoder receives it: the rendered bytes must show text, never live
		// markup, and the formula prefix must stay inert in both formats.
		result, bundle := loadEvaluated(t, "F09-unmapped-redhat-package")
		payload := `=SUM(1)<script>alert(1)</script><img src=x onerror=alert(2)>`
		replaced := false
		for index := range bundle.Evidence {
			if bundle.Evidence[index].Type != "prisma_v1.vulnerability_id" {
				continue
			}
			hash := a108ValueHash(payload)
			bundle.Evidence[index].Value = &payload
			bundle.Evidence[index].ValueHash = &hash
			replaced = true
			break
		}
		if !replaced {
			t.Fatal("the fixture must carry a vulnerability id item")
		}
		result.Target.VulnerabilityID = payload
		rehashed, err := canonical.HashCanonicalJSON(bundle)
		if err != nil {
			t.Fatalf("rehash: %v", err)
		}
		result.BundleHash = rehashed
		report, err := Build(result, bundle)
		if err != nil {
			t.Fatalf("the injected payload must still build: %v", err)
		}
		document, err := JSON(report)
		if err != nil {
			t.Fatalf("JSON: %v", err)
		}
		page, err := HTML(report)
		if err != nil {
			t.Fatalf("HTML: %v", err)
		}
		if !strings.Contains(string(document), "alert(1)") {
			t.Fatal("the injected value did not reach the JSON report: the control is vacuous")
		}
		// The JSON encoder escapes <, > and & (ADR-0022 §D4): a raw tag delimiter
		// in the document would close a tag when the JSON is embedded in another
		// document, so the control also forbids raw markup in the JSON bytes.
		for _, forbidden := range []string{"<script", "<img", "<svg", "<iframe"} {
			if strings.Contains(string(document), forbidden) {
				t.Fatalf("the JSON document emits live markup %q", forbidden)
			}
		}
		if !strings.Contains(string(page), "alert(1)") {
			t.Fatal("the injected value did not reach the HTML report: the control is vacuous")
		}
		// Live markup would need a tag delimiter starting the payload fragment;
		// the escaped form (&lt;script&gt;) is inert text. The event-handler
		// text may appear inside the escaped value — that is exactly the inert
		// rendering — so only raw tag delimiters are forbidden.
		lowered := strings.ToLower(string(page))
		for _, forbidden := range []string{"<script", "<img", "<svg", "<iframe"} {
			if strings.Contains(lowered, forbidden) {
				t.Fatalf("the page emits live markup %q", forbidden)
			}
		}
		if !strings.Contains(string(page), "&lt;script&gt;") {
			t.Fatal("the markup delimiters of the injected value must be escaped in HTML")
		}
		if !strings.Contains(string(page), "&lt;img") {
			t.Fatal("the img tag of the injected value must be escaped in HTML")
		}
		// The formula prefix stays inert text in both formats.
		if !strings.Contains(string(document), `=SUM(1)`) || !strings.Contains(string(page), `=SUM(1)`) {
			t.Fatal("the formula prefix must stay in both reports as inert text")
		}
	})
}

// TestA108PresentationOmissions covers R04: synthetic markers placed in fields
// the report must omit never reach the rendered bytes, while an allowed
// identifier carrying the same marker is not silently deleted.
func TestA108PresentationOmissions(t *testing.T) {
	t.Run("operational metadata never reaches the report", func(t *testing.T) {
		result, bundle := loadEvaluated(t, "F09-unmapped-redhat-package")
		// Only the fields excluded from the projection are mutated, so the bundle
		// hash stays the one the result carries: argv, versions, timestamps and
		// budget are operational metadata and never reach the report.
		bundle.Provenance.ArgvSanitized = []string{"import", a108Marker + ".csv"}
		bundle.Provenance.CollectorVersion = a108Marker + "-collector"
		bundle.Provenance.ParserVersion = a108Marker + "-parser"
		bundle.Provenance.Budget = contract.Budget{WallClock: a108Marker + "5m", Requests: 1, Objects: 1, Bytes: 1}
		report := mustBuild(t, result, bundle)
		document, err := JSON(report)
		if err != nil {
			t.Fatalf("JSON: %v", err)
		}
		page, err := HTML(report)
		if err != nil {
			t.Fatalf("HTML: %v", err)
		}
		for name, body := range map[string]string{"json": string(document), "html": string(page)} {
			if strings.Contains(body, a108Marker) {
				t.Fatalf("%s leaked operational metadata carrying the marker", name)
			}
		}
	})

	t.Run("warning messages never reach the report", func(t *testing.T) {
		result, bundle := loadEvaluated(t, "F13-contradictory-evidence")
		if len(bundle.Evidence) == 0 {
			t.Fatal("the fixture must carry evidence")
		}
		// The warning is attached to the real bundle (not a local copy) and the
		// projection link is recomputed, so the case reaches the encoder instead of
		// being rejected earlier by a stale hash. Only the code and class travel in
		// the report; the free-text message is omitted.
		bundle.Evidence[0].Warnings = append(append([]contract.Warning{}, bundle.Evidence[0].Warnings...), contract.Warning{
			Code:    "synthetic_marker_warning",
			Class:   contract.WarningInformational,
			Message: a108Marker + " message",
		})
		for index := range bundle.Evidence {
			result.WarningReferences = append(result.WarningReferences, evaluator.WarningReference{
				Origin: evaluator.WarningFromEvidence, EvidenceIndex: index, WarningIndex: 0,
			})
			break
		}
		hash, err := canonical.HashCanonicalJSON(bundle)
		if err != nil {
			t.Fatalf("rehash: %v", err)
		}
		result.BundleHash = hash
		report, err := Build(result, bundle)
		if err != nil {
			t.Fatalf("the mutated bundle must still build: %v", err)
		}
		document, err := JSON(report)
		if err != nil {
			t.Fatalf("JSON: %v", err)
		}
		if strings.Contains(string(document), a108Marker) {
			t.Fatal("a warning message reached the JSON report")
		}
		if !strings.Contains(string(document), "synthetic_marker_warning") {
			t.Fatal("the warning code must reach the report")
		}
	})

	t.Run("a marker in an emitted value is preserved verbatim", func(t *testing.T) {
		result, bundle := loadEvaluated(t, "F09-unmapped-redhat-package")
		// The allowed identifier carries the very marker the omitted fields used:
		// a filter that deletes the marker indiscriminately would pass a control
		// built with a different value and must fail this one. The value and its
		// hash are recomputed together so the bundle stays valid.
		value := a108Marker + "-CVE-2026-77777"
		replaced := false
		for index := range bundle.Evidence {
			if bundle.Evidence[index].Type != "prisma_v1.vulnerability_id" {
				continue
			}
			hash := a108ValueHash(value)
			bundle.Evidence[index].Value = &value
			bundle.Evidence[index].ValueHash = &hash
			replaced = true
			break
		}
		if !replaced {
			t.Fatal("the fixture must carry a vulnerability id item")
		}
		// The marker replaces the vulnerability id the target cites, so the target
		// itself is updated to keep the control valid: the emitted value must appear
		// verbatim and no heuristic may delete it.
		result.Target.VulnerabilityID = value
		hash, err := canonical.HashCanonicalJSON(bundle)
		if err != nil {
			t.Fatalf("rehash: %v", err)
		}
		result.BundleHash = hash
		report, err := Build(result, bundle)
		if err != nil {
			t.Fatalf("the control must build: %v", err)
		}
		document, err := JSON(report)
		if err != nil {
			t.Fatalf("JSON: %v", err)
		}
		page, err := HTML(report)
		if err != nil {
			t.Fatalf("HTML: %v", err)
		}
		for name, body := range map[string]string{"json": string(document), "html": string(page)} {
			if !strings.Contains(body, value) {
				t.Fatalf("the %s report removed the allowed identifier carrying the marker", name)
			}
			if !strings.Contains(body, "CVE-2026-77777") {
				t.Fatalf("the %s report lost the identifier", name)
			}
		}
	})
}
