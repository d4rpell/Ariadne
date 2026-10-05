package interop

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/d4rpell/Ariadne/internal/evaluator"
	contract "github.com/d4rpell/Ariadne/pkg/evidence"
)

func unmarshalObject(t *testing.T, data []byte) map[string]any {
	t.Helper()
	var object map[string]any
	if err := json.Unmarshal(data, &object); err != nil {
		t.Fatalf("unmarshal output: %v\n%s", err, data)
	}
	return object
}

func firstStatement(t *testing.T, object map[string]any) map[string]any {
	t.Helper()
	statements, ok := object["statements"].([]any)
	if !ok || len(statements) != 1 {
		t.Fatalf("statements = %v, want exactly one", object["statements"])
	}
	statement, ok := statements[0].(map[string]any)
	if !ok {
		t.Fatalf("statement is not an object: %v", statements[0])
	}
	return statement
}

func TestOpenVEXStatusMapping(t *testing.T) {
	bundle := goldenBundle()
	cases := []struct {
		profile string
		status  contract.ProductStatus
	}{
		{profileProduct, contract.ProductAffected},
		{profileProduct, contract.ProductNotAffected},
		{profileProduct, contract.ProductFixed},
		{profileReadiness, contract.ProductUnderInvestigation},
	}
	for _, testCase := range cases {
		t.Run(string(testCase.status), func(t *testing.T) {
			var candidates []evaluator.Candidate
			if testCase.status != contract.ProductUnderInvestigation {
				candidates = []evaluator.Candidate{candidate("rule-a", testCase.status)}
			}
			result := goldenResult(t, testCase.profile, testCase.status, candidates)
			document, err := OpenVEX(result, bundle, goldenIssuer(t))
			if err != nil {
				t.Fatalf("OpenVEX: %v", err)
			}
			statement := firstStatement(t, unmarshalObject(t, document))
			if got := statement["status"]; got != string(testCase.status) {
				t.Fatalf("status = %v, want %s", got, testCase.status)
			}
		})
	}
}

func TestOpenVEXConditionalFields(t *testing.T) {
	bundle := goldenBundle()
	render := func(t *testing.T, profile string, status contract.ProductStatus) map[string]any {
		t.Helper()
		var candidates []evaluator.Candidate
		if status != contract.ProductUnderInvestigation {
			candidates = []evaluator.Candidate{candidate("rule-a", status)}
		}
		result := goldenResult(t, profile, status, candidates)
		document, err := OpenVEX(result, bundle, goldenIssuer(t))
		if err != nil {
			t.Fatalf("OpenVEX: %v", err)
		}
		return firstStatement(t, unmarshalObject(t, document))
	}

	notAffected := render(t, profileProduct, contract.ProductNotAffected)
	if _, present := notAffected["impact_statement"]; !present {
		t.Fatal("not_affected must carry an impact_statement")
	}
	if _, present := notAffected["action_statement"]; present {
		t.Fatal("not_affected must not carry an action_statement")
	}
	if _, present := notAffected["justification"]; present {
		t.Fatal("justification must never be emitted")
	}

	affected := render(t, profileProduct, contract.ProductAffected)
	if _, present := affected["action_statement"]; !present {
		t.Fatal("affected must carry an action_statement")
	}
	if _, present := affected["impact_statement"]; present {
		t.Fatal("affected must not carry an impact_statement")
	}
	if _, present := affected["justification"]; present {
		t.Fatal("justification must never be emitted")
	}

	for _, status := range []contract.ProductStatus{contract.ProductFixed, contract.ProductUnderInvestigation} {
		profile := profileProduct
		if status == contract.ProductUnderInvestigation {
			profile = profileReadiness
		}
		statement := render(t, profile, status)
		for _, key := range []string{"impact_statement", "action_statement", "justification"} {
			if _, present := statement[key]; present {
				t.Fatalf("%s must carry no %s", status, key)
			}
		}
	}
}

func TestOpenVEXProductIDStability(t *testing.T) {
	bundle := goldenBundle()
	identifier := func(t *testing.T, mutate func(target *evaluator.Target)) string {
		t.Helper()
		result := goldenResult(t, profileProduct, contract.ProductNotAffected, []evaluator.Candidate{candidate("rule-a", contract.ProductNotAffected)})
		mutate(&result.Target)
		document, err := OpenVEX(result, bundle, goldenIssuer(t))
		if err != nil {
			t.Fatalf("OpenVEX: %v", err)
		}
		products := firstStatement(t, unmarshalObject(t, document))["products"].([]any)
		return products[0].(map[string]any)["@id"].(string)
	}

	base := identifier(t, func(*evaluator.Target) {})
	if again := identifier(t, func(*evaluator.Target) {}); again != base {
		t.Fatalf("product id is not stable: %s vs %s", base, again)
	}
	if !strings.HasPrefix(base, "urn:ariadne:subject:sha256:") {
		t.Fatalf("product id is not the local opaque URN: %s", base)
	}
	variants := map[string]func(*evaluator.Target){
		"uid":   func(target *evaluator.Target) { target.SubjectUID = "uid-9999" },
		"class": func(target *evaluator.Target) { target.ContainerClass = contract.ContainerInit },
		"name":  func(target *evaluator.Target) { target.ContainerName = "sidecar" },
	}
	for label, mutate := range variants {
		if changed := identifier(t, mutate); changed == base {
			t.Fatalf("product id ignores the %s", label)
		}
	}
}

func TestOpenVEXOmitsLocalExtensions(t *testing.T) {
	bundle := goldenBundle()
	result := goldenResult(t, profileProduct, contract.ProductNotAffected, []evaluator.Candidate{candidate("rule-a", contract.ProductNotAffected)})
	document, err := OpenVEX(result, bundle, goldenIssuer(t))
	if err != nil {
		t.Fatalf("OpenVEX: %v", err)
	}
	for _, forbidden := range []string{"exploitability", "risk_decision", "bundle_hash", "candidates", "\"rules\"", "pack_hash"} {
		if strings.Contains(string(document), forbidden) {
			t.Fatalf("OpenVEX document leaks local extension %q: %s", forbidden, document)
		}
	}
}

func TestOpenVEXDocumentFields(t *testing.T) {
	bundle := goldenBundle()
	result := goldenResult(t, profileProduct, contract.ProductNotAffected, []evaluator.Candidate{candidate("rule-a", contract.ProductNotAffected)})
	document, err := OpenVEX(result, bundle, goldenIssuer(t))
	if err != nil {
		t.Fatalf("OpenVEX: %v", err)
	}
	object := unmarshalObject(t, document)
	if object["@context"] != "https://openvex.dev/ns/v0.2.0" {
		t.Fatalf("@context = %v", object["@context"])
	}
	if object["@id"] != "https://example.test/vex/2026-0001" {
		t.Fatalf("@id = %v", object["@id"])
	}
	if object["author"] != "Example Security Team" {
		t.Fatalf("author = %v", object["author"])
	}
	if object["timestamp"] != "2026-01-02T03:04:05Z" {
		t.Fatalf("timestamp = %v", object["timestamp"])
	}
	if object["version"] != float64(1) {
		t.Fatalf("version = %v", object["version"])
	}
	if object["tooling"] != "ariadne/"+evaluator.EngineVersion {
		t.Fatalf("tooling = %v", object["tooling"])
	}
}

func TestEscapeHTML(t *testing.T) {
	bundle := goldenBundle()
	result := goldenResult(t, profileProduct, contract.ProductNotAffected, []evaluator.Candidate{candidate("rule-a", contract.ProductNotAffected)})
	result.Target.VulnerabilityID = "CVE-<x>&y"
	document, err := OpenVEX(result, bundle, goldenIssuer(t))
	if err != nil {
		t.Fatalf("OpenVEX: %v", err)
	}
	if strings.Contains(string(document), "<x>") || strings.Contains(string(document), "&y") {
		t.Fatalf("output is not HTML-escaped: %s", document)
	}
	if !strings.Contains(string(document), `\u003c`) || !strings.Contains(string(document), `\u0026`) {
		t.Fatalf("output does not escape < and &: %s", document)
	}
}
