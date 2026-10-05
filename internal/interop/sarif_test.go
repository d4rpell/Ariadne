package interop

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/d4rpell/Ariadne/internal/evaluator"
	contract "github.com/d4rpell/Ariadne/pkg/evidence"
)

func parseRun(t *testing.T, document []byte) map[string]any {
	t.Helper()
	object := unmarshalObject(t, document)
	runs, ok := object["runs"].([]any)
	if !ok || len(runs) != 1 {
		t.Fatalf("runs = %v, want exactly one", object["runs"])
	}
	return runs[0].(map[string]any)
}

func TestSARIFResultsPerCandidate(t *testing.T) {
	bundle := goldenBundle()
	result := goldenResult(t, profileProduct, contract.ProductNotAffected, []evaluator.Candidate{
		candidate("rule-a", contract.ProductNotAffected),
		candidate("rule-b", contract.ProductNotAffected),
		candidate("rule-a", contract.ProductNotAffected),
	})
	document, err := SARIF(result, bundle)
	if err != nil {
		t.Fatalf("SARIF: %v", err)
	}
	runs := parseRun(t, document)
	results := runs["results"].([]any)
	if len(results) != 3 {
		t.Fatalf("results = %d, want one per candidate", len(results))
	}
	want := []string{"rule-a", "rule-b", "rule-a"}
	for index, ruleID := range want {
		if got := results[index].(map[string]any)["ruleId"]; got != ruleID {
			t.Fatalf("results[%d].ruleId = %v, want %s", index, got, ruleID)
		}
	}
	driver := runs["tool"].(map[string]any)["driver"].(map[string]any)
	rules := driver["rules"].([]any)
	if len(rules) != 2 {
		t.Fatalf("rules = %d, want the two distinct ids", len(rules))
	}
	if rules[0].(map[string]any)["id"] != "rule-a" || rules[1].(map[string]any)["id"] != "rule-b" {
		t.Fatalf("rules are not deduplicated in ASCII order: %v", rules)
	}
}

func TestSARIFRulesAsciiOrder(t *testing.T) {
	bundle := goldenBundle()
	// Candidates in an order that is not ASCII-sorted: the rules list must be.
	result := goldenResult(t, profileProduct, contract.ProductNotAffected, []evaluator.Candidate{
		candidate("rule-z", contract.ProductNotAffected),
		candidate("rule-a", contract.ProductNotAffected),
	})
	document, err := SARIF(result, bundle)
	if err != nil {
		t.Fatalf("SARIF: %v", err)
	}
	run := parseRun(t, document)
	driver := run["tool"].(map[string]any)["driver"].(map[string]any)
	rules := driver["rules"].([]any)
	if len(rules) != 2 {
		t.Fatalf("rules = %d, want two", len(rules))
	}
	if rules[0].(map[string]any)["id"] != "rule-a" || rules[1].(map[string]any)["id"] != "rule-z" {
		t.Fatalf("rules are not in ASCII order: %v", rules)
	}
	// The results keep the input order, unsorted.
	results := run["results"].([]any)
	if results[0].(map[string]any)["ruleId"] != "rule-z" || results[1].(map[string]any)["ruleId"] != "rule-a" {
		t.Fatalf("results must keep the candidate order: %v", results)
	}
}

func TestSARIFEmptyResultsValid(t *testing.T) {
	bundle := goldenBundle()
	result := goldenResult(t, profileReadiness, contract.ProductUnderInvestigation, nil)
	document, err := SARIF(result, bundle)
	if err != nil {
		t.Fatalf("SARIF: %v", err)
	}
	var object map[string]any
	if err := json.Unmarshal(document, &object); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	results := object["runs"].([]any)[0].(map[string]any)["results"]
	array, ok := results.([]any)
	if !ok {
		t.Fatalf("results is not a JSON array: %v", results)
	}
	if len(array) != 0 {
		t.Fatalf("results = %v, want an empty array", array)
	}
	if !strings.Contains(string(document), `"results":[]`) {
		t.Fatalf("results is not emitted as an empty array: %s", document)
	}
}

func TestSARIFLevelIsNote(t *testing.T) {
	bundle := goldenBundle()
	result := goldenResult(t, profileProduct, contract.ProductAffected, []evaluator.Candidate{candidate("rule-a", contract.ProductAffected)})
	document, err := SARIF(result, bundle)
	if err != nil {
		t.Fatalf("SARIF: %v", err)
	}
	runs := parseRun(t, document)
	for _, item := range runs["results"].([]any) {
		if item.(map[string]any)["level"] != "note" {
			t.Fatalf("result level = %v, want note", item.(map[string]any)["level"])
		}
	}
	driver := runs["tool"].(map[string]any)["driver"].(map[string]any)
	for _, item := range driver["rules"].([]any) {
		configuration := item.(map[string]any)["defaultConfiguration"].(map[string]any)
		if configuration["level"] != "note" {
			t.Fatalf("rule default level = %v, want note", configuration["level"])
		}
	}
}

func TestSARIFPropertiesNamespaced(t *testing.T) {
	bundle := goldenBundle()
	result := goldenResult(t, profileProduct, contract.ProductNotAffected, []evaluator.Candidate{candidate("rule-a", contract.ProductNotAffected)})
	document, err := SARIF(result, bundle)
	if err != nil {
		t.Fatalf("SARIF: %v", err)
	}
	runs := parseRun(t, document)
	item := runs["results"].([]any)[0].(map[string]any)
	properties, ok := item["properties"].(map[string]any)
	if !ok {
		t.Fatalf("result has no properties bag: %v", item)
	}
	bag, ok := properties["ariadne"].(map[string]any)
	if !ok {
		t.Fatalf("properties bag is not namespaced under ariadne: %v", properties)
	}
	for _, key := range []string{"product_status", "exploitability", "profile_version", "bundle_hash"} {
		if _, present := bag[key]; !present {
			t.Fatalf("ariadne bag misses %q: %v", key, bag)
		}
	}
	// The local state is never a top-level result property.
	for _, forbidden := range []string{"product_status", "exploitability", "bundle_hash"} {
		if _, present := item[forbidden]; present {
			t.Fatalf("result has a top-level local field %q: %v", forbidden, item)
		}
	}
}

func TestSARIFNoTimestampsOrLocations(t *testing.T) {
	bundle := goldenBundle()
	result := goldenResult(t, profileProduct, contract.ProductNotAffected, []evaluator.Candidate{candidate("rule-a", contract.ProductNotAffected)})
	document, err := SARIF(result, bundle)
	if err != nil {
		t.Fatalf("SARIF: %v", err)
	}
	for _, forbidden := range []string{"locations", "invocations", "timestamp", "startTimeUtc"} {
		if strings.Contains(string(document), forbidden) {
			t.Fatalf("SARIF leaks %q: %s", forbidden, document)
		}
	}
}
