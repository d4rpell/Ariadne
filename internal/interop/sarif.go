package interop

import (
	"sort"

	"github.com/d4rpell/Ariadne/internal/evaluator"
	contract "github.com/d4rpell/Ariadne/pkg/evidence"
)

const (
	sarifVersion    = "2.1.0"
	sarifSchema     = "https://json.schemastore.org/sarif-2.1.0.json"
	sarifDriverName = "Ariadne"
	sarifLevelNote  = "note"
)

// SARIF returns the compact SARIF v2.1.0 log of one validated result: a single
// run, one descriptor per distinct candidate rule in ASCII order, and one result
// per candidate in the order the result carries them. The severity is never
// asserted: level is the constant note and the local state travels in the
// namespaced property bag. It emits no location and no timestamp.
func SARIF(result evaluator.Result, bundle contract.Bundle) ([]byte, error) {
	if err := admissible(result, bundle); err != nil {
		return nil, err
	}
	results := make([]sarifResult, 0, len(result.Candidates))
	for _, candidate := range result.Candidates {
		results = append(results, sarifResult{
			RuleID:  candidate.RuleID,
			Level:   sarifLevelNote,
			Message: sarifMessageString{Text: sarifMessage(result, candidate)},
			Properties: sarifProperties{Ariadne: sarifAriadne{
				ProductStatus:  string(candidate.ProductStatus),
				Exploitability: string(result.Exploitability),
				ProfileVersion: result.ProfileVersion,
				BundleHash:     result.BundleHash,
			}},
		})
	}
	document := sarifLog{
		Version: sarifVersion,
		Schema:  sarifSchema,
		Runs: []sarifRun{{
			Tool: sarifTool{Driver: sarifDriver{
				Name:    sarifDriverName,
				Version: result.EngineVersion,
				Rules:   sarifRules(result),
			}},
			Results: results,
		}},
	}
	return encode(document)
}

// sarifRules lists one reporting descriptor per distinct candidate rule id, in
// ASCII order. Deduplication applies to rules only; results keep one element per
// candidate, including candidates that share a rule id.
func sarifRules(result evaluator.Result) []sarifRule {
	seen := make(map[string]struct{}, len(result.Candidates))
	ids := make([]string, 0, len(result.Candidates))
	for _, candidate := range result.Candidates {
		if _, repeated := seen[candidate.RuleID]; repeated {
			continue
		}
		seen[candidate.RuleID] = struct{}{}
		ids = append(ids, candidate.RuleID)
	}
	sort.Strings(ids)
	rules := make([]sarifRule, 0, len(ids))
	for _, id := range ids {
		rules = append(rules, sarifRule{
			ID:                   id,
			ShortDescription:     sarifMessageString{Text: id},
			DefaultConfiguration: sarifConfiguration{Level: sarifLevelNote},
		})
	}
	return rules
}

// sarifMessage is a deterministic text that names the candidate status and the
// vulnerability. It carries no evidence value.
func sarifMessage(result evaluator.Result, candidate evaluator.Candidate) string {
	return "Ariadne: " + string(candidate.ProductStatus) + " for " + result.Target.VulnerabilityID
}
