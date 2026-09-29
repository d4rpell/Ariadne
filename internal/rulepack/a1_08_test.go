package rulepack

import (
	"strings"
	"testing"
	"time"

	contract "github.com/d4rpell/Ariadne/pkg/evidence"
)

// TestA108PackLimits covers the strict scanner, the closed schema and the pack
// limits with their ratified literal values and their reachable boundaries. The
// controls the scanner cannot isolate (requires budget, total checks) declare
// their dominance instead of fabricating an unreachable case (handoff §5.1).
func TestA108PackLimits(t *testing.T) {
	t.Run("ratified constants keep their literal values", func(t *testing.T) {
		checks := []struct {
			name string
			got  int64
			want int64
		}{
			{"MaxPackBytes", MaxPackBytes, 1_048_576},
			{"MaxJSONDepth", MaxJSONDepth, 8},
			{"MaxJSONTokens", MaxJSONTokens, 20_000},
			{"MaxStringBytes", MaxStringBytes, 256},
			{"MaxRules", MaxRules, 128},
			{"MaxRequires", MaxRequires, 32},
			{"MaxChecksPerRule", MaxChecksPerRule, 32},
			{"MaxChecksTotal", MaxChecksTotal, 4_096},
			{"MaxIDBytes", MaxIDBytes, 64},
			{"MaxVersion", MaxVersion, 1<<53 - 1},
		}
		for _, check := range checks {
			if check.got != check.want {
				t.Fatalf("%s = %d, want the ratified literal %d", check.name, check.got, check.want)
			}
		}
	})

	t.Run("pack byte boundary is inclusive and N+1 rejects", func(t *testing.T) {
		document := packDoc(baseRule())
		atLimit := document + strings.Repeat(" ", MaxPackBytes-len(document))
		if len(atLimit) != MaxPackBytes {
			t.Fatalf("padding produced %d bytes", len(atLimit))
		}
		// N is admitted: the only trailing tolerance of a strict scanner is
		// whitespace, so the limit itself does not reject.
		if _, err := Decode([]byte(atLimit)); err != nil {
			t.Fatalf("exactly MaxPackBytes must decode: %v", err)
		}
		over := atLimit + " "
		if len(over) != MaxPackBytes+1 {
			t.Fatalf("the over-limit document is %d bytes", len(over))
		}
		_, err := Decode([]byte(over))
		wantCode(t, err, CodeInputLimit)
	})

	t.Run("string byte boundary", func(t *testing.T) {
		atLimit := replaceOne(t, packDoc(baseRule()), `"check_id":"check.one"`, `"check_id":"`+strings.Repeat("c", MaxStringBytes)+`"`)
		// N decoded bytes reach the identifier grammar; the rejection is the
		// grammar, never the byte limit.
		_, err := Decode([]byte(atLimit))
		wantCode(t, err, CodeInvalidPack)

		overLimit := replaceOne(t, packDoc(baseRule()), `"check_id":"check.one"`, `"check_id":"`+strings.Repeat("c", MaxStringBytes+1)+`"`)
		_, err = Decode([]byte(overLimit))
		wantCode(t, err, CodeInputLimit)
	})

	t.Run("json depth boundary", func(t *testing.T) {
		// Depth 8 is admitted by the scanner; the schema then rejects the
		// document for unrelated reasons. Depth 9 is refused as input_limit.
		allowed := `{"rules":[` + strings.Repeat("[", 6) + strings.Repeat("]", 6) + `]}`
		_, err := Decode([]byte(allowed))
		wantCode(t, err, CodeInvalidPack)

		rejected := `{"rules":[` + strings.Repeat("[", 7) + strings.Repeat("]", 7) + `]}`
		_, err = Decode([]byte(rejected))
		wantCode(t, err, CodeInputLimit)
	})

	t.Run("rule count boundary", func(t *testing.T) {
		pack := mustDecode(t, packDoc(makeRuleList(MaxRules)))
		if len(pack.Rules) != MaxRules {
			t.Fatalf("rules = %d, want %d", len(pack.Rules), MaxRules)
		}
		// One more rule exceeds the token budget before the count rule is
		// reached; either way a document over the count is refused, never
		// silently truncated.
		_, err := Decode([]byte(packDoc(makeRuleList(MaxRules + 1))))
		if err == nil {
			t.Fatal("a document over the rule count must be refused")
		}
	})

	t.Run("checks per rule boundary", func(t *testing.T) {
		checks := ruleWith(checkList(MaxChecksPerRule), `"bundle.complete","finding.row","finding.fix_status"`)
		pack := mustDecode(t, packDoc(checks))
		if len(pack.Rules[0].Checks) != MaxChecksPerRule {
			t.Fatalf("checks = %d, want %d", len(pack.Rules[0].Checks), MaxChecksPerRule)
		}
		over := ruleWith(checkList(MaxChecksPerRule+1), `"bundle.complete","finding.row","finding.fix_status"`)
		_, err := Decode([]byte(packDoc(over)))
		if err == nil {
			t.Fatal("a rule over the check count must be refused")
		}
	})

	t.Run("declared dominance of the requires budget", func(t *testing.T) {
		// The vocabulary is closed and duplicates are refused, so the reachable
		// requirement count stays below MaxRequires: the budget is not
		// isolatable and this control declares why instead of lowering it.
		vocabulary := []Requirement{
			RequirementBundleComplete, RequirementFindingRow,
			RequirementImageBoundDigest, RequirementImageKnownPlatform,
			FindingRequirement(FieldVulnerabilityID), FindingRequirement(FieldPackageName),
			FindingRequirement(FieldInstalledVersion), FindingRequirement(FieldPackageType),
			FindingRequirement(FieldPackageID), FindingRequirement(FieldFixStatus),
		}
		if int64(len(vocabulary)) >= MaxRequires {
			t.Fatalf("the dominance argument no longer holds: %d members", len(vocabulary))
		}
	})

	t.Run("declared dominance of the total checks budget", func(t *testing.T) {
		if MaxRules*MaxChecksPerRule != MaxChecksTotal {
			t.Fatalf("the dominance argument no longer holds: %d", MaxRules*MaxChecksPerRule)
		}
	})

	t.Run("the token budget precedes the schema rules", func(t *testing.T) {
		// A document over the token budget is refused with input_limit before any
		// vocabulary rule, so the limit is the observed cause.
		overTokens := "[" + strings.Repeat(`"a",`, 9_999) + `"a"` + "]"
		_, err := Decode([]byte(overTokens))
		wantCode(t, err, CodeInputLimit)
	})
}

// TestA108PackValidity covers the validity window with its equality semantics:
// valid_from is inclusive, expires_at is exclusive, and the replay of one
// instant is reproducible.
func TestA108PackValidity(t *testing.T) {
	document := packDoc(baseRule())
	at := func(moment time.Time) AdmissionContext {
		context := validContext(document)
		stamp, err := contract.NewTimestamp(moment)
		if err != nil {
			t.Fatalf("timestamp construction failed: %v", err)
		}
		context.EvaluatedAt = stamp
		return context
	}

	t.Run("one second before valid_from", func(t *testing.T) {
		_, err := Admit([]byte(document), at(time.Date(2026, 8, 31, 23, 59, 59, 0, time.UTC)))
		wantCode(t, err, CodePackNotYetValid)
	})

	t.Run("exactly valid_from", func(t *testing.T) {
		if _, err := Admit([]byte(document), at(time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC))); err != nil {
			t.Fatalf("the first valid instant is inclusive: %v", err)
		}
	})

	t.Run("exactly expires_at expires", func(t *testing.T) {
		_, err := Admit([]byte(document), at(time.Date(2026, 12, 31, 23, 59, 59, 0, time.UTC)))
		wantCode(t, err, CodePackExpired)
	})

	t.Run("one second before expires_at is valid", func(t *testing.T) {
		if _, err := Admit([]byte(document), at(time.Date(2026, 12, 31, 23, 59, 58, 0, time.UTC))); err != nil {
			t.Fatalf("the last valid second must be admitted: %v", err)
		}
	})

	t.Run("replay of a fixed instant is reproducible", func(t *testing.T) {
		context := at(time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC))
		first, err := Admit([]byte(document), context)
		if err != nil {
			t.Fatalf("first admission: %v", err)
		}
		second, err := Admit([]byte(document), context)
		if err != nil {
			t.Fatalf("second admission: %v", err)
		}
		if first.Hash() != second.Hash() || first.Version() != second.Version() {
			t.Fatal("the same instant must admit identically")
		}
		if !first.Valid() {
			t.Fatal("the admitted pack must be valid")
		}
		if first.Pack().Profile != SupportedProfile {
			t.Fatalf("profile = %q, want %q", first.Pack().Profile, SupportedProfile)
		}
	})

	t.Run("an expiry outside the window fails closed", func(t *testing.T) {
		expired := replaceOne(t, document, `"expires_at":"2026-12-31T23:59:59Z"`, `"expires_at":"2026-08-31T23:59:59Z"`)
		context := validContext(expired)
		context.EvaluatedAt = at(time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)).EvaluatedAt
		_, err := Admit([]byte(expired), context)
		// A window whose expiry precedes its start is either refused as an invalid
		// document or as an expired pack: never admitted.
		if err == nil {
			t.Fatal("an impossible validity window must never be admitted")
		}
		if !Is(err, CodePackExpired) && !Is(err, CodeInvalidPack) {
			t.Fatalf("unexpected classification: %v", err)
		}
	})
}
