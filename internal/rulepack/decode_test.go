package rulepack

import (
	"strconv"
	"strings"
	"testing"
)

// Fixtures of this file are synthetic documents assembled from string literals
// on purpose: the tests must not share a marshaller with production decoding.
// Documents that carry JSON escapes are written as raw strings, because Go
// rejects surrogate and control escapes in interpreted literals.

func baseRule() string {
	return ruleWith(`{"check_id":"check.one","predicate":"finding_field_present","params":{"field":"fix_status"}}`,
		`"bundle.complete","finding.row","finding.fix_status"`)
}

func ruleWith(checkJSON, requiresJSON string) string {
	return `{"rule_id":"rule.one",` +
		`"selector":{"coverage_method":"findings_import","vulnerability_id":"CVE-2026-12345"},` +
		`"requires":[` + requiresJSON + `],` +
		`"checks":[` + checkJSON + `],` +
		`"on_missing_evidence":"under_investigation","emit":"under_investigation"}`
}

func equalsCheck(valueJSON string) string {
	return `{"check_id":"check.one","predicate":"finding_field_equals","params":{"field":"package_name","value":"` +
		valueJSON + `"}}`
}

func packDoc(rules string) string {
	return packDocVersion(7, rules)
}

func packDocVersion(version int64, rules string) string {
	return `{"schema_version":"0.1","profile":"evidence-readiness-v1","pack_id":"pack.one","version":` +
		strconv.FormatInt(version, 10) +
		`,"valid_from":"2026-09-01T00:00:00Z","expires_at":"2026-12-31T23:59:59Z","rules":[` + rules + `]}`
}

func mustDecode(t *testing.T, document string) Pack {
	t.Helper()
	pack, err := Decode([]byte(document))
	if err != nil {
		t.Fatalf("Decode of the control document failed: %v", err)
	}
	return pack
}

func wantCode(t *testing.T, err error, code ErrorCode) {
	t.Helper()
	if err == nil {
		t.Fatalf("expected %s, got no error", code)
	}
	if !Is(err, code) {
		t.Fatalf("expected %s, got %v", code, err)
	}
}

// replaceOne swaps the first occurrence of before for after, failing the test if
// the fixture no longer contains it: a silently ineffective fixture would make
// the case vacuous.
func replaceOne(t *testing.T, document, before, after string) string {
	t.Helper()
	if !strings.Contains(document, before) {
		t.Fatalf("fixture does not contain %q", before)
	}
	return strings.Replace(document, before, after, 1)
}

// TestPackClosedVocabulary is I-01: a pack cannot introduce executable language,
// unknown vocabulary or an output other than under_investigation, and the four
// declared predicates are admitted with their exact parameter shape.
func TestPackClosedVocabulary(t *testing.T) {
	mustDecode(t, packDoc(baseRule()))

	check := `{"check_id":"check.one","predicate":"finding_field_present","params":{"field":"fix_status"}}`
	cases := []struct {
		name     string
		document string
		code     ErrorCode
	}{
		{"unknown predicate", replaceOne(t, packDoc(baseRule()), `"predicate":"finding_field_present"`, `"predicate":"always_true"`), CodeUnsupportedPack},
		{"executable predicate", replaceOne(t, packDoc(baseRule()), `"predicate":"finding_field_present"`, `"predicate":"exec"`), CodeUnsupportedPack},
		{"unknown requirement", replaceOne(t, packDoc(baseRule()), `"finding.fix_status"`, `"finding.severity"`), CodeUnsupportedPack},
		{"unknown emit", replaceOne(t, packDoc(baseRule()), `"emit":"under_investigation"`, `"emit":"not_affected"`), CodeUnsupportedPack},
		{"unknown missing-evidence outcome", replaceOne(t, packDoc(baseRule()), `"on_missing_evidence":"under_investigation"`, `"on_missing_evidence":"not_affected"`), CodeUnsupportedPack},
		{"unknown field", replaceOne(t, packDoc(baseRule()), `"params":{"field":"fix_status"}`, `"params":{"field":"path"}`), CodeUnsupportedPack},
		{"unknown schema", replaceOne(t, packDoc(baseRule()), `"schema_version":"0.1"`, `"schema_version":"0.2"`), CodeUnsupportedPack},
		{"unknown profile", replaceOne(t, packDoc(baseRule()), `"profile":"evidence-readiness-v1"`, `"profile":"assertive-v1"`), CodeUnsupportedPack},
		{"param outside the predicate shape", replaceOne(t, packDoc(baseRule()), `"params":{"field":"fix_status"}`, `"params":{"field":"fix_status","value":"fixed"}`), CodeInvalidPack},
		{"digest predicate with parameters", packDoc(ruleWith(replaceOne(t, check, `"predicate":"finding_field_present"`, `"predicate":"image_digest_bound"`), `"bundle.complete","finding.row","image.bound_digest"`)), CodeInvalidPack},
		{"platform predicate without architecture", packDoc(ruleWith(replaceOne(t, check, `"predicate":"finding_field_present","params":{"field":"fix_status"}`, `"predicate":"image_platform_known","params":{"os":"linux"}`), `"bundle.complete","finding.row","image.bound_digest","image.known_platform"`)), CodeInvalidPack},
		{"missing row requirement", packDoc(ruleWith(check, `"bundle.complete","finding.fix_status"`)), CodeInvalidPack},
		{"duplicated requirement", packDoc(ruleWith(check, `"bundle.complete","finding.row","finding.fix_status","finding.fix_status"`)), CodeInvalidPack},
		{"mandatory predicate requirement omitted", packDoc(ruleWith(check, `"bundle.complete","finding.row"`)), CodeInvalidPack},
		{"injected extension field", replaceOne(t, packDoc(baseRule()), `"emit":"under_investigation"`, `"emit":"under_investigation","command":"sh -c true"`), CodeInvalidPack},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			_, err := Decode([]byte(testCase.document))
			wantCode(t, err, testCase.code)
		})
	}

	admitted := []struct {
		name     string
		check    string
		requires string
	}{
		{"finding_field_present", check, `"bundle.complete","finding.row","finding.fix_status"`},
		{"finding_field_equals", `{"check_id":"check.one","predicate":"finding_field_equals","params":{"field":"vulnerability_id","value":"CVE-2026-12345"}}`, `"bundle.complete","finding.row","finding.vulnerability_id"`},
		{"image_digest_bound", `{"check_id":"check.one","predicate":"image_digest_bound","params":{}}`, `"bundle.complete","finding.row","image.bound_digest"`},
		{"image_platform_known", `{"check_id":"check.one","predicate":"image_platform_known","params":{"os":"linux","architecture":"amd64"}}`, `"bundle.complete","finding.row","image.bound_digest","image.known_platform"`},
	}
	for _, testCase := range admitted {
		t.Run("admitted "+testCase.name, func(t *testing.T) {
			pack := mustDecode(t, packDoc(ruleWith(testCase.check, testCase.requires)))
			if len(pack.Rules) != 1 || len(pack.Rules[0].Checks) != 1 {
				t.Fatalf("control pack did not decode to one rule with one check")
			}
			if pack.Rules[0].Emit != OutputUnderInvestigation || pack.Rules[0].OnMissingEvidence != OutputUnderInvestigation {
				t.Fatalf("output contract changed in the decoded pack")
			}
		})
	}
}

// TestPackStrictJSON is I-02: duplicate keys after decoding, case variants,
// unknown members, null, non-canonical numbers, unpaired surrogates, BOM,
// trailing content, comments and inadmissible text are rejected without
// coercion.
func TestPackStrictJSON(t *testing.T) {
	cases := []struct {
		name     string
		document string
		code     ErrorCode
	}{
		{"duplicate key", replaceOne(t, packDoc(baseRule()), `"pack_id":"pack.one"`, `"pack_id":"pack.one","pack_id":"pack.one"`), CodeInvalidPack},
		{"duplicate key via escape", replaceOne(t, packDoc(baseRule()), `"pack_id":"pack.one"`, `"pack_id":"pack.one","pack_\u0069d":"pack.two"`), CodeInvalidPack},
		{"case variant key", replaceOne(t, packDoc(baseRule()), `"pack_id"`, `"Pack_id"`), CodeInvalidPack},
		{"unknown top-level key", replaceOne(t, packDoc(baseRule()), `"pack_id":"pack.one"`, `"pack_id":"pack.one","owner":"someone"`), CodeInvalidPack},
		{"unknown rule key", replaceOne(t, packDoc(baseRule()), `"rule_id":"rule.one"`, `"rule_id":"rule.one","priority":1`), CodeInvalidPack},
		{"unknown params key", replaceOne(t, packDoc(baseRule()), `"params":{"field":"fix_status"}`, `"params":{"field":"fix_status","command":"true"}`), CodeInvalidPack},
		{"null for a declared string", replaceOne(t, packDoc(baseRule()), `"pack_id":"pack.one"`, `"pack_id":null`), CodeInvalidPack},
		{"exponent number", replaceOne(t, packDoc(baseRule()), `"version":7`, `"version":7e0`), CodeInvalidPack},
		{"fractional number", replaceOne(t, packDoc(baseRule()), `"version":7`, `"version":7.0`), CodeInvalidPack},
		{"leading zero version", replaceOne(t, packDoc(baseRule()), `"version":7`, `"version":07`), CodeInvalidPack},
		{"negative version", replaceOne(t, packDoc(baseRule()), `"version":7`, `"version":-7`), CodeInvalidPack},
		{"unpaired high surrogate", packDoc(ruleWith(equalsCheck(`pkg\uD800`), `"bundle.complete","finding.row","finding.package_name"`)), CodeInvalidPack},
		{"lone low surrogate", packDoc(ruleWith(equalsCheck(`pkg\uDC00`), `"bundle.complete","finding.row","finding.package_name"`)), CodeInvalidPack},
		{"high surrogate before a non-escape", packDoc(ruleWith(equalsCheck(`pkg\uD800x`), `"bundle.complete","finding.row","finding.package_name"`)), CodeInvalidPack},
		{"BOM", "\uFEFF" + packDoc(baseRule()), CodeInvalidPack},
		{"trailing document", packDoc(baseRule()) + "{}", CodeInvalidPack},
		{"comment", packDoc(baseRule()) + "// note", CodeInvalidPack},
		{"unterminated document", packDoc(baseRule())[:len(packDoc(baseRule()))-1], CodeInvalidPack},
		{"array root", "[" + baseRule() + "]", CodeInvalidPack},
		{"params not an object", replaceOne(t, packDoc(baseRule()), `"params":{"field":"fix_status"}`, `"params":["fix_status"]`), CodeInvalidPack},
		{"requires not an array", replaceOne(t, packDoc(baseRule()), `"requires":["bundle.complete","finding.row","finding.fix_status"]`, `"requires":"bundle.complete"`), CodeInvalidPack},
		{"raw control in string", replaceOne(t, packDoc(baseRule()), `"pack.one"`, "\"pack.\u0007one\""), CodeInvalidPack},
		{"nested duplicate key", replaceOne(t, packDoc(baseRule()), `"params":{"field":"fix_status"}`, `"params":{"field":"fix_status","field":"package_name"}`), CodeInvalidPack},
		{"emit affected", replaceOne(t, packDoc(baseRule()), `"emit":"under_investigation"`, `"emit":"affected"`), CodeUnsupportedPack},
		{"exploitability field", replaceOne(t, packDoc(baseRule()), `"emit":"under_investigation"`, `"emit":"under_investigation","exploitability":"not_assessed"`), CodeInvalidPack},
		{"escaped control in string", packDoc(ruleWith(equalsCheck(`pkg\u0001`), `"bundle.complete","finding.row","finding.package_name"`)), CodeInvalidPack},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			_, err := Decode([]byte(testCase.document))
			wantCode(t, err, testCase.code)
		})
	}

	t.Run("invalid UTF-8", func(t *testing.T) {
		document := []byte(replaceOne(t, packDoc(baseRule()), `"pack.one"`, "\"pack.\xffone\""))
		_, err := Decode(document)
		wantCode(t, err, CodeInvalidPack)
	})

	t.Run("surrounding whitespace is allowed", func(t *testing.T) {
		mustDecode(t, "\n\t "+packDoc(baseRule())+"\r\n ")
	})

	t.Run("surrogate pair decodes to one character", func(t *testing.T) {
		document := packDoc(ruleWith(equalsCheck(`pkg-\uD83D\uDE00`), `"bundle.complete","finding.row","finding.package_name"`))
		pack := mustDecode(t, document)
		if got := pack.Rules[0].Checks[0].Params.Value; got != "pkg-\U0001F600" {
			t.Fatalf("surrogate pair decoded to %q", got)
		}
	})
}

// TestPackLimits is I-03 for the pack budgets: byte size, JSON depth, token
// count, decoded string size, rule and check counts, identifier size and version
// range, each at its inclusive limit and at limit+1 where the control is
// reachable, with an explicit dominance argument where it is not.
func TestPackLimits(t *testing.T) {
	t.Run("pack bytes", func(t *testing.T) {
		document := packDoc(baseRule())
		padded := document + strings.Repeat(" ", MaxPackBytes-len(document))
		if len(padded) != MaxPackBytes {
			t.Fatalf("padding produced %d bytes", len(padded))
		}
		if _, err := Decode([]byte(padded)); err != nil {
			t.Fatalf("a pack of exactly the byte limit must decode: %v", err)
		}
		_, err := Decode([]byte(padded + " "))
		wantCode(t, err, CodeInputLimit)
	})

	t.Run("json depth", func(t *testing.T) {
		// The scanner admits depth 8 and rejects 9 before any schema rule runs,
		// so the control is syntactically valid and the schema rejects it for an
		// unrelated reason.
		allowed := `{"rules":[` + strings.Repeat("[", 6) + strings.Repeat("]", 6) + `]}`
		_, err := Decode([]byte(allowed))
		wantCode(t, err, CodeInvalidPack)

		rejected := `{"rules":[` + strings.Repeat("[", 7) + strings.Repeat("]", 7) + `]}`
		_, err = Decode([]byte(rejected))
		wantCode(t, err, CodeInputLimit)
	})

	t.Run("json tokens", func(t *testing.T) {
		// Token accounting: every delimiter, key, string and scalar counts one.
		// An array of s strings and o empty objects costs 2s+3o+1 tokens.
		atLimit := "[" + strings.Repeat(`"a",`, 9998) + "{}" + "]"
		if tokens := 2*9998 + 3*1 + 1; tokens != MaxJSONTokens {
			t.Fatalf("token arithmetic is wrong: %d", tokens)
		}
		_, err := Decode([]byte(atLimit))
		wantCode(t, err, CodeInvalidPack)

		overLimit := "[" + strings.Repeat(`"a",`, 9999) + `"a"` + "]"
		if tokens := 2*10000 + 1; tokens != MaxJSONTokens+1 {
			t.Fatalf("token arithmetic is wrong: %d", tokens)
		}
		_, err = Decode([]byte(overLimit))
		wantCode(t, err, CodeInputLimit)
	})

	t.Run("decoded string size", func(t *testing.T) {
		atLimit := replaceOne(t, packDoc(baseRule()), `"check_id":"check.one"`, `"check_id":"`+strings.Repeat("c", 256)+`"`)
		_, err := Decode([]byte(atLimit))
		wantCode(t, err, CodeInvalidPack) // decoded, then refused by the identifier grammar

		overLimit := replaceOne(t, packDoc(baseRule()), `"check_id":"check.one"`, `"check_id":"`+strings.Repeat("c", 257)+`"`)
		_, err = Decode([]byte(overLimit))
		wantCode(t, err, CodeInputLimit)
	})

	t.Run("rule count", func(t *testing.T) {
		pack := mustDecode(t, packDoc(makeRuleList(128)))
		if len(pack.Rules) != 128 {
			t.Fatalf("expected 128 rules, got %d", len(pack.Rules))
		}
		_, err := Decode([]byte(packDoc(makeRuleList(129))))
		wantCode(t, err, CodeInvalidPack)
	})

	t.Run("checks per rule", func(t *testing.T) {
		pack := mustDecode(t, packDoc(ruleWith(checkList(32), `"bundle.complete","finding.row","finding.fix_status"`)))
		if len(pack.Rules[0].Checks) != 32 {
			t.Fatalf("expected 32 checks, got %d", len(pack.Rules[0].Checks))
		}
		_, err := Decode([]byte(packDoc(ruleWith(checkList(33), `"bundle.complete","finding.row","finding.fix_status"`))))
		wantCode(t, err, CodeInvalidPack)
	})

	t.Run("identifier size", func(t *testing.T) {
		atLimit := replaceOne(t, packDoc(baseRule()), `"pack_id":"pack.one"`, `"pack_id":"p`+strings.Repeat("a", 63)+`"`)
		mustDecode(t, atLimit)
		overLimit := replaceOne(t, packDoc(baseRule()), `"pack_id":"pack.one"`, `"pack_id":"p`+strings.Repeat("a", 64)+`"`)
		_, err := Decode([]byte(overLimit))
		wantCode(t, err, CodeInvalidPack)

		uppercase := replaceOne(t, packDoc(baseRule()), `"pack_id":"pack.one"`, `"pack_id":"Pack"`)
		_, err = Decode([]byte(uppercase))
		wantCode(t, err, CodeInvalidPack)
	})

	t.Run("version range", func(t *testing.T) {
		mustDecode(t, packDocVersion(MaxVersion, baseRule()))
		_, err := Decode([]byte(packDocVersion(MaxVersion+1, baseRule())))
		wantCode(t, err, CodeInvalidPack)
		_, err = Decode([]byte(packDocVersion(0, baseRule())))
		wantCode(t, err, CodeInvalidPack)
	})

	// Declared non-isolatable limit: the requirement vocabulary has ten members
	// (four base plus six fields) and duplicates are rejected, so MaxRequires=32
	// cannot be reached by an admissible pack. Its controls are the duplicate and
	// vocabulary cases of I-01.
	t.Run("requires budget is dominated", func(t *testing.T) {
		vocabulary := []Requirement{
			RequirementBundleComplete, RequirementFindingRow,
			RequirementImageBoundDigest, RequirementImageKnownPlatform,
			FindingRequirement(FieldVulnerabilityID), FindingRequirement(FieldPackageName),
			FindingRequirement(FieldInstalledVersion), FindingRequirement(FieldPackageType),
			FindingRequirement(FieldPackageID), FindingRequirement(FieldFixStatus),
		}
		if len(vocabulary) >= MaxRequires {
			t.Fatalf("the dominance argument no longer holds: %d members", len(vocabulary))
		}
	})

	// Declared non-isolatable limit: MaxChecksTotal is the arithmetic product of
	// the reachable rule and per-rule limits, and a pack reaching it would exceed
	// the token budget first. Its controls are the rule, check and token cases.
	t.Run("total checks budget is dominated", func(t *testing.T) {
		if MaxRules*MaxChecksPerRule != MaxChecksTotal {
			t.Fatalf("the dominance argument no longer holds: %d", MaxRules*MaxChecksPerRule)
		}
	})
}

func makeRuleList(count int) string {
	parts := make([]string, count)
	for index := 0; index < count; index++ {
		parts[index] = strings.Replace(baseRule(), `"rule_id":"rule.one"`, `"rule_id":"rule.`+suffix(index)+`"`, 1)
	}
	return strings.Join(parts, ",")
}

func checkList(count int) string {
	parts := make([]string, count)
	for index := 0; index < count; index++ {
		parts[index] = `{"check_id":"check.` + suffix(index) + `","predicate":"finding_field_present","params":{"field":"fix_status"}}`
	}
	return strings.Join(parts, ",")
}

func suffix(value int) string {
	return "n" + strconv.Itoa(value)
}
