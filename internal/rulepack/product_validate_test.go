package rulepack

import (
	"strings"
	"testing"
	"time"

	contract "github.com/d4rpell/Ariadne/pkg/evidence"
)

// Fixtures of the product profile, assembled from literals on purpose: the tests
// must not share a marshaller with production decoding. Every affirmative rule
// declares the eleven requirements of ADR-0015 §8.1 literally.

const productBaseRequires = `"bundle.complete","finding.row"`

const productAffirmativeRequires = `"bundle.complete","finding.row",` +
	`"finding.package_type","finding.package_name","finding.package_id",` +
	`"image.bound_digest","image.known_platform",` +
	`"domain.mapping","domain.artifact","domain.vendor_proof","domain.current"`

func productCheck(checkID, predicate string) string {
	return `{"check_id":"` + checkID + `","predicate":"` + predicate + `","params":{}}`
}

func productRule(ruleID, emit, terminal string, requiresJSON string, extraChecks ...string) string {
	checks := []string{productCheck("check.terminal", terminal)}
	checks = append(checks, extraChecks...)
	return `{"rule_id":"` + ruleID + `",` +
		`"selector":{"coverage_method":"findings_import","vulnerability_id":"CVE-2026-12345"},` +
		`"requires":[` + requiresJSON + `],` +
		`"checks":[` + strings.Join(checks, ",") + `],` +
		`"on_missing_evidence":"under_investigation","emit":"` + emit + `"}`
}

func productPackDoc(rules string) string {
	return `{"schema_version":"0.1","profile":"` + ProductEvidenceProfile + `","pack_id":"pack.one","version":7,` +
		`"valid_from":"2026-09-01T00:00:00Z","expires_at":"2026-12-31T23:59:59Z","rules":[` + rules + `]}`
}

func productAffectedRule() string {
	return productRule("rule.affected", OutputAffected, "redhat_build_affected", productAffirmativeRequires)
}

// productInconclusiveRule uses an auxiliary predicate with every requirement it
// needs: an inconclusive rule of the product profile declares the base pair plus
// whatever its checks demand (ADR-0015 §8.1/§8.3).
func productInconclusiveRule() string {
	requires := productBaseRequires + `,"finding.package_type","finding.package_name","finding.package_id","domain.mapping"`
	return productRule("rule.review", OutputUnderInvestigation, "redhat_product_mapped", requires)
}

// removeRequirement deletes one quoted requirement from a fixture, tolerating
// both the middle position (trailing comma) and the last position.
func removeRequirement(t *testing.T, document, quoted string) string {
	t.Helper()
	if strings.Contains(document, quoted+",") {
		return strings.Replace(document, quoted+",", "", 1)
	}
	if strings.Contains(document, ","+quoted) {
		return strings.Replace(document, ","+quoted, "", 1)
	}
	t.Fatalf("fixture does not contain the requirement %s", quoted)
	return document
}

// TestProductPackClosedVocabulary is I-11: the reader knows exactly two profiles;
// an unknown one is unsupported, and the legacy profile does not accept the
// domain emits or predicates.
func TestProductPackClosedVocabulary(t *testing.T) {
	mustDecode(t, productPackDoc(productAffectedRule()))

	cases := []struct {
		name     string
		document string
		code     ErrorCode
	}{
		{
			"unknown profile",
			replaceOne(t, productPackDoc(productAffectedRule()), ProductEvidenceProfile, "product-evidence-v2"),
			CodeUnsupportedPack,
		},
		{
			"legacy profile with domain predicate",
			replaceOne(t, productPackDoc(productAffectedRule()), ProductEvidenceProfile, SupportedProfile),
			CodeUnsupportedPack,
		},
		{
			"unknown domain predicate",
			replaceOne(t, productPackDoc(productAffectedRule()), "redhat_build_affected", "redhat_build_guess"),
			CodeUnsupportedPack,
		},
		{
			"unknown requirement",
			replaceOne(t, productPackDoc(productAffectedRule()), `"domain.current"`, `"domain.future"`),
			CodeUnsupportedPack,
		},
		{
			"unknown emit",
			replaceOne(t, productPackDoc(productAffectedRule()), `"emit":"affected"`, `"emit":"probably"`),
			CodeUnsupportedPack,
		},
		{
			"pack schema newer",
			replaceOne(t, productPackDoc(productAffectedRule()), `"schema_version":"0.1"`, `"schema_version":"0.2"`),
			CodeUnsupportedPack,
		},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			_, err := Decode([]byte(testCase.document))
			wantCode(t, err, testCase.code)
		})
	}

	// An unknown profile is unsupported on the strength of the profile token
	// alone, never as a side effect of a body that happens to fit another
	// profile: a legacy-shaped body under an unknown name must be refused too,
	// because a fallback would silently admit a document nobody declared.
	t.Run("legacy body under an unknown profile", func(t *testing.T) {
		document := replaceOne(t, packDoc(baseRule()), `"profile":"evidence-readiness-v1"`, `"profile":"product-evidence-v2"`)
		_, err := Decode([]byte(document))
		wantCode(t, err, CodeUnsupportedPack)
	})

	// The legacy profile keeps rejecting the affirmative emit even when the rest
	// of the rule would be well formed for the product profile.
	legacy := replaceOne(t, productPackDoc(productAffectedRule()), ProductEvidenceProfile, SupportedProfile)
	_, err := Decode([]byte(legacy))
	wantCode(t, err, CodeUnsupportedPack)
}

// TestProductPackExplicitRequirements is I-12: every one of the eleven minimum
// requirements of an affirmative rule is validated literally, and no omission is
// filled in from the terminal.
func TestProductPackExplicitRequirements(t *testing.T) {
	mustDecode(t, productPackDoc(productAffectedRule()))

	// The two base requirements are mandatory for every rule, including the
	// inconclusive ones.
	for _, omitted := range []string{`"bundle.complete"`, `"finding.row"`} {
		t.Run("inconclusive omits "+omitted, func(t *testing.T) {
			document := removeRequirement(t, productPackDoc(productInconclusiveRule()), omitted)
			_, err := Decode([]byte(document))
			wantCode(t, err, CodeInvalidPack)
		})
	}

	required := []string{
		`"finding.package_type"`,
		`"finding.package_name"`,
		`"finding.package_id"`,
		`"image.bound_digest"`,
		`"image.known_platform"`,
		`"domain.mapping"`,
		`"domain.artifact"`,
		`"domain.vendor_proof"`,
		`"domain.current"`,
	}
	for _, omitted := range required {
		t.Run("affirmative omits "+omitted, func(t *testing.T) {
			document := removeRequirement(t, productPackDoc(productAffectedRule()), omitted)
			_, err := Decode([]byte(document))
			wantCode(t, err, CodeInvalidPack)
		})
	}

	t.Run("duplicated requirement", func(t *testing.T) {
		document := productPackDoc(productAffectedRule())
		document = replaceOne(t, document, `"domain.current"`, `"domain.current","domain.current"`)
		_, err := Decode([]byte(document))
		wantCode(t, err, CodeInvalidPack)
	})

	t.Run("extra known requirement is allowed", func(t *testing.T) {
		document := productPackDoc(productAffectedRule())
		document = replaceOne(t, document, `"domain.current"`, `"domain.current","finding.fix_status"`)
		if _, err := Decode([]byte(document)); err != nil {
			t.Fatalf("a known extra requirement must stay admissible: %v", err)
		}
	})

	t.Run("inconclusive rule keeps the base set only", func(t *testing.T) {
		if _, err := Decode([]byte(productPackDoc(productInconclusiveRule()))); err != nil {
			t.Fatalf("an inconclusive rule needs only the two base requirements: %v", err)
		}
	})
}

// TestProductPackTerminalContract is I-13: each affirmative emit has exactly one
// matching terminal; absence, a foreign terminal or several terminals fail, and
// the domain predicates take no parameters.
func TestProductPackTerminalContract(t *testing.T) {
	mustDecode(t, productPackDoc(productAffectedRule()))

	cases := []struct {
		name     string
		document string
	}{
		{
			"terminal absent",
			productPackDoc(productRule("rule.affected", OutputAffected, "redhat_product_mapped", productAffirmativeRequires)),
		},
		{
			"terminal of another state",
			productPackDoc(productRule("rule.affected", OutputAffected, "redhat_build_fixed", productAffirmativeRequires)),
		},
		{
			"two terminals with different ids",
			productPackDoc(productRule("rule.affected", OutputAffected, "redhat_build_affected", productAffirmativeRequires,
				productCheck("check.second", "redhat_build_fixed"))),
		},
		{
			"terminal duplicated under another id",
			productPackDoc(productRule("rule.affected", OutputAffected, "redhat_build_affected", productAffirmativeRequires,
				productCheck("check.second", "redhat_build_affected"))),
		},
		{
			"auxiliary used as terminal",
			productPackDoc(productRule("rule.fixed", OutputFixed, "redhat_artifact_bound", productAffirmativeRequires)),
		},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			_, err := Decode([]byte(testCase.document))
			wantCode(t, err, CodeInvalidPack)
		})
	}

	t.Run("auxiliaries alongside the terminal are allowed", func(t *testing.T) {
		document := productPackDoc(productRule("rule.affected", OutputAffected, "redhat_build_affected", productAffirmativeRequires,
			productCheck("check.mapped", "redhat_product_mapped"),
			productCheck("check.bound", "redhat_artifact_bound")))
		if _, err := Decode([]byte(document)); err != nil {
			t.Fatalf("the terminal checks the whole chain; auxiliaries must be admissible: %v", err)
		}
	})

	t.Run("every affirmative emit has its terminal", func(t *testing.T) {
		for emit, terminal := range map[string]string{
			OutputAffected:    "redhat_build_affected",
			OutputFixed:       "redhat_build_fixed",
			OutputNotAffected: "redhat_build_code_excluded",
		} {
			document := productPackDoc(productRule("rule."+emit, emit, terminal, productAffirmativeRequires))
			if _, err := Decode([]byte(document)); err != nil {
				t.Fatalf("emit %s with its terminal must decode: %v", emit, err)
			}
		}
	})

	t.Run("domain predicates take no parameters", func(t *testing.T) {
		document := productPackDoc(productAffectedRule())
		document = replaceOne(t, document,
			`{"check_id":"check.terminal","predicate":"redhat_build_affected","params":{}}`,
			`{"check_id":"check.terminal","predicate":"redhat_build_affected","params":{"field":"fix_status"}}`)
		_, err := Decode([]byte(document))
		wantCode(t, err, CodeInvalidPack)
	})

	t.Run("auxiliary requirements cannot be omitted", func(t *testing.T) {
		document := productPackDoc(productRule("rule.affected", OutputAffected, "redhat_build_affected", productAffirmativeRequires,
			productCheck("check.bound", "redhat_artifact_bound")))
		// The auxiliary needs image.known_platform; dropping it from the rule must
		// be refused even though the terminal declares the full set.
		document = replaceOne(t, document, `"image.known_platform",`, ``)
		_, err := Decode([]byte(document))
		wantCode(t, err, CodeInvalidPack)
	})
}

// TestProductPackAdmissionPreservesPolicy is I-14: hash, identity, anti-downgrade
// and validity keep their exact behaviour for the new profile.
func TestProductPackAdmissionPreservesPolicy(t *testing.T) {
	document := productPackDoc(productAffectedRule())
	context := validContext(document)

	t.Run("control admits", func(t *testing.T) {
		admitted, err := Admit([]byte(document), context)
		if err != nil {
			t.Fatalf("control product pack was not admitted: %v", err)
		}
		if !admitted.Valid() || admitted.Pack().Profile != ProductEvidenceProfile {
			t.Fatal("the admitted pack lost its profile")
		}
		if admitted.Hash() != independentHash(document) {
			t.Fatal("the admitted hash is not the SHA-256 of the exact bytes")
		}
	})

	t.Run("hash mismatch", func(t *testing.T) {
		_, err := Admit([]byte(document+" "), context)
		wantCode(t, err, CodePackHashMismatch)
	})

	t.Run("identity mismatch", func(t *testing.T) {
		other := context
		other.ExpectedPackID = "pack.other"
		other.ExpectedPackHash = independentHash(document)
		_, err := Admit([]byte(document), other)
		wantCode(t, err, CodePackIdentityMismatch)
	})

	t.Run("downgrade against previous", func(t *testing.T) {
		other := context
		other.Previous = &PreviousVersion{Version: 8, Hash: independentHash("other")}
		_, err := Admit([]byte(document), other)
		wantCode(t, err, CodePackDowngrade)
	})

	t.Run("equivocation", func(t *testing.T) {
		other := context
		other.Previous = &PreviousVersion{Version: 7, Hash: independentHash("other")}
		_, err := Admit([]byte(document), other)
		wantCode(t, err, CodePackEquivocation)
	})

	t.Run("expired", func(t *testing.T) {
		other := context
		later, err := contractTimestamp("2027-01-01T00:00:00Z")
		if err != nil {
			t.Fatalf("timestamp: %v", err)
		}
		other.EvaluatedAt = later
		_, err = Admit([]byte(document), other)
		wantCode(t, err, CodePackExpired)
	})

	t.Run("strict decoder preserved", func(t *testing.T) {
		_, err := Admit([]byte(replaceOne(t, document, `"pack_id":"pack.one"`, `"pack_id":"pack.one","extra":1`)), context)
		wantCode(t, err, CodePackHashMismatch)
	})
}

// TestProductPackBundleVersion is I-15: the profile/version cross admits the
// product profile only with Bundle 0.2, while readiness keeps working with both
// known versions.
func TestProductPackBundleVersion(t *testing.T) {
	product := productPackDoc(productAffectedRule())
	context := validContext(product)

	for _, version := range []string{"0.0", "0.1", "0.3", "1.0"} {
		t.Run("product rejects "+version, func(t *testing.T) {
			_, err := AdmitForBundle([]byte(product), context, version)
			wantCode(t, err, CodeInvalidPack)
		})
	}
	t.Run("product accepts 0.2", func(t *testing.T) {
		if _, err := AdmitForBundle([]byte(product), context, "0.2"); err != nil {
			t.Fatalf("product with Bundle 0.2 must be admitted: %v", err)
		}
	})

	legacy := packDoc(baseRule())
	legacyContext := validContext(legacy)
	for _, version := range []string{"0.1", "0.2"} {
		t.Run("readiness accepts "+version, func(t *testing.T) {
			if _, err := AdmitForBundle([]byte(legacy), legacyContext, version); err != nil {
				t.Fatalf("readiness with Bundle %s must be admitted: %v", version, err)
			}
		})
	}

	t.Run("no version supplied skips the cross", func(t *testing.T) {
		if _, err := AdmitForBundle([]byte(product), context, ""); err != nil {
			t.Fatalf("an empty bundle version means no cross: %v", err)
		}
	})
}

// TestProductRecognizeProfile is I-16 (recognition half): the strict, bounded,
// non-admitting classification of ADR-0018 §3 distinguishes the two known
// headers and leaves everything else indeterminate.
func TestProductRecognizeProfile(t *testing.T) {
	cases := []struct {
		name     string
		document string
		want     Recognition
	}{
		{"product header", productPackDoc(productAffectedRule()), RecognizedProduct},
		{"readiness header", packDoc(baseRule()), RecognizedReadiness},
		{"empty", "", RecognizedIndeterminate},
		{"not json", "not json at all", RecognizedIndeterminate},
		{"truncated", productPackDoc(productAffectedRule())[:40], RecognizedIndeterminate},
		{"root array", `[]`, RecognizedIndeterminate},
		{"root string", `"product-evidence-v1"`, RecognizedIndeterminate},
		{
			"duplicated profile key",
			`{"schema_version":"0.1","profile":"product-evidence-v1","profile":"product-evidence-v1"}`,
			RecognizedIndeterminate,
		},
		{
			"duplicated nested key",
			replaceOne(t, productPackDoc(productAffectedRule()), `"pack_id":"pack.one"`, `"pack_id":"pack.one","version":7`),
			RecognizedIndeterminate,
		},
		{
			"unknown profile",
			replaceOne(t, productPackDoc(productAffectedRule()), ProductEvidenceProfile, "product-evidence-v9"),
			RecognizedIndeterminate,
		},
		{
			"schema absent",
			replaceOne(t, productPackDoc(productAffectedRule()), `"schema_version":"0.1",`, ``),
			RecognizedIndeterminate,
		},
		{
			"schema numeric",
			replaceOne(t, productPackDoc(productAffectedRule()), `"schema_version":"0.1"`, `"schema_version":1`),
			RecognizedIndeterminate,
		},
		{
			"profile null",
			replaceOne(t, productPackDoc(productAffectedRule()), `"profile":"`+ProductEvidenceProfile+`"`, `"profile":null`),
			RecognizedIndeterminate,
		},
		{
			"unknown requirement does not erase the header",
			replaceOne(t, productPackDoc(productAffectedRule()), `"domain.current"`, `"domain.future"`),
			RecognizedProduct,
		},
		{
			"invalid later syntax does not erase the header",
			replaceOne(t, productPackDoc(productAffectedRule()), `"version":7`, `"version":7,`),
			RecognizedIndeterminate,
		},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			if got := RecognizeProfile([]byte(testCase.document)); got != testCase.want {
				t.Fatalf("RecognizeProfile = %d, want %d", got, testCase.want)
			}
		})
	}

	t.Run("recognition yields no admitted pack", func(t *testing.T) {
		if got := RecognizeProfile([]byte(productPackDoc(productAffectedRule()))); got.RequiresDomainContext() == false {
			t.Fatal("the product profile owes a domain context")
		}
		if got := RecognizeProfile([]byte(packDoc(baseRule()))); !got.ForbidsDomainContext() {
			t.Fatal("readiness forbids an extra domain context")
		}
		if got := RecognizeProfile([]byte("garbage")); got.RequiresDomainContext() || got.ForbidsDomainContext() {
			t.Fatal("an indeterminate classification must not claim either contract")
		}
	})

	t.Run("scanner limits are respected", func(t *testing.T) {
		oversized := `{"schema_version":"0.1","profile":"product-evidence-v1","pad":"` +
			strings.Repeat("a", MaxStringBytes+1) + `"}`
		if got := RecognizeProfile([]byte(oversized)); got != RecognizedIndeterminate {
			t.Fatal("an over-long string must not be recognized")
		}
		deep := `{"schema_version":"0.1","profile":"product-evidence-v1","a":` +
			strings.Repeat("[", MaxJSONDepth) + strings.Repeat("]", MaxJSONDepth) + `}`
		if got := RecognizeProfile([]byte(deep)); got != RecognizedIndeterminate {
			t.Fatal("an over-deep document must not be recognized")
		}
	})
}

func contractTimestamp(value string) (contract.Timestamp, error) {
	parsed, err := time.Parse(time.RFC3339Nano, value)
	if err != nil {
		return contract.Timestamp{}, err
	}
	return contract.NewTimestamp(parsed)
}
