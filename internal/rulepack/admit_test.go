package rulepack

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"
	"time"

	contract "github.com/d4rpell/Ariadne/pkg/evidence"
)

// independentHash computes the pack identity without the production helper: the
// integrity control must not share its implementation with the code it checks.
func independentHash(document string) string {
	digest := sha256.Sum256([]byte(document))
	return "sha256:" + hex.EncodeToString(digest[:])
}

func evaluationTime() contract.Timestamp {
	stamp, err := contract.NewTimestamp(time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC))
	if err != nil {
		panic(err)
	}
	return stamp
}

func validContext(document string) AdmissionContext {
	return AdmissionContext{
		EvaluatedAt:      evaluationTime(),
		ExpectedPackID:   "pack.one",
		ExpectedPackHash: independentHash(document),
		MinimumVersion:   1,
	}
}

// TestPackExactBytesHash is I-04: the pack identity covers every supplied byte,
// the pin is independent of the pack content, and the admitted hash matches an
// independently computed SHA-256.
func TestPackExactBytesHash(t *testing.T) {
	document := packDoc(baseRule())
	admitted, err := Admit([]byte(document), validContext(document))
	if err != nil {
		t.Fatalf("control pack was not admitted: %v", err)
	}
	if !admitted.Valid() {
		t.Fatalf("a successful admission must be valid")
	}
	if admitted.Hash() != independentHash(document) {
		t.Fatalf("admitted hash %q differs from the independent SHA-256", admitted.Hash())
	}
	if admitted.PackID() != "pack.one" || admitted.Version() != 7 {
		t.Fatalf("admitted identity changed: %q version %d", admitted.PackID(), admitted.Version())
	}

	t.Run("pin of another document", func(t *testing.T) {
		_, err := Admit([]byte(document), validContext(document+" "))
		wantCode(t, err, CodePackHashMismatch)
	})

	t.Run("added byte after the object", func(t *testing.T) {
		_, err := Admit([]byte(document+"\n"), validContext(document))
		wantCode(t, err, CodePackHashMismatch)
	})

	t.Run("whitespace inside changed", func(t *testing.T) {
		spaced := strings.Replace(document, `,"profile"`, `, "profile"`, 1)
		if spaced == document {
			t.Fatalf("fixture did not change")
		}
		_, err := Admit([]byte(spaced), validContext(document))
		wantCode(t, err, CodePackHashMismatch)
		// The same bytes with their own pin are admitted: identity is the byte
		// sequence, not its meaning.
		if _, err := Admit([]byte(spaced), validContext(spaced)); err != nil {
			t.Fatalf("the same bytes with their own pin must be admitted: %v", err)
		}
	})

	t.Run("content changed", func(t *testing.T) {
		changed := replaceOne(t, document, `"version":7`, `"version":8`)
		_, err := Admit([]byte(changed), validContext(document))
		wantCode(t, err, CodePackHashMismatch)
	})
}

// TestPackVersionPolicy is I-05: anti-downgrade is relative to the supplied
// policy, an equivocation is a same-version content change, and an invalid
// previous pair is refused even when the incoming version is greater. Bootstrap
// is the explicit nil case.
func TestPackVersionPolicy(t *testing.T) {
	document := packDocVersion(7, baseRule())
	otherBytes := packDocVersion(7, baseRule()) + " "

	t.Run("below minimum", func(t *testing.T) {
		context := validContext(document)
		context.MinimumVersion = 8
		_, err := Admit([]byte(document), context)
		wantCode(t, err, CodePackDowngrade)
	})

	t.Run("equal to minimum", func(t *testing.T) {
		context := validContext(document)
		context.MinimumVersion = 7
		if _, err := Admit([]byte(document), context); err != nil {
			t.Fatalf("version equal to the minimum must be admitted: %v", err)
		}
	})

	t.Run("above minimum", func(t *testing.T) {
		context := validContext(document)
		context.MinimumVersion = 6
		if _, err := Admit([]byte(document), context); err != nil {
			t.Fatalf("version above the minimum must be admitted: %v", err)
		}
	})

	t.Run("bootstrap", func(t *testing.T) {
		if _, err := Admit([]byte(document), validContext(document)); err != nil {
			t.Fatalf("explicit bootstrap must be admitted: %v", err)
		}
	})

	t.Run("below previous version", func(t *testing.T) {
		context := validContext(document)
		context.Previous = &PreviousVersion{Version: 8, Hash: independentHash(otherBytes)}
		_, err := Admit([]byte(document), context)
		wantCode(t, err, CodePackDowngrade)
	})

	t.Run("same version, different bytes", func(t *testing.T) {
		context := validContext(document)
		context.Previous = &PreviousVersion{Version: 7, Hash: independentHash(otherBytes)}
		_, err := Admit([]byte(document), context)
		wantCode(t, err, CodePackEquivocation)
	})

	t.Run("same version, same bytes", func(t *testing.T) {
		context := validContext(document)
		context.Previous = &PreviousVersion{Version: 7, Hash: independentHash(document)}
		if _, err := Admit([]byte(document), context); err != nil {
			t.Fatalf("re-admitting the same version and bytes must pass: %v", err)
		}
	})

	t.Run("above previous version", func(t *testing.T) {
		context := validContext(document)
		context.Previous = &PreviousVersion{Version: 6, Hash: independentHash(otherBytes)}
		if _, err := Admit([]byte(document), context); err != nil {
			t.Fatalf("an upgrade over accepted history must pass: %v", err)
		}
	})

	t.Run("previous hash malformed despite a greater version", func(t *testing.T) {
		context := validContext(document)
		context.Previous = &PreviousVersion{Version: 3, Hash: "sha256:xyz"}
		_, err := Admit([]byte(document), context)
		wantCode(t, err, CodeInvalidContext)
	})

	t.Run("previous version zero", func(t *testing.T) {
		context := validContext(document)
		context.Previous = &PreviousVersion{Version: 0, Hash: independentHash(otherBytes)}
		_, err := Admit([]byte(document), context)
		wantCode(t, err, CodeInvalidContext)
	})

	t.Run("context without pin shape", func(t *testing.T) {
		context := validContext(document)
		context.ExpectedPackHash = "sha256:ABCDEF"
		_, err := Admit([]byte(document), context)
		wantCode(t, err, CodeInvalidContext)
	})

	t.Run("context without identity", func(t *testing.T) {
		context := validContext(document)
		context.ExpectedPackID = "Pack.One"
		_, err := Admit([]byte(document), context)
		wantCode(t, err, CodeInvalidContext)
	})

	t.Run("context without instant", func(t *testing.T) {
		context := validContext(document)
		context.EvaluatedAt = contract.Timestamp{}
		_, err := Admit([]byte(document), context)
		wantCode(t, err, CodeInvalidContext)
	})
}

// TestPackValidityInterval is I-06: the validity window is inclusive at its
// start and exclusive at its end, it is read from the explicit instant only, and
// a non-canonical timestamp is refused by the schema.
func TestPackValidityInterval(t *testing.T) {
	document := packDoc(baseRule())

	at := func(date time.Time) AdmissionContext {
		context := validContext(document)
		stamp, err := contract.NewTimestamp(date)
		if err != nil {
			t.Fatalf("timestamp construction failed: %v", err)
		}
		context.EvaluatedAt = stamp
		return context
	}

	t.Run("before valid_from", func(t *testing.T) {
		_, err := Admit([]byte(document), at(time.Date(2026, 8, 31, 23, 59, 59, 0, time.UTC)))
		wantCode(t, err, CodePackNotYetValid)
	})

	t.Run("at valid_from", func(t *testing.T) {
		if _, err := Admit([]byte(document), at(time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC))); err != nil {
			t.Fatalf("the first valid instant must be admitted: %v", err)
		}
	})

	t.Run("inside", func(t *testing.T) {
		if _, err := Admit([]byte(document), at(time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC))); err != nil {
			t.Fatalf("an instant inside the window must be admitted: %v", err)
		}
	})

	t.Run("at expires_at", func(t *testing.T) {
		_, err := Admit([]byte(document), at(time.Date(2026, 12, 31, 23, 59, 59, 0, time.UTC)))
		wantCode(t, err, CodePackExpired)
	})

	t.Run("after expires_at", func(t *testing.T) {
		_, err := Admit([]byte(document), at(time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC)))
		wantCode(t, err, CodePackExpired)
	})

	t.Run("replay with a fixed instant", func(t *testing.T) {
		context := at(time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC))
		first, err := Admit([]byte(document), context)
		if err != nil {
			t.Fatalf("first admission failed: %v", err)
		}
		second, err := Admit([]byte(document), context)
		if err != nil {
			t.Fatalf("second admission failed: %v", err)
		}
		if first.Hash() != second.Hash() || first.Version() != second.Version() {
			t.Fatalf("admission is not reproducible for the same instant")
		}
	})

	nonCanonical := []struct {
		name     string
		document string
	}{
		{"fractional zeros", replaceOne(t, document, `"valid_from":"2026-09-01T00:00:00Z"`, `"valid_from":"2026-09-01T00:00:00.000Z"`)},
		{"numeric offset", replaceOne(t, document, `"valid_from":"2026-09-01T00:00:00Z"`, `"valid_from":"2026-09-01T00:00:00+00:00"`)},
		{"lowercase z", replaceOne(t, document, `"valid_from":"2026-09-01T00:00:00Z"`, `"valid_from":"2026-09-01T00:00:00z"`)},
		{"date only", replaceOne(t, document, `"valid_from":"2026-09-01T00:00:00Z"`, `"valid_from":"2026-09-01"`)},
		{"epoch zero", replaceOne(t, document, `"valid_from":"2026-09-01T00:00:00Z"`, `"valid_from":"0001-01-01T00:00:00Z"`)},
	}
	for _, testCase := range nonCanonical {
		t.Run("non-canonical "+testCase.name, func(t *testing.T) {
			_, err := Decode([]byte(testCase.document))
			wantCode(t, err, CodeInvalidPack)
		})
	}

	t.Run("empty interval", func(t *testing.T) {
		swapped := replaceOne(t, document, `"valid_from":"2026-09-01T00:00:00Z","expires_at":"2026-12-31T23:59:59Z"`,
			`"valid_from":"2026-12-31T23:59:59Z","expires_at":"2026-12-31T23:59:59Z"`)
		_, err := Decode([]byte(swapped))
		wantCode(t, err, CodeInvalidPack)
	})

	t.Run("inverted interval", func(t *testing.T) {
		swapped := replaceOne(t, document, `"valid_from":"2026-09-01T00:00:00Z","expires_at":"2026-12-31T23:59:59Z"`,
			`"valid_from":"2027-01-01T00:00:00Z","expires_at":"2026-12-31T23:59:59Z"`)
		_, err := Decode([]byte(swapped))
		wantCode(t, err, CodeInvalidPack)
	})
}

// TestAdmissionFailureHasNoResult is I-07 for admission: every rejection returns
// the zero AdmittedPack and a typed code, so no partial admission can be used.
func TestAdmissionFailureHasNoResult(t *testing.T) {
	document := packDoc(baseRule())
	oversized := document + strings.Repeat(" ", MaxPackBytes-len(document)+1)

	withPrevious := validContext(document)
	withPrevious.Previous = &PreviousVersion{Version: 8, Hash: independentHash(document)}

	cases := []struct {
		name    string
		data    string
		context AdmissionContext
		code    ErrorCode
	}{
		{"input limit", oversized, validContext(document), CodeInputLimit},
		{"invalid context", document, func() AdmissionContext {
			context := validContext(document)
			context.MinimumVersion = 0
			return context
		}(), CodeInvalidContext},
		{"missing pack", "", validContext(document), CodeMissingPack},
		{"hash mismatch", document, validContext(document + "x"), CodePackHashMismatch},
		{"invalid pack", "{", validContext("{"), CodeInvalidPack},
		{"unsupported pack", replaceOne(t, document, `"profile":"evidence-readiness-v1"`, `"profile":"other"`), validContext(replaceOne(t, document, `"profile":"evidence-readiness-v1"`, `"profile":"other"`)), CodeUnsupportedPack},
		{"identity mismatch", document, func() AdmissionContext {
			context := validContext(document)
			context.ExpectedPackID = "pack.two"
			return context
		}(), CodePackIdentityMismatch},
		{"downgrade", document, withPrevious, CodePackDowngrade},
		{"equivocation", document, func() AdmissionContext {
			context := validContext(document)
			context.Previous = &PreviousVersion{Version: 7, Hash: independentHash(document + " ")}
			return context
		}(), CodePackEquivocation},
		{"not yet valid", document, func() AdmissionContext {
			context := validContext(document)
			stamp, _ := contract.NewTimestamp(time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC))
			context.EvaluatedAt = stamp
			return context
		}(), CodePackNotYetValid},
		{"expired", document, func() AdmissionContext {
			context := validContext(document)
			stamp, _ := contract.NewTimestamp(time.Date(2027, 6, 1, 0, 0, 0, 0, time.UTC))
			context.EvaluatedAt = stamp
			return context
		}(), CodePackExpired},
	}
	seen := make(map[ErrorCode]bool, len(cases))
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			admitted, err := Admit([]byte(testCase.data), testCase.context)
			wantCode(t, err, testCase.code)
			seen[testCase.code] = true
			if admitted.Valid() || admitted.Hash() != "" || admitted.PackID() != "" || admitted.Version() != 0 || len(admitted.Pack().Rules) != 0 {
				t.Fatalf("a rejected admission returned a usable pack: %+v", admitted)
			}
		})
	}

	t.Run("every declared code was exercised", func(t *testing.T) {
		declared := []ErrorCode{
			CodeInputLimit, CodeInvalidContext, CodeMissingPack, CodePackHashMismatch,
			CodeInvalidPack, CodeUnsupportedPack, CodePackIdentityMismatch,
			CodePackDowngrade, CodePackEquivocation, CodePackNotYetValid, CodePackExpired,
		}
		for _, code := range declared {
			if !seen[code] {
				t.Fatalf("code %s is declared but never produced by the failing paths", code)
			}
		}
	})
}

// TestAdmittedPackIsDetachedAndZeroInvalid covers the ownership of an admitted
// pack: the value returned by Pack() is a copy, and the zero value is not a
// usable admission.
func TestAdmittedPackIsDetachedAndZeroInvalid(t *testing.T) {
	var zero AdmittedPack
	if zero.Valid() || zero.Hash() != "" || len(zero.Pack().Rules) != 0 {
		t.Fatalf("the zero AdmittedPack must not be usable")
	}

	document := packDoc(baseRule())
	admitted, err := Admit([]byte(document), validContext(document))
	if err != nil {
		t.Fatalf("control pack was not admitted: %v", err)
	}
	first := admitted.Pack()
	first.Rules[0].Requires[0] = Requirement("finding.package_name")
	first.Rules[0].Checks[0].Params.Field = "package_type"
	first.PackID = "pack.other"
	second := admitted.Pack()
	if second.Rules[0].Requires[0] != RequirementBundleComplete {
		t.Fatalf("the admitted pack was mutated through a returned copy")
	}
	if second.Rules[0].Checks[0].Params.Field != "fix_status" {
		t.Fatalf("the admitted checks were mutated through a returned copy")
	}
	if second.PackID != "pack.one" {
		t.Fatalf("the admitted identity was mutated through a returned copy")
	}
}
