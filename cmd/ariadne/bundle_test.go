package main

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/d4rpell/Ariadne/internal/bundle"
	contract "github.com/d4rpell/Ariadne/pkg/evidence"
)

// IN-01 and IN-06: the envelope admission. A mutation of one documented fact of
// the canonical envelope must be rejected at bundle_decode; the unmodified
// fixture is the positive control, and the budget preflight is proven to run
// before the canonical encoder (its spy must never be called for an oversized
// model).

func TestBundleDecodePositiveControl(t *testing.T) {
	figures := composeFixture(t, "F09-unmapped-redhat-package")
	if _, failure := decodeBundle(readTemp(t, figures.bundle)); failure != nil {
		t.Fatalf("canonical fixture envelope rejected: %v", failure)
	}
}

func TestBundleRejections(t *testing.T) {
	figures := composeFixture(t, "F09-unmapped-redhat-package")
	canonical := readTemp(t, figures.bundle)
	cases := []struct {
		name   string
		mutate func([]byte) []byte
	}{
		{"byte order mark", func(data []byte) []byte {
			return append([]byte{0xEF, 0xBB, 0xBF}, data...)
		}},
		{"trailing newline", func(data []byte) []byte {
			return append(append([]byte{}, data...), '\n')
		}},
		{"leading whitespace", func(data []byte) []byte {
			return append([]byte{'\n'}, data...)
		}},
		{"truncated", func(data []byte) []byte {
			return data[:len(data)-1]
		}},
		{"trailing garbage", func(data []byte) []byte {
			return append(append([]byte{}, data...), []byte(`{"x":1}`)...)
		}},
		{"duplicate root member", func(data []byte) []byte {
			return []byte(strings.Replace(string(data), `"schema_version":`,
				`"schema_version":"0.2","schema_version":`, 1))
		}},
		{"unknown root member", func(data []byte) []byte {
			return []byte(strings.Replace(string(data), `{`, `{"surplus":true,`, 1))
		}},
		{"root member omitted", func(data []byte) []byte {
			return []byte(strings.Replace(string(data), `"observed_container_classes":[]`, ``, 1))
		}},
		{"alternate casing", func(data []byte) []byte {
			return []byte(strings.Replace(string(data), `"schema_version":`,
				`"Schema_Version":`, 1))
		}},
		{"unsupported version", func(data []byte) []byte {
			return []byte(strings.Replace(string(data), `"schema_version":"0.2"`,
				`"schema_version":"0.3"`, 1))
		}},
		{"hash-input as envelope", func(data []byte) []byte {
			return readTemp(t, filepath.Join(filepath.Dir(figures.bundle), "..", "expected", "bundle.hash-input.json"))
		}},
		{"invalid utf8 inside string", func(data []byte) []byte {
			return []byte(strings.Replace(string(data), `uid-F09`, "uid-F\xff09", 1))
		}},
		{"unpaired surrogate escape", func(data []byte) []byte {
			return []byte(strings.Replace(string(data), `uid-F09`, `uid-\ud800F09`, 1))
		}},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			mutated := testCase.mutate(canonical)
			if _, failure := decodeBundle(mutated); failure == nil {
				t.Fatalf("mutated envelope was admitted; want rejection")
			}
		})
	}
}

// IN-06: the model-budget preflight observes the excess before the canonical
// encoder runs, and each of the four budgets is exercised in isolation. The spy
// proves short-circuiting; the fixture is the positive control that does reach
// the encoder.
func TestBundleBudgetPreflightBeforeEncoder(t *testing.T) {
	figures := composeFixture(t, "F09-unmapped-redhat-package")
	canonical := readTemp(t, figures.bundle)

	original := canonicalEncode
	defer func() { canonicalEncode = original }()
	encoded := false
	canonicalEncode = func(input contract.Bundle) (bundle.Artifacts, error) {
		encoded = true
		return original(input)
	}

	// The fixture itself stays inside every budget and reaches the encoder.
	if _, failure := decodeBundle(canonical); failure != nil {
		t.Fatalf("canonical fixture rejected: %v", failure)
	}
	if !encoded {
		t.Fatalf("canonical fixture did not reach the encoder")
	}

	base := func() contract.Bundle {
		var decoded contract.Bundle
		if err := jsonUnmarshal(canonical, &decoded); err != nil {
			t.Fatalf("decode fixture: %v", err)
		}
		return decoded
	}

	// One oversized model per budget axis; each keeps raw bytes below the
	// transport bound, so it is the model budget that rejects.
	oversized := []struct {
		name   string
		mutate func(*contract.Bundle)
	}{
		{"items", func(decoded *contract.Bundle) {
			decoded.Evidence = make([]contract.EvidenceItem, 0)
			item := contract.EvidenceItem{}
			for len(decoded.Evidence) <= maxItemsForTest() {
				decoded.Evidence = append(decoded.Evidence, item)
			}
		}},
		{"images", func(decoded *contract.Bundle) {
			decoded.Images = make([]contract.ImageIdentity, 0)
			image := contract.ImageIdentity{}
			for len(decoded.Images) <= maxImagesForTest() {
				decoded.Images = append(decoded.Images, image)
			}
		}},
		{"elements", func(decoded *contract.Bundle) {
			decoded.ObservedContainerClasses = make([]contract.ContainerClass, 0)
			for len(decoded.ObservedContainerClasses) <= maxElementsForTest() {
				decoded.ObservedContainerClasses = append(decoded.ObservedContainerClasses, contract.ContainerRegular)
			}
		}},
		{"strings", func(decoded *contract.Bundle) {
			decoded.Provenance.Errors = []string{strings.Repeat("a", maxStringsForTest()+1)}
		}},
	}
	for _, testCase := range oversized {
		t.Run(testCase.name, func(t *testing.T) {
			model := base()
			testCase.mutate(&model)
			mutatedBytes := marshalForTest(t, model)
			encoded = false
			_, failure := decodeBundle(mutatedBytes)
			if failure == nil || failure.code != codeInputLimit {
				t.Fatalf("oversized %s failure = %+v, want input_limit", testCase.name, failure)
			}
			if encoded {
				t.Fatalf("canonical encoder ran for a bundle already over the %s budget", testCase.name)
			}
		})
	}
}

func TestBundleDepthLimit(t *testing.T) {
	deep := []byte(`{"a":` + strings.Repeat("[", 40) + strings.Repeat("]", 40) + `}`)
	if err := strictDepth(deep, maxInputDepth); err == nil {
		t.Fatalf("depth 41 admitted with limit 32")
	}
	atLimit := []byte(`{"a":` + strings.Repeat("[", 31) + strings.Repeat("]", 31) + `}`)
	if err := strictDepth(atLimit, maxInputDepth); err != nil {
		t.Fatalf("depth exactly 32 rejected: %v", err)
	}
	overLimit := []byte(`{"a":` + strings.Repeat("[", 32) + strings.Repeat("]", 32) + `}`)
	if err := strictDepth(overLimit, maxInputDepth); err == nil {
		t.Fatalf("depth 33 admitted with limit 32")
	}
	shallow := []byte(`{"a":[1,2,{"b":"c"}]}`)
	if err := strictDepth(shallow, maxInputDepth); err != nil {
		t.Fatalf("shallow document rejected: %v", err)
	}
}

// Delimiters inside strings are data, not nesting.
func TestStrictDepthIgnoresStrings(t *testing.T) {
	document := []byte(`{"note":"[[[[[[[[[[{}{}{}"}`)
	if err := strictDepth(document, 2); err != nil {
		t.Fatalf("delimiters inside a string counted as nesting: %v", err)
	}
}

func TestStrictFloorRejections(t *testing.T) {
	if err := strictFloor([]byte{0xEF, 0xBB, 0xBF, '{', '}'}); err == nil {
		t.Fatalf("BOM admitted")
	}
	if err := strictFloor([]byte{' ', 0xFF}); err == nil {
		t.Fatalf("invalid UTF-8 admitted")
	}
	if err := strictFloor(nil); err == nil {
		t.Fatalf("empty document admitted")
	}
}

// H08 regression: a complete surrogate pair is admitted whatever its position —
// including at the very end of the document — and only an unpaired half is
// rejected. Key order and length must not change the verdict.
func TestStrictSurrogatesPositionIndependent(t *testing.T) {
	admitted := []string{
		`{"a":"\ud83d\ude00"}`,
		`{"a":"\ud83d\ude00","b":1}`,
		`{"b":1,"a":"\ud83d\ude00"}`,
		`{"a":"x\ud83d\ude00"}`,
		`{"a":"\ud83d\ude00x"}`,
		`{"a":"\ud83d\ude00","b":{"c":"\ud83d\ude00"}}`,
	}
	for _, document := range admitted {
		if err := strictSurrogates([]byte(document)); err != nil {
			t.Errorf("valid pair rejected in %s: %v", document, err)
		}
	}
	rejected := []string{
		`{"a":"\ud83d"}`,
		`{"a":"\ude00"}`,
		`{"a":"\ud83d\ud83d"}`,
		`{"a":"\ud83dx"}`,
		`{"a":"\ud83d\u0041"}`,
	}
	for _, document := range rejected {
		if err := strictSurrogates([]byte(document)); err == nil {
			t.Errorf("unpaired surrogate admitted in %s", document)
		}
	}
}

// H09 regression: an empty string is a string for this decoder. The
// representational rules stay (H, T, N), and emptiness travels to the kernel.
func TestEmptyStringsAreNotADecoderRejection(t *testing.T) {
	document := []byte(`{"role":"","source":"","source_hash":"` + validHashA + `","advisory_id":null,"advisory_revision":null}`)
	pin, err := decodeSourcePin(document)
	if err != nil {
		t.Fatalf("empty strings rejected by the decoder: %v", err)
	}
	if pin.Role != "" || pin.Source != "" {
		t.Fatalf("empty strings were altered: %+v", pin)
	}
}
