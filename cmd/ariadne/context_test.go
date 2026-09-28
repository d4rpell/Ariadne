package main

import (
	"encoding/json"
	"strings"
	"testing"
)

// IN-02: the context decoder. Each case mutates one documented fact of the
// ratified context and expects contexts_decode/invalid_context; the exact
// positive control (the composed fixture context) proves the decoder is not
// rejecting everything.

func validContextDocument(t *testing.T) map[string]any {
	t.Helper()
	figures := composeFixture(t, "F09-unmapped-redhat-package")
	data := readTemp(t, figures.context)
	var document map[string]any
	if err := json.Unmarshal(data, &document); err != nil {
		t.Fatalf("composed context is not JSON: %v", err)
	}
	return document
}

func mutateContext(t *testing.T, mutate func(map[string]any)) []byte {
	t.Helper()
	document := validContextDocument(t)
	mutate(document)
	data, err := json.Marshal(document)
	if err != nil {
		t.Fatalf("mutated context: %v", err)
	}
	return data
}

func TestContextDecodePositiveControl(t *testing.T) {
	document := validContextDocument(t)
	if _, err := decodeContext(mustJSON(t, document)); err != nil {
		t.Fatalf("composed fixture context rejected: %v", err)
	}
}

func mustJSON(t *testing.T, value any) []byte {
	t.Helper()
	data, err := json.Marshal(value)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return data
}

func TestContextRejections(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(map[string]any)
	}{
		{"target missing", func(d map[string]any) { delete(d, "target") }},
		{"admission missing", func(d map[string]any) { delete(d, "admission") }},
		{"domain missing", func(d map[string]any) { delete(d, "domain") }},
		{"unknown root member", func(d map[string]any) { d["extra"] = 1 }},
		{"target member missing", func(d map[string]any) {
			delete(d["target"].(map[string]any), "locator")
		}},
		{"target member unknown", func(d map[string]any) {
			d["target"].(map[string]any)["extra"] = "x"
		}},
		{"target member duplicated in bytes", nil},
		{"target member null", func(d map[string]any) {
			d["target"].(map[string]any)["source"] = nil
		}},
		{"target member wrong type", func(d map[string]any) {
			d["target"].(map[string]any)["subject_uid"] = 7
		}},
		{"admission member missing", func(d map[string]any) {
			delete(d["admission"].(map[string]any), "previous")
		}},
		{"previous null vs missing", func(d map[string]any) {
			delete(d["admission"].(map[string]any), "previous")
			d["admission"].(map[string]any)["previous_"] = nil
		}},
		{"previous unknown member", func(d map[string]any) {
			d["admission"].(map[string]any)["previous"] = map[string]any{
				"version": 1, "hash": validHashA, "extra": true,
			}
		}},
		{"minimum_version zero", func(d map[string]any) {
			d["admission"].(map[string]any)["minimum_version"] = 0
		}},
		{"minimum_version negative", func(d map[string]any) {
			d["admission"].(map[string]any)["minimum_version"] = -1
		}},
		{"minimum_version fractional", func(d map[string]any) {
			d["admission"].(map[string]any)["minimum_version"] = 1.5
		}},
		{"minimum_version exponent", nil},
		{"minimum_version string", func(d map[string]any) {
			d["admission"].(map[string]any)["minimum_version"] = "1"
		}},
		{"minimum_version above ceiling", func(d map[string]any) {
			d["admission"].(map[string]any)["minimum_version"] = float64(1<<53 + 1)
		}},
		{"evaluated_at with offset", func(d map[string]any) {
			d["admission"].(map[string]any)["evaluated_at"] = "2026-10-01T14:00:00+02:00"
		}},
		{"evaluated_at not canonical", func(d map[string]any) {
			d["admission"].(map[string]any)["evaluated_at"] = "2026-10-01T12:00:00.000Z"
		}},
		{"evaluated_at zero", func(d map[string]any) {
			d["admission"].(map[string]any)["evaluated_at"] = "0001-01-01T00:00:00Z"
		}},
		{"source_hash malformed", func(d map[string]any) {
			d["target"].(map[string]any)["source_hash"] = "sha256:ABC"
		}},
		{"expected_pack_hash uppercase", func(d map[string]any) {
			d["admission"].(map[string]any)["expected_pack_hash"] =
				"sha256:492D5D023C5180E1CD2073B2F2ABF25BA944134C6B9C343E559005CD68A276D1"
		}},
		{"domain pins null", func(d map[string]any) {
			d["domain"].(map[string]any)["source_pins"] = nil
		}},
		{"domain pin null element", func(d map[string]any) {
			d["domain"].(map[string]any)["source_pins"] = []any{nil}
		}},
		{"domain pin member missing", func(d map[string]any) {
			pin := d["domain"].(map[string]any)["source_pins"].([]any)[0].(map[string]any)
			delete(pin, "advisory_id")
		}},
		{"domain pin member unknown", func(d map[string]any) {
			pin := d["domain"].(map[string]any)["source_pins"].([]any)[0].(map[string]any)
			pin["extra"] = "x"
		}},
		{"domain age zero", func(d map[string]any) {
			d["domain"].(map[string]any)["maximum_evidence_age_seconds"] = 0
		}},
		{"domain unknown member", func(d map[string]any) {
			d["domain"].(map[string]any)["extra"] = true
		}},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			var data []byte
			switch testCase.name {
			case "target member duplicated in bytes":
				base := string(mustJSON(t, validContextDocument(t)))
				data = []byte(strings.Replace(base, `"subject_uid":`, `"subject_uid":"dup","subject_uid":`, 1))
			case "minimum_version exponent":
				base := string(mustJSON(t, validContextDocument(t)))
				data = []byte(strings.Replace(base, `"minimum_version":1`, `"minimum_version":1e2`, 1))
			default:
				data = mutateContext(t, testCase.mutate)
			}
			if _, err := decodeContext(data); err == nil {
				t.Fatalf("context was admitted; want rejection")
			}
		})
	}
}

// The rejected context through the full CLI surfaces as
// context_decode/invalid_context with exit 3, after the bundle was already read
// and decoded successfully.
func TestContextFailureEndToEnd(t *testing.T) {
	figures := composeFixture(t, "F09-unmapped-redhat-package")
	bad := mutateContextPath(t, func(d map[string]any) {
		d["target"].(map[string]any)["observed_at"] = "2026-09-20T10:00:00+00:00"
	})
	argv := []string{"evaluate",
		"--bundle", figures.bundle, "--bundle-hash", figures.bundleHash,
		"--pack", figures.pack, "--context", bad}
	expectRejection(t, argv, stageContextDecode, codeInvalidContext, 3)
}

func mutateContextPath(t *testing.T, mutate func(map[string]any)) string {
	t.Helper()
	document := validContextDocument(t)
	mutate(document)
	return writeTemp(t, "context.json", mustJSON(t, document))
}
