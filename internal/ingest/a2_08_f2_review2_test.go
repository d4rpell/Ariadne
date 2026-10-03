package ingest

import (
	"strconv"
	"strings"
	"testing"

	"github.com/d4rpell/Ariadne/internal/schema"
)

// Discriminating tests for the second round of the A2-08-F2 review (R2-01,
// R2-03). Each case fails before its correction and passes after it.

// TestA208F2WriterTokenCountMatchesReplay pins that the derived-token count the
// shared writer reserves while emitting equals the replay admission (parseTree)
// of the same canonical bytes, so the two budgets can never disagree.
func TestA208F2WriterTokenCountMatchesReplay(t *testing.T) {
	cases := map[string]NativeSource{
		"offline_json_1_0": minimalJSONSource(),
		"offline_csv_1_0":  minimalCSVSource(),
		"api_json_1_1":     a208F2APISource(t),
		"api_json_many":    a208F2ManyRecordsSource(t),
	}
	for name, src := range cases {
		t.Run(name, func(t *testing.T) {
			full := EncodeNativeSource(src)
			want, ok := NativeSourceTokenCount(full)
			if !ok || want == 0 {
				t.Fatalf("replay token count = %d/%v", want, ok)
			}
			got, gotTokens, err := EncodeNativeSourceBudgeted(src, NativeOutputBudget{
				PageSourceBytes: 1 << 30, RetainedBytes: 1 << 30, DerivedTokens: 1 << 30,
			})
			if err != nil {
				t.Fatalf("budgeted encode failed: %v", err)
			}
			if string(got) != string(full) {
				t.Fatal("the budgeted encode changed the emitted bytes")
			}
			if gotTokens != want {
				t.Fatalf("writer tokens = %d, replay tokens = %d", gotTokens, want)
			}
		})
	}
}

// TestA208F2DerivedTokenReservedDuringEncoding proves the derived-token budget
// is reserved by the shared writer as it emits: an over-budget source aborts
// before the rest is built, and the diagnostic is token_limit, not only an error.
func TestA208F2DerivedTokenReservedDuringEncoding(t *testing.T) {
	src := a208F2APISource(t)
	full := EncodeNativeSource(src)
	total, ok := NativeSourceTokenCount(full)
	if !ok || total == 0 {
		t.Fatalf("token count = %d/%v", total, ok)
	}
	base := NativeOutputBudget{PageSourceBytes: 1 << 30, RetainedBytes: 1 << 30}

	t.Run("zero_is_active", func(t *testing.T) {
		b := base
		b.DerivedTokens = 0
		if _, _, err := EncodeNativeSourceBudgeted(src, b); err == nil || err.Code != NativeCodeTokenLimit {
			t.Fatalf("err = %v, want %s", err, NativeCodeTokenLimit)
		}
	})
	t.Run("L_minus_1_rejected", func(t *testing.T) {
		b := base
		b.DerivedTokens = total - 1
		if _, _, err := EncodeNativeSourceBudgeted(src, b); err == nil || err.Code != NativeCodeTokenLimit {
			t.Fatalf("err = %v, want %s", err, NativeCodeTokenLimit)
		}
	})
	t.Run("L_accepted", func(t *testing.T) {
		b := base
		b.DerivedTokens = total
		got, tokens, err := EncodeNativeSourceBudgeted(src, b)
		if err != nil {
			t.Fatalf("L rejected: %v", err)
		}
		if tokens != total || string(got) != string(full) {
			t.Fatalf("L = %d/%t, want %d/true", tokens, string(got) == string(full), total)
		}
	})

	// A tiny derived-token ceiling on a many-record source stops the writer long
	// before the full buffer would exist: this is the "previo" behaviour, not a
	// post-hoc measurement over an already built source.
	big := a208F2ManyRecordsSource(t)
	fullBig := EncodeNativeSource(big)
	var w nativeWriter
	w.limit = 1 << 30
	w.tokenActive = true
	w.tokenLimit = 25
	writeNativeSource(&w, big)
	if !w.tokenOver {
		t.Fatal("the writer did not stop on the derived-token budget")
	}
	if len(w.bytes()) >= len(fullBig)/2 {
		t.Fatalf("the writer built %d of %d bytes before rejecting", len(w.bytes()), len(fullBig))
	}
}

// a208F2ManyRecordsSource builds a 1.1 JSON source with enough records and
// members that a tiny token budget stops the writer early.
func a208F2ManyRecordsSource(t *testing.T) NativeSource {
	t.Helper()
	var b strings.Builder
	b.WriteByte('[')
	for i := 0; i < 40; i++ {
		if i > 0 {
			b.WriteByte(',')
		}
		b.WriteString(`{"type":"image","id":"id-` + strconv.Itoa(i) + `","packages":[],"vulnerabilities":[]}`)
	}
	b.WriteByte(']')
	draft, err := AdmitNativeJSON([]byte(b.String()), NativeAdmission{})
	if err != nil {
		t.Fatalf("admission failed: %v", err)
	}
	src := draft.Source(jsonProfile(), a208F2APIContext())
	src.Version = schema.NativeFormatVersionV11
	return src
}

// TestA208F2WriterStopsTraversalAfterTokenExhaustion proves the shared writer
// stops processing the source — it does not keep walking arrays or sorting
// objects — as soon as the derived-token budget is exhausted, instead of only
// refusing the finished buffer (§7.10). The observable is the count of value
// entries the writer actually started: a post-exhaustion traversal would count
// every remaining node, while an early stop stays bounded by the token budget.
func TestA208F2WriterStopsTraversalAfterTokenExhaustion(t *testing.T) {
	const items = 100_000
	build := func(n int) NativeSource {
		arr := make([]NativeValue, n)
		for i := range arr {
			arr[i] = NativeNull{}
		}
		return NativeSource{
			Profile: jsonProfile(),
			Context: a208F2APIContext(),
			Input:   NativeInput{SourceAlias: "fixture", NativeFormat: "json", OriginalBytes: 8},
			Records: []NativeRecord{{
				Ordinal:       0,
				OriginLocator: "json:/0",
				OriginStart:   1,
				OriginEnd:     7,
				Data: NativeObject{
					Keys:   []string{"packages"},
					Values: []NativeValue{NativeArray{Items: arr}},
				},
			}},
			Version: schema.NativeFormatVersionV11,
		}
	}
	emptyTokens, ok := NativeSourceTokenCount(EncodeNativeSource(build(0)))
	if !ok {
		t.Fatal("empty-array source token count failed")
	}
	full := build(items)
	total, ok := NativeSourceTokenCount(EncodeNativeSource(full))
	if !ok {
		t.Fatal("full source token count failed")
	}
	if total < uint64(items) {
		t.Fatalf("full token count = %d, want at least %d", total, items)
	}
	// A budget that exhausts a few items into the huge array.
	tokenLimit := emptyTokens + 10
	if total < tokenLimit*10 {
		t.Fatalf("token budget %d is not far below the full %d", tokenLimit, total)
	}
	var w nativeWriter
	w.limit = 1 << 30
	w.tokenActive = true
	w.tokenLimit = tokenLimit
	writeNativeSource(&w, full)
	if !w.tokenOver {
		t.Fatal("the writer did not stop on the derived-token budget")
	}
	if w.processed > tokenLimit+1 {
		t.Fatalf("the writer processed %d entries under a %d-token budget: it kept traversing the source after exhaustion", w.processed, tokenLimit)
	}
}

// TestA208F2StructuralTokenReservedBeforeByte pins that a structural comma or
// closing token is reserved before its byte is written: an exhaustion at that
// lexeme must not leave the byte in the buffer (§7.10).
func TestA208F2StructuralTokenReservedBeforeByte(t *testing.T) {
	var sepWriter nativeWriter
	sepWriter.tokenActive = true
	sepWriter.tokenLimit = 0
	sepWriter.sep()
	if !sepWriter.tokenOver || len(sepWriter.bytes()) != 0 {
		t.Fatalf("sep wrote %q before reserving its token", sepWriter.bytes())
	}
	var endWriter nativeWriter
	endWriter.tokenActive = true
	endWriter.tokenLimit = 0
	endWriter.end(']')
	if !endWriter.tokenOver || len(endWriter.bytes()) != 0 {
		t.Fatalf("end wrote %q before reserving its token", endWriter.bytes())
	}
}

// TestA208F2ActiveCeilingsClampToF1 pins that an active acquisition budget can
// only lower the F1 ceilings, never enlarge them, while an active zero stays a
// real zero ceiling.
func TestA208F2ActiveCeilingsClampToF1(t *testing.T) {
	huge := &nativeJSONParser{adm: NativeAdmission{Budget: NativeBudget{
		LimitsActive: true, Tokens: 99_000_000, Images: 10_001, Findings: 200_000, Packages: 200_000,
	}}}
	if got := huge.tokenCeiling(); got != uint64(schema.NativeMaxTokens) {
		t.Fatalf("token ceiling = %d, want %d", got, schema.NativeMaxTokens)
	}
	if got := huge.imageCeiling(); got != uint64(schema.NativeMaxRootItems) {
		t.Fatalf("image ceiling = %d, want %d", got, schema.NativeMaxRootItems)
	}
	if got := huge.findingCeiling(); got != uint64(schema.NativeMaxVulnsPerSource) {
		t.Fatalf("finding ceiling = %d, want %d", got, schema.NativeMaxVulnsPerSource)
	}
	if got := huge.packageCeiling(); got != uint64(schema.NativeMaxPackagesPerSource) {
		t.Fatalf("package ceiling = %d, want %d", got, schema.NativeMaxPackagesPerSource)
	}

	lower := &nativeJSONParser{adm: NativeAdmission{Budget: NativeBudget{
		LimitsActive: true, Tokens: 7, Images: 3, Findings: 5, Packages: 9,
	}}}
	if lower.tokenCeiling() != 7 || lower.imageCeiling() != 3 || lower.findingCeiling() != 5 || lower.packageCeiling() != 9 {
		t.Fatal("an active budget below the F1 limit was not honoured")
	}

	zero := &nativeJSONParser{adm: NativeAdmission{Budget: NativeBudget{LimitsActive: true}}}
	if zero.tokenCeiling() != 0 || zero.imageCeiling() != 0 || zero.findingCeiling() != 0 || zero.packageCeiling() != 0 {
		t.Fatal("an active zero ceiling must remain an exact zero")
	}

	inactive := &nativeJSONParser{adm: NativeAdmission{Budget: NativeBudget{Tokens: 5, Images: 3}}}
	if inactive.tokenCeiling() != 5 || inactive.imageCeiling() != 3 {
		t.Fatal("the offline path must still honour a smaller positive budget")
	}
}
