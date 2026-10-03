package ingest

import (
	"strings"
	"testing"

	"github.com/d4rpell/Ariadne/internal/schema"
)

// Contraejemplos locales del lote P2 de A2-08-F1 (ADR-0027 §11.9.1): el writer
// canónico se acota antes de crecer, el presupuesto de registro derivado mide
// el envelope completo, y los presupuestos léxicos derivados (clave 512/256,
// string 128 KiB fuente / 2 KiB manifiesto, número 10 bytes) se aplican por
// artefacto en replay. Estos tests sustituyen la revisión de detalle mecánico.

// a208Vuln builds one minimal valid vulnerability object.
func a208Vuln(pkgLen, vecLen int) NativeObject {
	return NativeObject{
		Keys: []string{"cve", "packageName", "vecStr"},
		Values: []NativeValue{
			NativeString("CVE-2026-1"),
			NativeString(strings.Repeat("a", pkgLen)),
			NativeString(strings.Repeat("b", vecLen)),
		},
	}
}

// a208ImageData builds a valid image object with bulk vulnerabilities of a fixed
// size plus one trailing pad vulnerability.
func a208ImageData(bulk int, pad NativeObject) NativeObject {
	vulns := NativeArray{}
	for i := 0; i < bulk; i++ {
		vulns.Items = append(vulns.Items, a208Vuln(1024, 4000))
	}
	vulns.Items = append(vulns.Items, pad)
	return NativeObject{
		Keys:   []string{"packages", "type", "vulnerabilities"},
		Values: []NativeValue{NativeArray{}, NativeString("image"), vulns},
	}
}

// a208Record wraps a data object in the declared record metadata that the schema
// validation accepts for a JSON profile.
func a208Record(data NativeValue) NativeRecord {
	return NativeRecord{Ordinal: 0, OriginLocator: "json:/0", OriginStart: 1, OriginEnd: 2, Data: data}
}

func a208Source(data NativeValue) NativeSource {
	return NativeSource{
		Profile: jsonProfile(),
		Context: validCtx(),
		Input:   NativeInput{SourceAlias: "fixture", NativeFormat: "json", OriginalBytes: 3},
		Records: []NativeRecord{a208Record(data)},
	}
}

// TestPrismaNativeBoundedWriter asserts that the canonical writer refuses to
// grow past a budget: L fits and L-1 is rejected without the buffer exceeding L.
func TestPrismaNativeBoundedWriter(t *testing.T) {
	src := a208Source(a208ImageData(1, a208Vuln(8, 8)))
	full := EncodeNativeSource(src)
	got, ok := EncodeNativeSourceBounded(src, len(full))
	if !ok || string(got) != string(full) {
		t.Fatalf("bounded source at L: ok=%v equal=%v", ok, string(got) == string(full))
	}
	over, ok := EncodeNativeSourceBounded(src, len(full)-1)
	if ok {
		t.Fatalf("bounded source accepted L-1")
	}
	if len(over) > len(full)-1 {
		t.Fatalf("bounded source grew past its limit: %d > %d", len(over), len(full)-1)
	}

	man := NativeManifest{
		SourceHash: "sha256:" + strings.Repeat("0", 64), SourceBytes: 1, OriginalBytes: 3,
		Profile: jsonProfile(), Counts: NativeCounts{Records: 1}, Limitations: []string{"documentary_profile"},
	}
	mfull := EncodeNativeManifest(man)
	mgot, ok := EncodeNativeManifestBounded(man, len(mfull))
	if !ok || string(mgot) != string(mfull) {
		t.Fatalf("bounded manifest at L: ok=%v equal=%v", ok, string(mgot) == string(mfull))
	}
	mover, ok := EncodeNativeManifestBounded(man, len(mfull)-1)
	if ok {
		t.Fatalf("bounded manifest accepted L-1")
	}
	if len(mover) > len(mfull)-1 {
		t.Fatalf("bounded manifest grew past its limit: %d > %d", len(mover), len(mfull)-1)
	}
}

// TestPrismaNativeRecordSizeCountsEnvelope asserts that the derived record budget
// measures the complete records[] envelope, not just the data object.
func TestPrismaNativeRecordSizeCountsEnvelope(t *testing.T) {
	rec := a208Record(NativeObject{Keys: []string{"type"}, Values: []NativeValue{NativeString("image")}})
	data := NativeValueSize(rec.Data)
	envelope := len([]byte(`{"ordinal":0,"origin_locator":"json:/0","origin_start":1,"origin_end":2,"data":}`))
	if got := NativeRecordSize(rec); got != data+envelope {
		t.Fatalf("NativeRecordSize = %d, want data(%d)+envelope(%d)", got, data, envelope)
	}
}

// TestPrismaNativeDerivedRecordFullEnvelope builds a record whose data object is
// within the 16 MiB budget but whose complete envelope exceeds it, and asserts
// the over-budget record is rejected while a near-limit fitting one is admitted.
func TestPrismaNativeDerivedRecordFullEnvelope(t *testing.T) {
	limit := schema.NativeMaxDerivedRecordBytes

	// Cost of one bulk vulnerability through NativeValueSize (includes the
	// array comma), measured with a tiny pad so the pad overhead cancels out.
	base := NativeValueSize(a208ImageData(0, a208Vuln(1, 1)))
	one := NativeValueSize(a208ImageData(1, a208Vuln(1, 1)))
	step := one - base
	if step <= 0 {
		t.Fatalf("bulk step = %d", step)
	}
	bulk := (limit - 40 - base) / step
	remainder := (limit - 40) - (base + bulk*step)
	if remainder < 0 || remainder > 1024+4096 {
		t.Fatalf("remainder %d outside the pad range", remainder)
	}
	pkg := remainder - 2 // the tiny pad in base already contributed 2 bytes
	if pkg < 0 {
		t.Fatalf("pad pkg = %d", pkg)
	}
	vec := 0
	if pkg > 1024 {
		vec = pkg - 1024
		pkg = 1024
	}
	if vec > 4096 {
		t.Fatalf("pad vec = %d exceeds its member budget", vec)
	}

	data := a208ImageData(bulk, a208Vuln(pkg, vec))
	dataSize := NativeValueSize(data)
	recordSize := NativeRecordSize(a208Record(data))
	if dataSize > limit {
		t.Fatalf("data %d exceeds the record budget", dataSize)
	}
	if recordSize <= limit {
		t.Fatalf("envelope not exercised: record=%d limit=%d", recordSize, limit)
	}
	if err := ValidateNativeSource(a208Source(data)); err == nil {
		t.Fatalf("full record over budget admitted (data=%d record=%d)", dataSize, recordSize)
	} else if err.Code != NativeCodeInvalidArtifact {
		t.Fatalf("code = %s, want invalid_artifact", err.Code)
	}

	fitting := a208ImageData(bulk-1, a208Vuln(0, 0))
	if rs := NativeRecordSize(a208Record(fitting)); rs > limit {
		t.Fatalf("fitting record unexpectedly over budget: %d", rs)
	}
	if err := ValidateNativeSource(a208Source(fitting)); err != nil {
		t.Fatalf("fitting record rejected: %v", err)
	}
}

// TestPrismaNativeDerivedLexicalBudgets asserts the per-artifact lexical budgets
// of §11.9.1 during replay: a key over 256 decoded bytes is key_limit (not a
// schema rejection), a manifest string over 2 KiB is string_limit while the same
// bytes are admitted by the source budget, and an 11-byte number token is
// number_limit.
func TestPrismaNativeDerivedLexicalBudgets(t *testing.T) {
	t.Run("decoded_key", func(t *testing.T) {
		key := strings.Repeat("a", schema.NativeMaxDerivedKeyDecodedBytes+1)
		if _, err := ParseNativeSourceBytes([]byte(`{"` + key + `":0}`)); err == nil || err.Code != NativeCodeKeyLimit {
			t.Fatalf("source err = %v, want key_limit", err)
		}
		if _, _, err := ParseNativeManifestBytes([]byte(`{"` + key + `":0}`)); err == nil || err.Code != NativeCodeKeyLimit {
			t.Fatalf("manifest err = %v, want key_limit", err)
		}
	})
	t.Run("per_artifact_string_budget", func(t *testing.T) {
		body := `{"x":"` + strings.Repeat("a", 3000) + `"}`
		if _, _, err := ParseNativeManifestBytes([]byte(body)); err == nil || err.Code != NativeCodeStringLimit {
			t.Fatalf("manifest err = %v, want string_limit", err)
		}
		if _, err := ParseNativeSourceBytes([]byte(body)); err == nil || err.Code == NativeCodeStringLimit {
			t.Fatalf("source err = %v, want not string_limit", err)
		}
	})
	t.Run("number_token", func(t *testing.T) {
		if _, _, err := ParseNativeManifestBytes([]byte(`{"x":12345678901}`)); err == nil || err.Code != NativeCodeNumberLimit {
			t.Fatalf("err = %v, want number_limit", err)
		}
	})
	t.Run("key_over_string_budget", func(t *testing.T) {
		// 2047 chars: below the manifest string budget (2 KiB) but above the key
		// budget (512 raw / 256 decoded), so it must be key_limit, not string_limit.
		key := strings.Repeat("a", 2047)
		if _, _, err := ParseNativeManifestBytes([]byte(`{"` + key + `":0}`)); err == nil || err.Code != NativeCodeKeyLimit {
			t.Fatalf("err = %v, want key_limit", err)
		}
	})
	t.Run("decoded_key_before_escape", func(t *testing.T) {
		// 257 decoded bytes then an invalid escape: the decoded key budget must
		// fire before the escape is read (§11.9.1, §12.4.5).
		body := `{"` + strings.Repeat("a", 257) + `\q":0}`
		if _, _, err := ParseNativeManifestBytes([]byte(body)); err == nil || err.Code != NativeCodeKeyLimit {
			t.Fatalf("err = %v, want key_limit", err)
		}
	})
	t.Run("replay_key_token_budget", func(t *testing.T) {
		// A key must count against the parser's own token budget, not the native
		// 8M ceiling: with tokenLimit=1 and one token already spent, reading the
		// key crosses the budget.
		var p nativeJSONParser
		p.data = []byte(`"k"`)
		p.tokenLimit = 1
		p.tokens = 1
		if _, err := p.parseStructuralKey(); err == nil || err.Code != NativeCodeTokenLimit {
			t.Fatalf("err = %v, want token_limit", err)
		}
	})
}

// TestPrismaNativeBoundedWriterNeverExceeds is a property check over every limit:
// the canonical writer never returns a buffer larger than its budget, including
// on the optional-integer (optInt) path.
func TestPrismaNativeBoundedWriterNeverExceeds(t *testing.T) {
	one, two := 1, 2
	ctx := validCtx()
	ctx.PageOrdinal = &one
	ctx.PagesExpected = &two
	src := a208Source(a208ImageData(1, a208Vuln(8, 8)))
	src.Context = ctx
	full := EncodeNativeSource(src)
	for limit := 1; limit <= len(full); limit++ {
		out, ok := EncodeNativeSourceBounded(src, limit)
		if len(out) > limit {
			t.Fatalf("limit %d: writer grew to %d", limit, len(out))
		}
		if (limit == len(full)) != ok {
			t.Fatalf("limit %d: ok = %v", limit, ok)
		}
	}
}
