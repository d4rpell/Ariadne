package prismaacquire

import (
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/d4rpell/Ariadne/internal/ingest"
)

// Incremento 8 de A2-08-F2: presupuestos y contabilidad acumulada (ADR-0028 §7,
// §13.5). Los límites son constantes de producción; la autenticación y la página
// vacía terminal se cuentan.

func TestA208F2BudgetConstants(t *testing.T) {
	checks := []struct {
		name string
		got  int
		want int
	}{
		{"total_attempts", maxTotalAttempts, 129},
		{"auth_attempts", maxAuthAttempts, 1},
		{"image_get_attempts", maxImageGETAttempts, 128},
		{"images_per_page", maxImagesPerPage, 50},
		{"image_occurrences", maxImageOccurrences, 5000},
		{"finding_occurrences", maxFindingOccurrences, 100_000},
		{"package_occurrences", maxPackageOccurrences, 100_000},
		{"native_tokens", maxNativeTokens, 8_000_000},
		{"accumulated_body", maxAccumulatedBodyBytes, 64 * 1024 * 1024},
		{"image_response", maxImageResponseBytes, 16 * 1024 * 1024},
		{"auth_response", maxAuthResponseBytes, 64 * 1024},
		{"response_headers", maxResponseHeaderBytes, 32 * 1024},
		{"request_duration", maxRequestDuration, 10 * int(time.Second)},
		{"spacing", minRequestSpacing, 1250 * int(time.Millisecond)},
	}
	for _, c := range checks {
		if c.got != c.want {
			t.Errorf("%s = %d, want %d", c.name, c.got, c.want)
		}
	}
}

func TestA208F2AttemptAccounting(t *testing.T) {
	t.Run("bearer_zero_post", func(t *testing.T) {
		result, err := f2Run(t, f2Config(), f2Bearer(), f2Steps(f2DistinctPage(0, 3), "[]"))
		if err != nil {
			t.Fatalf("bearer sequence failed: %v", err)
		}
		if result.Attempts.Auth != 0 {
			t.Fatalf("auth attempts = %d, want 0", result.Attempts.Auth)
		}
		if result.Attempts.Total != 2 || result.Attempts.ImageGET != 2 {
			t.Fatalf("total/get = %d/%d, want 2/2", result.Attempts.Total, result.Attempts.ImageGET)
		}
	})
	t.Run("password_single_post", func(t *testing.T) {
		cfg := f2Config()
		cfg.AuthMode = AuthPasswordExchange
		cred := Credential{Reference: "cred-1", Username: "u", Password: "p"}
		script := &f2Sequenced{steps: []f2SequencedStep{
			{status: 200, body: io.NopCloser(strings.NewReader(`{"token":"synthetic.token"}`))},
			{status: 200, body: io.NopCloser(strings.NewReader("[]"))},
		}}
		result, err := f2Run(t, cfg, cred, script)
		if err != nil {
			t.Fatalf("password sequence failed: %v", err)
		}
		if result.Attempts.Auth != 1 || result.Attempts.Total != 2 || result.Attempts.ImageGET != 1 {
			t.Fatalf("attempts = auth:%d total:%d get:%d, want 1/2/1", result.Attempts.Auth, result.Attempts.Total, result.Attempts.ImageGET)
		}
		if script.requests[0].Method != http.MethodPost {
			t.Fatalf("first request method = %s, want POST", script.requests[0].Method)
		}
	})
}

func TestA208F2AccumulatedBudgets(t *testing.T) {
	b := budget{images: maxImageOccurrences - 1}
	if err := b.addDraft(ingest.NativeAccounting{Images: 1}); err != nil {
		t.Fatalf("L admitted: %v", err)
	}
	if err := b.addDraft(ingest.NativeAccounting{Images: 1}); err == nil || err.Code != CodeObjectLimit {
		t.Fatalf("L+1: err = %v, want %s", err, CodeObjectLimit)
	}
	tb := budget{tokens: maxNativeTokens - 1}
	if err := tb.addDraft(ingest.NativeAccounting{Tokens: 1}); err != nil {
		t.Fatalf("token L admitted: %v", err)
	}
	if err := tb.addDraft(ingest.NativeAccounting{Tokens: 1}); err == nil || err.Code != CodeTokenLimit {
		t.Fatalf("token L+1: err = %v, want %s", err, CodeTokenLimit)
	}
}

func TestA208F2BudgetPrecedence(t *testing.T) {
	// The accumulated image budget is carried as an active, exact ceiling and the
	// structural per-page cap is carried separately, so a page over 50 records is
	// classified as page_size_exceeded rather than an accumulated object_limit.
	b := budget{}
	nb := b.nativeBudget()
	if !nb.LimitsActive {
		t.Fatal("the acquisition budget must be active so a zero ceiling is a real ceiling")
	}
	if nb.Images != maxImageOccurrences {
		t.Fatalf("native budget images = %d, want %d", nb.Images, maxImageOccurrences)
	}
	if nb.PageImages != maxImagesPerPage {
		t.Fatalf("page image cap = %d, want %d", nb.PageImages, maxImagesPerPage)
	}
	small := budget{images: maxImageOccurrences - 10}
	if got := small.nativeBudget().Images; got != 10 {
		t.Fatalf("remaining image budget = %d, want 10", got)
	}
}
