package ingest

import (
	"io"
	"strings"
	"testing"
	"time"

	contract "github.com/d4rpell/Ariadne/pkg/evidence"
)

// Context validation of ADR-0025 A.6 and A.10.3 §1. The tests assert the exact
// code and message, that the reader is never consumed while a context field is
// refused, and that the refusal happens before the acquisition.

// a201CountingReader records how many times it was read: a context failure must
// leave it untouched.
type a201CountingReader struct {
	reads int
	data  string
}

func (reader *a201CountingReader) Read(buffer []byte) (int, error) {
	reader.reads++
	if reader.data == "" {
		return 0, io.EOF
	}
	count := copy(buffer, reader.data)
	reader.data = reader.data[count:]
	if reader.data == "" {
		return count, io.EOF
	}
	return count, nil
}

func TestA201Context(t *testing.T) {
	t.Run("accepted", func(t *testing.T) {
		reader := &a201CountingReader{data: a201List()}
		result, err := ParseSanitizedPodList(reader, a201Context())
		if err != nil {
			t.Fatalf("ParseSanitizedPodList: %v", err)
		}
		if !result.PodListAccepted() {
			t.Fatal("a valid context and source were not admitted")
		}
		if reader.reads == 0 {
			t.Fatal("an admitted source was never read")
		}
	})

	t.Run("selector empty", func(t *testing.T) {
		a201RefusedBeforeRead(t, a201ContextWith(func(context *PodListContext) { context.Selector = "" }), "unsupported input selector")
	})
	t.Run("selector unknown", func(t *testing.T) {
		a201RefusedBeforeRead(t, a201ContextWith(func(context *PodListContext) { context.Selector = "sanitized-podlist-v2" }), "unsupported input selector")
	})
	t.Run("version empty", func(t *testing.T) {
		a201RefusedBeforeRead(t, a201ContextWith(func(context *PodListContext) { context.Version = "" }), "unsupported input version")
	})
	t.Run("version future", func(t *testing.T) {
		a201RefusedBeforeRead(t, a201ContextWith(func(context *PodListContext) { context.Version = "2.0" }), "unsupported input version")
	})
	t.Run("version with a leading zero", func(t *testing.T) {
		a201RefusedBeforeRead(t, a201ContextWith(func(context *PodListContext) { context.Version = "01.0" }), "unsupported input version")
	})
	t.Run("policy missing", func(t *testing.T) {
		a201RefusedBeforeRead(t, a201ContextWith(func(context *PodListContext) { context.RedactionPolicy = "" }), "required redaction policy was not acknowledged")
	})
	t.Run("policy different", func(t *testing.T) {
		a201RefusedBeforeRead(t, a201ContextWith(func(context *PodListContext) { context.RedactionPolicy = "sanitized-podlist-v1" }), "required redaction policy was not acknowledged")
	})
	t.Run("source alias dot", func(t *testing.T) {
		a201RefusedBeforeRead(t, a201ContextWith(func(context *PodListContext) { context.SourceName = "." }), "invalid observation context")
	})
	t.Run("source alias dot dot", func(t *testing.T) {
		a201RefusedBeforeRead(t, a201ContextWith(func(context *PodListContext) { context.SourceName = ".." }), "invalid observation context")
	})
	t.Run("source alias with a path separator", func(t *testing.T) {
		a201RefusedBeforeRead(t, a201ContextWith(func(context *PodListContext) { context.SourceName = "exports/pods.json" }), "invalid observation context")
	})
	t.Run("source alias leading punctuation", func(t *testing.T) {
		a201RefusedBeforeRead(t, a201ContextWith(func(context *PodListContext) { context.SourceName = "-pods.json" }), "invalid observation context")
	})
	t.Run("source alias too long", func(t *testing.T) {
		a201RefusedBeforeRead(t, a201ContextWith(func(context *PodListContext) { context.SourceName = strings.Repeat("a", 129) }), "invalid observation context")
	})
	t.Run("cluster alias invalid", func(t *testing.T) {
		a201RefusedBeforeRead(t, a201ContextWith(func(context *PodListContext) { context.ClusterAlias = "https://cluster" }), "invalid observation context")
	})
	t.Run("namespace empty", func(t *testing.T) {
		a201RefusedBeforeRead(t, a201ContextWith(func(context *PodListContext) { context.Namespace = "" }), "invalid observation context")
	})
	t.Run("namespace with surrounding whitespace", func(t *testing.T) {
		a201RefusedBeforeRead(t, a201ContextWith(func(context *PodListContext) { context.Namespace = "payments " }), "invalid observation context")
	})
	t.Run("namespace with a control character", func(t *testing.T) {
		a201RefusedBeforeRead(t, a201ContextWith(func(context *PodListContext) { context.Namespace = "pay\u0000ments" }), "invalid observation context")
	})
	t.Run("namespace with format character", func(t *testing.T) {
		a201RefusedBeforeRead(t, a201ContextWith(func(context *PodListContext) { context.Namespace = "pay\u200Bments" }), "invalid observation context")
	})
	t.Run("zero timestamp", func(t *testing.T) {
		a201RefusedBeforeRead(t, a201ContextWith(func(context *PodListContext) { context.ObservedAt = time.Time{} }), "invalid observation context")
	})
	t.Run("timestamp not in UTC", func(t *testing.T) {
		a201RefusedBeforeRead(t, a201ContextWith(func(context *PodListContext) {
			context.ObservedAt = time.Date(2026, 9, 30, 12, 0, 0, 0, time.FixedZone("CEST", 2*60*60))
		}), "invalid observation context")
	})
	t.Run("termination missing", func(t *testing.T) {
		a201RefusedBeforeRead(t, a201ContextWith(func(context *PodListContext) { context.CaptureTermination = "" }), "invalid observation context")
	})
	t.Run("termination unknown value", func(t *testing.T) {
		a201RefusedBeforeRead(t, a201ContextWith(func(context *PodListContext) {
			context.CaptureTermination = contract.CoverageTermination("partial")
		}), "invalid observation context")
	})
	t.Run("order stops at the selector", func(t *testing.T) {
		context := a201ContextWith(func(context *PodListContext) {
			context.Selector = "other"
			context.Version = ""
			context.RedactionPolicy = ""
		})
		_, err := a201ParseWith(t, a201List(), context)
		a201WantFailure(t, err, a201Literal(0, "unsupported input selector"))
	})
	t.Run("order checks the version after the selector", func(t *testing.T) {
		context := a201ContextWith(func(context *PodListContext) {
			context.Version = ""
			context.RedactionPolicy = ""
		})
		_, err := a201ParseWith(t, a201List(), context)
		a201WantFailure(t, err, a201Literal(0, "unsupported input version"))
	})
	t.Run("order checks the policy before the reader", func(t *testing.T) {
		context := a201ContextWith(func(context *PodListContext) { context.RedactionPolicy = "" })
		if _, err := ParseSanitizedPodList(nil, context); err == nil {
			t.Fatal("a refused context with a nil reader was admitted")
		} else {
			a201WantFailure(t, err, a201Literal(0, "required redaction policy was not acknowledged"))
		}
	})
}

// a201RefusedBeforeRead requires the context failure, an empty result and an
// untouched reader.
func a201RefusedBeforeRead(t *testing.T, context PodListContext, message string) {
	t.Helper()
	reader := &a201CountingReader{data: a201List()}
	result, err := ParseSanitizedPodList(reader, context)
	a201WantFailure(t, err, a201Literal(0, message))
	if reader.reads != 0 {
		t.Fatalf("the reader was consumed %d times before the context was validated", reader.reads)
	}
	if result.Source != nil || len(result.Subjects) != 0 || len(result.Rejections) != 0 {
		t.Fatal("a refused context produced publicable observations")
	}
	if result.TotalItems != nil {
		t.Fatal("a refused context produced a known item total")
	}
}
