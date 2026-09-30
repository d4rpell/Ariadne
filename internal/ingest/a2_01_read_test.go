package ingest

import (
	"errors"
	"io"
	"strings"
	"testing"
)

// Bounded acquisition of ADR-0025 A.4, A.5.3 and A.10.3 §2. The tests use
// scripted readers so the sequence of returns is exact, and they always assert
// that a failed acquisition publishes nothing: no source, no hash, no
// observation and never the text of the underlying error.

// a201Step is one scripted read result.
type a201Step struct {
	data []byte
	err  error
}

// a201ScriptedReader returns the scripted steps in order and then EOF. Steps are
// shorter than the acquisition buffer of the profile.
type a201ScriptedReader struct {
	steps []a201Step
	index int
	reads int
}

func (reader *a201ScriptedReader) Read(buffer []byte) (int, error) {
	reader.reads++
	if reader.index >= len(reader.steps) {
		return 0, io.EOF
	}
	step := reader.steps[reader.index]
	reader.index++
	return copy(buffer, step.data), step.err
}

func TestA201Acquisition(t *testing.T) {
	t.Run("bytes then EOF", func(t *testing.T) {
		reader := &a201ScriptedReader{steps: []a201Step{{data: []byte(a201List()), err: io.EOF}}}
		result, err := ParseSanitizedPodList(reader, a201Context())
		if err != nil {
			t.Fatalf("ParseSanitizedPodList: %v", err)
		}
		if !result.PodListAccepted() {
			t.Fatal("a complete source was not admitted")
		}
		if result.Source.ByteCount != uint64(len(a201List())) {
			t.Fatalf("byte count = %d, want %d", result.Source.ByteCount, len(a201List()))
		}
	})

	t.Run("prefix then EOF without error", func(t *testing.T) {
		reader := &a201ScriptedReader{steps: []a201Step{{data: []byte(a201List()[:20])}, {data: []byte(a201List()[20:]), err: io.EOF}}}
		if _, err := ParseSanitizedPodList(reader, a201Context()); err != nil {
			t.Fatalf("ParseSanitizedPodList: %v", err)
		}
	})

	t.Run("bytes with an error", func(t *testing.T) {
		reader := &a201ScriptedReader{steps: []a201Step{{data: []byte("abc"), err: errors.New("marker-reader-secret")}}}
		result, err := ParseSanitizedPodList(reader, a201Context())
		a201WantFailure(t, err, a201Literal(3, "input read failed"))
		a201NoPublication(t, result)
		if strings.Contains(err.Error(), "marker-reader-secret") {
			t.Fatal("the original reader error was exposed")
		}
	})

	t.Run("error after a prefix", func(t *testing.T) {
		reader := &a201ScriptedReader{steps: []a201Step{{data: []byte("abc")}, {err: errors.New("marker-reader-secret")}}}
		result, err := ParseSanitizedPodList(reader, a201Context())
		a201WantFailure(t, err, a201Literal(3, "input read failed"))
		a201NoPublication(t, result)
		if strings.Contains(err.Error(), "marker-reader-secret") {
			t.Fatal("the original reader error was exposed")
		}
		if len(result.Diagnostics) != 0 {
			t.Fatal("a failed acquisition produced diagnostics with content")
		}
	})

	t.Run("empty source", func(t *testing.T) {
		reader := &a201ScriptedReader{}
		result, err := ParseSanitizedPodList(reader, a201Context())
		a201WantFailure(t, err, a201Literal(0, "invalid JSON structure"))
		a201NoPublication(t, result)
		if !result.LocalAborted {
			t.Fatal("a failed source examination did not mark the local processing as aborted")
		}
	})

	t.Run("whitespace only source", func(t *testing.T) {
		result, err := a201Parse(t, "   \n\t ")
		a201WantFailure(t, err, a201Literal(6, "invalid JSON structure"))
		a201NoPublication(t, result)
	})

	t.Run("prefix with invalid JSON is not published", func(t *testing.T) {
		document := a201List() + `{"apiVersion":"v1"}`
		result, err := a201Parse(t, document)
		a201WantFailure(t, err, a201Literal(uint64(len(a201List())), "invalid JSON structure"))
		a201NoPublication(t, result)
	})
}

// a201NoPublication asserts that a fatal failure exposed no publicable state.
func a201NoPublication(t *testing.T, result PodListResult) {
	t.Helper()
	if result.Source != nil {
		t.Fatal("a rejected source published an admitted source")
	}
	if result.TotalItems != nil {
		t.Fatal("a rejected source published an item total")
	}
	if len(result.Subjects) != 0 {
		t.Fatal("a rejected source published observations")
	}
	if len(result.Rejections) != 0 {
		t.Fatal("a rejected source published rejections")
	}
}
