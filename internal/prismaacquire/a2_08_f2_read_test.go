package prismaacquire

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
)

// Incremento 7 de A2-08-F2: lectura acotada y transaccional (ADR-0028 §6.11,
// §7.5–§7.6). Un prefijo válido seguido de truncamiento no constituye fuente; el
// byte de sondeo se contabiliza; cien lecturas sin progreso fallan.

type f2ZeroProgressReader struct{ n int }

func (r *f2ZeroProgressReader) Read([]byte) (int, error) { r.n++; return 0, nil }

type f2FailingReader struct {
	data []byte
	done bool
}

func (r *f2FailingReader) Read(p []byte) (int, error) {
	if !r.done {
		r.done = true
		return copy(p, r.data), nil
	}
	return 0, errors.New("synthetic failure")
}

type f2RecordingBody struct {
	read   bool
	closed bool
}

func (b *f2RecordingBody) Read([]byte) (int, error) { b.read = true; return 0, io.EOF }
func (b *f2RecordingBody) Close() error             { b.closed = true; return nil }

type f2CloseFailBody struct{}

func (f2CloseFailBody) Read([]byte) (int, error) { return 0, io.EOF }
func (f2CloseFailBody) Close() error             { return errors.New("close failure") }

func TestA208F2ReadTransactional(t *testing.T) {
	result, err := readBounded(io.NopCloser(strings.NewReader("abc")), 10, 10)
	if err != nil {
		t.Fatalf("clean read failed: %v", err)
	}
	if string(result.data) != "abc" || result.bytes != 3 {
		t.Fatalf("result = %q/%d, want abc/3", result.data, result.bytes)
	}

	_, err = readBounded(io.NopCloser(&f2FailingReader{data: []byte("ab")}), 10, 10)
	if err == nil || errors.Is(err, errBodyNoProgress) {
		t.Fatalf("truncated read: err = %v, want an underlying read failure", err)
	}
}

func TestA208F2ReadProbeAccounting(t *testing.T) {
	limit := 8
	exact := strings.Repeat("a", limit)
	result, err := readBounded(io.NopCloser(strings.NewReader(exact)), limit, 100)
	if err != nil {
		t.Fatalf("exact limit rejected: %v", err)
	}
	if result.bytes != uint64(limit) || len(result.data) != limit {
		t.Fatalf("exact read = %d/%d, want %d/%d", len(result.data), result.bytes, limit, limit)
	}

	_, err = readBounded(io.NopCloser(strings.NewReader(exact+"x")), limit, 100)
	if f2ReadCode(err) != CodeResponseLimit {
		t.Fatalf("L+1: err = %v, want %s", err, CodeResponseLimit)
	}

	_, err = readBounded(io.NopCloser(strings.NewReader("abcdef")), 10, 5)
	if f2ReadCode(err) != CodeByteLimit {
		t.Fatalf("accumulated excess: err = %v, want %s", err, CodeByteLimit)
	}
}

func TestA208F2ReadNoProgress(t *testing.T) {
	_, err := readBounded(io.NopCloser(&f2ZeroProgressReader{}), 8, 100)
	if !errors.Is(err, errBodyNoProgress) {
		t.Fatalf("no-progress read: err = %v, want the no-progress sentinel", err)
	}
}

// f2ReadCode extracts the closed diagnostic code from a bounded-read error,
// which may be a raw transport error before the connector classifies it.
func f2ReadCode(err error) string {
	var failure *AcquisitionError
	if errors.As(err, &failure) {
		return failure.Code
	}
	return ""
}

func TestA208F2BodyCloseFailure(t *testing.T) {
	a := &acquirer{ctx: context.Background()}
	resp := &http.Response{
		StatusCode: http.StatusOK,
		Header:     f2JSONHeader(),
		Body:       f2CloseFailBody{},
	}
	if _, err := a.readResponse(resp, 1024); err == nil || err.Code != CodeBodyReadFailed {
		t.Fatalf("close failure: err = %v, want %s", err, CodeBodyReadFailed)
	}
}

func TestA208F2ErrorBodyNotRead(t *testing.T) {
	body := &f2RecordingBody{}
	resp := &http.Response{StatusCode: http.StatusTooManyRequests, Header: http.Header{}, Body: body}
	a := &acquirer{ctx: context.Background()}
	_, err := a.readResponse(resp, 1024)
	if err == nil || err.Code != CodeRateLimited {
		t.Fatalf("429: err = %v, want %s", err, CodeRateLimited)
	}
	if body.read {
		t.Fatal("an error body was read")
	}
	if !body.closed {
		t.Fatal("an error body was not closed")
	}
}
