package casefile

import (
	"bytes"
	"testing"
)

func TestWritePreparesBeforeDelivery(t *testing.T) {
	// An invalid book never reaches the writer.
	var zero Book
	counter := &countedWriter{}
	if err := Write(zero, counter); !IsCode(err, CodeInvalidBook) {
		t.Fatalf("zero book write: %v", err)
	}
	if counter.Calls != 0 {
		t.Fatalf("the writer was called %d times for an invalid book", counter.Calls)
	}

	// A valid book is delivered in exactly one call with the complete bytes.
	book := mustAppend(t, NewBook(), validInput())
	expected := mustEncode(t, book)
	counter = &countedWriter{}
	if err := Write(book, counter); err != nil {
		t.Fatalf("delivery failed: %v", err)
	}
	if counter.Calls != 1 {
		t.Fatalf("the writer was called %d times", counter.Calls)
	}
	if !bytes.Equal(counter.Data, expected) {
		t.Fatal("the delivered bytes differ from Encode")
	}
}

func TestWriteRejectsNilAndTypedNil(t *testing.T) {
	book := mustAppend(t, NewBook(), validInput())
	if err := Write(book, nil); !IsCode(err, CodeInvalidWriter) {
		t.Fatalf("plain nil writer: %v", err)
	}
	// The writer is checked first: a zero book with a nil writer is a writer
	// failure, never an invalid book.
	if err := Write(Book{}, nil); !IsCode(err, CodeInvalidWriter) {
		t.Fatalf("zero book with nil writer: %v", err)
	}
	if err := Write(Book{}, discardingWriter{}); !IsCode(err, CodeInvalidBook) {
		t.Fatalf("zero book with a healthy writer: %v", err)
	}
	var typedNil *bytes.Buffer
	if err := Write(book, typedNil); !IsCode(err, CodeInvalidWriter) {
		t.Fatalf("typed nil writer: %v", err)
	}
	if err := Write(book, &countedWriter{}); err != nil {
		t.Fatalf("a healthy writer was refused: %v", err)
	}
}

func TestWriteReportsFailuresAndShortWrites(t *testing.T) {
	book := mustAppend(t, NewBook(), validInput())

	if err := Write(book, failingWriter{Err: errDestination}); !IsCode(err, CodeWriteFailed) {
		t.Fatalf("failing writer: %v", err)
	}
	// A writer that returns zero without an error made a short delivery
	// (§7.3), not a failed one.
	if err := Write(book, failingWriter{}); !IsCode(err, CodeShortWrite) {
		t.Fatalf("writer returning zero without error: %v", err)
	}
	for _, count := range []int{-1, 0, 1, int(mustEncode(t, book)[0]), len(mustEncode(t, book)) - 1} {
		if err := Write(book, shortWriter{Count: count}); !IsCode(err, CodeShortWrite) {
			t.Fatalf("short write of %d bytes: %v", count, err)
		}
	}
	// No retry: a failing delivery produces exactly one call.
	failed := &failOnceWriter{}
	if err := Write(book, failed); !IsCode(err, CodeWriteFailed) {
		t.Fatalf("failing writer: %v", err)
	}
	if failed.calls != 1 {
		t.Fatalf("the writer was called %d times for one delivery", failed.calls)
	}
}

type failOnceWriter struct {
	calls int
}

func (writer *failOnceWriter) Write([]byte) (int, error) {
	writer.calls++
	return 0, errDestination
}
