package platform

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/d4rpell/Ariadne/internal/casefile"
)

const goldenAsOf = "2026-03-01T00:00:00Z"

// loadGoldenBook reads and verifies the frozen testdata book.
func loadGoldenBook(t *testing.T) casefile.Book {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("testdata", "book.json"))
	if err != nil {
		t.Fatalf("read testdata book: %v", err)
	}
	book, err := casefile.Verify(data)
	if err != nil {
		t.Fatalf("verify testdata book: %v", err)
	}
	return book
}

// hex64 builds one `sha256:` reference of 64 repeated characters.
func hex64(character byte) string {
	buffer := []byte("sha256:")
	for index := 0; index < 64; index++ {
		buffer = append(buffer, character)
	}
	return string(buffer)
}

// mustAppend appends one declaration or fails the test.
func mustAppend(t *testing.T, book casefile.Book, input casefile.DecisionInput) casefile.Book {
	t.Helper()
	next, err := casefile.Append(book, input)
	if err != nil {
		t.Fatalf("append: %v", err)
	}
	return next
}

// scopeOf builds a scope for one subject with the given vulnerability.
func scopeOf(uid, container, vulnerability string) casefile.Scope {
	return casefile.Scope{
		BundleHash:      hex64('1'),
		SubjectUID:      uid,
		ContainerName:   container,
		ContainerClass:  casefile.ContainerRegular,
		VulnerabilityID: vulnerability,
	}
}
