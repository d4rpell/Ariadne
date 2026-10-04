package casefile

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestVerifyRecomputesEntireChain(t *testing.T) {
	book := NewBook()
	for index := 0; index < 3; index++ {
		book = mustAppend(t, book, validInput())
	}
	document := mustEncode(t, book)
	elements := recordElements(t, document)

	// Corruption at the head must be caught even though the tail is intact:
	// no check may trust the stored hashes or only inspect the head.
	for index, element := range elements {
		tamperedElement := strings.Replace(element, "CHG-0001", "CHG-0002", 1)
		if tamperedElement == element {
			t.Fatalf("fixture %d does not contain the marker", index)
		}
		others := make([]string, 0, len(elements))
		for position, candidate := range elements {
			if position == index {
				others = append(others, tamperedElement)
			} else {
				others = append(others, candidate)
			}
		}
		rebuilt := rebuildDocument(t, document, strings.Join(others, ","))
		_, err := Verify(rebuilt)
		if !IsCode(err, CodeHashMismatch) {
			t.Fatalf("tampered record %d: %v", index, err)
		}
	}
}

func TestVerifyRejectsRecordReorderingAndInteriorRemoval(t *testing.T) {
	book := NewBook()
	for index := 0; index < 3; index++ {
		book = mustAppend(t, book, validInput())
	}
	document := mustEncode(t, book)
	elements := recordElements(t, document)

	// Reversal, interior removal and swapping all land on the sequence rule
	// first (§5.4: sequence precedes the predecessor relation).
	reversed := rebuildDocument(t, document,
		elements[2]+","+elements[1]+","+elements[0])
	if _, err := Verify(reversed); !IsCode(err, CodeInvalidSequence) {
		t.Fatalf("reversed records: %v", err)
	}
	removed := rebuildDocument(t, document,
		elements[0]+","+elements[2])
	if _, err := Verify(removed); !IsCode(err, CodeInvalidSequence) {
		t.Fatalf("interior removal: %v", err)
	}
	swapped := rebuildDocument(t, document,
		elements[1]+","+elements[0]+","+elements[2])
	if _, err := Verify(swapped); !IsCode(err, CodeInvalidSequence) {
		t.Fatalf("swapped records: %v", err)
	}

	// A sequence renumbered to fit is caught one rule later: the record still
	// links to its old predecessor, and that is chain_mismatch.
	renumbered := strings.Replace(elements[2], `"sequence":3`, `"sequence":2`, 1)
	relinked := rebuildDocument(t, document, elements[0]+","+renumbered)
	if _, err := Verify(relinked); !IsCode(err, CodeChainMismatch) {
		t.Fatalf("renumbered record: %v", err)
	}
}

func TestVerifyRejectsInvalidFinalRecordWithoutPrefix(t *testing.T) {
	book := mustAppend(t, mustAppend(t, NewBook(), validInput()), validInput())
	document := mustEncode(t, book)
	elements := recordElements(t, document)

	tampered := strings.Replace(elements[1], "CHG-0001", "CHG-0002", 1)
	rebuilt := rebuildDocument(t, document, elements[0]+","+tampered)
	result, err := Verify(rebuilt)
	if !IsCode(err, CodeHashMismatch) {
		t.Fatalf("tampered tail: %v", err)
	}
	if result.initialized {
		t.Fatal("a rejected book was returned as admitted")
	}
	if _, err := Records(result); !IsCode(err, CodeInvalidBook) {
		t.Fatalf("the rejected result must refuse every operation: %v", err)
	}
}

// rebuildDocument returns a book document whose records array body is
// replacement, sharing everything else with the source document.
func rebuildDocument(t *testing.T, document []byte, replacement string) []byte {
	t.Helper()
	start := bytes.Index(document, []byte(`"records":[`))
	if start < 0 {
		t.Fatal("malformed fixture document")
	}
	rebuilt := append([]byte{}, document[:start+len(`"records":[`)]...)
	rebuilt = append(rebuilt, replacement...)
	rebuilt = append(rebuilt, ']', '}')
	return rebuilt
}

func TestVerifyRejectsNoncanonicalEncoding(t *testing.T) {
	base := string(mustEncode(t, mustAppend(t, NewBook(), validInput())))
	cases := map[string]string{
		"leading space":         " " + base,
		"trailing newline":      base + "\n",
		"trailing spaces":       base + "  ",
		"bom":                   "\ufeff" + base,
		"space after colon":     strings.Replace(base, `"records":[`, `"records": [`, 1),
		"colon spacing":         strings.Replace(base, `,"version":`, `,"version": `, 1),
		"alternate escape":      strings.Replace(base, `"sequence":1`, `"sequence":01`, 1),
		"float sequence":        strings.Replace(base, `"sequence":1`, `"sequence":1.0`, 1),
		"string sequence":       strings.Replace(base, `"sequence":1`, `"sequence":"1"`, 1),
		"unicode escape owner":  strings.Replace(base, `platform owner`, `platform on\u0065`, 1),
		"escaped slash":         strings.Replace(base, `"controls":[`, `"controls":[\"x\",`, 1),
		"null records":          strings.Replace(base, `"records":[`, `"records":null,`, 1),
		"nested extra object":   strings.Replace(base, `"controls":[`, `"controls":{"a":1},`, 1),
		"raw control character": strings.Replace(base, `"decided_at":"`, "\"decided_at\":\"\n", 1),
	}
	for name, document := range cases {
		if _, err := Verify([]byte(document)); !IsCode(err, CodeInvalidEncoding) {
			t.Fatalf("%s admitted: %v", name, err)
		}
	}
	// Uppercase hexadecimal is a malformed hash for this profile:
	// invalid_reference, never a repaired digest.
	probe := mustAppend(t, NewBook(), validInput())
	probeRecords, _ := Records(probe)
	storedHash := probeRecords[0].Hash
	uppercased := "sha256:" + strings.ToUpper(storedHash[len("sha256:"):len("sha256:")+8]) + storedHash[len("sha256:")+8:]
	uppercaseHex := strings.Replace(base, storedHash, uppercased, 1)
	if _, err := Verify([]byte(uppercaseHex)); !IsCode(err, CodeInvalidReference) {
		t.Fatalf("uppercase digest: %v", err)
	}
}

func TestVerifyRejectsUnknownMissingAndDuplicateFields(t *testing.T) {
	base := string(mustEncode(t, mustAppend(t, NewBook(), validInput())))

	unknown := strings.Replace(base, `{"format":"`+BookFormat, `{"extra":1,"format":"`+BookFormat, 1)
	if _, err := Verify([]byte(unknown)); !IsCode(err, CodeInvalidEncoding) {
		t.Fatalf("unknown book key admitted: %v", err)
	}
	recordUnknown := strings.Replace(base, `"decided_at":`, `"unsupported":true,"decided_at":`, 1)
	if _, err := Verify([]byte(recordUnknown)); !IsCode(err, CodeInvalidEncoding) {
		t.Fatalf("unknown record key admitted: %v", err)
	}
	scopeUnknown := strings.Replace(base, `"vulnerability_id":`, `"cluster":"x","vulnerability_id":`, 1)
	if _, err := Verify([]byte(scopeUnknown)); !IsCode(err, CodeInvalidEncoding) {
		t.Fatalf("unknown scope key admitted: %v", err)
	}

	missing := strings.Replace(base, `"expires_at":null,`, ``, 1)
	if _, err := Verify([]byte(missing)); !IsCode(err, CodeInvalidEncoding) {
		t.Fatalf("missing record key admitted: %v", err)
	}
	scopeMissing := strings.Replace(base, `"container_class":"regular",`, ``, 1)
	if _, err := Verify([]byte(scopeMissing)); !IsCode(err, CodeInvalidEncoding) {
		t.Fatalf("missing scope key admitted: %v", err)
	}

	duplicated := strings.Replace(base, `"decided_at":"2026-10-04T12:00:00Z"`, `"decided_at":"2026-10-04T12:00:00Z","decided_at":"2026-10-04T12:00:00Z"`, 1)
	if _, err := Verify([]byte(duplicated)); !IsCode(err, CodeInvalidEncoding) {
		t.Fatalf("duplicated key admitted: %v", err)
	}

	caseChanged := strings.Replace(base, `"owner":`, `"Owner":`, 1)
	if _, err := Verify([]byte(caseChanged)); !IsCode(err, CodeInvalidEncoding) {
		t.Fatalf("case-different key admitted: %v", err)
	}

	wrongOrder := swapKeys(t, base, `"owner"`, `"approver"`)
	if _, err := Verify([]byte(wrongOrder)); !IsCode(err, CodeInvalidEncoding) {
		t.Fatalf("reordered keys admitted: %v", err)
	}
}

// swapKeys exchanges the first occurrence of two complete "key":value pairs.
func swapKeys(t *testing.T, document, first, second string) string {
	t.Helper()
	firstStart := strings.Index(document, first+`:`)
	secondStart := strings.Index(document, second+`:`)
	if firstStart < 0 || secondStart < 0 || secondStart < firstStart {
		t.Fatal("swap fixture is malformed")
	}
	firstEnd := firstStart + strings.Index(document[firstStart:], `,`)
	secondEnd := secondStart + strings.Index(document[secondStart:], `,`)
	return document[:firstStart] + document[secondStart:secondEnd] + "," +
		document[firstStart:firstEnd] + document[secondEnd:]
}

func TestCanonicalBookGoldenVectors(t *testing.T) {
	vectors := []struct {
		book    string
		records int
	}{
		{"v-empty", 0},
		{"v-one", 1},
		{"v-three", 3},
		{"v-supersedes", 2},
	}
	for _, vector := range vectors {
		t.Run(vector.book, func(t *testing.T) {
			expected, err := os.ReadFile(filepath.Join("testdata", vector.book+".book.json"))
			if err != nil {
				t.Fatal(err)
			}
			parsed, err := Verify(expected)
			if err != nil {
				t.Fatalf("the frozen vector must verify: %v", err)
			}
			if !bytes.Equal(mustEncode(t, parsed), expected) {
				t.Fatal("re-encoding the verified book diverged from the vector")
			}
			records, err := Records(parsed)
			if err != nil {
				t.Fatal(err)
			}
			if len(records) != vector.records {
				t.Fatalf("vector holds %d records, want %d", len(records), vector.records)
			}
			for index, record := range records {
				preimage, err := os.ReadFile(filepath.Join("testdata", vector.book+".r"+itoa(index+1)+".preimage.json"))
				if err != nil {
					t.Fatal(err)
				}
				if !bytes.Equal(recordPreimage(record), preimage) {
					t.Fatalf("record %d preimage diverged from the frozen vector", index+1)
				}
				digest := sha256.Sum256(preimage)
				computed := "sha256:" + hex.EncodeToString(digest[:])
				stored, err := os.ReadFile(filepath.Join("testdata", vector.book+".r"+itoa(index+1)+".sha256.txt"))
				if err != nil {
					t.Fatal(err)
				}
				if computed != string(stored) {
					t.Fatalf("record %d: recomputed %s, frozen %s", index+1, computed, stored)
				}
				if record.Hash != computed {
					t.Fatalf("record %d hash is not the digest of its preimage", index+1)
				}
			}
		})
	}
}

func itoa(value int) string {
	return string(rune('0' + value))
}
