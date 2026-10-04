package casefile

import "io"

// NewBook returns the empty, valid book.
func NewBook() Book {
	return Book{initialized: true, bytes: len(emptyBookDocument)}
}

// Append validates the whole book and the new declaration and returns a new,
// independent book with exactly one more record. The receiver is never
// modified: a failed append leaves it byte-for-byte intact. Repeating an
// identical input is not idempotent; it adds another record.
func Append(book Book, input DecisionInput) (Book, error) {
	if !book.initialized {
		return Book{}, problem(CodeInvalidBook)
	}
	if err := validateChain(book.records); err != nil {
		return Book{}, err
	}
	if len(book.records) >= MaxRecords {
		return Book{}, problem(CodeBookLimit)
	}
	if err := validateInput(input); err != nil {
		return Book{}, err
	}
	if input.Supersedes != nil && !hashExists(book.records, *input.Supersedes) {
		return Book{}, problem(CodeInvalidReference)
	}

	record := buildRecord(book.records, input)
	envelope := recordEnvelope(record)
	if len(envelope) > MaxRecordBytes {
		return Book{}, problem(CodeRecordLimit)
	}
	growth := len(envelope)
	if len(book.records) > 0 {
		growth++
	}
	if book.bytes+growth > MaxBookBytes {
		return Book{}, problem(CodeBookLimit)
	}

	records := make([]Record, len(book.records), len(book.records)+1)
	copy(records, book.records)
	records = append(records, record)
	return Book{initialized: true, records: records, bytes: book.bytes + growth}, nil
}

// Verify is the only path from bytes back to a book: it parses the canonical
// document with a schema-directed reader, validates every record, recomputes
// the whole hash chain and only then compares the rebuilt document with the
// input byte for byte. A defect anywhere refuses the complete book; no prefix
// is ever returned as success.
func Verify(data []byte) (Book, error) {
	return verifyBook(data)
}

// Encode returns the canonical bytes of the book.
func Encode(book Book) ([]byte, error) {
	if !book.initialized {
		return nil, problem(CodeInvalidBook)
	}
	if err := validateChain(book.records); err != nil {
		return nil, err
	}
	document := bookDocument(book.records)
	if len(document) > MaxBookBytes {
		return nil, problem(CodeBookLimit)
	}
	return document, nil
}

// Write checks the destination, prepares the complete canonical document and
// hands it to the writer in a single call. A failed delivery is never reported
// as complete; no retry, flush or close is attempted.
func Write(book Book, destination io.Writer) error {
	return writeBook(book, destination)
}

// Records returns deep copies of the records in append order. Mutating them
// cannot affect the book or any other result.
func Records(book Book) ([]Record, error) {
	if !book.initialized {
		return nil, problem(CodeInvalidBook)
	}
	records := make([]Record, len(book.records))
	for index, record := range book.records {
		records[index] = copyRecord(record)
	}
	return records, nil
}

// HeadHash returns the hash of the last record, or "" for the empty book. The
// empty result is not a digest and is never serialized as a reference.
func HeadHash(book Book) (string, error) {
	if !book.initialized {
		return "", problem(CodeInvalidBook)
	}
	if len(book.records) == 0 {
		return "", nil
	}
	return book.records[len(book.records)-1].Hash, nil
}

func buildRecord(previous []Record, input DecisionInput) Record {
	record := Record{
		Format:   RecordFormat,
		Version:  FormatVersion,
		Sequence: uint64(len(previous) + 1),
		Decision: copyInput(input),
	}
	if len(previous) > 0 {
		head := previous[len(previous)-1].Hash
		record.PreviousHash = &head
	}
	record.Hash = recordHash(record)
	return record
}

func copyInput(input DecisionInput) DecisionInput {
	copied := input
	if input.Controls != nil {
		copied.Controls = make([]string, len(input.Controls))
		copy(copied.Controls, input.Controls)
	}
	copied.Scope = copyScope(input.Scope)
	copied.ExpiresAt = copyPointer(input.ExpiresAt)
	copied.Supersedes = copyPointer(input.Supersedes)
	return copied
}

func copyScope(scope Scope) Scope {
	copied := scope
	copied.ResultFingerprint = copyPointer(scope.ResultFingerprint)
	return copied
}

func copyRecord(record Record) Record {
	copied := record
	if record.PreviousHash != nil {
		head := *record.PreviousHash
		copied.PreviousHash = &head
	}
	copied.Decision = copyInput(record.Decision)
	return copied
}

func copyPointer(value *string) *string {
	if value == nil {
		return nil
	}
	copied := *value
	return &copied
}

func hashExists(records []Record, hash string) bool {
	for index := range records {
		if records[index].Hash == hash {
			return true
		}
	}
	return false
}
