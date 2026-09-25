package ingest

import (
	"errors"
	"io"

	"github.com/d4rpell/Ariadne/internal/schema"
)

// readChunkBytes bounds how much is read ahead from the underlying reader. Fills
// are also clamped to the remaining file budget, so at most one extra byte is
// read to distinguish an exact-size file from an oversized one (ADR-0008 D1).
const readChunkBytes = 8 * 1024

var (
	errFileLimit  = errors.New("ingest: file byte limit exceeded")
	errNoProgress = errors.New("ingest: reader made no progress")
)

// scanError reports a structural failure at a verified stream offset. It is
// internal: the public surface only exposes *FileError.
type scanError struct {
	offset uint64
	reason Reason
}

func (e *scanError) Error() string { return "ingest: prisma-v1: scan failure" }

// source reads bytes from the input while enforcing the file byte budget. Byte
// limits count raw stream bytes; the reader is never drained after a failure.
type source struct {
	r       io.Reader
	buf     []byte
	pos     int
	end     int
	logical uint64 // bytes consumed by the state machine
	readRaw uint64 // bytes pulled from r, never above the file budget
	eofSeen bool
	rawErr  error
}

func newSource(r io.Reader) *source {
	return newSourceSize(r, readChunkBytes)
}

func newSourceSize(r io.Reader, size int) *source {
	if size < 1 {
		size = 1
	}
	return &source{r: r, buf: make([]byte, size)}
}

// readMore pulls bytes from the underlying reader into the buffer, compacting
// first when needed and never reading past the file budget.
func (s *source) readMore() {
	if s.eofSeen || s.rawErr != nil {
		return
	}
	if s.pos > 0 {
		copy(s.buf, s.buf[s.pos:s.end])
		s.end -= s.pos
		s.pos = 0
	}
	if s.end == len(s.buf) {
		return
	}
	remaining := uint64(schema.PrismaV1MaxFileBytes) - s.readRaw
	if remaining == 0 {
		return
	}
	want := len(s.buf) - s.end
	if uint64(want) > remaining {
		want = int(remaining)
	}
	n, err := s.r.Read(s.buf[s.end : s.end+want])
	s.end += n
	s.readRaw += uint64(n)
	if err != nil {
		if err == io.EOF {
			s.eofSeen = true
		} else {
			s.rawErr = err
		}
		return
	}
	if n == 0 {
		s.rawErr = errNoProgress
	}
}

// fill makes at least one unread byte available when the source is not finished.
func (s *source) fill() {
	if s.pos < s.end {
		return
	}
	s.readMore()
}

// peek returns the next logical byte without consuming it. ok is false at a
// real EOF; the error is errFileLimit when the stream continues past the budget
// or a sanitized read failure.
func (s *source) peek() (byte, bool, error) {
	for {
		if s.pos < s.end {
			return s.buf[s.pos], true, nil
		}
		if s.eofSeen {
			return 0, false, nil
		}
		if s.rawErr != nil {
			return 0, false, s.rawErr
		}
		if s.readRaw >= uint64(schema.PrismaV1MaxFileBytes) {
			return 0, false, s.probeLimit()
		}
		s.readMore()
		if s.pos == s.end && !s.eofSeen && s.rawErr == nil && s.readRaw < uint64(schema.PrismaV1MaxFileBytes) {
			// readMore could not grow the window; avoid spinning and report the
			// reader as failed instead of pretending progress.
			if s.rawErr == nil {
				s.rawErr = errNoProgress
			}
			return 0, false, s.rawErr
		}
	}
}

// probeLimit reads at most one byte to distinguish an exact-size file from an
// oversized one; the rest of an oversized stream is never consumed.
func (s *source) probeLimit() error {
	var probe [1]byte
	n, err := s.r.Read(probe[:])
	switch {
	case n > 0:
		return errFileLimit
	case err == io.EOF:
		s.eofSeen = true
		return nil
	case err != nil:
		s.rawErr = err
		return err
	default:
		s.rawErr = errNoProgress
		return s.rawErr
	}
}

func (s *source) next() (byte, uint64, bool, error) {
	offset := s.logical
	b, ok, err := s.peek()
	if !ok || err != nil {
		return 0, offset, false, err
	}
	s.pos++
	s.logical++
	return b, offset, true, nil
}

// hasBOM reports whether the stream starts with a UTF-8 BOM. The bytes are never
// stripped; a detected BOM aborts the import.
func (s *source) hasBOM() bool {
	for s.end-s.pos < 3 {
		before := s.end - s.pos
		s.readMore()
		if s.end-s.pos == before {
			break
		}
	}
	return s.end-s.pos >= 3 &&
		s.buf[s.pos] == 0xEF && s.buf[s.pos+1] == 0xBB && s.buf[s.pos+2] == 0xBF
}

// fileError maps an internal failure to the public sanitized error. A raw reader
// error keeps its verified offset and never carries the underlying text.
func (s *source) fileError(err error) *FileError {
	if errors.Is(err, errFileLimit) {
		return &FileError{Offset: uint64(schema.PrismaV1MaxFileBytes), Reason: ReasonFileLimit}
	}
	var scan *scanError
	if errors.As(err, &scan) {
		return &FileError{Offset: scan.offset, Reason: scan.reason}
	}
	return &FileError{Offset: s.logical, Reason: ReasonReadFailure}
}

const (
	stateFieldStart = iota
	stateUnquoted
	stateQuoted
	stateQuoteClosed
)

// rawRecord is one delimited CSV record: decoded field content plus the facts
// needed for locators, header validation and limit diagnostics. raws holds the
// raw field representation (quotes and escapes included) and is only collected
// when the caller asks for it: it lets header diagnostics report a stream
// offset that quoted fields cannot derive from the decoded content.
type rawRecord struct {
	fields      [][]byte
	raws        [][]byte
	quoted      []bool
	starts      []uint64
	start       uint64
	end         uint64 // exclusive, excluding the outer terminator
	limitReason Reason
	limitOffset uint64
	hasLimit    bool
}

// readRecord delimits one record without normalizing bytes. Internal CR and LF
// are preserved only inside quoted fields; LF and CRLF terminate a record and a
// lone CR is unquoted content (ADR-0008 D2).
func (s *source) readRecord(keepRaw bool) (rawRecord, bool, error) {
	var rec rawRecord
	if _, ok, err := s.peek(); !ok || err != nil {
		return rec, false, err
	}
	rec.start = s.logical

	state := stateFieldStart
	var (
		field       []byte
		raw         []byte
		fieldQuoted bool
		fieldStart  = s.logical
		fieldRaw    uint64
		recRaw      uint64
		fields      [][]byte
		raws        [][]byte
		quoteds     []bool
		starts      []uint64
		overflow    bool
	)
	pushField := func() {
		if !overflow {
			fields = append(fields, field)
			quoteds = append(quoteds, fieldQuoted)
			starts = append(starts, fieldStart)
			if keepRaw {
				raws = append(raws, raw)
			}
		}
		field = nil
		raw = nil
		fieldQuoted = false
		fieldRaw = 0
	}
	setLimit := func(reason Reason, offset uint64) {
		if !rec.hasLimit {
			rec.hasLimit = true
			rec.limitReason = reason
			rec.limitOffset = offset
			overflow = true
			field = nil
		}
	}
	// addFieldBytes counts raw CSV bytes of the field representation (quoting and
	// escaped quotes included), stores the decoded content while within budget and
	// collects the raw representation when requested. Every raw byte of these
	// cases is the same byte repeated: one quote, a doubled quote or one content
	// byte.
	addFieldBytes := func(rawBytes uint64, rawByte, content byte, hasContent bool, offset uint64) error {
		if recRaw+rawBytes > uint64(schema.PrismaV1MaxRecordBytes) {
			return &scanError{offset: offset, reason: ReasonRecordLimit}
		}
		recRaw += rawBytes
		if keepRaw {
			for i := uint64(0); i < rawBytes; i++ {
				raw = append(raw, rawByte)
			}
		}
		if fieldRaw+rawBytes > uint64(schema.PrismaV1MaxFieldBytes) {
			setLimit(ReasonFieldLimit, offset)
			return nil
		}
		fieldRaw += rawBytes
		if hasContent && !overflow {
			field = append(field, content)
		}
		return nil
	}
	// addRecordByte counts internal delimiters, which belong to the record but
	// not to any field.
	addRecordByte := func(offset uint64) error {
		if recRaw >= uint64(schema.PrismaV1MaxRecordBytes) {
			return &scanError{offset: offset, reason: ReasonRecordLimit}
		}
		recRaw++
		return nil
	}
	closeField := func(offset uint64) error {
		if err := addRecordByte(offset); err != nil {
			return err
		}
		pushField()
		if len(fields) >= schema.PrismaV1MaxFields {
			setLimit(ReasonFieldCountLimit, offset)
		}
		fieldStart = s.logical
		state = stateFieldStart
		return nil
	}

	var end uint64
loop:
	for {
		b, offset, ok, err := s.next()
		if err != nil {
			return rec, false, err
		}
		if !ok {
			if state == stateQuoted {
				return rec, false, &scanError{offset: s.logical, reason: ReasonInvalidCSV}
			}
			end = s.logical
			break loop
		}
		switch state {
		case stateFieldStart:
			switch b {
			case '"':
				if err := addFieldBytes(1, '"', 0, false, offset); err != nil {
					return rec, false, err
				}
				state = stateQuoted
				fieldQuoted = true
			case ',':
				if err := closeField(offset); err != nil {
					return rec, false, err
				}
			case '\r':
				next, ok, err := s.peek()
				if err != nil {
					return rec, false, err
				}
				if ok && next == '\n' {
					if _, _, _, err := s.next(); err != nil {
						return rec, false, err
					}
					end = offset
					break loop
				}
				if err := addFieldBytes(1, b, b, true, offset); err != nil {
					return rec, false, err
				}
				state = stateUnquoted
			case '\n':
				end = offset
				break loop
			default:
				if err := addFieldBytes(1, b, b, true, offset); err != nil {
					return rec, false, err
				}
				state = stateUnquoted
			}
		case stateUnquoted:
			switch b {
			case ',':
				if err := closeField(offset); err != nil {
					return rec, false, err
				}
			case '\r':
				next, ok, err := s.peek()
				if err != nil {
					return rec, false, err
				}
				if ok && next == '\n' {
					if _, _, _, err := s.next(); err != nil {
						return rec, false, err
					}
					end = offset
					break loop
				}
				if err := addFieldBytes(1, b, b, true, offset); err != nil {
					return rec, false, err
				}
			case '\n':
				end = offset
				break loop
			case '"':
				return rec, false, &scanError{offset: offset, reason: ReasonInvalidCSV}
			default:
				if err := addFieldBytes(1, b, b, true, offset); err != nil {
					return rec, false, err
				}
			}
		case stateQuoted:
			if b == '"' {
				next, ok, err := s.peek()
				if err != nil {
					return rec, false, err
				}
				if ok && next == '"' {
					if _, _, _, err := s.next(); err != nil {
						return rec, false, err
					}
					if err := addFieldBytes(2, '"', '"', true, offset); err != nil {
						return rec, false, err
					}
					continue
				}
				if err := addFieldBytes(1, '"', 0, false, offset); err != nil {
					return rec, false, err
				}
				state = stateQuoteClosed
				continue
			}
			if err := addFieldBytes(1, b, b, true, offset); err != nil {
				return rec, false, err
			}
		case stateQuoteClosed:
			switch b {
			case ',':
				if err := closeField(offset); err != nil {
					return rec, false, err
				}
			case '\r':
				next, ok, err := s.peek()
				if err != nil {
					return rec, false, err
				}
				if ok && next == '\n' {
					if _, _, _, err := s.next(); err != nil {
						return rec, false, err
					}
					end = offset
					break loop
				}
				return rec, false, &scanError{offset: offset, reason: ReasonInvalidCSV}
			case '\n':
				end = offset
				break loop
			default:
				return rec, false, &scanError{offset: offset, reason: ReasonInvalidCSV}
			}
		}
	}
	pushField()
	rec.end = end
	rec.fields = fields
	rec.raws = raws
	rec.quoted = quoteds
	rec.starts = starts
	return rec, true, nil
}
