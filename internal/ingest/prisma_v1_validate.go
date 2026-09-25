package ingest

import (
	"regexp"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/d4rpell/Ariadne/internal/schema"
)

var (
	versionPattern = regexp.MustCompile(`^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$`)
	cvePattern     = regexp.MustCompile(`^CVE-[0-9]{4}-[0-9]{4,}$`)
)

// headerTextProblem reports the first forbidden text byte in the header at its
// verified stream offset. It scans the raw field representation, not the decoded
// content: quoting and `""` escapes shift decoded offsets, and the raw bytes are
// the stream bytes (quotes are admissible text, so the first forbidden byte is
// the same one).
func headerTextProblem(rec rawRecord) (uint64, Reason) {
	for i, raw := range rec.raws {
		if offset, reason := textProblem(raw, rec.quoted[i]); reason != "" {
			return rec.starts[i] + uint64(offset), reason
		}
	}
	return 0, ""
}

// headerIndexes maps each header position to its canonical column index. The
// header must be a strictly increasing subsequence of the canonical order with
// every required column present.
func headerIndexes(rec rawRecord) ([]int, *FileError) {
	columns := schema.PrismaV1Columns()
	seen := make(map[int]bool, len(rec.fields))
	indexes := make([]int, len(rec.fields))
	previous := -1
	for i, name := range rec.fields {
		canonical := -1
		for c := range columns {
			if string(name) == columns[c].Name {
				canonical = c
				break
			}
		}
		if canonical < 0 {
			return nil, &FileError{Offset: rec.starts[i], Reason: ReasonUnknownSelector}
		}
		if seen[canonical] {
			return nil, &FileError{Offset: rec.starts[i], Reason: ReasonDuplicateColumn}
		}
		if canonical <= previous {
			return nil, &FileError{Offset: rec.starts[i], Reason: ReasonInvalidHeader}
		}
		seen[canonical] = true
		indexes[i] = canonical
		previous = canonical
	}
	for c := range columns {
		if columns[c].Required && !seen[c] {
			return nil, &FileError{Offset: rec.end, Reason: ReasonMissingRequiredColumn}
		}
	}
	return indexes, nil
}

// rowProblem classifies one delimited data record; an empty Reason means the
// record is accepted.
func rowProblem(rec rawRecord, indexes []int) Reason {
	if rec.hasLimit {
		return rec.limitReason
	}
	if len(rec.fields) != len(indexes) {
		return ReasonFieldCount
	}
	for i, value := range rec.fields {
		if _, reason := textProblem(value, rec.quoted[i]); reason != "" {
			return reason
		}
	}
	for i, canonical := range indexes {
		if reason := columnProblem(canonical, rec.fields[i]); reason != "" {
			return reason
		}
	}
	return ""
}

// textProblem reports the offset of the first forbidden byte within the value
// and its reason: NUL, invalid UTF-8, C0 controls other than quoted CR/LF, DEL,
// C1 controls or Unicode format characters (ADR-0008 D3). An empty Reason means
// the text is admissible; the offset is the first offending byte.
func textProblem(value []byte, quoted bool) (int, Reason) {
	for i := 0; i < len(value); {
		c := value[i]
		switch {
		case c == 0x00:
			return i, ReasonNUL
		case c < utf8.RuneSelf:
			if c == '\r' || c == '\n' {
				if !quoted {
					return i, ReasonForbiddenText
				}
				i++
				continue
			}
			if c < 0x20 || c == 0x7F {
				return i, ReasonForbiddenText
			}
			i++
		default:
			r, size := utf8.DecodeRune(value[i:])
			if r == utf8.RuneError && size == 1 {
				return i, ReasonInvalidUTF8
			}
			if unicode.Is(unicode.Cf, r) || (r >= 0x80 && r <= 0x9F) {
				return i, ReasonForbiddenText
			}
			i += size
		}
	}
	return 0, ""
}

// columnProblem applies the type and requiredness rules of one canonical column.
func columnProblem(canonical int, value []byte) Reason {
	switch canonical {
	case 0:
		if requiredValueProblem(value) {
			return ReasonRequiredValue
		}
		if !versionPattern.Match(value) {
			return ReasonInvalidVersion
		}
		if string(value) != schema.PrismaV1Version {
			return ReasonUnsupportedVersion
		}
	case 1:
		if requiredValueProblem(value) {
			return ReasonRequiredValue
		}
		if !cvePattern.Match(value) {
			return ReasonInvalidCVE
		}
	case 2, 3, 4, 5, 6:
		if requiredValueProblem(value) {
			return ReasonRequiredValue
		}
	case 13, 14:
		if len(value) > 0 && !validDate(value) {
			return ReasonInvalidDate
		}
	}
	return ""
}

// requiredValueProblem reports values that cannot serve as a required
// identifier: empty, only whitespace, or surrounded by whitespace, Unicode
// whitespace included (ADR-0008 D6). The value is never trimmed or transformed.
// Callers reject invalid UTF-8 first, so decoding the boundary runes is safe.
func requiredValueProblem(value []byte) bool {
	if len(value) == 0 {
		return true
	}
	if first, _ := utf8.DecodeRune(value); unicode.IsSpace(first) {
		return true
	}
	if last, _ := utf8.DecodeLastRune(value); unicode.IsSpace(last) {
		return true
	}
	return false
}

// validDate accepts exactly YYYY-MM-DD with a real calendar date. Year 0000 is
// rejected; no chronological relation between dates is imposed (ADR-0008 D6).
func validDate(value []byte) bool {
	if len(value) != 10 {
		return false
	}
	for i, c := range value {
		if i == 4 || i == 7 {
			if c != '-' {
				return false
			}
			continue
		}
		if c < '0' || c > '9' {
			return false
		}
	}
	if string(value[:4]) == "0000" {
		return false
	}
	parsed, err := time.Parse("2006-01-02", string(value))
	if err != nil {
		return false
	}
	return parsed.Format("2006-01-02") == string(value)
}
