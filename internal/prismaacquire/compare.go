package prismaacquire

import (
	"bytes"
	"crypto/sha256"

	"github.com/d4rpell/Ariadne/internal/ingest"
)

// Repetition and drift guards of §8.10–§8.14. Both compare only sanitized,
// canonical record data: context, acquired_at, source alias, page ordinal and
// original offsets are excluded, so a legitimate context change never produces
// a false positive. Presence, absence, null, empty, order, wrappers and
// repetitions are preserved.

// pageComparer accumulates the comparison state of one acquisition. It is
// private, bounded by the number of pages and the admitted records and never
// becomes part of the artifacts.
type pageComparer struct {
	pages   map[string][][]byte // record-sequence fingerprint → canonical sequences
	anchors map[string][]anchorEntry
}

type anchorEntry struct {
	page      int
	record    int
	canonical []byte
}

func newPageComparer() *pageComparer {
	return &pageComparer{
		pages:   map[string][][]byte{},
		anchors: map[string][]anchorEntry{},
	}
}

// observePage confirms the repetition guard of §8.10 for a non-empty page. The
// equality is decided over the canonical record data, never by hash alone; a
// full match with a previously admitted page at another offset is page_repeated.
func (c *pageComparer) observePage(page int, records []ingest.NativeRecord) *AcquisitionError {
	if len(records) == 0 {
		return nil
	}
	sequence := canonicalSequence(records)
	digest := sha256.Sum256(sequence)
	key := string(digest[:])
	for _, previous := range c.pages[key] {
		if bytes.Equal(previous, sequence) {
			return acquireErr(CodePageRepeated, PhasePagination)
		}
	}
	c.pages[key] = append(c.pages[key], sequence)
	return nil
}

// observeDrift applies the bounded drift guard of §8.12–§8.13. A record
// participates when it has a non-empty id or _id, or when repoTag carries
// registry, repo and tag. Every variant of an anchor is retained with its page
// and record position, so a cross-page conflict is detected even when the same
// anchor appears more than once on a page. For two records of different pages
// with the same anchor, a difference in their canonical data is
// page_drift_suspected. The first conflicting pair in page and record order is
// reported.
func (c *pageComparer) observeDrift(page int, records []ingest.NativeRecord) *AcquisitionError {
	for index, record := range records {
		key, ok := recordAnchor(record.Data)
		if !ok {
			continue
		}
		canonical := ingest.EncodeNativeRecordData(record.Data)
		for _, previous := range c.anchors[key] {
			if previous.page == page {
				continue
			}
			if !bytes.Equal(previous.canonical, canonical) {
				failure := acquireErr(CodePageDriftSuspected, PhasePagination)
				failure.PreviousPage = previous.page
				failure.PageOrdinal = page
				failure.FirstRecord = previous.record
				failure.SecondRecord = index
				return failure
			}
		}
		c.anchors[key] = append(c.anchors[key], anchorEntry{page: page, record: index, canonical: canonical})
	}
	return nil
}

// canonicalSequence returns a length-prefixed concatenation of the canonical
// bytes of every record data, preserving order and repetitions.
func canonicalSequence(records []ingest.NativeRecord) []byte {
	var out []byte
	var length [8]byte
	for _, record := range records {
		data := ingest.EncodeNativeRecordData(record.Data)
		putUint64(length[:], uint64(len(data)))
		out = append(out, length[:]...)
		out = append(out, data...)
	}
	return out
}

func putUint64(b []byte, v uint64) {
	for i := 7; i >= 0; i-- {
		b[i] = byte(v)
		v >>= 8
	}
}

// recordAnchor builds the §8.12 anchor of one record and reports whether the
// record participates. The anchor records the presence and value of id and _id
// and the admitted repoTag members, distinguishing absence, null and empty.
func recordAnchor(value ingest.NativeValue) (string, bool) {
	obj, ok := value.(ingest.NativeObject)
	if !ok {
		return "", false
	}
	members := map[string]ingest.NativeValue{}
	for i, key := range obj.Keys {
		members[key] = obj.Values[i]
	}
	idPresent := nonEmptyString(members["id"])
	underscoreIDPresent := nonEmptyString(members["_id"])
	repoTag, hasRepoTag := members["repoTag"].(ingest.NativeObject)
	registryOK, repoOK, tagOK := false, false, false
	if hasRepoTag {
		repoMembers := map[string]ingest.NativeValue{}
		for i, key := range repoTag.Keys {
			repoMembers[key] = repoTag.Values[i]
		}
		registryOK = nonEmptyString(repoMembers["registry"])
		repoOK = nonEmptyString(repoMembers["repo"])
		tagOK = nonEmptyString(repoMembers["tag"])
	}
	if !(idPresent || underscoreIDPresent || (registryOK && repoOK && tagOK)) {
		return "", false
	}
	var buf bytes.Buffer
	for _, field := range []string{"id", "_id"} {
		appendAnchorMember(&buf, field, members[field], hasMember(members, field))
	}
	var repoMembers map[string]ingest.NativeValue
	if hasRepoTag {
		repoMembers = map[string]ingest.NativeValue{}
		for i, key := range repoTag.Keys {
			repoMembers[key] = repoTag.Values[i]
		}
	}
	for _, field := range []string{"registry", "repo", "tag", "id", "digest"} {
		if hasRepoTag {
			appendAnchorMember(&buf, "repoTag."+field, repoMembers[field], hasMember(repoMembers, field))
		} else {
			appendAnchorMember(&buf, "repoTag."+field, nil, false)
		}
	}
	return buf.String(), true
}

func hasMember(members map[string]ingest.NativeValue, name string) bool {
	_, ok := members[name]
	return ok
}

func nonEmptyString(value ingest.NativeValue) bool {
	s, ok := value.(ingest.NativeString)
	return ok && s != ""
}

// appendAnchorMember writes a field name, a presence marker and the canonical
// value bytes. Absence, null and empty therefore produce distinct encodings.
func appendAnchorMember(buf *bytes.Buffer, name string, value ingest.NativeValue, present bool) {
	buf.WriteString(name)
	if !present {
		buf.WriteByte('0')
		return
	}
	buf.WriteByte('1')
	buf.Write(ingest.EncodeNativeRecordData(value))
	buf.WriteByte('|')
}
