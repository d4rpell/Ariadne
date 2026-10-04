package casefile

import (
	"crypto/sha256"
	"encoding/hex"
	"strconv"
)

// Canonical serialization (ADR-0030 §4): one document per book, snake_case
// keys in a fixed order, no omitempty, no whitespace, no BOM and no trailing
// LF. Strings escape exactly four bytes — ", \, LF and TAB — because
// validation refuses every other control character before serialization sees
// it. All other bytes are written verbatim as UTF-8.

const emptyBookDocument = `{"format":"casefile-book-v1","version":"1.0","records":[]}`

// bookDocument renders the canonical document of the given records. records
// must already be valid: Encode and Verify both validate before rendering.
func bookDocument(records []Record) []byte {
	if len(records) == 0 {
		return []byte(emptyBookDocument)
	}
	document := make([]byte, 0, len(emptyBookDocument)+len(records)*256)
	document = append(document, `{"format":"`...)
	document = append(document, BookFormat...)
	document = append(document, `","version":"`...)
	document = append(document, FormatVersion...)
	document = append(document, `","records":[`...)
	for index := range records {
		if index > 0 {
			document = append(document, ',')
		}
		document = append(document, recordEnvelope(records[index])...)
	}
	document = append(document, ']', '}')
	return document
}

// recordEnvelope renders the full canonical envelope of one record, hash key
// included. The preimage ends in its closing brace; the envelope splices the
// hash key in as the last member of the same object.
func recordEnvelope(record Record) []byte {
	image := recordPreimage(record)
	envelope := make([]byte, 0, len(image)+96)
	envelope = append(envelope, image[:len(image)-1]...)
	envelope = append(envelope, `,"hash":"`...)
	envelope = append(envelope, record.Hash...)
	envelope = append(envelope, '"', '}')
	return envelope
}

// recordPreimage renders the exact bytes the record hash covers: the thirteen
// canonical fields of §4.2, without the hash key, enclosed in braces.
func recordPreimage(record Record) []byte {
	image := make([]byte, 0, 512)
	image = append(image, `{"format":"`...)
	image = append(image, record.Format...)
	image = append(image, `","version":"`...)
	image = append(image, record.Version...)
	image = append(image, `","sequence":`...)
	image = strconv.AppendUint(image, record.Sequence, 10)
	image = append(image, `,"previous_hash":`...)
	if record.PreviousHash == nil {
		image = append(image, "null"...)
	} else {
		image = append(image, '"')
		image = append(image, *record.PreviousHash...)
		image = append(image, '"')
	}
	image = append(image, `,"risk_decision":"`...)
	image = appendEscaped(image, string(record.Decision.RiskDecision))
	image = append(image, `","owner":"`...)
	image = appendEscaped(image, record.Decision.Owner)
	image = append(image, `","approver":"`...)
	image = appendEscaped(image, record.Decision.Approver)
	image = append(image, `","rationale":"`...)
	image = appendEscaped(image, record.Decision.Rationale)
	image = append(image, `","scope":{"bundle_hash":"`...)
	image = append(image, record.Decision.Scope.BundleHash...)
	image = append(image, `","subject_uid":"`...)
	image = appendEscaped(image, record.Decision.Scope.SubjectUID)
	image = append(image, `","container_name":"`...)
	image = appendEscaped(image, record.Decision.Scope.ContainerName)
	image = append(image, `","container_class":"`...)
	image = append(image, string(record.Decision.Scope.ContainerClass)...)
	image = append(image, `","vulnerability_id":"`...)
	image = append(image, record.Decision.Scope.VulnerabilityID...)
	image = append(image, `","result_fingerprint":`...)
	if record.Decision.Scope.ResultFingerprint == nil {
		image = append(image, "null"...)
	} else {
		image = append(image, '"')
		image = append(image, *record.Decision.Scope.ResultFingerprint...)
		image = append(image, '"')
	}
	image = append(image, `},"controls":[`...)
	for index, control := range record.Decision.Controls {
		if index > 0 {
			image = append(image, ',')
		}
		image = append(image, '"')
		image = appendEscaped(image, control)
		image = append(image, '"')
	}
	image = append(image, `],"decided_at":"`...)
	image = append(image, record.Decision.DecidedAt...)
	image = append(image, `","expires_at":`...)
	if record.Decision.ExpiresAt == nil {
		image = append(image, "null"...)
	} else {
		image = append(image, '"')
		image = append(image, *record.Decision.ExpiresAt...)
		image = append(image, '"')
	}
	image = append(image, `,"supersedes":`...)
	if record.Decision.Supersedes == nil {
		image = append(image, "null"...)
	} else {
		image = append(image, '"')
		image = append(image, *record.Decision.Supersedes...)
		image = append(image, '"')
	}
	image = append(image, '}')
	return image
}

func appendEscaped(image []byte, value string) []byte {
	for index := 0; index < len(value); index++ {
		switch c := value[index]; c {
		case '"':
			image = append(image, '\\', '"')
		case '\\':
			image = append(image, '\\', '\\')
		case '\n':
			image = append(image, '\\', 'n')
		case '\t':
			image = append(image, '\\', 't')
		default:
			image = append(image, c)
		}
	}
	return image
}

// recordHash computes H(R): "sha256:" plus the lowercase hex digest of the
// preimage bytes.
func recordHash(record Record) string {
	digest := sha256.Sum256(recordPreimage(record))
	return "sha256:" + hex.EncodeToString(digest[:])
}
