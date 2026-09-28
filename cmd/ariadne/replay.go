package main

import (
	"crypto/sha256"
	"encoding/hex"
)

// Replay fingerprint of ADR-0023 §4.3. The fingerprint is the SHA-256 of the
// exact bytes of the root `result` value of the JSON document produced by
// report.JSON for this evaluation — without its key, without the catalogues and
// without external whitespace. It is not the bundle hash, the pack hash or a
// hash of the complete report, and it is never computed over a document supplied
// by the caller: the bytes come from the renderer that just ran in memory.

func resultFingerprint(jsonDocument []byte) string {
	value, ok := rootMemberValue(jsonDocument, "result")
	if !ok {
		// The renderer always emits this shape; an impossible shape fails closed
		// as an internal inconsistency instead of hashing something else.
		return ""
	}
	sum := sha256.Sum256(value)
	return "sha256:" + hex.EncodeToString(sum[:])
}

// rootMemberValue returns the exact bytes of one member of the root object,
// located with its own scanner: the value keeps the exact spelling the renderer
// emitted, including escapes, so the fingerprint covers the ratified projection
// and nothing else.
func rootMemberValue(document []byte, name string) ([]byte, bool) {
	scanner := &shapeScanner{data: document}
	scanner.skipSpace()
	if scanner.at >= len(scanner.data) || scanner.data[scanner.at] != '{' {
		return nil, false
	}
	scanner.at++
	for {
		scanner.skipSpace()
		if scanner.at < len(scanner.data) && scanner.data[scanner.at] == '}' {
			return nil, false
		}
		key, err := scanner.stringText()
		if err != nil {
			return nil, false
		}
		scanner.skipSpace()
		if scanner.at >= len(scanner.data) || scanner.data[scanner.at] != ':' {
			return nil, false
		}
		scanner.at++
		scanner.skipSpace()
		start := scanner.at
		if err := scanner.value(); err != nil {
			return nil, false
		}
		end := scanner.at
		if key == name {
			return document[start:end], true
		}
		scanner.skipSpace()
		if scanner.at >= len(scanner.data) {
			return nil, false
		}
		switch scanner.data[scanner.at] {
		case ',':
			scanner.at++
		case '}':
			return nil, false
		default:
			return nil, false
		}
	}
}
