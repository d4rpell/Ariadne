package bundle

import (
	"crypto/sha256"
	"encoding/hex"

	contract "github.com/d4rpell/Ariadne/pkg/evidence"
)

const sha256Prefix = "sha256:"

// HashSource returns the canonical source hash over every byte it is given. The
// caller must hand over the complete source and parse exactly those bytes; this
// function cannot prove that a slice is a whole file, and neither can Build
// (ADR-0012 §2). Hashes of a prefix, of accepted rows or of a reserialized file
// are never source hashes.
func HashSource(data []byte) contract.SourceHash {
	digest := sha256.Sum256(data)
	return contract.SourceHash(sha256Prefix + hex.EncodeToString(digest[:]))
}

// HashValue returns the value hash of one evidence value: SHA-256 over the exact
// UTF-8 bytes of the value, with no normalization and no serialization of
// structures (ADR-0012 §1). It is the only admitted preimage.
func HashValue(value string) contract.ValueHash {
	return contract.ValueHash(HashSource([]byte(value)))
}

// isSha256 accepts exactly "sha256:" plus 64 lowercase hex digits, the same
// shape the identity package proves for a guaranteed digest.
func isSha256(value string) bool {
	if len(value) != len(sha256Prefix)+64 || value[:len(sha256Prefix)] != sha256Prefix {
		return false
	}
	for index := len(sha256Prefix); index < len(value); index++ {
		digit := value[index]
		if (digit < '0' || digit > '9') && (digit < 'a' || digit > 'f') {
			return false
		}
	}
	return true
}
