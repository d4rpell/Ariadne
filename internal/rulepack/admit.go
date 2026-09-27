package rulepack

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"time"
)

const sha256Prefix = "sha256:"

// hashBytes returns the pack identity over the exact bytes received, whitespace
// and line endings included. No canonicalization is applied, so two documents
// with the same meaning but different bytes are different packs.
func hashBytes(data []byte) string {
	digest := sha256.Sum256(data)
	return sha256Prefix + hex.EncodeToString(digest[:])
}

// isSha256 accepts exactly "sha256:" plus 64 lowercase hex digits.
func isSha256(value string) bool {
	if len(value) != len(sha256Prefix)+64 || !strings.HasPrefix(value, sha256Prefix) {
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

// Validate checks the caller-supplied admission policy itself: the explicit
// instant, the pinned identity and the version policy. It reads no clock and no
// store; every field is a claim of the caller.
func (context AdmissionContext) Validate() error {
	if context.EvaluatedAt.IsZero() || context.EvaluatedAt.Location() != time.UTC {
		return problem(CodeInvalidContext, -1)
	}
	if !validID(context.ExpectedPackID) {
		return problem(CodeInvalidContext, -1)
	}
	if !isSha256(context.ExpectedPackHash) {
		return problem(CodeInvalidContext, -1)
	}
	if context.MinimumVersion < 1 || context.MinimumVersion > MaxVersion {
		return problem(CodeInvalidContext, -1)
	}
	if previous := context.Previous; previous != nil {
		if previous.Version < 1 || previous.Version > MaxVersion || !isSha256(previous.Hash) {
			return problem(CodeInvalidContext, -1)
		}
	}
	return nil
}

// Admit is the only way to obtain an AdmittedPack. The phase order is the one
// ratified in ADR-0013 §5.3: byte limit, caller context, presence and hash of the
// pack bytes, syntax and schema, pinned identity, version policy, validity. A
// failure rejects admission and produces no evaluation input at all.
func Admit(data []byte, context AdmissionContext) (AdmittedPack, error) {
	return admit(data, context, "")
}

// AdmitForBundle is Admit plus the profile/version cross of ADR-0015 §7.3: the
// product profile requires Bundle 0.2, and any other version is the illegal
// combination invalid_pack. The cross sits inside the syntax/schema/profile
// phase, after the pack hash is verified and the vocabulary is known, and before
// identity, anti-downgrade and validity, so it wins over pack_expired and
// ruleset_mismatch but never over pack_hash_mismatch. An empty bundleSchemaVersion
// means the caller has no bundle to cross and skips the check, which is what the
// legacy Admit path does.
func AdmitForBundle(data []byte, context AdmissionContext, bundleSchemaVersion string) (AdmittedPack, error) {
	return admit(data, context, bundleSchemaVersion)
}

func admit(data []byte, context AdmissionContext, bundleSchemaVersion string) (AdmittedPack, error) {
	if len(data) > MaxPackBytes {
		return AdmittedPack{}, limitProblem()
	}
	if err := context.Validate(); err != nil {
		return AdmittedPack{}, err
	}
	if len(data) == 0 {
		return AdmittedPack{}, problem(CodeMissingPack, -1)
	}
	hash := hashBytes(data)
	if hash != context.ExpectedPackHash {
		return AdmittedPack{}, problem(CodePackHashMismatch, -1)
	}
	pack, err := Decode(data)
	if err != nil {
		return AdmittedPack{}, err
	}
	if bundleSchemaVersion != "" && pack.Profile == ProductEvidenceProfile && bundleSchemaVersion != ProductBundleSchemaVersion {
		return AdmittedPack{}, problem(CodeInvalidPack, -1)
	}
	if pack.PackID != context.ExpectedPackID {
		return AdmittedPack{}, problem(CodePackIdentityMismatch, -1)
	}
	if previous := context.Previous; previous != nil {
		// The same version with different bytes is an equivocation, never an
		// update; a lower version against accepted history is a downgrade.
		if pack.Version == previous.Version && hash != previous.Hash {
			return AdmittedPack{}, problem(CodePackEquivocation, -1)
		}
		if pack.Version < previous.Version {
			return AdmittedPack{}, problem(CodePackDowngrade, -1)
		}
	}
	if pack.Version < context.MinimumVersion {
		return AdmittedPack{}, problem(CodePackDowngrade, -1)
	}
	if context.EvaluatedAt.Time.Before(pack.ValidFrom.Time) {
		return AdmittedPack{}, problem(CodePackNotYetValid, -1)
	}
	// The expiry instant itself is already outside the interval.
	if !context.EvaluatedAt.Time.Before(pack.ExpiresAt.Time) {
		return AdmittedPack{}, problem(CodePackExpired, -1)
	}
	return AdmittedPack{pack: pack, hash: hash, ok: true}, nil
}
