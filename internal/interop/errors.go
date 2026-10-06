package interop

import (
	"errors"
	"strings"
)

// ErrorCode is the closed set of export failures of ADR-0032 §7. They are local
// to this renderer: none of them is an evaluation state and none changes an
// evaluator or rulepack code.
type ErrorCode string

const (
	CodeInvalidResult      ErrorCode = "invalid_result"
	CodeInvalidBundle      ErrorCode = "invalid_bundle"
	CodeBundleHashMismatch ErrorCode = "bundle_hash_mismatch"
	CodeInvalidIssuer      ErrorCode = "invalid_issuer"
	CodeInvalidRemediation ErrorCode = "invalid_remediation"
	CodeRenderFailure      ErrorCode = "render_failure"
)

// Error is a static export failure. The text is exactly "interop: <code>": it
// carries no index, no detail and nothing taken from the input, so a diagnostic
// cannot disclose what the document deliberately omits.
type Error struct {
	Code ErrorCode
}

func (failure *Error) Error() string {
	return "interop: " + string(failure.Code)
}

// IsCode reports whether err is an export failure carrying the given code.
func IsCode(err error, code ErrorCode) bool {
	var failure *Error
	return errors.As(err, &failure) && failure.Code == code
}

func problem(code ErrorCode) error {
	return &Error{Code: code}
}

// isSha256 is the grammar of the boundary hashes: exactly "sha256:" followed by
// 64 lowercase hexadecimal characters.
func isSha256(value string) bool {
	const prefix = "sha256:"
	if len(value) != len(prefix)+64 || !strings.HasPrefix(value, prefix) {
		return false
	}
	for index := len(prefix); index < len(value); index++ {
		c := value[index]
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}
