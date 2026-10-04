package casefile

import (
	"errors"
	"strings"
)

// ErrorCode is the closed set of casefile failures (ADR-0030 §7). None of them
// is a product, exploitability, risk or validity state, and none changes an
// evaluator, rulepack or report code.
type ErrorCode string

const (
	CodeInvalidBook       ErrorCode = "invalid_book"
	CodeInvalidEncoding   ErrorCode = "invalid_encoding"
	CodeUnsupportedFormat ErrorCode = "unsupported_format"
	CodeBookLimit         ErrorCode = "book_limit"
	CodeRecordLimit       ErrorCode = "record_limit"
	CodeFieldLimit        ErrorCode = "field_limit"
	CodeControlLimit      ErrorCode = "control_limit"
	CodeInvalidDecision   ErrorCode = "invalid_decision"
	CodeInvalidActor      ErrorCode = "invalid_actor"
	CodeInvalidRationale  ErrorCode = "invalid_rationale"
	CodeInvalidScope      ErrorCode = "invalid_scope"
	CodeInvalidControl    ErrorCode = "invalid_control"
	CodeInvalidTimestamp  ErrorCode = "invalid_timestamp"
	CodeInvalidReference  ErrorCode = "invalid_reference"
	CodeInvalidSequence   ErrorCode = "invalid_sequence"
	CodeChainMismatch     ErrorCode = "chain_mismatch"
	CodeHashMismatch      ErrorCode = "hash_mismatch"
	CodeInvalidWriter     ErrorCode = "invalid_writer"
	CodeWriteFailed       ErrorCode = "write_failed"
	CodeShortWrite        ErrorCode = "short_write"
)

// Error is a static casefile failure. The ratified text is exactly
// "casefile: <code>": it carries no index, no field name, no caller value and
// no writer error, so a diagnostic cannot disclose what the record holds.
type Error struct {
	Code ErrorCode
}

func (failure *Error) Error() string {
	return "casefile: " + string(failure.Code)
}

// IsCode reports whether err is a casefile failure carrying the given code.
func IsCode(err error, code ErrorCode) bool {
	var failure *Error
	return errors.As(err, &failure) && failure.Code == code
}

func problem(code ErrorCode) error {
	return &Error{Code: code}
}

// isSha256 is the grammar of every hash in a record: exactly "sha256:" followed
// by 64 lowercase hexadecimal characters. A syntactically valid hash proves
// nothing about the existence or content of the artefact it names.
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
