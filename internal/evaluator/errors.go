package evaluator

import (
	"errors"
	"strconv"
)

// ErrorCode is the closed set of evaluation failures of ADR-0013 §5.3 that this
// package owns. Pack failures keep their rulepack codes and are returned
// unwrapped, so each package owns the codes of its own phases.
type ErrorCode string

const (
	CodeInputLimit         ErrorCode = "input_limit"
	CodeInvalidTarget      ErrorCode = "invalid_target"
	CodeInvalidBundle      ErrorCode = "invalid_bundle"
	CodeBundleHashMismatch ErrorCode = "bundle_hash_mismatch"
	CodeValueHashMismatch  ErrorCode = "value_hash_mismatch"
	CodeRulesetMismatch    ErrorCode = "ruleset_mismatch"
	CodeEvaluationLimit    ErrorCode = "evaluation_limit"
)

// Error is a static evaluation failure: a closed code and, at most, a bounded
// numeric index. It never carries evidence values, paths, locators, identifiers
// or raw errors from other packages.
type Error struct {
	Code  ErrorCode
	Index int
}

func (failure *Error) Error() string {
	if failure.Index < 0 {
		return "evaluator: " + string(failure.Code)
	}
	return "evaluator: " + string(failure.Code) + " (index " + strconv.Itoa(failure.Index) + ")"
}

// IsCode reports whether err is an evaluation failure carrying the given code.
// Pack-phase failures are reported by rulepack.Is, not here.
func IsCode(err error, code ErrorCode) bool {
	var failure *Error
	if errors.As(err, &failure) {
		return failure.Code == code
	}
	return false
}

func problem(code ErrorCode, index int) error {
	return &Error{Code: code, Index: index}
}
