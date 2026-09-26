package rulepack

import (
	"errors"
	"strconv"
)

// ErrorCode is the closed set of admission and decoding failures of ADR-0013
// §5.3. Codes the evaluator owns (invalid_target, invalid_bundle, ...) live in
// its own package; this set is the one produced by pack handling.
type ErrorCode string

const (
	CodeInputLimit           ErrorCode = "input_limit"
	CodeInvalidContext       ErrorCode = "invalid_context"
	CodeMissingPack          ErrorCode = "missing_pack"
	CodePackHashMismatch     ErrorCode = "pack_hash_mismatch"
	CodeInvalidPack          ErrorCode = "invalid_pack"
	CodeUnsupportedPack      ErrorCode = "unsupported_pack"
	CodePackIdentityMismatch ErrorCode = "pack_identity_mismatch"
	CodePackDowngrade        ErrorCode = "pack_downgrade"
	CodePackEquivocation     ErrorCode = "pack_equivocation"
	CodePackNotYetValid      ErrorCode = "pack_not_yet_valid"
	CodePackExpired          ErrorCode = "pack_expired"
)

// Error is a static admission failure. It carries a closed code and, at most, a
// bounded numeric index; never input values, pack text, paths, locators or raw
// parser errors.
type Error struct {
	Code  ErrorCode
	Index int
}

func (failure *Error) Error() string {
	if failure.Index < 0 {
		return "rulepack: " + string(failure.Code)
	}
	return "rulepack: " + string(failure.Code) + " (index " + strconv.Itoa(failure.Index) + ")"
}

// Is reports whether err is an admission failure carrying the given code.
func Is(err error, code ErrorCode) bool {
	var failure *Error
	if errors.As(err, &failure) {
		return failure.Code == code
	}
	return false
}

func problem(code ErrorCode, index int) error {
	return &Error{Code: code, Index: index}
}

func syntaxProblem() error           { return problem(CodeInvalidPack, -1) }
func limitProblem() error            { return problem(CodeInputLimit, -1) }
func invalidProblem(index int) error { return problem(CodeInvalidPack, index) }
