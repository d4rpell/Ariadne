package main

import (
	"encoding/json"
	"io"
)

// Closed vocabulary of ADR-0023 §5. Stages and codes are exactly the ratified
// sets: the executor does not extend them, and a code the table does not know
// fails closed as internal_failure instead of inventing a stage.
const (
	stageArguments      = "arguments"
	stageBundleRead     = "bundle_read"
	stageContextRead    = "context_read"
	stagePackRead       = "pack_read"
	stageFindingsRead   = "findings_read"
	stageBindingsRead   = "bindings_read"
	stageBundleDecode   = "bundle_decode"
	stageContextDecode  = "context_decode"
	stageFindingsDecode = "findings_decode"
	stageBindingsDecode = "bindings_decode"
	stageCasefile       = "casefile"
	stageImport         = "import"
	stageEvaluate       = "evaluate"
	stageReport         = "report"
	stageVerify         = "verify"
	stageOutputWrite    = "output_write"
	stageStdoutWrite    = "stdout_write"
	stageInternal       = "internal"
)

const (
	codeInvalidArguments          = "invalid_arguments"
	codeUnknownCommand            = "unknown_command"
	codeCommandDeferred           = "command_deferred"
	codeNotFound                  = "not_found"
	codePermissionDenied          = "permission_denied"
	codeInvalidFile               = "invalid_file"
	codeReadFailure               = "read_failure"
	codeWriteFailure              = "write_failure"
	codeTimeout                   = "timeout"
	codeAlreadyExists             = "already_exists"
	codeInputLimit                = "input_limit"
	codeInvalidBundle             = "invalid_bundle"
	codeInvalidContext            = "invalid_context"
	codeInvalidFindings           = "invalid_findings"
	codeInvalidBindings           = "invalid_bindings"
	codeResultFingerprintMismatch = "result_fingerprint_mismatch"
	codeInternalFailure           = "internal_failure"
)

// cliError is one handled failure: the closed stage/code pair and the process
// status the table assigns to it. It never carries paths, values, argv, native
// error text or stack information.
type cliError struct {
	stage string
	code  string
	exit  int
}

func (failure *cliError) Error() string { return "ariadne: " + failure.code }

// exitRows is the ratified table of ADR-0023 §5. Every row pairs one stage with
// the codes it may emit and the process status that follows.
var exitRows = []struct {
	stage string
	codes []string
	exit  int
}{
	{stageArguments, []string{codeInvalidArguments, codeUnknownCommand, codeCommandDeferred}, 2},
	{stageBundleDecode, []string{codeInvalidBundle}, 3},
	{stageContextDecode, []string{codeInvalidContext}, 3},
	{stageFindingsDecode, []string{codeInvalidFindings}, 3},
	{stageBindingsDecode, []string{codeInvalidBindings}, 3},
	{stageImport, []string{codeInvalidBindings}, 3},
	// The declared-decision stage of ADR-0037 travels the library code verbatim.
	// The codes Append cannot return on an already verified book (encoding,
	// format, sequence, chain, hash, writer) are deliberately absent: if one
	// ever appeared it fails closed as an internal failure.
	{stageCasefile, []string{
		"invalid_book", "book_limit", "record_limit", "field_limit", "control_limit",
		"invalid_decision", "invalid_actor", "invalid_rationale", "invalid_scope",
		"invalid_control", "invalid_timestamp", "invalid_reference",
	}, 3},
	{stageBundleRead, []string{codeInputLimit}, 3},
	{stageContextRead, []string{codeInputLimit}, 3},
	{stagePackRead, []string{codeInputLimit}, 3},
	{stageFindingsRead, []string{codeInputLimit}, 3},
	{stageBindingsRead, []string{codeInputLimit}, 3},
	{stageBundleDecode, []string{codeInputLimit}, 3},
	{stageEvaluate, []string{
		codeInputLimit, "invalid_target", "invalid_bundle", codeInvalidContext,
		"value_hash_mismatch", "missing_pack", "invalid_pack", "unsupported_pack",
		"pack_identity_mismatch", "pack_downgrade", "pack_equivocation",
		"pack_not_yet_valid", "pack_expired", "ruleset_mismatch", "evaluation_limit",
	}, 3},
	{stageBundleRead, []string{codeNotFound, codePermissionDenied, codeInvalidFile, codeReadFailure, codeTimeout}, 4},
	{stageContextRead, []string{codeNotFound, codePermissionDenied, codeInvalidFile, codeReadFailure, codeTimeout}, 4},
	{stagePackRead, []string{codeNotFound, codePermissionDenied, codeInvalidFile, codeReadFailure, codeTimeout}, 4},
	{stageFindingsRead, []string{codeNotFound, codePermissionDenied, codeInvalidFile, codeReadFailure, codeTimeout}, 4},
	{stageBindingsRead, []string{codeNotFound, codePermissionDenied, codeInvalidFile, codeReadFailure, codeTimeout}, 4},
	{stageOutputWrite, []string{codeAlreadyExists, codePermissionDenied, codeInvalidFile, codeWriteFailure, codeTimeout}, 4},
	{stageStdoutWrite, []string{codeWriteFailure, codeTimeout}, 4},
	{stageEvaluate, []string{"bundle_hash_mismatch"}, 5},
	{stageEvaluate, []string{"pack_hash_mismatch"}, 5},
	{stageVerify, []string{codeResultFingerprintMismatch}, 5},
	{stageReport, []string{"invalid_result", codeInvalidBundle, "bundle_hash_mismatch", "invalid_reference", "invalid_report", "render_failure"}, 6},
	{stageInternal, []string{codeInternalFailure}, 6},
}

// failure resolves the status of one stage/code pair. An unknown pair is not a
// table error to report as itself: it fails closed as an internal failure, so no
// unlisted combination can reach the caller as a success or as a made-up row.
func newFailure(stage, code string) *cliError {
	for _, row := range exitRows {
		if row.stage != stage {
			continue
		}
		for _, listed := range row.codes {
			if listed == code {
				return &cliError{stage: stage, code: code, exit: row.exit}
			}
		}
	}
	return &cliError{stage: stageInternal, code: codeInternalFailure, exit: 6}
}

type diagnostic struct {
	Error struct {
		Stage   string `json:"stage"`
		Code    string `json:"code"`
		Message string `json:"message"`
	} `json:"error"`
}

// writeDiagnostic attempts exactly one compact JSON line on stderr. A broken
// stderr cannot be reported recursively: the caller keeps a non-zero status and
// the delivery is simply not guaranteed.
func writeDiagnostic(stderr io.Writer, failure *cliError) {
	payload := diagnostic{}
	payload.Error.Stage = failure.stage
	payload.Error.Code = failure.code
	payload.Error.Message = "ariadne: " + failure.code
	line, err := json.Marshal(payload)
	if err != nil {
		// The vocabulary is closed ASCII, so this branch is unreachable; failing
		// closed keeps it that way without hiding a design error.
		return
	}
	line = append(line, '\n')
	_, _ = stderr.Write(line)
}
