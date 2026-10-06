package main

import (
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/d4rpell/Ariadne/internal/evaluator"
	"github.com/d4rpell/Ariadne/internal/report"
	"github.com/d4rpell/Ariadne/internal/rulepack"
)

// Runner: the single order of ADR-0023 §5. Arguments first; then reading bundle,
// context and pack without decoding; then the bundle decode with its model-budget
// preflight and its canonical comparison; then the context decoder; then
// Evaluate with its ratified precedence; then report building, encoding and
// fingerprint; and only then the replay comparison or the artifact delivery. The
// destination is never opened before every byte exists.

func run(argv []string, stdout, stderr io.Writer) int {
	call, argumentFailure := parseArguments(argv)
	if argumentFailure != nil {
		writeDiagnostic(stderr, argumentFailure)
		return argumentFailure.exit
	}
	if call.root || call.help {
		if failure := deliverStdout(stdout, call.helpText()); failure != nil {
			writeDiagnostic(stderr, failure)
			return failure.exit
		}
		return 0
	}
	cwd, err := os.Getwd()
	if err != nil {
		failure := newFailure(stageInternal, codeInternalFailure)
		writeDiagnostic(stderr, failure)
		return failure.exit
	}
	if failure := execute(call, stdout, cwd); failure != nil {
		writeDiagnostic(stderr, failure)
		return failure.exit
	}
	return 0
}

func execute(call invocation, stdout io.Writer, cwd string) *cliError {
	// The read-only platform server is its own surface (ADR-0034, task A3-06):
	// it reads one casefile book instead of a bundle, context and pack, so it
	// branches before the evaluation order.
	if call.command == commandServe {
		return runServe(call, stdout, cwd)
	}
	// Phase 1-2: every read precedes every decode, in the ratified order.
	bundleBytes, failure := readInput(call.value("bundle"), stageBundleRead, maxBundleInputBytes, true, cwd)
	if failure != nil {
		return failure
	}
	contextBytes, failure := readInput(call.value("context"), stageContextRead, maxContextInputBytes, true, cwd)
	if failure != nil {
		return failure
	}
	packBytes, failure := readInput(call.value("pack"), stagePackRead, rulepack.MaxPackBytes, false, cwd)
	if failure != nil {
		return failure
	}

	// Phase 3: typed bundle decode, its budgets and its canonical comparison,
	// and only then the context decoder.
	decodedBundle, failure := decodeBundle(bundleBytes)
	if failure != nil {
		return failure
	}
	document, err := decodeContext(contextBytes)
	if err != nil {
		return newFailure(stageContextDecode, codeInvalidContext)
	}

	// Phase 4: Evaluate keeps its own ratified precedence; its failures are
	// mapped by code, never by message.
	result, err := evaluator.Evaluate(evaluator.Request{
		Bundle:             decodedBundle,
		ExpectedBundleHash: call.value("bundle-hash"),
		Target:             document.target,
		PackBytes:          packBytes,
		Admission:          document.admission,
		Domain:             document.domain,
	})
	if err != nil {
		return kernelFailure(err)
	}

	// Phase 5: presentation in memory and the fingerprint over its exact bytes.
	rendered, err := report.Build(result, decodedBundle)
	if err != nil {
		return rendererFailure(err)
	}
	jsonBytes, err := report.JSON(rendered)
	if err != nil {
		return rendererFailure(err)
	}
	fingerprint := resultFingerprint(jsonBytes)
	if fingerprint == "" {
		return newFailure(stageInternal, codeInternalFailure)
	}

	// Phase 6: the replay comparison or the artifact delivery.
	switch call.command {
	case commandEvaluate:
		receipt := fmt.Sprintf("{\"bundle_hash\":%q,\"result_fingerprint\":%q}\n", result.BundleHash, fingerprint)
		return deliverStdout(stdout, receipt)
	case commandVerify:
		if fingerprint != call.value("result-fingerprint") {
			return newFailure(stageVerify, codeResultFingerprintMismatch)
		}
		return deliverStdout(stdout, "verified\n")
	case commandReport:
		documentBytes := jsonBytes
		if call.value("format") == "html" {
			documentBytes, err = report.HTML(rendered)
			if err != nil {
				return rendererFailure(err)
			}
		}
		return writeOutput(call.value("out"), documentBytes, cwd)
	}
	return newFailure(stageInternal, codeInternalFailure)
}

// kernelFailure maps one evaluator or pack admission failure to the ratified
// stage/code table. The code travels as itself and the table decides the status;
// a code outside the table fails closed.
func kernelFailure(err error) *cliError {
	var evaluation *evaluator.Error
	if errors.As(err, &evaluation) {
		return newFailure(stageEvaluate, string(evaluation.Code))
	}
	var admission *rulepack.Error
	if errors.As(err, &admission) {
		return newFailure(stageEvaluate, string(admission.Code))
	}
	return newFailure(stageInternal, codeInternalFailure)
}

// rendererFailure maps one report failure to its own stage. The renderer codes
// are their own set; nothing of the input leaks into the diagnostic.
func rendererFailure(err error) *cliError {
	var rendering *report.Error
	if errors.As(err, &rendering) {
		return newFailure(stageReport, string(rendering.Code))
	}
	return newFailure(stageInternal, codeInternalFailure)
}
