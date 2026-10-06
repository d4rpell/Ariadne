package main

import (
	"io"
	"strconv"

	"github.com/d4rpell/Ariadne/internal/casefile"
	"github.com/d4rpell/Ariadne/internal/platform"
)

// runServe reads one canonical casefile book through the ratified local-path
// frontier (ADR-0023 §6/§7, R-02), verifies it, projects it at the caller's
// as-of instant and serves the read-only dashboard on loopback until the process
// is terminated. It performs no mutation, no egress and no evaluation.
//
// The read and decode failures reuse the existing catalog stages: the casebook
// is the primary canonical input of this command, exactly as the bundle is for
// evaluate. The book is opened only here, in cmd/ariadne.
func runServe(call invocation, stdout io.Writer, cwd string) *cliError {
	port, err := strconv.Atoi(call.value("port"))
	if err != nil {
		// parseCommand already refused a non-canonical port; keep fail-closed.
		return newFailure(stageArguments, codeInvalidArguments)
	}
	bookBytes, failure := readInput(call.value("casebook"), stageBundleRead, casefile.MaxBookBytes, true, cwd)
	if failure != nil {
		return failure
	}
	book, err := casefile.Verify(bookBytes)
	if err != nil {
		return newFailure(stageBundleDecode, codeInvalidBundle)
	}
	model, err := platform.BuildModel(book, call.value("as-of"))
	if err != nil {
		return newFailure(stageBundleDecode, codeInvalidBundle)
	}
	server := platform.NewServer(model)
	if failure := deliverStdout(stdout, "listening on http://"+platform.LoopbackAddress(port)+"\n"); failure != nil {
		return failure
	}
	if err := serveLoop(server, port); err != nil {
		return newFailure(stageInternal, codeInternalFailure)
	}
	return nil
}

// serveLoop is the blocking serve call. It exists so the argument and read paths
// can be exercised without binding a socket; production always serves.
var serveLoop = func(server *platform.Server, port int) error {
	return server.Serve(port)
}
