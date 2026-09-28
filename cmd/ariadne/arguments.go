package main

import (
	"strings"
)

// Command names of the ratified surface (ADR-0023 §4.1). The deferred ones are
// known and rejected with their own code: they are not aliases and they must not
// appear to work.
const (
	commandEvaluate = "evaluate"
	commandReport   = "report"
	commandVerify   = "verify"
)

var deferredCommands = []string{"import", "normalize", "diff"}

// helpLines are the exact ratified texts of ADR-0023 §4.1. They are constants of
// this package, not data from any file, and the tests freeze them byte a byte.
const (
	helpRoot = "Usage: ariadne <evaluate|report|verify> [flags]\n" +
		"Use ariadne <command> --help for required flags.\n" +
		"Pre-alpha. Offline. Report distribution is not authorized.\n"
	helpLastLine = "Pre-alpha. Offline. Report distribution is not authorized.\n"
)

// flagSet is the complete and only admitted flag set of one command, in the
// order the usage line declares. A set is exact: a flag of another set, a
// repeated flag or an unknown name is rejected.
type flagSet []string

var (
	flagsEvaluate = flagSet{"bundle", "bundle-hash", "pack", "context"}
	flagsReport   = flagSet{"bundle", "bundle-hash", "pack", "context", "format", "out"}
	flagsVerify   = flagSet{"bundle", "bundle-hash", "pack", "context", "result-fingerprint"}
)

// invocation is one parsed command with its flags resolved. Values are literals
// from argv: no expansion, no normalization and no default.
type invocation struct {
	command string
	help    bool
	root    bool
	values  map[string]string
}

func (call invocation) value(name string) string { return call.values[name] }

// parseArguments is the complete argument phase: the first failure of §5
// precedence. It reads no file and touches no path.
func parseArguments(argv []string) (invocation, *cliError) {
	if len(argv) == 0 {
		return invocation{}, newFailure(stageArguments, codeInvalidArguments)
	}
	name := argv[0]
	if strings.HasPrefix(name, "-") {
		// A flag where a command or the exact `--help` belongs.
		if name == "--help" && len(argv) == 1 {
			return invocation{root: true}, nil
		}
		return invocation{}, newFailure(stageArguments, codeInvalidArguments)
	}
	switch name {
	case commandEvaluate:
		return parseCommand(commandEvaluate, flagsEvaluate, argv[1:])
	case commandReport:
		return parseCommand(commandReport, flagsReport, argv[1:])
	case commandVerify:
		return parseCommand(commandVerify, flagsVerify, argv[1:])
	}
	for _, deferred := range deferredCommands {
		if name == deferred {
			// Deferred: the surface is known and refuses to be an alias, with or
			// without `--help`.
			return invocation{}, newFailure(stageArguments, codeCommandDeferred)
		}
	}
	return invocation{}, newFailure(stageArguments, codeUnknownCommand)
}

func parseCommand(command string, admitted flagSet, rest []string) (invocation, *cliError) {
	if len(rest) == 1 && rest[0] == "--help" {
		return invocation{command: command, help: true}, nil
	}
	if len(rest) == 0 {
		return invocation{}, newFailure(stageArguments, codeInvalidArguments)
	}
	values := map[string]string{}
	for index := 0; index < len(rest); index++ {
		token := rest[index]
		// Only the exact `--name value` pair exists: `--name=value`, short flags
		// and the `--` terminator are not this grammar.
		if !strings.HasPrefix(token, "--") || token == "--" || len(token) == 2 {
			return invocation{}, newFailure(stageArguments, codeInvalidArguments)
		}
		name := token[2:]
		if !admitted.has(name) {
			return invocation{}, newFailure(stageArguments, codeInvalidArguments)
		}
		if index+1 >= len(rest) {
			return invocation{}, newFailure(stageArguments, codeInvalidArguments)
		}
		value := rest[index+1]
		if value == "" || value == "-" || strings.HasPrefix(value, "--") {
			// An empty value, the exact token `-` — which designates no valid
			// file in this grammar and must never reach the filesystem as a
			// literal name — and a token that looks like a flag are all refused;
			// a path with the `--` prefix needs the explicit ./ spelling.
			return invocation{}, newFailure(stageArguments, codeInvalidArguments)
		}
		if _, repeated := values[name]; repeated {
			return invocation{}, newFailure(stageArguments, codeInvalidArguments)
		}
		values[name] = value
		index++
	}
	// Every flag of the set is mandatory; a missing one is the same rejection.
	for _, name := range admitted {
		if _, present := values[name]; !present {
			return invocation{}, newFailure(stageArguments, codeInvalidArguments)
		}
	}
	// The closed vocabularies of the interface are argument grammar: a hash that
	// is not `sha256:` plus 64 lowercase hex and a format outside json|html are
	// the same rejection as an unknown flag, decided before any file is read.
	if !isSha256Text(values["bundle-hash"]) {
		return invocation{}, newFailure(stageArguments, codeInvalidArguments)
	}
	if command == commandVerify && !isSha256Text(values["result-fingerprint"]) {
		return invocation{}, newFailure(stageArguments, codeInvalidArguments)
	}
	if command == commandReport {
		switch values["format"] {
		case "json", "html":
		default:
			return invocation{}, newFailure(stageArguments, codeInvalidArguments)
		}
	}
	return invocation{command: command, values: values}, nil
}

func (set flagSet) has(name string) bool {
	for _, candidate := range set {
		if candidate == name {
			return true
		}
	}
	return false
}

// helpText returns the exact help of one parsed request. Root help and command
// help are static text: they open no path and read no environment.
func (call invocation) helpText() string {
	switch {
	case call.root:
		return helpRoot
	case call.command == commandEvaluate:
		return "Usage: ariadne evaluate --bundle PATH --bundle-hash H --pack PATH --context PATH\n" + helpLastLine
	case call.command == commandReport:
		return "Usage: ariadne report --bundle PATH --bundle-hash H --pack PATH --context PATH --format json|html --out PATH\n" + helpLastLine
	case call.command == commandVerify:
		return "Usage: ariadne verify --bundle PATH --bundle-hash H --pack PATH --context PATH --result-fingerprint H\n" + helpLastLine
	}
	return ""
}
