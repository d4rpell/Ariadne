package main

import (
	"strconv"
	"strings"

	"github.com/d4rpell/Ariadne/internal/casefile"
)

// Command names of the ratified surface (ADR-0023 §4.1), the read-only
// platform server (ADR-0034, task A3-06), the CSV-to-case import pipeline
// (ADR-0036, task A3-09) and the casefile book persistence commands
// (ADR-0037, task A3-11). The deferred ones are known and rejected with their
// own code: they are not aliases and they must not appear to work.
const (
	commandEvaluate = "evaluate"
	commandReport   = "report"
	commandVerify   = "verify"
	commandServe    = "serve"
	commandImport   = "import"
	commandBook     = "book"
	commandAppend   = "append"
	commandDiff     = "diff"
)

var deferredCommands = []string{"normalize"}

// helpLines are the exact ratified texts of ADR-0023 §4.1 as extended by
// ADR-0036, ADR-0037, ADR-0038 and ADR-0039. They are constants of this
// package, not data from any file, and the tests freeze them byte a byte.
const (
	helpRoot = "Usage: ariadne <book|append|diff|evaluate|report|verify|import|serve> [flags]\n" +
		"Use ariadne <command> --help for required flags.\n" +
		"MVP complete. Offline.\n"
	helpLastLine = "MVP complete. Offline.\n"
)

// flagSet is the complete and only admitted flag set of one command, in the
// order the usage line declares. A set is exact: a flag of another set, a
// repeated flag or an unknown name is rejected.
type flagSet []string

var (
	flagsEvaluate = flagSet{"bundle", "bundle-hash", "pack", "context"}
	flagsReport   = flagSet{"bundle", "bundle-hash", "pack", "context", "format", "out"}
	flagsVerify   = flagSet{"bundle", "bundle-hash", "pack", "context", "result-fingerprint"}
	flagsServe    = flagSet{"casebook", "as-of", "port"}
	flagsImport   = flagSet{"findings", "bindings", "observed-at", "out-envelope", "out-projection", "out-digest"}
	flagsBook     = flagSet{"out"}
	flagsAppend   = flagSet{"casebook", "decision", "owner", "approver", "rationale", "bundle-hash",
		"subject-uid", "container-name", "container-class", "vulnerability-id",
		"decided-at", "expires-at", "supersedes", "result-fingerprint", "controls", "out"}
	flagsDiff = flagSet{"casebook", "since", "as-of", "out"}

	// optionalAppend names the flags of append whose absence is meaningful:
	// an undeclared expiry, no supersession, no fingerprint and no controls.
	optionalAppend = flagSet{"expires-at", "supersedes", "result-fingerprint", "controls"}
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
	case commandServe:
		return parseCommand(commandServe, flagsServe, argv[1:])
	case commandImport:
		return parseCommand(commandImport, flagsImport, argv[1:])
	case commandBook:
		return parseCommand(commandBook, flagsBook, argv[1:])
	case commandAppend:
		return parseCommand(commandAppend, flagsAppend, argv[1:])
	case commandDiff:
		return parseCommand(commandDiff, flagsDiff, argv[1:])
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
		value := rest[index+1] //nolint:gosec // bounds guarded by the check above (G602 cannot follow it)
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
	// Every flag of the set is mandatory, except the declared optional flags of
	// append (ADR-0037): their absence is declared absence, never a default
	// value. A missing mandatory flag is the same rejection.
	optional := flagSet(nil)
	if command == commandAppend {
		optional = optionalAppend
	}
	for _, name := range admitted {
		if optional.has(name) {
			continue
		}
		if _, present := values[name]; !present {
			return invocation{}, newFailure(stageArguments, codeInvalidArguments)
		}
	}
	// The closed vocabularies of the interface are argument grammar: a hash that
	// is not `sha256:` plus 64 lowercase hex and a format outside json|html are
	// the same rejection as an unknown flag, decided before any file is read.
	// Only the bundle-consuming commands carry a bundle hash. The import command
	// carries no bundle hash: its instant is its grammar check, decided with the
	// same rule as the server's as-of. The persistence commands of ADR-0037
	// declare their own vocabularies in their own block below.
	if command == commandEvaluate || command == commandReport || command == commandVerify {
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
	}
	if command == commandServe {
		// The port and the as-of instant are argument grammar: a port outside
		// 1..65535 and an instant the canonical timestamp profile rejects are the
		// same rejection as an unknown flag, decided before any file is read. The
		// instant is validated by the very function that consumes it.
		if !validPortText(values["port"]) {
			return invocation{}, newFailure(stageArguments, codeInvalidArguments)
		}
		if _, err := casefile.Assess(casefile.NewBook(), values["as-of"]); err != nil {
			return invocation{}, newFailure(stageArguments, codeInvalidArguments)
		}
	}
	if command == commandImport {
		// The observation instant is argument grammar (ADR-0036): a non-canonical
		// spelling is rejected before any file is read, and the same canonical
		// value is rebuilt once here so the pipeline never re-parses it.
		if _, ok := canonicalTimestamp(values["observed-at"]); !ok {
			return invocation{}, newFailure(stageArguments, codeInvalidArguments)
		}
	}
	if command == commandAppend {
		// The declared decision carries its own closed vocabularies and reference
		// grammars (ADR-0037): the decision and the container class admit only
		// the casefile words, the three hashes are sha256 text and the two
		// instants follow the stricter casefile profile, validated by the very
		// function that consumes it — all before any file is read.
		switch values["decision"] {
		case string(casefile.DecisionAccepted), string(casefile.DecisionDeferred), string(casefile.DecisionRejected):
		default:
			return invocation{}, newFailure(stageArguments, codeInvalidArguments)
		}
		switch values["container-class"] {
		case string(casefile.ContainerRegular), string(casefile.ContainerInit), string(casefile.ContainerEphemeral):
		default:
			return invocation{}, newFailure(stageArguments, codeInvalidArguments)
		}
		// Optional flags are only validated when declared: absence is absence,
		// never an empty value to check.
		for _, hashFlag := range []string{"bundle-hash", "supersedes", "result-fingerprint"} {
			if _, declared := values[hashFlag]; declared && !isSha256Text(values[hashFlag]) {
				return invocation{}, newFailure(stageArguments, codeInvalidArguments)
			}
		}
		for _, instantFlag := range []string{"decided-at", "expires-at"} {
			if _, declared := values[instantFlag]; declared {
				if _, err := casefile.Assess(casefile.NewBook(), values[instantFlag]); err != nil {
					return invocation{}, newFailure(stageArguments, codeInvalidArguments)
				}
			}
		}
		if _, declared := values["controls"]; declared {
			if _, ok := parseControls(values["controls"]); !ok {
				return invocation{}, newFailure(stageArguments, codeInvalidArguments)
			}
		}
	}
	if command == commandDiff {
		// The two instants follow the stricter casefile profile and are validated by
		// the very function that consumes them; the interval must not be inverted —
		// the canonical form is zero-padded, so byte order is chronological — all
		// before any file is read.
		for _, instantFlag := range []string{"since", "as-of"} {
			if _, err := casefile.Assess(casefile.NewBook(), values[instantFlag]); err != nil {
				return invocation{}, newFailure(stageArguments, codeInvalidArguments)
			}
		}
		if values["since"] > values["as-of"] {
			return invocation{}, newFailure(stageArguments, codeInvalidArguments)
		}
	}
	return invocation{command: command, values: values}, nil
}

// parseControls splits the declared controls list. The values are literals: no
// trimming and no quoting. An empty element — an empty text, a leading or
// trailing comma, or an empty position between commas — is a grammar failure,
// because it would silently name no control. The absence of the flag is the
// absence of declared controls, never an empty list value.
func parseControls(text string) ([]string, bool) {
	if text == "" {
		return nil, true
	}
	parts := strings.Split(text, ",")
	controls := make([]string, len(parts))
	for index, part := range parts {
		if part == "" {
			return nil, false
		}
		controls[index] = part
	}
	return controls, true
}

// validPortText admits the decimal spelling of an integer in 1..65535: digits
// only, no sign and no whitespace.
func validPortText(value string) bool {
	if value == "" {
		return false
	}
	for index := 0; index < len(value); index++ {
		if value[index] < '0' || value[index] > '9' {
			return false
		}
	}
	port, err := strconv.Atoi(value)
	if err != nil {
		return false
	}
	return port >= 1 && port <= 65535
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
	case call.command == commandServe:
		return "Usage: ariadne serve --casebook PATH --as-of TIMESTAMP --port N\n" + helpLastLine
	case call.command == commandImport:
		return "Usage: ariadne import --findings PATH --bindings PATH --observed-at TIMESTAMP --out-envelope PATH --out-projection PATH --out-digest PATH\n" + helpLastLine
	case call.command == commandBook:
		return "Usage: ariadne book --out PATH\n" + helpLastLine
	case call.command == commandAppend:
		return "Usage: ariadne append --casebook PATH --decision accepted|deferred|rejected --owner TEXT --approver TEXT --rationale TEXT --bundle-hash H --subject-uid TEXT --container-name TEXT --container-class regular|init|ephemeral --vulnerability-id TEXT --decided-at TIMESTAMP [--expires-at TIMESTAMP] [--supersedes H] [--result-fingerprint H] [--controls LIST] --out PATH\n" + helpLastLine
	case call.command == commandDiff:
		return "Usage: ariadne diff --casebook PATH --since TIMESTAMP --as-of TIMESTAMP --out PATH\n" + helpLastLine
	}
	return ""
}
