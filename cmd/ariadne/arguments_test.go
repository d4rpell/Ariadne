package main

import (
	"bytes"
	"strings"
	"testing"
)

// CLI-01..CLI-04: the complete argument matrix. Each rejection is asserted as a
// whole (exit 2, stage arguments, code invalid_arguments, empty stdout) and each
// timeout-free case reads no file: the calls run against a working directory
// that does not exist, so any path access would surface as a different failure.

const (
	validHashA  = "sha256:1111111111111111111111111111111111111111111111111111111111111111"
	validHashB  = "sha256:2222222222222222222222222222222222222222222222222222222222222222"
	validFinger = "sha256:3333333333333333333333333333333333333333333333333333333333333333"
)

func runCLI(t *testing.T, argv []string) (int, string, string) {
	t.Helper()
	var stdout, stderr bytes.Buffer
	code := run(argv, &stdout, &stderr)
	return code, stdout.String(), stderr.String()
}

func expectRejection(t *testing.T, argv []string, stage, code string, exit int) {
	t.Helper()
	gotExit, stdout, stderr := runCLI(t, argv)
	if gotExit != exit {
		t.Fatalf("exit = %d, want %d (stderr %q)", gotExit, exit, stderr)
	}
	if stdout != "" {
		t.Fatalf("stdout = %q, want empty", stdout)
	}
	want := `{"error":{"stage":"` + stage + `","code":"` + code + `","message":"ariadne: ` + code + `"}}` + "\n"
	if stderr != want {
		t.Fatalf("stderr = %q, want %q", stderr, want)
	}
}

func baseEvaluate() []string {
	return []string{"evaluate",
		"--bundle", "b.json", "--bundle-hash", validHashA,
		"--pack", "p.json", "--context", "c.json"}
}

func TestArgumentsRejections(t *testing.T) {
	cases := []struct {
		name string
		argv []string
	}{
		{"no arguments", nil},
		{"flag in command position", []string{"--bundle", "x"}},
		{"missing every flag", []string{"evaluate"}},
		{"missing one flag", []string{"evaluate", "--bundle", "b", "--bundle-hash", validHashA, "--pack", "p"}},
		{"flag of another command", append(baseEvaluate(), "--format", "json")},
		{"unknown flag", append(baseEvaluate(), "--extra", "x")},
		{"duplicate flag equal value", []string{"evaluate", "--bundle", "b", "--bundle", "b",
			"--bundle-hash", validHashA, "--pack", "p", "--context", "c"}},
		{"duplicate flag different value", []string{"evaluate", "--bundle", "b", "--bundle", "b2",
			"--bundle-hash", validHashA, "--pack", "p", "--context", "c"}},
		{"empty value", []string{"evaluate", "--bundle", "", "--bundle-hash", validHashA,
			"--pack", "p", "--context", "c"}},
		{"value looks like a flag", []string{"evaluate", "--bundle", "--bundle-hash",
			"--bundle-hash", validHashA, "--pack", "p", "--context", "c"}},
		{"value absent at the end", []string{"evaluate", "--bundle", "b", "--bundle-hash", validHashA,
			"--pack", "p", "--context"}},
		{"equals form", []string{"evaluate", "--bundle=b", "--bundle-hash", validHashA,
			"--pack", "p", "--context", "c"}},
		{"short flag", []string{"evaluate", "-b", "b", "--bundle-hash", validHashA,
			"--pack", "p", "--context", "c"}},
		{"terminator", []string{"evaluate", "--", "--bundle", "b", "--bundle-hash", validHashA,
			"--pack", "p", "--context", "c"}},
		{"case changed flag", []string{"evaluate", "--Bundle", "b", "--bundle-hash", validHashA,
			"--pack", "p", "--context", "c"}},
		{"extra operand", append(baseEvaluate(), "surplus")},
		{"help mixed with flags", append([]string{"evaluate", "--help"}, baseEvaluate()[1:]...)},
		{"bundle hash not sha256", []string{"evaluate", "--bundle", "b", "--bundle-hash", "md5:abc",
			"--pack", "p", "--context", "c"}},
		{"bundle hash short", []string{"evaluate", "--bundle", "b", "--bundle-hash",
			"sha256:111111111111111111111111111111111111111111111111111111111111111", "--pack", "p", "--context", "c"}},
		{"bundle hash uppercase", []string{"evaluate", "--bundle", "b", "--bundle-hash",
			"sha256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", "--pack", "p", "--context", "c"}},
		{"fingerprint not sha256", []string{"verify", "--bundle", "b", "--bundle-hash", validHashA,
			"--pack", "p", "--context", "c", "--result-fingerprint", "sha256:xyz"}},
		{"format unknown", []string{"report", "--bundle", "b", "--bundle-hash", validHashA,
			"--pack", "p", "--context", "c", "--format", "xml", "--out", "o"}},
		{"format uppercase", []string{"report", "--bundle", "b", "--bundle-hash", validHashA,
			"--pack", "p", "--context", "c", "--format", "JSON", "--out", "o"}},
		{"format empty", []string{"report", "--bundle", "b", "--bundle-hash", validHashA,
			"--pack", "p", "--context", "c", "--format", "", "--out", "o"}},
		{"format list", []string{"report", "--bundle", "b", "--bundle-hash", validHashA,
			"--pack", "p", "--context", "c", "--format", "json,html", "--out", "o"}},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			expectRejection(t, testCase.argv, stageArguments, codeInvalidArguments, 2)
		})
	}
}

func TestArgumentsDeferredCommands(t *testing.T) {
	for _, name := range deferredCommands {
		t.Run(name, func(t *testing.T) {
			expectRejection(t, []string{name}, stageArguments, codeCommandDeferred, 2)
			expectRejection(t, []string{name, "--help"}, stageArguments, codeCommandDeferred, 2)
			expectRejection(t, []string{name, "--bundle", "b"}, stageArguments, codeCommandDeferred, 2)
		})
	}
}

func TestArgumentsUnknownCommand(t *testing.T) {
	expectRejection(t, []string{"evaluat"}, stageArguments, codeUnknownCommand, 2)
}

func TestArgumentsHelpExact(t *testing.T) {
	cases := []struct {
		argv []string
		want string
	}{
		{[]string{"--help"},
			"Usage: ariadne <book|append|evaluate|report|verify|import|serve> [flags]\n" +
				"Use ariadne <command> --help for required flags.\n" +
				"Pre-alpha. Offline. Report distribution is not authorized.\n"},
		{[]string{"evaluate", "--help"},
			"Usage: ariadne evaluate --bundle PATH --bundle-hash H --pack PATH --context PATH\n" +
				"Pre-alpha. Offline. Report distribution is not authorized.\n"},
		{[]string{"report", "--help"},
			"Usage: ariadne report --bundle PATH --bundle-hash H --pack PATH --context PATH --format json|html --out PATH\n" +
				"Pre-alpha. Offline. Report distribution is not authorized.\n"},
		{[]string{"verify", "--help"},
			"Usage: ariadne verify --bundle PATH --bundle-hash H --pack PATH --context PATH --result-fingerprint H\n" +
				"Pre-alpha. Offline. Report distribution is not authorized.\n"},
		{[]string{"serve", "--help"},
			"Usage: ariadne serve --casebook PATH --as-of TIMESTAMP --port N\n" +
				"Pre-alpha. Offline. Report distribution is not authorized.\n"},
		{[]string{"import", "--help"},
			"Usage: ariadne import --findings PATH --bindings PATH --observed-at TIMESTAMP --out-envelope PATH --out-projection PATH --out-digest PATH\n" +
				"Pre-alpha. Offline. Report distribution is not authorized.\n"},
		{[]string{"book", "--help"},
			"Usage: ariadne book --out PATH\n" +
				"Pre-alpha. Offline. Report distribution is not authorized.\n"},
		{[]string{"append", "--help"},
			"Usage: ariadne append --casebook PATH --decision accepted|deferred|rejected --owner TEXT --approver TEXT --rationale TEXT --bundle-hash H --subject-uid TEXT --container-name TEXT --container-class regular|init|ephemeral --vulnerability-id TEXT --decided-at TIMESTAMP [--expires-at TIMESTAMP] [--supersedes H] [--result-fingerprint H] [--controls LIST] --out PATH\n" +
				"Pre-alpha. Offline. Report distribution is not authorized.\n"},
	}
	for _, testCase := range cases {
		t.Run(strings.Join(testCase.argv, " "), func(t *testing.T) {
			exit, stdout, stderr := runCLI(t, testCase.argv)
			if exit != 0 || stderr != "" || stdout != testCase.want {
				t.Fatalf("exit=%d stdout=%q stderr=%q, want exit 0 and exact help", exit, stdout, stderr)
			}
		})
	}
}

// The order of admitted pairs is free: the same request parses in any
// permutation.
func TestArgumentsOrderFreedom(t *testing.T) {
	permuted := []string{"evaluate",
		"--context", "c.json", "--pack", "p.json",
		"--bundle-hash", validHashA, "--bundle", "b.json"}
	call, failure := parseArguments(permuted)
	if failure != nil {
		t.Fatalf("permuted arguments rejected: %v", failure)
	}
	if call.value("bundle") != "b.json" || call.value("context") != "c.json" {
		t.Fatalf("values not resolved: %+v", call.values)
	}
}
