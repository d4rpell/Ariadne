package main

import (
	"io/fs"
	"strings"
	"testing"
)

// a108ExitTable is the independent transcription of the 56 stage/code/exit pairs
// of ADR-0023 §5, written as string literals. It never iterates exitRows and
// never reuses production constants as its only vocabulary proof: the table
// below is data the production table must match, in both directions.
var a108ExitTable = []struct {
	stage string
	code  string
	exit  int
}{
	{"arguments", "invalid_arguments", 2},
	{"arguments", "unknown_command", 2},
	{"arguments", "command_deferred", 2},
	{"bundle_decode", "invalid_bundle", 3},
	{"context_decode", "invalid_context", 3},
	{"bundle_read", "input_limit", 3},
	{"context_read", "input_limit", 3},
	{"pack_read", "input_limit", 3},
	{"bundle_decode", "input_limit", 3},
	{"evaluate", "input_limit", 3},
	{"evaluate", "invalid_target", 3},
	{"evaluate", "invalid_bundle", 3},
	{"evaluate", "invalid_context", 3},
	{"evaluate", "value_hash_mismatch", 3},
	{"evaluate", "missing_pack", 3},
	{"evaluate", "invalid_pack", 3},
	{"evaluate", "unsupported_pack", 3},
	{"evaluate", "pack_identity_mismatch", 3},
	{"evaluate", "pack_downgrade", 3},
	{"evaluate", "pack_equivocation", 3},
	{"evaluate", "pack_not_yet_valid", 3},
	{"evaluate", "pack_expired", 3},
	{"evaluate", "ruleset_mismatch", 3},
	{"evaluate", "evaluation_limit", 3},
	{"bundle_read", "not_found", 4},
	{"bundle_read", "permission_denied", 4},
	{"bundle_read", "invalid_file", 4},
	{"bundle_read", "read_failure", 4},
	{"bundle_read", "timeout", 4},
	{"context_read", "not_found", 4},
	{"context_read", "permission_denied", 4},
	{"context_read", "invalid_file", 4},
	{"context_read", "read_failure", 4},
	{"context_read", "timeout", 4},
	{"pack_read", "not_found", 4},
	{"pack_read", "permission_denied", 4},
	{"pack_read", "invalid_file", 4},
	{"pack_read", "read_failure", 4},
	{"pack_read", "timeout", 4},
	{"output_write", "already_exists", 4},
	{"output_write", "permission_denied", 4},
	{"output_write", "invalid_file", 4},
	{"output_write", "write_failure", 4},
	{"output_write", "timeout", 4},
	{"stdout_write", "write_failure", 4},
	{"stdout_write", "timeout", 4},
	{"evaluate", "bundle_hash_mismatch", 5},
	{"evaluate", "pack_hash_mismatch", 5},
	{"verify", "result_fingerprint_mismatch", 5},
	{"report", "invalid_result", 6},
	{"report", "invalid_bundle", 6},
	{"report", "bundle_hash_mismatch", 6},
	{"report", "invalid_reference", 6},
	{"report", "invalid_report", 6},
	{"report", "render_failure", 6},
	{"internal", "internal_failure", 6},
}

// TestA108AllDiagnosticBytes covers C01 and I-15: every one of the 56 pairs
// resolves to its stage, code, exit and exact diagnostic bytes, and the
// independent table and the production table are equal as sets.
func TestA108AllDiagnosticBytes(t *testing.T) {
	if len(a108ExitTable) != 56 {
		t.Fatalf("the independent table carries %d pairs, want the ratified 56", len(a108ExitTable))
	}

	t.Run("every pair produces its exact diagnostic line", func(t *testing.T) {
		seen := map[[2]string]bool{}
		for _, row := range a108ExitTable {
			key := [2]string{row.stage, row.code}
			if seen[key] {
				t.Fatalf("the independent table repeats the pair %v", key)
			}
			seen[key] = true

			failure := newFailure(row.stage, row.code)
			if failure.stage != row.stage || failure.code != row.code {
				t.Fatalf("newFailure(%q, %q) = %q/%q", row.stage, row.code, failure.stage, failure.code)
			}
			if failure.exit != row.exit {
				t.Fatalf("newFailure(%q, %q).exit = %d, want %d", row.stage, row.code, failure.exit, row.exit)
			}
			var stderr strings.Builder
			writeDiagnostic(&stderr, failure)
			want := `{"error":{"stage":"` + row.stage + `","code":"` + row.code + `","message":"ariadne: ` + row.code + `"}}` + "\n"
			if stderr.String() != want {
				t.Fatalf("diagnostic for %s/%s = %q, want %q", row.stage, row.code, stderr.String(), want)
			}
			if strings.Count(stderr.String(), "\n") != 1 {
				t.Fatalf("diagnostic for %s/%s must carry exactly one LF", row.stage, row.code)
			}
		}
	})

	t.Run("the production table equals the independent table as a set", func(t *testing.T) {
		production := map[[2]string]bool{}
		for _, row := range exitRows {
			for _, code := range row.codes {
				production[[2]string{row.stage, code}] = true
			}
		}
		if len(production) != len(a108ExitTable) {
			t.Fatalf("production has %d pairs, the independent table has %d", len(production), len(a108ExitTable))
		}
		for _, row := range a108ExitTable {
			if !production[[2]string{row.stage, row.code}] {
				t.Fatalf("the independent pair %s/%s is absent from the production table", row.stage, row.code)
			}
		}
	})

	t.Run("an unknown pair fails closed", func(t *testing.T) {
		failure := newFailure("evaluate", "a_code_no_adr_declares")
		if failure.stage != "internal" || failure.code != "internal_failure" || failure.exit != 6 {
			t.Fatalf("unknown pair = %+v, want internal/internal_failure/6", failure)
		}
		var stderr strings.Builder
		writeDiagnostic(&stderr, failure)
		want := `{"error":{"stage":"internal","code":"internal_failure","message":"ariadne: internal_failure"}}` + "\n"
		if stderr.String() != want {
			t.Fatalf("unknown pair diagnostic = %q, want %q", stderr.String(), want)
		}
	})
}

// TestA108FailurePrecedence covers C01 and H12: the transport precedence uses
// composite failures that satisfy several categories at once, so swapping two
// clauses turns the case red.
func TestA108FailurePrecedence(t *testing.T) {
	t.Run("read precedence", func(t *testing.T) {
		cases := []struct {
			name    string
			failure error
			want    string
		}{
			{"timeout over permission", compositeFailure{message: "both", is: []error{fs.ErrPermission}, timed: true}, "timeout"},
			{"permission over missing", compositeFailure{message: "both", is: []error{fs.ErrPermission, fs.ErrNotExist}}, "permission_denied"},
			{"missing over generic", compositeFailure{message: "missing and generic", is: []error{fs.ErrNotExist}}, "not_found"},
			{"generic", compositeFailure{message: "unclassified"}, "read_failure"},
		}
		for _, testCase := range cases {
			t.Run(testCase.name, func(t *testing.T) {
				if got := classifyRead(testCase.failure); got != testCase.want {
					t.Fatalf("classifyRead = %q, want %q", got, testCase.want)
				}
			})
		}
	})

	t.Run("create precedence", func(t *testing.T) {
		cases := []struct {
			name    string
			failure error
			want    string
		}{
			{"timeout over permission", compositeFailure{message: "both", is: []error{fs.ErrPermission}, timed: true}, "timeout"},
			{"permission over exists", compositeFailure{message: "both", is: []error{fs.ErrPermission, fs.ErrExist}}, "permission_denied"},
			{"exists", compositeFailure{message: "exists", is: []error{fs.ErrExist}}, "already_exists"},
			{"generic", compositeFailure{message: "unclassified"}, "write_failure"},
		}
		for _, testCase := range cases {
			t.Run(testCase.name, func(t *testing.T) {
				if got := classifyCreate(testCase.failure); got != testCase.want {
					t.Fatalf("classifyCreate = %q, want %q", got, testCase.want)
				}
			})
		}
	})

	t.Run("close never reports not_found or already_exists", func(t *testing.T) {
		// A close failure is a read failure of the transport, whatever is.Is
		// reports, except a real timeout.
		for _, failure := range []error{
			compositeFailure{message: "missing at close", is: []error{fs.ErrNotExist}},
			compositeFailure{message: "permission at close", is: []error{fs.ErrPermission}},
		} {
			if got := classifyClose(failure); got != "read_failure" {
				t.Fatalf("classifyClose = %q, want read_failure", got)
			}
		}
		if got := classifyClose(compositeFailure{message: "timeout at close", timed: true}); got != "timeout" {
			t.Fatalf("classifyClose timeout = %q, want timeout", got)
		}
	})

	t.Run("arguments precede any file access", func(t *testing.T) {
		// A missing path plus invalid arguments: the argument phase refuses first,
		// without opening anything.
		exit, stdout, stderr := runCLI(t, []string{"evaluate", "--bundle", "/definitely/absent.json"})
		if exit != 2 || stdout != "" {
			t.Fatalf("exit = %d, stdout = %q; want the argument rejection", exit, stdout)
		}
		if !strings.Contains(stderr, `"stage":"arguments"`) || !strings.Contains(stderr, `"code":"invalid_arguments"`) {
			t.Fatalf("stderr = %q, want the argument rejection", stderr)
		}
	})
}

// TestA108FlagMatrix covers C01 (flag half): every applicable flag of every
// implemented command is exercised in its rejection forms — absent, repeated,
// empty, missing value, token `-`, value with flag shape, equals form, short
// form, terminator, extra operand, casing, foreign and unknown flags — plus the
// `--format` vocabulary and the help mix. Each row asserts the exact diagnostic
// of the arguments stage, so a flag added or dropped from the grammar fails here.
func TestA108FlagMatrix(t *testing.T) {
	common := []string{"--bundle", "b.json", "--bundle-hash", validHashA,
		"--pack", "p.json", "--context", "c.json"}

	// byCommand lists the flags each implemented command accepts beyond the common
	// set, so the matrix can exercise every flag name against its own command.
	type command struct {
		name     string
		common   []string
		ownFlags []string
		ownPad   []string
	}
	commands := []command{
		{name: "evaluate", common: common},
		{name: "verify", common: common,
			ownFlags: []string{"--result-fingerprint"}, ownPad: []string{validFinger}},
		{name: "report", common: common,
			ownFlags: []string{"--format", "--out"}, ownPad: []string{"json", "out.json"}},
	}

	rejects := func(t *testing.T, name string, argv []string) {
		t.Helper()
		// One subtest per rejection, so the executed count is auditable in the
		// verbose log instead of being an unverifiable claim in the report.
		t.Run(name, func(t *testing.T) {
			exit, stdout, stderr := runCLI(t, argv)
			if exit != 2 || stdout != "" {
				t.Fatalf("%s: exit = %d, stdout = %q; want the argument rejection", name, exit, stdout)
			}
			want := `{"error":{"stage":"arguments","code":"invalid_arguments","message":"ariadne: invalid_arguments"}}` + "\n"
			if stderr != want {
				t.Fatalf("%s: stderr = %q, want %q", name, stderr, want)
			}
		})
	}

	for _, cmd := range commands {
		t.Run(cmd.name, func(t *testing.T) {
			// argvOf builds one valid argv of the command, with the flag/value
			// pairs of every flag it accepts in a fixed order. Variants below are
			// derived from this valid argv, so no rejection can be masked by a
			// malformed base.
			type pair struct{ flag, value string }
			pairs := make([]pair, 0, len(cmd.common)/2+len(cmd.ownFlags))
			for index := 0; index < len(cmd.common); index += 2 {
				pairs = append(pairs, pair{cmd.common[index], cmd.common[index+1]})
			}
			for index := range cmd.ownFlags {
				pairs = append(pairs, pair{cmd.ownFlags[index], cmd.ownPad[index]})
			}
			argvOf := func() []string {
				argv := []string{cmd.name}
				for _, item := range pairs {
					argv = append(argv, item.flag, item.value)
				}
				return argv
			}
			valueOf := func(flag string) string {
				for _, item := range pairs {
					if item.flag == flag {
						return item.value
					}
				}
				return ""
			}
			positionOf := func(argv []string, flag string) int {
				for position := range argv {
					if argv[position] == flag {
						return position
					}
				}
				return -1
			}

			// Every applicable flag — common and own — is exercised in each
			// rejection form, derived from the same valid argv.
			for _, item := range pairs {
				flag := item.flag

				without := make([]string, 0, len(pairs)*2)
				for _, other := range pairs {
					if other.flag == flag {
						continue
					}
					without = append(without, other.flag, other.value)
				}
				rejects(t, flag+" absent", append([]string{cmd.name}, without...))

				duplicated := append(argvOf(), flag, valueOf(flag))
				rejects(t, flag+" repeated equal", duplicated)

				changed := append(argvOf(), flag, "other")
				rejects(t, flag+" repeated different", changed)

				emptied := append([]string{}, argvOf()...)
				emptied[positionOf(emptied, flag)+1] = ""
				rejects(t, flag+" empty", emptied)

				missingValue := append([]string{}, argvOf()...)
				at := positionOf(missingValue, flag)
				missingValue = append(missingValue[:at+1], missingValue[at+2:]...)
				rejects(t, flag+" value absent", missingValue)

				dashed := append([]string{}, argvOf()...)
				dashed[positionOf(dashed, flag)+1] = "-"
				rejects(t, flag+" with the dash token", dashed)

				flagged := append([]string{}, argvOf()...)
				flagged[positionOf(flagged, flag)+1] = "--other"
				rejects(t, flag+" with a flag-shaped value", flagged)

				equals := append([]string{}, argvOf()...)
				at = positionOf(equals, flag)
				equals[at] = flag + "=" + valueOf(flag)
				equals = append(equals[:at+1], equals[at+2:]...)
				rejects(t, flag+" in the equals form", equals)

				short := append([]string{}, argvOf()...)
				short[positionOf(short, flag)] = "-" + strings.TrimPrefix(flag, "--")[:1]
				rejects(t, flag+" in the short form", short)

				cased := append([]string{}, argvOf()...)
				at = positionOf(cased, flag)
				cased[at] = "--" + strings.ToUpper(flag[2:3]) + flag[3:]
				rejects(t, flag+" with different casing", cased)
			}

			helpMix := append([]string{cmd.name, "--help"}, argvOf()[1:]...)
			rejects(t, "help mixed with flags", helpMix)

			extra := append(argvOf(), "surplus")
			rejects(t, "extra operand", extra)

			terminator := append([]string{cmd.name, "--"}, argvOf()[1:]...)
			rejects(t, "terminator", terminator)

			foreignFlag := "--format"
			if cmd.name == "report" {
				foreignFlag = "--result-fingerprint"
			}
			foreign := append(argvOf(), foreignFlag, validFinger)
			rejects(t, "flag of another command", foreign)

			unknown := append(argvOf(), "--extra", "x")
			rejects(t, "unknown flag", unknown)
		})
	}

	t.Run("report format vocabulary", func(t *testing.T) {
		for _, value := range []string{"xml", "JSON", "", "json,html", "html,json"} {
			argv := []string{"report"}
			argv = append(argv, common...)
			argv = append(argv, "--format", value, "--out", "out.json")
			rejects(t, "format "+value, argv)
		}
	})

	t.Run("help and deferred commands stay exact", func(t *testing.T) {
		// The four help texts are golden-compared elsewhere; here only the zero
		// exit contract is pinned so the matrix cannot silently swallow `--help`.
		for _, argv := range [][]string{
			{"--help"}, {"evaluate", "--help"}, {"report", "--help"}, {"verify", "--help"},
		} {
			exit, _, stderr := runCLI(t, argv)
			if exit != 0 || stderr != "" {
				t.Fatalf("%v: exit = %d, stderr = %q; want exit 0 and clean stderr", argv, exit, stderr)
			}
		}
		for _, name := range []string{"import", "normalize", "diff"} {
			t.Run(name+" deferred", func(t *testing.T) {
				exit, stdout, stderr := runCLI(t, []string{name})
				if exit != 2 || stdout != "" {
					t.Fatalf("exit = %d, stdout = %q; want the deferred rejection", exit, stdout)
				}
				want := `{"error":{"stage":"arguments","code":"command_deferred","message":"ariadne: command_deferred"}}` + "\n"
				if stderr != want {
					t.Fatalf("stderr = %q, want %q", stderr, want)
				}
			})
		}
	})
}

// TestA108IOFailures covers C04: the unit-level IO failures keep the ratified
// classification through the existing doubles. The precedence is the subject;
// the doubles are not presented as real filesystem failures.
func TestA108IOFailures(t *testing.T) {
	t.Run("a composite read failure never loses its category", func(t *testing.T) {
		if got := classifyRead(compositeFailure{message: "timeout and missing", is: []error{fs.ErrNotExist}, timed: true}); got != "timeout" {
			t.Fatalf("classifyRead = %q, want timeout: the first clause must win", got)
		}
	})

	t.Run("a short stdout delivery is a write failure and not a success", func(t *testing.T) {
		short := &shortWriter{failAfter: 3}
		failure := deliverStdout(short, "a long delivery")
		if failure == nil {
			t.Fatal("a short delivery must be reported")
		}
		if failure.code != "write_failure" || failure.exit != 4 {
			t.Fatalf("failure = %+v, want write_failure/4", failure)
		}
	})

	t.Run("a timeout on stdout is classified as timeout", func(t *testing.T) {
		failure := deliverStdout(timeoutWriter{}, "a long delivery")
		if failure == nil || failure.code != "timeout" || failure.exit != 4 {
			t.Fatalf("failure = %+v, want timeout/4", failure)
		}
	})
}

// shortWriter accepts a fixed amount of bytes and then reports a short write.
type shortWriter struct {
	failAfter int
	written   int
}

func (writer *shortWriter) Write(data []byte) (int, error) {
	room := writer.failAfter - writer.written
	if room <= 0 {
		return 0, nil
	}
	if room > len(data) {
		room = len(data)
	}
	writer.written += room
	return room, nil
}

// timeoutWriter always fails with a timeout.
type timeoutWriter struct{}

func (timeoutWriter) Write([]byte) (int, error) {
	return 0, timeoutFailure{}
}
