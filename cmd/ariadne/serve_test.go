package main

import (
	"errors"
	"testing"

	"github.com/d4rpell/Ariadne/internal/casefile"
	"github.com/d4rpell/Ariadne/internal/platform"
)

// writeCasebook composes one valid canonical book and writes it to a private
// temporary file, returning its path.
func writeCasebook(t *testing.T) string {
	t.Helper()
	book, err := casefile.Append(casefile.NewBook(), casefile.DecisionInput{
		RiskDecision: casefile.DecisionAccepted,
		Owner:        "platform owner",
		Approver:     "security approver",
		Rationale:    "compensating controls reviewed",
		Scope: casefile.Scope{
			BundleHash:      hashOfBytes([]byte("bundle")),
			SubjectUID:      "uid-a",
			ContainerName:   "payments-api",
			ContainerClass:  casefile.ContainerRegular,
			VulnerabilityID: "CVE-2026-1234",
		},
		Controls:  []string{"network policy"},
		DecidedAt: "2026-01-01T00:00:00Z",
	})
	if err != nil {
		t.Fatalf("append: %v", err)
	}
	encoded, err := casefile.Encode(book)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	return writeTemp(t, "casebook.json", encoded)
}

func TestServeParsesArguments(t *testing.T) {
	call, failure := parseArguments([]string{"serve",
		"--casebook", "book.json", "--as-of", "2026-03-01T00:00:00Z", "--port", "8080"})
	if failure != nil {
		t.Fatalf("valid serve arguments rejected: %v", failure)
	}
	if call.command != commandServe {
		t.Fatalf("command = %q, want serve", call.command)
	}
	if call.value("casebook") != "book.json" || call.value("as-of") != "2026-03-01T00:00:00Z" || call.value("port") != "8080" {
		t.Fatalf("values not resolved: %+v", call.values)
	}
}

func TestServeArgumentRejections(t *testing.T) {
	valid := []string{"serve",
		"--casebook", "book.json", "--as-of", "2026-03-01T00:00:00Z", "--port", "8080"}

	cases := []struct {
		name string
		argv []string
	}{
		{"missing every flag", []string{"serve"}},
		{"missing casebook", []string{"serve", "--as-of", "2026-03-01T00:00:00Z", "--port", "8080"}},
		{"missing as-of", []string{"serve", "--casebook", "book.json", "--port", "8080"}},
		{"missing port", []string{"serve", "--casebook", "book.json", "--as-of", "2026-03-01T00:00:00Z"}},
		{"port zero", []string{"serve", "--casebook", "book.json", "--as-of", "2026-03-01T00:00:00Z", "--port", "0"}},
		{"port too high", []string{"serve", "--casebook", "book.json", "--as-of", "2026-03-01T00:00:00Z", "--port", "65536"}},
		{"port not numeric", []string{"serve", "--casebook", "book.json", "--as-of", "2026-03-01T00:00:00Z", "--port", "http"}},
		{"port negative", []string{"serve", "--casebook", "book.json", "--as-of", "2026-03-01T00:00:00Z", "--port", "-1"}},
		{"as-of not canonical", []string{"serve", "--casebook", "book.json", "--as-of", "2026-03-01T00:00:00+00:00", "--port", "8080"}},
		{"as-of empty", []string{"serve", "--casebook", "book.json", "--as-of", "", "--port", "8080"}},
		{"casebook dash token", []string{"serve", "--casebook", "-", "--as-of", "2026-03-01T00:00:00Z", "--port", "8080"}},
		{"unknown flag", append(append([]string{}, valid...), "--extra", "x")},
		{"flag of another command", append(append([]string{}, valid...), "--format", "json")},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			expectRejection(t, testCase.argv, stageArguments, codeInvalidArguments, 2)
		})
	}
}

func TestServeRunsAndAnnounces(t *testing.T) {
	original := serveLoop
	defer func() { serveLoop = original }()
	captured := -1
	serveLoop = func(server *platform.Server, port int) error {
		captured = port
		return nil
	}

	casebook := writeCasebook(t)
	exit, stdout, stderr := runCLI(t, []string{"serve",
		"--casebook", casebook, "--as-of", "2026-03-01T00:00:00Z", "--port", "18080"})
	if exit != 0 {
		t.Fatalf("exit = %d, stderr = %q", exit, stderr)
	}
	if stdout != "listening on http://127.0.0.1:18080\n" {
		t.Fatalf("stdout = %q, want the loopback announcement", stdout)
	}
	if stderr != "" {
		t.Fatalf("stderr = %q, want empty", stderr)
	}
	if captured != 18080 {
		t.Fatalf("served port = %d, want 18080", captured)
	}
}

func TestServeRejectsInvalidCasebook(t *testing.T) {
	original := serveLoop
	defer func() { serveLoop = original }()
	serveLoop = func(server *platform.Server, port int) error { return nil }

	notABook := writeTemp(t, "casebook.json", []byte("not a canonical book"))
	expectRejection(t, []string{"serve",
		"--casebook", notABook, "--as-of", "2026-03-01T00:00:00Z", "--port", "8080"},
		stageBundleDecode, codeInvalidBundle, 3)
}

func TestServeReadsThroughTheLocalFrontier(t *testing.T) {
	original := serveLoop
	defer func() { serveLoop = original }()
	serveLoop = func(server *platform.Server, port int) error { return nil }

	// A missing casebook is a not-found read, decided by the shared R-02 helper.
	expectRejection(t, []string{"serve",
		"--casebook", "no-such-casebook.json", "--as-of", "2026-03-01T00:00:00Z", "--port", "8080"},
		stageBundleRead, codeNotFound, 4)

	// A directory is not a regular file and is refused before any open.
	expectRejection(t, []string{"serve",
		"--casebook", t.TempDir(), "--as-of", "2026-03-01T00:00:00Z", "--port", "8080"},
		stageBundleRead, codeInvalidFile, 4)
}

func TestServeSurfacesListenFailure(t *testing.T) {
	original := serveLoop
	defer func() { serveLoop = original }()
	serveLoop = func(server *platform.Server, port int) error { return errors.New("bind failed") }

	casebook := writeCasebook(t)
	exit, stdout, stderr := runCLI(t, []string{"serve",
		"--casebook", casebook, "--as-of", "2026-03-01T00:00:00Z", "--port", "8080"})
	if exit != 6 {
		t.Fatalf("exit = %d, want 6", exit)
	}
	// The announcement precedes the serve call, so it is already on stdout when
	// the listener fails; the failure itself is the diagnostic on stderr.
	if stdout != "listening on http://127.0.0.1:8080\n" {
		t.Fatalf("stdout = %q, want the announcement", stdout)
	}
	want := `{"error":{"stage":"internal","code":"internal_failure","message":"ariadne: internal_failure"}}` + "\n"
	if stderr != want {
		t.Fatalf("stderr = %q, want %q", stderr, want)
	}
}
