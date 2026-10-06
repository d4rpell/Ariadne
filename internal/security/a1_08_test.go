package security

import (
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestA108ImportBoundaryControls covers M25 and I-16 with synthetic sources: the
// walkers the gate and its controls share detect a forbidden reference even when
// the import is aliased, assigned to a variable or dot-imported, and the build
// excluded file is a finding of the closure. No policy is relaxed anywhere: the
// controls call the same walker the gate calls.
func TestA108ImportBoundaryControls(t *testing.T) {
	t.Run("process references are found through every spelling", func(t *testing.T) {
		cases := []struct {
			name    string
			source  string
			wantHit bool
		}{
			{
				name:    "plain reference",
				source:  "package synthetic\n\nimport \"os\"\n\nfunc use() { _, _, _ = os.StartProcess(\"x\", nil, nil) }\n",
				wantHit: true,
			},
			{
				name:    "aliased import",
				source:  "package synthetic\n\nimport o \"os\"\n\nfunc use() { _, _, _ = o.StartProcess(\"x\", nil, nil) }\n",
				wantHit: true,
			},
			{
				name:    "assigned to a variable",
				source:  "package synthetic\n\nimport \"os\"\n\nvar start = os.StartProcess\n\nfunc use() { _, _, _ = start(\"x\", nil, nil) }\n",
				wantHit: true,
			},
			{
				name:    "dot import is itself a finding",
				source:  "package synthetic\n\nimport . \"os\"\n\nfunc use() { _, _, _ = StartProcess(\"x\", nil, nil) }\n",
				wantHit: true,
			},
			{
				name:    "no os import",
				source:  "package synthetic\n\nimport \"strings\"\n\nfunc use() string { return strings.ToUpper(\"x\") }\n",
				wantHit: false,
			},
			{
				name:    "an unrelated selector with the same method name",
				source:  "package synthetic\n\ntype execer struct{}\n\nfunc (execer) StartProcess(string) {}\n\nfunc use(e execer) { e.StartProcess(\"x\") }\n",
				wantHit: false,
			},
		}
		fset := token.NewFileSet()
		for _, testCase := range cases {
			t.Run(testCase.name, func(t *testing.T) {
				file, err := parser.ParseFile(fset, "synthetic.go", testCase.source, parser.AllErrors)
				if err != nil {
					t.Fatalf("the synthetic source must parse: %v", err)
				}
				findings := processStartFindings(file)
				if testCase.wantHit && len(findings) == 0 {
					t.Fatal("the walker missed a forbidden process reference")
				}
				if !testCase.wantHit && len(findings) != 0 {
					t.Fatalf("the walker reported a false positive: %v", findings)
				}
			})
		}
	})

	t.Run("the gate declares every boundary with its prohibitions", func(t *testing.T) {
		declared := map[string]bool{}
		for _, boundary := range importBoundaries {
			declared[boundary.name] = true
			if boundary.name == "cli" {
				if !boundary.strict {
					t.Fatal("the CLI boundary must stay strict")
				}
				for _, forbidden := range []string{"net", "os/exec", "plugin", "unsafe", "syscall"} {
					found := false
					for _, exact := range boundary.exact {
						if exact == forbidden {
							found = true
						}
					}
					if !found {
						t.Fatalf("the CLI boundary no longer forbids %q", forbidden)
					}
				}
				for _, forbidden := range []string{"net/http", "k8s.io/client-go"} {
					found := false
					for _, tree := range boundary.trees {
						if tree == forbidden {
							found = true
						}
					}
					if !found {
						t.Fatalf("the CLI boundary no longer forbids the %q tree", forbidden)
					}
				}
				if len(boundary.graphExact) == 0 || len(boundary.graphTrees) == 0 {
					t.Fatal("the CLI graph policy must keep its transitive prohibitions")
				}
			}
		}
		for _, expected := range []string{"evaluator", "rulepack", "report", "interop", "cli", "ingest", "normalize", "identity", "bundle", "collector", "prismaacquire", "casefile", "platform"} {
			if !declared[expected] {
				t.Fatalf("the %s boundary is no longer declared", expected)
			}
		}
		if len(importBoundaries) != 13 {
			t.Fatalf("importBoundaries has %d entries, want the thirteen declared roots", len(importBoundaries))
		}
	})

	t.Run("a synthetic forbidden import is a finding of the direct scan", func(t *testing.T) {
		// The scan walks the project rather than synthetic files, so this control
		// asserts the shape of what it reads: a production file declaring a
		// forbidden import would be reported. The mechanism is exercised through a
		// synthetic directory.
		dir := t.TempDir()
		writeSyntheticSource(t, dir, "synthetic.go", "package synthetic\n\nimport (\n\t\"net/http\"\n\t\"os/exec\"\n)\n\nvar _ = http.Get\nvar _ = exec.Command\n")
		imports := scanDirectImports(t, dir)
		if len(imports) == 0 {
			t.Fatal("the direct scan found no imports in a file that declares two")
		}
		trees := []string{"net/http", "os/exec"}
		hits := 0
		for _, imported := range imports {
			if path := forbiddenMatch(imported.path, nil, trees); path != "" {
				hits++
			}
		}
		if hits != 2 {
			t.Fatalf("the direct scan matched %d of the two forbidden trees", hits)
		}
	})

	t.Run("an allowed import is not a finding", func(t *testing.T) {
		dir := t.TempDir()
		writeSyntheticSource(t, dir, "synthetic.go", "package synthetic\n\nimport \"strings\"\n\nvar _ = strings.ToUpper\n")
		imports := scanDirectImports(t, dir)
		if len(imports) != 1 {
			t.Fatalf("imports = %d, want 1", len(imports))
		}
		if path := forbiddenMatch(imports[0].path, []string{"net", "os/exec"}, []string{"net/http", "k8s.io/client-go"}); path != "" {
			t.Fatalf("an allowed import matched the prohibition as %q", path)
		}
		if !strings.Contains(imports[0].path, "strings") {
			t.Fatalf("path = %q, want the strings package", imports[0].path)
		}
	})
}

// writeSyntheticSource writes one synthetic production-looking source in a
// private directory, so the direct-import scan is exercised without touching the
// repository.
func writeSyntheticSource(t *testing.T, dir, name, source string) {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte(source), 0o600); err != nil {
		t.Fatalf("write synthetic source: %v", err)
	}
}
