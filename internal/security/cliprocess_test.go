package security

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// ADR-0023 §7 requires one more control for the CLI adapter than the import
// closure alone: references to os.StartProcess must be found even when the
// import is aliased or the function is assigned to a variable. The gate and its
// discriminating controls call the same walker, so removing the walk from the
// gate cannot leave the controls green.

// processStartFindings walks one parsed production source and returns every
// reference to os.StartProcess: through the package name, through an alias or
// assigned to a variable. A dot-import of os is itself a finding: the reference
// would appear as a bare identifier that this static walk cannot attribute to a
// package, so the form is refused instead of guessed.
func processStartFindings(file *ast.File) []string {
	findings := []string{}
	names := map[string]bool{}
	dotImported := false
	for _, spec := range file.Imports {
		quoted, err := strconv.Unquote(spec.Path.Value)
		if err != nil || quoted != "os" {
			continue
		}
		switch {
		case spec.Name == nil:
			names["os"] = true
		case spec.Name.Name == ".":
			dotImported = true
		case spec.Name.Name == "_":
		default:
			names[spec.Name.Name] = true
		}
	}
	if dotImported {
		findings = append(findings, "dot-import of os hides every package-level reference")
	}
	ast.Inspect(file, func(node ast.Node) bool {
		selector, ok := node.(*ast.SelectorExpr)
		if !ok || selector.Sel == nil || selector.Sel.Name != "StartProcess" {
			return true
		}
		identifier, ok := selector.X.(*ast.Ident)
		if ok && names[identifier.Name] {
			findings = append(findings, "reference to os.StartProcess through "+identifier.Name)
		}
		return true
	})
	return findings
}

func TestCLIProductionHasNoProcessStart(t *testing.T) {
	dir := filepath.Join(moduleRoot(t), "cmd", "ariadne")
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read %s: %v", dir, err)
	}
	fset := token.NewFileSet()
	checked := 0
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		parsed, err := parser.ParseFile(fset, filepath.Join(dir, name), nil, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", name, err)
		}
		checked++
		for _, finding := range processStartFindings(parsed) {
			t.Errorf("cmd/ariadne/%s: %s: the adapter must never start a process", name, finding)
		}
	}
	if checked == 0 {
		t.Fatalf("no production sources checked: the walk would be vacuous")
	}
}

// The walk is proven to discriminate through the same function the gate uses:
// each positive case must produce a finding and each negative case must not.
func TestCLIProcessStartControlDiscriminates(t *testing.T) {
	cases := []struct {
		name     string
		source   string
		wantFind bool
	}{
		{"direct reference", "package main\n\nimport \"os\"\n\nvar start = os.StartProcess\n", true},
		{"aliased import", "package main\n\nimport system \"os\"\n\nvar start = system.StartProcess\n", true},
		{"dot import", "package main\n\nimport . \"os\"\n\nvar start = StartProcess\n", true},
		{"blank import only", "package main\n\nimport _ \"os\"\n\nfunc use() {}\n", false},
		{"clean file", "package main\n\nimport \"os\"\n\nvar args = os.Args\n", false},
		{"other package selector", "package main\n\nimport \"os\"\n\nvar start = runtime.StartProcess\n", false},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			file, err := parser.ParseFile(token.NewFileSet(), "case.go", testCase.source, 0)
			if err != nil {
				t.Fatalf("parse synthetic file: %v", err)
			}
			findings := processStartFindings(file)
			if testCase.wantFind && len(findings) == 0 {
				t.Fatalf("the walk did not find the reference it must find")
			}
			if !testCase.wantFind && len(findings) != 0 {
				t.Fatalf("false positive: %v", findings)
			}
		})
	}
}

// The control is not vacuous either: the real tree it protects has production
// sources, so an empty walk would fail closed.
func TestCLIProcessStartControlHasSources(t *testing.T) {
	dir := filepath.Join(moduleRoot(t), "cmd", "ariadne")
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read %s: %v", dir, err)
	}
	production := 0
	for _, entry := range entries {
		name := entry.Name()
		if !entry.IsDir() && strings.HasSuffix(name, ".go") && !strings.HasSuffix(name, "_test.go") {
			production++
		}
	}
	if production == 0 {
		t.Fatalf("cmd/ariadne has no production sources: the gate would pass vacuously")
	}
}
