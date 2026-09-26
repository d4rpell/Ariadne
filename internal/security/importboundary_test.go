package security

import (
	"errors"
	"go/parser"
	"go/token"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
)

// Import boundaries from ARQUITECTURE.md §8 and threat T12, plus the static
// closure of ADR-0014.
//
// Three passes, because none alone is sufficient:
//   - `go list -deps` resolves the transitive graph of the package as compiled
//     for the active build context, which catches indirect dependencies, and the
//     graph must contain its root: an empty result is a failure, never a pass;
//   - parsing the package directory catches direct imports in files the active
//     build context excludes (GOOS, GOARCH, build tags), which the graph misses;
//   - the local closure (analyzeClosure in importclosure_test.go) unions the
//     imports of every local production source reachable from the root, so a
//     forbidden import reached through an intermediate local package from an
//     excluded file is found as well. It fails closed on anything it cannot
//     resolve instead of omitting it.
//
// An entry matches a package that is that path or lives below it, so "net/http"
// covers net/http/httptest. "net" is matched exactly on purpose: it is the socket
// API ("no network" in ARQUITECTURE.md §4), while net/url and net/netip do no
// I/O. The core roots (evaluator and rule admission) additionally restrict every
// standard-library import reachable from them to the allowlist of ADR-0014; that
// allowlist and the prohibitions are code of this reviewed test, never
// configuration of a rule pack or of a user.
type boundaryDeclaration struct {
	name   string
	target string
	dir    string
	core   bool
	exact  []string
	trees  []string
}

// importBoundaries is the declared surface of the gate. A policy never comes
// from a rule pack or from user configuration.
var importBoundaries = []boundaryDeclaration{
	{
		name:   "evaluator",
		target: "../evaluator",
		dir:    "internal/evaluator",
		core:   true,
		exact:  []string{"net"},
		trees:  []string{"net/http", "os/exec", "k8s.io/client-go"},
	},
	{
		name:   "rulepack",
		target: "../rulepack",
		dir:    "internal/rulepack",
		core:   true,
		exact:  []string{"net"},
		trees:  []string{"net/http", "os/exec", "k8s.io/client-go"},
	},
	{
		name:   "report",
		target: "../report",
		dir:    "internal/report",
		trees:  []string{"os/exec"},
	},
}

func TestImportBoundary(t *testing.T) {
	for _, boundary := range importBoundaries {
		t.Run(boundary.name, func(t *testing.T) {
			resolved := goListLines(t, "-f", "{{.ImportPath}}", boundary.target)
			if len(resolved) != 1 {
				t.Fatalf("go list %s: expected exactly one package, got %v", boundary.target, resolved)
			}
			importPath := resolved[0]

			deps := goListLines(t, "-deps", "-f", "{{.ImportPath}}", boundary.target)
			if !slices.Contains(deps, importPath) {
				t.Fatalf("dependency graph of %s omits %s: the check would be vacuous", boundary.target, importPath)
			}
			slices.Sort(deps)

			for _, dep := range deps {
				if banned := forbiddenMatch(dep, boundary.exact, boundary.trees); banned != "" {
					t.Errorf("%s depends on %s, forbidden by the import boundary (%s)", importPath, dep, banned)
				}
			}

			for _, found := range scanDirectImports(t, goListDir(t, boundary.target)) {
				if banned := forbiddenMatch(found.path, boundary.exact, boundary.trees); banned != "" {
					t.Errorf("%s: %s imports %s, forbidden by the import boundary (%s)", importPath, found.file, found.path, banned)
				}
			}

			// The closure is reached through this test on purpose: the gate the
			// Makefile names selects this function, so a closure failure must
			// fail here and not only in the analyzer's own cases.
			closure := analyzeClosure(t, moduleRoot(t), closurePolicy{
				name:  boundary.name,
				dir:   boundary.dir,
				core:  boundary.core,
				exact: boundary.exact,
				trees: boundary.trees,
			})
			for _, finding := range closure {
				t.Errorf("import closure: %s", finding)
			}
		})
	}
}

func forbiddenMatch(path string, exact, trees []string) string {
	if slices.Contains(exact, path) {
		return path
	}
	for _, tree := range trees {
		if path == tree || strings.HasPrefix(path, tree+"/") {
			return tree
		}
	}

	return ""
}

type directImport struct {
	file string
	path string
}

// Reads every build variant of the package's non-test sources. Files ending in
// _test.go are skipped, matching the non-test semantics of go list.
func scanDirectImports(t *testing.T, dir string) []directImport {
	t.Helper()

	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read package directory %s: %v", dir, err)
	}

	var found []directImport
	fset := token.NewFileSet()
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}

		parsed, err := parser.ParseFile(fset, filepath.Join(dir, name), nil, parser.ImportsOnly)
		if err != nil {
			t.Fatalf("parse %s: %v", name, err)
		}
		for _, spec := range parsed.Imports {
			path, err := strconv.Unquote(spec.Path.Value)
			if err != nil {
				t.Fatalf("unquote import %s in %s: %v", spec.Path.Value, name, err)
			}
			found = append(found, directImport{file: name, path: path})
		}
	}

	return found
}

func goListDir(t *testing.T, target string) string {
	t.Helper()

	return strings.TrimSpace(goListOutput(t, "-f", "{{.Dir}}", target))
}

func goListLines(t *testing.T, args ...string) []string {
	t.Helper()

	return strings.Fields(goListOutput(t, args...))
}

func goListOutput(t *testing.T, args ...string) string {
	t.Helper()

	command := exec.Command("go", append([]string{"list"}, args...)...)
	// Module resolution is read-only and offline: the gate must not download
	// dependencies, install tools or touch go.mod/go.sum.
	command.Env = append(os.Environ(), "GOPROXY=off", "GOSUMDB=off", "GOFLAGS=-mod=readonly")
	out, err := command.Output()
	if err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			t.Fatalf("go list %v failed: %v\n%s", args, err, exitErr.Stderr)
		}
		t.Fatalf("go list %v failed: %v", args, err)
	}

	return string(out)
}
