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

// Import boundaries from ARQUITECTURE.md §8, threat T12.
//
// Two passes, because neither alone is sufficient:
//   - `go list -deps` resolves the transitive graph of the package as compiled
//     for the active build context, which catches indirect dependencies;
//   - parsing the package directory catches direct imports in files the active
//     build context excludes (GOOS, GOARCH, build tags), which the graph misses.
//
// An entry matches a package that is that path or lives below it, so "net/http"
// covers net/http/httptest. "net" is matched exactly on purpose: it is the socket
// API ("no network" in ARQUITECTURE.md §4), while net/url and net/netip do no I/O.
//
// Ratified limit (owner, 2026-09-24): a violation reached transitively from a
// build-tagged file through an intermediate local package is not detected here,
// because the graph only resolves the active build context and the scan only
// reads direct imports. This is an intermediate state, not the final T12
// guarantee: closing it requires a static closure over local packages for every
// build variant, planned for A1-04/AX-01 under a new ADR.
func TestImportBoundary(t *testing.T) {
	boundaries := []struct {
		name   string
		target string
		exact  []string
		trees  []string
	}{
		{
			name:   "evaluator",
			target: "../evaluator",
			exact:  []string{"net"},
			trees:  []string{"net/http", "os/exec", "k8s.io/client-go"},
		},
		{
			name:   "report",
			target: "../report",
			trees:  []string{"os/exec"},
		},
	}

	for _, boundary := range boundaries {
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

	out, err := exec.Command("go", append([]string{"list"}, args...)...).Output()
	if err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			t.Fatalf("go list %v failed: %v\n%s", args, err, exitErr.Stderr)
		}
		t.Fatalf("go list %v failed: %v", args, err)
	}

	return string(out)
}
