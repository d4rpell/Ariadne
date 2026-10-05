package security

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// A3-01 rows of the import gate (ADR-0030 §6): internal/casefile is the
// eleventh root and the only stdlib-only one. The tests exercise the real
// enforcer, not a copy of its policy.

const casefilePackage = "github.com/d4rpell/Ariadne/internal/casefile"

func TestCasefileImportPolicy(t *testing.T) {
	t.Run("eleven_unique_roots", func(t *testing.T) {
		declared := map[string]boundaryDeclaration{}
		for _, boundary := range importBoundaries {
			if _, repeated := declared[boundary.name]; repeated {
				t.Fatalf("boundary %s is declared twice", boundary.name)
			}
			declared[boundary.name] = boundary
		}
		if len(importBoundaries) != 12 {
			t.Fatalf("importBoundaries has %d entries, want twelve", len(importBoundaries))
		}
		casefile, present := declared["casefile"]
		if !present {
			t.Fatal("the casefile root is not declared")
		}
		if !casefile.strict {
			t.Fatal("the casefile root must stay strict")
		}
		if !casefile.stdlibOnly {
			t.Fatal("the casefile root must keep the stdlib-only flag")
		}
		if casefile.dir != "internal/casefile" || casefile.target != "../casefile" {
			t.Fatalf("casefile root points at %q/%q", casefile.dir, casefile.target)
		}
		for _, forbidden := range []string{"os", "os/exec", "net", "time", "fmt", "log", "crypto/rand", "math/rand", "plugin", "unsafe", "syscall", "C"} {
			if !slices.Contains(casefile.exact, forbidden) {
				t.Fatalf("the casefile root no longer forbids %q", forbidden)
			}
		}
		for _, forbidden := range []string{"net/http", "k8s.io/client-go"} {
			if !slices.Contains(casefile.trees, forbidden) {
				t.Fatalf("the casefile root no longer forbids the %q tree", forbidden)
			}
		}
		if len(casefile.networkDirs) != 0 {
			t.Fatal("the casefile root must not grant any network permission")
		}
		if !slices.Equal(casefile.allowlist, casefileStdlibAllowlist) {
			t.Fatal("the casefile root does not use its own allowlist")
		}
	})
	t.Run("allowlist_is_independent_and_closed", func(t *testing.T) {
		if len(casefileStdlibAllowlist) != 10 {
			t.Fatalf("casefile allowlist has %d entries, want the ten of ADR-0030 §6.1", len(casefileStdlibAllowlist))
		}
		for _, entry := range casefileStdlibAllowlist {
			if slices.Contains(coreStdlibAllowlist, entry) && entry == "reflect" {
				continue
			}
			if slices.Contains(adapterStdlibAllowlist, entry) && !slices.Contains(coreStdlibAllowlist, entry) {
				t.Fatalf("casefile allowlist leaks the adapter addition %q", entry)
			}
		}
		for _, network := range collectorNetworkAdditions {
			if slices.Contains(casefileStdlibAllowlist, network) {
				t.Fatalf("casefile allowlist leaks the network addition %q", network)
			}
		}
		for _, forbidden := range []string{"time", "fmt", "encoding/json", "sort", "slices", "cmp", "math"} {
			if slices.Contains(casefileStdlibAllowlist, forbidden) {
				t.Fatalf("casefile allowlist admits %q outside the contract", forbidden)
			}
		}
	})
	t.Run("root_sources_exist", func(t *testing.T) {
		dir := filepath.Join(moduleRoot(t), "internal", "casefile")
		entries, err := os.ReadDir(dir)
		if err != nil {
			t.Fatalf("read the casefile package: %v", err)
		}
		production := 0
		for _, entry := range entries {
			if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".go") || strings.HasSuffix(entry.Name(), "_test.go") {
				continue
			}
			production++
		}
		if production == 0 {
			t.Fatal("the casefile root has no production source")
		}
	})
}

func TestCasefileBoundaryRejectsExcludedVariants(t *testing.T) {
	policy := func() closurePolicy {
		return closurePolicy{
			name:        "casefile",
			dir:         "internal/casefile",
			strict:      true,
			stdlibOnly:  true,
			exact:       []string{"os", "os/exec", "net", "time", "fmt", "log", "crypto/rand", "math/rand", "plugin", "unsafe", "syscall", "C"},
			trees:       []string{"net/http", "k8s.io/client-go"},
			allowlist:   casefileStdlibAllowlist,
			bannedLocal: offlineRootBannedLocal,
		}
	}
	t.Run("local_import_is_refused", func(t *testing.T) {
		root := writeTree(t, map[string]string{
			"go.mod":                        syntheticModule,
			"internal/casefile/casefile.go": "package casefile\n\nimport \"example.test/synthetic/internal/other\"\n\nvar _ = other.Value\n",
			"internal/other/other.go":       "package other\n\nconst Value = 1\n",
		})
		expectFinding(t, analyzeClosure(t, root, policy()), "local import is not permitted by the stdlib-only profile")
	})
	t.Run("helper_escape_is_refused", func(t *testing.T) {
		root := writeTree(t, map[string]string{
			"go.mod":                        syntheticModule,
			"internal/casefile/casefile.go": "package casefile\n\nimport \"example.test/synthetic/internal/helper\"\n\nvar _ = helper.Value\n",
			"internal/helper/helper.go":     "package helper\n\nconst Value = 1\n",
		})
		expectFinding(t, analyzeClosure(t, root, policy()), "local import is not permitted by the stdlib-only profile")
	})
	t.Run("stdlib_outside_allowlist_is_refused", func(t *testing.T) {
		root := writeTree(t, map[string]string{
			"go.mod":                        syntheticModule,
			"internal/casefile/casefile.go": "package casefile\n\nimport \"fmt\"\n\nvar _ = fmt.Sprintf\n",
		})
		expectFinding(t, analyzeClosure(t, root, policy()), "outside the adapter allowlist")
	})
	t.Run("network_import_is_refused", func(t *testing.T) {
		root := writeTree(t, map[string]string{
			"go.mod":                        syntheticModule,
			"internal/casefile/casefile.go": "package casefile\n\nimport \"net/http\"\n\nvar _ = http.DefaultClient\n",
		})
		expectFinding(t, analyzeClosure(t, root, policy()), "outside the adapter allowlist")
	})
	t.Run("excluded_variant_is_still_analysed", func(t *testing.T) {
		root := writeTree(t, map[string]string{
			"go.mod":                           syntheticModule,
			"internal/casefile/casefile.go":    "package casefile\n",
			"internal/casefile/clock_plan9.go": "//go:build plan9\n\npackage casefile\n\nimport \"time\"\n\nvar _ = time.Now\n",
		})
		expectFinding(t, analyzeClosure(t, root, policy()), "outside the adapter allowlist")
	})
	t.Run("external_dependency_is_refused", func(t *testing.T) {
		root := writeTree(t, map[string]string{
			"go.mod":                        syntheticModule,
			"internal/casefile/casefile.go": "package casefile\n\nimport \"github.com/other/thing\"\n\nvar _ = thing.Value\n",
		})
		expectFinding(t, analyzeClosure(t, root, policy()), "external dependency")
	})
}

// TestCasefileOperationBoundary scans the casefile production sources for the
// operations the profile forbids (ADR-0030 §6.2): clocks, global output,
// goroutines, init functions, process or network use and reflect calls beyond
// the typed-nil probe. The import gate covers the packages; this test covers
// the call shapes the allowlist cannot express.
func TestCasefileOperationBoundary(t *testing.T) {
	dir := filepath.Join(moduleRoot(t), "internal", "casefile")
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read the casefile package: %v", err)
	}
	forbidden := []string{
		"time.", "os.", "os/", "net.", "net/", "http.", "fmt.", "log.",
		"rand.", "go func", "func init(", "println(", "print(",
		"Getenv", "os.Open", "os.Create", "StartProcess", "reflect.New",
		"reflect.Value.", "unsafe.",
	}
	allowedReflect := []string{"reflect.ValueOf", "reflect.Ptr", "reflect.Interface", "reflect.Map", "reflect.Slice", "reflect.Func", "reflect.Chan"}
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		content := productionSource(t, "internal"+string(filepath.Separator)+"casefile", name)
		for _, line := range strings.Split(content, "\n") {
			for _, shape := range forbidden {
				if strings.Contains(line, shape) {
					t.Errorf("%s uses a forbidden operation shape %q: %s", name, shape, strings.TrimSpace(line))
				}
			}
			if strings.Contains(line, "reflect.") {
				permitted := false
				for _, shape := range allowedReflect {
					if strings.Contains(line, shape) {
						permitted = true
						break
					}
				}
				if !permitted {
					t.Errorf("%s uses reflect outside the typed-nil probe: %s", name, strings.TrimSpace(line))
				}
			}
		}
	}
}
