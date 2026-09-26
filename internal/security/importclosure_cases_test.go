package security

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Synthetic module trees of the closure analyzer. The graphs are sources parsed
// from disk, never programs: no case runs code from the tree under analysis.

const syntheticModule = "module example.test/synthetic\n\ngo 1.23\n"

func writeTree(t *testing.T, files map[string]string) string {
	t.Helper()
	root := t.TempDir()
	for name, content := range files {
		path := filepath.Join(root, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatalf("cannot create %s: %v", name, err)
		}
		if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
			t.Fatalf("cannot write %s: %v", name, err)
		}
	}
	return root
}

func syntheticCorePolicy() closurePolicy {
	return closurePolicy{
		name:  "core-root",
		dir:   "internal/core",
		core:  true,
		exact: []string{"net"},
		trees: []string{"net/http", "os/exec", "k8s.io/client-go"},
	}
}

func findingsText(findings []closureFinding) string {
	parts := make([]string, 0, len(findings))
	for _, finding := range findings {
		parts = append(parts, finding.String())
	}
	return strings.Join(parts, "\n")
}

func expectFinding(t *testing.T, findings []closureFinding, contains string) {
	t.Helper()
	for _, finding := range findings {
		if strings.Contains(finding.String(), contains) {
			return
		}
	}
	t.Fatalf("expected a finding containing %q, got:\n%s", contains, findingsText(findings))
}

func expectClean(t *testing.T, findings []closureFinding) {
	t.Helper()
	if len(findings) != 0 {
		t.Fatalf("expected no findings, got:\n%s", findingsText(findings))
	}
}

// TestImportClosureBuildVariants is I-24: a forbidden import is found through
// every local production file, including the variants the active build excludes,
// and mutually exclusive constraints do not exempt a path.
func TestImportClosureBuildVariants(t *testing.T) {
	t.Run("direct forbidden import", func(t *testing.T) {
		root := writeTree(t, map[string]string{
			"go.mod":                  syntheticModule,
			"internal/core/core.go":   "package core\n\nimport \"os/exec\"\n\nvar _ = exec.Command\n",
			"internal/core/helper.go": "package core\n",
		})
		expectFinding(t, analyzeClosure(t, root, syntheticCorePolicy()), "os/exec")
	})

	t.Run("excluded variant through a local package", func(t *testing.T) {
		root := writeTree(t, map[string]string{
			"go.mod":                       syntheticModule,
			"internal/core/core.go":        "package core\n\nimport \"example.test/synthetic/internal/middle\"\n\nvar _ = middle.Value\n",
			"internal/middle/middle.go":    "package middle\n\nimport \"example.test/synthetic/internal/leaf\"\n\nconst Value = leaf.Value\n",
			"internal/leaf/leaf.go":        "package leaf\n\nconst Value = 1\n",
			"internal/leaf/shell_plan9.go": "//go:build plan9\n\npackage leaf\n\nimport \"os/exec\"\n\nvar _ = exec.Command\n",
		})
		findings := analyzeClosure(t, root, syntheticCorePolicy())
		expectFinding(t, findings, "os/exec")
		expectFinding(t, findings, "internal/middle")
	})

	t.Run("two hops under tags", func(t *testing.T) {
		root := writeTree(t, map[string]string{
			"go.mod":                      syntheticModule,
			"internal/core/core.go":       "package core\n\nimport \"example.test/synthetic/internal/one\"\n\nvar _ = one.Value\n",
			"internal/one/one.go":         "package one\n\nimport \"example.test/synthetic/internal/two\"\n\nconst Value = two.Value\n",
			"internal/two/two.go":         "package two\n\nconst Value = 2\n",
			"internal/two/net_windows.go": "//go:build windows\n\npackage two\n\nimport \"net\"\n\nvar _ = net.Dial\n",
		})
		expectFinding(t, analyzeClosure(t, root, syntheticCorePolicy()), "net")
	})

	t.Run("mutually exclusive constraints still reject", func(t *testing.T) {
		root := writeTree(t, map[string]string{
			"go.mod":                        syntheticModule,
			"internal/core/core.go":         "package core\n\nimport \"example.test/synthetic/internal/both\"\n\nvar _ = both.Value\n",
			"internal/both/linux.go":        "//go:build linux\n\npackage both\n\nimport \"os/exec\"\n\nconst Value = 1\n\nvar _ = exec.Command\n",
			"internal/both/windows.go":      "//go:build windows\n\npackage both\n\nconst Value = 2\n",
			"internal/both/excluded_arm.go": "//go:build arm && plan9\n\npackage both\n\nimport \"os/exec\"\n\nvar _ = exec.Command\n",
		})
		expectFinding(t, analyzeClosure(t, root, syntheticCorePolicy()), "os/exec")
	})

	t.Run("allowed local chain", func(t *testing.T) {
		root := writeTree(t, map[string]string{
			"go.mod":                    syntheticModule,
			"internal/core/core.go":     "package core\n\nimport (\n\t\"strings\"\n\n\t\"example.test/synthetic/internal/middle\"\n)\n\nvar _ = strings.TrimSpace\nvar _ = middle.Value\n",
			"internal/middle/middle.go": "package middle\n\nimport \"crypto/sha256\"\n\nvar Value = sha256.New\n",
		})
		expectClean(t, analyzeClosure(t, root, syntheticCorePolicy()))
	})

	t.Run("test-only import is outside the production boundary", func(t *testing.T) {
		root := writeTree(t, map[string]string{
			"go.mod":                     syntheticModule,
			"internal/core/core.go":      "package core\n",
			"internal/core/core_test.go": "package core\n\nimport \"os/exec\"\n\nvar _ = exec.Command\n",
		})
		expectClean(t, analyzeClosure(t, root, syntheticCorePolicy()))
	})
}

// TestImportClosureFailClosed is I-25: an unresolved, unsupported or ambiguous
// arrangement fails the analysis instead of passing quietly.
func TestImportClosureFailClosed(t *testing.T) {
	t.Run("absent local path", func(t *testing.T) {
		root := writeTree(t, map[string]string{
			"go.mod":                syntheticModule,
			"internal/core/core.go": "package core\n\nimport \"example.test/synthetic/internal/absent\"\n\nvar _ = absent.Value\n",
		})
		findings := analyzeClosure(t, root, syntheticCorePolicy())
		expectFinding(t, findings, "unresolved local import")
		// The reason travels with the finding, which is what makes a rejection
		// reviewable on every platform, not only where links can be created.
		expectFinding(t, findings, "does not exist")
	})

	t.Run("unparseable source", func(t *testing.T) {
		root := writeTree(t, map[string]string{
			"go.mod":                syntheticModule,
			"internal/core/core.go": "package core\n\nfunc Broken( {\n",
		})
		expectFinding(t, analyzeClosure(t, root, syntheticCorePolicy()), "unparseable production source")
	})

	t.Run("import cycle", func(t *testing.T) {
		root := writeTree(t, map[string]string{
			"go.mod":                syntheticModule,
			"internal/core/core.go": "package core\n\nimport \"example.test/synthetic/internal/one\"\n\nvar _ = one.Value\n",
			"internal/one/one.go":   "package one\n\nimport \"example.test/synthetic/internal/two\"\n\nconst Value = two.Value\n",
			"internal/two/two.go":   "package two\n\nimport \"example.test/synthetic/internal/one\"\n\nconst Value = one.Value\n",
		})
		expectFinding(t, analyzeClosure(t, root, syntheticCorePolicy()), "import cycle")
	})

	t.Run("module prefix lookalike", func(t *testing.T) {
		root := writeTree(t, map[string]string{
			"go.mod":                syntheticModule,
			"internal/core/core.go": "package core\n\nimport \"example.test/synthetic-extra/internal/leaf\"\n\nvar _ = leaf.Value\n",
		})
		expectFinding(t, analyzeClosure(t, root, syntheticCorePolicy()), "external dependency")
	})

	t.Run("third-party dependency", func(t *testing.T) {
		root := writeTree(t, map[string]string{
			"go.mod":                syntheticModule,
			"internal/core/core.go": "package core\n\nimport \"github.com/other/thing\"\n\nvar _ = thing.Value\n",
		})
		expectFinding(t, analyzeClosure(t, root, syntheticCorePolicy()), "external dependency")
	})

	t.Run("standard library outside the allowlist", func(t *testing.T) {
		root := writeTree(t, map[string]string{
			"go.mod":                syntheticModule,
			"internal/core/core.go": "package core\n\nimport \"net/url\"\n\nvar _ = url.Parse\n",
		})
		expectFinding(t, analyzeClosure(t, root, syntheticCorePolicy()), "outside the core allowlist")
	})

	t.Run("required module", func(t *testing.T) {
		root := writeTree(t, map[string]string{
			"go.mod":                "module example.test/synthetic\n\ngo 1.23\n\nrequire github.com/other/thing v1.0.0\n",
			"internal/core/core.go": "package core\n",
		})
		expectFinding(t, analyzeClosure(t, root, syntheticCorePolicy()), "unsupported go.mod directive")
	})

	t.Run("replaced module", func(t *testing.T) {
		root := writeTree(t, map[string]string{
			"go.mod":                "module example.test/synthetic\n\ngo 1.23\n\nreplace github.com/other/thing => ../thing\n",
			"internal/core/core.go": "package core\n",
		})
		expectFinding(t, analyzeClosure(t, root, syntheticCorePolicy()), "unsupported go.mod directive")
	})

	t.Run("nested module", func(t *testing.T) {
		root := writeTree(t, map[string]string{
			"go.mod":                syntheticModule,
			"internal/core/core.go": "package core\n",
			"internal/other/go.mod": "module example.test/other\n\ngo 1.23\n",
		})
		expectFinding(t, analyzeClosure(t, root, syntheticCorePolicy()), "nested module")
	})

	t.Run("vendor directory", func(t *testing.T) {
		root := writeTree(t, map[string]string{
			"go.mod":                                 syntheticModule,
			"internal/core/core.go":                  "package core\n",
			"vendor/github.com/other/thing/thing.go": "package thing\n",
		})
		expectFinding(t, analyzeClosure(t, root, syntheticCorePolicy()), "vendored sources")
	})

	t.Run("workspace file", func(t *testing.T) {
		root := writeTree(t, map[string]string{
			"go.mod":                syntheticModule,
			"go.work":               "go 1.23\n\nuse .\n",
			"internal/core/core.go": "package core\n",
		})
		expectFinding(t, analyzeClosure(t, root, syntheticCorePolicy()), "workspace file")
	})

	t.Run("native and linking mechanisms", func(t *testing.T) {
		native := writeTree(t, map[string]string{
			"go.mod":                syntheticModule,
			"internal/core/core.go": "package core\n",
			"internal/core/asm.s":   "TEXT ·Value(SB),$0-0\n",
		})
		expectFinding(t, analyzeClosure(t, native, syntheticCorePolicy()), "native or linked source")

		linked := writeTree(t, map[string]string{
			"go.mod":                syntheticModule,
			"internal/core/core.go": "package core\n\n//go:linkname secret runtime.secret\nfunc secret()\n",
		})
		expectFinding(t, analyzeClosure(t, linked, syntheticCorePolicy()), "go:linkname")

		embedded := writeTree(t, map[string]string{
			"go.mod":                syntheticModule,
			"internal/core/core.go": "package core\n\n//go:embed data.txt\nvar data string\n",
		})
		expectFinding(t, analyzeClosure(t, embedded, syntheticCorePolicy()), "go:embed")
	})

	t.Run("path that crosses a link or escapes", func(t *testing.T) {
		root := writeTree(t, map[string]string{
			"go.mod":                syntheticModule,
			"internal/core/core.go": "package core\n",
		})
		outside := t.TempDir()
		linkPath := filepath.Join(root, "internal", "linked")
		if err := os.Symlink(outside, linkPath); err != nil {
			// The physical attempt is not possible here: the deterministic
			// refusals of the resolver are asserted instead, and the missing
			// physical case is declared rather than reported as verified.
			t.Logf("link creation is not permitted in this environment: %v", err)
			if _, err := localDir(root, "internal/absent"); err == nil {
				t.Fatalf("an absent local path must be refused")
			}
			if _, err := localDir(root, "../escape"); err == nil {
				t.Fatalf("a path escaping the module must be refused")
			}
			if _, err := localDir(root, "internal/core/core.go"); err == nil {
				t.Fatalf("a file is not a package directory")
			}
			return
		}
		linked := writeTree(t, map[string]string{
			"go.mod":                syntheticModule,
			"internal/core/core.go": "package core\n\nimport \"example.test/synthetic/internal/linked\"\n\nvar _ = linked.Value\n",
		})
		if err := os.Symlink(outside, filepath.Join(linked, "internal", "linked")); err != nil {
			t.Fatalf("link creation failed after a successful attempt: %v", err)
		}
		expectFinding(t, analyzeClosure(t, linked, syntheticCorePolicy()), "symlink")
	})
}

// TestImportBoundaryDeclaresCoreRoots guards the declared surface of the gate:
// the evaluator and pack admission are core roots, and the policy declared for
// them rejects a standard-library import that the narrower report policy admits.
// The discriminator is net/url: it performs no I/O, it is not in the denylist and
// it is not in the core allowlist, so only the core policy rejects it.
func TestImportBoundaryDeclaresCoreRoots(t *testing.T) {
	declared := map[string]boundaryDeclaration{}
	for _, boundary := range importBoundaries {
		if _, repeated := declared[boundary.name]; repeated {
			t.Fatalf("boundary %s is declared twice", boundary.name)
		}
		declared[boundary.name] = boundary
	}
	for _, name := range []string{"evaluator", "rulepack"} {
		boundary, present := declared[name]
		if !present {
			t.Fatalf("the core root %s is not declared in the import boundary", name)
		}
		if !boundary.core {
			t.Fatalf("the core root %s must carry the core policy", name)
		}
	}

	tree := writeTree(t, map[string]string{
		"go.mod":                          syntheticModule,
		"internal/evaluator/evaluator.go": "package evaluator\n\nimport \"net/url\"\n\nvar _ = url.Parse\n",
	})
	core := declared["evaluator"]
	expectFinding(t, analyzeClosure(t, tree, closurePolicy{
		name:  core.name,
		dir:   "internal/evaluator",
		core:  core.core,
		exact: core.exact,
		trees: core.trees,
	}), "outside the core allowlist")

	expectClean(t, analyzeClosure(t, tree, closurePolicy{
		name:  "report",
		dir:   "internal/evaluator",
		trees: []string{"os/exec"},
	}))
}

// TestImportClosureControls is I-26: the controls are positive and the gate
// cannot pass vacuously, and the report root keeps its narrower policy.
func TestImportClosureControls(t *testing.T) {
	t.Run("absent protected root is a failure", func(t *testing.T) {
		root := writeTree(t, map[string]string{"go.mod": syntheticModule})
		findings := analyzeClosure(t, root, syntheticCorePolicy())
		expectFinding(t, findings, "local path does not exist")
	})

	t.Run("directory without production sources", func(t *testing.T) {
		root := writeTree(t, map[string]string{
			"go.mod":                     syntheticModule,
			"internal/core/core_test.go": "package core\n",
		})
		expectFinding(t, analyzeClosure(t, root, syntheticCorePolicy()), "without production sources")
	})

	t.Run("alias and blank imports are found", func(t *testing.T) {
		root := writeTree(t, map[string]string{
			"go.mod":                syntheticModule,
			"internal/core/core.go": "package core\n\nimport (\n\t_ \"os/exec\"\n)\n\nfunc Use() {}\n",
		})
		expectFinding(t, analyzeClosure(t, root, syntheticCorePolicy()), "os/exec")

		aliased := writeTree(t, map[string]string{
			"go.mod":                syntheticModule,
			"internal/core/core.go": "package core\n\nimport shell \"os/exec\"\n\nvar _ = shell.Command\n",
		})
		expectFinding(t, analyzeClosure(t, aliased, syntheticCorePolicy()), "os/exec")
	})

	t.Run("the report policy is narrower", func(t *testing.T) {
		policy := closurePolicy{name: "report", dir: "internal/report", trees: []string{"os/exec"}}
		root := writeTree(t, map[string]string{
			"go.mod":                    syntheticModule,
			"internal/report/report.go": "package report\n\nimport \"net/url\"\n\nvar _ = url.Parse\n",
		})
		expectClean(t, analyzeClosure(t, root, policy))

		shell := writeTree(t, map[string]string{
			"go.mod":                    syntheticModule,
			"internal/report/report.go": "package report\n\nimport \"os/exec\"\n\nvar _ = exec.Command\n",
		})
		expectFinding(t, analyzeClosure(t, shell, policy), "os/exec")
	})

	t.Run("package name mix", func(t *testing.T) {
		root := writeTree(t, map[string]string{
			"go.mod":               syntheticModule,
			"internal/core/one.go": "package core\n",
			"internal/core/two.go": "package other\n",
		})
		expectFinding(t, analyzeClosure(t, root, syntheticCorePolicy()), "package name mix")
	})
}

// TestImportClosureEnvironmentAndLinks covers the arrangements the directory
// probes cannot see: a workspace selected through the environment and a source
// file reached through a link.
func TestImportClosureEnvironmentAndLinks(t *testing.T) {
	t.Run("workspace selected by the environment", func(t *testing.T) {
		root := writeTree(t, map[string]string{
			"go.mod":                syntheticModule,
			"internal/core/core.go": "package core\n",
		})
		outside := filepath.Join(t.TempDir(), "go.work")
		if err := os.WriteFile(outside, []byte("go 1.23\n"), 0o644); err != nil {
			t.Fatalf("cannot write the external workspace: %v", err)
		}
		t.Setenv("GOWORK", outside)
		expectFinding(t, analyzeClosure(t, root, syntheticCorePolicy()), "active workspace selected by the environment")
	})

	t.Run("linked source file", func(t *testing.T) {
		root := writeTree(t, map[string]string{
			"go.mod":                syntheticModule,
			"internal/core/core.go": "package core\n",
		})
		target := filepath.Join(root, "external_source.txt")
		if err := os.WriteFile(target, []byte("package core\n\nimport \"os/exec\"\n\nvar _ = exec.Command\n"), 0o644); err != nil {
			t.Fatalf("cannot write the link target: %v", err)
		}
		if err := os.Symlink(target, filepath.Join(root, "internal", "core", "linked.go")); err != nil {
			// Declared physical limit: the link cannot be created in this
			// environment, so the refusal is not reported as verified. The
			// positive control proves a regular file is still analysed.
			t.Logf("link creation is not permitted in this environment: %v", err)
			clean := writeTree(t, map[string]string{
				"go.mod":                syntheticModule,
				"internal/core/core.go": "package core\n\nimport \"strings\"\n\nvar _ = strings.TrimSpace\n",
			})
			expectClean(t, analyzeClosure(t, clean, syntheticCorePolicy()))
			return
		}
		expectFinding(t, analyzeClosure(t, root, syntheticCorePolicy()), "linked source")
	})

	t.Run("generated sources are analysed", func(t *testing.T) {
		root := writeTree(t, map[string]string{
			"go.mod":                        syntheticModule,
			"internal/core/core.go":         "package core\n",
			"internal/core/zz_generated.go": "// Code generated by a tool. DO NOT EDIT.\n\npackage core\n\nimport \"os/exec\"\n\nvar _ = exec.Command\n",
		})
		expectFinding(t, analyzeClosure(t, root, syntheticCorePolicy()), "os/exec")
	})
}
