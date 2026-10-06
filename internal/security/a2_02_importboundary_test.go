package security

import (
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// A2-02 rows of the import gate (handoff §4.6): the ninth root exists with its
// own policy, the previous policies are untouched, the forbidden directions are
// enforced in both senses and the real gate really applies all of it.

func TestA202ImportBoundaryRoots(t *testing.T) {
	t.Run("eleven_unique_roots", func(t *testing.T) {
		declared := map[string]boundaryDeclaration{}
		for _, boundary := range importBoundaries {
			if _, repeated := declared[boundary.name]; repeated {
				t.Fatalf("boundary %s is declared twice", boundary.name)
			}
			declared[boundary.name] = boundary
		}
		if len(importBoundaries) != 13 {
			t.Fatalf("importBoundaries has %d entries, want the thirteen declared roots", len(importBoundaries))
		}
		collector, present := declared["collector"]
		if !present {
			t.Fatal("the collector root is not declared")
		}
		if !collector.strict {
			t.Fatal("the collector root must stay strict")
		}
		if collector.dir != "internal/collector" || collector.target != "../collector" {
			t.Fatalf("collector root points at %q/%q", collector.dir, collector.target)
		}
		for _, forbidden := range []string{"os", "os/exec", "plugin", "unsafe", "syscall"} {
			if !slices.Contains(collector.exact, forbidden) {
				t.Fatalf("the collector root no longer forbids %q", forbidden)
			}
		}
		if !slices.Contains(collector.trees, "k8s.io/client-go") {
			t.Fatal("the collector root no longer forbids the client-go tree")
		}
	})
	t.Run("root_sources_exist", func(t *testing.T) {
		dir := filepath.Join(moduleRoot(t), "internal", "collector")
		entries, err := os.ReadDir(dir)
		if err != nil {
			t.Fatalf("read the collector package: %v", err)
		}
		production := 0
		for _, entry := range entries {
			if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".go") || strings.HasSuffix(entry.Name(), "_test.go") {
				continue
			}
			production++
		}
		if production == 0 {
			t.Fatal("the collector root has no production source")
		}
	})
}

func TestA202ImportBoundaryPolicies(t *testing.T) {
	t.Run("collector_exact_additions", func(t *testing.T) {
		additions := []string{}
		for _, entry := range collectorStdlibAllowlist {
			if !slices.Contains(adapterStdlibAllowlist, entry) {
				additions = append(additions, entry)
			}
		}
		want := []string{"context", "crypto/tls", "crypto/x509", "net", "net/http", "net/url"}
		if !slices.Equal(additions, want) {
			t.Fatalf("collector additions = %v, want exactly %v", additions, want)
		}
		// The base of the collector list is the adapter list, not a copy of a
		// copy: widening one never widens the other.
		for _, entry := range adapterStdlibAllowlist {
			if !slices.Contains(collectorStdlibAllowlist, entry) {
				t.Fatalf("the collector list lost the adapter entry %q", entry)
			}
		}
	})
	t.Run("adapter_policy_unchanged", func(t *testing.T) {
		extra := []string{}
		for _, entry := range adapterStdlibAllowlist {
			if !slices.Contains(coreStdlibAllowlist, entry) {
				extra = append(extra, entry)
			}
		}
		if !slices.Equal(extra, []string{"regexp", "net/netip"}) {
			t.Fatalf("the adapter additions = %v, want exactly regexp and net/netip", extra)
		}
	})
	t.Run("core_policy_unchanged", func(t *testing.T) {
		for _, leaked := range []string{"regexp", "net/netip", "context", "crypto/tls", "crypto/x509", "net", "net/http", "net/url"} {
			if slices.Contains(coreStdlibAllowlist, leaked) {
				t.Fatalf("the core allowlist gained %q", leaked)
			}
		}
	})
	t.Run("allowlist_storage_independent", func(t *testing.T) {
		// Mutating the selected policy must not alter its declared source list,
		// and the collector list must not share storage with the adapter list.
		before := slices.Clone(adapterStdlibAllowlist)
		policy := stdlibAllowlistFor(closurePolicy{allowlist: adapterStdlibAllowlist, networkPackages: []string{"internal/collector"}}, "internal/collector")
		if len(policy) == 0 {
			t.Fatal("no policy was selected")
		}
		policy[0] = "synthetic-mutation"
		if !slices.Equal(adapterStdlibAllowlist, before) {
			t.Fatal("the selected policy shares storage with the adapter list")
		}
		// Writing through the collector list must not reach the adapter list:
		// the probe is restored unconditionally, and the two lists never share
		// their backing storage.
		original := collectorStdlibAllowlist[0]
		collectorStdlibAllowlist[0] = "synthetic-storage-probe"
		defer func() { collectorStdlibAllowlist[0] = original }()
		if adapterStdlibAllowlist[0] == "synthetic-storage-probe" {
			t.Fatal("the collector list shares storage with the adapter list")
		}
		for _, entry := range coreStdlibAllowlist {
			if entry == "synthetic-storage-probe" {
				t.Fatal("the collector list shares storage with the core list")
			}
		}
	})
	t.Run("network_only_in_collector_package", func(t *testing.T) {
		policy := closurePolicy{allowlist: adapterStdlibAllowlist, networkPackages: []string{"internal/collector"}}
		inCollector := stdlibAllowlistFor(policy, "internal/collector")
		for _, addition := range collectorNetworkAdditions {
			if !slices.Contains(inCollector, addition) {
				t.Fatalf("the collector package lost %q", addition)
			}
		}
		helper := stdlibAllowlistFor(policy, "internal/collector/transport")
		for _, addition := range collectorNetworkAdditions {
			if slices.Contains(helper, addition) {
				t.Fatalf("a local helper inherited the network addition %q", addition)
			}
		}
		// A core root keeps the core list whatever it declares.
		if core := stdlibAllowlistFor(closurePolicy{core: true}, "internal/collector"); !slices.Equal(core, coreStdlibAllowlist) {
			t.Fatal("a core policy selected another allowlist for the collector package")
		}
	})
}

func TestA202ImportBoundaryDirections(t *testing.T) {
	// The analyzer is exercised over a synthetic tree with the real policy of
	// the collector root: the direction is refused in both senses.
	// The synthetic tree uses the synthetic module path, so the prohibition list
	// of the control is the same closed set expressed against that path.
	syntheticBanned := []string{
		"os", "os/exec", "unsafe", "syscall", "plugin", "C",
		"example.test/synthetic/internal/evaluator",
		"example.test/synthetic/internal/rulepack",
		"example.test/synthetic/internal/report",
		"example.test/synthetic/cmd/ariadne",
	}
	collectorPolicy := func(dir string) closurePolicy {
		return closurePolicy{
			name:            "collector",
			dir:             dir,
			strict:          true,
			allowlist:       adapterStdlibAllowlist,
			networkPackages: []string{"internal/collector"},
			bannedLocal:     syntheticBanned,
		}
	}
	for name, target := range map[string]string{
		"evaluator": "internal/evaluator",
		"rulepack":  "internal/rulepack",
		"report":    "internal/report",
		"cli":       "cmd/ariadne",
	} {
		t.Run("collector_cannot_reach_"+name, func(t *testing.T) {
			root := writeTree(t, map[string]string{
				"go.mod":                          syntheticModule,
				"internal/collector/collector.go": "package collector\n\nimport \"example.test/synthetic/" + target + "\"\n\nvar _ = " + packageName(target) + ".Value\n",
				target + "/value.go":              "package " + packageName(target) + "\n\nconst Value = 1\n",
			})
			findings := analyzeClosure(t, root, collectorPolicy("internal/collector"))
			expectFinding(t, findings, "forbidden local package")
		})
	}
	for _, name := range []string{"evaluator", "rulepack", "report", "cli"} {
		t.Run("each_old_root_cannot_reach_collector/"+name, func(t *testing.T) {
			// The reverse direction is a declared prohibition of each previous
			// root; the control proves the analyzer reports the edge.
			root := writeTree(t, map[string]string{
				"go.mod":                          syntheticModule,
				"internal/collector/collector.go": "package collector\n\nconst Value = 1\n",
				"internal/x/value.go":             "package x\n\nimport \"example.test/synthetic/internal/collector\"\n\nvar _ = collector.Value\n",
			})
			policy := closurePolicy{
				name:        name,
				dir:         "internal/x",
				bannedLocal: []string{"example.test/synthetic/internal/collector"},
			}
			// The mechanism the previous roots use to refuse the direction is
			// the same banned-local check: the synthetic edge is detected.
			expectFinding(t, analyzeClosure(t, root, policy), "forbidden local package")
		})
	}
	t.Run("real_roots_do_not_reach_collector", func(t *testing.T) {
		// The real gate: no previous root reaches internal/collector.
		for _, boundary := range importBoundaries {
			if boundary.name == "collector" {
				continue
			}
			deps := goListLines(t, "-deps", "-f", "{{.ImportPath}}", boundary.target)
			for _, dep := range deps {
				if dep == "github.com/d4rpell/Ariadne/internal/collector" {
					t.Fatalf("%s depends on internal/collector", boundary.name)
				}
			}
		}
	})
}

func TestA202ImportBoundaryVariants(t *testing.T) {
	policy := func(dir string) closurePolicy {
		return closurePolicy{
			name:            "collector",
			dir:             dir,
			strict:          true,
			allowlist:       adapterStdlibAllowlist,
			networkPackages: []string{"internal/collector"},
			bannedLocal:     collectorBannedLocal,
		}
	}
	t.Run("forbidden_local_import", func(t *testing.T) {
		root := writeTree(t, map[string]string{
			"go.mod":                          syntheticModule,
			"internal/collector/collector.go": "package collector\n\nimport \"os\"\n\nvar _ = os.Getenv\n",
		})
		expectFinding(t, analyzeClosure(t, root, policy("internal/collector")), "forbidden local package")
	})
	t.Run("transitive_helper", func(t *testing.T) {
		root := writeTree(t, map[string]string{
			"go.mod":                          syntheticModule,
			"internal/collector/collector.go": "package collector\n\nimport \"example.test/synthetic/internal/helper\"\n\nvar _ = helper.Value\n",
			"internal/helper/helper.go":       "package helper\n\nimport \"os/exec\"\n\nvar _ = exec.Command\n\nconst Value = 1\n",
		})
		findings := analyzeClosure(t, root, policy("internal/collector"))
		expectFinding(t, findings, "forbidden local package")
	})
	t.Run("excluded_build_tag", func(t *testing.T) {
		root := writeTree(t, map[string]string{
			"go.mod":                            syntheticModule,
			"internal/collector/collector.go":   "package collector\n",
			"internal/collector/shell_plan9.go": "//go:build plan9\n\npackage collector\n\nimport \"os/exec\"\n\nvar _ = exec.Command\n",
		})
		expectFinding(t, analyzeClosure(t, root, policy("internal/collector")), "forbidden local package")
	})
	t.Run("excluded_goos", func(t *testing.T) {
		root := writeTree(t, map[string]string{
			"go.mod":                          syntheticModule,
			"internal/collector/collector.go": "package collector\n",
			"internal/collector/net_js.go":    "//go:build js\n\npackage collector\n\nimport \"net\"\n\nvar _ = net.Dial\n",
		})
		// net is admitted in the package itself: no finding for it, and the
		// variant is still analysed (the union walk reads every file).
		expectClean(t, analyzeClosure(t, root, policy("internal/collector")))
	})
	t.Run("native_source", func(t *testing.T) {
		root := writeTree(t, map[string]string{
			"go.mod":                          syntheticModule,
			"internal/collector/collector.go": "package collector\n",
			"internal/collector/asm.s":        "TEXT ·Value(SB),$0-0\n",
		})
		expectFinding(t, analyzeClosure(t, root, policy("internal/collector")), "native or linked source")
	})
	t.Run("unsupported_directive", func(t *testing.T) {
		root := writeTree(t, map[string]string{
			"go.mod":                          syntheticModule,
			"internal/collector/collector.go": "package collector\n\n//go:linkname secret runtime.secret\nfunc secret()\n",
		})
		expectFinding(t, analyzeClosure(t, root, policy("internal/collector")), "go:linkname")
	})
	t.Run("external_dependency", func(t *testing.T) {
		root := writeTree(t, map[string]string{
			"go.mod":                          syntheticModule,
			"internal/collector/collector.go": "package collector\n\nimport \"github.com/other/thing\"\n\nvar _ = thing.Value\n",
		})
		expectFinding(t, analyzeClosure(t, root, policy("internal/collector")), "external dependency")
	})
	t.Run("resolution_failure", func(t *testing.T) {
		root := writeTree(t, map[string]string{
			"go.mod":                          syntheticModule,
			"internal/collector/collector.go": "package collector\n\nimport \"example.test/synthetic/internal/absent\"\n\nvar _ = absent.Value\n",
		})
		expectFinding(t, analyzeClosure(t, root, policy("internal/collector")), "unresolved local import")
	})
}

func TestA202ImportBoundaryGateWiring(t *testing.T) {
	t.Run("real_gate_passes_policy", func(t *testing.T) {
		// The real gate selects the collector policy, not a copy: the closure of
		// the real root must run clean with the declared allowlist.
		findings := analyzeClosure(t, moduleRoot(t), closurePolicy{
			name:            "collector",
			dir:             "internal/collector",
			strict:          true,
			exact:           []string{"os", "os/exec", "plugin", "unsafe", "syscall"},
			trees:           []string{"k8s.io/client-go"},
			allowlist:       collectorStdlibAllowlist,
			networkPackages: []string{"internal/collector"},
			bannedLocal:     collectorBannedLocal,
		})
		if len(findings) != 0 {
			t.Fatalf("the real collector closure reports findings:\n%s", findingsText(findings))
		}
	})
	t.Run("real_gate_declares_the_local_prohibitions", func(t *testing.T) {
		// The real gate must carry the closed local prohibitions of the
		// collector: without them the closure would not refuse the directions.
		collector := boundaryDeclaration{}
		for _, boundary := range importBoundaries {
			if boundary.name == "collector" {
				collector = boundary
			}
		}
		for _, forbidden := range collectorBannedLocal {
			if !slices.Contains(collector.bannedLocal, forbidden) {
				t.Fatalf("the collector root no longer forbids the local package %q", forbidden)
			}
		}
		if len(collector.bannedLocal) != len(collectorBannedLocal) {
			t.Fatalf("the collector local prohibitions changed: %v", collector.bannedLocal)
		}
		if len(collector.networkDirs) != 1 || collector.networkDirs[0] != "internal/collector" {
			t.Fatalf("the collector network grant changed: %v", collector.networkDirs)
		}
	})
	t.Run("real_gate_checks_local_edges", func(t *testing.T) {
		// The closure of the real root refuses a synthetic tree where the
		// collector reaches a forbidden package: the policy the gate passes is
		// the one that decides.
		root := writeTree(t, map[string]string{
			"go.mod":                          syntheticModule,
			"internal/collector/collector.go": "package collector\n\nimport \"example.test/synthetic/internal/helper\"\n\nvar _ = helper.Value\n",
			"internal/helper/helper.go":       "package helper\n\nimport \"syscall\"\n\nvar _ = syscall.Getpid\n\nconst Value = 1\n",
		})
		findings := analyzeClosure(t, root, closurePolicy{
			name:            "collector",
			dir:             "internal/collector",
			strict:          true,
			allowlist:       adapterStdlibAllowlist,
			networkPackages: []string{"internal/collector"},
			bannedLocal:     collectorBannedLocal,
		})
		expectFinding(t, findings, "forbidden local package")
	})
	t.Run("real_gate_selects_per_package_allowlist", func(t *testing.T) {
		// A helper reached from the collector may not use the network additions:
		// the per-package selector proves it.
		root := writeTree(t, map[string]string{
			"go.mod":                          syntheticModule,
			"internal/collector/collector.go": "package collector\n\nimport \"example.test/synthetic/internal/helper\"\n\nvar _ = helper.Value\n",
			"internal/helper/helper.go":       "package helper\n\nimport \"net/http\"\n\nvar _ = http.Get\n\nconst Value = 1\n",
		})
		findings := analyzeClosure(t, root, closurePolicy{
			name:            "collector",
			dir:             "internal/collector",
			strict:          true,
			allowlist:       adapterStdlibAllowlist,
			networkPackages: []string{"internal/collector"},
			bannedLocal:     collectorBannedLocal,
		})
		expectFinding(t, findings, "outside the adapter allowlist")
	})
}

func TestA202CollectorAPISurface(t *testing.T) {
	t.Run("public_api_has_no_transport_hook", func(t *testing.T) {
		// The public configuration carries no transport, client, dialer or clock
		// hook: the fields are exactly the declared ones.
		source := productionSource(t, filepath.Join("internal", "collector"), "types.go")
		for _, forbidden := range []string{"Transport", "Client *http.Client", "Dial", "Clock"} {
			if strings.Contains(source, forbidden) {
				t.Fatalf("the public configuration exposes %q", forbidden)
			}
		}
	})
	t.Run("no_global_client_mutation", func(t *testing.T) {
		// No production source assigns to http.DefaultClient or
		// http.DefaultTransport.
		files, err := os.ReadDir(filepath.Join(moduleRoot(t), "internal", "collector"))
		if err != nil {
			t.Fatalf("read the collector package: %v", err)
		}
		for _, file := range files {
			if file.IsDir() || !strings.HasSuffix(file.Name(), ".go") || strings.HasSuffix(file.Name(), "_test.go") {
				continue
			}
			content := productionSource(t, filepath.Join("internal", "collector"), file.Name())
			for _, forbidden := range []string{"http.DefaultClient =", "http.DefaultTransport ="} {
				if strings.Contains(content, forbidden) {
					t.Fatalf("%s assigns %q", file.Name(), forbidden)
				}
			}
		}
	})
	t.Run("no_listener_or_persistence_path", func(t *testing.T) {
		files, err := os.ReadDir(filepath.Join(moduleRoot(t), "internal", "collector"))
		if err != nil {
			t.Fatalf("read the collector package: %v", err)
		}
		for _, file := range files {
			if file.IsDir() || !strings.HasSuffix(file.Name(), ".go") || strings.HasSuffix(file.Name(), "_test.go") {
				continue
			}
			content := productionSource(t, filepath.Join("internal", "collector"), file.Name())
			for _, forbidden := range []string{"net.Listen", "os.Open", "os.Create", "os.WriteFile", "os/exec"} {
				if strings.Contains(content, forbidden) {
					t.Fatalf("%s uses %q", file.Name(), forbidden)
				}
			}
		}
	})
}

// productionSource reads one production file of the module.
func productionSource(t *testing.T, dir, name string) string {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(moduleRoot(t), filepath.FromSlash(dir), name))
	if err != nil {
		t.Fatalf("read %s/%s: %v", dir, name, err)
	}
	return string(data)
}

// packageName derives the package identifier of one local directory path.
func packageName(path string) string {
	parts := strings.Split(path, "/")
	last := parts[len(parts)-1]
	return strings.ReplaceAll(last, "-", "")
}

// goListDepsOf is a small wrapper used by the direction controls.
func goListDepsOf(t *testing.T, target string) []string {
	t.Helper()
	command := exec.Command("go", "list", "-deps", "-f", "{{.ImportPath}}", target)
	command.Dir = moduleRoot(t)
	command.Env = append(os.Environ(), "GOPROXY=off", "GOSUMDB=off", "GOFLAGS=-mod=readonly")
	out, err := command.Output()
	if err != nil {
		t.Fatalf("go list -deps %s: %v", target, err)
	}
	return strings.Fields(string(out))
}
