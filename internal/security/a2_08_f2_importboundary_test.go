package security

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// A2-08-F2 rows of the import gate (handoff §5): internal/prismaacquire is the
// tenth root and a second network-privileged root, independent of the collector
// in both directions. The tests exercise the real enforcer, not a copy of its
// policy.

const f2ConnectorPackage = "github.com/d4rpell/Ariadne/internal/prismaacquire"

func TestA208F2ImportBoundaryRoots(t *testing.T) {
	t.Run("eleven_unique_roots", func(t *testing.T) {
		declared := map[string]boundaryDeclaration{}
		for _, boundary := range importBoundaries {
			if _, repeated := declared[boundary.name]; repeated {
				t.Fatalf("boundary %s is declared twice", boundary.name)
			}
			declared[boundary.name] = boundary
		}
		if len(importBoundaries) != 13 {
			t.Fatalf("importBoundaries has %d entries, want thirteen", len(importBoundaries))
		}
		connector, present := declared["prismaacquire"]
		if !present {
			t.Fatal("the prismaacquire root is not declared")
		}
		if !connector.strict {
			t.Fatal("the prismaacquire root must stay strict")
		}
		if connector.dir != "internal/prismaacquire" || connector.target != "../prismaacquire" {
			t.Fatalf("prismaacquire root points at %q/%q", connector.dir, connector.target)
		}
		for _, forbidden := range []string{"os", "os/exec", "plugin", "unsafe", "syscall"} {
			if !slices.Contains(connector.exact, forbidden) {
				t.Fatalf("the prismaacquire root no longer forbids %q", forbidden)
			}
		}
		if !slices.Contains(connector.trees, "k8s.io/client-go") {
			t.Fatal("the prismaacquire root no longer forbids the client-go tree")
		}
		if !slices.Equal(connector.allowlist, connectorStdlibAllowlist) {
			t.Fatal("the prismaacquire root does not use the connector allowlist")
		}
		if !slices.Contains(connector.networkDirs, "internal/prismaacquire") {
			t.Fatal("the network permission is not granted per package to prismaacquire")
		}
	})
	t.Run("root_sources_exist", func(t *testing.T) {
		dir := filepath.Join(moduleRoot(t), "internal", "prismaacquire")
		entries, err := os.ReadDir(dir)
		if err != nil {
			t.Fatalf("read the prismaacquire package: %v", err)
		}
		production := 0
		for _, entry := range entries {
			if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".go") || strings.HasSuffix(entry.Name(), "_test.go") {
				continue
			}
			production++
		}
		if production == 0 {
			t.Fatal("the prismaacquire root has no production source")
		}
	})
}

func TestA208F2ImportBoundaryPolicies(t *testing.T) {
	t.Run("connector_exact_additions", func(t *testing.T) {
		additions := []string{}
		for _, entry := range connectorStdlibAllowlist {
			if !slices.Contains(adapterStdlibAllowlist, entry) {
				additions = append(additions, entry)
			}
		}
		want := []string{"context", "crypto/tls", "crypto/x509", "net", "net/http", "net/url"}
		if !slices.Equal(additions, want) {
			t.Fatalf("connector additions = %v, want exactly %v", additions, want)
		}
		for _, entry := range adapterStdlibAllowlist {
			if !slices.Contains(connectorStdlibAllowlist, entry) {
				t.Fatalf("the connector list lost the adapter entry %q", entry)
			}
		}
	})
	t.Run("collector_policy_unchanged", func(t *testing.T) {
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
	})
	t.Run("allowlist_storage_independent", func(t *testing.T) {
		before := slices.Clone(adapterStdlibAllowlist)
		policy := stdlibAllowlistFor(closurePolicy{allowlist: connectorStdlibAllowlist, networkPackages: []string{"internal/prismaacquire"}}, "internal/prismaacquire")
		if len(policy) == 0 {
			t.Fatal("no policy was selected")
		}
		policy[0] = "synthetic-mutation"
		if !slices.Equal(adapterStdlibAllowlist, before) {
			t.Fatal("the selected policy shares storage with the adapter list")
		}
		original := connectorStdlibAllowlist[0]
		connectorStdlibAllowlist[0] = "synthetic-storage-probe"
		if adapterStdlibAllowlist[0] == "synthetic-storage-probe" {
			connectorStdlibAllowlist[0] = original
			t.Fatal("the connector list shares storage with the adapter list")
		}
		connectorStdlibAllowlist[0] = original
	})
}

func TestA208F2ImportBoundaryDirections(t *testing.T) {
	for _, entry := range []string{f2ConnectorPackage} {
		if !slices.Contains(offlineRootBannedLocal, entry) {
			t.Fatalf("offline roots no longer forbid %q", entry)
		}
	}
	if !slices.Contains(collectorBannedLocal, f2ConnectorPackage) {
		t.Fatal("the collector no longer forbids the connector")
	}
	for _, entry := range []string{
		"github.com/d4rpell/Ariadne/internal/collector",
		"github.com/d4rpell/Ariadne/internal/evaluator",
		"github.com/d4rpell/Ariadne/internal/rulepack",
		"github.com/d4rpell/Ariadne/internal/report",
		"github.com/d4rpell/Ariadne/internal/bundle",
		"github.com/d4rpell/Ariadne/cmd/ariadne",
	} {
		if !slices.Contains(connectorBannedLocal, entry) {
			t.Fatalf("the connector no longer forbids %q", entry)
		}
	}

	t.Run("no_offline_root_reaches_connector", func(t *testing.T) {
		for _, boundary := range importBoundaries {
			if boundary.name == "prismaacquire" {
				continue
			}
			deps := goListLines(t, "-deps", "-f", "{{.ImportPath}}", boundary.target)
			for _, dep := range deps {
				if dep == f2ConnectorPackage {
					t.Fatalf("%s depends on internal/prismaacquire", boundary.name)
				}
			}
		}
	})
	t.Run("connector_does_not_reach_domain", func(t *testing.T) {
		deps := goListLines(t, "-deps", "-f", "{{.ImportPath}}", "../prismaacquire")
		for _, forbidden := range connectorBannedLocal {
			if !strings.HasPrefix(forbidden, "github.com/d4rpell/Ariadne/") {
				continue // stdlib surfaces are governed by the allowlist, not this dep check
			}
			for _, dep := range deps {
				if dep == forbidden || strings.HasPrefix(dep, forbidden+"/") {
					t.Fatalf("prismaacquire depends on %s", dep)
				}
			}
		}
	})
}

func TestA208F2ImportBoundaryGateWiring(t *testing.T) {
	var connector boundaryDeclaration
	found := false
	for _, boundary := range importBoundaries {
		if boundary.name == "prismaacquire" {
			connector = boundary
			found = true
		}
	}
	if !found {
		t.Fatal("the prismaacquire boundary is not declared")
	}
	findings := analyzeClosure(t, moduleRoot(t), closurePolicy{
		name:            connector.name,
		dir:             connector.dir,
		core:            connector.core,
		strict:          connector.strict,
		exact:           connector.exact,
		trees:           connector.trees,
		allowlist:       connector.allowlist,
		networkPackages: connector.networkDirs,
		bannedLocal:     connector.bannedLocal,
	})
	if len(findings) != 0 {
		t.Fatalf("the real gate reports findings for prismaacquire: %v", findings)
	}
	for _, found := range scanDirectImports(t, goListDir(t, connector.target)) {
		if banned := forbiddenMatch(found.path, connector.exact, connector.trees); banned != "" {
			t.Errorf("%s imports %s, forbidden (%s)", found.file, found.path, banned)
		}
	}
}

func TestA208F2APISurface(t *testing.T) {
	dir := filepath.Join(moduleRoot(t), "internal", "prismaacquire")
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read prismaacquire: %v", err)
	}
	forbiddenInExported := []string{"RoundTripper", "http.Client", "tls.Config", "net.Dialer", "func(", "http.DefaultClient", "net.Listen"}
	forbiddenAnywhere := []string{"InsecureSkipVerify", "os.Open", "os.Create", "os.WriteFile", "os.Getenv"}
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".go") || strings.HasSuffix(entry.Name(), "_test.go") {
			continue
		}
		content := productionSource(t, "internal/prismaacquire", entry.Name())
		for _, line := range strings.Split(content, "\n") {
			trimmed := strings.TrimSpace(line)
			if strings.HasPrefix(trimmed, "func ") {
				name := strings.TrimPrefix(trimmed, "func ")
				if name != "" && name[0] >= 'A' && name[0] <= 'Z' {
					for _, forbidden := range forbiddenInExported {
						if strings.Contains(trimmed, forbidden) {
							t.Fatalf("%s: exported %q admits %q", entry.Name(), trimmed, forbidden)
						}
					}
				}
			}
			for _, forbidden := range forbiddenAnywhere {
				if strings.Contains(trimmed, forbidden) {
					t.Fatalf("%s: production source contains %q", entry.Name(), forbidden)
				}
			}
		}
	}
}
