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
	strict bool
	// stdlibOnly marks the one root (internal/casefile, ADR-0030 §6) whose
	// closure may reach no local package at all; every import must be standard
	// library inside the root's own allowlist.
	stdlibOnly bool
	exact      []string
	trees      []string
	// graphExact and graphTrees narrow the transitive `go list -deps` pass when
	// the standard library's own internals would trip a prohibition that is only
	// meant for this project's sources: `os` needs `syscall` and `unsafe`, and
	// treating the stdlib's implementation as a violation would be a false
	// positive. The direct-import scan and the closure keep the full lists.
	graphExact []string
	graphTrees []string
	// allowlist is the closure policy of this root. The collector root uses the
	// independent list of ADR-0026 A.4.2; the adapter roots keep theirs and the
	// core roots keep coreStdlibAllowlist.
	allowlist []string
	// networkDirs lists the module-relative directories whose own sources may
	// use the network additions of the collector profile.
	networkDirs []string
	// networkAdditions, when non-nil, replaces the collector network additions
	// for the directories granted in networkDirs, letting a root grant a
	// narrower addition (the read-only platform grants only net and net/http).
	networkAdditions []string
	// bannedLocal lists package paths forbidden in the sources of the closure.
	bannedLocal []string
}

// importBoundaries is the declared surface of the gate. A policy never comes
// from a rule pack or from user configuration.
var importBoundaries = []boundaryDeclaration{
	{
		name:        "evaluator",
		target:      "../evaluator",
		dir:         "internal/evaluator",
		core:        true,
		exact:       []string{"net"},
		trees:       []string{"net/http", "os/exec", "k8s.io/client-go"},
		bannedLocal: offlineRootBannedLocal,
	},
	{
		name:        "rulepack",
		target:      "../rulepack",
		dir:         "internal/rulepack",
		core:        true,
		exact:       []string{"net"},
		trees:       []string{"net/http", "os/exec", "k8s.io/client-go"},
		bannedLocal: offlineRootBannedLocal,
	},
	{
		name:        "report",
		target:      "../report",
		dir:         "internal/report",
		trees:       []string{"os/exec"},
		bannedLocal: offlineRootBannedLocal,
	},
	// Interoperability exports (ADR-0032). This is the twelfth root: an offline
	// projection with no process execution, no network and no dependence on the
	// live collector or the Prisma API connector, in the sources, the direct scan
	// and the closure alike. It is stricter than the report root beside it so the
	// contract's "no network" is enforced, not merely asserted.
	{
		name:        "interop",
		target:      "../interop",
		dir:         "internal/interop",
		exact:       []string{"net", "os/exec", "plugin", "unsafe", "syscall"},
		trees:       []string{"net/http", "k8s.io/client-go"},
		graphExact:  []string{"net", "os/exec", "plugin"},
		graphTrees:  []string{"net/http", "k8s.io/client-go"},
		bannedLocal: offlineRootBannedLocal,
	},
	{
		name:   "cli",
		target: "../../cmd/ariadne",
		dir:    "cmd/ariadne",
		strict: true,
		exact:  []string{"net", "os/exec", "plugin", "unsafe", "syscall"},
		trees:  []string{"net/http", "k8s.io/client-go"},
		// The adapter legitimately reaches `os`, and `os` reaches its syscalls
		// inside the standard library: the graph pass bans only what must never
		// appear even transitively, while `unsafe`, `syscall` and `plugin` remain
		// forbidden in the adapter's own sources and in the local closure.
		//
		// Since the CLI reaches the read-only platform server (ADR-0034), its
		// graph now contains net and net/http transitively; the transitive graph
		// pass can no longer ban them, but the direct scan still forbids net and
		// the net/http tree in the CLI's own sources (exact/trees), and the
		// closure checks every local package against cliStdlibAllowlist.
		graphExact: []string{"os/exec", "plugin"},
		graphTrees: []string{"k8s.io/client-go"},
		allowlist:  cliStdlibAllowlist,
		// net and net/http are granted per package to internal/platform alone,
		// with the narrower readOnlyPlatformNetworkAdditions; every other package
		// of the CLI closure keeps the base list, which excludes them.
		networkDirs:      []string{"internal/platform"},
		networkAdditions: readOnlyPlatformNetworkAdditions,
		bannedLocal:      offlineRootBannedLocal,
	},
	// Sanitized PodList adapter roots (ADR-0025 A.11.3). The profile must not
	// reach network, shell, filesystem, process execution or cluster clients,
	// directly or through a local intermediate package. `os` is forbidden
	// exactly in the sources themselves and in the closure; the graph pass
	// cannot ban it because the standard library's own `fmt` reaches it.
	{
		name:        "ingest",
		target:      "../ingest",
		dir:         "internal/ingest",
		strict:      true,
		exact:       []string{"net", "os", "os/exec", "plugin", "unsafe", "syscall"},
		trees:       []string{"net/http", "k8s.io/client-go"},
		graphExact:  []string{"net", "os/exec", "plugin"},
		graphTrees:  []string{"net/http", "k8s.io/client-go"},
		bannedLocal: offlineRootBannedLocal,
	},
	{
		name:        "normalize",
		target:      "../normalize",
		dir:         "internal/normalize",
		strict:      true,
		exact:       []string{"net", "os", "os/exec", "plugin", "unsafe", "syscall"},
		trees:       []string{"net/http", "k8s.io/client-go"},
		graphExact:  []string{"net", "os/exec", "plugin"},
		graphTrees:  []string{"net/http", "k8s.io/client-go"},
		bannedLocal: offlineRootBannedLocal,
	},
	{
		name:        "identity",
		target:      "../identity",
		dir:         "internal/identity",
		strict:      true,
		exact:       []string{"net", "os", "os/exec", "plugin", "unsafe", "syscall"},
		trees:       []string{"net/http", "k8s.io/client-go"},
		graphExact:  []string{"net", "os/exec", "plugin"},
		graphTrees:  []string{"net/http", "k8s.io/client-go"},
		bannedLocal: offlineRootBannedLocal,
	},
	{
		name:        "bundle",
		target:      "../bundle",
		dir:         "internal/bundle",
		strict:      true,
		exact:       []string{"net", "os", "os/exec", "plugin", "unsafe", "syscall"},
		trees:       []string{"net/http", "k8s.io/client-go"},
		graphExact:  []string{"net", "os/exec", "plugin"},
		graphTrees:  []string{"net/http", "k8s.io/client-go"},
		bannedLocal: offlineRootBannedLocal,
	},
	// Optional live collector (ADR-0026 A.4.2). This is the ninth root and the
	// only one whose own sources may reach the network: the profile needs a REST
	// client built on the standard library. The permission lives in
	// networkDirs and is granted per package by stdlibAllowlistFor: a local
	// helper reached from the collector keeps the adapter list. `os` stays
	// forbidden in the sources themselves and in the closure even though the
	// graph pass cannot ban it (the standard library's fmt reaches it).
	{
		name:        "collector",
		target:      "../collector",
		dir:         "internal/collector",
		strict:      true,
		exact:       []string{"os", "os/exec", "plugin", "unsafe", "syscall"},
		trees:       []string{"k8s.io/client-go"},
		graphExact:  []string{"os/exec", "plugin"},
		graphTrees:  []string{"k8s.io/client-go"},
		allowlist:   adapterStdlibAllowlist,
		networkDirs: []string{"internal/collector"},
		bannedLocal: collectorBannedLocal,
	},
	// Optional Prisma API acquisition connector (ADR-0028). This is the tenth
	// root and a second network-privileged root, independent of the collector in
	// both directions: the two must never import each other. Its own sources may
	// reach the same closed network addition as the collector, granted per
	// package; a local helper keeps the adapter list. `os` stays forbidden in
	// the sources and the closure (the standard library's fmt reaches it, so the
	// graph pass cannot ban it).
	{
		name:        "prismaacquire",
		target:      "../prismaacquire",
		dir:         "internal/prismaacquire",
		strict:      true,
		exact:       []string{"os", "os/exec", "plugin", "unsafe", "syscall"},
		trees:       []string{"k8s.io/client-go"},
		graphExact:  []string{"os/exec", "plugin"},
		graphTrees:  []string{"k8s.io/client-go"},
		allowlist:   connectorStdlibAllowlist,
		networkDirs: []string{"internal/prismaacquire"},
		bannedLocal: connectorBannedLocal,
	},
	// Governance decision records (ADR-0030). This is the eleventh root and the
	// only stdlib-only one: internal/casefile may import neither another local
	// package nor any standard-library package outside its own ten-entry list.
	// No network, no os, no time and no fmt, in the sources, the direct scan,
	// the graph pass and the closure alike.
	{
		name:        "casefile",
		target:      "../casefile",
		dir:         "internal/casefile",
		strict:      true,
		stdlibOnly:  true,
		exact:       []string{"os", "os/exec", "net", "time", "fmt", "log", "crypto/rand", "math/rand", "plugin", "unsafe", "syscall", "C"},
		trees:       []string{"net/http", "k8s.io/client-go"},
		graphExact:  []string{"net", "os/exec", "plugin"},
		graphTrees:  []string{"net/http", "k8s.io/client-go"},
		allowlist:   casefileStdlibAllowlist,
		bannedLocal: offlineRootBannedLocal,
	},
	// Read-only governance platform (ADR-0034, task A3-06). This is the
	// thirteenth root and the only one that listens on the network: the loopback
	// dashboard server binds 127.0.0.1 and serves net/http. net and net/http are
	// therefore permitted in its own sources and in the closure, but only through
	// the root's own allowlist (platformStdlibAllowlist), which also covers the
	// direct imports of internal/casefile reached from it: the permission is a
	// closed list, never the collector's network addition. The server listens
	// (net.Listen) and never dials. `os`, the process and the native surfaces stay
	// forbidden in the sources and in the closure; the graph pass cannot ban `os`
	// because the standard library's own net/http reaches it. The root must never
	// reach the live collector or the Prisma API connector.
	{
		name:        "platform",
		target:      "../platform",
		dir:         "internal/platform",
		strict:      true,
		exact:       []string{"os", "os/exec", "plugin", "unsafe", "syscall"},
		trees:       []string{"k8s.io/client-go"},
		graphExact:  []string{"os/exec", "plugin"},
		graphTrees:  []string{"k8s.io/client-go"},
		allowlist:   platformStdlibAllowlist,
		bannedLocal: offlineRootBannedLocal,
	},
}

// adapterRoots are the boundary names whose closure uses the independent
// adapter allowlist of ADR-0025 A.11.3 instead of the core allowlist.
var adapterRoots = map[string]bool{
	"ingest":    true,
	"normalize": true,
	"identity":  true,
	"bundle":    true,
}

// allowlistFor selects the closure policy declared for one boundary. A root
// may declare its own list; the adapter roots keep the ADR-0025 policy and
// every other root keeps the core policy of ADR-0014.
func allowlistFor(boundary boundaryDeclaration) []string {
	if boundary.allowlist != nil {
		return boundary.allowlist
	}
	if adapterRoots[boundary.name] {
		return adapterStdlibAllowlist
	}
	return nil
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

			graphExact, graphTrees := boundary.exact, boundary.trees
			if boundary.graphExact != nil || boundary.graphTrees != nil {
				graphExact, graphTrees = boundary.graphExact, boundary.graphTrees
			}
			for _, dep := range deps {
				if banned := forbiddenMatch(dep, graphExact, graphTrees); banned != "" {
					t.Errorf("%s depends on %s, forbidden by the import boundary (%s)", importPath, dep, banned)
				}
			}

			for _, found := range scanDirectImports(t, goListDir(t, boundary.target)) {
				if banned := forbiddenMatch(found.path, boundary.exact, boundary.trees); banned != "" {
					t.Errorf("%s: %s imports %s, forbidden by the import boundary (%s)", importPath, found.file, found.path, banned)
				}
				// A root with a per-package allowlist is checked here as well:
				// the direct scan sees every build variant of the package, so an
				// addition outside the declared list is refused without waiting
				// for the closure pass.
				if boundary.allowlist != nil && stdlibPath(found.path) {
					packageAllowlist := stdlibAllowlistFor(closurePolicy{allowlist: boundary.allowlist, networkPackages: boundary.networkDirs, networkAdditions: boundary.networkAdditions}, boundary.dir)
					if !slices.Contains(packageAllowlist, found.path) {
						t.Errorf("%s: %s imports %s, outside the declared allowlist", importPath, found.file, found.path)
					}
				}
			}

			// The closure is reached through this test on purpose: the gate the
			// Makefile names selects this function, so a closure failure must
			// fail here and not only in the analyzer's own cases.
			closure := analyzeClosure(t, moduleRoot(t), closurePolicy{
				name:             boundary.name,
				dir:              boundary.dir,
				core:             boundary.core,
				strict:           boundary.strict,
				stdlibOnly:       boundary.stdlibOnly,
				exact:            boundary.exact,
				trees:            boundary.trees,
				allowlist:        allowlistFor(boundary),
				networkPackages:  boundary.networkDirs,
				networkAdditions: boundary.networkAdditions,
				bannedLocal:      boundary.bannedLocal,
			})
			for _, finding := range closure {
				t.Errorf("import closure: %s", finding)
			}
		})
	}
}

// TestCLINetworkGrantIsScoped pins the invariant of the ADR-0034 CLI boundary:
// net and net/http are granted inside the CLI closure to internal/platform
// alone, never to another local package. It would have caught the original
// over-broad grant, where the base allowlist let any helper reach the socket.
func TestCLINetworkGrantIsScoped(t *testing.T) {
	for _, pkg := range []string{"net", "net/http"} {
		if slices.Contains(cliStdlibAllowlist, pkg) {
			t.Errorf("cliStdlibAllowlist must not contain %q in its base list", pkg)
		}
	}
	// Read the grant from the real CLI boundary declaration, not a local copy:
	// otherwise a widened production networkDirs would leave this test green
	// while the boundary it names had changed.
	var cliBoundary boundaryDeclaration
	for _, boundary := range importBoundaries {
		if boundary.name == "cli" {
			cliBoundary = boundary
		}
	}
	if cliBoundary.name == "" {
		t.Fatal("the cli boundary is not declared")
	}
	policy := closurePolicy{
		allowlist:        cliBoundary.allowlist,
		networkPackages:  cliBoundary.networkDirs,
		networkAdditions: cliBoundary.networkAdditions,
	}
	granted := stdlibAllowlistFor(policy, "internal/platform")
	if !slices.Contains(granted, "net") || !slices.Contains(granted, "net/http") {
		t.Errorf("internal/platform must be granted net and net/http inside the CLI closure, got %v", granted)
	}
	if slices.Contains(granted, "crypto/tls") || slices.Contains(granted, "net/url") || slices.Contains(granted, "context") {
		t.Errorf("the platform grant must stay narrower than the collector addition, got %v", granted)
	}
	for _, other := range []string{"internal/report", "internal/casefile", "internal/bundle"} {
		got := stdlibAllowlistFor(policy, other)
		if slices.Contains(got, "net") || slices.Contains(got, "net/http") {
			t.Errorf("%s must not be granted net or net/http, got %v", other, got)
		}
	}
	// Enumerate every local package of the CLI closure instead of trusting the
	// three names above: a new local package reached from cmd/ariadne must keep
	// the base list too. The enumeration is proven non-empty so the invariant
	// cannot pass vacuously.
	const modulePrefix = "github.com/d4rpell/Ariadne/"
	seenPlatform, seenOther := false, 0
	seen := map[string]bool{}
	for _, dep := range goListLines(t, "-deps", "-f", "{{.ImportPath}}", "../../cmd/ariadne") {
		if !strings.HasPrefix(dep, modulePrefix) {
			continue
		}
		relDir := strings.TrimPrefix(dep, modulePrefix)
		seen[relDir] = true
		if relDir == "internal/platform" {
			seenPlatform = true
			continue
		}
		seenOther++
		got := stdlibAllowlistFor(policy, relDir)
		if slices.Contains(got, "net") || slices.Contains(got, "net/http") {
			t.Errorf("local package %s of the CLI closure is granted net or net/http: %v", relDir, got)
		}
	}
	if !seenPlatform || seenOther == 0 {
		t.Fatalf("CLI closure enumeration is vacuous: platform=%v other=%d", seenPlatform, seenOther)
	}
	// Non-omission control: packages reached only through the subcommands (not
	// through a short prefix) must appear in the walk, so a filter regression
	// cannot silently shrink the enumerated set.
	for _, want := range []string{"internal/casefile", "internal/evaluator", "internal/bundle"} {
		if !seen[want] {
			t.Errorf("CLI closure enumeration omitted %s", want)
		}
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

// stdlibPath is a cheap shape test used only to route a direct import towards
// the allowlist check: the closure pass verifies the GOROOT location of every
// import, so this test never decides whether a package is standard library.
func stdlibPath(importPath string) bool {
	return importPath != "" && !strings.Contains(importPath, ".")
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
