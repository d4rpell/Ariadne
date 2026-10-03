package security

import (
	"errors"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"sort"
	"strconv"
	"strings"
	"testing"
)

// Static closure of local imports (ADR-0014).
//
// The two passes of TestImportBoundary see the active build graph and the direct
// imports of the protected package. Neither sees a forbidden import reached
// through an intermediate local package from a source file the active build
// excludes. This analyzer unions the imports of every local production source
// reachable from a protected root, without filtering by GOOS, GOARCH or build
// tags, and fails closed on anything it cannot resolve. False positives from
// mutually exclusive constraints are accepted on purpose: the union favours a
// reviewable rejection over a silently omitted path, and it never claims that
// every variant compiles or that any platform was executed.
//
// A policy never comes from a rule pack or from user configuration: the roots,
// the allowlist and the prohibitions are code of this reviewed test file, and the
// negative cases exercise this same function instead of a copy.

type closurePolicy struct {
	name   string
	dir    string
	core   bool
	strict bool
	exact  []string
	trees  []string
	// allowlist, when non-nil, replaces coreStdlibAllowlist for this policy. The
	// sanitized PodList adapter roots (ADR-0025 A.11.3) need a policy of their
	// own: the core list plus regexp and net/netip, without touching the
	// evaluator or pack-admission lists.
	allowlist []string
	// networkPackages lists the local package directories (module-relative,
	// slash-separated) whose own sources may use the network additions of the
	// collector profile. A helper reached from them keeps the adapter allowlist:
	// the network permission never propagates to another local package.
	networkPackages []string
	// bannedLocal are the package paths forbidden in the sources of every local
	// package of this closure, the root included. They are checked before any
	// allowlist branch, so a variant file or a local helper cannot smuggle them.
	bannedLocal []string
}

// adapterStdlibAllowlist is the independent policy of the sanitized PodList
// adapter roots (ADR-0025 A.11.3): the core list plus regexp (already used by
// the prisma-v1 ingestion for static patterns) and net/netip (required by the
// existing lexical composition of image references). It is not shared with, and
// does not modify, the evaluator or rulepack policies.
var adapterStdlibAllowlist = append(append([]string{}, coreStdlibAllowlist...), "regexp", "net/netip")

// collectorNetworkAdditions is the exact network addition of the collector
// profile (ADR-0026 A.4). It is a second, independent list: widening it never
// widens the adapter list and vice versa.
var collectorNetworkAdditions = []string{
	"context",
	"crypto/tls",
	"crypto/x509",
	"net",
	"net/http",
	"net/url",
}

// collectorStdlibAllowlist is the policy of internal/collector: a copy of the
// adapter list plus the network additions. Only the sources of that package
// receive it; a local helper reached from it keeps the adapter list.
var collectorStdlibAllowlist = append(append([]string{}, adapterStdlibAllowlist...), collectorNetworkAdditions...)

// connectorStdlibAllowlist is the policy of internal/prismaacquire (ADR-0028
// §3.4): the adapter list plus the same closed network addition, as a third,
// independent list. Widening it never widens the collector or adapter lists,
// and leaking the permission to a local helper is refused because it is granted
// per package in networkPackages.
var connectorStdlibAllowlist = append(append([]string{}, adapterStdlibAllowlist...), "context", "crypto/tls", "crypto/x509", "net", "net/http", "net/url")

// collectorBannedLocal is the closed set of package paths forbidden in the
// sources of every local package of the collector closure. It covers the
// process, filesystem, native and dynamic-loading surfaces the profile must
// never reach, plus the modules the collector must not depend on in either
// direction.
var collectorBannedLocal = []string{
	"os", "os/exec", "unsafe", "syscall", "plugin", "C",
	"github.com/d4rpell/Ariadne/internal/evaluator",
	"github.com/d4rpell/Ariadne/internal/rulepack",
	"github.com/d4rpell/Ariadne/internal/report",
	"github.com/d4rpell/Ariadne/internal/prismaacquire",
	"github.com/d4rpell/Ariadne/cmd/ariadne",
}

// connectorBannedLocal is the closed set of package paths forbidden in the
// sources of every local package of the connector closure (ADR-0028 §3.4): the
// process, filesystem, native and dynamic-loading surfaces, plus the modules
// the connector must not depend on in either direction (the Kubernetes
// collector and the domain packages it must stay outside of).
var connectorBannedLocal = []string{
	"os", "os/exec", "unsafe", "syscall", "plugin", "C",
	"github.com/d4rpell/Ariadne/internal/collector",
	"github.com/d4rpell/Ariadne/internal/evaluator",
	"github.com/d4rpell/Ariadne/internal/rulepack",
	"github.com/d4rpell/Ariadne/internal/report",
	"github.com/d4rpell/Ariadne/internal/bundle",
	"github.com/d4rpell/Ariadne/cmd/ariadne",
}

// offlineRootBannedLocal is the inverse prohibition of ADR-0026 A.4.1 for every
// root that must stay offline: none of the nine offline roots may reach the live
// collector or the Prisma API connector, directly or through a local helper. The
// prohibition lives in the real policies of those roots, not only in a synthetic
// control, so an accidental dependency on a network package fails the gate.
var offlineRootBannedLocal = []string{
	"github.com/d4rpell/Ariadne/internal/collector",
	"github.com/d4rpell/Ariadne/internal/prismaacquire",
}

// stdlibAllowlistFor selects the standard-library policy of one import inside
// one resolved local package. The policy depends on the package that performs
// the import, not only on the root: the additions of the collector profile are
// granted exclusively to the sources of internal/collector.
func stdlibAllowlistFor(policy closurePolicy, localPackage string) []string {
	if policy.core {
		return coreStdlibAllowlist
	}
	if policy.allowlist == nil {
		return nil
	}
	for _, granted := range policy.networkPackages {
		if localPackage == granted {
			return append(append([]string{}, policy.allowlist...), collectorNetworkAdditions...)
		}
	}
	return policy.allowlist
}

// localPackageFor converts a resolved absolute package directory into the
// module-relative slash-separated form stdlibAllowlistFor compares. A path
// outside the root keeps its absolute form, which matches no granted package.
func localPackageFor(root, absolute string) string {
	relative, err := filepath.Rel(root, absolute)
	if err != nil {
		return absolute
	}
	return filepath.ToSlash(relative)
}

// bannedLocalMatch reports the first banned local package the import path
// addresses, comparing whole path elements so "osx" is not mistaken for "os".
func bannedLocalMatch(importPath string, banned []string) string {
	for _, candidate := range banned {
		if importPath == candidate || strings.HasPrefix(importPath, candidate+"/") {
			return candidate
		}
	}
	return ""
}

// coreStdlibAllowlist is the only set of direct standard-library imports the
// evaluator and pack admission may reach, including through local packages. It
// does not make those APIs pure: clock reads, global output and impure
// operations are still review findings.
var coreStdlibAllowlist = []string{
	"bytes",
	"cmp",
	"crypto/sha256",
	"encoding/hex",
	"encoding/json",
	"errors",
	"fmt",
	"io",
	"math",
	"reflect",
	"slices",
	"sort",
	"strconv",
	"strings",
	"time",
	"unicode",
	"unicode/utf8",
}

// nativeExtensions make the initial profile unsupported: the closure covers Go
// sources and directives, not native code or link steps.
var nativeExtensions = []string{".s", ".S", ".c", ".cc", ".cpp", ".h", ".syso"}

type closureFinding struct {
	chain  string
	detail string
}

func (finding closureFinding) String() string {
	return finding.chain + ": " + finding.detail
}

type parsedSource struct {
	name       string
	pkg        string
	imports    []string
	directives []string
}

func moduleRoot(t *testing.T) string {
	t.Helper()
	root, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatalf("cannot resolve the module root: %v", err)
	}
	if _, err := os.Stat(filepath.Join(root, "go.mod")); err != nil {
		t.Fatalf("module root has no go.mod: %v", err)
	}
	return root
}

// analyzeClosure returns every finding of one protected root. An empty slice is
// the only passing result; the analysis never reports success from an empty
// graph.
func analyzeClosure(t *testing.T, root string, policy closurePolicy) []closureFinding {
	t.Helper()
	findings := []closureFinding{}
	modulePath, profileProblem := moduleProfile(root)
	if profileProblem != "" {
		return append(findings, closureFinding{chain: policy.name, detail: profileProblem})
	}
	// The directory probes above cannot see a workspace selected through the
	// environment: the toolchain's own answer decides, and an active workspace is
	// not supported by this profile.
	if workspace := effectiveWorkspace(t); workspace != "" {
		return append(findings, closureFinding{chain: policy.name, detail: "active workspace selected by the environment: " + workspace})
	}
	goroot := strings.TrimSpace(goEnvValue(t, "GOROOT"))
	if goroot == "" {
		return append(findings, closureFinding{chain: policy.name, detail: "GOROOT is not available"})
	}
	stdlibRoot := filepath.Join(goroot, "src")

	startDir, err := localDir(root, policy.dir)
	if err != nil {
		return append(findings, closureFinding{chain: policy.name, detail: err.Error()})
	}

	visited := map[string]bool{}
	chain := map[string]string{startDir: policy.name}
	edges := map[string][]string{}
	queue := []string{startDir}
	for len(queue) > 0 {
		dir := queue[0]
		queue = queue[1:]
		if visited[dir] {
			continue
		}
		visited[dir] = true

		if problem := nativeProblem(dir); problem != "" && (policy.core || policy.strict) {
			findings = append(findings, closureFinding{chain: chain[dir], detail: problem})
		}
		sources, problems := parseProductionSources(dir)
		for _, problem := range problems {
			findings = append(findings, closureFinding{chain: chain[dir], detail: problem})
		}
		if len(sources) == 0 {
			findings = append(findings, closureFinding{chain: chain[dir], detail: "package directory without production sources"})
			continue
		}
		for _, source := range sources {
			location := chain[dir] + "/" + source.name
			if policy.core || policy.strict {
				for _, directive := range source.directives {
					findings = append(findings, closureFinding{chain: location, detail: "unsupported directive: " + directive})
				}
			}
			// The local-package allowlist is selected by the package that performs
			// the import, so the network additions of the collector profile never
			// reach an intermediate helper.
			packageAllowlist := stdlibAllowlistFor(policy, localPackageFor(root, dir))
			for _, importPath := range source.imports {
				// The local prohibitions govern this package's own sources,
				// whatever their constraints: they are checked before the local
				// and standard-library branches, so no variant file and no
				// helper path can bypass them.
				if banned := bannedLocalMatch(importPath, policy.bannedLocal); banned != "" {
					findings = append(findings, closureFinding{chain: location, detail: "forbidden local package: " + banned})
					continue
				}
				switch {
				case importPath == modulePath || strings.HasPrefix(importPath, modulePath+"/"):
					target, err := localDir(root, strings.TrimPrefix(strings.TrimPrefix(importPath, modulePath), "/"))
					if err != nil {
						// The reason travels with the finding: a link, an escape or an
						// absent directory must be reviewable without a debugger.
						findings = append(findings, closureFinding{chain: location, detail: "unresolved local import " + importPath + ": " + err.Error()})
						continue
					}
					edges[dir] = append(edges[dir], target)
					if _, known := chain[target]; !known {
						chain[target] = location + " -> " + importPath
					}
					queue = append(queue, target)
				case isStdlib(stdlibRoot, importPath):
					if policy.core {
						if !slices.Contains(coreStdlibAllowlist, importPath) {
							findings = append(findings, closureFinding{chain: location, detail: "standard-library import outside the core allowlist: " + importPath})
						}
						continue
					}
					if packageAllowlist != nil {
						if !slices.Contains(packageAllowlist, importPath) {
							findings = append(findings, closureFinding{chain: location, detail: "standard-library import outside the adapter allowlist: " + importPath})
						}
						continue
					}
					if banned := forbiddenMatch(importPath, policy.exact, policy.trees); banned != "" {
						findings = append(findings, closureFinding{chain: location, detail: "forbidden standard-library import: " + importPath})
					}
				default:
					findings = append(findings, closureFinding{chain: location, detail: "external dependency is not supported by this profile: " + importPath})
				}
			}
		}
	}

	for _, cycle := range cycleChains(edges, chain) {
		findings = append(findings, closureFinding{chain: cycle, detail: "import cycle in the union graph"})
	}
	sort.Slice(findings, func(i, j int) bool {
		if findings[i].chain != findings[j].chain {
			return findings[i].chain < findings[j].chain
		}
		return findings[i].detail < findings[j].detail
	})
	return findings
}

// moduleProfile reads the module path and refuses any arrangement the initial
// profile does not support: another directive, a required or replaced module, a
// vendor directory, a nested module or an active workspace.
func moduleProfile(root string) (string, string) {
	data, err := os.ReadFile(filepath.Join(root, "go.mod"))
	if err != nil {
		return "", "module root has no readable go.mod"
	}
	modulePath := ""
	for _, line := range strings.Split(string(data), "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "//") {
			continue
		}
		fields := strings.Fields(trimmed)
		switch fields[0] {
		case "module":
			if len(fields) < 2 {
				return "", "go.mod declares no module path"
			}
			modulePath = fields[1]
		case "go", "toolchain":
		default:
			return "", "unsupported go.mod directive: " + fields[0]
		}
	}
	if modulePath == "" {
		return "", "go.mod declares no module path"
	}

	problem := ""
	walkErr := filepath.WalkDir(root, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			problem = "cannot inspect the module tree"
			return fs.SkipAll
		}
		if entry.IsDir() {
			switch entry.Name() {
			case ".git":
				return fs.SkipDir
			case "vendor":
				problem = "vendored sources are not supported"
				return fs.SkipAll
			}
			return nil
		}
		switch {
		case entry.Name() == "go.mod" && filepath.Dir(path) != root:
			problem = "nested module: " + path
			return fs.SkipAll
		case entry.Name() == "go.work":
			problem = "workspace file inside the module: " + path
			return fs.SkipAll
		}
		return nil
	})
	if walkErr != nil && problem == "" {
		problem = "cannot inspect the module tree"
	}
	if problem != "" {
		return "", problem
	}
	if workspace := workspaceAbove(root); workspace != "" {
		return "", "active workspace above the module: " + workspace
	}
	return modulePath, ""
}

// effectiveWorkspace is the workspace the toolchain would use, which may differ
// from any go.work found next to the module.
func effectiveWorkspace(t *testing.T) string {
	t.Helper()
	value := strings.TrimSpace(goEnvValue(t, "GOWORK"))
	if value == "" || value == "off" {
		return ""
	}
	return value
}

func workspaceAbove(root string) string {
	dir := filepath.Dir(root)
	for depth := 0; depth < 8; depth++ {
		if _, err := os.Stat(filepath.Join(dir, "go.work")); err == nil {
			return filepath.Join(dir, "go.work")
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return ""
		}
		dir = parent
	}
	return ""
}

// localDir resolves a module-relative path inside the root, refusing escapes,
// absent directories and any path that crosses a symlink or reparse point.
func localDir(root, relative string) (string, error) {
	if relative == "" {
		return "", errors.New("ambiguous local path: empty")
	}
	if strings.HasPrefix(relative, "/") || strings.HasPrefix(relative, `\`) || strings.Contains(relative, "\\") {
		return "", errors.New("ambiguous local path: " + relative)
	}
	cleaned := filepath.Clean(filepath.FromSlash(relative))
	if cleaned == "." || strings.HasPrefix(cleaned, "..") {
		return "", errors.New("ambiguous local path: " + relative)
	}
	absolute := filepath.Join(root, cleaned)
	if !strings.HasPrefix(absolute, root+string(os.PathSeparator)) {
		return "", errors.New("path escapes the module root: " + relative)
	}
	info, err := os.Stat(absolute)
	if err != nil {
		return "", errors.New("local path does not exist: " + relative)
	}
	if !info.IsDir() {
		return "", errors.New("local path is not a directory: " + relative)
	}
	if problem := symlinkProblem(root, absolute); problem != "" {
		return "", errors.New(problem)
	}
	return absolute, nil
}

func symlinkProblem(root, absolute string) string {
	current := root
	relative, err := filepath.Rel(root, absolute)
	if err != nil {
		return "unresolvable path: " + absolute
	}
	for _, element := range strings.Split(relative, string(os.PathSeparator)) {
		current = filepath.Join(current, element)
		info, err := os.Lstat(current)
		if err != nil {
			return "unreadable path element: " + current
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return "path crosses a symlink or reparse point: " + current
		}
	}
	return ""
}

func nativeProblem(dir string) string {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return "cannot read package directory"
	}
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		if slices.Contains(nativeExtensions, filepath.Ext(entry.Name())) {
			return "native or linked source is not supported by this profile: " + entry.Name()
		}
	}
	return ""
}

func parseProductionSources(dir string) ([]parsedSource, []string) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, []string{"cannot read package directory"}
	}
	var sources []parsedSource
	var problems []string
	packages := map[string]bool{}
	fset := token.NewFileSet()
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		// A linked file would be read from outside the tree: the profile refuses
		// it instead of analysing a source that is not the one in the package.
		if entry.Type()&fs.ModeSymlink != 0 {
			problems = append(problems, "linked source is not supported by this profile: "+name)
			continue
		}
		parsed, err := parser.ParseFile(fset, filepath.Join(dir, name), nil, parser.ParseComments)
		if err != nil {
			problems = append(problems, "unparseable production source: "+name)
			continue
		}
		source := parsedSource{name: name, pkg: parsed.Name.Name}
		for _, spec := range parsed.Imports {
			path, err := strconv.Unquote(spec.Path.Value)
			if err != nil {
				problems = append(problems, "unquoteable import in "+name)
				continue
			}
			source.imports = append(source.imports, path)
		}
		for _, group := range parsed.Comments {
			for _, comment := range group.List {
				switch {
				case strings.HasPrefix(comment.Text, "//go:linkname"):
					source.directives = append(source.directives, "go:linkname")
				case strings.HasPrefix(comment.Text, "//go:embed"):
					source.directives = append(source.directives, "go:embed")
				}
			}
		}
		packages[source.pkg] = true
		sources = append(sources, source)
	}
	if len(packages) > 1 {
		problems = append(problems, "unresolvable package name mix")
	}
	sort.Slice(sources, func(i, j int) bool { return sources[i].name < sources[j].name })
	return sources, problems
}

// isStdlib recognises the standard library by its verified location under
// GOROOT/src, never by the shape of its path.
func isStdlib(stdlibRoot, importPath string) bool {
	if importPath == "" || strings.Contains(importPath, ".") {
		return false
	}
	info, err := os.Stat(filepath.Join(stdlibRoot, filepath.FromSlash(importPath)))
	return err == nil && info.IsDir()
}

// cycleChains reports the strongly connected leftovers of the union graph in a
// deterministic order: a cycle is an analysis error, even when the union created
// one that no single build could compile.
func cycleChains(edges map[string][]string, chain map[string]string) []string {
	indegree := map[string]int{}
	for dir := range chain {
		if _, known := indegree[dir]; !known {
			indegree[dir] = 0
		}
	}
	for from, targets := range edges {
		for _, target := range targets {
			indegree[target]++
			if _, known := indegree[from]; !known {
				indegree[from] = 0
			}
		}
	}
	ready := []string{}
	for dir, degree := range indegree {
		if degree == 0 {
			ready = append(ready, dir)
		}
	}
	sort.Strings(ready)
	processed := map[string]bool{}
	for len(ready) > 0 {
		dir := ready[0]
		ready = ready[1:]
		processed[dir] = true
		targets := append([]string{}, edges[dir]...)
		sort.Strings(targets)
		for _, target := range targets {
			indegree[target]--
			if indegree[target] == 0 {
				ready = append(ready, target)
				sort.Strings(ready)
			}
		}
	}
	var cycles []string
	for dir := range indegree {
		if !processed[dir] {
			cycles = append(cycles, chain[dir])
		}
	}
	sort.Strings(cycles)
	return cycles
}

func goEnvValue(t *testing.T, name string) string {
	t.Helper()
	command := exec.Command("go", "env", name)
	command.Env = append(os.Environ(), "GOPROXY=off", "GOSUMDB=off", "GOFLAGS=-mod=readonly")
	out, err := command.Output()
	if err != nil {
		t.Fatalf("go env %s failed: %v", name, err)
	}
	return string(out)
}
