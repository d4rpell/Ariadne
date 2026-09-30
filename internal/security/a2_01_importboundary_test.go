package security

import (
	"slices"
	"testing"
)

// A2-01 import-boundary rows of the execution plan (handoff §4.1, I-27):
// the four adapter roots of ADR-0025 A.11.3 must stay declared with the
// independent allowlist, and the core policies must not be widened.

func TestA201ImportBoundaryRoots(t *testing.T) {
	declared := map[string]boundaryDeclaration{}
	for _, boundary := range importBoundaries {
		declared[boundary.name] = boundary
	}
	for _, name := range []string{"ingest", "normalize", "identity", "bundle"} {
		boundary, present := declared[name]
		if !present {
			t.Fatalf("adapter root %q is no longer declared", name)
		}
		if !boundary.strict {
			t.Fatalf("adapter root %q must stay strict", name)
		}
		for _, forbidden := range []string{"net", "os", "os/exec", "plugin", "unsafe", "syscall"} {
			if !slices.Contains(boundary.exact, forbidden) {
				t.Fatalf("adapter root %q no longer forbids %q", name, forbidden)
			}
		}
		for _, forbidden := range []string{"net/http", "k8s.io/client-go"} {
			if !slices.Contains(boundary.trees, forbidden) {
				t.Fatalf("adapter root %q no longer forbids the %q tree", name, forbidden)
			}
		}
	}
	// The four pre-existing roots keep their declaration: the adapter must not
	// have replaced or relaxed them.
	for _, name := range []string{"evaluator", "rulepack", "report", "cli"} {
		if _, present := declared[name]; !present {
			t.Fatalf("pre-existing root %q disappeared", name)
		}
	}
	if len(importBoundaries) != 8 {
		t.Fatalf("importBoundaries has %d entries, want eight", len(importBoundaries))
	}
}

func TestA201ImportBoundaryPolicies(t *testing.T) {
	for _, name := range []string{"ingest", "normalize", "identity", "bundle"} {
		policy := allowlistFor(boundaryDeclaration{name: name})
		if policy == nil {
			t.Fatalf("adapter root %q must select the adapter allowlist", name)
		}
		if !slices.Contains(policy, "regexp") {
			t.Fatalf("adapter allowlist of %q lost regexp, required by the existing prisma-v1 validation", name)
		}
		if !slices.Contains(policy, "net/netip") {
			t.Fatalf("adapter allowlist of %q lost net/netip, required by the image composition", name)
		}
	}
	// The core policy stays untouched: neither addition may leak into it.
	for _, leaks := range []string{"regexp", "net/netip"} {
		if slices.Contains(coreStdlibAllowlist, leaks) {
			t.Fatalf("the core allowlist gained %q: the evaluator and rulepack policies must not be widened", leaks)
		}
	}
	for _, name := range []string{"evaluator", "rulepack", "report", "cli"} {
		if policy := allowlistFor(boundaryDeclaration{name: name}); policy != nil {
			t.Fatalf("%s must keep the core policy, got a replacement allowlist", name)
		}
	}
}

func TestA201ImportBoundaryControls(t *testing.T) {
	// The adapter allowlist is exactly the core list plus the two documented
	// additions: a third addition would be a policy change nobody reviewed.
	extra := []string{}
	for _, entry := range adapterStdlibAllowlist {
		if !slices.Contains(coreStdlibAllowlist, entry) {
			extra = append(extra, entry)
		}
	}
	slices.Sort(extra)
	if !slices.Equal(extra, []string{"net/netip", "regexp"}) {
		t.Fatalf("adapter allowlist additions = %v, want exactly [net/netip regexp]", extra)
	}
	if len(adapterStdlibAllowlist) != len(coreStdlibAllowlist)+2 {
		t.Fatalf("adapter allowlist has %d entries, want core+2", len(adapterStdlibAllowlist))
	}
	// A forbidden import is still matched by the same helper the gate uses.
	if path := forbiddenMatch("os/exec", []string{"os", "os/exec"}, nil); path != "os/exec" {
		t.Fatalf("forbiddenMatch lost the os/exec prohibition: %q", path)
	}
	if path := forbiddenMatch("net/http", nil, []string{"net/http"}); path != "net/http" {
		t.Fatalf("forbiddenMatch lost the net/http tree prohibition: %q", path)
	}
}
