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

// Registry-image family boundary of ADR-0029. Two properties are enforced here:
// the registry JSON profile must reuse the single shared admission seam (no
// second parser), and the network connector root must not acquire registry
// reports (the registry family is offline-only).

// TestRegistryUsesSharedAdmission asserts the registry entry file calls the
// shared admitNativeJSON seam and imports neither encoding/json nor encoding/csv.
func TestRegistryUsesSharedAdmission(t *testing.T) {
	dir := goListDir(t, "github.com/d4rpell/Ariadne/internal/ingest")
	path := filepath.Join(dir, "prisma_registry.go")
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, path, nil, 0)
	if err != nil {
		t.Fatalf("parse %s: %v", path, err)
	}
	for _, imp := range file.Imports {
		p, _ := strconv.Unquote(imp.Path.Value)
		if p == "encoding/json" || p == "encoding/csv" {
			t.Fatalf("registry entry imports %q", p)
		}
	}
	callsShared := false
	ast.Inspect(file, func(n ast.Node) bool {
		if call, ok := n.(*ast.CallExpr); ok {
			if id, ok := call.Fun.(*ast.Ident); ok && id.Name == "admitNativeJSON" {
				callsShared = true
			}
		}
		return true
	})
	if !callsShared {
		t.Fatal("registry entry does not call the shared admitNativeJSON")
	}
}

// TestConnectorDoesNotAcquireRegistry asserts no source under the network
// connector root references a registry selector: registry acquisition is a
// separate, future review and is not part of the connector.
func TestConnectorDoesNotAcquireRegistry(t *testing.T) {
	dir := goListDir(t, "github.com/d4rpell/Ariadne/internal/prismaacquire")
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read %s: %v", dir, err)
	}
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".go") {
			continue
		}
		b, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			t.Fatalf("read %s: %v", e.Name(), err)
		}
		if strings.Contains(string(b), "prisma-native-registry") {
			t.Fatalf("connector file %s references a registry selector", e.Name())
		}
	}
}
