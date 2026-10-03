package security

import (
	"go/parser"
	"go/token"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// TestPrismaNativeReaderImplementationBoundary enforces ADR-0027 §6.1 and §13.4:
// the prisma-native adapters must not use encoding/json or encoding/csv as
// decoders, must not reach the network, a shell, a filesystem or the collector,
// and must not depend on external modules.
func TestPrismaNativeReaderImplementationBoundary(t *testing.T) {
	forbidden := map[string]string{
		"encoding/json":    "general JSON decoder is not allowed in native paths",
		"encoding/csv":     "general CSV decoder is not allowed in native paths",
		"net":              "network access is not allowed in offline adapters",
		"net/http":         "network access is not allowed in offline adapters",
		"os":               "system access is not allowed in offline adapters",
		"os/exec":          "shell execution is not allowed",
		"k8s.io/client-go": "cluster client is not allowed in offline adapters",
		"github.com/d4rpell/Ariadne/internal/collector": "collector dependency is not allowed",
		"github.com/d4rpell/Ariadne/internal/rulepack":  "rulepack dependency is not allowed",
	}
	files := []string{
		filepath.Join("..", "schema", "prisma_native.go"),
		filepath.Join("..", "ingest", "prisma_native_context.go"),
		filepath.Join("..", "ingest", "prisma_native_diagnostic.go"),
		filepath.Join("..", "ingest", "prisma_native_source.go"),
		filepath.Join("..", "ingest", "prisma_native_json.go"),
		filepath.Join("..", "ingest", "prisma_native_csv.go"),
		filepath.Join("..", "ingest", "prisma_native_read.go"),
		filepath.Join("..", "ingest", "prisma_native_replay.go"),
		filepath.Join("..", "normalize", "prisma_native.go"),
		filepath.Join("..", "normalize", "prisma_native_cvss.go"),
		filepath.Join("..", "normalize", "prisma_native_time.go"),
		filepath.Join("..", "normalize", "prisma_native_inventory.go"),
	}
	fset := token.NewFileSet()
	for _, file := range files {
		parsed, err := parser.ParseFile(fset, file, nil, parser.ImportsOnly)
		if err != nil {
			t.Fatalf("parse %s: %v", file, err)
		}
		for _, spec := range parsed.Imports {
			importPath, err := strconv.Unquote(spec.Path.Value)
			if err != nil {
				t.Fatalf("unquote import in %s: %v", file, err)
			}
			for prefix, reason := range forbidden {
				if importPath == prefix || strings.HasPrefix(importPath, prefix+"/") {
					t.Fatalf("%s imports %q: %s", file, importPath, reason)
				}
			}
			if !nativeAllowedImport(importPath) {
				t.Fatalf("%s imports external module %q", file, importPath)
			}
		}
	}
}

// nativeAllowedImport admits the standard library and this module's own
// packages, rejecting any external module (ADR-0027 §6.1/§13.4).
func nativeAllowedImport(importPath string) bool {
	first := importPath
	if i := strings.IndexByte(importPath, '/'); i >= 0 {
		first = importPath[:i]
	}
	if !strings.Contains(first, ".") {
		return true // standard library
	}
	return strings.HasPrefix(importPath, "github.com/d4rpell/Ariadne/")
}
