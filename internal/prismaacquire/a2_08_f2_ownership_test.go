package prismaacquire

import (
	"strings"
	"testing"
)

// Incrementos 8 y 10 de A2-08-F2: propiedad y privacidad (ADR-0028 §3.6, §5.9,
// §9.6, §12). Los marcadores sintéticos de token, proyecto y endpoint no deben
// aparecer en artefactos, diagnósticos ni representaciones del resultado.

func TestA208F2SecretMarkersAbsent(t *testing.T) {
	const (
		tokenMarker  = "MARKER_TOKEN_7f3a"
		projectMark  = "MARKER_PROJECT_b21"
		endpointHost = "marker-host.example.test"
	)
	alias := "scope-a"
	cfg := f2Config()
	cfg.OriginAlias = "origin-a"
	cfg.Endpoint = "https://" + endpointHost + ":8443"
	cfg.Project = projectMark
	cfg.ScopeAlias = &alias
	cred := Credential{Reference: "cred-1", Token: tokenMarker}

	script := f2Steps(f2DistinctPage(0, 2), "[]")
	result, err := f2Run(t, cfg, cred, script)
	if err != nil {
		t.Fatalf("sequence failed: %v", err)
	}

	var out strings.Builder
	for _, page := range result.Pages {
		out.Write(page.Artifacts.Source)
		out.Write(page.Artifacts.Manifest)
		out.Write(page.Artifacts.Digest)
	}
	for _, diagnostic := range result.Diagnostics {
		out.WriteString(diagnostic.Error())
	}
	out.WriteString(result.OriginAlias)
	if result.ScopeAlias != nil {
		out.WriteString(*result.ScopeAlias)
	}
	rendered := out.String()
	for _, marker := range []string{tokenMarker, projectMark, endpointHost, cred.Password} {
		if marker == "" {
			continue
		}
		if strings.Contains(rendered, marker) {
			t.Fatalf("marker %q leaked into the result", marker)
		}
	}
}

func TestA208F2ResultOwnership(t *testing.T) {
	alias := "scope-a"
	cfg := f2Config()
	cfg.ScopeAlias = &alias
	result, err := f2Run(t, cfg, f2Bearer(), f2Steps("[]"))
	if err != nil {
		t.Fatalf("sequence failed: %v", err)
	}
	alias = "mutated-after-run"
	if result.ScopeAlias == nil || *result.ScopeAlias != "scope-a" {
		t.Fatalf("result scope alias = %v, want the value captured at run time", result.ScopeAlias)
	}
}

func TestA208F2NewRunStartsAtZero(t *testing.T) {
	first, err := f2Run(t, f2Config(), f2Bearer(), f2Steps(f2DistinctPage(0, 4), "[]"))
	if err != nil {
		t.Fatalf("first run failed: %v", err)
	}
	second, err := f2Run(t, f2Config(), f2Bearer(), f2Steps("[]"))
	if err != nil {
		t.Fatalf("second run failed: %v", err)
	}
	if first.Attempts.Total == second.Attempts.Total {
		t.Fatal("a new run inherited counters from the previous one")
	}
	if second.Pages[0].Offset != 0 || len(second.Pages) != 1 {
		t.Fatalf("second run did not start at offset 0 with one page")
	}
}
