package prismaacquire

import (
	"strings"
	"testing"
	"time"
)

func validConfig() AcquisitionConfig {
	alias := "scope-a"
	return AcquisitionConfig{
		Selector:      AcquisitionSelector,
		Version:       AcquisitionVersion,
		Profile:       AcquisitionProfile,
		OriginAlias:   "origin-a",
		Edition:       DeclaredEdition,
		Release:       DeclaredRelease,
		Endpoint:      "https://prisma.example.test:8443",
		CA:            []byte("ca"),
		ScopeMode:     ScopeProjectSelect,
		Project:       "proj_1",
		ScopeAlias:    &alias,
		AuthMode:      AuthBearerSupplied,
		CredentialRef: "cred-1",
		DataPolicyAck: requiredDataPolicyAck,
	}
}

func TestA208F2ConfigBeforeCredentialsAndNetwork(t *testing.T) {
	base := validConfig()
	if err := validateConfig(base); err != nil {
		t.Fatalf("valid config rejected: %v", err)
	}
	cases := []struct {
		name string
		mut  func(*AcquisitionConfig)
		code string
	}{
		{"empty_selector", func(c *AcquisitionConfig) { c.Selector = "" }, CodeInvalidConfig},
		{"wrong_selector", func(c *AcquisitionConfig) { c.Selector = "other" }, CodeUnsupportedProfile},
		{"wrong_version", func(c *AcquisitionConfig) { c.Version = "2.0" }, CodeUnsupportedProfile},
		{"wrong_edition", func(c *AcquisitionConfig) { c.Edition = "saas" }, CodeUnsupportedProfile},
		{"wrong_release", func(c *AcquisitionConfig) { c.Release = "1.0" }, CodeUnsupportedProfile},
		{"http_endpoint", func(c *AcquisitionConfig) { c.Endpoint = "http://prisma.example.test:8443" }, CodeInvalidConfig},
		{"missing_port", func(c *AcquisitionConfig) { c.Endpoint = "https://prisma.example.test" }, CodeInvalidConfig},
		{"path_prefix", func(c *AcquisitionConfig) { c.Endpoint = "https://prisma.example.test:8443/api" }, CodeInvalidConfig},
		{"with_query", func(c *AcquisitionConfig) { c.Endpoint = "https://prisma.example.test:8443/?a=1" }, CodeInvalidConfig},
		{"with_userinfo", func(c *AcquisitionConfig) { c.Endpoint = "https://u:p@prisma.example.test:8443" }, CodeInvalidConfig},
		{"empty_ca", func(c *AcquisitionConfig) { c.CA = nil }, CodeTLSConfigInvalid},
		{"empty_origin", func(c *AcquisitionConfig) { c.OriginAlias = "" }, CodeInvalidConfig},
		{"bad_ack", func(c *AcquisitionConfig) { c.DataPolicyAck = "no" }, CodeInvalidConfig},
		{"bad_scope", func(c *AcquisitionConfig) { c.ScopeMode = "all_projects" }, CodeInvalidConfig},
		{"project_without_alias", func(c *AcquisitionConfig) { c.ScopeAlias = nil }, CodeInvalidConfig},
		{"bad_project", func(c *AcquisitionConfig) { c.Project = "-bad" }, CodeInvalidConfig},
		{"single_tenant_with_project", func(c *AcquisitionConfig) { c.ScopeMode = ScopeSingleTenant }, CodeInvalidConfig},
		{"bad_auth", func(c *AcquisitionConfig) { c.AuthMode = "basic" }, CodeUnsupportedAuth},
		{"empty_ref", func(c *AcquisitionConfig) { c.CredentialRef = "" }, CodeInvalidConfig},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := base
			tc.mut(&c)
			err := validateConfig(c)
			if err == nil || err.Code != tc.code {
				t.Fatalf("err = %v, want %s", err, tc.code)
			}
		})
	}
}

func TestA208F2CredentialValidation(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	base := validConfig()
	good := Credential{Reference: "cred-1", Token: "abc.DEF-123_~+/="}
	if err := validateCredential(base, good, now); err != nil {
		t.Fatalf("valid bearer rejected: %v", err)
	}
	mismatch := good
	mismatch.Reference = "other"
	if err := validateCredential(base, mismatch, now); err == nil || err.Code != CodeCredentialReferenceMismatch {
		t.Fatalf("mismatch err = %v", err)
	}
	empty := good
	empty.Token = ""
	if err := validateCredential(base, empty, now); err == nil || err.Code != CodeCredentialUnavailable {
		t.Fatalf("empty token err = %v", err)
	}
	spaced := good
	spaced.Token = "abc def"
	if err := validateCredential(base, spaced, now); err == nil || err.Code != CodeInvalidConfig {
		t.Fatalf("spaced token err = %v", err)
	}
	oversized := good
	oversized.Token = strings.Repeat("a", maxTokenBytes+1)
	if err := validateCredential(base, oversized, now); err == nil || err.Code != CodeInvalidConfig {
		t.Fatalf("oversized token err = %v", err)
	}
	expired := base
	at := now.Add(-time.Second)
	expired.TokenExpiresAt = &at
	if err := validateCredential(expired, good, now); err == nil || err.Code != CodeCredentialExpired {
		t.Fatalf("expired err = %v", err)
	}
}

func TestA208F2ProjectGrammar(t *testing.T) {
	valid := []string{"a", "A0", "proj_1", "a.b-c_9", strings.Repeat("a", 128)}
	for _, p := range valid {
		if !validProjectID(p) {
			t.Fatalf("project %q rejected", p)
		}
	}
	invalid := []string{"", "-a", "_a", ".a", "a/b", "a b", strings.Repeat("a", 129)}
	for _, p := range invalid {
		if validProjectID(p) {
			t.Fatalf("project %q accepted", p)
		}
	}
}
