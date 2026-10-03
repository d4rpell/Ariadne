package prismaacquire

import (
	"context"
	"net/http"
	"testing"
)

// Incremento 7 de A2-08-F2: construcción y guarda final de peticiones
// (ADR-0028 §4.5, §6.5–§6.6, §7.4).

func f2Acquirer(cfg AcquisitionConfig) *acquirer {
	return &acquirer{
		ctx:       context.Background(),
		cfg:       cfg,
		origin:    "https://prisma.example.test:8443",
		authority: "prisma.example.test:8443",
		token:     "synthetic.token",
	}
}

func TestA208F2RequestAllowlist(t *testing.T) {
	a := f2Acquirer(f2Config())
	query := a.imageQuery(50)
	want := map[string]string{
		"offset": "50", "limit": "50", "compact": "false",
		"normalizedSeverity": "false", "layers": "false", "filterBaseImage": "false",
		"project": "proj_1",
	}
	if len(query) != len(want) {
		t.Fatalf("query has %d parameters, want %d: %v", len(query), len(want), query)
	}
	for key, value := range want {
		if query.Get(key) != value {
			t.Fatalf("query %s = %q, want %q", key, query.Get(key), value)
		}
	}

	single := f2Config()
	single.ScopeMode = ScopeSingleTenant
	single.Project = ""
	single.ScopeAlias = nil
	if _, ok := f2Acquirer(single).imageQuery(0)["project"]; ok {
		t.Fatal("single_tenant_declared query carries a project parameter")
	}
}

func TestA208F2RequestHeaders(t *testing.T) {
	a := f2Acquirer(f2Config())
	req, err := a.buildImageRequest(0)
	if err != nil {
		t.Fatalf("buildImageRequest: %v", err)
	}
	if req.Method != http.MethodGet || req.Body != nil {
		t.Fatal("GET must have no body")
	}
	if req.Header.Get("Accept") != "application/json" ||
		req.Header.Get("Accept-Encoding") != "identity" ||
		req.Header.Get("User-Agent") != userAgent ||
		req.Header.Get("Authorization") != "Bearer synthetic.token" {
		t.Fatalf("unexpected GET headers: %v", req.Header)
	}
	if req.Header.Get("Content-Type") != "" {
		t.Fatal("GET carries a Content-Type")
	}
	if err := a.guardRequest(req, http.MethodGet, imagesPath, true); err != nil {
		t.Fatalf("valid GET rejected by the guard: %v", err)
	}

	post, err := a.buildAuthRequest([]byte(`{"username":"u","password":"p"}`))
	if err != nil {
		t.Fatalf("buildAuthRequest: %v", err)
	}
	if post.Header.Get("Authorization") != "" {
		t.Fatal("POST carries a bearer")
	}
	if post.Header.Get("Content-Type") != "application/json" {
		t.Fatal("POST lacks its Content-Type")
	}
	// The authentication POST is only admitted in password_exchange, before the
	// token exists; the guard verifies the authentication state of the sequence.
	postAcq := f2Acquirer(f2Config())
	postAcq.cfg.AuthMode = AuthPasswordExchange
	postAcq.token = ""
	if err := postAcq.guardRequest(post, http.MethodPost, authenticatePath, false); err != nil {
		t.Fatalf("valid POST rejected by the guard: %v", err)
	}
	if err := a.guardRequest(post, http.MethodPost, authenticatePath, false); err == nil || err.Code != CodeRequestNotAllowed {
		t.Fatalf("a POST from a bearer sequence: err = %v, want %s", err, CodeRequestNotAllowed)
	}
}

func TestA208F2RequestGuardBeforeTransport(t *testing.T) {
	a := f2Acquirer(f2Config())
	req, _ := a.buildImageRequest(0)
	req.URL.Path = "/api/v34.04/other"
	if err := a.guardRequest(req, http.MethodGet, imagesPath, true); err == nil || err.Code != CodeRequestNotAllowed {
		t.Fatalf("wrong path: err = %v, want %s", err, CodeRequestNotAllowed)
	}

	req, _ = a.buildImageRequest(0)
	req.Method = http.MethodPost
	if err := a.guardRequest(req, http.MethodGet, imagesPath, true); err == nil || err.Code != CodeRequestNotAllowed {
		t.Fatalf("wrong method: err = %v, want %s", err, CodeRequestNotAllowed)
	}

	req, _ = a.buildImageRequest(0)
	req.Header.Set("X-Injected", "1")
	if err := a.guardRequest(req, http.MethodGet, imagesPath, true); err == nil || err.Code != CodeRequestNotAllowed {
		t.Fatalf("extra header: err = %v, want %s", err, CodeRequestNotAllowed)
	}

	// A locally rejected request must not consume an HTTP attempt.
	script := f2Steps("[]")
	cfg := f2Config()
	cfg.ScopeMode = ScopeProjectSelect
	acq := f2Acquirer(cfg)
	before := script.requestCount()
	if err := acq.guardRequest(req, http.MethodGet, imagesPath, true); err == nil {
		t.Fatal("injected header was accepted")
	}
	if script.requestCount() != before {
		t.Fatal("a rejected request reached the transport")
	}
}
