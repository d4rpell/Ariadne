package collector

import (
	"context"
	"net/http"
	"strings"
	"testing"

	"github.com/d4rpell/Ariadne/internal/bundle"
)

// Request-guard cases of the A2-02 plan (handoff §4.2 row "Guarda de request").
// Every forbidden action is refused before the transport: the guard is the only
// component that decides what may reach the network.

func TestA202RequestGuard(t *testing.T) {
	config := a202Config(t)
	validated, err := validateConfig(config)
	if err != nil {
		t.Fatalf("validateConfig: %v", err)
	}

	t.Run("allowed_list", func(t *testing.T) {
		request, err := newRequest(context.Background(), validated, operationSpec{verb: "list", namespace: a202Namespace})
		if err != nil {
			t.Fatalf("allowed list refused: %v", err)
		}
		if request.URL.Path != "/api/v1/namespaces/payments/pods" {
			t.Fatalf("path = %q", request.URL.Path)
		}
		query := request.URL.Query()
		if query.Get("limit") != "100" || len(query) != 1 {
			t.Fatalf("query = %v", query)
		}
	})
	t.Run("allowed_get", func(t *testing.T) {
		request, err := newRequest(context.Background(), validated, operationSpec{verb: "get", namespace: a202Namespace, name: "api-0"})
		if err != nil {
			t.Fatalf("allowed get refused: %v", err)
		}
		if request.URL.Path != "/api/v1/namespaces/payments/pods/api-0" || request.URL.RawQuery != "" {
			t.Fatalf("get request = %s?%s", request.URL.Path, request.URL.RawQuery)
		}
	})
	for _, method := range []string{http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete} {
		t.Run("mutating_verbs/"+method, func(t *testing.T) {
			// The operation specification only knows get and list: a mutation
			// cannot even be described, and the guard refuses the shape.
			request, _ := http.NewRequest(method, "https://synthetic.example:6443/api/v1/namespaces/payments/pods", nil)
			if err := validateRequest(request, validated, operationSpec{verb: "get", namespace: a202Namespace, name: "api-0"}); err == nil {
				t.Fatalf("%s was admitted", method)
			}
		})
	}
	t.Run("watch", func(t *testing.T) {
		request, _ := http.NewRequest(http.MethodGet, "https://synthetic.example:6443/api/v1/namespaces/payments/pods?watch=true&limit=100", nil)
		if err := validateRequest(request, validated, operationSpec{verb: "list", namespace: a202Namespace}); err == nil {
			t.Fatal("a watch query was admitted")
		}
	})
	t.Run("global_list", func(t *testing.T) {
		request, _ := http.NewRequest(http.MethodGet, "https://synthetic.example:6443/api/v1/pods?limit=100", nil)
		if err := validateRequest(request, validated, operationSpec{verb: "list", namespace: a202Namespace}); err == nil {
			t.Fatal("a global list was admitted")
		}
	})
	for _, subresource := range []string{"log", "exec", "attach", "portforward", "proxy", "status"} {
		t.Run("each_subresource/"+subresource, func(t *testing.T) {
			request, _ := http.NewRequest(http.MethodGet, "https://synthetic.example:6443/api/v1/namespaces/payments/pods/api-0/"+subresource, nil)
			if err := validateRequest(request, validated, operationSpec{verb: "get", namespace: a202Namespace, name: "api-0"}); err == nil {
				t.Fatalf("subresource %q was admitted", subresource)
			}
		})
	}
	resources := map[string]string{
		"secrets":              "/api/v1/namespaces/payments/secrets",
		"configmaps":           "/api/v1/namespaces/payments/configmaps",
		"nodes":                "/api/v1/nodes",
		"deployments":          "/apis/apps/v1/namespaces/payments/deployments",
		"namespaces":           "/api/v1/namespaces",
		"authorization_review": "/apis/authorization.k8s.io/v1/selfsubjectaccessreviews",
	}
	for name, path := range resources {
		t.Run("each_forbidden_resource/"+name, func(t *testing.T) {
			request, _ := http.NewRequest(http.MethodGet, "https://synthetic.example:6443"+path, nil)
			if err := validateRequest(request, validated, operationSpec{verb: "list", namespace: a202Namespace}); err == nil {
				t.Fatalf("resource %q was admitted", path)
			}
		})
	}
	for _, discovery := range []string{"/api", "/apis", "/version"} {
		t.Run("discovery/"+strings.TrimPrefix(discovery, "/"), func(t *testing.T) {
			request, _ := http.NewRequest(http.MethodGet, "https://synthetic.example:6443"+discovery, nil)
			if err := validateRequest(request, validated, operationSpec{verb: "list", namespace: a202Namespace}); err == nil {
				t.Fatalf("discovery endpoint %q was admitted", discovery)
			}
		})
	}
	t.Run("host_mismatch", func(t *testing.T) {
		request, _ := http.NewRequest(http.MethodGet, "https://other.example:6443/api/v1/namespaces/payments/pods?limit=100", nil)
		if err := validateRequest(request, validated, operationSpec{verb: "list", namespace: a202Namespace}); err == nil {
			t.Fatal("a request for another authority was admitted")
		}
	})
	t.Run("path_escape/dot_segments", func(t *testing.T) {
		request, _ := http.NewRequest(http.MethodGet, "https://synthetic.example:6443/api/v1/namespaces/payments/pods/../secrets", nil)
		if err := validateRequest(request, validated, operationSpec{verb: "get", namespace: a202Namespace, name: "../secrets"}); err == nil {
			t.Fatal("a dot-segment path was admitted")
		}
	})
	t.Run("path_escape/encoded_slash", func(t *testing.T) {
		request, _ := http.NewRequest(http.MethodGet, "https://synthetic.example:6443/api/v1/namespaces/payments/pods/api%2F0", nil)
		if err := validateRequest(request, validated, operationSpec{verb: "get", namespace: a202Namespace, name: "api/0"}); err == nil {
			t.Fatal("an encoded slash was admitted")
		}
	})
	t.Run("path_escape/query_in_name", func(t *testing.T) {
		request, _ := http.NewRequest(http.MethodGet, "https://synthetic.example:6443/api/v1/namespaces/payments/pods/api-0?watch=true", nil)
		if err := validateRequest(request, validated, operationSpec{verb: "get", namespace: a202Namespace, name: "api-0"}); err == nil {
			t.Fatal("a query on a get was admitted")
		}
	})
	t.Run("path_escape/fragment_in_name", func(t *testing.T) {
		request, _ := http.NewRequest(http.MethodGet, "https://synthetic.example:6443/api/v1/namespaces/payments/pods/api-0#frag", nil)
		if err := validateRequest(request, validated, operationSpec{verb: "get", namespace: a202Namespace, name: "api-0"}); err == nil {
			t.Fatal("a fragment on a get was admitted")
		}
	})
	t.Run("path_escape/absolute_url", func(t *testing.T) {
		request, _ := http.NewRequest(http.MethodGet, "https://synthetic.example:6443/api/v1/namespaces/payments/pods/https%3A%2F%2Fevil.example", nil)
		if err := validateRequest(request, validated, operationSpec{verb: "get", namespace: a202Namespace, name: "https://evil.example"}); err == nil {
			t.Fatal("an absolute URL as a name was admitted")
		}
	})
	t.Run("path_escape/opaque_continue_token", func(t *testing.T) {
		// A control positive: reserved characters inside a valid token are
		// encoded as a query value and never alter authority, path or keys.
		token := "tok+en/with=reserved&chars?x=1#frag"
		request, err := newRequest(context.Background(), validated, operationSpec{verb: "list", namespace: a202Namespace, cont: token})
		if err != nil {
			t.Fatalf("a reserved-character token was refused: %v", err)
		}
		if request.URL.Path != "/api/v1/namespaces/payments/pods" {
			t.Fatalf("path = %q", request.URL.Path)
		}
		query := request.URL.Query()
		if query.Get("continue") != token {
			t.Fatalf("continue = %q, want %q", query.Get("continue"), token)
		}
		if len(query) != 2 || query.Get("limit") != "100" {
			t.Fatalf("query keys = %v", query)
		}
	})
	t.Run("query_extra", func(t *testing.T) {
		request, _ := http.NewRequest(http.MethodGet, "https://synthetic.example:6443/api/v1/namespaces/payments/pods?limit=100&fieldSelector=x", nil)
		if err := validateRequest(request, validated, operationSpec{verb: "list", namespace: a202Namespace}); err == nil {
			t.Fatal("an extra query key was admitted")
		}
	})
	t.Run("query_duplicate", func(t *testing.T) {
		request, _ := http.NewRequest(http.MethodGet, "https://synthetic.example:6443/api/v1/namespaces/payments/pods?limit=100&limit=100", nil)
		if err := validateRequest(request, validated, operationSpec{verb: "list", namespace: a202Namespace}); err == nil {
			t.Fatal("a duplicated query key was admitted")
		}
	})
	t.Run("body_present", func(t *testing.T) {
		request, _ := http.NewRequest(http.MethodGet, "https://synthetic.example:6443/api/v1/namespaces/payments/pods?limit=100", strings.NewReader("{}"))
		if err := validateRequest(request, validated, operationSpec{verb: "list", namespace: a202Namespace}); err == nil {
			t.Fatal("a request with a body was admitted")
		}
	})
	t.Run("unplanned_namespace", func(t *testing.T) {
		request, _ := http.NewRequest(http.MethodGet, "https://synthetic.example:6443/api/v1/namespaces/other/pods?limit=100", nil)
		if err := validateRequest(request, validated, operationSpec{verb: "list", namespace: a202Namespace}); err == nil {
			t.Fatal("a list for another namespace was admitted")
		}
		if _, err := newRequest(context.Background(), validated, operationSpec{verb: "list", namespace: "Other"}); err == nil {
			t.Fatal("an invalid namespace built a request")
		}
	})
	t.Run("no_transport_call_on_refusal", func(t *testing.T) {
		// A refused operation is never admitted to the transport: the run state
		// refuses it and the scripted transport, which rejects any call, stays
		// untouched.
		transport := newA202ScriptedTransport()
		state := &runState{
			config: validated,
			client: newHTTPClient(transport),
			clock:  newA202Clock(t, a202StartMoment),
			budget: &budgetState{},
		}
		// A mutation verb is not part of the profile: the operation cannot even
		// describe an allowed request.
		err := state.acquire(context.Background(), operationSpec{verb: "patch", namespace: a202Namespace, name: "api-0"})
		if err == nil || err.Error() != "collector: request_not_allowed" {
			t.Fatalf("err = %v, want collector: request_not_allowed", err)
		}
		if transport.callCount() != 0 {
			t.Fatalf("transport calls = %d, want 0", transport.callCount())
		}
		if state.budget.requests != 0 {
			t.Fatalf("requests consumed = %d, want 0", state.budget.requests)
		}
	})
}

var _ = bundle.CodeRequestNotAllowed
