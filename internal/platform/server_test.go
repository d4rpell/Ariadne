package platform

import (
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func testServer(t *testing.T) (*Server, Model) {
	t.Helper()
	model := mustBuild(t, loadGoldenBook(t))
	return NewServer(model), model
}

func TestHandlerRoutes(t *testing.T) {
	server, _ := testServer(t)
	httpServer := httptest.NewServer(server.Handler())
	defer httpServer.Close()

	cases := []struct {
		method string
		path   string
		status int
	}{
		{http.MethodGet, "/", http.StatusOK},
		{http.MethodGet, "/decision/1", http.StatusOK},
		{http.MethodGet, "/decision/6", http.StatusOK},
		{http.MethodGet, "/healthz", http.StatusOK},
		{http.MethodGet, "/decision/999", http.StatusNotFound},
		{http.MethodGet, "/decision/0", http.StatusNotFound},
		{http.MethodGet, "/decision/abc", http.StatusNotFound},
		{http.MethodGet, "/decision/", http.StatusNotFound},
		{http.MethodGet, "/nope", http.StatusNotFound},
		{http.MethodGet, "/healthz/", http.StatusNotFound},
		{http.MethodPost, "/", http.StatusMethodNotAllowed},
		{http.MethodPut, "/decision/1", http.StatusMethodNotAllowed},
		{http.MethodDelete, "/healthz", http.StatusMethodNotAllowed},
	}
	for _, testCase := range cases {
		t.Run(testCase.method+" "+testCase.path, func(t *testing.T) {
			request, err := http.NewRequest(testCase.method, httpServer.URL+testCase.path, nil)
			if err != nil {
				t.Fatal(err)
			}
			response, err := http.DefaultClient.Do(request)
			if err != nil {
				t.Fatal(err)
			}
			defer response.Body.Close()
			if response.StatusCode != testCase.status {
				t.Fatalf("status = %d, want %d", response.StatusCode, testCase.status)
			}
			if testCase.status == http.StatusMethodNotAllowed {
				if allow := response.Header.Get("Allow"); allow != "GET, HEAD" {
					t.Fatalf("Allow = %q, want GET, HEAD", allow)
				}
			}
		})
	}
}

func TestHandlerHealthzBody(t *testing.T) {
	server, _ := testServer(t)
	httpServer := httptest.NewServer(server.Handler())
	defer httpServer.Close()

	response, err := http.Get(httpServer.URL + "/healthz")
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	body, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatal(err)
	}
	if string(body) != "ok" {
		t.Fatalf("healthz body = %q, want ok", string(body))
	}
	if contentType := response.Header.Get("Content-Type"); !strings.HasPrefix(contentType, "text/plain") {
		t.Fatalf("healthz Content-Type = %q, want text/plain", contentType)
	}
}

func TestHandlerSecurityHeaders(t *testing.T) {
	server, _ := testServer(t)
	httpServer := httptest.NewServer(server.Handler())
	defer httpServer.Close()

	response, err := http.Get(httpServer.URL + "/")
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if got := response.Header.Get("Content-Security-Policy"); got != contentSecurityPolicy {
		t.Fatalf("CSP = %q, want %q", got, contentSecurityPolicy)
	}
	if got := response.Header.Get("X-Content-Type-Options"); got != "nosniff" {
		t.Fatalf("X-Content-Type-Options = %q, want nosniff", got)
	}
	if got := response.Header.Get("Referrer-Policy"); got != "no-referrer" {
		t.Fatalf("Referrer-Policy = %q, want no-referrer", got)
	}
	if cookies := response.Header.Values("Set-Cookie"); len(cookies) != 0 {
		t.Fatalf("Set-Cookie present: %v", cookies)
	}
	if contentType := response.Header.Get("Content-Type"); !strings.HasPrefix(contentType, "text/html") {
		t.Fatalf("dashboard Content-Type = %q, want text/html", contentType)
	}
}

func TestHandlerHeadHasNoBody(t *testing.T) {
	server, _ := testServer(t)
	httpServer := httptest.NewServer(server.Handler())
	defer httpServer.Close()

	response, err := http.Head(httpServer.URL + "/")
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		t.Fatalf("HEAD status = %d, want 200", response.StatusCode)
	}
	body, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatal(err)
	}
	if len(body) != 0 {
		t.Fatalf("HEAD body = %q, want empty", string(body))
	}
}

func TestLoopbackAddressIsFixed(t *testing.T) {
	if loopbackHost != "127.0.0.1" {
		t.Fatalf("loopbackHost = %q, want 127.0.0.1", loopbackHost)
	}
	if address := LoopbackAddress(8080); address != "127.0.0.1:8080" {
		t.Fatalf("LoopbackAddress = %q, want 127.0.0.1:8080", address)
	}
	if err := validatePort(0); err == nil {
		t.Fatal("port 0 must be refused")
	}
	if err := validatePort(65536); err == nil {
		t.Fatal("port 65536 must be refused")
	}
	if err := validatePort(1); err != nil {
		t.Fatalf("port 1 must be accepted: %v", err)
	}
}

func TestListenBindsLoopback(t *testing.T) {
	port := freePort(t)
	listener, err := Listen(port)
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	defer listener.Close()
	address, ok := listener.Addr().(*net.TCPAddr)
	if !ok {
		t.Fatalf("listener address is %T, want *net.TCPAddr", listener.Addr())
	}
	if !address.IP.IsLoopback() {
		t.Fatalf("listener bound %s, want a loopback address", address.IP)
	}
	if address.IP.String() != "127.0.0.1" {
		t.Fatalf("listener bound %s, want 127.0.0.1 (never 0.0.0.0)", address.IP)
	}
}

func TestServeServesOnLoopback(t *testing.T) {
	port := freePort(t)
	server, _ := testServer(t)
	listener, err := Listen(port)
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- server.ServeListener(listener) }()
	defer func() { _ = listener.Close() }()

	response, err := http.Get("http://" + LoopbackAddress(port) + "/healthz")
	if err != nil {
		select {
		case serveErr := <-done:
			t.Fatalf("serve returned %v", serveErr)
		default:
			t.Fatalf("GET healthz: %v", err)
		}
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", response.StatusCode)
	}
}

// freePort reserves and releases a loopback port so Listen can bind it.
func freePort(t *testing.T) int {
	t.Helper()
	probe, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserve a port: %v", err)
	}
	port := probe.Addr().(*net.TCPAddr).Port
	if err := probe.Close(); err != nil {
		t.Fatalf("release the port: %v", err)
	}
	return port
}
