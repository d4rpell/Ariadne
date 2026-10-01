package collector

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"net/http"
	"testing"
	"time"

	"github.com/d4rpell/Ariadne/internal/bundle"
)

// Closed-transport cases of the A2-02 plan (handoff §4.2 row "Transporte
// cerrado"). The built transport is inspected directly; the redirect cases run
// against the same client the collector uses, and the scripted transport stays
// out of these assertions.

func TestA202TransportProfile(t *testing.T) {
	pki := a202SyntheticPKI(t)
	config := a202Config(t)
	config.CAPEM = pki.CAPEM
	validated, err := validateConfig(config)
	if err != nil {
		t.Fatalf("validateConfig: %v", err)
	}
	transport := newTransport(validated)

	t.Run("explicit_ca", func(t *testing.T) {
		if transport.TLSClientConfig == nil || transport.TLSClientConfig.RootCAs == nil {
			t.Fatal("the transport has no explicit root pool")
		}
		// The pool of the run verifies the supplied synthetic CA and does not
		// equal a pool built from another CA.
		if _, err := pki.CACert.Verify(x509.VerifyOptions{
			Roots:     transport.TLSClientConfig.RootCAs,
			KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
		}); err != nil {
			t.Fatalf("the supplied CA does not verify against the transport pool: %v", err)
		}
		otherPool := x509.NewCertPool()
		if !otherPool.AppendCertsFromPEM(pki.OtherCAPEM) {
			t.Fatal("cannot build the control pool")
		}
		if otherPool.Equal(transport.TLSClientConfig.RootCAs) {
			t.Fatal("the run pool equals a pool built from another CA")
		}
	})
	t.Run("tls_minimum", func(t *testing.T) {
		if transport.TLSClientConfig.MinVersion != tls.VersionTLS12 {
			t.Fatalf("MinVersion = %d, want TLS 1.2", transport.TLSClientConfig.MinVersion)
		}
		if transport.TLSClientConfig.InsecureSkipVerify {
			t.Fatal("InsecureSkipVerify is enabled")
		}
	})
	t.Run("hostname_validation", func(t *testing.T) {
		if transport.TLSClientConfig.InsecureSkipVerify {
			t.Fatal("hostname validation is disabled")
		}
	})
	t.Run("proxy_disabled", func(t *testing.T) {
		if transport.Proxy != nil {
			t.Fatal("the transport selected a proxy")
		}
	})
	t.Run("redirect_same_authority", func(t *testing.T) {
		client := newHTTPClient(newA202ScriptedTransport(a202RoundTrip{
			status: http.StatusFound,
			header: http.Header{"Location": []string{"https://synthetic.example:6443/api/v1/namespaces/payments/pods"}},
		}))
		request, _ := http.NewRequest(http.MethodGet, "https://synthetic.example:6443/api/v1/namespaces/payments/pods", nil)
		_, err := client.Do(request)
		if err == nil {
			t.Fatal("a same-authority redirect was followed")
		}
		if code := classifyTransportError(err); code != bundle.CodeRedirectRefused {
			t.Fatalf("classified %q, want redirect_refused", code)
		}
	})
	t.Run("redirect_other_authority", func(t *testing.T) {
		client := newHTTPClient(newA202ScriptedTransport(a202RoundTrip{
			status: http.StatusMovedPermanently,
			header: http.Header{"Location": []string{"https://elsewhere.example/api/v1/namespaces/payments/pods"}},
		}))
		request, _ := http.NewRequest(http.MethodGet, "https://synthetic.example:6443/api/v1/namespaces/payments/pods", nil)
		_, err := client.Do(request)
		if err == nil {
			t.Fatal("a cross-authority redirect was followed")
		}
		if code := classifyTransportError(err); code != bundle.CodeRedirectRefused {
			t.Fatalf("classified %q, want redirect_refused", code)
		}
	})
	t.Run("http2_disabled", func(t *testing.T) {
		if transport.ForceAttemptHTTP2 {
			t.Fatal("HTTP/2 is enabled")
		}
		if transport.TLSNextProto == nil || len(transport.TLSNextProto) != 0 {
			t.Fatal("TLSNextProto must be a non-nil empty map")
		}
	})
	t.Run("connection_not_reused", func(t *testing.T) {
		if !transport.DisableKeepAlives {
			t.Fatal("connection re-use is enabled")
		}
	})
	t.Run("fixed_headers", func(t *testing.T) {
		request, err := newRequest(context.Background(), validated, operationSpec{verb: "list", namespace: a202Namespace})
		if err != nil {
			t.Fatalf("newRequest: %v", err)
		}
		if request.Header.Get("Accept") != "application/json" {
			t.Fatalf("Accept = %q", request.Header.Get("Accept"))
		}
		if request.Header.Get("User-Agent") != "ariadne-collector/k8s-pod-read-v1" {
			t.Fatalf("User-Agent = %q", request.Header.Get("User-Agent"))
		}
		if request.Header.Get("Authorization") != "Bearer "+a202MarkerToken {
			t.Fatal("the bearer header is not the configured one")
		}
	})
}

// TestA202ContentEncoding covers the exact admitted values of Content-Encoding
// (A-7): absence and exactly "identity" pass; anything else is refused.
func TestA202ContentEncoding(t *testing.T) {
	cases := map[string]struct {
		values []string
		want   bool
	}{
		"absent":          {nil, false},
		"identity":        {[]string{"identity"}, false},
		"present_empty":   {[]string{""}, true},
		"gzip":            {[]string{"gzip"}, true},
		"parameters":      {[]string{"identity; q=1"}, true},
		"list":            {[]string{"identity, gzip"}, true},
		"multiple_values": {[]string{"identity", "identity"}, true},
		"other_value":     {[]string{"br"}, true},
	}
	for name, testCase := range cases {
		t.Run(name, func(t *testing.T) {
			if got := contentEncodingProblem(testCase.values); got != testCase.want {
				t.Fatalf("contentEncodingProblem(%v) = %v, want %v", testCase.values, got, testCase.want)
			}
		})
	}
}

// TestA202TLSInMemory drives the built client against an in-memory TLS pair: no
// socket, no listener and no DNS. The server end is a scripted HTTP/1.1 writer.
func TestA202TLSInMemory(t *testing.T) {
	t.Run("trusted_server", func(t *testing.T) {
		pki := a202SyntheticPKI(t)
		clientConn, serverConn := a202PipePair()
		serverDone := make(chan error, 1)
		go func() {
			serverDone <- a202ServeTLS(serverConn, &pki.Server, "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n{}", "")
		}()
		config := a202Config(t)
		config.CAPEM = pki.CAPEM
		validated, err := validateConfig(config)
		if err != nil {
			t.Fatalf("validateConfig: %v", err)
		}
		transport := newTransport(validated)
		transport.DialContext = a202Dial(clientConn)
		client := newHTTPClient(transport)
		request, _ := http.NewRequest(http.MethodGet, "https://synthetic.example:6443/api/v1/namespaces/payments/pods?limit=100", nil)
		response, err := client.Do(request)
		if err != nil {
			t.Fatalf("trusted server: %v", err)
		}
		response.Body.Close()
		if response.StatusCode != http.StatusOK {
			t.Fatalf("status = %d", response.StatusCode)
		}
		if err := <-serverDone; err != nil {
			t.Fatalf("server side: %v", err)
		}
	})
	t.Run("wrong_ca", func(t *testing.T) {
		pki := a202SyntheticPKI(t)
		clientConn, serverConn := a202PipePair()
		go func() {
			_ = a202ServeTLS(serverConn, &pki.Server, "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n{}", "")
		}()
		config := a202Config(t)
		config.CAPEM = pki.OtherCAPEM
		validated, err := validateConfig(config)
		if err != nil {
			t.Fatalf("validateConfig: %v", err)
		}
		transport := newTransport(validated)
		transport.DialContext = a202Dial(clientConn)
		client := newHTTPClient(transport)
		request, _ := http.NewRequest(http.MethodGet, "https://synthetic.example:6443/pods", nil)
		_, err = client.Do(request)
		if err == nil {
			t.Fatal("a certificate of another CA was accepted")
		}
		if code := classifyTransportError(err); code != bundleCodeTLSFailed() {
			t.Fatalf("classifyTransportError = %q, want tls_failed", code)
		}
	})
	t.Run("wrong_name", func(t *testing.T) {
		pki := a202SyntheticPKI(t)
		clientConn, serverConn := a202PipePair()
		go func() {
			_ = a202ServeTLS(serverConn, &pki.Server, "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n{}", "")
		}()
		config := a202Config(t)
		config.CAPEM = pki.CAPEM
		config.Endpoint = "https://other-name.example:6443"
		validated, err := validateConfig(config)
		if err != nil {
			t.Fatalf("validateConfig: %v", err)
		}
		transport := newTransport(validated)
		transport.DialContext = a202Dial(clientConn)
		client := newHTTPClient(transport)
		request, _ := http.NewRequest(http.MethodGet, "https://other-name.example:6443/pods", nil)
		_, err = client.Do(request)
		if err == nil {
			t.Fatal("a certificate of another host name was accepted")
		}
		if code := classifyTransportError(err); code != bundleCodeTLSFailed() {
			t.Fatalf("classifyTransportError = %q, want tls_failed", code)
		}
	})
	t.Run("mtls_required", func(t *testing.T) {
		pki := a202SyntheticPKI(t)
		clientConn, serverConn := a202PipePair()
		go func() {
			_ = a202ServeTLS(serverConn, &pki.Server, "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n{}", "RequireAnyClientCert")
		}()
		config := a202Config(t)
		config.CAPEM = pki.CAPEM
		validated, err := validateConfig(config)
		if err != nil {
			t.Fatalf("validateConfig: %v", err)
		}
		transport := newTransport(validated)
		transport.DialContext = a202Dial(clientConn)
		client := newHTTPClient(transport)
		request, _ := http.NewRequest(http.MethodGet, "https://synthetic.example:6443/pods", nil)
		if _, err := client.Do(request); err == nil {
			t.Fatal("the server required a client certificate and none was sent")
		}
	})
	t.Run("invalid_client_certificate", func(t *testing.T) {
		config := a202Config(t)
		config.BearerToken = ""
		config.ClientCertificatePEM = []byte("-----BEGIN CERTIFICATE-----\nnot-base64\n-----END CERTIFICATE-----\n")
		config.ClientKeyPEM = []byte("-----BEGIN EC PRIVATE KEY-----\nnot-base64\n-----END EC PRIVATE KEY-----\n")
		assertA202ConfigFailure(t, config, bundle.CodeUnsupportedAuth)
	})
	t.Run("handshake_timeout", func(t *testing.T) {
		config := a202Config(t)
		validated, err := validateConfig(config)
		if err != nil {
			t.Fatalf("validateConfig: %v", err)
		}
		transport := newTransport(validated)
		if transport.TLSHandshakeTimeout != 3*time.Second {
			t.Fatalf("TLSHandshakeTimeout = %v, want 3s", transport.TLSHandshakeTimeout)
		}
	})
	t.Run("cancel_handshake", func(t *testing.T) {
		pki := a202SyntheticPKI(t)
		clientConn, serverConn := a202PipePair()
		// The server end is never driven: the handshake blocks until the client
		// context is cancelled, and the pair is closed without a goroutine leak.
		defer serverConn.Close()
		config := a202Config(t)
		config.CAPEM = pki.CAPEM
		validated, err := validateConfig(config)
		if err != nil {
			t.Fatalf("validateConfig: %v", err)
		}
		transport := newTransport(validated)
		transport.DialContext = a202Dial(clientConn)
		client := newHTTPClient(transport)
		ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
		defer cancel()
		request, _ := http.NewRequestWithContext(ctx, http.MethodGet, "https://synthetic.example:6443/pods", nil)
		_, err = client.Do(request)
		if err == nil {
			t.Fatal("a cancelled handshake was reported as successful")
		}
		if code := classifyTransportError(err); code != bundleCodeRequestTimeout() && code != bundleCodeCancelled() {
			t.Fatalf("classifyTransportError = %q, want request_timeout or cancelled", code)
		}
	})
}
