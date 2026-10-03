package prismaacquire

import (
	"crypto/tls"
	"crypto/x509"
	"io"
	"net/http"
	"strings"
	"testing"
)

// Incremento 7 de A2-08-F2: transporte cerrado y TLS (ADR-0028 §6.1–§6.4,
// §6.14). Las propiedades efectivas se comprueban sobre la configuración de
// producción y conexiones en memoria, sin sockets de escucha.

func TestA208F2TransportProfile(t *testing.T) {
	pki := f2SyntheticPKI(t)
	transport, err := newTransport(pki.CAPEM, nil)
	if err != nil {
		t.Fatalf("newTransport: %v", err)
	}
	if transport.Proxy != nil {
		t.Fatal("transport selected a proxy")
	}
	if transport.TLSClientConfig == nil || transport.TLSClientConfig.RootCAs == nil {
		t.Fatal("transport has no explicit root pool")
	}
	if transport.TLSClientConfig.MinVersion != tls.VersionTLS12 {
		t.Fatalf("MinVersion = %d, want TLS 1.2", transport.TLSClientConfig.MinVersion)
	}
	if transport.TLSClientConfig.MaxVersion != 0 {
		t.Fatal("MaxVersion must not be fixed")
	}
	if transport.TLSClientConfig.InsecureSkipVerify {
		t.Fatal("InsecureSkipVerify is enabled")
	}
	if transport.ForceAttemptHTTP2 {
		t.Fatal("HTTP/2 is enabled")
	}
	if !transport.DisableCompression {
		t.Fatal("automatic compression is enabled")
	}
	if !transport.DisableKeepAlives {
		t.Fatal("keep-alive is enabled")
	}
	if transport.MaxConnsPerHost != 1 {
		t.Fatalf("MaxConnsPerHost = %d, want 1", transport.MaxConnsPerHost)
	}
	if _, err := pki.CACert.Verify(x509.VerifyOptions{
		Roots:     transport.TLSClientConfig.RootCAs,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	}); err != nil {
		t.Fatalf("supplied CA does not verify against the transport pool: %v", err)
	}
	otherPool := x509.NewCertPool()
	if !otherPool.AppendCertsFromPEM(pki.OtherPEM) {
		t.Fatal("cannot build the control pool")
	}
	if otherPool.Equal(transport.TLSClientConfig.RootCAs) {
		t.Fatal("run pool equals a pool built from another CA")
	}
}

func TestA208F2TLSInMemory(t *testing.T) {
	pki := f2SyntheticPKI(t)
	serverTLS := &tls.Config{Certificates: []tls.Certificate{pki.Server}, MinVersion: tls.VersionTLS12}

	t.Run("accepted_ca", func(t *testing.T) {
		client, serverConn, cleanup := f2InMemoryTransport(t, pki.CAPEM)
		defer cleanup()
		f2ServeTLS(t, serverConn, serverTLS, []f2TLSResponse{{status: 200, body: "[]"}})
		req, _ := http.NewRequest(http.MethodGet, "https://prisma.example.test:8443/api/v34.04/images?offset=0", nil)
		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("handshake with the supplied CA failed: %v", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != 200 {
			t.Fatalf("status = %d, want 200", resp.StatusCode)
		}
	})
	t.Run("untrusted_ca", func(t *testing.T) {
		client, serverConn, cleanup := f2InMemoryTransport(t, pki.OtherPEM)
		defer cleanup()
		f2ServeTLS(t, serverConn, serverTLS, []f2TLSResponse{{status: 200, body: "[]"}})
		req, _ := http.NewRequest(http.MethodGet, "https://prisma.example.test:8443/api/v34.04/images?offset=0", nil)
		if _, err := client.Do(req); err == nil {
			t.Fatal("a connection was accepted with a CA that did not sign the server")
		}
	})
}

func TestA208F2NoRedirectFollow(t *testing.T) {
	cfg := f2Config()
	script := &f2Sequenced{steps: []f2SequencedStep{{
		status: http.StatusFound,
		header: http.Header{"Location": []string{"https://prisma.example.test:8443/api/v34.04/images"}},
		body:   io.NopCloser(strings.NewReader("")),
	}}}
	result, err := f2Run(t, cfg, f2Bearer(), script)
	if err == nil || err.Code != CodeRedirectRefused {
		t.Fatalf("err = %v, want %s", err, CodeRedirectRefused)
	}
	if result.Termination != TerminationAborted || len(result.Pages) != 0 {
		t.Fatalf("result = %s/%d pages, want aborted/0", result.Termination, len(result.Pages))
	}
	if script.requestCount() != 1 {
		t.Fatalf("requests = %d, want 1 (Location must not be followed)", script.requestCount())
	}
}

func TestA208F2HTTPRepresentation(t *testing.T) {
	cases := []struct {
		name   string
		header http.Header
		ok     bool
	}{
		{"json", http.Header{"Content-Type": []string{"application/json"}}, true},
		{"json_charset", http.Header{"Content-Type": []string{"application/json; charset=utf-8"}}, true},
		{"json_charset_upper", http.Header{"Content-Type": []string{"Application/JSON; Charset=UTF-8"}}, true},
		{"missing", http.Header{}, false},
		{"text", http.Header{"Content-Type": []string{"text/plain"}}, false},
		{"duplicate_type", http.Header{"Content-Type": []string{"application/json", "application/json"}}, false},
		{"json_extra_param", http.Header{"Content-Type": []string{"application/json; charset=utf-8; x=1"}}, false},
		{"identity_encoding", http.Header{"Content-Type": []string{"application/json"}, "Content-Encoding": []string{"identity"}}, true},
		{"gzip_encoding", http.Header{"Content-Type": []string{"application/json"}, "Content-Encoding": []string{"gzip"}}, false},
		{"duplicate_encoding", http.Header{"Content-Type": []string{"application/json"}, "Content-Encoding": []string{"identity", "identity"}}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := admittedRepresentation(tc.header)
			if tc.ok && err != nil {
				t.Fatalf("accepted representation rejected: %v", err)
			}
			if !tc.ok && (err == nil || err.Code != CodeResponseInvalid) {
				t.Fatalf("err = %v, want %s", err, CodeResponseInvalid)
			}
		})
	}
}
