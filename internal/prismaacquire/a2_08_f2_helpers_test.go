package prismaacquire

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"
)

// Synthetic fixtures and doubles of ADR-0028 §13.2. No socket is ever opened for
// listening: the sequence double is a scripted round tripper and the transport
// tests use an in-memory pipe carrying TLS.

func f2Config() AcquisitionConfig {
	alias := "scope-a"
	return AcquisitionConfig{
		Selector:      AcquisitionSelector,
		Version:       AcquisitionVersion,
		Profile:       AcquisitionProfile,
		OriginAlias:   "origin-a",
		Edition:       DeclaredEdition,
		Release:       DeclaredRelease,
		Endpoint:      "https://prisma.example.test:8443",
		CA:            []byte("synthetic-ca"),
		ScopeMode:     ScopeProjectSelect,
		Project:       "proj_1",
		ScopeAlias:    &alias,
		AuthMode:      AuthBearerSupplied,
		CredentialRef: "cred-1",
		DataPolicyAck: requiredDataPolicyAck,
	}
}

func f2Bearer() Credential { return Credential{Reference: "cred-1", Token: "synthetic.token"} }

// f2SequencedStep is one scripted HTTP response.
type f2SequencedStep struct {
	status int
	header http.Header
	body   io.ReadCloser
}

// f2Sequenced is a RoundTripper that returns a fixed sequence of responses and
// records every request it was handed.
type f2Sequenced struct {
	mu       sync.Mutex
	steps    []f2SequencedStep
	requests []*http.Request
}

func (s *f2Sequenced) RoundTrip(req *http.Request) (*http.Response, error) {
	s.mu.Lock()
	s.requests = append(s.requests, req)
	if len(s.steps) == 0 {
		s.mu.Unlock()
		return nil, fmt.Errorf("f2Sequenced: unexpected request %s %s", req.Method, req.URL.Path)
	}
	step := s.steps[0]
	s.steps = s.steps[1:]
	s.mu.Unlock()
	if step.header == nil {
		step.header = f2JSONHeader()
	}
	if step.body == nil {
		step.body = io.NopCloser(strings.NewReader(""))
	}
	return &http.Response{StatusCode: step.status, Header: step.header, Body: step.body, Request: req}, nil
}

func (s *f2Sequenced) lastMethod() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.requests) == 0 {
		return ""
	}
	return s.requests[len(s.requests)-1].Method
}

func (s *f2Sequenced) requestCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.requests)
}

func f2JSONHeader() http.Header { return http.Header{"Content-Type": []string{"application/json"}} }

// f2Page builds a synthetic JSON array of n image records.
func f2Page(n int, prefix string) string {
	if n == 0 {
		return "[]"
	}
	parts := make([]string, n)
	for i := 0; i < n; i++ {
		parts[i] = fmt.Sprintf(`{"type":"image","id":"%s-%d","packages":[],"vulnerabilities":[]}`, prefix, i)
	}
	return "[" + strings.Join(parts, ",") + "]"
}

// f2Clock is a monotonic civil clock advanced on every read, so timestamps are
// canonical and never regress while the inter-request wait is instantaneous.
type f2Clock struct {
	mu sync.Mutex
	t  time.Time
}

func newF2Clock() *f2Clock { return &f2Clock{t: time.Date(2026, 10, 3, 0, 0, 0, 0, time.UTC)} }

func (c *f2Clock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(time.Second)
	return c.t
}

func (c *f2Clock) sleep(context.Context, time.Duration) error { return nil }

// f2Run acquires with the scripted sequence and the fast clock.
func f2Run(t *testing.T, cfg AcquisitionConfig, cred Credential, script *f2Sequenced) (*AcquisitionResult, *AcquisitionError) {
	t.Helper()
	clock := newF2Clock()
	return acquireWith(context.Background(), cfg, cred,
		func([]byte) (http.RoundTripper, *AcquisitionError) { return script, nil },
		runtimeHooks{now: clock.now, sleep: clock.sleep})
}

// f2Steps builds a scripted sequence of 200 JSON pages.
func f2Steps(pages ...string) *f2Sequenced {
	steps := make([]f2SequencedStep, 0, len(pages))
	for _, page := range pages {
		steps = append(steps, f2SequencedStep{
			status: http.StatusOK,
			body:   io.NopCloser(strings.NewReader(page)),
		})
	}
	return &f2Sequenced{steps: steps}
}

// f2PKI is a synthetic in-memory certificate authority and server identity.
type f2PKI struct {
	CAPEM    []byte
	CACert   *x509.Certificate
	CAKey    *ecdsa.PrivateKey
	Server   tls.Certificate
	OtherPEM []byte
}

func f2SyntheticPKI(t *testing.T) f2PKI {
	t.Helper()
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("CA key: %v", err)
	}
	caTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "f2-synthetic-ca"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatalf("CA cert: %v", err)
	}
	caCert, _ := x509.ParseCertificate(caDER)

	serverKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("server key: %v", err)
	}
	serverTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "prisma.example.test"},
		DNSNames:     []string{"prisma.example.test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	serverDER, err := x509.CreateCertificate(rand.Reader, serverTemplate, caCert, &serverKey.PublicKey, caKey)
	if err != nil {
		t.Fatalf("server cert: %v", err)
	}

	otherKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("other key: %v", err)
	}
	otherTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(3),
		Subject:               pkix.Name{CommonName: "f2-other-ca"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	otherDER, err := x509.CreateCertificate(rand.Reader, otherTemplate, otherTemplate, &otherKey.PublicKey, otherKey)
	if err != nil {
		t.Fatalf("other cert: %v", err)
	}

	return f2PKI{
		CAPEM:    f2PEM("CERTIFICATE", caDER),
		CACert:   caCert,
		CAKey:    caKey,
		Server:   tls.Certificate{Certificate: [][]byte{serverDER}, PrivateKey: serverKey},
		OtherPEM: f2PEM("CERTIFICATE", otherDER),
	}
}

func f2PEM(kind string, der []byte) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: kind, Bytes: der})
}

// f2TLSResponse is one scripted response served over the in-memory TLS pipe.
type f2TLSResponse struct {
	status int
	header http.Header
	body   string
}

// f2ServeTLS drives one HTTP/1.1 exchange over conn using the production client
// transport pointed at the other end of the pipe. It returns after serving the
// configured responses in order, one per request.
func f2ServeTLS(t *testing.T, serverConn net.Conn, serverTLS *tls.Config, responses []f2TLSResponse) {
	t.Helper()
	go func() {
		tlsConn := tls.Server(serverConn, serverTLS)
		if err := tlsConn.Handshake(); err != nil {
			return
		}
		for _, response := range responses {
			req, err := http.ReadRequest(bufio.NewReader(tlsConn))
			if err != nil {
				return
			}
			_ = req.Body.Close()
			header := response.header
			if header == nil {
				header = f2JSONHeader()
			}
			statusText := http.StatusText(response.status)
			fmt.Fprintf(tlsConn, "HTTP/1.1 %d %s\r\n", response.status, statusText)
			for key, values := range header {
				for _, value := range values {
					fmt.Fprintf(tlsConn, "%s: %s\r\n", key, value)
				}
			}
			fmt.Fprintf(tlsConn, "Content-Length: %d\r\n\r\n", len(response.body))
			io.WriteString(tlsConn, response.body)
		}
		tlsConn.Close()
	}()
}

// f2InMemoryTransport builds the effective production transport with its dialer
// pointed at an in-memory pipe, plus the server end of that pipe.
func f2InMemoryTransport(t *testing.T, ca []byte) (*http.Client, net.Conn, func()) {
	t.Helper()
	clientConn, serverConn := net.Pipe()
	transport, err := newTransport(ca, func(context.Context, string, string) (net.Conn, error) {
		return clientConn, nil
	})
	if err != nil {
		t.Fatalf("newTransport: %v", err)
	}
	client := newHTTPClient(transport)
	cleanup := func() {
		transport.CloseIdleConnections()
		clientConn.Close()
		serverConn.Close()
	}
	return client, serverConn, cleanup
}
