package prismaacquire

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net"
	"net/http"
)

// Closed transport of §§6.1–6.4. The connector builds its own client and
// transport for each acquisition: explicit in-memory CA, TLS 1.2 minimum, no
// proxy, redirects, cookies, HTTP/2, keep-alive, automatic compression or
// retries. No caller-supplied client, transport, dialer or TLS configuration is
// accepted.

// buildTLSConfig parses the explicit in-memory CA into a root pool. A CA that is
// not valid PEM is a local configuration failure; the system trust store is
// never a silent fallback.
func buildTLSConfig(ca []byte) (*tls.Config, *AcquisitionError) {
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(ca) {
		return nil, acquireErr(CodeTLSConfigInvalid, PhaseConfig)
	}
	return &tls.Config{
		MinVersion: tls.VersionTLS12,
		RootCAs:    pool,
	}, nil
}

// newTransport builds the effective transport. dial, when non-nil, replaces the
// real dialer; it exists only so the in-memory TLS/HTTP tests can exercise the
// effective production configuration without a listening socket. It is not a
// public option.
func newTransport(ca []byte, dial func(ctx context.Context, network, addr string) (net.Conn, error)) (*http.Transport, *AcquisitionError) {
	tlsConf, err := buildTLSConfig(ca)
	if err != nil {
		return nil, err
	}
	transport := &http.Transport{
		Proxy:                  nil,
		TLSClientConfig:        tlsConf,
		ForceAttemptHTTP2:      false,
		DisableCompression:     true,
		DisableKeepAlives:      true,
		MaxIdleConns:           0,
		MaxIdleConnsPerHost:    0,
		MaxConnsPerHost:        1,
		IdleConnTimeout:        0,
		TLSHandshakeTimeout:    maxTLSDuration,
		ResponseHeaderTimeout:  maxHeaderWaitDuration,
		ExpectContinueTimeout:  0,
		MaxResponseHeaderBytes: maxResponseHeaderBytes,
	}
	if dial != nil {
		transport.DialContext = dial
	} else {
		dialer := &net.Dialer{Timeout: maxConnectDuration}
		transport.DialContext = dialer.DialContext
	}
	return transport, nil
}

// newHTTPClient wraps a transport with the closed redirect policy: a 3xx is
// returned to the caller, never followed, so no credential is ever re-sent to a
// Location (§6.7). The per-request timeout covers the body read (§6.12).
func newHTTPClient(transport http.RoundTripper) *http.Client {
	return &http.Client{
		Transport: transport,
		Timeout:   maxRequestDuration,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

// classifyError maps a transport failure to the closed diagnostic catalogue
// (§11.2). A caller cancellation is `cancelled`; the distinction between the
// per-request timeout and the global budget is decided by the caller from its
// own budget state, not from error text.
func classifyError(err error) *AcquisitionError {
	if err == nil {
		return nil
	}
	if errors.Is(err, context.Canceled) {
		return acquireErr(CodeCancelled, PhaseRequest)
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return acquireErr(CodeRequestTimeout, PhaseRequest)
	}
	var verifyErr *tls.CertificateVerificationError
	if errors.As(err, &verifyErr) {
		return acquireErr(CodeTLSFailed, PhaseRequest)
	}
	var unknownAuth x509.UnknownAuthorityError
	if errors.As(err, &unknownAuth) {
		return acquireErr(CodeTLSFailed, PhaseRequest)
	}
	var hostnameErr x509.HostnameError
	if errors.As(err, &hostnameErr) {
		return acquireErr(CodeTLSFailed, PhaseRequest)
	}
	var invalidErr x509.CertificateInvalidError
	if errors.As(err, &invalidErr) {
		return acquireErr(CodeTLSFailed, PhaseRequest)
	}
	var recordErr tls.RecordHeaderError
	if errors.As(err, &recordErr) {
		return acquireErr(CodeTLSFailed, PhaseRequest)
	}
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return acquireErr(CodeRequestTimeout, PhaseRequest)
	}
	return acquireErr(CodeTransportFailed, PhaseRequest)
}
