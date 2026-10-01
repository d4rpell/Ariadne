package collector

import (
	"crypto/tls"
	"net"
	"net/http"
	"time"
)

// Private REST transport (ADR-0026 A.3.2). The collector never touches
// http.DefaultClient, http.DefaultTransport or the ambient proxy settings: the
// single client of one run is built here from the validated configuration.

// newTransport builds the only transport the collector uses.
func newTransport(config validatedConfig) *http.Transport {
	return &http.Transport{
		// No ambient proxy: the request never leaves the configured authority
		// through a third party.
		Proxy: nil,
		// No reuse: a pooled connection could be retried internally by
		// net/http, which would break the zero-retry guarantee.
		DisableKeepAlives: true,
		// No implicit decompression: an encoded body is refused, not decoded.
		DisableCompression: true,
		ForceAttemptHTTP2:  false,
		// A non-nil empty map pins the profile to HTTP/1.1: no HTTP/2 upgrade.
		TLSNextProto: map[string]func(string, *tls.Conn) http.RoundTripper{},
		TLSClientConfig: &tls.Config{
			MinVersion: tls.VersionTLS12,
			RootCAs:    config.caPool,
			// The CA bundle of the run is the only trust anchor: no system pool
			// and no insecure verification.
			InsecureSkipVerify: false,
		},
		DialContext: (&net.Dialer{
			Timeout: dialTimeout,
		}).DialContext,
		TLSHandshakeTimeout:    tlsHandshakeTimeout,
		ResponseHeaderTimeout:  responseHeaderTimeout,
		MaxResponseHeaderBytes: maxResponseHeaderBytes,
	}
}

// newHTTPClient wraps one transport. Redirects are refused, including those to
// the same authority: a redirect is an action outside the profile.
func newHTTPClient(transport http.RoundTripper) *http.Client {
	return &http.Client{
		Transport: transport,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return errRedirectRefused
		},
	}
}

// applyClientCertificate installs the mTLS pair when the run uses it.
func applyClientCertificate(transport *http.Transport, config validatedConfig) {
	if config.cert != nil && transport.TLSClientConfig != nil {
		transport.TLSClientConfig.Certificates = []tls.Certificate{*config.cert}
	}
}

// oneRequestTimeout bounds one request, body read included.
func oneRequestTimeout() time.Duration { return requestTimeout }
