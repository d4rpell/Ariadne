package collector

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"time"

	"github.com/d4rpell/Ariadne/internal/bundle"
)

// In-memory TLS harness of the A2-02 transport cases (handoff §4.1): a real
// tls.Server and tls.Client over net.Pipe. No socket, listener or DNS is
// created; the server end writes one fixed HTTP/1.1 response and closes.

// a202ServeTLS runs one TLS handshake over the server end and writes one fixed
// HTTP/1.1 response. The client-auth mode selects the exact server demand.
func a202ServeTLS(conn net.Conn, certificate *tls.Certificate, response, clientAuth string) error {
	config := &tls.Config{
		Certificates: []tls.Certificate{*certificate},
		MinVersion:   tls.VersionTLS12,
		MaxVersion:   tls.VersionTLS12,
	}
	switch clientAuth {
	case "":
	case "RequireAnyClientCert":
		config.ClientAuth = tls.RequireAnyClientCert
	default:
		return errors.New("collector test harness: unknown client-auth mode")
	}
	server := tls.Server(conn, config)
	defer server.Close()
	if err := server.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		return err
	}
	handshake := make(chan error, 1)
	go func() { handshake <- server.Handshake() }()
	select {
	case err := <-handshake:
		if err != nil {
			return err
		}
	case <-time.After(3 * time.Second):
		return errors.New("collector test harness: handshake did not finish")
	}
	// The handshake deadline must not bound the exchange: writing a large
	// response over the synchronous pipe waits for the client's read loop, and
	// under -race on a loaded runner the handshake's five seconds are not enough
	// (the CI failure of 2026-10-01 refused a 28672-byte block that way). The
	// post-handshake phases get their own generous bound; a stuck exchange is
	// the caller's client-side context deadline, not this harness.
	if err := server.SetDeadline(time.Now().Add(60 * time.Second)); err != nil {
		return err
	}
	// The request is read before the response is written: a response the server
	// sends before the request reached the transport is ill-formed HTTP/1.1 and
	// the stdlib only tolerates it by timing (readLoopPeekFailLocked and the
	// unsolicited-response log under -race with GOMAXPROCS=1). Reading the
	// request head makes the exchange order deterministic. A client that never
	// sends one (a failed verification, for instance) fails the read here and
	// the caller ignores this error.
	reader := bufio.NewReader(server)
	for {
		line, readErr := reader.ReadString('\n')
		if readErr != nil {
			return readErr
		}
		if line == "\r\n" || line == "\n" {
			break
		}
	}
	if _, err := io.WriteString(server, response); err != nil {
		return err
	}
	// The server end stays open until the client closes its side: the response
	// is only valid while the bytes are readable, and closing early would turn
	// a correct exchange into a read failure.
	_, _ = io.Copy(io.Discard, server)
	return nil
}

// a202Dial returns a dialer that answers every address with the prepared
// in-memory client end. It is the only transport seam the TLS cases use.
func a202Dial(client net.Conn) func(ctx context.Context, network, address string) (net.Conn, error) {
	return func(context.Context, string, string) (net.Conn, error) { return client, nil }
}

// bundleCodeTLSFailed and its siblings keep the assertions readable without
// duplicating the literal at every call site.
func bundleCodeTLSFailed() bundle.CollectionCode      { return bundle.CodeTLSFailed }
func bundleCodeRequestTimeout() bundle.CollectionCode { return bundle.CodeRequestTimeout }
func bundleCodeCancelled() bundle.CollectionCode      { return bundle.CodeCancelled }
func bundleCodeTransportFailed() bundle.CollectionCode {
	return bundle.CodeTransportFailed
}
