package collector

import (
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
	if _, err := io.WriteString(server, response); err != nil {
		return err
	}
	// The server end stays open until the client closes its side: the response
	// is only valid while the bytes are readable, and closing early would turn
	// a correct exchange into a read failure.
	_ = server.SetReadDeadline(time.Now().Add(5 * time.Second))
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
