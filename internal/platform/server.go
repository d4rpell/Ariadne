package platform

import (
	"fmt"
	"net"
	"net/http"
	"strconv"
	"strings"
)

// loopbackHost is the only host the server binds. It is never 0.0.0.0, never an
// IPv6 wildcard and never another interface. The server listens; it never dials
// and performs no network egress.
const loopbackHost = "127.0.0.1"

const (
	contentSecurityPolicy = "default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'"
	contentTypeHTML       = "text/html; charset=utf-8"
	contentTypeText       = "text/plain; charset=utf-8"
)

// Server serves the read-only projection of one model over loopback. The model
// is fixed at construction and every request renders from it without mutation.
type Server struct {
	model Model
}

// NewServer builds the server for one model.
func NewServer(model Model) *Server { return &Server{model: model} }

// Listen binds the fixed loopback address on port and returns the listener so
// the caller can observe the exact bound address. It is the only binding this
// package performs; the host is always 127.0.0.1 and never another interface.
// It listens; it never dials.
func Listen(port int) (net.Listener, error) {
	if err := validatePort(port); err != nil {
		return nil, err
	}
	return net.Listen("tcp", LoopbackAddress(port))
}

// Serve binds the fixed loopback address on port and serves until the listener
// fails. The process is expected to run until the operating system terminates
// it (Ctrl+C). No signal is handled here and there is no autoshutdown.
func (server *Server) Serve(port int) error {
	listener, err := Listen(port)
	if err != nil {
		return err
	}
	return server.ServeListener(listener)
}

// ServeListener serves the read-only handler on an already bound listener.
func (server *Server) ServeListener(listener net.Listener) error {
	httpServer := &http.Server{Handler: server.Handler()}
	return httpServer.Serve(listener)
}

// LoopbackAddress returns the exact host:port the server binds. It is exported
// so the CLI announces the same address the server uses, and so a test can pin
// the loopback host without a socket.
func LoopbackAddress(port int) string {
	return loopbackHost + ":" + strconv.Itoa(port)
}

func validatePort(port int) error {
	if port < 1 || port > 65535 {
		return fmt.Errorf("platform: port out of range")
	}
	return nil
}

// Handler returns the read-only HTTP handler. It admits only GET and HEAD,
// answers /healthz with the plain text "ok", / with the dashboard and
// /decision/{sequence} with one entry's detail. Every other path is 404 and
// every other method is 405 with the Allow header. No response carries
// Set-Cookie, and no external resource is referenced.
func (server *Server) Handler() http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		setSecurityHeaders(writer.Header())
		if request.Method != http.MethodGet && request.Method != http.MethodHead {
			writer.Header().Set("Allow", "GET, HEAD")
			writeDocument(writer, request, http.StatusMethodNotAllowed, contentTypeText, []byte("method not allowed\n"))
			return
		}
		switch {
		case request.URL.Path == "/":
			server.serveDashboard(writer, request)
		case request.URL.Path == "/healthz":
			writeDocument(writer, request, http.StatusOK, contentTypeText, []byte("ok"))
		case strings.HasPrefix(request.URL.Path, "/decision/"):
			server.serveDecision(writer, request)
		default:
			writeDocument(writer, request, http.StatusNotFound, contentTypeText, []byte("not found\n"))
		}
	})
}

func (server *Server) serveDashboard(writer http.ResponseWriter, request *http.Request) {
	document, err := RenderDashboard(server.model)
	if err != nil {
		writeDocument(writer, request, http.StatusInternalServerError, contentTypeText, []byte("internal error\n"))
		return
	}
	writeDocument(writer, request, http.StatusOK, contentTypeHTML, document)
}

func (server *Server) serveDecision(writer http.ResponseWriter, request *http.Request) {
	raw := strings.TrimPrefix(request.URL.Path, "/decision/")
	sequence, err := strconv.ParseUint(raw, 10, 64)
	if err != nil || sequence == 0 {
		writeDocument(writer, request, http.StatusNotFound, contentTypeText, []byte("not found\n"))
		return
	}
	document, found, err := RenderDecision(server.model, sequence)
	if err != nil {
		writeDocument(writer, request, http.StatusInternalServerError, contentTypeText, []byte("internal error\n"))
		return
	}
	if !found {
		writeDocument(writer, request, http.StatusNotFound, contentTypeText, []byte("not found\n"))
		return
	}
	writeDocument(writer, request, http.StatusOK, contentTypeHTML, document)
}

func setSecurityHeaders(header http.Header) {
	header.Set("Content-Security-Policy", contentSecurityPolicy)
	header.Set("X-Content-Type-Options", "nosniff")
	header.Set("Referrer-Policy", "no-referrer")
}

// writeDocument writes one complete response. The Content-Length is set from the
// body, and a HEAD request receives the headers and status without the body.
func writeDocument(writer http.ResponseWriter, request *http.Request, status int, contentType string, body []byte) {
	writer.Header().Set("Content-Type", contentType)
	writer.Header().Set("Content-Length", strconv.Itoa(len(body)))
	writer.WriteHeader(status)
	if request.Method == http.MethodHead {
		return
	}
	_, _ = writer.Write(body)
}
