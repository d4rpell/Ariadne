package collector

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	contract "github.com/d4rpell/Ariadne/pkg/evidence"
)

// Shared harness of the A2-02 tests (handoff §4.1). Every document, credential
// and certificate below is synthetic: no cluster, no socket, no listener and no
// real data. The scripted transport and the controlled clock are the only
// seams, and both are private to the package.

const (
	a202Selector     = "k8s-pod-read-v1"
	a202Version      = "1.0"
	a202Policy       = "k8s-pod-read-v1/1.0"
	a202Alias        = "cluster-synthetic"
	a202Namespace    = "payments"
	a202NamespaceAlt = "orders"

	a202StartMoment = "2026-10-01T10:00:00Z"

	a202Image    = "registry.example/app:release"
	a202ImageID  = "sha256:" + "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	a202ImageID2 = "sha256:" + "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"

	a202MarkerToken    = "SYNTHETIC-TOKEN-MARKER-7f31"
	a202MarkerEndpoint = "synthetic-endpoint-marker"
	a202MarkerForeign  = "synthetic-foreign-name-marker"
)

// a202Clock is a fixed-instant clock with independent civil and monotonic
// readings, recorded waits and caller-controlled deadlines.
type a202Clock struct {
	mu            sync.Mutex
	civil         time.Time
	elapsed       time.Duration
	waits         []time.Duration
	deadlineCalls []time.Duration
	// failWait, when set, fails the next Wait with this error.
	failWait error
}

func newA202Clock(t *testing.T, start string) *a202Clock {
	t.Helper()
	moment, err := time.Parse(time.RFC3339, start)
	if err != nil {
		t.Fatalf("parse synthetic start %q: %v", start, err)
	}
	return &a202Clock{civil: moment.UTC()}
}

func (c *a202Clock) Now() clockSample {
	c.mu.Lock()
	defer c.mu.Unlock()
	return clockSample{UTC: c.civil, Elapsed: c.elapsed}
}

func (c *a202Clock) Wait(_ context.Context, delay time.Duration) error {
	c.mu.Lock()
	c.waits = append(c.waits, delay)
	failure := c.failWait
	c.failWait = nil
	c.mu.Unlock()
	return failure
}

func (c *a202Clock) WithTimeout(parent context.Context, timeout time.Duration) (context.Context, context.CancelFunc) {
	c.mu.Lock()
	c.deadlineCalls = append(c.deadlineCalls, timeout)
	c.mu.Unlock()
	return context.WithCancel(parent)
}

// advance moves the civil and monotonic readings forward together.
func (c *a202Clock) advance(delta time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.civil = c.civil.Add(delta)
	c.elapsed += delta
}

// setCivil moves only the civil reading, so a regression can be scripted while
// the monotonic clock keeps advancing.
func (c *a202Clock) setCivil(moment time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.civil = moment
}

func (c *a202Clock) recordedWaits() []time.Duration {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]time.Duration{}, c.waits...)
}

// a202RunContext is the run context of the "failure placed at an event" cases:
// it stays alive until expire() is called and reports exactly the scripted
// error from then on, so a test can place a global deadline expiry or a caller
// cancellation precisely, which context.WithCancelCause cannot express (it
// always reports context.Canceled in Err).
type a202RunContext struct {
	mu   sync.Mutex
	done chan struct{}
	err  error
}

func newA202RunContext() *a202RunContext {
	return &a202RunContext{done: make(chan struct{})}
}

func (c *a202RunContext) Deadline() (time.Time, bool) { return time.Time{}, false }

func (c *a202RunContext) Done() <-chan struct{} { return c.done }

func (c *a202RunContext) Err() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.err
}

func (c *a202RunContext) Value(any) any { return nil }

// expire returns the hook that makes the context report one fixed error and
// closes its completion channel. It is idempotent: a second call leaves the
// first cause untouched.
func (c *a202RunContext) expire(cause error) func() {
	return func() {
		c.mu.Lock()
		defer c.mu.Unlock()
		if c.err != nil {
			return
		}
		c.err = cause
		close(c.done)
	}
}

// a202ArmedClock is the scripted clock of the "failure placed at an event"
// cases. It hands the run-level deadline of the acquisition and every
// per-request deadline its own context and exposes independent switches, so a
// test places the exact failure it studies at an event of the response flow (a
// delivery, a consumed body, a closed body) instead of at a counting position:
// arm() makes the civil reading unusable from then on (the clock dies,
// clock_invalid), expire(cause) expires the run context with that cause (the
// caller gave up or the global deadline elapsed) and expireRequest(cause)
// expires the request-level context only (the individual deadline elapsed after
// the exchange, never causing the failure it accompanies).
type a202ArmedClock struct {
	mu         sync.Mutex
	start      time.Time
	elapsed    time.Duration
	reads      int
	armed      bool
	runCtx     *a202RunContext
	requestCtx *a202RunContext
}

func newA202ArmedClock(t *testing.T, start string) *a202ArmedClock {
	t.Helper()
	moment, err := time.Parse(time.RFC3339, start)
	if err != nil {
		t.Fatalf("parse synthetic start %q: %v", start, err)
	}
	return &a202ArmedClock{
		start:      moment.UTC(),
		runCtx:     newA202RunContext(),
		requestCtx: newA202RunContext(),
	}
}

// arm returns the hook that kills the civil clock: every later reading is
// unusable while the monotonic reading keeps advancing.
func (c *a202ArmedClock) arm() func() {
	return func() {
		c.mu.Lock()
		c.armed = true
		c.mu.Unlock()
	}
}

// expire returns the hook that expires the run context with one fixed cause.
func (c *a202ArmedClock) expire(cause error) func() {
	return c.runCtx.expire(cause)
}

// expireRequest returns the hook that expires the request-level context with
// one fixed cause.
func (c *a202ArmedClock) expireRequest(cause error) func() {
	return c.requestCtx.expire(cause)
}

func (c *a202ArmedClock) Now() clockSample {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.reads++
	c.elapsed += time.Millisecond
	if c.armed {
		return clockSample{UTC: time.Time{}, Elapsed: c.elapsed}
	}
	return clockSample{UTC: c.start.Add(time.Duration(c.reads) * time.Second), Elapsed: c.elapsed}
}

func (c *a202ArmedClock) Wait(parent context.Context, delay time.Duration) error { return nil }

// WithTimeout hands the run-level deadline of the acquisition and every
// per-request deadline their own contexts, so the test can expire each one
// exactly; nothing else derives a child.
func (c *a202ArmedClock) WithTimeout(parent context.Context, timeout time.Duration) (context.Context, context.CancelFunc) {
	if timeout == acquisitionDeadline {
		return c.runCtx, func() {}
	}
	return c.requestCtx, func() {}
}

// a202TrackedBody is a scripted response body that records every read and
// close, delivers bytes with an optional error and can fail its close.
type a202TrackedBody struct {
	data     []byte
	pos      int
	reads    int
	closes   int
	tailErr  error
	closeErr error
	// afterLimit counts reads issued after the body already delivered more than
	// one probe byte beyond a limit; the harness asserts that it stays zero.
	afterLimit int
	maxChunk   int
	// limit is the read budget used by the afterLimit accounting.
	limit int
	// blocked, when non-nil, holds every read until it is closed.
	blocked chan struct{}
	// onExhaust, when non-nil, runs once when the body has delivered all its
	// bytes: the test can arm a switch exactly after the response was consumed,
	// never at a counting position.
	onExhaust func()
	// onClose, when non-nil, runs once inside Close, after the whole body was
	// read: the test can arm a switch exactly when the read is unambiguously
	// complete, without racing the loop that consumed it.
	onClose func()
	// eofWithData, when true, makes the last data read return its bytes together
	// with io.EOF, so a reader that consumed them has finished the body in the
	// same call.
	eofWithData bool
}

func newA202Body(data string) *a202TrackedBody {
	return &a202TrackedBody{data: []byte(data), maxChunk: 32 * 1024}
}

func (b *a202TrackedBody) Read(p []byte) (int, error) {
	b.reads++
	if b.blocked != nil {
		<-b.blocked
	}
	// A read issued after the probe byte has already been delivered is a
	// post-probe read: the probe is the only read the profile authorizes beyond
	// the limit, and nothing may be read after it.
	if b.limit > 0 && b.pos > b.limit {
		b.afterLimit++
	}
	if b.pos >= len(b.data) {
		return 0, io.EOF
	}
	limit := len(p)
	if b.maxChunk > 0 && limit > b.maxChunk {
		limit = b.maxChunk
	}
	remaining := len(b.data) - b.pos
	if limit > remaining {
		limit = remaining
	}
	copied := copy(p[:limit], b.data[b.pos:b.pos+limit])
	b.pos += copied
	if b.pos >= len(b.data) && b.onExhaust != nil {
		hook := b.onExhaust
		b.onExhaust = nil
		hook()
	}
	if b.pos >= len(b.data) && b.tailErr != nil {
		return copied, b.tailErr
	}
	if b.pos >= len(b.data) && b.eofWithData {
		return copied, io.EOF
	}
	return copied, nil
}

func (b *a202TrackedBody) Close() error {
	b.closes++
	if b.onClose != nil {
		hook := b.onClose
		b.onClose = nil
		hook()
	}
	return b.closeErr
}

// a202ScriptedTransport answers a fixed sequence of responses or errors and
// rejects any call the script did not announce.
type a202ScriptedTransport struct {
	mu      sync.Mutex
	steps   []a202RoundTrip
	calls   []*http.Request
	rejects int
	bodies  []*a202TrackedBody
}

type a202RoundTrip struct {
	status  int
	body    string
	header  http.Header
	err     error
	handler func(*http.Request) (*http.Response, error)
	// onDeliver, when non-nil, runs once as the scripted response is handed to
	// the client, before its body is read.
	onDeliver func()
	// onExhaust, when non-nil, runs once when the delivered body has been fully
	// consumed. An empty body carries no tracked body and therefore no hook.
	onExhaust func()
	// onClose, when non-nil, runs once when the delivered body is closed.
	onClose func()
	// eofWithData delivers the last bytes of the body together with io.EOF.
	eofWithData bool
}

func newA202ScriptedTransport(steps ...a202RoundTrip) *a202ScriptedTransport {
	return &a202ScriptedTransport{steps: steps}
}

func (t *a202ScriptedTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	t.mu.Lock()
	t.calls = append(t.calls, request)
	if len(t.steps) == 0 {
		t.rejects++
		t.mu.Unlock()
		return nil, errors.New("collector test transport: unexpected request")
	}
	step := t.steps[0]
	t.steps = t.steps[1:]
	t.mu.Unlock()
	if step.handler != nil {
		return step.handler(request)
	}
	if step.err != nil {
		return nil, step.err
	}
	if step.onDeliver != nil {
		step.onDeliver()
	}
	header := step.header
	if header == nil {
		header = http.Header{}
	}
	body := newA202Body(step.body)
	body.onExhaust = step.onExhaust
	body.onClose = step.onClose
	body.eofWithData = step.eofWithData
	t.mu.Lock()
	t.bodies = append(t.bodies, body)
	t.mu.Unlock()
	var reader io.ReadCloser = body
	if step.body == "" {
		reader = http.NoBody
	}
	return &http.Response{
		StatusCode: step.status,
		Status:     fmt.Sprintf("%d synthetic", step.status),
		Proto:      "HTTP/1.1",
		ProtoMajor: 1,
		ProtoMinor: 1,
		Header:     header,
		Body:       reader,
		Request:    request,
	}, nil
}

func (t *a202ScriptedTransport) callCount() int {
	t.mu.Lock()
	defer t.mu.Unlock()
	return len(t.calls)
}

func (t *a202ScriptedTransport) requestURLs() []string {
	t.mu.Lock()
	defer t.mu.Unlock()
	urls := make([]string, 0, len(t.calls))
	for _, call := range t.calls {
		urls = append(urls, call.URL.String())
	}
	return urls
}

func (t *a202ScriptedTransport) recordedBodies() []*a202TrackedBody {
	t.mu.Lock()
	defer t.mu.Unlock()
	return append([]*a202TrackedBody{}, t.bodies...)
}

// a202Config builds a valid synthetic configuration.
func a202Config(t *testing.T) Config {
	t.Helper()
	return Config{
		Selector:        a202Selector,
		Version:         a202Version,
		RedactionPolicy: a202Policy,
		ClusterAlias:    a202Alias,
		Namespaces:      []string{a202Namespace},
		Endpoint:        "https://synthetic.example:6443",
		CAPEM:           a202CABundle(t),
		BearerToken:     a202MarkerToken,
	}
}

// a202Document builds one synthetic PodList response of the API.
func a202Document(items ...string) string {
	return `{"apiVersion":"v1","kind":"PodList","metadata":{"resourceVersion":"100"},"items":[` + strings.Join(items, ",") + `]}`
}

func a202Pod(uid, name string) string {
	return `{"apiVersion":"v1","kind":"Pod","metadata":{"uid":"` + uid + `","namespace":"` + a202Namespace + `","name":"` + name + `"},` +
		`"spec":{"containers":[{"name":"api","image":"` + a202Image + `"}]},` +
		`"status":{"containerStatuses":[{"name":"api","imageID":"` + a202ImageID + `"}]}}`
}

// a202CompletePod is one Pod with the three categories explicitly present: the
// shape that can reach a complete observation.
func a202CompletePod(uid, name string) string {
	return `{"apiVersion":"v1","kind":"Pod","metadata":{"uid":"` + uid + `","namespace":"` + a202Namespace + `","name":"` + name + `"},` +
		`"spec":{"containers":[{"name":"api","image":"` + a202Image + `"}],"initContainers":[],"ephemeralContainers":[]},` +
		`"status":{"containerStatuses":[{"name":"api","imageID":"` + a202ImageID + `","image":"` + a202Image + `","ready":true,"state":{"running":{}},"restartCount":0}],` +
		`"initContainerStatuses":[],"ephemeralContainerStatuses":[]}}`
}

func a202CompleteDocument(uid, name string) string {
	return a202Document(a202CompletePod(uid, name))
}

// a202IncompletePod is one Pod with identity and a spec declaration but no
// status: the categories of the status side stay omitted.
func a202IncompletePod(uid, name string) string {
	return `{"apiVersion":"v1","kind":"Pod","metadata":{"uid":"` + uid + `","namespace":"` + a202Namespace + `","name":"` + name + `"},` +
		`"spec":{"containers":[{"name":"api","image":"` + a202Image + `"}]}}`
}

// a202F07Pod is the F07 shape: the requested image is the argument while the
// whole projected status tuple stays fixed.
func a202F07Pod(requested, imageID string) string {
	return `{"apiVersion":"v1","kind":"Pod","metadata":{"uid":"u1","namespace":"` + a202Namespace + `","name":"n1"},` +
		`"spec":{"containers":[{"name":"api","image":"` + requested + `"}],"initContainers":[],"ephemeralContainers":[]},` +
		`"status":{"containerStatuses":[{"name":"api","imageID":"` + imageID + `","image":"` + a202Image + `","ready":true,"state":{"running":{}},"restartCount":0}],` +
		`"initContainerStatuses":[],"ephemeralContainerStatuses":[]}}`
}

// a202EphemeralPod is one Pod with an optional ephemeral declaration.
func a202EphemeralPod(imageID, debugImage string) string {
	ephemeral := ""
	if debugImage != "" {
		ephemeral = `[{"name":"debug","image":"` + debugImage + `"}]`
	} else {
		ephemeral = "[]"
	}
	return `{"apiVersion":"v1","kind":"Pod","metadata":{"uid":"u1","namespace":"` + a202Namespace + `","name":"n1"},` +
		`"spec":{"containers":[{"name":"api","image":"` + a202Image + `"}],"initContainers":[],"ephemeralContainers":` + ephemeral + `},` +
		`"status":{"containerStatuses":[{"name":"api","imageID":"` + imageID + `","image":"` + a202Image + `","ready":true,"state":{"running":{}},"restartCount":0}],"initContainerStatuses":[],"ephemeralContainerStatuses":[]}}`
}

// a202CollisionPod is one Pod whose container name appears in the regular and
// the init classes.
func a202CollisionPod(uid, name string) string {
	return `{"apiVersion":"v1","kind":"Pod","metadata":{"uid":"` + uid + `","namespace":"` + a202Namespace + `","name":"` + name + `"},` +
		`"spec":{"containers":[{"name":"api","image":"` + a202Image + `"}],"initContainers":[{"name":"api","image":"registry.example/init:release"}],"ephemeralContainers":[]},` +
		`"status":{"containerStatuses":[{"name":"api","imageID":"` + a202ImageID + `"}],"initContainerStatuses":[{"name":"api","imageID":"sha256:bbbb"}],"ephemeralContainerStatuses":[]}}`
}

// a202AllCollidedPod is one Pod whose container name appears in the three
// classes.
func a202AllCollidedPod(uid, name string) string {
	return `{"apiVersion":"v1","kind":"Pod","metadata":{"uid":"` + uid + `","namespace":"` + a202Namespace + `","name":"` + name + `"},` +
		`"spec":{"containers":[{"name":"api","image":"` + a202Image + `"}],"initContainers":[{"name":"api","image":"registry.example/init:release"}],"ephemeralContainers":[{"name":"api","image":"registry.example/eph:release"}]},` +
		`"status":{"containerStatuses":[{"name":"api","imageID":"` + a202ImageID + `"}],"initContainerStatuses":[{"name":"api","imageID":"sha256:bbbb"}],"ephemeralContainerStatuses":[{"name":"api","imageID":"sha256:cccc"}]}}`
}

// a202DocumentFor builds one PodList response for an explicit namespace.
func a202DocumentFor(namespace, pod string) string {
	return `{"apiVersion":"v1","kind":"PodList","metadata":{"resourceVersion":"100"},"items":[` + pod + `]}`
}

// a202CompletePodFor builds one complete Pod of an explicit namespace.
func a202CompletePodFor(namespace, uid, name string) string {
	return `{"apiVersion":"v1","kind":"Pod","metadata":{"uid":"` + uid + `","namespace":"` + namespace + `","name":"` + name + `"},` +
		`"spec":{"containers":[{"name":"api","image":"` + a202Image + `"}],"initContainers":[],"ephemeralContainers":[]},` +
		`"status":{"containerStatuses":[{"name":"api","imageID":"` + a202ImageID + `","image":"` + a202Image + `","ready":true,"state":{"running":{}},"restartCount":0}],` +
		`"initContainerStatuses":[],"ephemeralContainerStatuses":[]}}`
}

// a202JSONResponse is one scripted successful response.
func a202JSONResponse(document string) a202RoundTrip {
	return a202RoundTrip{status: 200, body: document}
}

// a202IndependentHash is the independent SHA-256 oracle of these tests: it
// never calls the production hashing helpers.
func a202IndependentHash(data []byte) string {
	digest := sha256.Sum256(data)
	return "sha256:" + hex.EncodeToString(digest[:])
}

// a202HasWarning reports whether one wire warning is present exactly.
func a202HasWarning(warnings []contract.Warning, code string, class contract.WarningClass, message string) bool {
	for _, warning := range warnings {
		if warning.Code == code && warning.Class == class && warning.Message == message {
			return true
		}
	}
	return false
}

// a202HasError reports whether one exact error text is present.
func a202HasError(errors []string, message string) bool {
	for _, failure := range errors {
		if failure == message {
			return true
		}
	}
	return false
}

// a202SyntheticPKI builds one self-signed CA and one server certificate for the
// synthetic host name. No key leaves the test process and nothing is written to
// disk.
type a202PKI struct {
	CAPEM      []byte
	CADER      []byte
	CAKey      *ecdsa.PrivateKey
	CACert     *x509.Certificate
	Server     tls.Certificate
	OtherCAPEM []byte
}

func a202SyntheticPKI(t *testing.T) a202PKI {
	t.Helper()
	pki := a202PKI{}
	caTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "ariadne-synthetic-ca"},
		NotBefore:             time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
		NotAfter:              time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate synthetic CA key: %v", err)
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create synthetic CA certificate: %v", err)
	}
	caCertificate, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatalf("parse synthetic CA certificate: %v", err)
	}
	pki.CADER, pki.CAKey, pki.CACert = caDER, key, caCertificate
	pki.CAPEM = a202PEM(t, "CERTIFICATE", caDER)

	serverTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "synthetic.example"},
		NotBefore:    time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
		NotAfter:     time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{"synthetic.example"},
	}
	serverKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate synthetic server key: %v", err)
	}
	serverDER, err := x509.CreateCertificate(rand.Reader, serverTemplate, caCertificate, &serverKey.PublicKey, key)
	if err != nil {
		t.Fatalf("create synthetic server certificate: %v", err)
	}
	serverCertificate, err := x509.ParseCertificate(serverDER)
	if err != nil {
		t.Fatalf("parse synthetic server certificate: %v", err)
	}
	pki.Server = tls.Certificate{Certificate: [][]byte{serverDER}, PrivateKey: serverKey, Leaf: serverCertificate}

	otherTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(3),
		Subject:               pkix.Name{CommonName: "ariadne-synthetic-ca-2"},
		NotBefore:             time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
		NotAfter:              time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}
	otherKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate second synthetic CA key: %v", err)
	}
	otherDER, err := x509.CreateCertificate(rand.Reader, otherTemplate, otherTemplate, &otherKey.PublicKey, otherKey)
	if err != nil {
		t.Fatalf("create second synthetic CA certificate: %v", err)
	}
	pki.OtherCAPEM = a202PEM(t, "CERTIFICATE", otherDER)
	return pki
}

// a202ClientMaterial builds one client certificate for the mTLS cases.
func a202ClientMaterial(t *testing.T, pki a202PKI) (certPEM, keyPEM []byte) {
	t.Helper()
	template := &x509.Certificate{
		SerialNumber: big.NewInt(4),
		Subject:      pkix.Name{CommonName: "ariadne-synthetic-client"},
		NotBefore:    time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
		NotAfter:     time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		DNSNames:     []string{"ariadne-synthetic-client"},
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate synthetic client key: %v", err)
	}
	der, err := x509.CreateCertificate(rand.Reader, template, pki.CACert, &key.PublicKey, pki.CAKey)
	if err != nil {
		t.Fatalf("create synthetic client certificate: %v", err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatalf("marshal synthetic client key: %v", err)
	}
	return a202PEM(t, "CERTIFICATE", der), a202PEM(t, "EC PRIVATE KEY", keyDER)
}

func a202CABundle(t *testing.T) []byte { return a202SyntheticPKI(t).CAPEM }

func a202PEM(t *testing.T, kind string, der []byte) []byte {
	t.Helper()
	block := pem.EncodeToMemory(&pem.Block{Type: kind, Bytes: der})
	if block == nil {
		t.Fatalf("encode synthetic %s block", kind)
	}
	return block
}

// a202Base64 is kept for cases that need a raw base64 image payload.
func a202Base64(data []byte) string { return base64.StdEncoding.EncodeToString(data) }

// a202PipePair returns one in-memory connection pair: no socket, no listener
// and no DNS resolution participate.
func a202PipePair() (client net.Conn, server net.Conn) { return net.Pipe() }
