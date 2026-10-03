package prismaacquire

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/d4rpell/Ariadne/internal/ingest"
)

// Serial acquisition sequence of §8.1. One acquisition is a finite, strictly
// serial sequence: validate configuration, admit the credential, authenticate
// when required, GET offset=0, admit the page, advance by the number of admitted
// records, and close only on an admitted empty page. Any failure ends the
// sequence with a known `aborted` termination; there is no recovery branch.

// transportFactory builds the round tripper for one acquisition. Tests in this
// package pass a factory whose transport dials an in-memory pipe or returns a
// scripted round tripper; it is not a public option.
type transportFactory func(ca []byte) (http.RoundTripper, *AcquisitionError)

// pageDraft is the private admitted page held until the global termination is
// known (§8.18). It carries sanitized records and accounting, never finalized
// artifacts.
type pageDraft struct {
	ordinal    int
	offset     int
	acquiredAt string
	draft      ingest.NativeDraft
}

type acquirer struct {
	parent context.Context
	ctx    context.Context
	cfg    AcquisitionConfig
	cred   Credential

	origin    string
	authority string
	client    *http.Client
	token     string

	now   func() time.Time
	sleep func(context.Context, time.Duration) error

	start     time.Time
	lastStart time.Time
	lastCivil time.Time

	budget      budget
	comparer    *pageComparer
	pages       []pageDraft
	diagnostics []*AcquisitionError

	// finalizationHook, when non-nil, runs once after each page is built inside
	// finalizePages. It exists only so an in-package test can cancel after the
	// initial checkpoint of a page; it is nil in production and is not a public
	// option.
	finalizationHook func()
}

// Acquire is the public operation of §§4.1, 3.6: an offline-capable connector
// that reads existing image reports over a closed HTTPS surface. Cancellation is
// the caller's context.Context; the credential is already resolved in memory.
func Acquire(ctx context.Context, cfg AcquisitionConfig, cred Credential) (*AcquisitionResult, *AcquisitionError) {
	return acquire(ctx, cfg, cred, func(ca []byte) (http.RoundTripper, *AcquisitionError) {
		transport, err := newTransport(ca, nil)
		if err != nil {
			return nil, err
		}
		return transport, nil
	})
}

// runtimeHooks let the in-package tests substitute the civil clock and the
// cancellable wait so a multi-page sequence does not spend real seconds in the
// inter-request interval. They are nil in production.
type runtimeHooks struct {
	now   func() time.Time
	sleep func(context.Context, time.Duration) error
}

func acquire(ctx context.Context, cfg AcquisitionConfig, cred Credential, makeTransport transportFactory) (*AcquisitionResult, *AcquisitionError) {
	return acquireWith(ctx, cfg, cred, makeTransport, runtimeHooks{})
}

func acquireWith(ctx context.Context, cfg AcquisitionConfig, cred Credential, makeTransport transportFactory, hooks runtimeHooks) (*AcquisitionResult, *AcquisitionError) {
	if ctx == nil {
		ctx = context.Background()
	}
	// Capture the referenced configuration at admission so a later mutation of
	// the caller's CA, scope alias or expiry cannot change an acquisition in
	// progress (§3.6).
	cfg = snapshotConfig(cfg)
	if err := validateConfig(cfg); err != nil {
		a := &acquirer{parent: ctx, ctx: ctx, cfg: cfg}
		return a.finish(err)
	}
	runCtx, cancel := context.WithTimeout(ctx, maxAcquisitionDuration)
	defer cancel()

	a := &acquirer{
		parent:   ctx,
		ctx:      runCtx,
		cfg:      cfg,
		cred:     cred,
		now:      time.Now,
		sleep:    sleepContext,
		start:    time.Now(),
		comparer: newPageComparer(),
	}
	if hooks.now != nil {
		a.now = hooks.now
	}
	if hooks.sleep != nil {
		a.sleep = hooks.sleep
	}
	if err := validateCredential(cfg, cred, a.now()); err != nil {
		return a.finish(err)
	}
	parsed, perr := url.Parse(cfg.Endpoint)
	if perr != nil {
		return a.finish(acquireErr(CodeInvalidConfig, PhaseConfig))
	}
	a.authority = parsed.Host
	a.origin = "https://" + parsed.Host

	transport, terr := makeTransport(cfg.CA)
	if terr != nil {
		return a.finish(terr)
	}
	a.client = newHTTPClient(transport)

	if cfg.AuthMode == AuthPasswordExchange {
		if err := a.exchangePassword(); err != nil {
			return a.finish(err)
		}
	} else {
		a.token = cred.Token
	}

	return a.runPages()
}

// exchangePassword performs the single POST of §5.4 before any image read.
func (a *acquirer) exchangePassword() *AcquisitionError {
	body, err := authRequestBody(a.cred.Username, a.cred.Password)
	if err != nil {
		return err
	}
	if err := a.budget.ensureAttempt(); err != nil {
		return err
	}
	if err := a.waitSpacing(); err != nil {
		return err
	}
	// The declared expiry is revalidated before every delivery to the transport,
	// including the authentication POST, after the wait (§5.3): an expired token
	// aborts with credential_expired and no request is sent.
	if err := a.checkTokenExpiry(); err != nil {
		return err
	}
	req, err := a.buildAuthRequest(body)
	if err != nil {
		return err
	}
	if err := a.guardRequest(req, http.MethodPost, authenticatePath, false); err != nil {
		return err
	}
	// The attempt is consumed only when the request is handed to the transport,
	// after every local validation and the wait (§7.4).
	if err := a.budget.reserveAttempt(); err != nil {
		return err
	}
	if err := a.budget.reserveAuth(); err != nil {
		return err
	}
	resp, err := a.do(req)
	if err != nil {
		return err
	}
	data, err := a.readResponse(resp, maxAuthResponseBytes)
	if err != nil {
		return err
	}
	token, err := parseAuthResponse(data)
	if err != nil {
		return err
	}
	a.token = token
	return nil
}

// runPages executes the pagination loop of §8.2–§8.9.
func (a *acquirer) runPages() (*AcquisitionResult, *AcquisitionError) {
	offset := 0
	ordinal := 0
	for {
		if err := a.budget.ensureAttempt(); err != nil {
			return a.finish(err)
		}
		if err := a.budget.ensurePage(); err != nil {
			return a.finish(err)
		}
		ordinal++
		if err := a.waitSpacing(); err != nil {
			return a.finish(err)
		}
		// A declared expiry is revalidated before every delivery to the transport,
		// after the wait: the request is aborted with credential_expired without
		// being sent, and the already admitted pages are conserved as aborted
		// (§5.3).
		if err := a.checkTokenExpiry(); err != nil {
			return a.finish(err)
		}
		req, err := a.buildImageRequest(offset)
		if err != nil {
			return a.finish(err)
		}
		if err := a.guardRequest(req, http.MethodGet, imagesPath, true); err != nil {
			return a.finish(err)
		}
		if err := a.budget.reserveAttempt(); err != nil {
			return a.finish(err)
		}
		if err := a.budget.reservePage(); err != nil {
			return a.finish(err)
		}
		resp, err := a.do(req)
		if err != nil {
			return a.finish(err)
		}
		data, err := a.readResponse(resp, maxImageResponseBytes)
		if err != nil {
			return a.finish(err)
		}
		acquiredAt, err := a.acquiredAt()
		if err != nil {
			return a.finish(err)
		}
		draft, err := a.admitPage(data)
		if err != nil {
			return a.finish(err)
		}
		if err := pageSizeExcess(len(draft.Records)); err != nil {
			return a.finish(err)
		}
		if err := a.budget.addDraft(draft.Accounting); err != nil {
			return a.finish(err)
		}
		a.pages = append(a.pages, pageDraft{ordinal: ordinal, offset: offset, acquiredAt: acquiredAt, draft: draft})
		if isTerminalPage(len(draft.Records)) {
			// The admitted empty page is the only successful close (§8.5–§8.6).
			return a.finish(nil)
		}
		if err := a.comparer.observePage(ordinal, draft.Records); err != nil {
			return a.finish(err)
		}
		if err := a.comparer.observeDrift(ordinal, draft.Records); err != nil {
			return a.finish(err)
		}
		next, ok := nextOffset(offset, len(draft.Records))
		if !ok {
			return a.finish(acquireErr(CodeInternalInvariantFailed, PhasePagination))
		}
		offset = next
	}
}

// checkTokenExpiry aborts before a request when the declared expiry has been
// reached (§5.3). A nil expiry is unknown, never "never".
func (a *acquirer) checkTokenExpiry() *AcquisitionError {
	if tokenExpired(a.cfg.TokenExpiresAt, a.now()) {
		return acquireErr(CodeCredentialExpired, PhaseAuth)
	}
	return nil
}

// readResponse applies the §6.8 representation rules, reads the body under the
// budgets and closes it. A non-200 status or an unadmitted representation closes
// the body without reading it.
func (a *acquirer) readResponse(resp *http.Response, limit int) ([]byte, *AcquisitionError) {
	if resp.StatusCode != http.StatusOK {
		failure := acquireErr(httpStatusError(resp.StatusCode), PhaseBody)
		failure.HTTPStatus = resp.StatusCode
		_ = resp.Body.Close()
		return nil, failure
	}
	if err := admittedRepresentation(resp.Header); err != nil {
		_ = resp.Body.Close()
		return nil, err
	}
	result, readErr := readBounded(resp.Body, limit, a.budget.bodyRemaining())
	a.budget.addBody(result.bytes)
	closeErr := resp.Body.Close()
	if readErr != nil {
		return nil, a.classifyReadError(readErr)
	}
	if closeErr != nil {
		return nil, acquireErr(CodeBodyReadFailed, PhaseBody)
	}
	return result.data, nil
}

// admittedRepresentation enforces the single Content-Type and the absent-or-
// identity Content-Encoding of §6.8.
func admittedRepresentation(header http.Header) *AcquisitionError {
	types := header.Values("Content-Type")
	if len(types) != 1 {
		return acquireErr(CodeResponseInvalid, PhaseBody)
	}
	if !admittedContentType(types[0]) {
		return acquireErr(CodeResponseInvalid, PhaseBody)
	}
	encodings := header.Values("Content-Encoding")
	if len(encodings) > 1 {
		return acquireErr(CodeResponseInvalid, PhaseBody)
	}
	if len(encodings) == 1 && !strings.EqualFold(strings.TrimSpace(encodings[0]), "identity") {
		return acquireErr(CodeResponseInvalid, PhaseBody)
	}
	return nil
}

func admittedContentType(value string) bool {
	normalized := strings.ToLower(strings.TrimSpace(value))
	return normalized == "application/json" || normalized == "application/json; charset=utf-8"
}

// do hands a guarded request to the transport and classifies the failure.
func (a *acquirer) do(req *http.Request) (*http.Response, *AcquisitionError) {
	resp, err := a.client.Do(req)
	if err != nil {
		return nil, a.classifyTransportError(err)
	}
	return resp, nil
}

// classifyTransportError maps a transport or body-read failure to the closed
// catalogue from the connector's own state, without inspecting error text
// (§7.14, §11.4). A caller cancellation is `cancelled`; the global budget is
// `time_limit`; the per-request timeout is `request_timeout`.
func (a *acquirer) classifyTransportError(err error) *AcquisitionError {
	if a.parent.Err() != nil {
		if errors.Is(a.parent.Err(), context.Canceled) {
			return acquireErr(CodeCancelled, PhaseRequest)
		}
		return acquireErr(CodeTimeLimit, PhaseRequest)
	}
	if a.ctx.Err() == context.DeadlineExceeded {
		return acquireErr(CodeTimeLimit, PhaseRequest)
	}
	return classifyError(err)
}

// classifyReadError keeps a typed local excess and the no-progress guard,
// classifies a timeout or a cancellation from the connector's own state, and
// reduces every other body-read failure (for example io.ErrUnexpectedEOF on a
// truncated body) to body_read_failed, never to a transport failure (§7.14,
// §11.4).
func (a *acquirer) classifyReadError(err error) *AcquisitionError {
	if errors.Is(err, errBodyNoProgress) {
		return acquireErr(CodeBodyReadFailed, PhaseBody)
	}
	var failure *AcquisitionError
	if errors.As(err, &failure) {
		return failure
	}
	if a.parent.Err() != nil {
		if errors.Is(a.parent.Err(), context.Canceled) {
			return acquireErr(CodeCancelled, PhaseRequest)
		}
		return acquireErr(CodeTimeLimit, PhaseRequest)
	}
	if a.ctx.Err() == context.DeadlineExceeded {
		return acquireErr(CodeTimeLimit, PhaseRequest)
	}
	if errors.Is(err, context.Canceled) {
		return acquireErr(CodeCancelled, PhaseRequest)
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return acquireErr(CodeRequestTimeout, PhaseRequest)
	}
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return acquireErr(CodeRequestTimeout, PhaseRequest)
	}
	return acquireErr(CodeBodyReadFailed, PhaseBody)
}

// waitSpacing enforces the minimum interval between request starts (§6.12). The
// wait is cancellable and consumes the global budget.
func (a *acquirer) waitSpacing() *AcquisitionError {
	now := a.now()
	if !a.lastStart.IsZero() {
		if wait := minRequestSpacing - now.Sub(a.lastStart); wait > 0 {
			if err := a.sleep(a.ctx, wait); err != nil {
				return a.contextFailure()
			}
		}
	}
	a.lastStart = a.now()
	return nil
}

// contextFailure maps a wait interrupted by the context to the closed code.
func (a *acquirer) contextFailure() *AcquisitionError {
	if a.parent.Err() != nil && errors.Is(a.parent.Err(), context.Canceled) {
		return acquireErr(CodeCancelled, PhaseRequest)
	}
	if a.ctx.Err() == context.DeadlineExceeded {
		return acquireErr(CodeTimeLimit, PhaseRequest)
	}
	return acquireErr(CodeCancelled, PhaseRequest)
}

// acquiredAt obtains the page timestamp after a successful read and close and
// rejects an invalid or regressive civil clock (§7.12). The comparison uses the
// civil instants without the monotonic component, which is reserved for
// durations.
func (a *acquirer) acquiredAt() (string, *AcquisitionError) {
	now := a.now().Round(0)
	value, ok := canonicalInstant(now)
	if !ok {
		return "", acquireErr(CodeClockInvalid, PhaseFinalization)
	}
	if !a.lastCivil.IsZero() && now.Before(a.lastCivil) {
		return "", acquireErr(CodeClockInvalid, PhaseFinalization)
	}
	a.lastCivil = now
	return value, nil
}

// snapshotConfig copies the referenced configuration fields at admission, so a
// later mutation of the caller's CA, scope alias or expiry cannot change an
// acquisition in progress (§3.6). The CA length is checked before the copy, so
// an oversized CA is rejected by validation without duplicating it first
// (§§6.3, 7.1).
func snapshotConfig(cfg AcquisitionConfig) AcquisitionConfig {
	if len(cfg.CA) > 0 && len(cfg.CA) <= maxCAContentBytes {
		cfg.CA = append([]byte(nil), cfg.CA...)
	}
	cfg.ScopeAlias = cloneAlias(cfg.ScopeAlias)
	if cfg.TokenExpiresAt != nil {
		expiry := *cfg.TokenExpiresAt
		cfg.TokenExpiresAt = &expiry
	}
	return cfg
}
