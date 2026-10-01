package collector

import (
	"context"
	"errors"
	"io"
	"net/http"

	"github.com/d4rpell/Ariadne/internal/bundle"
)

// Bounded body reading (ADR-0026 A.5.2, A.8). A rejected or truncated response
// never yields a source or a hash: only a complete, closed and admitted body
// does. The byte probe that detects the overflow is counted, never published,
// the body is closed, and the remaining data is not drained.

// readResponse reads one response body with the per-response limit, the global
// remaining budget and one probe byte. It returns the bytes only when the body
// ended cleanly inside both limits; any other outcome yields no bytes at all.
//
// The read is bounded by the residual global budget: a block never consumes
// more than what is left, so the accumulated counter stays exact. The probe is
// a single byte beyond the per-response limit, counted and unpublished, and it
// never becomes data. The probe also requires a real end of body: a `(0,nil)`
// return is not an admitted termination.
func readResponse(ctx context.Context, response *http.Response, budget *budgetState) ([]byte, error) {
	if response == nil || response.Body == nil {
		return nil, staticError(bundle.CodeBodyReadFailed)
	}
	if err := ctx.Err(); err != nil {
		_ = response.Body.Close()
		return nil, staticError(bundle.CodeCancelled)
	}
	captured := make([]byte, 0, 4096)
	for {
		if err := ctx.Err(); err != nil {
			_ = response.Body.Close()
			return nil, staticError(bundle.CodeCancelled)
		}
		remaining := maxResponseBodyBytes - len(captured)
		if remaining == 0 {
			// One probe byte beyond the per-response limit. Its overflow is
			// response_limit even when that same byte also exhausts the global
			// budget (A.5.2): the more specific guard owns that byte, and the byte
			// is counted in both counters before the diagnosis.
			probe := make([]byte, 1)
			n, readErr := response.Body.Read(probe)
			if n > 0 {
				budget.addBodyBytes(uint64(n))
				_ = response.Body.Close()
				return nil, staticError(bundle.CodeResponseLimit)
			}
			if readErr == io.EOF {
				break
			}
			if readErr != nil {
				_ = response.Body.Close()
				return nil, staticError(bundle.CodeBodyReadFailed)
			}
			// A read of zero bytes with no error is not an end of body: it cannot
			// be presented as a complete response.
			_ = response.Body.Close()
			return nil, staticError(bundle.CodeBodyReadFailed)
		}
		remainingGlobal := budget.remainingBodyBudget()
		if remainingGlobal == 0 {
			// The global budget is exhausted while the per-response limit still
			// has room: the next read could only exceed the global bound, and no
			// additional probe is taken once it fired.
			_ = response.Body.Close()
			return nil, staticError(bundle.CodeByteLimit)
		}
		if uint64(remaining) > remainingGlobal {
			remaining = int(remainingGlobal)
		}
		chunk := make([]byte, 32*1024)
		if remaining < len(chunk) {
			chunk = chunk[:remaining]
		}
		n, err := response.Body.Read(chunk)
		if n > 0 {
			if budget.addBodyBytes(uint64(n)) {
				_ = response.Body.Close()
				return nil, staticError(bundle.CodeByteLimit)
			}
			captured = append(captured, chunk[:n]...)
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			_ = response.Body.Close()
			return nil, staticError(bundle.CodeBodyReadFailed)
		}
	}
	if err := response.Body.Close(); err != nil {
		// A failed close leaves the response unaccounted: it cannot be admitted.
		return nil, staticError(bundle.CodeBodyReadFailed)
	}
	return captured, nil
}

// remainingBodyBudget returns the bytes still admitted by the global budget of
// the run.
func (b *budgetState) remainingBodyBudget() uint64 {
	if b.totalBodyBytes >= maxTotalBodyBytes {
		return 0
	}
	return maxTotalBodyBytes - b.totalBodyBytes
}

// staticError builds an error whose message is exactly the closed diagnostic of
// one code. No underlying error, endpoint or value is ever included.
func staticError(code bundle.CollectionCode) error {
	message := bundle.CollectionMessage(code)
	if message == "" {
		message = bundle.CollectionMessage(bundle.CodeProjectionFailed)
	}
	return errors.New(message)
}

// headerProblem checks the response headers that must be refused before the
// body is read at all.
func headerProblem(response *http.Response) bundle.CollectionCode {
	if response == nil {
		return bundle.CodeTransportFailed
	}
	if contentEncodingProblem(response.Header.Values("Content-Encoding")) {
		return bundle.CodeResponseInvalid
	}
	return ""
}

// responseStatus is the status of one response, with a zero value for a nil
// response.
func responseStatus(response *http.Response) int {
	if response == nil {
		return 0
	}
	return response.StatusCode
}
