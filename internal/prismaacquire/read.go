package prismaacquire

import (
	"errors"
	"io"
)

// Bounded, transactional body read of §§6.11 and 7.5–7.6. A page is admissible
// only when the read ends with a correct EOF; a prefix followed by truncation,
// a non-EOF error, an over-limit probe or a close failure invalidates the whole
// page. The single probe byte that distinguishes an exact limit from an excess
// is counted; no further draining happens.
//
// A read failure is returned as its underlying error, so the caller can classify
// a timeout or a cancellation from its own budget state instead of collapsing
// every failure into body_read_failed (§7.14, §11.4). A local excess and the
// no-progress guard are returned as typed acquisition diagnostics.

// errBodyNoProgress is the local no-progress sentinel of §7.6.
var errBodyNoProgress = errors.New("prismaacquire: body read without progress")

// readResult carries the admitted bytes and the exact number of body bytes read,
// including rejected bytes and the probe.
type readResult struct {
	data  []byte
	bytes uint64
}

// readBounded reads a response body under the individual response limit and the
// accumulated body budget. When the individual limit is the more restrictive one
// an excess reports response_limit; otherwise byte_limit (§7.6). A read error is
// returned raw so the caller classifies it; the no-progress guard returns
// errBodyNoProgress.
func readBounded(body io.ReadCloser, responseLimit int, accumulatedRemaining uint64) (readResult, error) {
	allowed := uint64(responseLimit)
	excess := CodeResponseLimit
	if accumulatedRemaining < allowed {
		allowed = accumulatedRemaining
		excess = CodeByteLimit
	}
	data := make([]byte, 0, 4096)
	var read uint64
	noProgress := 0
	buf := make([]byte, 32*1024)
	for uint64(len(data)) < allowed {
		want := allowed - uint64(len(data))
		if want > uint64(len(buf)) {
			want = uint64(len(buf))
		}
		n, err := body.Read(buf[:want])
		read += uint64(n)
		if n > 0 {
			data = append(data, buf[:n]...)
			noProgress = 0
		} else if err == nil {
			noProgress++
			if noProgress >= 100 {
				return readResult{bytes: read}, errBodyNoProgress
			}
			continue
		}
		if err == io.EOF {
			return readResult{data: data, bytes: read}, nil
		}
		if err != nil {
			return readResult{bytes: read}, err
		}
	}
	// The allowed byte count was reached without EOF: a single probe byte decides
	// between an exact end and an excess.
	probe := make([]byte, 1)
	for {
		n, err := body.Read(probe)
		read += uint64(n)
		if n > 0 {
			return readResult{bytes: read}, acquireErr(excess, PhaseBody)
		}
		if err == io.EOF {
			return readResult{data: data, bytes: read}, nil
		}
		if err != nil {
			return readResult{bytes: read}, err
		}
		noProgress++
		if noProgress >= 100 {
			return readResult{bytes: read}, errBodyNoProgress
		}
	}
}
