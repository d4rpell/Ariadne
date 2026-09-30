package ingest

import (
	"crypto/sha256"
	"encoding/hex"
	"io"
	"reflect"

	"github.com/d4rpell/Ariadne/internal/schema"
	contract "github.com/d4rpell/Ariadne/pkg/evidence"
)

// Bounded acquisition of ADR-0025 A.5.3 and A.10.3 row 2. Exactly one source is
// read to a confirmed EOF with no error before any JSON examination starts. The
// stream budget is 64 MiB and at most one extra byte is requested to tell an
// exact-size file from an oversized one; a read that delivers the
// limit-exceeding byte together with an error still reports file_limit, and a
// failed acquisition drains nothing.

// podListReadChunk is the pull size of each acquisition call.
const podListReadChunk = 32 * 1024

// acquirePodListSource reads one complete bounded source and returns either its
// original bytes or the sanitized failure of the acquisition stage. The raw
// reader error is never exposed: only its verified progress is.
func acquirePodListSource(r io.Reader) ([]byte, *PodListError) {
	if isNilPodListReader(r) {
		return nil, failure(PodListCodeNilReader, 0)
	}
	limit := uint64(schema.SanitizedPodListMaxSourceBytes)
	data := make([]byte, 0, podListReadChunk)
	buffer := make([]byte, podListReadChunk)
	progress := 0
	read := uint64(0)
	for {
		want := uint64(podListReadChunk)
		if remaining := limit + 1 - read; remaining < want {
			want = remaining
		}
		n, err := r.Read(buffer[:want])
		if n > 0 {
			data = append(data, buffer[:n]...)
			read += uint64(n)
			progress = 0
		}
		if read > limit {
			return nil, failure(PodListCodeFileLimit, limit)
		}
		switch {
		case err == io.EOF:
			return data, nil
		case err != nil:
			return nil, failure(PodListCodeReadFailed, read)
		}
		if n == 0 {
			progress++
			if progress >= schema.SanitizedPodListMaxNoProgressReads {
				return nil, failure(PodListCodeReadFailed, read)
			}
		}
	}
}

// isNilPodListReader reports whether the reader is nil, including a typed nil
// whose method set would panic on the first call.
func isNilPodListReader(r io.Reader) bool {
	if r == nil {
		return true
	}
	value := reflect.ValueOf(r)
	switch value.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map,
		reflect.Pointer, reflect.Slice:
		return value.IsNil()
	}
	return false
}

// hashPodListSource hashes every original byte of one admitted source. It is
// called only after the complete structural examination succeeded; a rejected
// source never gets a publicable hash.
func hashPodListSource(data []byte) contract.SourceHash {
	digest := sha256.Sum256(data)
	return contract.SourceHash("sha256:" + hex.EncodeToString(digest[:]))
}
