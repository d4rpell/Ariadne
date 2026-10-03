package ingest

import (
	"io"
	"reflect"

	"github.com/d4rpell/Ariadne/internal/schema"
)

// Bounded acquisition and public entry point of the prisma-native adapters
// (ADR-0027 §5, §6, §11). The context and the profile selection are validated
// before any reader consumes the source; a nil reader, a read error or an
// oversized source leaves no publishable artifact behind.

// nativeReadChunk is the pull size of each acquisition call.
const nativeReadChunk = 32 * 1024

// ParsePrismaNative admits one native source selected explicitly by the caller
// and returns its derived source, or a fatal diagnostic. The selector and the
// input version must match the profile exactly; no fallback is attempted.
func ParsePrismaNative(reader io.Reader, selector, version, profile string, ctx NativeContext) (NativeSource, *NativeError) {
	if err := validateNativeContext(ctx); err != nil {
		return NativeSource{}, err
	}
	expected := ""
	switch selector {
	case schema.NativeJSONSelector:
		expected = schema.NativeJSONProfile
	case schema.NativeCSVSelector:
		expected = schema.NativeCSVProfile
	default:
		return NativeSource{}, nativeFailure(NativeCodeUnsupportedSelector, NativePhaseContext, NativeSpaceNone, 0)
	}
	if version != schema.NativeInputVersion {
		return NativeSource{}, nativeFailure(NativeCodeUnsupportedVersion, NativePhaseContext, NativeSpaceNone, 0)
	}
	if profile != expected {
		return NativeSource{}, nativeFailure(NativeCodeUnsupportedProfile, NativePhaseContext, NativeSpaceNone, 0)
	}
	if err := validateDeclaredOrigin(ctx); err != nil {
		return NativeSource{}, err
	}
	for _, field := range ctx.SelectedFields {
		if !schema.NativeValidateSelection(selector, field) {
			return NativeSource{}, nativeFailure(NativeCodeInvalidContext, NativePhaseContext, NativeSpaceNone, 0)
		}
	}
	data, err := acquireNativeSource(reader)
	if err != nil {
		return NativeSource{}, err
	}
	if selector == schema.NativeCSVSelector {
		return parsePrismaNativeCSV(data, ctx)
	}
	return parsePrismaNativeJSON(data, ctx)
}

// validateDeclaredOrigin rejects a declared edition or release other than the
// profile under selection (§4.2). Unknown values are admitted as a documentary
// assumption; a different known release requires another profile.
func validateDeclaredOrigin(ctx NativeContext) *NativeError {
	if ctx.DeclaredEdition == "compute_self_hosted" && ctx.DeclaredRelease != "34.04.145" && ctx.DeclaredRelease != "unknown" {
		return nativeFailure(NativeCodeUnsupportedProfile, NativePhaseContext, NativeSpaceNone, 0)
	}
	return nil
}

// acquireNativeSource reads one complete bounded source to a confirmed EOF with
// no error before any examination starts. The stream budget is 64 MiB and at
// most one extra byte is requested to distinguish an exact-size file from an
// oversized one; a failed acquisition drains nothing.
func acquireNativeSource(reader io.Reader) ([]byte, *NativeError) {
	if isNilNativeReader(reader) {
		return nil, nativeFailure(NativeCodeNilReader, NativePhaseContext, NativeSpaceNone, 0)
	}
	limit := uint64(schema.NativeMaxSourceBytes)
	data := make([]byte, 0, nativeReadChunk)
	buffer := make([]byte, nativeReadChunk)
	progress := 0
	read := uint64(0)
	for {
		want := uint64(nativeReadChunk)
		if remaining := limit + 1 - read; remaining < want {
			want = remaining
		}
		n, err := reader.Read(buffer[:want])
		if n > 0 {
			data = append(data, buffer[:n]...)
			read += uint64(n)
			progress = 0
		}
		if read > limit {
			return nil, nativeFailure(NativeCodeSourceLimit, NativePhaseAcquisition, NativeSpaceNative, limit)
		}
		switch {
		case err == io.EOF:
			return data, nil
		case err != nil:
			return nil, nativeFailure(NativeCodeReadFailed, NativePhaseAcquisition, NativeSpaceNative, read)
		}
		if n == 0 {
			progress++
			if progress > schema.NativeMaxNoProgressReads {
				return nil, nativeFailure(NativeCodeReadFailed, NativePhaseAcquisition, NativeSpaceNative, read)
			}
		}
	}
}

// isNilNativeReader reports whether the reader is nil, including a typed nil.
func isNilNativeReader(reader io.Reader) bool {
	if reader == nil {
		return true
	}
	value := reflect.ValueOf(reader)
	switch value.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map,
		reflect.Pointer, reflect.Slice:
		return value.IsNil()
	}
	return false
}

// IsNilNativeReader reports whether a reader is nil, including a typed nil.
func IsNilNativeReader(reader io.Reader) bool { return isNilNativeReader(reader) }
