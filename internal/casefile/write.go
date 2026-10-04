package casefile

import (
	"io"
	"reflect"
)

// isTypedNil refuses the non-nil interface values that wrap a nil pointer,
// map, slice, function or channel: they pass the plain == nil comparison and
// would turn the delivery into a runtime panic instead of invalid_writer.
func isTypedNil(destination io.Writer) bool {
	value := reflect.ValueOf(destination)
	switch value.Kind() {
	case reflect.Ptr, reflect.Interface, reflect.Map, reflect.Slice, reflect.Func, reflect.Chan:
		return value.IsNil()
	default:
		return false
	}
}

// writeBook delivers the canonical document through a caller-chosen
// io.Writer (ADR-0030 §7.3). The destination is the caller's privilege: the
// library never discovers one, never retries and never closes it.
func writeBook(book Book, destination io.Writer) error {
	if destination == nil || isTypedNil(destination) {
		return problem(CodeInvalidWriter)
	}
	if !book.initialized {
		return problem(CodeInvalidBook)
	}
	data, err := Encode(book)
	if err != nil {
		return err
	}
	written, err := destination.Write(data)
	if err != nil {
		return problem(CodeWriteFailed)
	}
	if written != len(data) {
		return problem(CodeShortWrite)
	}
	return nil
}
