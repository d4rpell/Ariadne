package report

import (
	"bytes"
	"encoding/json"
)

// JSON returns the compact UTF-8 JSON document of one validated report: the
// declared key order, no whitespace outside tokens, no BOM and no trailing
// newline. The encoder reads no clock, no environment and no file.
func JSON(report Report) ([]byte, error) {
	if !report.ok {
		return nil, problem(CodeInvalidReport)
	}
	var buffer bytes.Buffer
	encoder := json.NewEncoder(&buffer)
	// The canonical form of this presentation escapes <, > and &, so the bytes
	// can be embedded in another document without closing a tag.
	encoder.SetEscapeHTML(true)
	if err := encoder.Encode(report.envelope()); err != nil {
		return nil, problem(CodeRenderFailure)
	}
	return bytes.TrimSuffix(buffer.Bytes(), []byte("\n")), nil
}
