package main

import (
	"bytes"
	"encoding/json"

	"github.com/d4rpell/Ariadne/internal/bundle"
	contract "github.com/d4rpell/Ariadne/pkg/evidence"
)

// Reader of `--bundle` (ADR-0023 §4.2). The envelope is the complete wire `0.2`
// document in its canonical representation and nothing else: the adapter decodes
// it, preflights the four model budgets, validates it and re-encodes it with the
// project's own encoder, and only admits the bytes when the canonical envelope
// equals them exactly. A difference is a rejection, never a repair: duplicate or
// unknown members, alternate casing, omitted members, a byte-order mark, added
// whitespace, a trailing newline, an undue null and unsupported versions all
// fail closed. Paths named inside the evidence are never opened.

// canonicalEncode is the canonical encoder the adapter calls. It is a variable
// only so the tests can observe that the budget preflight short-circuits before
// it: production always runs bundle.Encode itself, and no test seam reaches the
// evaluator or the renderer.
var canonicalEncode = bundle.Encode

func decodeBundle(data []byte) (contract.Bundle, *cliError) {
	if err := strictFloor(data); err != nil {
		return contract.Bundle{}, newFailure(stageBundleDecode, codeInvalidBundle)
	}
	if err := strictSurrogates(data); err != nil {
		return contract.Bundle{}, newFailure(stageBundleDecode, codeInvalidBundle)
	}
	if err := strictShape(data); err != nil {
		return contract.Bundle{}, newFailure(stageBundleDecode, codeInvalidBundle)
	}
	var decoded contract.Bundle
	if err := json.Unmarshal(data, &decoded); err != nil {
		return contract.Bundle{}, newFailure(stageBundleDecode, codeInvalidBundle)
	}
	// Model budgets before validation, copying, sorting or canonical encoding.
	if !measureForCLI(decoded) {
		return contract.Bundle{}, newFailure(stageBundleDecode, codeInputLimit)
	}
	artifacts, err := canonicalEncode(decoded)
	if err != nil {
		return contract.Bundle{}, newFailure(stageBundleDecode, codeInvalidBundle)
	}
	if !bytes.Equal(artifacts.Envelope, data) {
		return contract.Bundle{}, newFailure(stageBundleDecode, codeInvalidBundle)
	}
	return decoded, nil
}
