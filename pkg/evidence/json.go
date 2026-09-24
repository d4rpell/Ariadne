package evidence

import (
	"bytes"
	"encoding/json"
)

// Wire grammar of ADR-0006 §2 and §4: no HTML escaping, no Unicode
// normalization, no added whitespace, and null for the optional values that the
// Go model keeps as non-pointer fields. The canonical bytes of a bundle are
// produced by internal/evidence; these marshalers fix the shape of the three
// objects whose null policy the Go types cannot express on their own.

func marshalWire(document any) ([]byte, error) {
	var buffer bytes.Buffer
	encoder := json.NewEncoder(&buffer)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(document); err != nil {
		return nil, err
	}
	return bytes.TrimSuffix(buffer.Bytes(), []byte("\n")), nil
}

// MarshalJSON emits null when the owner chain was not observed.
func (chain OwnerChain) MarshalJSON() ([]byte, error) {
	if chain == "" {
		return []byte("null"), nil
	}
	return marshalWire(string(chain))
}

// MarshalJSON emits os and architecture as null unless the platform is known.
func (platform Platform) MarshalJSON() ([]byte, error) {
	type wirePlatform struct {
		OS           *string        `json:"os"`
		Architecture *string        `json:"architecture"`
		Status       PlatformStatus `json:"status"`
	}
	wire := wirePlatform{Status: platform.Status}
	if platform.Status == PlatformKnown {
		wire.OS = &platform.OS
		wire.Architecture = &platform.Architecture
	}
	return marshalWire(wire)
}

// MarshalJSON emits null for the zero ruleset and the full object otherwise.
func (ruleset RulesetRef) MarshalJSON() ([]byte, error) {
	if ruleset == (RulesetRef{}) {
		return []byte("null"), nil
	}
	type wireRuleset struct {
		Path    string     `json:"path"`
		Hash    SourceHash `json:"hash"`
		Version string     `json:"version"`
	}
	return marshalWire(wireRuleset{Path: ruleset.Path, Hash: ruleset.Hash, Version: ruleset.Version})
}
