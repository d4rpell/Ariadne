package bundle

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"reflect"

	canonical "github.com/d4rpell/Ariadne/internal/evidence"
	contract "github.com/d4rpell/Ariadne/pkg/evidence"
)

// Artifacts are the three deliverables of ADR-0006 §5: the complete envelope,
// the exact bytes of the hash projection and the external digest of those bytes.
type Artifacts struct {
	Envelope  []byte
	HashInput []byte
	Hash      string
}

// Destinations are the sinks of the three artifacts. The caller decides where
// they go: this package never opens a path, creates a directory or promises
// atomicity across the three writers.
type Destinations struct {
	Envelope  io.Writer
	HashInput io.Writer
	Hash      io.Writer
}

var (
	errHashMismatch        = errors.New("bundle: canonical hash does not match the reconstructed projection")
	errEnvelopeUnusable    = errors.New("bundle: canonical envelope cannot be projected")
	errDestinationRequired = errors.New("bundle: destination writer is required")
	errTransportFailed     = errors.New("bundle: artifact transport failed")
	errTransportIncomplete = errors.New("bundle: artifact transport is incomplete")
)

// Encode builds and cross-checks the three artifacts. The digest is the one
// internal/evidence computes over its own projection; rebuilding that projection
// from the canonical envelope and hashing it must reproduce the same value, and
// a mismatch stops the delivery instead of replacing the expected hash
// (ADR-0012 §2). An invalid bundle yields no bytes and no hash.
func Encode(bundle contract.Bundle) (Artifacts, error) {
	envelope, err := canonical.CanonicalJSON(bundle)
	if err != nil {
		return Artifacts{}, err
	}
	hash, err := canonical.HashCanonicalJSON(bundle)
	if err != nil {
		return Artifacts{}, err
	}
	projection, err := hashInputFromEnvelope(envelope)
	if err != nil {
		return Artifacts{}, err
	}
	if computed := HashSource(projection); string(computed) != hash {
		return Artifacts{}, errHashMismatch
	}
	return Artifacts{Envelope: envelope, HashInput: projection, Hash: hash}, nil
}

// Write encodes every artifact before the first write and then transports them.
// A failure can leave a partial delivery: it is reported as such and never
// announced as a complete one.
func Write(bundle contract.Bundle, destinations Destinations) error {
	if isNilWriter(destinations.Envelope) || isNilWriter(destinations.HashInput) || isNilWriter(destinations.Hash) {
		return errDestinationRequired
	}
	artifacts, err := Encode(bundle)
	if err != nil {
		return err
	}
	deliveries := []struct {
		name   string
		writer io.Writer
		data   []byte
	}{
		{name: "envelope", writer: destinations.Envelope, data: artifacts.Envelope},
		{name: "hash input", writer: destinations.HashInput, data: artifacts.HashInput},
		{name: "hash", writer: destinations.Hash, data: []byte(artifacts.Hash + "\n")},
	}
	for _, delivery := range deliveries {
		if err := writeArtifact(delivery.writer, delivery.data); err != nil {
			return fmt.Errorf("bundle: %s: %w", delivery.name, err)
		}
	}
	return nil
}

func writeArtifact(writer io.Writer, data []byte) error {
	written, err := writer.Write(data)
	if err != nil {
		return errTransportFailed
	}
	if written != len(data) {
		return errTransportIncomplete
	}
	return nil
}

// isNilWriter reports a missing destination, including an interface that holds a
// typed nil. A bad writer is refused here instead of panicking later inside a
// method call.
func isNilWriter(writer io.Writer) bool {
	if writer == nil {
		return true
	}
	value := reflect.ValueOf(writer)
	switch value.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Ptr, reflect.Slice:
		return value.IsNil()
	}
	return false
}

// envelopeSections and provenanceSections read the already canonical envelope.
// Every member keeps its canonical bytes, so the reconstruction never reorders
// arrays or reinterprets strings.
type envelopeSections struct {
	SchemaVersion            json.RawMessage `json:"schema_version"`
	Subject                  json.RawMessage `json:"subject"`
	Images                   json.RawMessage `json:"images"`
	Evidence                 json.RawMessage `json:"evidence"`
	ObservedContainerClasses json.RawMessage `json:"observed_container_classes"`
	Provenance               json.RawMessage `json:"provenance"`
}

type provenanceSections struct {
	Ruleset         json.RawMessage `json:"ruleset"`
	Inputs          json.RawMessage `json:"inputs"`
	APIScope        json.RawMessage `json:"api_scope"`
	Coverage        json.RawMessage `json:"coverage"`
	Completeness    json.RawMessage `json:"completeness"`
	Consistency     json.RawMessage `json:"consistency"`
	RedactionPolicy json.RawMessage `json:"redaction_policy"`
	Warnings        json.RawMessage `json:"warnings"`
	Errors          json.RawMessage `json:"errors"`
}

type rulesetSections struct {
	Path    json.RawMessage `json:"path"`
	Hash    json.RawMessage `json:"hash"`
	Version json.RawMessage `json:"version"`
}

type projectionRuleset struct {
	Path json.RawMessage `json:"path"`
	Hash json.RawMessage `json:"hash"`
}

type projectionDocument struct {
	SchemaVersion            json.RawMessage      `json:"schema_version"`
	Subject                  json.RawMessage      `json:"subject"`
	Images                   json.RawMessage      `json:"images"`
	Evidence                 json.RawMessage      `json:"evidence"`
	ObservedContainerClasses json.RawMessage      `json:"observed_container_classes"`
	Provenance               projectionProvenance `json:"provenance"`
}

type projectionProvenance struct {
	Ruleset         json.RawMessage `json:"ruleset"`
	Inputs          json.RawMessage `json:"inputs"`
	APIScope        json.RawMessage `json:"api_scope"`
	Coverage        json.RawMessage `json:"coverage"`
	Completeness    json.RawMessage `json:"completeness"`
	Consistency     json.RawMessage `json:"consistency"`
	RedactionPolicy json.RawMessage `json:"redaction_policy"`
	Warnings        json.RawMessage `json:"warnings"`
	Errors          json.RawMessage `json:"errors"`
}

// hashInputFromEnvelope rebuilds the projection of ADR-0006 §1(a) from the
// canonical envelope: the five shared sections plus the provenance claims, with
// ruleset reduced to path and hash and the operational metadata left out. It is
// private on purpose: an arbitrary document is not an admissible input, only an
// envelope this package can also validate.
func hashInputFromEnvelope(envelope []byte) ([]byte, error) {
	var sections envelopeSections
	if err := json.Unmarshal(envelope, &sections); err != nil {
		return nil, errEnvelopeUnusable
	}
	shared := []json.RawMessage{
		sections.SchemaVersion, sections.Subject, sections.Images,
		sections.Evidence, sections.ObservedContainerClasses, sections.Provenance,
	}
	for _, raw := range shared {
		if len(raw) == 0 {
			return nil, errEnvelopeUnusable
		}
	}
	var run provenanceSections
	if err := json.Unmarshal(sections.Provenance, &run); err != nil {
		return nil, errEnvelopeUnusable
	}
	for _, raw := range []json.RawMessage{
		run.Ruleset, run.Inputs, run.APIScope, run.Coverage, run.Completeness,
		run.Consistency, run.RedactionPolicy, run.Warnings, run.Errors,
	} {
		if len(raw) == 0 {
			return nil, errEnvelopeUnusable
		}
	}
	ruleset, err := projectRuleset(run.Ruleset)
	if err != nil {
		return nil, err
	}
	return encodeProjection(projectionDocument{
		SchemaVersion:            sections.SchemaVersion,
		Subject:                  sections.Subject,
		Images:                   sections.Images,
		Evidence:                 sections.Evidence,
		ObservedContainerClasses: sections.ObservedContainerClasses,
		Provenance: projectionProvenance{
			Ruleset:         ruleset,
			Inputs:          run.Inputs,
			APIScope:        run.APIScope,
			Coverage:        run.Coverage,
			Completeness:    run.Completeness,
			Consistency:     run.Consistency,
			RedactionPolicy: run.RedactionPolicy,
			Warnings:        run.Warnings,
			Errors:          run.Errors,
		},
	})
}

// projectRuleset keeps null as null and, when the ruleset exists, drops only its
// operational version: changing that version does not change the bundle hash.
func projectRuleset(raw json.RawMessage) (json.RawMessage, error) {
	if string(raw) == "null" {
		return json.RawMessage("null"), nil
	}
	var ruleset rulesetSections
	if err := json.Unmarshal(raw, &ruleset); err != nil {
		return nil, errEnvelopeUnusable
	}
	if len(ruleset.Path) == 0 || len(ruleset.Hash) == 0 {
		return nil, errEnvelopeUnusable
	}
	encoded, err := encodeProjection(projectionRuleset{Path: ruleset.Path, Hash: ruleset.Hash})
	if err != nil {
		return nil, err
	}
	return json.RawMessage(encoded), nil
}

// encodeProjection writes a single UTF-8 JSON document without BOM, without
// whitespace outside tokens, without a trailing newline and without HTML
// escaping, the same byte grammar internal/evidence uses.
func encodeProjection(document any) ([]byte, error) {
	var buffer bytes.Buffer
	encoder := json.NewEncoder(&buffer)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(document); err != nil {
		return nil, errEnvelopeUnusable
	}
	return bytes.TrimSuffix(buffer.Bytes(), []byte("\n")), nil
}
