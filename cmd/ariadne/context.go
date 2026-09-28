package main

import (
	"time"

	"github.com/d4rpell/Ariadne/internal/evaluator"
	"github.com/d4rpell/Ariadne/internal/rulepack"
	contract "github.com/d4rpell/Ariadne/pkg/evidence"
)

// Decoder of `--context` (ADR-0023 §4.2). It admits exactly one JSON object with
// the three declared members and builds the Request pieces from it. Every member
// is required — an omitted one is never repaired into null — and the
// representational rules of H, T and N are checked here; the semantic rules of
// class, profile, pins, TTL and cardinality stay with the evaluator, which keeps
// its ratified precedence untouched.
type contextDocument struct {
	target    evaluator.Target
	admission rulepack.AdmissionContext
	domain    *evaluator.DomainContext
}

func decodeContext(data []byte) (contextDocument, error) {
	root, err := decodeObject(data)
	if err != nil {
		return contextDocument{}, err
	}
	if err := root.expectExact("target", "admission", "domain"); err != nil {
		return contextDocument{}, err
	}
	target, err := decodeContextTarget(root)
	if err != nil {
		return contextDocument{}, err
	}
	admission, err := decodeContextAdmission(root)
	if err != nil {
		return contextDocument{}, err
	}
	domain, err := decodeContextDomain(root)
	if err != nil {
		return contextDocument{}, err
	}
	return contextDocument{target: target, admission: admission, domain: domain}, nil
}

func decodeContextTarget(root object) (evaluator.Target, error) {
	target, err := root.object("target")
	if err != nil {
		return evaluator.Target{}, err
	}
	if err := target.expectExact(
		"subject_uid", "container_class", "container_name", "vulnerability_id",
		"source", "source_hash", "locator", "observed_at",
	); err != nil {
		return evaluator.Target{}, err
	}
	subjectUID, err := target.requiredString("subject_uid")
	if err != nil {
		return evaluator.Target{}, err
	}
	containerClass, err := target.requiredString("container_class")
	if err != nil {
		return evaluator.Target{}, err
	}
	containerName, err := target.requiredString("container_name")
	if err != nil {
		return evaluator.Target{}, err
	}
	vulnerabilityID, err := target.requiredString("vulnerability_id")
	if err != nil {
		return evaluator.Target{}, err
	}
	source, err := target.requiredString("source")
	if err != nil {
		return evaluator.Target{}, err
	}
	sourceHash, err := digestOf(target, "source_hash")
	if err != nil {
		return evaluator.Target{}, err
	}
	locator, err := target.requiredString("locator")
	if err != nil {
		return evaluator.Target{}, err
	}
	observedAt, err := timestampOf(target, "observed_at")
	if err != nil {
		return evaluator.Target{}, err
	}
	return evaluator.Target{
		SubjectUID:      contract.UID(subjectUID),
		ContainerClass:  contract.ContainerClass(containerClass),
		ContainerName:   contract.ContainerName(containerName),
		VulnerabilityID: vulnerabilityID,
		Source:          source,
		SourceHash:      contract.SourceHash(sourceHash),
		Locator:         contract.SourceLocator(locator),
		ObservedAt:      observedAt,
	}, nil
}

func decodeContextAdmission(root object) (rulepack.AdmissionContext, error) {
	admission, err := root.object("admission")
	if err != nil {
		return rulepack.AdmissionContext{}, err
	}
	if err := admission.expectExact(
		"evaluated_at", "expected_pack_id", "expected_pack_hash", "minimum_version", "previous",
	); err != nil {
		return rulepack.AdmissionContext{}, err
	}
	evaluatedAt, err := timestampOf(admission, "evaluated_at")
	if err != nil {
		return rulepack.AdmissionContext{}, err
	}
	expectedPackID, err := admission.requiredString("expected_pack_id")
	if err != nil {
		return rulepack.AdmissionContext{}, err
	}
	expectedPackHash, err := digestOf(admission, "expected_pack_hash")
	if err != nil {
		return rulepack.AdmissionContext{}, err
	}
	minimumVersion, err := admission.integer("minimum_version")
	if err != nil {
		return rulepack.AdmissionContext{}, err
	}
	var previous *rulepack.PreviousVersion
	if !admission.isNull("previous") {
		block, err := admission.object("previous")
		if err != nil {
			return rulepack.AdmissionContext{}, err
		}
		if err := block.expectExact("version", "hash"); err != nil {
			return rulepack.AdmissionContext{}, err
		}
		version, err := block.integer("version")
		if err != nil {
			return rulepack.AdmissionContext{}, err
		}
		hash, err := digestOf(block, "hash")
		if err != nil {
			return rulepack.AdmissionContext{}, err
		}
		previous = &rulepack.PreviousVersion{Version: version, Hash: hash}
	}
	return rulepack.AdmissionContext{
		EvaluatedAt:      evaluatedAt,
		ExpectedPackID:   expectedPackID,
		ExpectedPackHash: expectedPackHash,
		MinimumVersion:   minimumVersion,
		Previous:         previous,
	}, nil
}

func decodeContextDomain(root object) (*evaluator.DomainContext, error) {
	if root.isNull("domain") {
		return nil, nil
	}
	domain, err := root.object("domain")
	if err != nil {
		return nil, err
	}
	if err := domain.expectExact("maximum_evidence_age_seconds", "source_pins"); err != nil {
		return nil, err
	}
	maximumAge, err := domain.integer("maximum_evidence_age_seconds")
	if err != nil {
		return nil, err
	}
	rawPins, err := domain.array("source_pins")
	if err != nil {
		return nil, err
	}
	pins := make([]evaluator.SourcePin, 0, len(rawPins))
	for _, rawPin := range rawPins {
		pin, err := decodeSourcePin(rawPin)
		if err != nil {
			return nil, err
		}
		pins = append(pins, pin)
	}
	return &evaluator.DomainContext{
		MaximumEvidenceAgeSeconds: maximumAge,
		SourcePins:                pins,
	}, nil
}

func decodeSourcePin(raw []byte) (evaluator.SourcePin, error) {
	pin, err := decodeObject(raw)
	if err != nil {
		return evaluator.SourcePin{}, err
	}
	if err := pin.expectExact("role", "source", "source_hash", "advisory_id", "advisory_revision"); err != nil {
		return evaluator.SourcePin{}, err
	}
	role, err := pin.requiredString("role")
	if err != nil {
		return evaluator.SourcePin{}, err
	}
	source, err := pin.requiredString("source")
	if err != nil {
		return evaluator.SourcePin{}, err
	}
	sourceHash, err := digestOf(pin, "source_hash")
	if err != nil {
		return evaluator.SourcePin{}, err
	}
	advisoryID, err := pin.stringValue("advisory_id", true)
	if err != nil {
		return evaluator.SourcePin{}, err
	}
	advisoryRevision, err := pin.stringValue("advisory_revision", true)
	if err != nil {
		return evaluator.SourcePin{}, err
	}
	return evaluator.SourcePin{
		Role:             evaluator.SourceRole(role),
		Source:           source,
		SourceHash:       contract.SourceHash(sourceHash),
		AdvisoryID:       advisoryID,
		AdvisoryRevision: advisoryRevision,
	}, nil
}

// timestampOf reads one canonical timestamp: UTC, RFC3339Nano with Z, and never
// zero. The stored form must be exactly what the canonical format re-emits, so a
// non-canonical spelling is rejected instead of normalized.
func timestampOf(fields object, name string) (contract.Timestamp, error) {
	text, err := fields.requiredString(name)
	if err != nil {
		return contract.Timestamp{}, err
	}
	parsed, err := time.Parse(time.RFC3339Nano, text)
	if err != nil || parsed.Location() != time.UTC || parsed.Format(time.RFC3339Nano) != text {
		return contract.Timestamp{}, errStrictTimestamp
	}
	stamp, err := contract.NewTimestamp(parsed)
	if err != nil {
		return contract.Timestamp{}, errStrictTimestamp
	}
	return stamp, nil
}
