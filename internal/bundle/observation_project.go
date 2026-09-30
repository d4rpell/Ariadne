package bundle

import (
	"github.com/d4rpell/Ariadne/internal/identity"
	"github.com/d4rpell/Ariadne/internal/normalize"
	contract "github.com/d4rpell/Ariadne/pkg/evidence"
)

// Observation projection (ADR-0025 A.9): one bundle per accepted subject, one
// image per container, and exactly one evidence type emitted by this adapter:
// container_status.image_id. Everything else the source declared is kept as
// internal context and is never promoted to a new evidence type under wire 0.2.

// observationImages projects the images of one subject. A collided key is
// omitted; the rest of the subject is preserved.
func observationImages(subject normalize.ObservationSubject, result normalize.ObservationResult, observedAt *contract.Timestamp) ([]contract.ImageIdentity, []ObservationOmission) {
	images := make([]contract.ImageIdentity, 0, len(subject.Containers))
	omitted := []ObservationOmission{}
	for _, container := range subject.Containers {
		if observationCollided(subject, container.Class, container.Name) {
			omitted = append(omitted, ObservationOmission{
				Key:    observationKey{ContainerClass: container.Class, ContainerName: contract.ContainerName(container.Name)},
				Reason: OmissionCollision,
				// The locator of the observation that was withheld, so the
				// omission stays traceable to the original document.
				Locator: observationOmissionLocator(subject, container),
			})
			continue
		}
		image := contract.ImageIdentity{
			ContainerClass: container.Class,
			ContainerName:  contract.ContainerName(container.Name),
			// A PodList never proves a manifest digest or a platform: both stay
			// at their conservative, not-promoted values (A.8.3).
			Platform: contract.Platform{Status: contract.PlatformUnknown},
		}
		if container.Image != nil {
			requested := contract.RequestedImage(observationRequestedLiteral(*container.Image))
			image.RequestedImage = &requested
		}
		if container.ImageID != nil && *container.ImageID != "" {
			raw := contract.RawImageID(*container.ImageID)
			image.RawImageID = &raw
		}
		image.ObservedAt = observedAt
		images = append(images, image)
	}
	return images, omitted
}

// observationEvidence projects the evidence items of one subject: one
// container_status.image_id item per non-empty imageID, with the exact value,
// the exact preimage and the original locator.
func observationEvidence(subject normalize.ObservationSubject, result normalize.ObservationResult, observedAt *contract.Timestamp) []contract.EvidenceItem {
	evidence := []contract.EvidenceItem{}
	for _, container := range subject.Containers {
		if observationCollided(subject, container.Class, container.Name) {
			continue
		}
		if container.ImageID == nil || *container.ImageID == "" {
			continue
		}
		value := *container.ImageID
		locator := "items[" + itoaForBundle(subject.ItemIndex) + "]." + classArrayLocator(container.Class, container.StatusIndex) + ".imageID"
		valueHash := contract.ValueHash(HashValue(value))
		item := contract.EvidenceItem{
			Type:       "container_status.image_id",
			Source:     result.Source.Name,
			SourceHash: result.Source.Hash,
			Locator:    contract.SourceLocator(locator),
			Value:      &value,
			ValueHash:  &valueHash,
			ObservedAt: observedAt,
			Confidence: contract.ProvenanceObserved,
			Scope: contract.Scope{
				SubjectUID:    subject.UID,
				ContainerName: contract.ContainerName(container.Name),
			},
			Warnings: []contract.Warning{},
		}
		evidence = append(evidence, item)
	}
	return evidence
}

func classArrayLocator(class contract.ContainerClass, index int) string {
	return "status." + statusArrayName(class) + "[" + itoaForBundle(index) + "]"
}

func statusArrayName(class contract.ContainerClass) string {
	switch class {
	case contract.ContainerInit:
		return "initContainerStatuses"
	case contract.ContainerEphemeral:
		return "ephemeralContainerStatuses"
	default:
		return "containerStatuses"
	}
}

func itoaForBundle(value int) string {
	if value == 0 {
		return "0"
	}
	digits := []byte{}
	negative := value < 0
	if negative {
		value = -value
	}
	for value > 0 {
		digits = append([]byte{byte('0' + value%10)}, digits...)
		value /= 10
	}
	if negative {
		return "-" + string(digits)
	}
	return string(digits)
}

// observationBindingsToIdentity converts one normalized subject into the
// explicit identity bindings of the existing resolver. Only admitted facts are
// copied: the raw image ID is preserved verbatim and a guaranteed digest is
// never set by this adapter.
func observationBindingsToIdentity(result normalize.ObservationResult, subjectIndex int) ([]identity.ImageBinding, error) {
	bindings, err := normalize.ObservationBindings(result, subjectIndex)
	if err != nil {
		return nil, err
	}
	converted := make([]identity.ImageBinding, 0, len(bindings))
	for _, binding := range bindings {
		image := identity.ImageBinding{
			Key:            binding.Key,
			InputKind:      identity.InputContainerObservation,
			SourceName:     binding.SourceName,
			SourceHash:     binding.SourceHash,
			Locator:        binding.Locator,
			ObservedAt:     binding.ObservedAt,
			Platform:       contract.PlatformUnknown,
			RawImageID:     binding.RawImageID,
			RequestedImage: binding.RequestedImage,
		}
		converted = append(converted, image)
	}
	return converted, nil
}

// observationOmissionLocator returns the path that actually exists in the
// document for one omitted observation: the observed status field when it was
// present, the declared name of the container otherwise, and nothing when
// neither position is known. It never names an optional field the source did
// not carry.
func observationOmissionLocator(subject normalize.ObservationSubject, container normalize.ObservationContainer) contract.SourceLocator {
	if container.StatusPresent && container.StatusIndex >= 0 && container.ImageID != nil {
		return contract.SourceLocator("items[" + itoaForBundle(subject.ItemIndex) + "]." + classArrayLocator(container.Class, container.StatusIndex) + ".imageID")
	}
	if container.SpecPresent && container.SpecIndex >= 0 {
		return contract.SourceLocator("items[" + itoaForBundle(subject.ItemIndex) + "]." + specArrayLocator(container.Class, container.SpecIndex) + ".name")
	}
	return ""
}

// specArrayLocator renders the position of one declaration inside its class.
func specArrayLocator(class contract.ContainerClass, index int) string {
	name := "containers"
	switch class {
	case contract.ContainerInit:
		name = "initContainers"
	case contract.ContainerEphemeral:
		name = "ephemeralContainers"
	}
	return "spec." + name + "[" + itoaForBundle(index) + "]"
}
