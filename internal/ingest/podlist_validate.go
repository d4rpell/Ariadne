package ingest

import (
	contract "github.com/d4rpell/Ariadne/pkg/evidence"
)

// Per-Pod semantic validation of ADR-0025 A.7.2, A.7.3, A.8 and A.10.3 §8. The
// source was already admitted structurally; every item ends either accepted,
// possibly with incomplete evidence, or rejected with exactly one primary
// reason, chosen by the field order of the contract and never by the smallest
// offset. A rejected item never becomes a subject, and an accepted item is never
// repaired with defaults.

// podListClasses is the canonical category order of the profile.
var podListClasses = []contract.ContainerClass{
	contract.ContainerRegular,
	contract.ContainerInit,
	contract.ContainerEphemeral,
}

// podListOutcome is the result of validating one items element. A rejected
// element keeps its primary reason; an accepted one keeps the subject. The
// verified UID is recorded as soon as it passes its own field validation,
// because the duplicate pass must invalidate every occurrence that carried a
// usable UID, even the ones rejected for another defect.
type podListOutcome struct {
	subject    PodSubject
	accepted   bool
	code       PodListDiagnosticCode
	offset     uint64
	itemIndex  int
	uid        string
	uidOffset  uint64
	uidUsable  bool
	nameOffset uint64
}

// reject marks one Pod as rejected with its primary reason.
func (outcome podListOutcome) reject(code PodListDiagnosticCode, offset uint64) podListOutcome {
	outcome.accepted = false
	outcome.code = code
	outcome.offset = offset
	return outcome
}

// validatePodListElement validates one Pod element. The checks follow the field
// order of A.3.3: identity, declared namespace, metadata context, spec
// categories, status categories. A status without its declaration, a repeated
// name inside a category and an ambiguous state reject the Pod, never the
// source.
func validatePodListElement(element podListValue, itemIndex int, namespace string) podListOutcome {
	outcome := podListOutcome{itemIndex: itemIndex}
	subject := PodSubject{
		ItemIndex:        itemIndex,
		StartByte:        element.Offset,
		EndByte:          element.End,
		SpecPresent:      map[contract.ContainerClass]bool{},
		Statuses:         map[contract.ContainerClass]bool{},
		SpecContainers:   map[contract.ContainerClass][]PodContainerSpec{},
		StatusContainers: map[contract.ContainerClass][]PodContainerStatus{},
	}

	// Identity first: uid, declared namespace and name, in that order.
	metadata, present := element.member("metadata")
	if !present {
		return outcome.reject(PodListCodeMissingRequiredField, element.Offset)
	}
	if metadata.Kind != podListValueObject {
		return outcome.reject(PodListCodeInvalidFieldType, metadata.Offset)
	}
	uidValue, present := metadata.member("uid")
	if !present {
		return outcome.reject(PodListCodeMissingRequiredField, metadata.Offset)
	}
	uid, code := podListRequiredIdentifier(uidValue)
	if code != "" {
		return outcome.reject(code, uidValue.Offset)
	}
	outcome.uid = uid
	outcome.uidOffset = uidValue.Offset
	outcome.uidUsable = true

	namespaceValue, present := metadata.member("namespace")
	if !present {
		return outcome.reject(PodListCodeMissingRequiredField, metadata.Offset)
	}
	declaredNamespace, code := podListRequiredIdentifier(namespaceValue)
	if code != "" {
		return outcome.reject(code, namespaceValue.Offset)
	}
	if declaredNamespace != namespace {
		return outcome.reject(PodListCodeNamespaceMismatch, namespaceValue.Offset)
	}
	nameValue, present := metadata.member("name")
	if !present {
		return outcome.reject(PodListCodeMissingRequiredField, metadata.Offset)
	}
	name, code := podListRequiredIdentifier(nameValue)
	if code != "" {
		return outcome.reject(code, nameValue.Offset)
	}
	outcome.nameOffset = nameValue.Offset

	subject.UID = uid
	subject.Namespace = declaredNamespace
	subject.Name = name

	spec, present := element.member("spec")
	if !present {
		return outcome.reject(PodListCodeMissingRequiredField, element.Offset)
	}
	if spec.Kind != podListValueObject {
		return outcome.reject(PodListCodeInvalidFieldType, spec.Offset)
	}
	status, statusPresent := element.member("status")
	if statusPresent && status.Kind != podListValueObject {
		return outcome.reject(PodListCodeInvalidFieldType, status.Offset)
	}

	// Repetitions and associations, once the structures they need were checked:
	// container names inside each category, status names inside their own array
	// and a status without its declaration. Only the names are read here, so a
	// defect in a remaining field never hides a repetition.
	specNames := map[contract.ContainerClass][]string{}
	for _, class := range podListClasses {
		array, present := spec.member(podListSpecArray(class))
		if !present {
			continue
		}
		if array.Kind != podListValueArray {
			// An omitted category is unobserved; null is a type error.
			return outcome.reject(PodListCodeInvalidFieldType, array.Offset)
		}
		subject.SpecPresent[class] = true
		names, code, offset := podListSpecNames(array)
		if code != "" {
			return outcome.reject(code, offset)
		}
		specNames[class] = names
	}
	statusArrayOffsets := map[contract.ContainerClass]uint64{}
	for _, class := range podListClasses {
		if !statusPresent {
			continue
		}
		array, present := status.member(podListStatusArray(class))
		if !present {
			continue
		}
		if array.Kind != podListValueArray {
			return outcome.reject(PodListCodeInvalidFieldType, array.Offset)
		}
		subject.Statuses[class] = true
		statusArrayOffsets[class] = array.Offset
		if _, code, offset := podListStatusNames(array, specNames[class]); code != "" {
			return outcome.reject(code, offset)
		}
	}

	// The remaining fields, in the field order of A.3.3: metadata context first,
	// then the restrictions of each spec and status element.
	if value, present := metadata.member("resourceVersion"); present {
		version, code := podListOptionalIdentifier(value)
		if code != "" {
			return outcome.reject(code, value.Offset)
		}
		subject.ResourceVersion = version
	}
	if value, present := metadata.member("ownerReferences"); present {
		references, code, offset := validatePodListOwners(value)
		if code != "" {
			return outcome.reject(code, offset)
		}
		subject.OwnerReferences = references
	}
	for _, class := range podListClasses {
		array, present := spec.member(podListSpecArray(class))
		if !present {
			continue
		}
		containers, code, offset := podListSpecFields(array, class, specNames[class])
		if code != "" {
			return outcome.reject(code, offset)
		}
		subject.SpecContainers[class] = containers
	}
	for _, class := range podListClasses {
		if !statusPresent {
			continue
		}
		array, present := status.member(podListStatusArray(class))
		if !present {
			continue
		}
		statuses, code, offset := podListStatusFields(array, class)
		if code != "" {
			return outcome.reject(code, offset)
		}
		subject.StatusContainers[class] = statuses
	}

	missingStatusOffset := element.Offset
	if statusPresent {
		missingStatusOffset = status.Offset
	}
	subject.Diagnostics = podListIncompleteness(subject, spec.Offset, missingStatusOffset, statusArrayOffsets)
	outcome.subject = subject
	outcome.accepted = true
	return outcome
}

// podListSpecNames reads the container names of one spec category and refuses a
// name repeated inside it. Only identity is read here: the remaining fields of a
// container are validated after the repetitions and associations of the Pod.
func podListSpecNames(array podListValue) ([]string, PodListDiagnosticCode, uint64) {
	names := make([]string, 0, len(array.Elements))
	seen := map[string]bool{}
	for _, element := range array.Elements {
		if element.Kind != podListValueObject {
			return nil, PodListCodeInvalidFieldType, element.Offset
		}
		nameValue, present := element.member("name")
		if !present {
			return nil, PodListCodeMissingRequiredField, element.Offset
		}
		name, code := podListRequiredIdentifier(nameValue)
		if code != "" {
			return nil, code, nameValue.Offset
		}
		if seen[name] {
			return nil, PodListCodeDuplicateContainer, nameValue.Offset
		}
		seen[name] = true
		names = append(names, name)
	}
	return names, "", 0
}

// podListStatusNames reads the status names of one category and refuses a repeat
// inside its own array and a status whose declaration is missing from its own
// category: the join is by name and never by index or across classes.
func podListStatusNames(array podListValue, declared []string) ([]string, PodListDiagnosticCode, uint64) {
	declaredNames := make(map[string]bool, len(declared))
	for _, name := range declared {
		declaredNames[name] = true
	}
	names := make([]string, 0, len(array.Elements))
	seen := map[string]bool{}
	for _, element := range array.Elements {
		if element.Kind != podListValueObject {
			return nil, PodListCodeInvalidFieldType, element.Offset
		}
		nameValue, present := element.member("name")
		if !present {
			return nil, PodListCodeMissingRequiredField, element.Offset
		}
		name, code := podListRequiredIdentifier(nameValue)
		if code != "" {
			return nil, code, nameValue.Offset
		}
		if seen[name] {
			return nil, PodListCodeDuplicateStatus, nameValue.Offset
		}
		seen[name] = true
		if !declaredNames[name] {
			return nil, PodListCodeOrphanStatus, nameValue.Offset
		}
		names = append(names, name)
	}
	return names, "", 0
}

// podListSpecFields validates the remaining fields of one spec category: the
// optional requested reference of each declared container.
func podListSpecFields(array podListValue, class contract.ContainerClass, names []string) ([]PodContainerSpec, PodListDiagnosticCode, uint64) {
	containers := make([]PodContainerSpec, 0, len(array.Elements))
	for index, element := range array.Elements {
		container := PodContainerSpec{Class: class, Name: names[index], Offset: element.Offset}
		if value, present := element.member("image"); present {
			image, code := podListOptionalReference(value)
			if code != "" {
				return nil, code, value.Offset
			}
			container.Image = image
			container.ImageOff = value.Offset
		}
		containers = append(containers, container)
	}
	return containers, "", 0
}

// podListStatusFields validates the remaining fields of one status category:
// imageID, the status image, ready, state and restartCount.
func podListStatusFields(array podListValue, class contract.ContainerClass) ([]PodContainerStatus, PodListDiagnosticCode, uint64) {
	statuses := make([]PodContainerStatus, 0, len(array.Elements))
	for _, element := range array.Elements {
		nameValue, _ := element.member("name")
		name, _ := podListRequiredIdentifier(nameValue)
		status := PodContainerStatus{Class: class, Name: name, Offset: element.Offset}
		if value, present := element.member("imageID"); present {
			imageID, code := podListOptionalReference(value)
			if code != "" {
				return nil, code, value.Offset
			}
			status.ImageID = imageID
			status.ImageIDOff = value.Offset
		}
		if value, present := element.member("image"); present {
			image, code := podListOptionalReference(value)
			if code != "" {
				return nil, code, value.Offset
			}
			status.Image = image
		}
		if value, present := element.member("ready"); present {
			ready, code := podListOptionalBool(value)
			if code != "" {
				return nil, code, value.Offset
			}
			status.Ready = ready
		}
		if value, present := element.member("state"); present {
			if value.Kind != podListValueObject {
				return nil, PodListCodeInvalidFieldType, value.Offset
			}
			state, code, offset := podListStateCategory(value)
			if code != "" {
				return nil, code, offset
			}
			status.State = state
			status.StatePresent = true
		}
		if value, present := element.member("restartCount"); present {
			count, code := podListRestartCount(value)
			if code != "" {
				return nil, code, value.Offset
			}
			status.Restart = PodOptionalInt{Present: PresenceValue, Value: count}
		}
		statuses = append(statuses, status)
	}
	return statuses, "", 0
}

// validatePodListOwners validates the owner references array. The references are
// context: they are never followed, resolved or turned into an owner chain.
func validatePodListOwners(array podListValue) ([]PodOwnerReference, PodListDiagnosticCode, uint64) {
	if array.Kind != podListValueArray {
		return nil, PodListCodeInvalidFieldType, array.Offset
	}
	references := make([]PodOwnerReference, 0, len(array.Elements))
	for _, element := range array.Elements {
		if element.Kind != podListValueObject {
			return nil, PodListCodeInvalidFieldType, element.Offset
		}
		reference := PodOwnerReference{Offset: element.Offset}
		for _, field := range []string{"apiVersion", "kind", "name", "uid"} {
			value, present := element.member(field)
			if !present {
				return nil, PodListCodeMissingRequiredField, element.Offset
			}
			text, code := podListRequiredIdentifier(value)
			if code != "" {
				return nil, code, value.Offset
			}
			switch field {
			case "apiVersion":
				reference.APIVersion = text
			case "kind":
				reference.Kind = text
			case "name":
				reference.Name = text
			case "uid":
				reference.UID = text
			}
		}
		for _, field := range []string{"controller", "blockOwnerDeletion"} {
			value, present := element.member(field)
			if !present {
				continue
			}
			flag, code := podListOptionalBool(value)
			if code != "" {
				return nil, code, value.Offset
			}
			if field == "controller" {
				reference.OwnerController = flag
			} else {
				reference.BlockOwnerDeletion = flag
			}
		}
		references = append(references, reference)
	}
	return references, "", 0
}

// podListIncompleteness derives the local diagnostics of one accepted Pod: the
// categories that were not observed, the status coverage that stayed incomplete
// and the requested references the sanitized export did not carry. The anchors
// are the ones of A.10.1.
func podListIncompleteness(subject PodSubject, specOffset, missingStatusOffset uint64, statusArrayOffsets map[contract.ContainerClass]uint64) []PodListDiagnostic {
	diagnostics := []PodListDiagnostic{}
	// One pass per class, in canonical order: the diagnostics of a Pod are
	// ordered by class, then by position and code, never grouped by code.
	for _, class := range podListClasses {
		if !subject.SpecPresent[class] {
			diagnostics = append(diagnostics, PodListDiagnostic{Code: PodListCodeCategoryUnobserved, ByteOffset: specOffset})
			continue
		}
		if !podListCategoryComplete(subject, class) {
			offset := missingStatusOffset
			if subject.Statuses[class] {
				offset = statusArrayOffsets[class]
			}
			diagnostics = append(diagnostics, PodListDiagnostic{Code: PodListCodeStatusUnobserved, ByteOffset: offset})
		}
		for _, container := range subject.SpecContainers[class] {
			if container.Image.Present == PresenceValue {
				continue
			}
			offset := container.Offset
			if container.Image.Present == PresenceEmpty {
				offset = container.ImageOff
			}
			diagnostics = append(diagnostics, PodListDiagnostic{Code: PodListCodeRequestedImageUnavailable, ByteOffset: offset})
		}
	}
	return diagnostics
}

// podListCategoryComplete reports whether one category was observed with both
// arrays explicitly present and every declared container joined by name.
func podListCategoryComplete(subject PodSubject, class contract.ContainerClass) bool {
	if !subject.Statuses[class] {
		return false
	}
	joined := map[string]bool{}
	for _, status := range subject.StatusContainers[class] {
		joined[status.Name] = true
	}
	for _, container := range subject.SpecContainers[class] {
		if !joined[container.Name] {
			return false
		}
	}
	return true
}

func podListSpecArray(class contract.ContainerClass) string {
	switch class {
	case contract.ContainerInit:
		return "initContainers"
	case contract.ContainerEphemeral:
		return "ephemeralContainers"
	default:
		return "containers"
	}
}

func podListStatusArray(class contract.ContainerClass) string {
	switch class {
	case contract.ContainerInit:
		return "initContainerStatuses"
	case contract.ContainerEphemeral:
		return "ephemeralContainerStatuses"
	default:
		return "containerStatuses"
	}
}
