package normalize

import (
	"errors"

	"github.com/d4rpell/Ariadne/internal/identity"
	"github.com/d4rpell/Ariadne/internal/ingest"
	contract "github.com/d4rpell/Ariadne/pkg/evidence"
)

// NormalizePodList normalizes one admitted sanitized-PodList parse into
// per-subject observations (ADR-0025 A.11.1). It associates status with spec by
// name within the same class and never by position; it keeps every admitted
// context value; and it never fabricates an image, a digest, a platform or a
// finding. A source that was not admitted yields an error: no downstream stage
// may build a bundle from defaults.
func NormalizePodList(input ingest.PodListResult) (ObservationResult, error) {
	if input.Source == nil {
		return ObservationResult{}, errSourceNotAdmitted
	}
	if !input.Context.CaptureTermination.Valid() {
		return ObservationResult{}, errTerminationNotDeclared
	}

	if err := validatePodListInput(input); err != nil {
		return ObservationResult{}, err
	}

	result := ObservationResult{
		Source: ObservationSource{
			Name:      input.Source.Name,
			Hash:      input.Source.Hash,
			ByteCount: input.Source.ByteCount,
		},
		Namespace:    contract.Namespace(input.Context.Namespace),
		ClusterAlias: contract.ClusterAlias(input.Context.ClusterAlias),
		Termination:  input.Context.CaptureTermination,
		Subjects:     make([]ObservationSubject, 0, len(input.Subjects)),
	}
	if !input.Context.ObservedAt.IsZero() {
		observedAt, err := contract.NewTimestamp(input.Context.ObservedAt)
		if err != nil {
			return ObservationResult{}, errObservedAt
		}
		result.ObservedAt = &observedAt
	} else {
		return ObservationResult{}, errObservedAt
	}
	result.TotalItems = 0
	if input.TotalItems != nil {
		result.TotalItems = *input.TotalItems
	}
	result.RejectedItems = input.Rejected

	for _, rejection := range input.Rejections {
		index := rejection.ItemIndex
		result.GlobalDiagnostics = append(result.GlobalDiagnostics, ObservationDiagnostic{
			Code:      string(rejection.Code),
			Offset:    rejection.Offset,
			ItemIndex: &index,
		})
	}
	for _, diagnostic := range input.Diagnostics {
		result.GlobalDiagnostics = append(result.GlobalDiagnostics, ObservationDiagnostic{
			Code:      string(diagnostic.Code),
			Offset:    diagnostic.ByteOffset,
			ItemIndex: copyItemIndex(diagnostic.ItemIndex),
			Locator:   diagnostic.FieldLocator,
		})
	}

	for _, subject := range input.Subjects {
		normalized := normalizeSubject(subject)
		result.Subjects = append(result.Subjects, normalized)
	}
	return result, nil
}

var (
	errSourceNotAdmitted      = errors.New("normalize: podlist source was not admitted")
	errTerminationNotDeclared = errors.New("normalize: capture termination is not declared")
	errObservedAt             = errors.New("normalize: observation time is required")
	errItemAccounting         = errors.New("normalize: item accounting is not coherent")
	errDiagnosticIncoherent   = errors.New("normalize: diagnostic is outside the closed catalog or locator grammar")
	errSubjectIncoherent      = errors.New("normalize: subject is not coherent with its own declarations")
)

// normalizeSubject builds one subject observation: containers joined by name
// within their class, context preserved, collisions and conflicts detected.
func normalizeSubject(subject ingest.PodSubject) ObservationSubject {
	normalized := ObservationSubject{
		ItemIndex:               subject.ItemIndex,
		StartByte:               subject.StartByte,
		EndByte:                 subject.EndByte,
		UID:                     contract.UID(subject.UID),
		Namespace:               contract.Namespace(subject.Namespace),
		Name:                    subject.Name,
		ResourceVersion:         subject.ResourceVersion.Value,
		ResourceVersionPresence: subject.ResourceVersion.Present,
		Containers:              []ObservationContainer{},
		CategoriesObserved:      map[contract.ContainerClass]bool{},
		CategoriesComplete:      map[contract.ContainerClass]bool{},
		CollidedClasses:         map[string][]contract.ContainerClass{},
	}
	for _, owner := range subject.OwnerReferences {
		reference := ObservationOwnerReference{
			APIVersion: owner.APIVersion,
			Kind:       owner.Kind,
			Name:       owner.Name,
			UID:        owner.UID,
			Offset:     owner.Offset,
		}
		if owner.OwnerController.Present == ingest.PresenceValue {
			value := owner.OwnerController.Value
			reference.Controller = &value
		}
		if owner.BlockOwnerDeletion.Present == ingest.PresenceValue {
			value := owner.BlockOwnerDeletion.Value
			reference.BlockOwner = &value
		}
		normalized.OwnerReferences = append(normalized.OwnerReferences, reference)
	}
	for _, diagnostic := range subject.Diagnostics {
		normalized.Diagnostics = append(normalized.Diagnostics, ObservationDiagnostic{
			Code:      string(diagnostic.Code),
			Offset:    diagnostic.ByteOffset,
			ItemIndex: copyItemIndex(diagnostic.ItemIndex),
			Locator:   diagnostic.FieldLocator,
		})
	}

	for _, class := range []contract.ContainerClass{contract.ContainerRegular, contract.ContainerInit, contract.ContainerEphemeral} {
		specPresent := subject.SpecPresent[class]
		statusPresent := subject.Statuses[class]
		if specPresent {
			normalized.CategoriesObserved[class] = true
		}
		specContainers := subject.SpecContainers[class]
		statusContainers := subject.StatusContainers[class]

		statusByName := make(map[string]struct {
			status *ingest.PodContainerStatus
			index  int
		}, len(statusContainers))
		for index := range statusContainers {
			status := &statusContainers[index]
			statusByName[status.Name] = struct {
				status *ingest.PodContainerStatus
				index  int
			}{status: status, index: index}
		}

		containers := make([]ObservationContainer, 0, len(specContainers))
		for specIndex, spec := range specContainers {
			container := ObservationContainer{
				Class:       class,
				Name:        spec.Name,
				SpecIndex:   specIndex,
				StatusIndex: -1,
				SpecPresent: true,
				SpecOffset:  spec.Offset,
				ImageOffset: spec.ImageOff,
			}
			container.ImagePresence = spec.Image.Present
			if spec.Image.Present == ingest.PresenceValue {
				value := spec.Image.Value
				container.Image = &value
			}
			if entry, found := statusByName[spec.Name]; found {
				status := entry.status
				container.StatusPresent = true
				container.StatusIndex = entry.index
				container.ImageIDOffset = status.ImageIDOff
				container.ImageIDPresence = status.ImageID.Present
				container.StatusImagePresence = status.Image.Present
				container.StatePresence = presenceOf(status.StatePresent)
				if status.ImageID.Present == ingest.PresenceValue {
					value := status.ImageID.Value
					container.ImageID = &value
				}
				if status.Image.Present == ingest.PresenceValue {
					value := status.Image.Value
					container.StatusImage = &value
				}
				if status.Ready.Present == ingest.PresenceValue {
					value := status.Ready.Value
					container.Ready = &value
				}
				if status.Restart.Present == ingest.PresenceValue {
					value := status.Restart.Value
					container.RestartCount = &value
				}
				container.State = status.State.Category
			}
			containers = append(containers, container)
		}
		normalized.Containers = append(normalized.Containers, containers...)

		if specPresent && statusPresent {
			complete := true
			for _, spec := range specContainers {
				if _, found := statusByName[spec.Name]; !found {
					complete = false
					break
				}
			}
			if len(specContainers) == 0 && len(statusContainers) == 0 {
				complete = true
			}
			if complete {
				normalized.CategoriesComplete[class] = true
			}
		}
		// A status without its declaration is a rejected Pod; the ingest layer
		// refuses it, so reaching here with orphans would be a DTO defect.
	}

	// Collisions: the same container name in two classes of one subject cannot be
	// distinguished by the wire scope (ADR-0010 §2). All observations of a
	// collided key are kept internally and omitted from projection.
	byName := map[string][]contract.ContainerClass{}
	for _, container := range normalized.Containers {
		byName[container.Name] = append(byName[container.Name], container.Class)
	}
	for name, classes := range byName {
		if len(classes) > 1 {
			normalized.CollidedClasses[name] = dedupeClasses(classes)
		}
	}
	return normalized
}

func dedupeClasses(classes []contract.ContainerClass) []contract.ContainerClass {
	present := map[contract.ContainerClass]bool{}
	for _, class := range classes {
		present[class] = true
	}
	ordered := make([]contract.ContainerClass, 0, len(present))
	for _, class := range []contract.ContainerClass{contract.ContainerRegular, contract.ContainerInit, contract.ContainerEphemeral} {
		if present[class] {
			ordered = append(ordered, class)
		}
	}
	return ordered
}

// ObservationBindings returns the explicit bindings of one subject: one per
// container, with the observed raw image ID and the literal requested
// reference. GuaranteedDigest and platform stay untouched: a PodList alone
// never proves them (ADR-0025 A.8.3).
func ObservationBindings(result ObservationResult, subjectIndex int) ([]ObservationBinding, error) {
	if subjectIndex < 0 || subjectIndex >= len(result.Subjects) {
		return nil, errSubjectOutOfRange
	}
	subject := result.Subjects[subjectIndex]
	bindings := make([]ObservationBinding, 0, len(subject.Containers))
	for _, container := range subject.Containers {
		binding := ObservationBinding{
			Key: identity.ContainerKey{
				SubjectUID:     subject.UID,
				ContainerClass: container.Class,
				ContainerName:  contract.ContainerName(container.Name),
			},
			ObservedAt: copyTimestamp(result.ObservedAt),
			SourceName: result.Source.Name,
			SourceHash: result.Source.Hash,
		}
		if container.ImageID != nil {
			raw := contract.RawImageID(*container.ImageID)
			binding.RawImageID = &raw
			binding.Locator = contract.SourceLocator(imageIDLocator(subject.ItemIndex, container))
		}
		if container.Image != nil {
			requested := contract.RequestedImage(*container.Image)
			binding.RequestedImage = &requested
			if binding.Locator == "" {
				binding.Locator = contract.SourceLocator(imageLocator(subject.ItemIndex, container))
			}
		}
		bindings = append(bindings, binding)
	}
	return bindings, nil
}

var errSubjectOutOfRange = errors.New("normalize: subject index is out of range")

func classArrayName(class contract.ContainerClass) string {
	switch class {
	case contract.ContainerInit:
		return "initContainerStatuses"
	case contract.ContainerEphemeral:
		return "ephemeralContainerStatuses"
	default:
		return "containerStatuses"
	}
}

func specArrayName(class contract.ContainerClass) string {
	switch class {
	case contract.ContainerInit:
		return "initContainers"
	case contract.ContainerEphemeral:
		return "ephemeralContainers"
	default:
		return "containers"
	}
}

// imageIDLocator renders the exact locator of one observed imageID. The index
// is the position inside its own class array of the source document.
func imageIDLocator(itemIndex int, container ObservationContainer) string {
	return "items[" + itoa(itemIndex) + "].status." + classArrayName(container.Class) + "[" + itoa(container.StatusIndex) + "].imageID"
}

func imageLocator(itemIndex int, container ObservationContainer) string {
	return "items[" + itoa(itemIndex) + "].spec." + specArrayName(container.Class) + "[" + itoa(container.SpecIndex) + "].image"
}

func itoa(value int) string {
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

// validatePodListInput refuses an incoherent parse before any observation is
// built (ADR-0025 A.11.2). The adapter owns the closed diagnostic catalog and
// the closed locator grammar, so a code outside the catalog or a locator that is
// not the exact path to an admitted field can never reach an artifact as free
// text; the same holds for an identity, namespace or counter that contradicts
// the accepted items.
func validatePodListInput(input ingest.PodListResult) error {
	// The counters belong to the producer and are always declared by it. When they
	// are, they must agree with the accepted subjects: Accepted + Rejected equals
	// the known total and the accepted count is the number of subjects.
	// An admitted source has a known total and every item ends accepted or
	// rejected with a reason (A.7.1, A.7.2): the counters, the accepted subjects
	// and the rejection list must agree, and a parse that declares no total is not
	// an admitted parse.
	if input.TotalItems == nil {
		return errItemAccounting
	}
	if input.Accepted+input.Rejected != *input.TotalItems {
		return errItemAccounting
	}
	if uint64(len(input.Subjects)) != input.Accepted {
		return errItemAccounting
	}
	if uint64(len(input.Rejections)) != input.Rejected {
		return errItemAccounting
	}
	for _, rejection := range input.Rejections {
		if !ingest.PodListCodeKnown(string(rejection.Code)) {
			return errDiagnosticIncoherent
		}
	}
	for _, diagnostic := range input.Diagnostics {
		if !ingest.PodListCodeKnown(string(diagnostic.Code)) || !ingest.PodListLocatorValid(diagnostic.FieldLocator) {
			return errDiagnosticIncoherent
		}
	}
	for _, subject := range input.Subjects {
		if subject.UID == "" || subject.Namespace == "" || subject.Name == "" {
			return errSubjectIncoherent
		}
		if string(subject.Namespace) != input.Context.Namespace {
			return errSubjectIncoherent
		}
		for _, diagnostic := range subject.Diagnostics {
			if !ingest.PodListCodeKnown(string(diagnostic.Code)) || !ingest.PodListLocatorValid(diagnostic.FieldLocator) {
				return errDiagnosticIncoherent
			}
		}
		if _, err := podListSubjectContainers(subject); err != nil {
			return err
		}
	}
	return nil
}

// podListSubjectContainers checks the container lists of one ingest subject: a
// status can only exist for a declared container of its own class, a container
// name cannot repeat inside a category and a category cannot declare statuses it
// never declared. The normalized result would otherwise carry an orphan that the
// projection can no longer see.
func podListSubjectContainers(subject ingest.PodSubject) (int, error) {
	total := 0
	for _, class := range []contract.ContainerClass{
		contract.ContainerRegular, contract.ContainerInit, contract.ContainerEphemeral,
	} {
		declared := map[string]bool{}
		for _, container := range subject.SpecContainers[class] {
			if container.Name == "" || declared[container.Name] {
				return 0, errSubjectIncoherent
			}
			declared[container.Name] = true
		}
		seen := map[string]bool{}
		for _, status := range subject.StatusContainers[class] {
			if status.Name == "" || seen[status.Name] {
				return 0, errSubjectIncoherent
			}
			seen[status.Name] = true
			if !declared[status.Name] {
				return 0, errSubjectIncoherent
			}
		}
		if len(subject.StatusContainers[class]) > 0 && !subject.Statuses[class] {
			return 0, errSubjectIncoherent
		}
		total += len(subject.SpecContainers[class])
	}
	return total, nil
}

// copyItemIndex detaches the optional item index of one diagnostic: the result
// never shares a mutable carrier with its input.
func copyItemIndex(index *int) *int {
	if index == nil {
		return nil
	}
	copied := *index
	return &copied
}

// copyTimestamp detaches the observation time of one binding: the result never
// shares a mutable carrier with the result it was derived from.
func copyTimestamp(stamp *contract.Timestamp) *contract.Timestamp {
	if stamp == nil {
		return nil
	}
	copied := *stamp
	return &copied
}

// presenceOf turns one boolean presence into the explicit carrier of the
// normalization result.
func presenceOf(present bool) ingest.PodPresence {
	if present {
		return ingest.PresenceValue
	}
	return ingest.PresenceAbsent
}
