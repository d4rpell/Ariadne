package normalize

import (
	"strconv"

	"github.com/d4rpell/Ariadne/internal/ingest"
	contract "github.com/d4rpell/Ariadne/pkg/evidence"
)

// Projected-content signature and F07 pattern of the observation subjects
// (ADR-0026 A.8.3). Both live here, next to the observation types, so the
// producer of the comparisons and the integration validator of the bundle
// share one implementation: a comparison is accepted exactly when the producer
// could have generated it, and an incoherent one is refused.

// ContentSignature renders the projected content of one subject: the values and
// the presence of every admitted field, in a stable order. It never includes
// offsets or source hashes: a different page can change the hash without
// changing the Pod.
func ContentSignature(subject ObservationSubject) string {
	signature := ""
	for _, class := range []contract.ContainerClass{
		contract.ContainerRegular, contract.ContainerInit, contract.ContainerEphemeral,
	} {
		if !subject.CategoriesObserved[class] {
			signature += "|absent:" + string(class)
			continue
		}
		signature += "|observed:" + string(class)
		for _, container := range subject.Containers {
			if container.Class != class {
				continue
			}
			signature += "|" + container.Name + "|"
			signature += PresenceString(container.ImagePresence, container.Image)
			signature += PresenceString(container.ImageIDPresence, container.ImageID)
			signature += PresenceString(container.StatusImagePresence, container.StatusImage)
			ready := ""
			if container.Ready != nil {
				ready = strconv.FormatBool(*container.Ready)
			}
			signature += "|ready:" + ready
			signature += "|state:" + container.State
			signature += "|statePresence:" + presenceValue(container.StatePresence)
			restart := ""
			if container.RestartCount != nil {
				restart = strconv.FormatInt(*container.RestartCount, 10)
			}
			signature += "|restart:" + restart
			signature += "|status:" + statusPresence(container.StatusPresent)
		}
	}
	return signature
}

// StaleStatusPattern implements the bounded F07 detection of ADR-0026 A.8.3:
// the requested image changed and the whole projected status tuple, presence
// included, stayed identical for one container, and no contradicting change of
// that same container erases the pattern. Containers are matched by class and
// name, never by position: the order of an array is not identity.
//
// The condition is per paired container: the evolution of a different container
// (its spec and status moving together, or its disappearance or appearance)
// says nothing about whether this container's status lagged its spec, so it
// neither establishes nor erases the pattern. A container that is only present
// on one end is not a pair and cannot establish the pattern for itself.
func StaleStatusPattern(previous, current ObservationSubject) bool {
	previousByName := containerIndex(previous)
	currentByName := containerIndex(current)
	// A subject whose own keys collide cannot be compared by identity.
	if len(previousByName) != len(previous.Containers) || len(currentByName) != len(current.Containers) {
		return false
	}
	matched := false
	for key, before := range previousByName {
		after, present := currentByName[key]
		if !present {
			// The container is not addressable in this capture: it cannot
			// establish the pattern for itself, and its disappearance must not
			// erase the pattern of a container that keeps its identity.
			continue
		}
		specChanged := PresenceString(before.ImagePresence, before.Image) != PresenceString(after.ImagePresence, after.Image)
		statusChanged := StatusTuple(before) != StatusTuple(after)
		if specChanged && !statusChanged {
			// The freshness gap is established for this container: its requested
			// image changed while its whole status tuple stayed identical.
			matched = true
		}
	}
	return matched
}

// containerIndex indexes the containers of one subject by class and name,
// refusing duplicates by returning the full map only when every key is unique.
func containerIndex(subject ObservationSubject) map[string]ObservationContainer {
	indexed := map[string]ObservationContainer{}
	for _, container := range subject.Containers {
		key := string(container.Class) + "/" + container.Name
		if _, present := indexed[key]; present {
			// A duplicated key cannot be compared positionally: the pattern is not
			// established for this subject.
			return map[string]ObservationContainer{}
		}
		indexed[key] = container
	}
	return indexed
}

// StatusTuple renders the complete projected status of one container, presence
// included, in a stable form.
func StatusTuple(container ObservationContainer) string {
	return "status:" + statusPresence(container.StatusPresent) +
		"|imageID:" + PresenceString(container.ImageIDPresence, container.ImageID) +
		"|image:" + PresenceString(container.StatusImagePresence, container.StatusImage) +
		"|ready:" + boolPointerString(container.Ready) +
		"|state:" + container.State +
		"|statePresence:" + presenceValue(container.StatePresence) +
		"|restart:" + int64PointerString(container.RestartCount)
}

// presenceValue renders one presence enum of the ingest layer.
func presenceValue(presence ingest.PodPresence) string {
	switch presence {
	case ingest.PresenceAbsent:
		return "absent"
	case ingest.PresenceEmpty:
		return "empty"
	default:
		return "value"
	}
}

// PresenceString renders one optional string value with its presence.
func PresenceString(presence ingest.PodPresence, value *string) string {
	switch presence {
	case ingest.PresenceAbsent:
		return "absent"
	case ingest.PresenceEmpty:
		return "empty"
	default:
		if value == nil {
			return "absent"
		}
		return "value:" + *value
	}
}

func boolPointerString(value *bool) string {
	if value == nil {
		return "absent"
	}
	return strconv.FormatBool(*value)
}

func int64PointerString(value *int64) string {
	if value == nil {
		return "absent"
	}
	return strconv.FormatInt(*value, 10)
}

func statusPresence(present bool) string {
	if present {
		return "present"
	}
	return "absent"
}
