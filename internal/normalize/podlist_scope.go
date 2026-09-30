package normalize

import (
	"github.com/d4rpell/Ariadne/internal/identity"
	contract "github.com/d4rpell/Ariadne/pkg/evidence"
)

// Scope handling of ADR-0025 A.8.4 and A.7.2: two Pods that share
// namespace/name with different UIDs stay separate subjects with a visible
// conflict, and one container name appearing in two classes of the same
// subject is a scope collision that is omitted from projection, never merged
// or chosen.

// SubjectConflictCode is the warning code of two distinct subjects sharing a
// namespace/name pair. It matches the existing wire code of the same name.
const SubjectConflictCode = "source_conflict"

// CollisionWarningCode is the warning code of a scope collision.
const CollisionWarningCode = "scope_mismatch"

// ConflictingUIDs returns the UIDs of subjects that share a namespace/name pair
// with a different UID. Every affected subject is marked, not only the later
// occurrence, and the order of the array is never read as chronology.
func ConflictingUIDs(result ObservationResult) map[int]bool {
	type occurrences struct {
		first int
		uids  map[contract.UID]bool
	}
	byName := map[string]*occurrences{}
	for index, subject := range result.Subjects {
		key := string(subject.Namespace) + "\x00" + subject.Name
		entry, known := byName[key]
		if !known {
			entry = &occurrences{first: index, uids: map[contract.UID]bool{}}
			byName[key] = entry
		}
		entry.uids[subject.UID] = true
	}
	conflicts := map[int]bool{}
	for _, entry := range byName {
		if len(entry.uids) < 2 {
			continue
		}
		for index, subject := range result.Subjects {
			key := string(subject.Namespace) + "\x00" + subject.Name
			if byName[key] == entry {
				conflicts[index] = true
			}
		}
	}
	return conflicts
}

// CollidedClassesOf returns the classes of one collided container name in
// canonical order. The caller renders the warning message with this order, not
// with appearance order.
func CollidedClassesOf(subject ObservationSubject, containerName string) []contract.ContainerClass {
	return subject.CollidedClasses[containerName]
}

// CollisionKeys returns the container keys of every collided name of one
// subject: their observations stay internal and are omitted from projection.
func CollisionKeys(result ObservationResult, subjectIndex int) map[identity.ContainerKey]bool {
	if subjectIndex < 0 || subjectIndex >= len(result.Subjects) {
		return nil
	}
	subject := result.Subjects[subjectIndex]
	collided := map[identity.ContainerKey]bool{}
	for name := range subject.CollidedClasses {
		for _, container := range subject.Containers {
			if container.Name == name {
				collided[identity.ContainerKey{
					SubjectUID:     subject.UID,
					ContainerClass: container.Class,
					ContainerName:  contract.ContainerName(container.Name),
				}] = true
			}
		}
	}
	return collided
}
