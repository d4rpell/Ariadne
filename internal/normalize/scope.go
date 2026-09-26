package normalize

import contract "github.com/d4rpell/Ariadne/pkg/evidence"

// ScopeCollision reports one subject uid that carries the same container name in
// more than one container class. The wire Scope cannot distinguish those
// containers, so a bundle cannot state which one an evidence item belongs to
// (ADR-0010). A1-03 must refuse to project that identity and its evidence
// instead of merging the classes or discarding one of them.
type ScopeCollision struct {
	SubjectUID    contract.UID
	ContainerName contract.ContainerName
	Classes       []contract.ContainerClass
}

// ScopeCollisions returns the scope collisions of a normalized result in a
// deterministic order: collisions by first appearance of the uid and name, and
// the classes of each collision in the order the findings carry them. Findings
// without a binding carry no container and are ignored. The result never
// chooses, merges or rewrites a class, and the input is not mutated.
func ScopeCollisions(result Result) []ScopeCollision {
	type container struct {
		uid  contract.UID
		name contract.ContainerName
	}
	order := make([]container, 0, len(result.Findings))
	classes := make(map[container][]contract.ContainerClass, len(result.Findings))
	for _, finding := range result.Findings {
		if finding.Binding == nil {
			continue
		}
		key := container{uid: finding.Binding.Key.SubjectUID, name: finding.Binding.Key.ContainerName}
		if _, known := classes[key]; !known {
			order = append(order, key)
		}
		class := finding.Binding.Key.ContainerClass
		repeated := false
		for _, seen := range classes[key] {
			if seen == class {
				repeated = true
				break
			}
		}
		if !repeated {
			classes[key] = append(classes[key], class)
		}
	}

	collisions := make([]ScopeCollision, 0, len(order))
	for _, key := range order {
		seen := classes[key]
		if len(seen) < 2 {
			continue
		}
		collisions = append(collisions, ScopeCollision{
			SubjectUID:    key.uid,
			ContainerName: key.name,
			Classes:       append([]contract.ContainerClass{}, seen...),
		})
	}
	return collisions
}
