package normalize

import (
	"reflect"
	"testing"

	contract "github.com/d4rpell/Ariadne/pkg/evidence"
)

func TestScopeCollisionsDetectsClassesSharingName(t *testing.T) {
	imported := parseImport(t, validRow("CVE-2024-0001"), validRow("CVE-2024-0002"))
	regular := syntheticBinding("api")
	initContainer := syntheticBinding("api")
	initContainer.Key.ContainerClass = contract.ContainerInit

	result, err := Normalize(Input{Import: imported, Bindings: []Binding{bindingFor(0, regular), bindingFor(1, initContainer)}})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	collisions := ScopeCollisions(result)
	if len(collisions) != 1 {
		t.Fatalf("collisions = %+v, want exactly one", collisions)
	}
	if collisions[0].SubjectUID != contract.UID("uid-0001") || collisions[0].ContainerName != "api" {
		t.Fatalf("collision reported on %q/%q", collisions[0].SubjectUID, collisions[0].ContainerName)
	}
	want := []contract.ContainerClass{contract.ContainerRegular, contract.ContainerInit}
	if !reflect.DeepEqual(collisions[0].Classes, want) {
		t.Fatalf("classes = %v, want %v in first-appearance order", collisions[0].Classes, want)
	}
}

func TestScopeCollisionsIgnoresUnambiguousScopes(t *testing.T) {
	cases := map[string]struct {
		names []string
		class func(int) contract.ContainerClass
	}{
		"same class repeated": {
			names: []string{"api", "api"},
			class: func(int) contract.ContainerClass { return contract.ContainerRegular },
		},
		"distinct names in one class": {
			names: []string{"api", "worker"},
			class: func(int) contract.ContainerClass { return contract.ContainerRegular },
		},
		"distinct names across classes": {
			names: []string{"api", "worker"},
			class: func(i int) contract.ContainerClass {
				if i == 0 {
					return contract.ContainerRegular
				}
				return contract.ContainerInit
			},
		},
	}
	for name, testCase := range cases {
		imported := parseImport(t, validRow("CVE-2024-0001"), validRow("CVE-2024-0002"))
		bindings := make([]Binding, 0, len(testCase.names))
		for i, containerName := range testCase.names {
			binding := syntheticBinding(containerName)
			binding.Key.ContainerClass = testCase.class(i)
			bindings = append(bindings, bindingFor(i, binding))
		}
		result, err := Normalize(Input{Import: imported, Bindings: bindings})
		if err != nil {
			t.Fatalf("%s: unexpected error: %v", name, err)
		}
		if collisions := ScopeCollisions(result); len(collisions) != 0 {
			t.Errorf("%s: reported %+v, want no collision", name, collisions)
		}
	}
}

func TestScopeCollisionsSeparatesSubjects(t *testing.T) {
	imported := parseImport(t, validRow("CVE-2024-0001"), validRow("CVE-2024-0002"))
	first := syntheticBinding("api")
	second := syntheticBinding("api")
	second.Key.SubjectUID = contract.UID("uid-0002")
	second.Key.ContainerClass = contract.ContainerInit

	result, err := Normalize(Input{Import: imported, Bindings: []Binding{bindingFor(0, first), bindingFor(1, second)}})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if collisions := ScopeCollisions(result); len(collisions) != 0 {
		t.Fatalf("collisions = %+v, want none: distinct subjects never share a scope", collisions)
	}
}

func TestScopeCollisionsIgnoresUnboundFindings(t *testing.T) {
	imported := parseImport(t, validRow("CVE-2024-0001"), validRow("CVE-2024-0002"))
	result, err := Normalize(Input{Import: imported})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if collisions := ScopeCollisions(result); len(collisions) != 0 {
		t.Fatalf("collisions = %+v, want none: an unbound finding carries no container", collisions)
	}
}

func TestScopeCollisionsReportsThreeClassesOnce(t *testing.T) {
	imported := parseImport(t, validRow("CVE-2024-0001"), validRow("CVE-2024-0002"), validRow("CVE-2024-0003"))
	ephemeral := syntheticBinding("api")
	ephemeral.Key.ContainerClass = contract.ContainerEphemeral
	regular := syntheticBinding("api")
	initContainer := syntheticBinding("api")
	initContainer.Key.ContainerClass = contract.ContainerInit

	result, err := Normalize(Input{Import: imported, Bindings: []Binding{
		bindingFor(0, ephemeral), bindingFor(1, regular), bindingFor(2, initContainer),
	}})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	collisions := ScopeCollisions(result)
	if len(collisions) != 1 {
		t.Fatalf("collisions = %+v, want a single omission for the key", collisions)
	}
	want := []contract.ContainerClass{contract.ContainerEphemeral, contract.ContainerRegular, contract.ContainerInit}
	if !reflect.DeepEqual(collisions[0].Classes, want) {
		t.Fatalf("classes = %v, want %v in the order the findings carry", collisions[0].Classes, want)
	}
}

func TestScopeCollisionsAreDeterministicAndOrdered(t *testing.T) {
	imported := parseImport(t,
		validRow("CVE-2024-0001"), validRow("CVE-2024-0002"),
		validRow("CVE-2024-0003"), validRow("CVE-2024-0004"),
	)
	first := syntheticBinding("api")
	second := syntheticBinding("api")
	second.Key.ContainerClass = contract.ContainerInit
	third := syntheticBinding("metrics")
	third.Key.ContainerClass = contract.ContainerEphemeral
	fourth := syntheticBinding("metrics")

	bindings := []Binding{bindingFor(0, first), bindingFor(1, second), bindingFor(2, third), bindingFor(3, fourth)}
	result, err := Normalize(Input{Import: imported, Bindings: bindings})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	before := ScopeCollisions(result)
	after := ScopeCollisions(result)
	if !reflect.DeepEqual(before, after) {
		t.Fatal("collision detection is not deterministic")
	}
	if len(before) != 2 {
		t.Fatalf("collisions = %+v, want 2", before)
	}
	if before[0].ContainerName != "api" || before[1].ContainerName != "metrics" {
		t.Fatalf("collision order = %q, %q; want first-appearance order", before[0].ContainerName, before[1].ContainerName)
	}
	if before[1].Classes[0] != contract.ContainerEphemeral || before[1].Classes[1] != contract.ContainerRegular {
		t.Fatalf("classes = %v, want the order the findings carry", before[1].Classes)
	}
}

func TestScopeCollisionsReturnNonNilEmptySlice(t *testing.T) {
	if collisions := ScopeCollisions(Result{}); collisions == nil || len(collisions) != 0 {
		t.Fatalf("collisions = %#v, want a non-nil empty slice", collisions)
	}
}

// TestScopeCollisionsNeverAliasTheResult pins that the reported classes are a
// copy: a consumer cannot rewrite the result through the collision report.
func TestScopeCollisionsNeverAliasTheResult(t *testing.T) {
	imported := parseImport(t, validRow("CVE-2024-0001"), validRow("CVE-2024-0002"))
	regular := syntheticBinding("api")
	initContainer := syntheticBinding("api")
	initContainer.Key.ContainerClass = contract.ContainerInit
	result, err := Normalize(Input{Import: imported, Bindings: []Binding{bindingFor(0, regular), bindingFor(1, initContainer)}})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	collisions := ScopeCollisions(result)
	collisions[0].Classes[0] = "mutated"
	if ScopeCollisions(result)[0].Classes[0] != contract.ContainerRegular {
		t.Fatal("collision report aliases the normalized result")
	}
}
