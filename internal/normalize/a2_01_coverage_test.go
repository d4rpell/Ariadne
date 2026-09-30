package normalize

import (
	"testing"

	"github.com/d4rpell/Ariadne/internal/identity"
	contract "github.com/d4rpell/Ariadne/pkg/evidence"
)

// Coverage precedence of ADR-0025 A.7.4: an unknown capture termination always
// yields unknown completeness, a defect never promotes unknown to partial, and
// only a finished capture with the three complete categories and no defect is
// complete.

func coverageSubject(complete bool, withImage bool) ObservationSubject {
	subject := ObservationSubject{
		UID:                contract.UID("uid-0001"),
		Namespace:          contract.Namespace("payments"),
		Name:               "api-7f4d",
		CategoriesObserved: map[contract.ContainerClass]bool{},
		CategoriesComplete: map[contract.ContainerClass]bool{},
		CollidedClasses:    map[string][]contract.ContainerClass{},
	}
	if complete {
		for _, class := range []contract.ContainerClass{contract.ContainerRegular, contract.ContainerInit, contract.ContainerEphemeral} {
			subject.CategoriesObserved[class] = true
			subject.CategoriesComplete[class] = true
		}
	}
	// An incomplete subject observes no category: its only possible progress is
	// an inventoried image, which is exactly the distinction under test.
	container := ObservationContainer{Class: contract.ContainerRegular, Name: "api", SpecPresent: true, StatusPresent: true}
	if withImage {
		imageID := "registry.example/app@sha256:0000000000000000000000000000000000000000000000000000000000000000"
		container.ImageID = &imageID
	}
	subject.Containers = []ObservationContainer{container}
	return subject
}

func TestA201CoveragePrecedence(t *testing.T) {
	cases := []struct {
		name        string
		termination contract.CoverageTermination
		subject     ObservationSubject
		defect      bool
		want        contract.Completeness
	}{
		{
			name:        "finished complete without defect",
			termination: contract.TerminationFinished,
			subject:     coverageSubject(true, true),
			defect:      false,
			want:        contract.CompletenessComplete,
		},
		{
			name:        "finished complete with defect is partial",
			termination: contract.TerminationFinished,
			subject:     coverageSubject(true, true),
			defect:      true,
			want:        contract.CompletenessPartial,
		},
		{
			name:        "finished incomplete is partial with progress",
			termination: contract.TerminationFinished,
			subject:     coverageSubject(false, true),
			defect:      false,
			want:        contract.CompletenessPartial,
		},
		{
			name:        "aborted with progress is partial",
			termination: contract.TerminationAborted,
			subject:     coverageSubject(false, true),
			defect:      false,
			want:        contract.CompletenessPartial,
		},
		{
			name:        "aborted without progress is unknown",
			termination: contract.TerminationAborted,
			subject:     coverageSubject(false, false),
			defect:      false,
			want:        contract.CompletenessUnknown,
		},
		{
			name:        "unknown stays unknown without defect",
			termination: contract.TerminationUnknown,
			subject:     coverageSubject(true, true),
			defect:      false,
			want:        contract.CompletenessUnknown,
		},
		{
			name:        "unknown with defect stays unknown, never partial",
			termination: contract.TerminationUnknown,
			subject:     coverageSubject(true, true),
			defect:      true,
			want:        contract.CompletenessUnknown,
		},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			got := CompletenessFor(testCase.termination, testCase.subject, testCase.defect)
			if got != testCase.want {
				t.Fatalf("completeness = %q, want %q", got, testCase.want)
			}
		})
	}
}

func TestA201NoProgressCoverage(t *testing.T) {
	// A subject with no observed category and no inventoried image has no
	// verifiable progress: every termination yields unknown with visible errors,
	// and knowing the UID is not progress.
	subject := ObservationSubject{
		UID:                contract.UID("uid-0001"),
		CategoriesObserved: map[contract.ContainerClass]bool{},
		CategoriesComplete: map[contract.ContainerClass]bool{},
		CollidedClasses:    map[string][]contract.ContainerClass{},
		Containers:         []ObservationContainer{{Class: contract.ContainerRegular, Name: "api"}},
	}
	for _, termination := range []contract.CoverageTermination{contract.TerminationFinished, contract.TerminationAborted, contract.TerminationUnknown} {
		got := CompletenessFor(termination, subject, false)
		if got != contract.CompletenessUnknown {
			t.Fatalf("termination %q without progress: completeness = %q, want unknown", termination, got)
		}
	}
}

func TestA201ConflictIsVisibleOnEverySubject(t *testing.T) {
	// Two subjects share namespace/name with different UIDs: both are marked,
	// not only the later one, and the order of the array is never chronology.
	result := ObservationResult{
		Subjects: []ObservationSubject{
			{UID: contract.UID("uid-a"), Namespace: contract.Namespace("payments"), Name: "api"},
			{UID: contract.UID("uid-b"), Namespace: contract.Namespace("payments"), Name: "api"},
		},
	}
	conflicts := ConflictingUIDs(result)
	if !conflicts[0] || !conflicts[1] {
		t.Fatalf("conflicts = %v, want both subjects marked", conflicts)
	}
	// A single subject is never in conflict with itself.
	alone := ObservationResult{Subjects: []ObservationSubject{{UID: contract.UID("uid-a"), Namespace: contract.Namespace("payments"), Name: "api"}}}
	if len(ConflictingUIDs(alone)) != 0 {
		t.Fatal("a single subject must not report a conflict")
	}
}

func TestA201CollisionIsKeyedByContainerNotClass(t *testing.T) {
	subject := ObservationSubject{
		CollidedClasses: map[string][]contract.ContainerClass{
			"api": {contract.ContainerRegular, contract.ContainerInit},
		},
		Containers: []ObservationContainer{
			{Class: contract.ContainerRegular, Name: "api"},
			{Class: contract.ContainerInit, Name: "api"},
			{Class: contract.ContainerRegular, Name: "metrics"},
		},
	}
	result := ObservationResult{
		Subjects: []ObservationSubject{subject},
	}
	keys := CollisionKeys(result, 0)
	if len(keys) != 2 {
		t.Fatalf("collision keys = %d, want the two classes of the collided name", len(keys))
	}
	if !keys[identity.ContainerKey{SubjectUID: subject.UID, ContainerClass: contract.ContainerRegular, ContainerName: "api"}] {
		t.Fatal("regular class of the collided name is not marked")
	}
	if !keys[identity.ContainerKey{SubjectUID: subject.UID, ContainerClass: contract.ContainerInit, ContainerName: "api"}] {
		t.Fatal("init class of the collided name is not marked")
	}
	if keys[identity.ContainerKey{SubjectUID: subject.UID, ContainerClass: contract.ContainerRegular, ContainerName: "metrics"}] {
		t.Fatal("a non-collided container must not be marked")
	}
}

// TestA201CoverageRequestedImageDefect keeps the diagnostic of a container whose
// requested reference the export did not carry as a defect of the subject: the
// observation is partial and keeps its visible error, never complete with an
// error list the wire would refuse (ADR-0025 A.7.3, A.7.4).
func TestA201CoverageRequestedImageDefect(t *testing.T) {
	subject := coverageSubject(true, true)
	subject.Diagnostics = []ObservationDiagnostic{{Code: "requested_image_unavailable", Offset: 120}}
	if !SubjectHasDefect(subject) {
		t.Fatal("a preserved incompleteness diagnostic is not treated as a defect")
	}
	completeness := CompletenessFor(contract.TerminationFinished, subject, SubjectHasDefect(subject))
	if completeness != contract.CompletenessPartial {
		t.Fatalf("completeness = %q, want partial: a complete capture with a missing requested image is not complete", completeness)
	}
	// Without the diagnostic the same subject is complete: the rule does not
	// degrade a capture that carried every reference.
	clean := coverageSubject(true, true)
	if got := CompletenessFor(contract.TerminationFinished, clean, SubjectHasDefect(clean)); got != contract.CompletenessComplete {
		t.Fatalf("completeness = %q, want complete for a subject without defects", got)
	}
	// An unknown capture stays unknown even with the same defect.
	if got := CompletenessFor(contract.TerminationUnknown, subject, SubjectHasDefect(subject)); got != contract.CompletenessUnknown {
		t.Fatalf("completeness = %q, want unknown with an unknown termination", got)
	}
	// A collision is still detected without any diagnostic.
	collided := coverageSubject(true, true)
	collided.CollidedClasses = map[string][]contract.ContainerClass{"api": {contract.ContainerRegular, contract.ContainerInit}}
	if !SubjectHasDefect(collided) {
		t.Fatal("a collision is not treated as a defect")
	}
}
