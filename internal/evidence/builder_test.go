package evidence

import (
	"testing"

	contract "github.com/d4rpell/Ariadne/pkg/evidence"
)

func TestNewBundleAcceptsContractShapedBundle(t *testing.T) {
	bundle, err := NewBundle(testBundle(t))
	if err != nil {
		t.Fatalf("NewBundle rejected a contract shaped bundle: %v", err)
	}
	if bundle.SchemaVersion != "0.1" {
		t.Fatalf("NewBundle changed the bundle: %q", bundle.SchemaVersion)
	}
}

// TestNewBundlePreservesSchemaVersion fixes that NewBundle validates but never
// migrates: whatever known version it receives comes back unchanged.
func TestNewBundlePreservesSchemaVersion(t *testing.T) {
	for _, version := range []string{"0.0", "0.1", "0.2"} {
		t.Run(version, func(t *testing.T) {
			received := testBundle(t)
			received.SchemaVersion = version
			preserved, err := NewBundle(received)
			if err != nil {
				t.Fatalf("NewBundle rejected schema_version %q: %v", version, err)
			}
			if preserved.SchemaVersion != version {
				t.Fatalf("NewBundle migrated %q to %q", version, preserved.SchemaVersion)
			}
		})
	}
}

func TestNewBundleRejectsInvalidBundle(t *testing.T) {
	broken := testBundle(t)
	broken.SchemaVersion = ""
	if _, err := NewBundle(broken); err == nil {
		t.Fatal("NewBundle accepted a bundle without schema_version")
	}
}

func TestNewEvidenceItemRejectsForeignScope(t *testing.T) {
	subject := testSubject()
	foreign := testScope(subject, contract.ContainerName("api"))
	foreign.SubjectUID = contract.UID("pod-uid-2")
	if _, err := NewEvidenceItem(subject, testItem(t, foreign, contract.ProvenanceObserved, nil)); err == nil {
		t.Fatal("NewEvidenceItem accepted evidence scoped to another uid")
	}
}

func TestNewEvidenceItemRejectsEmptySubjectUID(t *testing.T) {
	empty := contract.Subject{}
	item := testItem(t, contract.Scope{}, contract.ProvenanceObserved, nil)
	if _, err := NewEvidenceItem(empty, item); err == nil {
		t.Fatal("NewEvidenceItem accepted an item whose subject and scope have no uid")
	}
}

func TestNewEvidenceItemAcceptsScopedEvidence(t *testing.T) {
	subject := testSubject()
	item, err := NewEvidenceItem(subject, testItem(t, testScope(subject, contract.ContainerName("api")), contract.ProvenanceObserved, nil))
	if err != nil {
		t.Fatalf("NewEvidenceItem rejected scoped evidence: %v", err)
	}
	if item.Scope.SubjectUID != subject.UID {
		t.Fatal("NewEvidenceItem changed the scope")
	}
}
