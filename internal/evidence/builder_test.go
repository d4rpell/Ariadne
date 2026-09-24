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
	if bundle.SchemaVersion != contract.SchemaVersionSupported {
		t.Fatalf("NewBundle changed the bundle: %q", bundle.SchemaVersion)
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
