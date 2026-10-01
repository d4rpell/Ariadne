package ingest

import (
	"strings"
	"testing"

	"github.com/d4rpell/Ariadne/internal/schema"
)

// Direct proof of the inherited per-object member budget (ADR-0025 A.4; A2-02
// handoff §4.4, corrected exception F1-H1). The closed allowlist admits at most
// six distinct keys per object, so end to end the 33rd member is unreachable and
// the reachable failure there is duplicate_key. The guard itself is still proven
// at its own boundary: this test drives the real scanObject counter with a
// controlled allowlist context that admits enough distinct synthetic keys, so
// neither the duplicate rejection nor the allowlist fires before the budget.
// No production constant is lowered and no counter is simulated: the check
// under test is the parser's own guard, reached by its normal code path.

const a202SyntheticMemberPath = "synthetic[]"

// a202SyntheticMemberDocument builds one JSON object with exactly count
// distinct synthetic keys.
func a202SyntheticMemberDocument(count int) string {
	members := make([]string, 0, count)
	for index := 0; index < count; index++ {
		members = append(members, `"key-`+itoaTest(uint64(index))+`":0`)
	}
	return "{" + strings.Join(members, ",") + "}"
}

// a202ScanSyntheticObject runs one scanObject over an object of exactly count
// distinct synthetic keys, with a controlled allowlist that admits them all on
// a path of its own. The shared table is restored unconditionally; production
// behavior is never altered, only the context of this direct invocation.
func a202ScanSyntheticObject(t *testing.T, count int) (podListValue, *PodListError) {
	t.Helper()
	admitted := map[string]bool{}
	for index := 0; index < count; index++ {
		admitted["key-"+itoaTest(uint64(index))] = true
	}
	original := podListAllowlistPaths
	overridden := make(map[string]map[string]bool, len(original)+1)
	for path, keys := range original {
		overridden[path] = keys
	}
	overridden[a202SyntheticMemberPath] = admitted
	podListAllowlistPaths = overridden
	defer func() { podListAllowlistPaths = original }()

	document := a202SyntheticMemberDocument(count)
	return newPodListScanner([]byte(document)).scanObject(a202SyntheticMemberPath, 1, 0)
}

func TestA202IngestMemberBudgetBoundary(t *testing.T) {
	if schema.SanitizedPodListMaxObjectMembers != 32 {
		t.Fatalf("the inherited member budget changed to %d", schema.SanitizedPodListMaxObjectMembers)
	}
	for name, count := range map[string]int{"L_minus_1": 31, "L": 32} {
		t.Run(name, func(t *testing.T) {
			value, problem := a202ScanSyntheticObject(t, count)
			if problem != nil {
				t.Fatalf("an object of %d members was refused: %v", count, problem)
			}
			if len(value.Members) != count {
				t.Fatalf("members = %d, want %d", len(value.Members), count)
			}
			if value.Members[count-1].Key != "key-"+itoaTest(uint64(count-1)) {
				t.Fatalf("last member = %q", value.Members[count-1].Key)
			}
		})
	}
	t.Run("L_plus_1", func(t *testing.T) {
		// The budget fires before the 33rd member is read: A.10.2 anchors
		// member_limit at the opening quote of the key of member 33.
		document := a202SyntheticMemberDocument(33)
		anchor := uint64(strings.Index(document, `"key-32"`))
		if document[anchor:anchor+uint64(len(`"key-32"`))] != `"key-32"` {
			t.Fatalf("anchor %d does not hold the 33rd key", anchor)
		}
		value, problem := a202ScanSyntheticObject(t, 33)
		if problem == nil {
			t.Fatalf("an object of 33 members was admitted with %d members", len(value.Members))
		}
		if problem.Diagnostic.Code != PodListCodeMemberLimit {
			t.Fatalf("failure code = %q, want member_limit", problem.Diagnostic.Code)
		}
		if problem.Diagnostic.ByteOffset != anchor {
			t.Fatalf("failure offset = %d, want the 33rd key at %d", problem.Diagnostic.ByteOffset, anchor)
		}
		if got := problem.Error(); got != a201Literal(anchor, "object member limit exceeded") {
			t.Fatalf("failure = %q", got)
		}
	})
}
