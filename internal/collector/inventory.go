package collector

import (
	"sort"

	"github.com/d4rpell/Ariadne/internal/bundle"
	contract "github.com/d4rpell/Ariadne/pkg/evidence"
)

// Initial inventory (ADR-0026 A.8.1, A.9). The inventory is formed from the
// list captures only; namespace and name are directions for re-reads, never the
// association key. A uid repeated anywhere in the initial inventory invalidates
// every occurrence, and no occurrence wins by order.

// inventoryEntry is one inventoried Pod with its origin.
type inventoryEntry struct {
	uid       contract.UID
	namespace contract.Namespace
	name      string
	capture   uint64
	itemIndex int
}

// initialInventory is the closed inventory of one run.
type initialInventory struct {
	entries []inventoryEntry
	// duplicateUIDs lists every uid that appeared more than once, with all its
	// occurrences preserved for the omission record.
	duplicateUIDs map[contract.UID][]inventoryEntry
}

// buildInventory collects the entries of every list capture and detects
// duplicated uids across the whole inventory, pages included. The identity
// comes from the projected items, so an occurrence whose Pod was later rejected
// by the admission stage still participates: a rejection never hides a
// duplicate. Every inventoried uid is charged to the initial-inventory budget
// before it is incorporated.
func buildInventory(captures []bundle.CollectedCapture, budget *budgetState) (initialInventory, []bundle.CollectionDiagnostic, error) {
	inventory := initialInventory{duplicateUIDs: map[contract.UID][]inventoryEntry{}}
	byUID := map[contract.UID]int{}
	exhausted := false
	var exhaustion error
	for _, capture := range captures {
		if capture.Verb != "list" {
			continue
		}
		if capture.Observation.Termination != contract.TerminationFinished &&
			capture.Observation.Termination != contract.TerminationAborted {
			continue
		}
		for itemIndex, item := range capture.Items {
			entry := inventoryEntry{
				uid:       item.UID,
				namespace: item.Namespace,
				name:      item.Name,
				capture:   capture.Ordinal,
				itemIndex: itemIndex,
			}
			if !identifierPresent(string(item.UID)) || !identifierPresent(item.Name) {
				// An occurrence without a usable identity cannot be inventoried,
				// and its lack is never filled: it stays out with a diagnostic.
				continue
			}
			// The budget is checked before the occurrence is incorporated, but a
			// uid consumed by an occurrence already seen still counts: the whole
			// inventory is scanned first so a duplicate can never be hidden by the
			// limit that closed the walk.
			if budget != nil && !exhausted {
				if err := budget.addInitialUID(); err != nil {
					exhausted = true
					exhaustion = err
				}
			}
			byUID[item.UID]++
			inventory.entries = append(inventory.entries, entry)
		}
	}
	if exhausted {
		// An exceeded inventory aborts the run, but the exclusions already
		// established are preserved and applied: a uid repeated between two
		// retained pages still invalidates every one of its occurrences.
		unique, diagnostics := inventoryExclusions(inventory, byUID)
		inventory.entries = unique
		return inventory, diagnostics, exhaustion
	}
	unique, diagnostics := inventoryExclusions(inventory, byUID)
	inventory.entries = unique
	return inventory, diagnostics, nil
}

// inventoryExclusions separates the unique occurrences from the duplicated
// ones: every occurrence of a uid seen more than once is omitted, recorded in
// duplicateUIDs and reported with one identity_conflict diagnostic, and the
// unique occurrences are returned in canonical order.
func inventoryExclusions(inventory initialInventory, byUID map[contract.UID]int) ([]inventoryEntry, []bundle.CollectionDiagnostic) {
	diagnostics := inventoryDiagnostics(byUID)
	unique := make([]inventoryEntry, 0, len(inventory.entries))
	for _, entry := range inventory.entries {
		if byUID[entry.uid] > 1 {
			inventory.duplicateUIDs[entry.uid] = append(inventory.duplicateUIDs[entry.uid], entry)
			continue
		}
		unique = append(unique, entry)
	}
	sort.Slice(diagnostics, func(i, j int) bool { return diagnostics[i].Code < diagnostics[j].Code })
	sort.Slice(unique, func(i, j int) bool {
		if unique[i].namespace != unique[j].namespace {
			return unique[i].namespace < unique[j].namespace
		}
		if unique[i].name != unique[j].name {
			return unique[i].name < unique[j].name
		}
		return unique[i].uid < unique[j].uid
	})
	return unique, diagnostics
}

// inventoryDiagnostics renders one identity_conflict diagnostic per uid that
// appears more than once in the scanned occurrences.
func inventoryDiagnostics(byUID map[contract.UID]int) []bundle.CollectionDiagnostic {
	diagnostics := []bundle.CollectionDiagnostic{}
	for _, count := range byUID {
		if count > 1 {
			diagnostics = append(diagnostics, bundle.CollectionDiagnostic{Code: bundle.CodeIdentityConflict})
		}
	}
	return diagnostics
}

// inInventory reports whether one subject of one capture belongs to the closed
// inventory and was not invalidated by a duplicated uid.
func (i initialInventory) inInventory(capture uint64, itemIndex int, uid contract.UID) bool {
	if _, duplicated := i.duplicateUIDs[uid]; duplicated {
		return false
	}
	for _, entry := range i.entries {
		if entry.capture == capture && entry.itemIndex == itemIndex && entry.uid == uid {
			return true
		}
	}
	return false
}

// identifierPresent reports whether an identity text is usable. It is a
// conservative local test: the ingest layer already validated the admitted
// document, and this guard only refuses empty or unbounded values.
func identifierPresent(value string) bool {
	if value == "" || len(value) > 1024 {
		return false
	}
	for index := 0; index < len(value); index++ {
		if value[index] < 0x21 || value[index] > 0x7e {
			return false
		}
	}
	return true
}
