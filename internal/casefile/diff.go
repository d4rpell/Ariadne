package casefile

// Validity diff between two declared instants over one admitted book (ADR-0038,
// task A3-10). Diff is a pure, offline and deterministic derived view: it reuses
// Assess at both instants, reads no clock, opens no path and never mutates the
// book. The compared unit is the whole set of decisions in force for a subject
// (every hash with standing effective), never a single representative: the
// comparison considers every in-force record at both extremes and does not
// reconstruct intermediate transitions. It is a governance view, never a product
// status, an exploitability value or a risk decision.

// Change is the closed vocabulary of the change of one subject's in-force set
// between the two instants.
type Change string

const (
	// ChangeGranted: the subject had no decision in force and now has some.
	ChangeGranted Change = "granted"
	// ChangeReopened: the subject had some decision in force and now has none.
	ChangeReopened Change = "reopened"
	// ChangeRevised: the subject has decisions in force at both instants but the
	// set differs.
	ChangeRevised Change = "revised"
	// ChangeUnchanged: the in-force set is identical (including both empty).
	ChangeUnchanged Change = "unchanged"
)

// DiffEntry is the change of one subject between the two instants. SinceHashes
// and AsOfHashes are the complete in-force sets in append order and may be empty.
type DiffEntry struct {
	Subject     Subject
	SinceHashes []string
	AsOfHashes  []string
	Change      Change
}

// DiffAnomaly is one derived signal located at a record. It is not an error and
// changes no outcome.
type DiffAnomaly struct {
	Sequence uint64
	Anomaly  Anomaly
}

// DiffView is an immutable derived view. The zero value is invalid.
type DiffView struct {
	initialized  bool
	entries      []DiffEntry
	declarations []string
	anomalies    []DiffAnomaly
}

// Diff validates the book and both instants exactly as Assess does, requires
// since <= asOf and derives the per-subject change of the in-force set. An
// inverted interval reuses invalid_timestamp: it is an inadmissible property of
// the declared instants. That branch is unreachable from the CLI, whose grammar
// rejects it before the book is read. Diff never mutates the book.
func Diff(book Book, since, asOf string) (DiffView, error) {
	if !book.initialized {
		return DiffView{}, problem(CodeInvalidBook)
	}
	if err := validateChain(book.records); err != nil {
		return DiffView{}, err
	}
	if err := validateTimestamp(since); err != nil {
		return DiffView{}, err
	}
	if err := validateTimestamp(asOf); err != nil {
		return DiffView{}, err
	}
	if since > asOf {
		return DiffView{}, problem(CodeInvalidTimestamp)
	}

	sinceView, err := Assess(book, since)
	if err != nil {
		return DiffView{}, err
	}
	asOfView, err := Assess(book, asOf)
	if err != nil {
		return DiffView{}, err
	}
	sinceEntries, err := sinceView.Entries()
	if err != nil {
		return DiffView{}, err
	}
	asOfEntries, err := asOfView.Entries()
	if err != nil {
		return DiffView{}, err
	}

	// Subjects in first-appearance (append) order. No sort is available in this
	// package's stdlib-only allowlist, and the append order of an append-only
	// ledger is deterministic and reproducible byte for byte.
	positions := make(map[Subject]int, len(book.records))
	order := make([]Subject, 0, len(book.records))
	for index := range book.records {
		subject := SubjectOf(book.records[index].Decision.Scope)
		if _, seen := positions[subject]; !seen {
			positions[subject] = len(order)
			order = append(order, subject)
		}
	}
	sinceSets := make([][]string, len(order))
	asOfSets := make([][]string, len(order))
	for index := range book.records {
		slot := positions[SubjectOf(book.records[index].Decision.Scope)]
		if sinceEntries[index].Standing == StandingEffective {
			sinceSets[slot] = append(sinceSets[slot], sinceEntries[index].Hash)
		}
		if asOfEntries[index].Standing == StandingEffective {
			asOfSets[slot] = append(asOfSets[slot], asOfEntries[index].Hash)
		}
	}

	entries := make([]DiffEntry, len(order))
	for index := range order {
		since := sinceSets[index]
		asOf := asOfSets[index]
		if since == nil {
			since = []string{}
		}
		if asOf == nil {
			asOf = []string{}
		}
		entries[index] = DiffEntry{
			Subject:     order[index],
			SinceHashes: since,
			AsOfHashes:  asOf,
			Change:      classifyChange(since, asOf),
		}
	}

	declarations := []string{}
	for index := range book.records {
		decided := book.records[index].Decision.DecidedAt
		if decided > since && decided <= asOf {
			declarations = append(declarations, book.records[index].Hash)
		}
	}

	return DiffView{
		initialized:  true,
		entries:      entries,
		declarations: declarations,
		anomalies:    mergedAnomalies(sinceEntries, asOfEntries),
	}, nil
}

// classifyChange compares the two in-force sets: empty/empty and identical
// non-empty sets are unchanged, an empty side on either end is granted or
// reopened, and two differing non-empty sets are revised.
func classifyChange(since, asOf []string) Change {
	switch {
	case len(since) == 0 && len(asOf) == 0:
		return ChangeUnchanged
	case len(since) == 0:
		return ChangeGranted
	case len(asOf) == 0:
		return ChangeReopened
	case equalHashes(since, asOf):
		return ChangeUnchanged
	default:
		return ChangeRevised
	}
}

func equalHashes(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for index := range a {
		if a[index] != b[index] {
			return false
		}
	}
	return true
}

// mergedAnomalies unions the anomalies of both views, deduplicated by
// (sequence, anomaly) and ordered by sequence and then by the declaration order
// of the constants, so the result is deterministic without a sort.
func mergedAnomalies(sinceEntries, asOfEntries []Entry) []DiffAnomaly {
	order := []Anomaly{AnomalySupersedesSubjectMismatch, AnomalyAmbiguousSupersession}
	present := make(map[uint64]map[Anomaly]bool, len(sinceEntries))
	mark := func(entries []Entry) {
		for index := range entries {
			sequence := entries[index].Sequence
			if present[sequence] == nil {
				present[sequence] = map[Anomaly]bool{}
			}
			for _, anomaly := range entries[index].Anomalies {
				present[sequence][anomaly] = true
			}
		}
	}
	mark(sinceEntries)
	mark(asOfEntries)
	merged := []DiffAnomaly{}
	for index := range sinceEntries {
		sequence := sinceEntries[index].Sequence
		for _, anomaly := range order {
			if present[sequence][anomaly] {
				merged = append(merged, DiffAnomaly{Sequence: sequence, Anomaly: anomaly})
			}
		}
	}
	return merged
}

// Entries returns deep copies of the per-subject changes in first-appearance
// order. The zero view is invalid.
func (view DiffView) Entries() ([]DiffEntry, error) {
	if !view.initialized {
		return nil, problem(CodeInvalidBook)
	}
	entries := make([]DiffEntry, len(view.entries))
	for index := range view.entries {
		entries[index] = copyDiffEntry(view.entries[index])
	}
	return entries, nil
}

// Declarations returns the hashes of the records decided within (since, asOf],
// in append order. The zero view is invalid.
func (view DiffView) Declarations() ([]string, error) {
	if !view.initialized {
		return nil, problem(CodeInvalidBook)
	}
	declarations := make([]string, len(view.declarations))
	copy(declarations, view.declarations)
	return declarations, nil
}

// Anomalies returns the merged anomalies in the declared order. The zero view is
// invalid.
func (view DiffView) Anomalies() ([]DiffAnomaly, error) {
	if !view.initialized {
		return nil, problem(CodeInvalidBook)
	}
	anomalies := make([]DiffAnomaly, len(view.anomalies))
	copy(anomalies, view.anomalies)
	return anomalies, nil
}

func copyDiffEntry(entry DiffEntry) DiffEntry {
	copied := entry
	copied.SinceHashes = append([]string{}, entry.SinceHashes...)
	copied.AsOfHashes = append([]string{}, entry.AsOfHashes...)
	return copied
}
