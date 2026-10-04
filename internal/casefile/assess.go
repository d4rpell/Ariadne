package casefile

// Derived validity view (ADR-0031, task A3-02). Assess classifies every
// admitted record at a caller-supplied instant and resolves invalidation through
// declared supersedes relations. It is a pure function: it opens no paths, uses
// no clock, and never rewrites the book. The vocabulary here is a derived
// governance view, never a product status, an exploitability value or a risk
// decision, and it never emits an exception-candidate label.

// Standing is the derived status of one record at an as-of instant.
type Standing string

const (
	StandingPending    Standing = "pending"
	StandingSuperseded Standing = "superseded"
	StandingExpired    Standing = "expired"
	StandingEffective  Standing = "effective"
)

// Subject is the continuity key of invalidation: the scope without the
// bundle-dependent fields. It is not a scope of application; each Entry keeps
// the full Scope so the caller can judge applicability.
type Subject struct {
	SubjectUID      string
	ContainerName   string
	ContainerClass  ContainerClass
	VulnerabilityID string
}

// Anomaly is a closed vocabulary of signals. It is not an error and does not
// change the outcome of Assess; it marks data that must not be resolved
// silently. A signal is either structural (independent of the as-of instant) or
// evaluated at that instant, as documented on each value.
type Anomaly string

const (
	// AnomalySupersedesSubjectMismatch marks a record whose Supersedes points
	// to a record of another Subject. The reference does not invalidate.
	AnomalySupersedesSubjectMismatch Anomaly = "supersedes_subject_mismatch"
	// AnomalyAmbiguousSupersession marks a record with two or more admissible
	// direct successors at the as-of instant. SupersededBy keeps the lowest
	// Sequence.
	AnomalyAmbiguousSupersession Anomaly = "ambiguous_supersession"
)

// Entry is the derived view of one record. Scope is conserved verbatim so the
// caller can match applicability; Subject is its continuity key.
type Entry struct {
	Sequence     uint64
	Hash         string
	Scope        Scope
	Subject      Subject
	Decision     Decision
	DecidedAt    string
	ExpiresAt    *string
	Standing     Standing
	SupersededBy *string
	Anomalies    []Anomaly
}

// View is an immutable derived view. The zero value is invalid.
type View struct {
	initialized bool
	entries     []Entry
}

// SubjectOf returns the continuity key of a scope: the scope without the bundle
// hash and the result fingerprint.
func SubjectOf(scope Scope) Subject {
	return Subject{
		SubjectUID:      scope.SubjectUID,
		ContainerName:   scope.ContainerName,
		ContainerClass:  scope.ContainerClass,
		VulnerabilityID: scope.VulnerabilityID,
	}
}

// Assess classifies every record of an admitted book at the instant asOf. The
// standing precedence is fixed: pending, then superseded, then expired, then
// effective. A supersedes edge is admissible only when the successor shares the
// predecessor's Subject and its DecidedAt is not after asOf; the successor need
// not itself be effective. asOf and every timestamp are compared as bytes,
// which is chronological because the profile fixes a zero-padded twenty-byte
// form; no clock is read. Assess never mutates the book.
func Assess(book Book, asOf string) (View, error) {
	if !book.initialized {
		return View{}, problem(CodeInvalidBook)
	}
	if err := validateChain(book.records); err != nil {
		return View{}, err
	}
	if err := validateTimestamp(asOf); err != nil {
		return View{}, err
	}

	index := make(map[string]int, len(book.records))
	entries := make([]Entry, len(book.records))
	for position := range book.records {
		record := &book.records[position]
		index[record.Hash] = position
		entries[position] = Entry{
			Sequence:  record.Sequence,
			Hash:      record.Hash,
			Scope:     copyScope(record.Decision.Scope),
			Subject:   SubjectOf(record.Decision.Scope),
			Decision:  record.Decision.RiskDecision,
			DecidedAt: record.Decision.DecidedAt,
			ExpiresAt: copyPointer(record.Decision.ExpiresAt),
		}
	}

	// Structural anomaly: a supersedes reference that leaves its Subject. It is
	// independent of asOf and is reported on the record that carries it.
	for position := range book.records {
		reference := book.records[position].Decision.Supersedes
		if reference == nil {
			continue
		}
		referenced, ok := index[*reference]
		if !ok {
			// validateChain guarantees the reference exists; keep fail-closed.
			continue
		}
		if SubjectOf(book.records[position].Decision.Scope) != SubjectOf(book.records[referenced].Decision.Scope) {
			entries[position].Anomalies = append(entries[position].Anomalies, AnomalySupersedesSubjectMismatch)
		}
	}

	for position := range book.records {
		record := &book.records[position]
		// Admissible successors and their anomaly are computed independently of
		// the standing precedence: a record that has not started yet (pending)
		// still carries the successors that already point at it.
		successors := 0
		for other := range book.records {
			candidate := &book.records[other]
			if candidate.Decision.Supersedes == nil || *candidate.Decision.Supersedes != record.Hash {
				continue
			}
			if SubjectOf(candidate.Decision.Scope) != entries[position].Subject {
				continue
			}
			if candidate.Decision.DecidedAt > asOf {
				continue
			}
			if successors == 0 {
				head := candidate.Hash
				entries[position].SupersededBy = &head
			}
			successors++
		}
		if successors > 1 {
			entries[position].Anomalies = append(entries[position].Anomalies, AnomalyAmbiguousSupersession)
		}
		switch {
		case record.Decision.DecidedAt > asOf:
			entries[position].Standing = StandingPending
		case successors > 0:
			entries[position].Standing = StandingSuperseded
		case record.Decision.ExpiresAt != nil && *record.Decision.ExpiresAt <= asOf:
			entries[position].Standing = StandingExpired
		default:
			entries[position].Standing = StandingEffective
		}
	}

	return View{initialized: true, entries: entries}, nil
}

// Entries returns deep copies of the derived entries in append order.
func (view View) Entries() ([]Entry, error) {
	if !view.initialized {
		return nil, problem(CodeInvalidBook)
	}
	entries := make([]Entry, len(view.entries))
	for position := range view.entries {
		entries[position] = copyEntry(view.entries[position])
	}
	return entries, nil
}

// Candidates returns the effective entries whose Subject matches, in append
// order. They are candidates within the book, never an applicable decision:
// the caller must match the full Scope against the evidence it holds. No
// conflict is collapsed, and the Subject components are compared for equality
// without further validation.
func (view View) Candidates(subject Subject) ([]Entry, error) {
	if !view.initialized {
		return nil, problem(CodeInvalidBook)
	}
	candidates := []Entry{}
	for position := range view.entries {
		entry := &view.entries[position]
		if entry.Standing == StandingEffective && entry.Subject == subject {
			candidates = append(candidates, copyEntry(*entry))
		}
	}
	return candidates, nil
}

func copyEntry(entry Entry) Entry {
	copied := entry
	copied.Scope = copyScope(entry.Scope)
	copied.ExpiresAt = copyPointer(entry.ExpiresAt)
	copied.SupersededBy = copyPointer(entry.SupersededBy)
	if entry.Anomalies != nil {
		copied.Anomalies = make([]Anomaly, len(entry.Anomalies))
		copy(copied.Anomalies, entry.Anomalies)
	}
	return copied
}
