package platform

import (
	"errors"

	"github.com/d4rpell/Ariadne/internal/casefile"
)

// errInconsistentProjection guards an internal invariant: the derived entries
// and the raw records are projections of the same admitted book and must have
// the same length. It is never expected to fire; failing closed keeps a defect
// from indexing out of range or dropping a record silently.
var errInconsistentProjection = errors.New("platform: inconsistent book projection")

// Model is the ordered, read-only projection of one verified book at one as-of
// instant. It is pure data: no slice, pointer or map of it aliases the book.
type Model struct {
	AsOf        string
	RecordCount int
	HeadHash    string
	Entries     []Entry
}

// HasHead reports whether the book has a head record. The empty book has none
// and its hash is rendered as an explicit null.
func (model Model) HasHead() bool { return model.HeadHash != "" }

// Entry is one declared decision together with its derived validity view. It
// reproduces the declared values; Standing, SupersededBy and Anomalies are the
// derived view of ADR-0031, shown as derived and never collapsed into the
// decision.
type Entry struct {
	Sequence     uint64
	Hash         string
	PreviousHash *string
	RiskDecision string
	Owner        string
	Approver     string
	Rationale    string
	Scope        Scope
	Controls     []string
	DecidedAt    string
	ExpiresAt    *string
	Standing     string
	SupersededBy *string
	Anomalies    []string
}

// Scope is the declared scope of application, conserved verbatim.
type Scope struct {
	BundleHash        string
	SubjectUID        string
	ContainerName     string
	ContainerClass    string
	VulnerabilityID   string
	ResultFingerprint *string
}

// BuildModel projects an admitted book at the instant asOf. It validates the
// book chain and the instant through casefile.Assess and never mutates the
// book: every value of the model is an independent copy.
func BuildModel(book casefile.Book, asOf string) (Model, error) {
	view, err := casefile.Assess(book, asOf)
	if err != nil {
		return Model{}, err
	}
	records, err := casefile.Records(book)
	if err != nil {
		return Model{}, err
	}
	entries, err := view.Entries()
	if err != nil {
		return Model{}, err
	}
	if len(records) != len(entries) {
		return Model{}, errInconsistentProjection
	}
	head, err := casefile.HeadHash(book)
	if err != nil {
		return Model{}, err
	}

	model := Model{
		AsOf:        asOf,
		RecordCount: len(records),
		HeadHash:    head,
		Entries:     make([]Entry, 0, len(records)),
	}
	for position := range records {
		record := records[position]
		assessment := entries[position]
		model.Entries = append(model.Entries, Entry{
			Sequence:     record.Sequence,
			Hash:         record.Hash,
			PreviousHash: copyText(record.PreviousHash),
			RiskDecision: string(record.Decision.RiskDecision),
			Owner:        record.Decision.Owner,
			Approver:     record.Decision.Approver,
			Rationale:    record.Decision.Rationale,
			Scope: Scope{
				BundleHash:        record.Decision.Scope.BundleHash,
				SubjectUID:        record.Decision.Scope.SubjectUID,
				ContainerName:     record.Decision.Scope.ContainerName,
				ContainerClass:    string(record.Decision.Scope.ContainerClass),
				VulnerabilityID:   record.Decision.Scope.VulnerabilityID,
				ResultFingerprint: copyText(record.Decision.Scope.ResultFingerprint),
			},
			Controls:     copyControls(record.Decision.Controls),
			DecidedAt:    record.Decision.DecidedAt,
			ExpiresAt:    copyText(record.Decision.ExpiresAt),
			Standing:     string(assessment.Standing),
			SupersededBy: copyText(assessment.SupersededBy),
			Anomalies:    anomalyText(assessment.Anomalies),
		})
	}
	return model, nil
}

// Entry returns the entry whose Sequence is sequence. The second result is false
// when no entry carries it.
func (model Model) Entry(sequence uint64) (Entry, bool) {
	for position := range model.Entries {
		if model.Entries[position].Sequence == sequence {
			return model.Entries[position], true
		}
	}
	return Entry{}, false
}

func copyText(value *string) *string {
	if value == nil {
		return nil
	}
	copied := *value
	return &copied
}

func copyControls(controls []string) []string {
	if controls == nil {
		return nil
	}
	copied := make([]string, len(controls))
	copy(copied, controls)
	return copied
}

func anomalyText(anomalies []casefile.Anomaly) []string {
	if len(anomalies) == 0 {
		return nil
	}
	text := make([]string, len(anomalies))
	for index := range anomalies {
		text[index] = string(anomalies[index])
	}
	return text
}
