package bundle

import (
	"errors"
	"reflect"
	"strings"
	"time"
	"unicode/utf8"

	canonical "github.com/d4rpell/Ariadne/internal/evidence"
	"github.com/d4rpell/Ariadne/internal/identity"
	"github.com/d4rpell/Ariadne/internal/ingest"
	"github.com/d4rpell/Ariadne/internal/normalize"
	contract "github.com/d4rpell/Ariadne/pkg/evidence"
)

// ImportSource identifies the CSV whose bytes were parsed. Hash must cover the
// complete source and ObservedAt must be the observation time of that source;
// neither is derived from the rows, from the run clock or from the vulnerability
// dates (ADR-0012 §2).
type ImportSource struct {
	Path       string
	Hash       contract.SourceHash
	ObservedAt *contract.Timestamp
}

// RunContext carries the explicit run metadata of the bundle. Nil Warnings
// means "none". No version, budget or policy is invented: everything here was
// supplied by the caller, and Ruleset stays the zero value (null on the wire).
type RunContext struct {
	CollectorVersion string
	ParserVersion    string
	ArgvSanitized    []string
	StartedAt        *contract.Timestamp
	EndedAt          *contract.Timestamp
	Budget           contract.Budget
	Consistency      contract.Consistency
	RedactionPolicy  string
	Warnings         []contract.Warning
}

// Input is everything Build consumes. Normalized is the whole import, not a
// slice pre-filtered by subject, and Subject is the caller's explicit choice of
// bundle identity: no subject is ever fabricated from a finding.
type Input struct {
	Normalized normalize.Result
	Subject    contract.Subject
	Source     ImportSource
	Run        RunContext
}

// OmissionReason is the static vocabulary of projection omissions.
type OmissionReason string

const (
	// OmissionUnbound is a finding without a binding: no UID is attributable.
	OmissionUnbound OmissionReason = "unbound"
	// OmissionOtherSubject is a finding bound to a workload outside this
	// subject: it belongs to another bundle, and its exclusion stays visible.
	OmissionOtherSubject OmissionReason = "other_subject"
	// OmissionScopeCollision is a key omitted by ADR-0010 §2.
	OmissionScopeCollision OmissionReason = "scope_collision"
	// OmissionRequestedImage is a blocked image identity (ADR-0009 §1).
	OmissionRequestedImage OmissionReason = "requested_image_unrepresentable"
	// OmissionMissingProvenance is an observation whose source identity is
	// incomplete, so its facts cannot be evidenced (ADR-0012 §3).
	OmissionMissingProvenance OmissionReason = "missing_provenance"
)

// Omission reports one finding left out of the emitted bundle. It carries the
// index, the row locator and a static reason: never the rejected content and
// never container identifiers.
type Omission struct {
	FindingIndex int
	Locator      ingest.Locator
	Reason       OmissionReason
}

// Diagnostics is returned next to the bundle. It is not part of the wire and
// must not be serialized as a bundle extension.
type Diagnostics struct {
	Ingest         normalize.Diagnostics
	Omissions      []Omission
	CollisionCount int
}

var (
	errSourcePath            = errors.New("bundle: source path is required")
	errSourceHash            = errors.New("bundle: source hash is not a sha256 digest")
	errSourceObservedAt      = errors.New("bundle: source observed_at is required")
	errCollectorVersion      = errors.New("bundle: collector version is required")
	errParserVersion         = errors.New("bundle: parser version is required")
	errRedactionPolicy       = errors.New("bundle: redaction policy is required")
	errArgvSanitized         = errors.New("bundle: argv sanitized is required")
	errNotImport             = errors.New("bundle: normalized result is not a findings import")
	errCompleteness          = errors.New("bundle: completeness is not declared")
	errBindingCoherence      = errors.New("bundle: binding is not coherent with its resolution")
	errScopeCollisionOmitted = errors.New("bundle: scope collision omitted")
	errRequestedImageBlocked = errors.New("bundle: requested image is not representable")
	errObservationUnproven   = errors.New("bundle: observation provenance is incomplete")
)

// Build projects one normalized import onto a bundle of the given subject.
// err == nil means the bundle is valid, not that the import is complete and
// never that a conclusion is favourable: the caller keeps the diagnostics and
// the provenance. A projection defect inside the subject yields a valid partial
// bundle with visible errors; an unusable input yields no bundle at all.
func Build(input Input) (contract.Bundle, Diagnostics, error) {
	if err := validateInput(input); err != nil {
		return contract.Bundle{}, Diagnostics{Ingest: copyDiagnostics(input.Normalized.Diagnostics)}, err
	}
	normalized := copyResult(input.Normalized)
	source := copyImportSource(input.Source)
	run := copyRun(input.Run)
	diagnostics := Diagnostics{Ingest: copyDiagnostics(normalized.Diagnostics)}

	collidedKeys, collisionWarnings, collisionErrors, err := subjectCollisions(normalized, input.Subject.UID)
	if err != nil {
		return contract.Bundle{}, diagnostics, err
	}
	diagnostics.CollisionCount = len(collidedKeys)

	messages := importErrors(diagnostics.Ingest)
	messages = append(messages, collisionErrors...)

	images := make([]contract.ImageIdentity, 0, len(normalized.Findings))
	evidence := make([]contract.EvidenceItem, 0, len(normalized.Findings))
	omissions := make([]Omission, 0, len(normalized.Findings))

	for index, finding := range normalized.Findings {
		if finding.Binding == nil {
			omissions = append(omissions, Omission{FindingIndex: index, Locator: finding.Source.Locator, Reason: OmissionUnbound})
			continue
		}
		binding := *finding.Binding
		if binding.Key.SubjectUID != input.Subject.UID {
			omissions = append(omissions, Omission{FindingIndex: index, Locator: finding.Source.Locator, Reason: OmissionOtherSubject})
			continue
		}
		if collidedKeys[scopeKey{SubjectUID: binding.Key.SubjectUID, ContainerName: binding.Key.ContainerName}] {
			omissions = append(omissions, Omission{FindingIndex: index, Locator: finding.Source.Locator, Reason: OmissionScopeCollision})
			continue
		}
		evidence = append(evidence, projectDeclared(input.Subject, finding, source)...)
		if finding.RequestedImage == nil {
			omissions = append(omissions, Omission{FindingIndex: index, Locator: finding.Source.Locator, Reason: OmissionRequestedImage})
			messages = append(messages, errRequestedImageBlocked.Error())
			continue
		}
		evidence = append(evidence, projectRequestedImage(input.Subject, finding, source))
		complete := observationProvenanceComplete(binding)
		observed := binding.RawImageID != nil || binding.GuaranteedDigest != nil
		if observed && !complete {
			images = append(images, projectImage(finding, false))
			omissions = append(omissions, Omission{FindingIndex: index, Locator: finding.Source.Locator, Reason: OmissionMissingProvenance})
			messages = append(messages, errObservationUnproven.Error())
			continue
		}
		images = append(images, projectImage(finding, complete))
		if complete {
			evidence = append(evidence, projectObserved(input.Subject, binding)...)
		}
	}
	diagnostics.Omissions = omissions

	bundle := contract.Bundle{
		SchemaVersion:            contract.SchemaVersionSupported,
		Subject:                  input.Subject,
		Images:                   images,
		Evidence:                 evidence,
		ObservedContainerClasses: []contract.ContainerClass{},
		Provenance:               buildProvenance(run, normalized, source, collisionWarnings, messages),
	}
	validated, err := canonical.NewBundle(bundle)
	if err != nil {
		return contract.Bundle{}, diagnostics, err
	}
	return validated, diagnostics, nil
}

func validateInput(input Input) error {
	if !identifierOK(input.Source.Path) {
		return errSourcePath
	}
	if !isSha256(string(input.Source.Hash)) {
		return errSourceHash
	}
	if !timestampOK(input.Source.ObservedAt) {
		return errSourceObservedAt
	}
	if !identifierOK(input.Run.CollectorVersion) {
		return errCollectorVersion
	}
	if !identifierOK(input.Run.ParserVersion) {
		return errParserVersion
	}
	if !identifierOK(input.Run.RedactionPolicy) {
		return errRedactionPolicy
	}
	if input.Run.ArgvSanitized == nil {
		return errArgvSanitized
	}
	if input.Normalized.Coverage.Method != contract.CoverageFindingsImport {
		return errNotImport
	}
	if !input.Normalized.Completeness.Valid() {
		return errCompleteness
	}
	for _, finding := range input.Normalized.Findings {
		if err := findingCoherence(finding, input.Normalized.Completeness); err != nil {
			return err
		}
	}
	return nil
}

// findingCoherence refuses a normalized finding that no Normalize run can
// produce: a resolution without a binding, a key mismatch, a divergence between
// the finding's observation and the one its resolution carries, or a state that
// claims more than the import and the resolution support.
func findingCoherence(finding normalize.NormalizedFinding, completeness contract.Completeness) error {
	switch finding.State {
	case normalize.NormalizationUnbound, normalize.NormalizationUnresolved,
		normalize.NormalizationBound, normalize.NormalizationUnknown:
	default:
		return errBindingCoherence
	}
	if finding.Binding == nil {
		if finding.Resolution != nil || finding.State != normalize.NormalizationUnbound {
			return errBindingCoherence
		}
		return nil
	}
	if finding.Resolution == nil || finding.Resolution.Binding == nil {
		return errBindingCoherence
	}
	if finding.Resolution.Key != finding.Binding.Key || finding.Resolution.Binding.Key != finding.Binding.Key {
		return errBindingCoherence
	}
	// Normalize attaches the resolution's own observation to the finding: the
	// two must be the same observation, so a fabricated divergence is refused
	// instead of being projected as facts.
	if !reflect.DeepEqual(*finding.Binding, *finding.Resolution.Binding) {
		return errBindingCoherence
	}
	// The state is exactly what normalize.stateFor derives: bound and unresolved
	// only over a complete import, and unknown whenever the import is incomplete
	// or the resolution itself is unknown. The resolution state enum is checked
	// on both paths, so an invented value is refused even over a partial import.
	var expected normalize.NormalizationState
	switch finding.Resolution.State {
	case identity.ResolutionResolved:
		expected = normalize.NormalizationBound
	case identity.ResolutionUnresolved:
		expected = normalize.NormalizationUnresolved
	case identity.ResolutionUnknown:
		expected = normalize.NormalizationUnknown
	default:
		return errBindingCoherence
	}
	if completeness != contract.CompletenessComplete {
		expected = normalize.NormalizationUnknown
	}
	if finding.State != expected {
		return errBindingCoherence
	}
	return nil
}

// identifierOK mirrors the wire rule for identifiers: present, no surrounding
// whitespace, valid UTF-8. It never trims or transforms.
func identifierOK(value string) bool {
	return value != "" && strings.TrimSpace(value) == value && utf8.ValidString(value)
}

// wireValueOK reports whether a value can be carried verbatim by evidence.value.
// A value that fails it is still recorded by hash, never trimmed.
func wireValueOK(value string) bool {
	return strings.TrimSpace(value) == value && utf8.ValidString(value)
}

func timestampOK(value *contract.Timestamp) bool {
	if value == nil || value.IsZero() {
		return false
	}
	return value.Location() == time.UTC
}

func copyPointer[T any](value *T) *T {
	if value == nil {
		return nil
	}
	copied := *value
	return &copied
}

func copyResult(result normalize.Result) normalize.Result {
	copied := normalize.Result{
		Diagnostics:  copyDiagnostics(result.Diagnostics),
		Coverage:     copyCoverage(result.Coverage),
		Completeness: result.Completeness,
		Findings:     make([]normalize.NormalizedFinding, len(result.Findings)),
	}
	for index, finding := range result.Findings {
		copied.Findings[index] = copyFinding(finding)
	}
	return copied
}

func copyFinding(finding normalize.NormalizedFinding) normalize.NormalizedFinding {
	copied := finding
	copied.RequestedImage = copyPointer(finding.RequestedImage)
	copied.Binding = copyBinding(finding.Binding)
	copied.Resolution = copyResolution(finding.Resolution)
	return copied
}

func copyResolution(resolution *identity.Resolution) *identity.Resolution {
	if resolution == nil {
		return nil
	}
	copied := *resolution
	copied.Binding = copyBinding(resolution.Binding)
	if resolution.AdvisoryNotes != nil {
		copied.AdvisoryNotes = append([]string{}, resolution.AdvisoryNotes...)
	}
	return &copied
}

func copyBinding(binding *identity.ImageBinding) *identity.ImageBinding {
	if binding == nil {
		return nil
	}
	copied := *binding
	copied.RequestedImage = copyPointer(binding.RequestedImage)
	copied.RawImageID = copyPointer(binding.RawImageID)
	copied.GuaranteedDigest = copyPointer(binding.GuaranteedDigest)
	copied.ObservedAt = copyPointer(binding.ObservedAt)
	return &copied
}

func copyDiagnostics(diagnostics normalize.Diagnostics) normalize.Diagnostics {
	copied := normalize.Diagnostics{
		Rejections: append([]ingest.Rejection{}, diagnostics.Rejections...),
	}
	if diagnostics.StructuralError != nil {
		failure := *diagnostics.StructuralError
		copied.StructuralError = &failure
	}
	return copied
}

// copyCoverage detaches the counted rows, including the total pointer, so a
// consumer of the result cannot rewrite what the caller still holds.
func copyCoverage(coverage contract.Coverage) contract.Coverage {
	copied := coverage
	if coverage.Rows != nil {
		rows := *coverage.Rows
		if coverage.Rows.Total != nil {
			total := *coverage.Rows.Total
			rows.Total = &total
		}
		copied.Rows = &rows
	}
	return copied
}

func copyImportSource(source ImportSource) ImportSource {
	copied := source
	copied.ObservedAt = copyPointer(source.ObservedAt)
	return copied
}

func copyRun(run RunContext) RunContext {
	copied := run
	copied.ArgvSanitized = append([]string{}, run.ArgvSanitized...)
	copied.StartedAt = copyPointer(run.StartedAt)
	copied.EndedAt = copyPointer(run.EndedAt)
	copied.Warnings = append([]contract.Warning{}, run.Warnings...)
	return copied
}
