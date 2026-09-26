// Package normalize turns one accepted prisma-v1 import into conservative
// normalized facts. The declared image reference is kept verbatim, identity is
// attached only through an explicit caller binding, ingest diagnostics are
// preserved for provenance, and nothing is inferred: an unbound finding stays
// unbound, a rejected record never becomes a finding, and the evidence bundle
// itself is built later (A1-03).
package normalize

import (
	"errors"

	"github.com/d4rpell/Ariadne/internal/identity"
	"github.com/d4rpell/Ariadne/internal/ingest"
	contract "github.com/d4rpell/Ariadne/pkg/evidence"
)

// DeclaredImage is the requested reference as declared by the source: registry,
// repository and tag kept as separate verbatim components. No composition, no
// normalization and no digest inference are applied here (ADR-0007).
type DeclaredImage struct {
	Registry   string
	Repository string
	Tag        string
}

// NormalizationState is internal. It is not a decision state and never reaches
// the wire.
type NormalizationState string

const (
	NormalizationBound      NormalizationState = "bound"
	NormalizationUnbound    NormalizationState = "unbound"
	NormalizationUnresolved NormalizationState = "unresolved"
	NormalizationUnknown    NormalizationState = "unknown"
)

// NormalizedFinding preserves one accepted source finding plus its declared
// image and, when an explicit binding exists, its identity resolution.
// RequestedImage is the reference composed from the declaration by the ADR-0009
// grammar. It is nil when the declaration is not representable: DeclaredImage
// keeps the components verbatim, and the consumer must treat a nil reference of
// a prisma-v1 finding as a blocking condition for that image identity rather
// than as an absent declaration.
type NormalizedFinding struct {
	Source         ingest.Finding
	DeclaredImage  DeclaredImage
	RequestedImage *contract.RequestedImage
	Binding        *identity.ImageBinding
	Resolution     *identity.Resolution
	State          NormalizationState
}

// Diagnostics carries ingest rejections and the structural failure for A1-03 to
// map onto provenance. It is never a finding.
type Diagnostics struct {
	Rejections      []ingest.Rejection
	StructuralError *ingest.FileError
}

// Result is the full conservative normalization of one import.
type Result struct {
	Findings     []NormalizedFinding
	Diagnostics  Diagnostics
	Coverage     contract.Coverage
	Completeness contract.Completeness
}

// Binding is an explicit instruction from the caller linking a finding to a
// scoped container. It is the only linkage mechanism: there is no matching by
// namespace/name, by name or by tag anywhere in this package.
type Binding struct {
	FindingIndex int
	ContainerKey identity.ContainerKey
	Image        identity.ImageBinding
}

// Input is the entry point of this package. Bindings are optional: a finding
// without one stays unbound instead of being guessed. StructuralError is the
// failure ParsePrismaV1 returned alongside the verified progress, kept verbatim
// so provenance can report it.
type Input struct {
	Import          ingest.Result
	StructuralError *ingest.FileError
	Bindings        []Binding
}

var (
	errMethodNotImport          = errors.New("normalize: coverage method is not a findings import")
	errCompletenessNotDeclared  = errors.New("normalize: completeness is not declared")
	errBindingIndexOutOfRange   = errors.New("normalize: binding index is out of range")
	errBindingIndexDuplicated   = errors.New("normalize: duplicate binding for the same finding")
	errBindingKeyMismatch       = errors.New("normalize: binding key does not match the image binding key")
	errResolutionWithoutBinding = errors.New("normalize: resolution carries no binding")
)

// Normalize consumes one ingest result. It never mutates its input, never
// fabricates identity, never promotes a rejected record and never produces a
// bundle. An impossible state (a foreign coverage method, an unusable binding)
// returns an error and an empty result; the absence of identity is a state, not
// an error.
func Normalize(input Input) (Result, error) {
	if problem := importProblem(input.Import); problem != nil {
		return Result{}, problem
	}
	if problem := bindingsProblem(input.Import, input.Bindings); problem != nil {
		return Result{}, problem
	}
	resolutions, err := identity.Resolve(bindingImages(input.Bindings))
	if err != nil {
		return Result{}, err
	}
	byKey := make(map[identity.ContainerKey]identity.Resolution, len(resolutions))
	for _, resolution := range resolutions {
		byKey[resolution.Key] = resolution
	}

	result := Result{
		Findings: make([]NormalizedFinding, 0, len(input.Import.Findings)),
		Diagnostics: Diagnostics{
			Rejections:      append([]ingest.Rejection{}, input.Import.Rejections...),
			StructuralError: copyStructuralError(input.StructuralError),
		},
		Coverage:     copyCoverage(input.Import.Coverage),
		Completeness: input.Import.Completeness,
	}
	boundTo := make(map[int]int, len(input.Bindings))
	for i, binding := range input.Bindings {
		boundTo[binding.FindingIndex] = i
	}
	for i, finding := range input.Import.Findings {
		declared := declaredImageFor(finding)
		normalized := NormalizedFinding{
			Source:        finding,
			DeclaredImage: declared,
			State:         NormalizationUnbound,
		}
		if composed, problem := RequestedImage(declared); problem == nil {
			normalized.RequestedImage = &composed
		}
		if bindingIndex, bound := boundTo[i]; bound {
			binding := input.Bindings[bindingIndex]
			resolution := byKey[binding.ContainerKey]
			if resolution.Binding == nil {
				return Result{}, errResolutionWithoutBinding
			}
			normalized.Binding = resolution.Binding
			normalized.Resolution = &resolution
			normalized.State = stateFor(resolution, input.Import.Completeness)
		}
		result.Findings = append(result.Findings, normalized)
	}
	return result, nil
}

// importProblem accepts only a findings import with a declared completeness. A
// completeness of "complete" describes the file relative to this method; it is
// never read as an inventory of containers.
func importProblem(result ingest.Result) error {
	if result.Coverage.Method != contract.CoverageFindingsImport {
		return errMethodNotImport
	}
	if !result.Completeness.Valid() {
		return errCompletenessNotDeclared
	}
	return nil
}

func bindingsProblem(result ingest.Result, bindings []Binding) error {
	seen := make(map[int]bool, len(bindings))
	for _, binding := range bindings {
		if binding.FindingIndex < 0 || binding.FindingIndex >= len(result.Findings) {
			return errBindingIndexOutOfRange
		}
		if seen[binding.FindingIndex] {
			return errBindingIndexDuplicated
		}
		seen[binding.FindingIndex] = true
		if binding.ContainerKey != binding.Image.Key {
			return errBindingKeyMismatch
		}
	}
	return nil
}

func bindingImages(bindings []Binding) []identity.ImageBinding {
	images := make([]identity.ImageBinding, 0, len(bindings))
	for _, binding := range bindings {
		images = append(images, binding.Image)
	}
	return images
}

// stateFor maps the identity resolution onto the normalized state. An import
// that is not complete never yields an affirmative state: a claim built on a
// file with rejected records or on an aborted read is incomplete evidence, and
// incomplete evidence is unknown, never favourable.
func stateFor(resolution identity.Resolution, completeness contract.Completeness) NormalizationState {
	if completeness != contract.CompletenessComplete {
		return NormalizationUnknown
	}
	switch resolution.State {
	case identity.ResolutionResolved:
		return NormalizationBound
	case identity.ResolutionUnresolved:
		return NormalizationUnresolved
	default:
		return NormalizationUnknown
	}
}

func declaredImageFor(finding ingest.Finding) DeclaredImage {
	return DeclaredImage{
		Registry:   finding.ImageRegistry,
		Repository: finding.ImageRepository,
		Tag:        finding.ImageTag,
	}
}

// copyCoverage detaches the counted rows from the caller, including the total,
// which is itself a pointer: the parser result must not be observed to change,
// and a shared pointer would let one consumer rewrite another's counters.
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

// copyStructuralError detaches the reported failure from the caller for the same
// reason the counters are detached: the result must not change under a caller
// that keeps writing to the value it passed in.
func copyStructuralError(failure *ingest.FileError) *ingest.FileError {
	if failure == nil {
		return nil
	}
	copied := *failure
	return &copied
}
