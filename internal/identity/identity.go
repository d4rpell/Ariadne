// Package identity resolves container identity conservatively. A resolution is
// affirmative only when it is anchored in metadata.uid plus container
// (uid + class + name) and in an image reference whose content identity is
// established: either a digest the source proved unambiguous, or the raw image
// ID exactly as observed. namespace/name is not representable here because it is
// context, never identity. The package is pure: no network, no shell, no clock,
// no filesystem, and no bundle or wire construction.
package identity

import (
	"errors"
	"unicode"
	"unicode/utf8"

	contract "github.com/d4rpell/Ariadne/pkg/evidence"
)

// InputKind labels where an observation came from. Synthetic bindings and
// container-observation bindings (the sanitized PodList profile of ADR-0025)
// are admitted; any other kind is refused fail-closed instead of being
// inferred. Admitting a kind never authenticates the origin: provenance is
// established by the evidence items, not by this label.
type InputKind string

const (
	InputSynthetic            InputKind = "synthetic"
	InputContainerObservation InputKind = "container_observation"
)

// ContainerKey is the identity key: uid + container class + container name. It
// is deliberately not namespace/name, which a Pod replacement keeps while the
// UID changes.
type ContainerKey struct {
	SubjectUID     contract.UID
	ContainerClass contract.ContainerClass
	ContainerName  contract.ContainerName
}

// ImageBinding is one image observation, already scoped to uid + container.
// RequestedImage and RawImageID stay separate fields: a declared reference is
// never copied onto an observed one. GuaranteedDigest must come from
// NewGuaranteedDigest and its format is re-checked on every resolution, so a
// value placed on the field directly is refused instead of being believed.
// PlatformOS and PlatformArchitecture carry an observed platform (ADR-0009):
// they are empty unless the source observed them, and PlatformKnown requires
// both together with a guaranteed digest.
type ImageBinding struct {
	Key                  ContainerKey
	InputKind            InputKind
	SourceName           string
	SourceHash           contract.SourceHash
	Locator              contract.SourceLocator
	RequestedImage       *contract.RequestedImage
	RawImageID           *contract.RawImageID
	GuaranteedDigest     *contract.NormalizedDigest
	Platform             contract.PlatformStatus
	PlatformOS           string
	PlatformArchitecture string
	ObservedAt           *contract.Timestamp
}

// ResolutionState is an internal conservative outcome. It is not a decision
// state and never reaches the wire.
type ResolutionState string

const (
	ResolutionResolved   ResolutionState = "resolved"
	ResolutionUnresolved ResolutionState = "unresolved"
	ResolutionUnknown    ResolutionState = "unknown"
)

// ConflictSourceConflict marks a container key that carries more than one image
// observation. It matches the warning code of the same name in the evidence
// contract; A1-02 only reports it, it does not choose between observations.
const ConflictSourceConflict = "source_conflict"

// Resolution is the conservative outcome for one ContainerKey.
type Resolution struct {
	Key           ContainerKey
	State         ResolutionState
	Binding       *ImageBinding
	BindingCount  int
	ConflictCode  string
	AdvisoryNotes []string
}

var (
	errKeyNotIdentifier            = errors.New("identity: container key is not an identifier")
	errKeyClassInvalid             = errors.New("identity: container class is not one of regular, init, ephemeral")
	errInputKindUnsupported        = errors.New("identity: input kind is not supported by this version")
	errPlatformNotDeclared         = errors.New("identity: platform status is not declared")
	errPlatformKnownNoCarrier      = errors.New("identity: platform known requires observed os and architecture")
	errPlatformKnownWithoutDigest  = errors.New("identity: platform known requires a digest proven by the source")
	errPlatformUnknownWithObserved = errors.New("identity: platform unknown cannot carry an observed os or architecture")
	errDigestNotGuaranteed         = errors.New("identity: digest is not in an unambiguous format")
	errDigestNotProven             = errors.New("identity: guaranteed digest is not in the proven format")
	errImageRefNotIdentifier       = errors.New("identity: requested image is not an identifier")
	errRawImageIDNotIdentifier     = errors.New("identity: raw image id is not an identifier")
	errBindingConflict             = errors.New("identity: conflicting bindings for the same container key")
)

// digestPrefix and sha256HexLength define the only digest form this package
// accepts as proven: exact lowercase sha256: plus 64 lowercase hex digits. Any
// other shape is rejected, never normalized: a digest inferred from a tag or
// repaired from an ambiguous value would sustain false conclusions later.
const (
	digestPrefix    = "sha256:"
	sha256HexLength = 64
)

// NewGuaranteedDigest returns a digest whose format this package has verified.
// The caller asserts that the digest was proven to reference the artifact
// content for the observed platform: an index digest that aggregates
// per-platform manifests is never passed here, it is preserved as the observed
// raw image ID with an unknown platform (ADR-0010). A value converted directly
// without this constructor is refused when consumed: ResolveOne re-checks the
// format of every digest a binding carries. Provenance of the assertion itself
// cannot be proven by this package: it is established by the evidence items and
// their provenance fields, and produced by a reviewed adapter (ADR-0010).
func NewGuaranteedDigest(value string) (contract.NormalizedDigest, error) {
	if !digestFormatGuaranteed(value) {
		return "", errDigestNotGuaranteed
	}
	return contract.NormalizedDigest(value), nil
}

func digestFormatGuaranteed(value string) bool {
	if len(value) != len(digestPrefix)+sha256HexLength || value[:len(digestPrefix)] != digestPrefix {
		return false
	}
	for i := len(digestPrefix); i < len(value); i++ {
		c := value[i]
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}

// ResolveOne resolves a single binding. The returned resolution keeps the
// binding whenever the state is resolved or unresolved; it carries no binding
// when the input is refused, so a caller that ignores the error still sees a
// non-affirmative state. Every field a binding carries is validated here, not
// only at construction: a digest set around NewGuaranteedDigest is refused
// rather than believed.
func ResolveOne(binding ImageBinding) (Resolution, error) {
	resolution := Resolution{Key: binding.Key, State: ResolutionUnknown, BindingCount: 1}
	if err := keyProblem(binding.Key); err != nil {
		return resolution, err
	}
	if err := inputKindProblem(binding.InputKind); err != nil {
		return resolution, err
	}
	if err := platformProblem(binding); err != nil {
		return resolution, err
	}
	if err := imageProblem(binding); err != nil {
		return resolution, err
	}
	kept := copyBinding(binding)
	resolution.Binding = &kept
	if affirmativeEvidence(binding) {
		resolution.State = ResolutionResolved
	} else {
		resolution.State = ResolutionUnresolved
	}
	return resolution, nil
}

// copyBinding detaches the observation from the caller: the pointers a binding
// carries are copied, so a consumer of a resolution cannot rewrite values the
// caller still holds, and the caller cannot rewrite what the resolution
// asserts.
func copyBinding(binding ImageBinding) ImageBinding {
	copied := binding
	if binding.RequestedImage != nil {
		value := *binding.RequestedImage
		copied.RequestedImage = &value
	}
	if binding.RawImageID != nil {
		value := *binding.RawImageID
		copied.RawImageID = &value
	}
	if binding.GuaranteedDigest != nil {
		value := *binding.GuaranteedDigest
		copied.GuaranteedDigest = &value
	}
	if binding.ObservedAt != nil {
		value := *binding.ObservedAt
		copied.ObservedAt = &value
	}
	return copied
}

// affirmativeEvidence holds the whole criterion for "content identity
// established". A requested tag alone is never enough: it is mutable. Platform
// is not part of it, because an unobserved platform is a normal, conservative
// value, not a defect of the binding.
func affirmativeEvidence(binding ImageBinding) bool {
	return binding.GuaranteedDigest != nil || binding.RawImageID != nil
}

func keyProblem(key ContainerKey) error {
	if !identifier(string(key.SubjectUID)) || !identifier(string(key.ContainerName)) {
		return errKeyNotIdentifier
	}
	if !key.ContainerClass.Valid() {
		return errKeyClassInvalid
	}
	return nil
}

// platformProblem validates the declared platform together with its carrier
// (ADR-0009). A known platform needs both observed fields, each an identifier,
// and a digest proven by the source, because the wire cannot express a known
// platform without one. An unknown platform carries neither field: an observed
// value there would be lost on the wire and is refused rather than dropped.
// Platform is never inferred from the host, the build or the process.
func platformProblem(binding ImageBinding) error {
	switch binding.Platform {
	case contract.PlatformUnknown:
		if binding.PlatformOS != "" || binding.PlatformArchitecture != "" {
			return errPlatformUnknownWithObserved
		}
		return nil
	case contract.PlatformKnown:
		if !identifier(binding.PlatformOS) || !identifier(binding.PlatformArchitecture) {
			return errPlatformKnownNoCarrier
		}
		if binding.GuaranteedDigest == nil {
			return errPlatformKnownWithoutDigest
		}
		return nil
	default:
		return errPlatformNotDeclared
	}
}

// imageProblem validates the optional references a binding carries, if present.
// A present reference must be an identifier, and a digest must match the proven
// format: a value set directly on the exported field is refused here instead of
// being believed.
func imageProblem(binding ImageBinding) error {
	if binding.RequestedImage != nil && !identifier(string(*binding.RequestedImage)) {
		return errImageRefNotIdentifier
	}
	if binding.RawImageID != nil && !identifier(string(*binding.RawImageID)) {
		return errRawImageIDNotIdentifier
	}
	if binding.GuaranteedDigest != nil && !digestFormatGuaranteed(string(*binding.GuaranteedDigest)) {
		return errDigestNotProven
	}
	return nil
}

// identifier mirrors the contract rule for identifiers: non-empty and without
// surrounding whitespace. It never trims: trimming would silently merge two
// distinct keys into one.
func identifier(text string) bool {
	if text == "" || !utf8.ValidString(text) {
		return false
	}
	first, _ := utf8.DecodeRuneInString(text)
	last, _ := utf8.DecodeLastRuneInString(text)
	return !unicode.IsSpace(first) && !unicode.IsSpace(last)
}

func inputKindProblem(kind InputKind) error {
	if kind == InputSynthetic || kind == InputContainerObservation {
		return nil
	}
	return errInputKindUnsupported
}
