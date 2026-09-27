package evaluator

import (
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/d4rpell/Ariadne/internal/rulepack"
	contract "github.com/d4rpell/Ariadne/pkg/evidence"
)

// SourceRole is the closed set of source roles a domain pin may declare.
type SourceRole string

const (
	SourceRoleMapping  SourceRole = "mapping"
	SourceRoleArtifact SourceRole = "artifact"
	SourceRoleVendor   SourceRole = "vendor"
)

// SourcePin authorizes one exact source for one role. advisory_id and
// advisory_revision are explicit nulls for mapping and artifact, and required
// strings for vendor (ADR-0015 §7.1).
type SourcePin struct {
	Role             SourceRole
	Source           string
	SourceHash       contract.SourceHash
	AdvisoryID       *string
	AdvisoryRevision *string
}

// DomainContext is the explicit caller policy of the product profile: the
// maximum accepted evidence age in seconds and the exact set of authorized
// sources. It has no default: an absent context is an error, never a zero TTL.
type DomainContext struct {
	MaximumEvidenceAgeSeconds int64
	SourcePins                []SourcePin
}

// MaxSourcePins is the cardinality limit of ADR-0015 §7.1.
const MaxSourcePins = 128

// MaxDomainEvidenceAgeSeconds is the exclusive upper bound of the age policy:
// 2^53-1, the same numeric ceiling the pack version uses.
const MaxDomainEvidenceAgeSeconds = int64(1<<53 - 1)

// validateDomainContext checks the form of one context. It never repairs: an
// absent TTL, an out-of-range value, an empty collection, a bad role, string or
// hash, a wrong null and a repeated identical pin are all invalid_context. The
// code belongs to the pack vocabulary (ADR-0018 §4), so the failure is the same
// one the admission context already produces.
func validateDomainContext(context DomainContext) error {
	if context.MaximumEvidenceAgeSeconds < 1 || context.MaximumEvidenceAgeSeconds > MaxDomainEvidenceAgeSeconds {
		return contextProblem(-1)
	}
	if len(context.SourcePins) < 1 || len(context.SourcePins) > MaxSourcePins {
		return contextProblem(-1)
	}
	seen := make([]SourcePin, 0, len(context.SourcePins))
	for index, pin := range context.SourcePins {
		if err := validateSourcePin(pin); err != nil {
			return contextProblem(index)
		}
		for _, previous := range seen {
			if sameSourcePin(previous, pin) {
				return contextProblem(index)
			}
		}
		seen = append(seen, pin)
	}
	return nil
}

// sameSourcePin compares two pins by value. The advisory members are pointers,
// so a struct comparison would compare addresses and treat two identical pins as
// different.
func sameSourcePin(a, b SourcePin) bool {
	return a.Role == b.Role && a.Source == b.Source && a.SourceHash == b.SourceHash &&
		sameOptionalString(a.AdvisoryID, b.AdvisoryID) &&
		sameOptionalString(a.AdvisoryRevision, b.AdvisoryRevision)
}

// contextProblem reuses the ratified invalid_context code without adding a new
// one to the closed list.
func contextProblem(index int) error {
	return &rulepack.Error{Code: rulepack.CodeInvalidContext, Index: index}
}

func validateSourcePin(pin SourcePin) error {
	switch pin.Role {
	case SourceRoleMapping, SourceRoleArtifact:
		if pin.AdvisoryID != nil || pin.AdvisoryRevision != nil {
			return contextProblem(-1)
		}
	case SourceRoleVendor:
		if pin.AdvisoryID == nil || pin.AdvisoryRevision == nil {
			return contextProblem(-1)
		}
		if !domainStringOK(*pin.AdvisoryID) || !domainStringOK(*pin.AdvisoryRevision) {
			return contextProblem(-1)
		}
	default:
		return contextProblem(-1)
	}
	if !domainStringOK(pin.Source) {
		return contextProblem(-1)
	}
	if !isSha256(string(pin.SourceHash)) {
		return contextProblem(-1)
	}
	return nil
}

// domainStringOK is the data-string rule of ADR-0015 §5.2: 1-256 UTF-8 bytes
// without surrounding whitespace and without control or format characters. The
// wire validator accepts a longer or control-bearing string, so this profile
// rule has to be enforced at the domain boundary.
func domainStringOK(value string) bool {
	if len(value) == 0 || len(value) > rulepack.MaxStringBytes {
		return false
	}
	if strings.TrimSpace(value) != value {
		return false
	}
	if !utf8.ValidString(value) {
		return false
	}
	for _, r := range value {
		if r < 0x20 || r == 0x7F || (r >= 0x80 && r <= 0x9F) || unicode.Is(unicode.Cf, r) {
			return false
		}
	}
	return true
}

func copyPointer[T any](value *T) *T {
	if value == nil {
		return nil
	}
	copied := *value
	return &copied
}

// copyDomainContext detaches the pins and their optional strings, so a caller
// cannot rewrite a returned result through its own context.
func copyDomainContext(context DomainContext) DomainContext {
	copied := context
	copied.SourcePins = make([]SourcePin, len(context.SourcePins))
	for index, pin := range context.SourcePins {
		copied.SourcePins[index] = copySourcePin(pin)
	}
	return copied
}

func copySourcePin(pin SourcePin) SourcePin {
	copied := pin
	copied.AdvisoryID = copyPointer(pin.AdvisoryID)
	copied.AdvisoryRevision = copyPointer(pin.AdvisoryRevision)
	return copied
}

// compareSourcePins orders pins by the ratified tuple, bytes UTF-8, with null
// before any string.
func compareSourcePins(a, b SourcePin) int {
	if result := strings.Compare(string(a.Role), string(b.Role)); result != 0 {
		return result
	}
	if result := strings.Compare(a.Source, b.Source); result != 0 {
		return result
	}
	if result := strings.Compare(string(a.SourceHash), string(b.SourceHash)); result != 0 {
		return result
	}
	if result := compareOptionalStrings(a.AdvisoryID, b.AdvisoryID); result != 0 {
		return result
	}
	return compareOptionalStrings(a.AdvisoryRevision, b.AdvisoryRevision)
}

func compareOptionalStrings(a, b *string) int {
	switch {
	case a == nil && b == nil:
		return 0
	case a == nil:
		return -1
	case b == nil:
		return 1
	}
	return strings.Compare(*a, *b)
}

// sortedDomainPins returns a sorted copy; sorting never selects a source nor
// removes a duplicated pin, which was already rejected in form.
func sortedDomainPins(pins []SourcePin) []SourcePin {
	ordered := make([]SourcePin, len(pins))
	copy(ordered, pins)
	for left := 0; left < len(ordered); left++ {
		for right := left + 1; right < len(ordered); right++ {
			if compareSourcePins(ordered[right], ordered[left]) < 0 {
				ordered[left], ordered[right] = ordered[right], ordered[left]
			}
		}
	}
	return ordered
}
