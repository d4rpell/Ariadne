package normalize

import (
	"errors"
	"net/netip"
	"strconv"
	"strings"

	contract "github.com/d4rpell/Ariadne/pkg/evidence"
)

// maxTagBytes is the upper bound of a canonical tag: one leading character plus
// at most 127 following ones.
const maxTagBytes = 128

var (
	errRegistryNotAuthority = errors.New("normalize: image registry is not a valid authority")
	errRepositoryEmpty      = errors.New("normalize: image repository is empty")
	errRepositorySegment    = errors.New("normalize: image repository has an empty or invalid segment")
	errTagNotCanonical      = errors.New("normalize: image tag is not in the canonical form")
)

// RequestedImage composes the declared reference for the wire from its three
// verbatim components (ADR-0009). The composition is lexical: it preserves the
// bytes and the case of every component, never adds an implicit tag, never
// escapes and never infers a digest. A declaration this grammar cannot
// represent is refused instead of repaired, so the ambiguity stays visible to
// the consumer rather than becoming a plausible-looking reference.
func RequestedImage(declared DeclaredImage) (contract.RequestedImage, error) {
	if problem := registryProblem(declared.Registry); problem != nil {
		return "", problem
	}
	if problem := repositoryProblem(declared.Repository); problem != nil {
		return "", problem
	}
	if problem := tagProblem(declared.Tag); problem != nil {
		return "", problem
	}
	composed := declared.Registry + "/" + declared.Repository
	if declared.Tag != "" {
		composed += ":" + declared.Tag
	}
	return contract.RequestedImage(composed), nil
}

// registryProblem accepts a bare host, a host with a decimal port, or a
// bracketed IPv6 literal with an optional decimal port (ADR-0009). The value is
// validated byte by byte, never rewritten. The check is lexical: it guarantees
// that the composed reference is unambiguous and safely encodable, not that the
// authority is resolvable.
func registryProblem(registry string) error {
	if registry == "" {
		return errRegistryNotAuthority
	}
	if strings.HasPrefix(registry, "[") {
		end := strings.IndexByte(registry, ']')
		if end < 0 {
			return errRegistryNotAuthority
		}
		if problem := ipv6HostProblem(registry[1:end]); problem != nil {
			return problem
		}
		remainder := registry[end+1:]
		if remainder == "" {
			return nil
		}
		if remainder[0] != ':' {
			return errRegistryNotAuthority
		}
		return portProblem(remainder[1:])
	}
	host := registry
	if index := strings.IndexByte(host, ':'); index >= 0 {
		if problem := portProblem(host[index+1:]); problem != nil {
			return problem
		}
		host = host[:index]
	}
	if host == "" || !alphanumericByte(host[0]) || !alphanumericByte(host[len(host)-1]) {
		return errRegistryNotAuthority
	}
	for i := 0; i < len(host); i++ {
		if !nameByteAllowed(host[i]) {
			return errRegistryNotAuthority
		}
	}
	return nil
}

// ipv6HostProblem accepts a bracketed literal only when it parses as an IPv6
// address. The declared bytes are kept as declared; the parse only decides
// whether the literal is admissible. A zone identifier is refused because it is
// host-local context, not part of a registry authority.
func ipv6HostProblem(host string) error {
	address, err := netip.ParseAddr(host)
	if err != nil || !address.Is6() || address.Zone() != "" {
		return errRegistryNotAuthority
	}
	return nil
}

// portProblem accepts a decimal port in the transport range. Leading zeros are
// allowed and preserved verbatim: the check never rewrites the value.
func portProblem(port string) error {
	if port == "" {
		return errRegistryNotAuthority
	}
	for i := 0; i < len(port); i++ {
		if port[i] < '0' || port[i] > '9' {
			return errRegistryNotAuthority
		}
	}
	value, err := strconv.ParseUint(port, 10, 16)
	if err != nil || value == 0 {
		return errRegistryNotAuthority
	}
	return nil
}

// repositoryProblem requires one or more non-empty segments from the explicit
// allowlist of ADR-0009: letters, digits, '.', '-' and '_'. A segment carrying
// ':' or '@' would make the composed reference ambiguous (it could be read as a
// tag, a port or a digest), and the relative segments '.' and '..' are refused
// as names. Nothing is trimmed or case-folded.
func repositoryProblem(repository string) error {
	if repository == "" {
		return errRepositoryEmpty
	}
	for _, segment := range strings.Split(repository, "/") {
		if segment == "" || segment == "." || segment == ".." {
			return errRepositorySegment
		}
		for i := 0; i < len(segment); i++ {
			if !nameByteAllowed(segment[i]) {
				return errRepositorySegment
			}
		}
	}
	return nil
}

// tagProblem enforces the canonical tag form `[A-Za-z_][A-Za-z0-9_.-]{0,127}`.
// An empty tag means the source did not declare one; no default is added.
func tagProblem(tag string) error {
	if tag == "" {
		return nil
	}
	if len(tag) > maxTagBytes {
		return errTagNotCanonical
	}
	for i := 0; i < len(tag); i++ {
		if !tagByteAllowed(tag[i], i == 0) {
			return errTagNotCanonical
		}
	}
	return nil
}

// tagByteAllowed enforces the canonical tag alphabet.
func tagByteAllowed(c byte, first bool) bool {
	switch {
	case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c == '_':
		return true
	case first:
		return false
	case c >= '0' && c <= '9', c == '.', c == '-':
		return true
	default:
		return false
	}
}

// nameByteAllowed is the allowlist of ADR-0009 for a host or a repository
// segment: letters, digits, '.', '-' and '_'. Everything else, including every
// non-ASCII byte and every control character, is refused.
func nameByteAllowed(c byte) bool {
	switch {
	case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9':
		return true
	case c == '.', c == '-', c == '_':
		return true
	default:
		return false
	}
}

func alphanumericByte(c byte) bool {
	return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')
}
