package collector

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net/url"
	"sort"
	"strings"

	"github.com/d4rpell/Ariadne/internal/bundle"
	contract "github.com/d4rpell/Ariadne/pkg/evidence"
)

// Configuration validation (ADR-0026 A.2.2, A.3.3). Everything here happens
// before the first request: an invalid configuration produces zero operations
// and zero transport calls, never a default or a repaired value.

var (
	errInvalidConfig   = errors.New("collector: invalid_config")
	errUnsupportedAuth = errors.New("collector: unsupported_auth")
)

// validatedConfig owns copies of every input it keeps, so a later mutation of
// the caller's Config cannot alter an in-flight run.
type validatedConfig struct {
	selector        string
	version         string
	redactionPolicy string
	clusterAlias    contract.ClusterAlias
	namespaces      []contract.Namespace

	endpoint *url.URL
	caPool   *x509.CertPool
	bearer   string
	cert     *tls.Certificate
}

// validateConfig checks the complete configuration and returns the immutable
// value the run uses. The error is always the static invalid_config or
// unsupported_auth diagnostic: no input value is echoed.
func validateConfig(config Config) (validatedConfig, error) {
	validated := validatedConfig{}
	if config.Selector != collectionSelector || config.Version != collectionVersion ||
		config.RedactionPolicy != collectionRedactionPolicy {
		return validatedConfig{}, errInvalidConfig
	}
	if !validClusterAlias(config.ClusterAlias) {
		return validatedConfig{}, errInvalidConfig
	}
	namespaces, err := validatedNamespaces(config.Namespaces)
	if err != nil {
		return validatedConfig{}, err
	}
	endpoint, err := validateEndpoint(config.Endpoint)
	if err != nil {
		return validatedConfig{}, err
	}
	if len(config.CAPEM) == 0 || len(config.CAPEM) > maxCAPEMBytes {
		return validatedConfig{}, errInvalidConfig
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(config.CAPEM) {
		return validatedConfig{}, errInvalidConfig
	}
	validated.selector = config.Selector
	validated.version = config.Version
	validated.redactionPolicy = config.RedactionPolicy
	validated.clusterAlias = contract.ClusterAlias(config.ClusterAlias)
	validated.namespaces = namespaces
	validated.endpoint = endpoint
	validated.caPool = pool

	hasBearer := config.BearerToken != ""
	hasCert := len(config.ClientCertificatePEM) > 0 || len(config.ClientKeyPEM) > 0
	switch {
	case hasBearer && hasCert:
		// Combining modalities is outside the profile.
		return validatedConfig{}, errUnsupportedAuth
	case hasBearer:
		if len(config.BearerToken) > maxBearerBytes {
			return validatedConfig{}, errInvalidConfig
		}
		if !validBearerMaterial(config.BearerToken) {
			return validatedConfig{}, errUnsupportedAuth
		}
		validated.bearer = config.BearerToken
	case hasCert:
		if len(config.ClientCertificatePEM) == 0 || len(config.ClientKeyPEM) == 0 {
			return validatedConfig{}, errUnsupportedAuth
		}
		if len(config.ClientCertificatePEM) > maxClientCertBytes || len(config.ClientKeyPEM) > maxClientKeyBytes {
			return validatedConfig{}, errInvalidConfig
		}
		pair, err := tls.X509KeyPair(config.ClientCertificatePEM, config.ClientKeyPEM)
		if err != nil {
			return validatedConfig{}, errUnsupportedAuth
		}
		validated.cert = &pair
	default:
		// No anonymous access: a modality is required.
		return validatedConfig{}, errUnsupportedAuth
	}
	return validated, nil
}

// validatedNamespaces accepts 1..16 distinct DNS-label namespaces, preserving
// canonical spelling: no trim, no lowercasing, no expansion.
func validatedNamespaces(values []string) ([]contract.Namespace, error) {
	if len(values) == 0 || len(values) > maxNamespaces {
		return nil, errInvalidConfig
	}
	seen := map[string]bool{}
	namespaces := make([]contract.Namespace, 0, len(values))
	for _, value := range values {
		if !validNamespace(value) || seen[value] {
			return nil, errInvalidConfig
		}
		seen[value] = true
		namespaces = append(namespaces, contract.Namespace(value))
	}
	sort.Slice(namespaces, func(i, j int) bool { return namespaces[i] < namespaces[j] })
	return namespaces, nil
}

// validNamespace enforces the DNS label grammar with the 63-byte ceiling.
func validNamespace(value string) bool {
	if value == "" || len(value) > maxNamespaceBytes {
		return false
	}
	for index := 0; index < len(value); index++ {
		character := value[index]
		switch {
		case character >= 'a' && character <= 'z':
		case character >= '0' && character <= '9':
		case character == '-' && index != 0 && index != len(value)-1:
		default:
			return false
		}
	}
	return true
}

// validClusterAlias enforces the ASCII alias grammar of the profile.
func validClusterAlias(value string) bool {
	if value == "" || len(value) > maxAliasBytes || value == "." || value == ".." {
		return false
	}
	for index := 0; index < len(value); index++ {
		character := value[index]
		switch {
		case character >= 'a' && character <= 'z':
		case character >= 'A' && character <= 'Z':
		case character >= '0' && character <= '9':
		case character == '.' || character == '_' || character == '-':
		default:
			return false
		}
	}
	return true
}

// validPodName checks the name used to build one get path. It refuses every
// character that could change the authority, path, query or fragment, and the
// navigation segments "." and ".." that PathEscape would preserve as directory
// steps of the URL.
func validPodName(value string) bool {
	if value == "" || len(value) > 253 || value == "." || value == ".." {
		return false
	}
	for index := 0; index < len(value); index++ {
		character := value[index]
		switch {
		case character >= 'a' && character <= 'z':
		case character >= 'A' && character <= 'Z':
		case character >= '0' && character <= '9':
		case character == '-' || character == '.' || character == '_':
		default:
			return false
		}
	}
	return true
}

// validBearerMaterial refuses control characters and separators that could
// alter the Authorization header.
func validBearerMaterial(value string) bool {
	for index := 0; index < len(value); index++ {
		character := value[index]
		if character < 0x21 || character > 0x7e {
			return false
		}
	}
	return true
}

// validateEndpoint requires HTTPS, a single authority and a path that is empty
// or "/". Userinfo, query, fragment and prefixed paths are refused.
func validateEndpoint(value string) (*url.URL, error) {
	if value == "" || len(value) > maxEndpointBytes {
		return nil, errInvalidConfig
	}
	parsed, err := url.Parse(value)
	if err != nil {
		return nil, errInvalidConfig
	}
	if parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil ||
		parsed.RawQuery != "" || parsed.Fragment != "" || parsed.Opaque != "" {
		return nil, errInvalidConfig
	}
	if parsed.Path != "" && parsed.Path != "/" {
		return nil, errInvalidConfig
	}
	if strings.ContainsAny(parsed.Host, " \t\n\r") {
		return nil, errInvalidConfig
	}
	return parsed, nil
}

// invalidConfigCode maps a validation failure to its closed diagnostic.
func invalidConfigCode(err error) bundle.CollectionCode {
	if errors.Is(err, errUnsupportedAuth) {
		return bundle.CodeUnsupportedAuth
	}
	return bundle.CodeInvalidConfig
}
