package prismaacquire

import (
	"net/url"
	"strings"
	"time"

	"github.com/d4rpell/Ariadne/internal/ingest"
)

// requiredDataPolicyAck is the F1 redaction policy acknowledgement that the
// caller must declare (§4.2).
const requiredDataPolicyAck = "prisma-native-offline-redaction-v1/1.0"

// validateConfig performs the pre-network validation of §4.6. It must run
// before any credential is used: invalid configuration produces no probe
// request and never discovers the correct format from server errors.
func validateConfig(cfg AcquisitionConfig) *AcquisitionError {
	switch cfg.Selector {
	case "":
		return acquireErr(CodeInvalidConfig, PhaseConfig)
	case AcquisitionSelector:
	default:
		return acquireErr(CodeUnsupportedProfile, PhaseConfig)
	}
	if cfg.Version != AcquisitionVersion || cfg.Profile != AcquisitionProfile {
		return acquireErr(CodeUnsupportedProfile, PhaseConfig)
	}
	if cfg.Edition != DeclaredEdition || cfg.Release != DeclaredRelease {
		return acquireErr(CodeUnsupportedProfile, PhaseConfig)
	}
	if err := validateEndpoint(cfg.Endpoint); err != nil {
		return err
	}
	if len(cfg.CA) == 0 || len(cfg.CA) > maxCAContentBytes {
		return acquireErr(CodeTLSConfigInvalid, PhaseConfig)
	}
	// The sanitized aliases destined for artifacts must satisfy the exact F1
	// alias grammar before any credential or transport is used (§4.3).
	if !ingest.ValidNativeAlias(cfg.OriginAlias) {
		return acquireErr(CodeInvalidConfig, PhaseConfig)
	}
	if cfg.DataPolicyAck != requiredDataPolicyAck {
		return acquireErr(CodeInvalidConfig, PhaseConfig)
	}
	switch cfg.ScopeMode {
	case ScopeSingleTenant:
		if cfg.Project != "" || cfg.ScopeAlias != nil {
			return acquireErr(CodeInvalidConfig, PhaseConfig)
		}
	case ScopeProjectSelect:
		if !validProjectID(cfg.Project) || cfg.ScopeAlias == nil || !ingest.ValidNativeAlias(*cfg.ScopeAlias) {
			return acquireErr(CodeInvalidConfig, PhaseConfig)
		}
	default:
		return acquireErr(CodeInvalidConfig, PhaseConfig)
	}
	switch cfg.AuthMode {
	case AuthBearerSupplied, AuthPasswordExchange:
	default:
		return acquireErr(CodeUnsupportedAuth, PhaseConfig)
	}
	if cfg.CredentialRef == "" || len(cfg.CredentialRef) > maxCredentialReferenceByte {
		return acquireErr(CodeInvalidConfig, PhaseConfig)
	}
	return nil
}

// validateEndpoint enforces the single destination rules of §6.1.
func validateEndpoint(endpoint string) *AcquisitionError {
	if endpoint == "" || len(endpoint) > maxEndpointBytes {
		return acquireErr(CodeInvalidConfig, PhaseConfig)
	}
	u, err := url.Parse(endpoint)
	if err != nil || u.Opaque != "" {
		return acquireErr(CodeInvalidConfig, PhaseConfig)
	}
	if u.Scheme != "https" {
		return acquireErr(CodeInvalidConfig, PhaseConfig)
	}
	if u.Host == "" || u.User != nil {
		return acquireErr(CodeInvalidConfig, PhaseConfig)
	}
	if u.RawQuery != "" || u.Fragment != "" || (u.Path != "" && u.Path != "/") {
		return acquireErr(CodeInvalidConfig, PhaseConfig)
	}
	if u.RawPath != "" { // encoded path: not a bare origin
		return acquireErr(CodeInvalidConfig, PhaseConfig)
	}
	if u.Port() == "" {
		return acquireErr(CodeInvalidConfig, PhaseConfig)
	}
	host := u.Hostname()
	if host == "" || strings.Contains(host, "%") { // reject IPv6 zones
		return acquireErr(CodeInvalidConfig, PhaseConfig)
	}
	return nil
}

// validProjectID enforces the Ariadne project identifier grammar of §4.4.2.
func validProjectID(project string) bool {
	if project == "" || len(project) > 128 {
		return false
	}
	for i := 0; i < len(project); i++ {
		c := project[i]
		switch {
		case c >= 'A' && c <= 'Z', c >= 'a' && c <= 'z', c >= '0' && c <= '9':
		case c == '.' || c == '_' || c == '-':
			if i == 0 {
				return false
			}
		default:
			return false
		}
	}
	return true
}

// validateCredential validates the already-resolved credential and its known
// expiry (§4.6, §5.2–§5.4). It never reads a credential from the environment.
func validateCredential(cfg AcquisitionConfig, cred Credential, now time.Time) *AcquisitionError {
	if cred.Reference != cfg.CredentialRef {
		return acquireErr(CodeCredentialReferenceMismatch, PhaseAuth)
	}
	switch cfg.AuthMode {
	case AuthBearerSupplied:
		if cred.Token == "" {
			return acquireErr(CodeCredentialUnavailable, PhaseAuth)
		}
		if len(cred.Token) > maxTokenBytes || !validBearerToken(cred.Token) {
			return acquireErr(CodeInvalidConfig, PhaseAuth)
		}
	case AuthPasswordExchange:
		if cred.Username == "" || cred.Password == "" {
			return acquireErr(CodeCredentialUnavailable, PhaseAuth)
		}
		if len(cred.Username) > maxUsernameBytes || len(cred.Password) > maxPasswordBytes {
			return acquireErr(CodeInvalidConfig, PhaseAuth)
		}
	}
	if cfg.TokenExpiresAt != nil && !now.Before(*cfg.TokenExpiresAt) {
		return acquireErr(CodeCredentialExpired, PhaseAuth)
	}
	return nil
}

// validBearerToken enforces the restricted bearer ASCII grammar of §5.2: letters,
// digits, `-`, `.`, `_`, `~`, `+`, `/`, with `=` only as a suffix. No spaces,
// controls, CR or LF.
func validBearerToken(token string) bool {
	for i := 0; i < len(token); i++ {
		c := token[i]
		switch {
		case c >= 'A' && c <= 'Z', c >= 'a' && c <= 'z', c >= '0' && c <= '9':
		case c == '-' || c == '.' || c == '_' || c == '~' || c == '+' || c == '/':
		case c == '=':
			for j := i; j < len(token); j++ {
				if token[j] != '=' {
					return false
				}
			}
			return true
		default:
			return false
		}
	}
	return token != ""
}
