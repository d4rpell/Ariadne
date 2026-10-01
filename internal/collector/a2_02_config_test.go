package collector

import (
	"context"
	"testing"
	"time"

	"github.com/d4rpell/Ariadne/internal/bundle"
	contract "github.com/d4rpell/Ariadne/pkg/evidence"
)

// Configuration and credential cases of the A2-02 plan (handoff §4.2 rows
// "Configuración" and "Credenciales"): every rejection happens before the
// first request, no input value is echoed and no modality is invented.

func TestA202Config(t *testing.T) {
	t.Run("selector", func(t *testing.T) {
		config := a202Config(t)
		config.Selector = "k8s-pod-read-v2"
		assertA202ConfigFailure(t, config, bundle.CodeInvalidConfig)
	})
	t.Run("version", func(t *testing.T) {
		config := a202Config(t)
		config.Version = "2.0"
		assertA202ConfigFailure(t, config, bundle.CodeInvalidConfig)
	})
	t.Run("policy", func(t *testing.T) {
		config := a202Config(t)
		config.RedactionPolicy = "k8s-pod-read-v1/2.0"
		assertA202ConfigFailure(t, config, bundle.CodeInvalidConfig)
	})
	t.Run("alias", func(t *testing.T) {
		for _, alias := range []string{"", ".", "..", "with space", "ümlaut", "slash/alias"} {
			config := a202Config(t)
			config.ClusterAlias = alias
			assertA202ConfigFailure(t, config, bundle.CodeInvalidConfig)
		}
	})
	t.Run("namespace_empty", func(t *testing.T) {
		config := a202Config(t)
		config.Namespaces = []string{}
		assertA202ConfigFailure(t, config, bundle.CodeInvalidConfig)
		config = a202Config(t)
		config.Namespaces = []string{""}
		assertA202ConfigFailure(t, config, bundle.CodeInvalidConfig)
	})
	t.Run("namespace_duplicate", func(t *testing.T) {
		config := a202Config(t)
		config.Namespaces = []string{a202Namespace, a202Namespace}
		assertA202ConfigFailure(t, config, bundle.CodeInvalidConfig)
	})
	t.Run("namespace_17", func(t *testing.T) {
		config := a202Config(t)
		namespaces := make([]string, 0, 17)
		for index := 0; index < 17; index++ {
			namespaces = append(namespaces, "ns-"+string(rune('a'+index)))
		}
		config.Namespaces = namespaces
		assertA202ConfigFailure(t, config, bundle.CodeInvalidConfig)
	})
	t.Run("namespace_noncanonical", func(t *testing.T) {
		for _, namespace := range []string{"*", "Payments", " payments", "payments ", "pay/ments", "pay_ments", "payments.", "-payments", "payments-"} {
			config := a202Config(t)
			config.Namespaces = []string{namespace}
			assertA202ConfigFailure(t, config, bundle.CodeInvalidConfig)
		}
	})
	t.Run("endpoint_components", func(t *testing.T) {
		for _, endpoint := range []string{
			"http://synthetic.example:6443",
			"https://user:pass@synthetic.example:6443",
			"https://synthetic.example:6443?query=1",
			"https://synthetic.example:6443#fragment",
			"https://synthetic.example:6443/prefix",
			"",
		} {
			config := a202Config(t)
			config.Endpoint = endpoint
			assertA202ConfigFailure(t, config, bundle.CodeInvalidConfig)
		}
	})
	t.Run("auth_missing", func(t *testing.T) {
		config := a202Config(t)
		config.BearerToken = ""
		assertA202ConfigFailure(t, config, bundle.CodeUnsupportedAuth)
	})
	t.Run("auth_combined", func(t *testing.T) {
		pki := a202SyntheticPKI(t)
		cert, key := a202ClientMaterial(t, pki)
		config := a202Config(t)
		config.ClientCertificatePEM = cert
		config.ClientKeyPEM = key
		assertA202ConfigFailure(t, config, bundle.CodeUnsupportedAuth)
	})
	t.Run("zero_requests", func(t *testing.T) {
		// A rejected configuration never reaches the transport, even when the
		// scripted transport would fail if it were called.
		transport := newA202ScriptedTransport(a202RoundTrip{err: errTransportMarker()})
		config := a202Config(t)
		config.Namespaces = []string{"Bad Namespace"}
		_, err := collectWithDependencies(context.Background(), config, transport, newA202Clock(t, a202StartMoment))
		if err == nil || err.Error() != "collector: invalid_config" {
			t.Fatalf("err = %v, want collector: invalid_config", err)
		}
		if transport.callCount() != 0 {
			t.Fatalf("transport calls = %d, want 0", transport.callCount())
		}
	})
}

func TestA202CredentialMaterial(t *testing.T) {
	t.Run("bearer", func(t *testing.T) {
		config := a202Config(t)
		validated, err := validateConfig(config)
		if err != nil {
			t.Fatalf("validateConfig: %v", err)
		}
		if validated.bearer != a202MarkerToken {
			t.Fatal("the bearer modality was not retained")
		}
	})
	t.Run("mtls", func(t *testing.T) {
		pki := a202SyntheticPKI(t)
		cert, key := a202ClientMaterial(t, pki)
		config := a202Config(t)
		config.BearerToken = ""
		config.ClientCertificatePEM = cert
		config.ClientKeyPEM = key
		validated, err := validateConfig(config)
		if err != nil {
			t.Fatalf("validateConfig: %v", err)
		}
		if validated.cert == nil {
			t.Fatal("the client certificate pair was not retained")
		}
		if validated.bearer != "" {
			t.Fatal("both modalities were retained")
		}
	})
	t.Run("missing_pair", func(t *testing.T) {
		pki := a202SyntheticPKI(t)
		cert, key := a202ClientMaterial(t, pki)
		for _, partial := range []Config{
			func() Config {
				config := a202Config(t)
				config.BearerToken = ""
				config.ClientCertificatePEM = cert
				return config
			}(),
			func() Config {
				config := a202Config(t)
				config.BearerToken = ""
				config.ClientKeyPEM = key
				return config
			}(),
		} {
			assertA202ConfigFailure(t, partial, bundle.CodeUnsupportedAuth)
		}
	})
	t.Run("invalid_ca", func(t *testing.T) {
		config := a202Config(t)
		config.CAPEM = []byte("not a certificate")
		assertA202ConfigFailure(t, config, bundle.CodeInvalidConfig)
	})
	t.Run("invalid_keypair", func(t *testing.T) {
		config := a202Config(t)
		config.BearerToken = ""
		config.ClientCertificatePEM = []byte("not a certificate")
		config.ClientKeyPEM = []byte("not a key")
		assertA202ConfigFailure(t, config, bundle.CodeUnsupportedAuth)
	})
	t.Run("header_injection", func(t *testing.T) {
		for _, token := range []string{"with space", "line\nbreak", "tab\tchar", "ümlaut"} {
			config := a202Config(t)
			config.BearerToken = token
			assertA202ConfigFailure(t, config, bundle.CodeUnsupportedAuth)
		}
	})
	t.Run("input_ownership", func(t *testing.T) {
		// A later mutation of the caller's slices must not alter a validated run.
		namespaces := []string{"alpha", "beta"}
		capEM := a202CABundle(t)
		config := Config{
			Selector:        a202Selector,
			Version:         a202Version,
			RedactionPolicy: a202Policy,
			ClusterAlias:    a202Alias,
			Namespaces:      namespaces,
			Endpoint:        "https://synthetic.example:6443",
			CAPEM:           capEM,
			BearerToken:     a202MarkerToken,
		}
		validated, err := validateConfig(config)
		if err != nil {
			t.Fatalf("validateConfig: %v", err)
		}
		namespaces[0] = "mutated"
		capEM[0] = 'X'
		if validated.namespaces[0] != "alpha" || validated.namespaces[1] != "beta" {
			t.Fatalf("validated namespaces changed: %v", validated.namespaces)
		}
	})
	t.Run("safe_formatting", func(t *testing.T) {
		config := a202Config(t)
		for _, rendered := range []string{config.String(), config.GoString()} {
			if rendered != "collector.Config{REDACTED}" {
				t.Fatalf("formatted config = %q", rendered)
			}
			if contains(rendered, a202MarkerToken) || contains(rendered, config.Endpoint) {
				t.Fatal("the formatted configuration leaks connection material")
			}
		}
	})
}

// assertA202ConfigFailure runs the collector with one invalid configuration and
// requires the exact static error, zero transport calls and no source.
func assertA202ConfigFailure(t *testing.T, config Config, code bundle.CollectionCode) {
	t.Helper()
	transport := newA202ScriptedTransport(a202RoundTrip{err: errTransportMarker()})
	result, err := collectWithDependencies(context.Background(), config, transport, newA202Clock(t, a202StartMoment))
	if err == nil {
		t.Fatalf("config %+v was admitted", code)
	}
	if want := "collector: " + string(code); err.Error() != want {
		t.Fatalf("err = %q, want %q", err.Error(), want)
	}
	if transport.callCount() != 0 {
		t.Fatalf("transport calls = %d, want 0", transport.callCount())
	}
	if len(result.Acquisition.Captures) != 0 || len(result.Bundles) != 0 {
		t.Fatal("a rejected configuration produced sources or bundles")
	}
}

// errTransportMarker is the sentinel a configuration failure must never reach.
func errTransportMarker() error { return staticError(bundle.CodeTransportFailed) }

func contains(haystack, needle string) bool {
	if needle == "" {
		return true
	}
	for index := 0; index+len(needle) <= len(haystack); index++ {
		if haystack[index:index+len(needle)] == needle {
			return true
		}
	}
	return false
}

var _ = time.Second
var _ = contract.Warning{}
