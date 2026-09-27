package bundle_test

import (
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/d4rpell/Ariadne/internal/bundle"
	"github.com/d4rpell/Ariadne/internal/identity"
	"github.com/d4rpell/Ariadne/internal/ingest"
	"github.com/d4rpell/Ariadne/internal/normalize"
	contract "github.com/d4rpell/Ariadne/pkg/evidence"
)

// TestDomainAssemblyBeforeHash is I-10: a caller assembles domain items onto the
// bundle Build projects, and only then the artifacts are produced. Build keeps
// its projection and its coverage untouched, the assembly is visible in the
// canonical bytes and in the digest, and the historical projection is not
// rewritten.
//
// The test lives in the external package on purpose: it uses only the exported
// surface, which is what a future caller of the bundle has.
func TestDomainAssemblyBeforeHash(t *testing.T) {
	const (
		csvHeader = "schema_version,vulnerability_id,package_name,installed_version,fix_status,image_registry,image_repository,image_tag,severity\n"
		csvRow    = "1.0,CVE-2024-1234,openssl,1.1.1k,fixed,registry.example,payments/api,release,high\n"
		source    = "findings.csv"
	)

	parsed, err := ingest.ParsePrismaV1(strings.NewReader(csvHeader + csvRow))
	if err != nil {
		t.Fatalf("parse prisma-v1: %v", err)
	}
	digest, err := identity.NewGuaranteedDigest("sha256:" + strings.Repeat("a", 64))
	if err != nil {
		t.Fatalf("guaranteed digest: %v", err)
	}
	raw := contract.RawImageID("registry.example/payments/api@sha256:" + strings.Repeat("a", 64))
	observedAt, err := contract.NewTimestamp(time.Date(2026, 9, 26, 9, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatalf("timestamp: %v", err)
	}
	subject := contract.Subject{
		ClusterAlias: contract.ClusterAlias("cluster-a"),
		Namespace:    contract.Namespace("payments"),
		Kind:         "Pod",
		Name:         "payments-api",
		UID:          contract.UID("pod-uid-1"),
		OwnerChain:   contract.OwnerChain("deployments/payments-api"),
	}

	normalized, err := normalize.Normalize(normalize.Input{
		Import: parsed,
		Bindings: []normalize.Binding{{
			FindingIndex: 0,
			ContainerKey: identity.ContainerKey{
				SubjectUID:     subject.UID,
				ContainerClass: contract.ContainerRegular,
				ContainerName:  contract.ContainerName("api"),
			},
			Image: identity.ImageBinding{
				Key:                  identity.ContainerKey{SubjectUID: subject.UID, ContainerClass: contract.ContainerRegular, ContainerName: contract.ContainerName("api")},
				InputKind:            identity.InputSynthetic,
				SourceName:           "sanitized-pods.json",
				SourceHash:           contract.SourceHash("sha256:" + strings.Repeat("c", 64)),
				Locator:              contract.SourceLocator("items[0].status.containerStatuses[0].imageID"),
				RawImageID:           &raw,
				GuaranteedDigest:     &digest,
				Platform:             contract.PlatformKnown,
				PlatformOS:           "linux",
				PlatformArchitecture: "amd64",
				ObservedAt:           &observedAt,
			},
		}},
	})
	if err != nil {
		t.Fatalf("normalize: %v", err)
	}

	built, _, err := bundle.Build(bundle.Input{
		Normalized: normalized,
		Subject:    subject,
		Source: bundle.ImportSource{
			Path:       source,
			Hash:       bundle.HashSource([]byte(csvHeader + csvRow)),
			ObservedAt: &observedAt,
		},
		Run: bundle.RunContext{
			CollectorVersion: "0.1.0",
			ParserVersion:    "prisma-v1.0",
			ArgvSanitized:    []string{"import", source, "--schema", "prisma-v1"},
			Budget:           contract.Budget{WallClock: "5m", Requests: 1, Objects: 1, Bytes: 4096},
			Consistency:      contract.ConsistencyPointObservation,
			RedactionPolicy:  "default-v1",
			Warnings:         []contract.Warning{},
		},
	})
	if err != nil {
		t.Fatalf("build: %v", err)
	}

	// Build keeps its own projection: the emitted bundle is 0.2 and carries no
	// domain vocabulary.
	if built.SchemaVersion != "0.2" {
		t.Fatalf("Build emitted schema_version %q, want 0.2", built.SchemaVersion)
	}
	for _, item := range built.Evidence {
		if strings.HasPrefix(item.Type, "product_v1.") {
			t.Fatalf("Build must not project domain vocabulary: %s", item.Type)
		}
	}

	// The projection of the built bundle is frozen before the assembly.
	before, err := bundle.Encode(built)
	if err != nil {
		t.Fatalf("encode before the assembly: %v", err)
	}
	if len(built.Evidence) == 0 {
		t.Fatal("the built bundle must carry projected evidence")
	}
	declared := built.Evidence[0]

	// A synthetic producer assembles one complete domain record explicitly: every
	// fact carries its own provenance and an independently computed value hash.
	locator := contract.SourceLocator("records/mapping/0")
	domainSource := "synthetic-mapping.json"
	domainSourceHash := bundle.HashSource([]byte("synthetic mapping source\n"))
	make := func(field, value string, confidence contract.ProvenanceKind) contract.EvidenceItem {
		hash := bundle.HashValue(value)
		return contract.EvidenceItem{
			Type:       "product_v1.mapping." + field,
			Source:     domainSource,
			SourceHash: domainSourceHash,
			Locator:    locator,
			Value:      &value,
			ValueHash:  &hash,
			ObservedAt: &observedAt,
			Confidence: confidence,
			Scope:      contract.Scope{SubjectUID: subject.UID, ContainerName: contract.ContainerName("api")},
			Warnings:   []contract.Warning{},
		}
	}
	assembled := built
	assembled.Evidence = append(append([]contract.EvidenceItem{}, built.Evidence...),
		make("method", "product-component-map-v1", contract.ProvenanceDerived),
		make("coverage", "complete", contract.ProvenanceDerived),
		make("vulnerability_id", "CVE-2024-1234", contract.ProvenanceDerived),
		make("scanner_package_type", "rpm", contract.ProvenanceDerived),
		make("scanner_package_name", "openssl", contract.ProvenanceDerived),
		make("scanner_package_id", "pkg-1", contract.ProvenanceDerived),
		make("vendor", "redhat", contract.ProvenanceDerived),
		make("product_id", "rhel", contract.ProvenanceDerived),
		make("product_release", "9", contract.ProvenanceDerived),
		make("os", "linux", contract.ProvenanceDerived),
		make("architecture", "amd64", contract.ProvenanceDerived),
		make("component_id", "openssl", contract.ProvenanceDerived),
		make("package_name", "openssl", contract.ProvenanceDerived),
		make("package_arch", "x86_64", contract.ProvenanceDerived),
	)

	// The assembly is valid only because it is complete: the evaluator's own
	// validation is not run here, but the wire contract must accept the result.
	if err := contract.ValidateBundle(assembled); err != nil {
		t.Fatalf("the assembled bundle must stay valid: %v", err)
	}

	after, err := bundle.Encode(assembled)
	if err != nil {
		t.Fatalf("encode after the assembly: %v", err)
	}

	// The assembly changed the canonical bytes and the digest.
	if string(after.Envelope) == string(before.Envelope) {
		t.Fatal("the assembly must change the envelope")
	}
	if after.Hash == before.Hash {
		t.Fatal("the assembly must change the digest")
	}
	if !strings.Contains(string(after.Envelope), `"product_v1.mapping.method"`) {
		t.Fatal("the assembled evidence is not in the envelope")
	}
	// The hash is still the digest of the delivered projection, not of the
	// envelope: the rule that builds it does not change with the assembly.
	if bundle.HashSource(after.HashInput) != contract.SourceHash(after.Hash) {
		t.Fatal("the digest does not cover the delivered projection after the assembly")
	}

	// Build's own projection and coverage are untouched by the assembly.
	if built.Provenance.Coverage.Method != contract.CoverageFindingsImport {
		t.Fatal("the assembly changed the coverage method of the built bundle")
	}
	if strings.Contains(string(before.Envelope), `"product_v1.`) {
		t.Fatal("the pre-assembly projection carries domain vocabulary")
	}
	// The declared row item of the built bundle is unchanged by the assembly.
	if len(assembled.Evidence) <= len(built.Evidence) {
		t.Fatal("the assembly must append evidence, not replace it")
	}
	if !reflect.DeepEqual(assembled.Evidence[0], declared) {
		t.Fatal("the assembly rewrote the projected evidence of Build")
	}
}
