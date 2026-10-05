package interop

import (
	"testing"
	"time"

	canonical "github.com/d4rpell/Ariadne/internal/evidence"
	contract "github.com/d4rpell/Ariadne/pkg/evidence"
)

func canonicalHash(bundle contract.Bundle) (string, error) {
	return canonical.HashCanonicalJSON(bundle)
}

func ptrRequested(value string) *contract.RequestedImage {
	typed := contract.RequestedImage(value)
	return &typed
}

func ptrDigest(value string) *contract.NormalizedDigest {
	typed := contract.NormalizedDigest(value)
	return &typed
}

func ptrRawImage(value string) *contract.RawImageID {
	typed := contract.RawImageID(value)
	return &typed
}

func ptrU64(value uint64) *uint64 { return &value }

func goldenInstant(t *testing.T, year int) contract.Timestamp {
	t.Helper()
	ts, err := contract.NewTimestamp(time.Date(year, time.January, 2, 3, 4, 5, 0, time.UTC))
	if err != nil {
		t.Fatalf("timestamp: %v", err)
	}
	return ts
}

// goldenBundle is a minimal but valid bundle used as the frozen input of the
// golden vectors. Its projection hash is asserted against goldenBundleHash.
func goldenBundle() contract.Bundle {
	return contract.Bundle{
		SchemaVersion: "0.2",
		Subject: contract.Subject{
			ClusterAlias: "cluster-a",
			Namespace:    "payments",
			Kind:         "Pod",
			Name:         "api-0",
			UID:          "uid-0001",
			OwnerChain:   "deployments/api",
		},
		Images: []contract.ImageIdentity{{
			ContainerClass:   contract.ContainerRegular,
			ContainerName:    "api",
			RequestedImage:   ptrRequested("registry.example/api:release"),
			RawImageID:       ptrRawImage("registry.example/api@sha256:1111111111111111111111111111111111111111111111111111111111111111"),
			NormalizedDigest: ptrDigest("sha256:1111111111111111111111111111111111111111111111111111111111111111"),
			Platform:         contract.Platform{OS: "linux", Architecture: "amd64", Status: contract.PlatformKnown},
		}},
		Evidence:                 []contract.EvidenceItem{},
		ObservedContainerClasses: []contract.ContainerClass{},
		Provenance: contract.RunProvenance{
			CollectorVersion: "0.1.0",
			ParserVersion:    "prisma-v1.2",
			Ruleset:          contract.RulesetRef{Path: "rules/", Hash: "sha256:2222222222222222222222222222222222222222222222222222222222222222", Version: "2026-09"},
			ArgvSanitized:    []string{"import", "findings.csv", "--schema", "prisma-v1"},
			Inputs:           []contract.InputRef{{Path: "findings.csv", Hash: "sha256:3333333333333333333333333333333333333333333333333333333333333333"}},
			APIScope:         contract.APIScope{Namespaces: []contract.Namespace{}, Verbs: []string{}, Resources: []string{}},
			Budget:           contract.Budget{WallClock: "5m"},
			Coverage:         contract.Coverage{Method: contract.CoverageFindingsImport, Termination: contract.TerminationFinished, Rows: &contract.CoverageRows{Total: ptrU64(0)}},
			Completeness:     contract.CompletenessComplete,
			Consistency:      contract.ConsistencyPointObservation,
			RedactionPolicy:  "default-v1",
			Warnings:         []contract.Warning{},
			Errors:           []string{},
		},
	}
}
