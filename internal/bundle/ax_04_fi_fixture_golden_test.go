package bundle_test

import (
	"strings"
	"testing"
	"time"

	"github.com/d4rpell/Ariadne/internal/bundle"
	"github.com/d4rpell/Ariadne/internal/identity"
	"github.com/d4rpell/Ariadne/internal/ingest"
	"github.com/d4rpell/Ariadne/internal/normalize"
	contract "github.com/d4rpell/Ariadne/pkg/evidence"
)

// AX-04 group A, findings-import cases (F02, F03, F04). The caller supplies the
// input binding and the import record; the bundle is produced by the real Build
// path, so the nulls asserted below are produced by production and never
// pre-set by the test. The requested reference is composed from the record
// (ADR-0009), never from the binding. Fixtures are synthetic throughout.
//
// What these tests accredit: the exact bytes of each case and the identity
// separation each case declares. What they do not accredit: any registry
// resolution, any digest-class attestation, and no claim that a raw reference
// identifies an index.

const ax04FIFixtureF02 = "F02-mutable-tag"
const ax04FIFixtureF03 = "F03-unparseable-image-id"
const ax04FIFixtureF04 = "F04-multiarch"

const (
	ax04CSVHeader = "schema_version,vulnerability_id,package_name,installed_version,fix_status,image_registry,image_repository,image_tag,severity\n"
	ax04DigestA   = "sha256:" + "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	ax04RawA      = "registry.example/payments/api@" + ax04DigestA
)

// ax04CSVRow is one canonical prisma-v1 record for the synthetic subject; the
// composed requested reference is registry.example/payments/api:<tag>.
func ax04CSVRow(tag string) string {
	return "1.0,CVE-2024-1234,openssl,1.1.1k,fixed,registry.example,payments/api," + tag + ",high\n"
}

// ax04FIBinding describes the caller-declared observation of one container. A
// nil raw/digest pointer is the caller declaring no observed content reference.
type ax04FIBinding struct {
	raw      *string
	digest   *string
	platform contract.PlatformStatus
	os       string
	arch     string
}

// ax04BuildFI runs the real import pipeline with one record and one binding.
func ax04BuildFI(t *testing.T, tag string, binding ax04FIBinding) contract.Bundle {
	t.Helper()
	row := ax04CSVRow(tag)
	parsed, err := ingest.ParsePrismaV1(strings.NewReader(ax04CSVHeader + row))
	if err != nil {
		t.Fatalf("parse prisma-v1: %v", err)
	}
	observedAt, err := contract.NewTimestamp(time.Date(2026, 9, 26, 9, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatalf("timestamp: %v", err)
	}
	subject := contract.Subject{
		ClusterAlias: contract.ClusterAlias("cluster-a"),
		Namespace:    contract.Namespace("payments"),
		Kind:         "Pod",
		Name:         "payments-api-7f4d",
		UID:          contract.UID("pod-uid-1"),
		OwnerChain:   contract.OwnerChain("deployments/payments-api"),
	}
	image := identity.ImageBinding{
		Key: identity.ContainerKey{
			SubjectUID:     subject.UID,
			ContainerClass: contract.ContainerRegular,
			ContainerName:  contract.ContainerName("api"),
		},
		InputKind:            identity.InputSynthetic,
		SourceName:           "sanitized-pods.json",
		SourceHash:           contract.SourceHash("sha256:" + strings.Repeat("c", 64)),
		Locator:              contract.SourceLocator("items[3].status.containerStatuses[0].imageID"),
		Platform:             binding.platform,
		PlatformOS:           binding.os,
		PlatformArchitecture: binding.arch,
		ObservedAt:           &observedAt,
	}
	if binding.raw != nil {
		raw := contract.RawImageID(*binding.raw)
		image.RawImageID = &raw
	}
	if binding.digest != nil {
		digest, err := identity.NewGuaranteedDigest(*binding.digest)
		if err != nil {
			t.Fatalf("guaranteed digest: %v", err)
		}
		image.GuaranteedDigest = &digest
	}
	normalized, err := normalize.Normalize(normalize.Input{
		Import: parsed,
		Bindings: []normalize.Binding{{
			FindingIndex: 0,
			ContainerKey: image.Key,
			Image:        image,
		}},
	})
	if err != nil {
		t.Fatalf("normalize: %v", err)
	}
	built, _, err := bundle.Build(bundle.Input{
		Normalized: normalized,
		Subject:    subject,
		Source: bundle.ImportSource{
			Path:       "findings.csv",
			Hash:       bundle.HashSource([]byte(ax04CSVHeader + row)),
			ObservedAt: &observedAt,
		},
		Run: bundle.RunContext{
			CollectorVersion: "0.1.0",
			ParserVersion:    "prisma-v1.0",
			ArgvSanitized:    []string{"import", "findings.csv", "--schema", "prisma-v1"},
			Budget:           contract.Budget{WallClock: "5m", Requests: 1, Objects: 1, Bytes: 4096},
			Consistency:      contract.ConsistencyPointObservation,
			RedactionPolicy:  "default-v1",
			Warnings:         []contract.Warning{},
		},
	})
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	return built
}

func ax04Str(value string) *string { return &value }

func TestAX04FIFixtureGoldens(t *testing.T) {
	t.Run(ax04FIFixtureF02+"/tag-vs-digest", func(t *testing.T) {
		// F02: a requested tag and an observed digest are three separate fields.
		built := ax04BuildFI(t, "release", ax04FIBinding{
			raw:      ax04Str(ax04RawA),
			digest:   ax04Str(ax04DigestA),
			platform: contract.PlatformKnown,
			os:       "linux",
			arch:     "amd64",
		})
		if len(built.Images) != 1 {
			t.Fatalf("images = %d, want one", len(built.Images))
		}
		image := built.Images[0]
		if image.RequestedImage == nil || string(*image.RequestedImage) != "registry.example/payments/api:release" {
			t.Fatalf("requested = %v, want the composed tag from the record", image.RequestedImage)
		}
		if image.RawImageID == nil || string(*image.RawImageID) != ax04RawA {
			t.Fatalf("raw = %v, want the observed image id", image.RawImageID)
		}
		if image.NormalizedDigest == nil || string(*image.NormalizedDigest) != ax04DigestA {
			t.Fatalf("digest = %v, want the proven digest", image.NormalizedDigest)
		}
		if string(*image.RequestedImage) == string(*image.RawImageID) {
			t.Fatal("requested and raw must stay distinct fields")
		}
		ax04CompareTriplet(t, ax04FIFixtureF02, "tag-vs-digest", built)
	})

	t.Run(ax04FIFixtureF02+"/tag-without-digest", func(t *testing.T) {
		// F02: a requested tag alone is never content identity. The caller
		// declares no raw and no digest; the nulls are produced by production.
		built := ax04BuildFI(t, "latest", ax04FIBinding{platform: contract.PlatformUnknown})
		image := built.Images[0]
		if image.RequestedImage == nil || string(*image.RequestedImage) != "registry.example/payments/api:latest" {
			t.Fatalf("requested = %v, want the composed tag from the record", image.RequestedImage)
		}
		if image.RawImageID != nil || image.NormalizedDigest != nil {
			t.Fatalf("raw/digest = %v/%v, want both null for a tag without digest", image.RawImageID, image.NormalizedDigest)
		}
		if image.Platform.Status != contract.PlatformUnknown {
			t.Fatalf("platform = %q, want unknown", image.Platform.Status)
		}
		ax04CompareTriplet(t, ax04FIFixtureF02, "tag-without-digest", built)
	})

	t.Run(ax04FIFixtureF03+"/opaque-raw", func(t *testing.T) {
		// F03: an opaque, non-digest raw identifier is preserved verbatim; no
		// digest is promoted and the platform stays unknown. The null is
		// produced by production, not pre-set here.
		built := ax04BuildFI(t, "release", ax04FIBinding{
			raw:      ax04Str("ref:opaque-identifier"),
			platform: contract.PlatformUnknown,
		})
		image := built.Images[0]
		if image.RawImageID == nil || string(*image.RawImageID) != "ref:opaque-identifier" {
			t.Fatalf("raw = %v, want the opaque identifier preserved verbatim", image.RawImageID)
		}
		if image.NormalizedDigest != nil {
			t.Fatalf("digest = %v, want null: no digest is promoted from an opaque reference", image.NormalizedDigest)
		}
		if image.Platform.Status != contract.PlatformUnknown {
			t.Fatalf("platform = %q, want unknown", image.Platform.Status)
		}
		ax04CompareTriplet(t, ax04FIFixtureF03, "opaque-raw", built)
	})

	t.Run(ax04FIFixtureF04+"/no-accredited-manifest", func(t *testing.T) {
		// F04: a reference whose manifest for the observed platform the available
		// method does not accredit is preserved as raw and never promoted. The
		// assertion is the observable predicate, not a claim about digest class:
		// the syntax of a digest does not prove it identifies an index.
		built := ax04BuildFI(t, "release", ax04FIBinding{
			raw:      ax04Str(ax04RawA),
			platform: contract.PlatformUnknown,
		})
		image := built.Images[0]
		if image.RawImageID == nil || string(*image.RawImageID) != ax04RawA {
			t.Fatalf("raw = %v, want the reference preserved", image.RawImageID)
		}
		if image.NormalizedDigest != nil {
			t.Fatalf("digest = %v, want null: without an accredited manifest of the observed platform nothing is promoted", image.NormalizedDigest)
		}
		if image.Platform.Status != contract.PlatformUnknown {
			t.Fatalf("platform = %q, want unknown", image.Platform.Status)
		}
		ax04CompareTriplet(t, ax04FIFixtureF04, "no-accredited-manifest", built)
	})
}
