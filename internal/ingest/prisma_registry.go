package ingest

import (
	"io"

	"github.com/d4rpell/Ariadne/internal/schema"
)

// Registry-image JSON profile of ADR-0029, the third offline native family. It
// reuses the deployed-image JSON admission unchanged (same schema
// shared.ImageScanResult, same closed field disposition and budgets); only the
// report class, the artifact family and the no-deployment semantics differ. The
// registry CSV selector/profile are reserved (ES-R1 open) and are not admitted.

// registryJSONProfile is the registry-image JSON profile identity of §4.1.
func registryJSONProfile() NativeProfile {
	return NativeProfile{
		Selector:         schema.NativeRegistryJSONSelector,
		InputVersion:     schema.NativeRegistryInputVersion,
		Name:             schema.NativeRegistryJSONProfile,
		RedactionPolicy:  schema.NativeRedactionPolicy,
		AdapterSemantics: schema.NativeRegistryAdapterSemantics,
	}
}

// isRegistryProfile reports whether a profile belongs to the registry family.
func isRegistryProfile(p NativeProfile) bool {
	return p.Name == schema.NativeRegistryJSONProfile || p.Name == schema.NativeRegistryCSVProfile
}

// nativeSourceFormat returns the source format literal of a profile (§4.7).
func nativeSourceFormat(p NativeProfile) string {
	if isRegistryProfile(p) {
		return schema.NativeRegistrySourceFormat
	}
	return schema.NativeSourceFormat
}

// nativeManifestFormat returns the manifest format literal of a profile (§4.7).
func nativeManifestFormat(p NativeProfile) string {
	if isRegistryProfile(p) {
		return schema.NativeRegistryManifestFormat
	}
	return schema.NativeManifestFormat
}

// knownNativeProfile reports whether p is one of the admitted profiles: the two
// deployed-image profiles and the registry-image JSON profile. The registry CSV
// profile is reserved and rejected.
func knownNativeProfile(p NativeProfile) bool {
	return p == jsonProfile() || p == csvProfile() || p == registryJSONProfile()
}

// validFamilyVersion reports whether an artifact version belongs to the family
// of the profile (ADR-0029 §4.7). The registry family is the 2.0 line only; the
// deployed family is the 1.x line, with 1.1 reserved to the JSON profile. The
// coupling is bidirectional: a registry profile with 1.x is rejected, and a
// deployed profile with 2.0 is rejected.
func validFamilyVersion(profile NativeProfile, version string) bool {
	if isRegistryProfile(profile) {
		return version == schema.NativeRegistryInputVersion
	}
	switch version {
	case schema.NativeFormatVersion:
		return true
	case schema.NativeFormatVersionV11:
		return profile == jsonProfile()
	default:
		return false
	}
}

// parsePrismaNativeRegistryJSON admits one native registry-image JSON document and
// returns the derived source, or a fatal diagnostic. It runs the same shared
// admission as the deployed-image profiles and finalizes with the registry JSON
// profile under artifact version 2.0. Original bytes are never retained.
func parsePrismaNativeRegistryJSON(data []byte, ctx NativeContext) (NativeSource, *NativeError) {
	draft, err := admitNativeJSON(data, NativeAdmission{})
	if err != nil {
		return NativeSource{}, err
	}
	src := draft.Source(registryJSONProfile(), ctx)
	src.Version = schema.NativeRegistryInputVersion
	return src, nil
}

// ParsePrismaRegistryJSON is the offline entry point of the registry-image JSON
// profile (ADR-0029 §4.1, §4.5, §5). The selector, the input version and the
// profile must be the registry JSON ones exactly; no fallback is attempted. The
// context is validated with the version in force before any reader consumes the
// source.
func ParsePrismaRegistryJSON(reader io.Reader, selector, version, profile string, ctx NativeContext) (NativeSource, *NativeError) {
	if selector != schema.NativeRegistryJSONSelector {
		return NativeSource{}, nativeFailure(NativeCodeUnsupportedSelector, NativePhaseContext, NativeSpaceNone, 0)
	}
	if version != schema.NativeRegistryInputVersion {
		return NativeSource{}, nativeFailure(NativeCodeUnsupportedVersion, NativePhaseContext, NativeSpaceNone, 0)
	}
	if profile != schema.NativeRegistryJSONProfile {
		return NativeSource{}, nativeFailure(NativeCodeUnsupportedProfile, NativePhaseContext, NativeSpaceNone, 0)
	}
	return ParsePrismaNative(reader, selector, version, profile, ctx)
}
