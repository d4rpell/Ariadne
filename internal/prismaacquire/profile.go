package prismaacquire

// Closed acquisition profile of ADR-0028 §2. The connector builds every
// operation from this profile; it accepts no caller-supplied method, path or
// URL, and no autodetection or fallback.
const (
	// AcquisitionSelector and AcquisitionVersion identify the acquisition
	// contract of §2.2.
	AcquisitionSelector = "prisma-compute-images-api-v1"
	AcquisitionVersion  = "1.0"

	// AcquisitionProfile identifies the acquisition restrictions (network and
	// sequencing); it is not the offline admission profile.
	AcquisitionProfile = "compute-sh-34.04.145-images-api"

	// AcquisitionPolicy is the closed policy value of §2.2.
	AcquisitionPolicy = "prisma-compute-images-api-v1/1.0"

	// DeclaredEdition and DeclaredRelease are the only accepted documentary
	// declarations (§2.3). The connector does not verify them remotely.
	DeclaredEdition = "compute_self_hosted"
	DeclaredRelease = "34.04.145"
)

// Fixed operations and read parameters of §§2.1 and 4.5.
const (
	imagesPath       = "/api/v34.04/images"
	authenticatePath = "/api/v34.04/authenticate"

	pageLimit = 50 // images requested per page, fixed
)

// Acquisition budgets of §7.2. Binary units: KiB is 1024 bytes and MiB is
// 1048576 bytes. Every guard is checked before the structure that would exceed
// it grows.
const (
	maxAcquisitionDuration = 300 * second
	maxRequestDuration     = 10 * second
	maxConnectDuration     = 3 * second
	maxTLSDuration         = 3 * second
	maxHeaderWaitDuration  = 5 * second
	minRequestSpacing      = 1250 * millisecond

	maxConcurrentRequests = 1
	maxTotalAttempts      = 129
	maxAuthAttempts       = 1
	maxImageGETAttempts   = 128

	maxImagesPerPage           = 50
	maxImageOccurrences        = 5000
	maxFindingOccurrences      = 100_000
	maxPackageOccurrences      = 100_000
	maxNativeTokens            = 8_000_000
	maxAccumulatedBodyBytes    = 64 * 1024 * 1024
	maxImageResponseBytes      = 16 * 1024 * 1024
	maxAuthResponseBytes       = 64 * 1024
	maxAuthRequestBytes        = 64 * 1024
	maxResponseHeaderBytes     = 32 * 1024
	maxSanitizedSourcePage     = 32 * 1024 * 1024
	maxRetainedArtifactsBytes  = 128 * 1024 * 1024
	maxDerivedTokens           = 16_000_000
	maxEndpointBytes           = 2 * 1024
	maxCAContentBytes          = 1024 * 1024
	maxCredentialReferenceByte = 128
	maxUsernameBytes           = 1024
	maxPasswordBytes           = 4096
	maxTokenBytes              = 16 * 1024
)

// Durations are expressed in nanoseconds without importing time in the
// constants above.
const (
	second      = 1_000_000_000
	millisecond = 1_000_000
)
