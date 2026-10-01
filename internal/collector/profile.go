package collector

import "time"

// Fixed profile of the live collector (ADR-0026 A.2, A.5). Nothing in this
// file is configurable at run time: the budgets are program constants, so no
// caller can raise them and no test may lower them.

const (
	// collectionSelector identifies the acquisition profile.
	collectionSelector = "k8s-pod-read-v1"
	// collectionVersion is the only supported version of that profile.
	collectionVersion = "1.0"
	// collectionRedactionPolicy is the policy stamped on every provenance.
	collectionRedactionPolicy = "k8s-pod-read-v1/1.0"
)

const (
	// maxNamespaces is the upper bound of the namespace allowlist.
	maxNamespaces = 16
	// maxNamespaceBytes bounds one namespace name.
	maxNamespaceBytes = 63
	// maxAliasBytes bounds the cluster alias.
	maxAliasBytes = 128
	// maxEndpointBytes bounds the configured endpoint.
	maxEndpointBytes = 2048
	// maxBearerBytes bounds the bearer token material.
	maxBearerBytes = 16 * 1024
	// maxCAPEMBytes bounds the supplied CA bundle.
	maxCAPEMBytes = 1 * 1024 * 1024
	// maxClientCertBytes bounds the supplied client certificate chain.
	maxClientCertBytes = 1 * 1024 * 1024
	// maxClientKeyBytes bounds the supplied client private key.
	maxClientKeyBytes = 64 * 1024
)

const (
	// acquisitionDeadline bounds the whole run, cooperative work included.
	acquisitionDeadline = 300 * time.Second
	// requestTimeout bounds one request, body read included.
	requestTimeout = 10 * time.Second
	// dialTimeout bounds one connection establishment.
	dialTimeout = 3 * time.Second
	// tlsHandshakeTimeout bounds one TLS handshake.
	tlsHandshakeTimeout = 3 * time.Second
	// responseHeaderTimeout bounds the wait for response headers.
	responseHeaderTimeout = 5 * time.Second
	// requestSpacing is the minimum separation between request starts.
	requestSpacing = 200 * time.Millisecond
)

const (
	// maxRequests bounds attempted requests.
	maxRequests = 1024
	// maxPodOccurrences bounds examined Pod occurrences.
	maxPodOccurrences = 1024
	// maxInitialUIDs bounds the initial inventory.
	maxInitialUIDs = 256
	// maxTotalBodyBytes bounds accumulated received body bytes.
	maxTotalBodyBytes = 64 * 1024 * 1024
	// maxResponseBodyBytes bounds one response body.
	maxResponseBodyBytes = 4 * 1024 * 1024
	// maxResponseHeaderBytes bounds one response header block.
	maxResponseHeaderBytes = 32 * 1024
	// maxRawPodBytes bounds one raw Pod object.
	maxRawPodBytes = 1 * 1024 * 1024
	// maxRetainedSourceBytes bounds retained sanitized sources.
	maxRetainedSourceBytes = 32 * 1024 * 1024
	// maxContinuationBytes bounds one continuation token.
	maxContinuationBytes = 8 * 1024
	// maxRawDepth bounds the depth of one raw response document.
	maxRawDepth = 64
	// maxRawTokens bounds the tokens of one raw response document.
	maxRawTokens = 1_000_000
	// maxRawObjectMembers bounds the members of one raw JSON object.
	maxRawObjectMembers = 2048
)

const (
	// listPageLimit is the page size requested on list calls.
	listPageLimit = 100
	// rereadRounds is the fixed number of get rounds over the inventory.
	rereadRounds = 2
	// retriesPerOperation is fixed at zero: the profile performs no retry.
	retriesPerOperation = 0
)

const (
	// listPathPrefix is the only path prefix the collector addresses.
	listPathPrefix = "/api/v1/namespaces/"
	// podsResourceSegment is the only resource addressed.
	podsResourceSegment = "pods"
	// userAgent is the fixed, non-identifying User-Agent.
	userAgent = "ariadne-collector/k8s-pod-read-v1"
	// acceptHeader is the only Accept value sent.
	acceptHeader = "application/json"
)
