package main

import (
	"encoding/json"
	"fmt"

	"github.com/d4rpell/Ariadne/internal/identity"
	"github.com/d4rpell/Ariadne/internal/normalize"
	"github.com/d4rpell/Ariadne/internal/schema"
	contract "github.com/d4rpell/Ariadne/pkg/evidence"
)

// Decoder of the `--bindings` document (ADR-0036 §3, profile
// case-import-bindings-v1/1.0). The document is the operator's explicit
// declaration of the finding-to-container links and of the image observations
// that carry the provenance. Every representational rule of the strict reader
// applies; the semantic rules are decided here, fail-closed, because the
// document is the only place the operator can state them. No link is ever
// inferred: a finding without a binding stays unbound (ADR-0009/0010).

const (
	bindingsFormat  = "case-import-bindings-v1"
	bindingsVersion = "1.0"

	maxImportContainers  = 1024
	maxImportBindings    = 1024
	maxImportStringBytes = 4096
)

// bindingsContainer is one declared image observation, already scoped to the
// subject of the document: the document carries exactly one subject, so the
// key is assembled from it, never invented per container.
type bindingsContainer struct {
	key   identity.ContainerKey
	image identity.ImageBinding
}

// bindingsLink is one declared finding-to-container instruction. The container
// is named by class and name inside the document's single subject.
type bindingsLink struct {
	findingIndex   int
	containerClass contract.ContainerClass
	containerName  contract.ContainerName
}

// bindingsDocument is the decoded and validated document, ready to be joined
// with the parsed findings into the normalize input.
type bindingsDocument struct {
	subject    contract.Subject
	containers []bindingsContainer
	links      []bindingsLink
}

func decodeBindings(data []byte) (bindingsDocument, error) {
	root, err := decodeObject(data)
	if err != nil {
		return bindingsDocument{}, err
	}
	if err := root.expectExact("format", "version", "subject", "containers", "bindings"); err != nil {
		return bindingsDocument{}, err
	}
	format, err := root.requiredString("format")
	if err != nil {
		return bindingsDocument{}, err
	}
	if format != bindingsFormat {
		return bindingsDocument{}, fmt.Errorf("%w: format", errStrictEnum)
	}
	version, err := root.requiredString("version")
	if err != nil {
		return bindingsDocument{}, err
	}
	if version != bindingsVersion {
		return bindingsDocument{}, fmt.Errorf("%w: version", errStrictEnum)
	}
	subject, err := decodeBindingsSubject(root)
	if err != nil {
		return bindingsDocument{}, err
	}
	containers, err := decodeBindingsContainers(root, subject)
	if err != nil {
		return bindingsDocument{}, err
	}
	links, err := decodeBindingsLinks(root)
	if err != nil {
		return bindingsDocument{}, err
	}
	return bindingsDocument{subject: subject, containers: containers, links: links}, nil
}

// expectExactOptional enforces one closed key set where some members may be
// absent: every required member present, no member outside the union, and an
// absent optional member is never repaired into null.
func expectExactOptional(fields object, required, optional []string) error {
	for _, name := range required {
		if _, ok := fields[name]; !ok {
			return fmt.Errorf("%w: %s", errStrictMissing, name)
		}
	}
	for name := range fields {
		known := false
		for _, declared := range append(append([]string{}, required...), optional...) {
			if name == declared {
				known = true
				break
			}
		}
		if !known {
			return fmt.Errorf("%w: %s", errStrictUnknown, name)
		}
	}
	return nil
}

func decodeBindingsSubject(root object) (contract.Subject, error) {
	fields, err := root.object("subject")
	if err != nil {
		return contract.Subject{}, err
	}
	if err := expectExactOptional(fields,
		[]string{"cluster_alias", "namespace", "kind", "name", "uid"},
		[]string{"owner_chain"}); err != nil {
		return contract.Subject{}, err
	}
	clusterAlias, err := boundedString(fields, "cluster_alias")
	if err != nil {
		return contract.Subject{}, err
	}
	namespace, err := boundedString(fields, "namespace")
	if err != nil {
		return contract.Subject{}, err
	}
	kind, err := boundedString(fields, "kind")
	if err != nil {
		return contract.Subject{}, err
	}
	name, err := boundedString(fields, "name")
	if err != nil {
		return contract.Subject{}, err
	}
	uid, err := boundedString(fields, "uid")
	if err != nil {
		return contract.Subject{}, err
	}
	ownerChain, err := optionalBoundedString(fields, "owner_chain")
	if err != nil {
		return contract.Subject{}, err
	}
	// The identity grammar of the wire applies here and now: an empty or
	// whitespace-padded uid is refused at the door, not at the encoder.
	subjectUID, err := contract.ParseUID(uid)
	if err != nil {
		return contract.Subject{}, fmt.Errorf("%w: uid", errStrictEnum)
	}
	if clusterAlias == "" || namespace == "" || kind == "" || name == "" {
		return contract.Subject{}, fmt.Errorf("%w: subject identity", errStrictEmpty)
	}
	return contract.Subject{
		ClusterAlias: contract.ClusterAlias(clusterAlias),
		Namespace:    contract.Namespace(namespace),
		Kind:         kind,
		Name:         name,
		UID:          subjectUID,
		OwnerChain:   contract.OwnerChain(ownerChain),
	}, nil
}

func decodeBindingsContainers(root object, subject contract.Subject) ([]bindingsContainer, error) {
	rawContainers, err := root.array("containers")
	if err != nil {
		return nil, err
	}
	if len(rawContainers) > maxImportContainers {
		return nil, fmt.Errorf("%w: containers", errStrictIntegerRange)
	}
	containers := make([]bindingsContainer, 0, len(rawContainers))
	seenKeys := make(map[identity.ContainerKey]bool, len(rawContainers))
	for _, raw := range rawContainers {
		container, err := decodeBindingsContainer(raw, subject)
		if err != nil {
			return nil, err
		}
		if seenKeys[container.key] {
			// Two declarations for the same uid + class + name are conflicting
			// observations, never a silent overwrite (ADR-0010).
			return nil, fmt.Errorf("%w: duplicate container key", errStrictDuplicate)
		}
		seenKeys[container.key] = true
		containers = append(containers, container)
	}
	return containers, nil
}

func decodeBindingsContainer(raw []byte, subject contract.Subject) (bindingsContainer, error) {
	fields, err := decodeObject(raw)
	if err != nil {
		return bindingsContainer{}, err
	}
	if err := expectExactOptional(fields,
		[]string{"container_name", "container_class", "observed_at", "platform", "source_name", "source_hash", "locator"},
		[]string{"requested_image", "raw_image_id", "normalized_digest"}); err != nil {
		return bindingsContainer{}, err
	}
	containerName, err := boundedString(fields, "container_name")
	if err != nil {
		return bindingsContainer{}, err
	}
	containerClass, err := boundedString(fields, "container_class")
	if err != nil {
		return bindingsContainer{}, err
	}
	switch contract.ContainerClass(containerClass) {
	case contract.ContainerRegular, contract.ContainerInit, contract.ContainerEphemeral:
	default:
		return bindingsContainer{}, fmt.Errorf("%w: container_class", errStrictEnum)
	}
	observedAt, err := bindingsTimestamp(fields)
	if err != nil {
		return bindingsContainer{}, err
	}
	sourceName, err := boundedString(fields, "source_name")
	if err != nil {
		return bindingsContainer{}, err
	}
	sourceHash, err := digestOf(fields, "source_hash")
	if err != nil {
		return bindingsContainer{}, err
	}
	locator, err := boundedString(fields, "locator")
	if err != nil {
		return bindingsContainer{}, err
	}
	if sourceName == "" || locator == "" {
		return bindingsContainer{}, fmt.Errorf("%w: observation provenance", errStrictEmpty)
	}
	requestedImage, err := decodeBindingsRequestedImage(fields)
	if err != nil {
		return bindingsContainer{}, err
	}
	rawImageID, err := optionalBoundedString(fields, "raw_image_id")
	if err != nil {
		return bindingsContainer{}, err
	}
	digestText, err := optionalBoundedString(fields, "normalized_digest")
	if err != nil {
		return bindingsContainer{}, err
	}
	var guaranteedDigest *contract.NormalizedDigest
	if digestText != "" {
		digest, err := identity.NewGuaranteedDigest(digestText)
		if err != nil {
			return bindingsContainer{}, fmt.Errorf("%w: normalized_digest", errStrictHash)
		}
		guaranteedDigest = &digest
	}
	platformStatus, platformOS, platformArchitecture, err := decodeBindingsPlatform(fields)
	if err != nil {
		return bindingsContainer{}, err
	}
	key := identity.ContainerKey{
		SubjectUID:     subject.UID,
		ContainerClass: contract.ContainerClass(containerClass),
		ContainerName:  contract.ContainerName(containerName),
	}
	image := identity.ImageBinding{
		Key:                  key,
		InputKind:            identity.InputContainerObservation,
		SourceName:           sourceName,
		SourceHash:           contract.SourceHash(sourceHash),
		Locator:              contract.SourceLocator(locator),
		RequestedImage:       requestedImage,
		Platform:             platformStatus,
		PlatformOS:           platformOS,
		PlatformArchitecture: platformArchitecture,
		ObservedAt:           observedAt,
	}
	if rawImageID != "" {
		raw := contract.RawImageID(rawImageID)
		image.RawImageID = &raw
	}
	image.GuaranteedDigest = guaranteedDigest
	return bindingsContainer{key: key, image: image}, nil
}

// decodeBindingsRequestedImage composes the declared reference through the
// ADR-0009 grammar or leaves it absent. An absent or null member is absence; a
// present object must carry the three verbatim components, and a declaration
// the grammar cannot compose is refused, never repaired.
func decodeBindingsRequestedImage(fields object) (*contract.RequestedImage, error) {
	if !fields["requested_image"].present {
		return nil, nil
	}
	if fields.isNull("requested_image") {
		return nil, nil
	}
	declared, err := fields.object("requested_image")
	if err != nil {
		return nil, err
	}
	if err := declared.expectExact("registry", "repository", "tag"); err != nil {
		return nil, err
	}
	registry, err := boundedString(declared, "registry")
	if err != nil {
		return nil, err
	}
	repository, err := boundedString(declared, "repository")
	if err != nil {
		return nil, err
	}
	tag, err := boundedString(declared, "tag")
	if err != nil {
		return nil, err
	}
	composed, err := normalize.RequestedImage(normalize.DeclaredImage{
		Registry:   registry,
		Repository: repository,
		Tag:        tag,
	})
	if err != nil {
		return nil, fmt.Errorf("%w: requested_image", errStrictEnum)
	}
	requested := contract.RequestedImage(composed)
	return &requested, nil
}

func decodeBindingsPlatform(fields object) (contract.PlatformStatus, string, string, error) {
	platform, err := fields.object("platform")
	if err != nil {
		return "", "", "", err
	}
	if err := expectExactOptional(platform,
		[]string{"status"},
		[]string{"os", "architecture"}); err != nil {
		return "", "", "", err
	}
	status, err := boundedString(platform, "status")
	if err != nil {
		return "", "", "", err
	}
	osName, err := optionalBoundedString(platform, "os")
	if err != nil {
		return "", "", "", err
	}
	architecture, err := optionalBoundedString(platform, "architecture")
	if err != nil {
		return "", "", "", err
	}
	switch contract.PlatformStatus(status) {
	case contract.PlatformKnown:
		if osName == "" || architecture == "" {
			return "", "", "", fmt.Errorf("%w: known platform without os/architecture", errStrictEnum)
		}
		return contract.PlatformKnown, osName, architecture, nil
	case contract.PlatformUnknown:
		if osName != "" || architecture != "" {
			return "", "", "", fmt.Errorf("%w: unknown platform with os/architecture", errStrictEnum)
		}
		return contract.PlatformUnknown, "", "", nil
	default:
		return "", "", "", fmt.Errorf("%w: platform.status", errStrictEnum)
	}
}

func decodeBindingsLinks(root object) ([]bindingsLink, error) {
	rawLinks, err := root.array("bindings")
	if err != nil {
		return nil, err
	}
	if len(rawLinks) > maxImportBindings {
		return nil, fmt.Errorf("%w: bindings", errStrictIntegerRange)
	}
	links := make([]bindingsLink, 0, len(rawLinks))
	for _, raw := range rawLinks {
		fields, err := decodeObject(raw)
		if err != nil {
			return nil, err
		}
		if err := fields.expectExact("finding_index", "container_name", "container_class"); err != nil {
			return nil, err
		}
		index, err := findingIndexOf(fields, "finding_index")
		if err != nil {
			return nil, err
		}
		containerName, err := boundedString(fields, "container_name")
		if err != nil {
			return nil, err
		}
		containerClass, err := boundedString(fields, "container_class")
		if err != nil {
			return nil, err
		}
		switch contract.ContainerClass(containerClass) {
		case contract.ContainerRegular, contract.ContainerInit, contract.ContainerEphemeral:
		default:
			return nil, fmt.Errorf("%w: container_class", errStrictEnum)
		}
		if containerName == "" {
			return nil, fmt.Errorf("%w: container_name", errStrictEmpty)
		}
		links = append(links, bindingsLink{
			findingIndex:   index,
			containerClass: contract.ContainerClass(containerClass),
			containerName:  contract.ContainerName(containerName),
		})
	}
	return links, nil
}

// findingIndexOf reads the zero-based finding index. It is a separate reader
// from the pack version's integer(): index zero is a real row here, so the
// value rule admits it while the representational rules (decimal digits only,
// no sign, no leading zero) still apply to the raw token.
func findingIndexOf(fields object, name string) (int, error) {
	raw := trimRaw(fields, name)
	text := string(raw)
	if text == "" || text == "null" {
		return 0, fmt.Errorf("%w: %s", errStrictInteger, name)
	}
	if text != "0" {
		if len(text) > 1 && text[0] == '0' {
			return 0, fmt.Errorf("%w: %s", errStrictInteger, name)
		}
	}
	for _, character := range text {
		if character < '0' || character > '9' {
			return 0, fmt.Errorf("%w: %s", errStrictInteger, name)
		}
	}
	var value int64
	if err := json.Unmarshal(raw, &value); err != nil || value < 0 {
		return 0, fmt.Errorf("%w: %s", errStrictInteger, name)
	}
	if value > maxSafeInteger {
		return 0, fmt.Errorf("%w: %s", errStrictIntegerRange, name)
	}
	return int(value), nil
}

// boundedString reads one required string and enforces the document's own
// byte bound. Emptiness is decided by the caller when the field has its own
// rule.
func boundedString(fields object, name string) (string, error) {
	value, err := fields.requiredString(name)
	if err != nil {
		return "", err
	}
	if len(value) > maxImportStringBytes {
		return "", fmt.Errorf("%w: %s", errStrictIntegerRange, name)
	}
	return value, nil
}

// optionalBoundedString treats an absent member and an explicit null the same
// way the wire does: both are the canonical absence.
func optionalBoundedString(fields object, name string) (string, error) {
	if !fields[name].present || fields.isNull(name) {
		return "", nil
	}
	value, err := boundedString(fields, name)
	if err != nil {
		return "", err
	}
	return value, nil
}

func bindingsTimestamp(fields object) (*contract.Timestamp, error) {
	text, err := boundedString(fields, "observed_at")
	if err != nil {
		return nil, err
	}
	stamp, ok := canonicalTimestamp(text)
	if !ok {
		return nil, fmt.Errorf("%w: observed_at", errStrictTimestamp)
	}
	return &stamp, nil
}

func trimRaw(fields object, name string) []byte {
	return fields[name].raw
}

// parserVersion is the declared parser identity of the import profile: the
// only admitted schema at its only admitted version.
var parserVersion = "prisma-v" + schema.PrismaV1Version
