package bundle

import (
	"errors"

	"github.com/d4rpell/Ariadne/internal/identity"
	"github.com/d4rpell/Ariadne/internal/ingest"
	"github.com/d4rpell/Ariadne/internal/normalize"
	contract "github.com/d4rpell/Ariadne/pkg/evidence"
)

// scopeKey is the container identity the wire Scope can express: uid plus
// container name, with no class. Two classes under the same key are a collision
// that ADR-0010 makes unprojectable.
type scopeKey struct {
	SubjectUID    contract.UID
	ContainerName contract.ContainerName
}

// subjectCollisions lists the collided keys of one subject in the order
// normalize.ScopeCollisions reports them, each with its visible warning and its
// static error. The detection runs over the whole result before any finding is
// discarded for another reason, so a collided key never leaks the half that
// happens to be otherwise projectable.
func subjectCollisions(result normalize.Result, uid contract.UID) (map[scopeKey]bool, []contract.Warning, []string, error) {
	keys := make(map[scopeKey]bool)
	var warnings []contract.Warning
	var messages []string
	for _, collision := range normalize.ScopeCollisions(result) {
		if collision.SubjectUID != uid {
			continue
		}
		keys[scopeKey{SubjectUID: collision.SubjectUID, ContainerName: collision.ContainerName}] = true
		warning, err := scopeCollisionWarning(collision.Classes)
		if err != nil {
			return nil, nil, nil, err
		}
		warnings = append(warnings, warning)
		messages = append(messages, errScopeCollisionOmitted.Error())
	}
	return keys, warnings, messages, nil
}

// declaredColumn is one canonical CSV column as a source fact.
type declaredColumn struct {
	name  string
	value string
}

var declaredColumnOrder = []string{
	"schema_version",
	"vulnerability_id",
	"package_name",
	"installed_version",
	"fix_status",
	"image_registry",
	"image_repository",
	"image_tag",
	"package_type",
	"package_id",
	"path",
	"severity",
	"description",
	"published_date",
	"discovery_date",
}

// declaredColumns returns the column values of one accepted record in canonical
// order. An omitted optional column and an empty cell are both the empty,
// not-informed value; nothing is inferred from other fields (ADR-0008 D6).
func declaredColumns(finding ingest.Finding) []declaredColumn {
	values := []string{
		finding.SchemaVersion,
		finding.VulnerabilityID,
		finding.PackageName,
		finding.InstalledVersion,
		finding.FixStatus,
		finding.ImageRegistry,
		finding.ImageRepository,
		finding.ImageTag,
		finding.PackageType,
		finding.PackageID,
		finding.Path,
		finding.Severity,
		finding.Description,
		finding.PublishedDate,
		finding.DiscoveryDate,
	}
	columns := make([]declaredColumn, 0, len(declaredColumnOrder))
	for index, name := range declaredColumnOrder {
		columns = append(columns, declaredColumn{name: name, value: values[index]})
	}
	return columns
}

// projectDeclared maps the informed columns of one finding onto declared
// evidence items. Every item cites the CSV row it comes from; a value that the
// wire cannot carry verbatim is kept auditable by hash only.
func projectDeclared(subject contract.Subject, finding normalize.NormalizedFinding, source ImportSource) []contract.EvidenceItem {
	container := finding.Binding.Key.ContainerName
	items := make([]contract.EvidenceItem, 0, len(declaredColumnOrder)+1)
	for _, column := range declaredColumns(finding.Source) {
		if column.value == "" {
			continue
		}
		items = append(items, declaredItem(subject, container, finding.Source.Locator, source,
			"prisma_v1."+column.name, column.value, contract.ProvenanceObserved))
	}
	return items
}

// projectRequestedImage records the composed reference as a derived fact: the
// string does not appear literally in the source, the ADR-0009 grammar produces
// it from three declared columns.
func projectRequestedImage(subject contract.Subject, finding normalize.NormalizedFinding, source ImportSource) contract.EvidenceItem {
	return declaredItem(subject, finding.Binding.Key.ContainerName, finding.Source.Locator, source,
		"prisma_v1.requested_image", string(*finding.RequestedImage), contract.ProvenanceDerived)
}

func declaredItem(subject contract.Subject, container contract.ContainerName, locator ingest.Locator, source ImportSource, itemType, value string, confidence contract.ProvenanceKind) contract.EvidenceItem {
	item := contract.EvidenceItem{
		Type:       itemType,
		Source:     source.Path,
		SourceHash: source.Hash,
		Locator:    contract.SourceLocator(locator.String()),
		ObservedAt: copyPointer(source.ObservedAt),
		Confidence: confidence,
		Scope:      contract.Scope{SubjectUID: subject.UID, ContainerName: container},
		Warnings:   []contract.Warning{},
	}
	item.ValueHash = valueHashPointer(value)
	if wireValueOK(value) {
		item.Value = copyPointer(&value)
	}
	return item
}

// projectObserved maps the facts one binding actually carries onto observation
// items. It is called only for a binding whose provenance is complete: a fact
// without a source, a hash, a locator and a timestamp is not projected at all.
func projectObserved(subject contract.Subject, binding identity.ImageBinding) []contract.EvidenceItem {
	items := make([]contract.EvidenceItem, 0, 4)
	if binding.RawImageID != nil {
		items = append(items, observedItem(subject, binding, "container_status.image_id",
			string(*binding.RawImageID), contract.ProvenanceObserved))
	}
	if binding.GuaranteedDigest != nil {
		items = append(items, observedItem(subject, binding, "container_status.normalized_digest",
			string(*binding.GuaranteedDigest), contract.ProvenanceDerived))
	}
	if binding.Platform == contract.PlatformKnown {
		items = append(items, observedItem(subject, binding, "container_status.platform.os",
			binding.PlatformOS, contract.ProvenanceObserved))
		items = append(items, observedItem(subject, binding, "container_status.platform.architecture",
			binding.PlatformArchitecture, contract.ProvenanceObserved))
	}
	return items
}

func observedItem(subject contract.Subject, binding identity.ImageBinding, itemType, value string, confidence contract.ProvenanceKind) contract.EvidenceItem {
	item := contract.EvidenceItem{
		Type:       itemType,
		Source:     binding.SourceName,
		SourceHash: binding.SourceHash,
		Locator:    binding.Locator,
		ObservedAt: copyPointer(binding.ObservedAt),
		Confidence: confidence,
		Scope:      contract.Scope{SubjectUID: subject.UID, ContainerName: binding.Key.ContainerName},
		Warnings:   []contract.Warning{},
	}
	item.ValueHash = valueHashPointer(value)
	if wireValueOK(value) {
		item.Value = copyPointer(&value)
	}
	return item
}

// projectImage projects the image identity of one finding. The requested
// reference is a declaration of the finding; the observed fields and the
// platform carrier come only from a binding whose provenance is complete, so an
// unevidenced observation is never presented as identity (ADR-0010 E1).
func projectImage(finding normalize.NormalizedFinding, complete bool) contract.ImageIdentity {
	binding := *finding.Binding
	image := contract.ImageIdentity{
		ContainerClass: binding.Key.ContainerClass,
		ContainerName:  binding.Key.ContainerName,
		RequestedImage: copyPointer(finding.RequestedImage),
		Platform:       contract.Platform{Status: contract.PlatformUnknown},
	}
	if !complete {
		return image
	}
	image.ObservedAt = copyPointer(binding.ObservedAt)
	image.RawImageID = copyPointer(binding.RawImageID)
	image.NormalizedDigest = copyPointer(binding.GuaranteedDigest)
	if binding.Platform == contract.PlatformKnown {
		image.Platform = contract.Platform{
			OS:           binding.PlatformOS,
			Architecture: binding.PlatformArchitecture,
			Status:       contract.PlatformKnown,
		}
	}
	return image
}

// valueHashPointer builds the required hash of one value. The pointer is fresh
// per item: two items never share mutable state.
func valueHashPointer(value string) *contract.ValueHash {
	hash := HashValue(value)
	return &hash
}

var errCollisionClassUnknown = errors.New("bundle: scope collision carries a class outside the enum")
