package evaluator

import (
	"sort"

	"github.com/d4rpell/Ariadne/internal/rulepack"
	contract "github.com/d4rpell/Ariadne/pkg/evidence"
)

// domainOutcome is the three-valued result of one domain predicate, with the
// reasons that produced it and the references it rests on.
type domainOutcome struct {
	value   CheckOutcome
	reasons []CheckReason
	refs    []EvidenceReference
}

// supportedState is one product state sustained by a valid applicable proof.
type supportedState struct {
	status contract.ProductStatus
	kind   proofKind
	refs   []EvidenceReference
}

// domainAssessment is the resolved view of every domain record of the target:
// which records are usable, which states are sustained, which blockers exist and
// which references belong to the global inspection. It is computed once, before
// the checks run, and the global inspection happens even without a favourable
// rule, so a pack cannot hide a contradiction by omitting the other branch.
type domainAssessment struct {
	mappingOK bool
	mapping   *mappingRecord

	artifactOK bool
	artifact   *artifactRecord

	// applicable proofs of the exact build and the states they sustain.
	proofs    []vendorProof
	supported []supportedState

	// Pertinent candidate sets: the records §6.4 considers for this target. Pins,
	// the age policy and the conflict detection apply to these, never to a record
	// of another CVE, product or component, which the target does not use. A
	// vendor record whose identity is explicitly foreign is not part of them:
	// §6.4 allows discarding it as not applicable.
	mappingCandidates  []mappingRecord
	artifactCandidates []artifactRecord

	// blockers of the chain, each with its reason and references. The set
	// records the reason even when it carries no reference, so a gap that is
	// only a missing candidate (a pin without a proof) is not lost.
	blockers map[CheckReason][]EvidenceReference
	blocked  map[CheckReason]bool

	// unknown names inside the reserved prefix: they block an affirmation.
	unknownDomain []EvidenceReference

	// global references of every domain candidate considered.
	globalRefs []EvidenceReference

	// pinsApproved reports whether every applicable candidate matched an exact
	// pin and every pin had at least one candidate.
	pinsApproved bool

	// current reports whether every used record is inside the age policy.
	current bool
}

// assessDomain resolves records, pins and time once per request. It reads the
// canonical copy through the resolver, so every reference is an index of the
// canonical evidence array.
func assessDomain(resolver *resolver, context DomainContext) domainAssessment {
	assessment := domainAssessment{
		blockers:     make(map[CheckReason][]EvidenceReference),
		blocked:      make(map[CheckReason]bool),
		pinsApproved: true,
		current:      true,
	}
	index := indexDomainRecords(resolver.bundle, resolver.target)
	records := decodeDomainRecords(index)

	for _, itemIndex := range index.unknown {
		assessment.unknownDomain = append(assessment.unknownDomain, EvidenceReference{ItemIndex: itemIndex})
	}
	// A group inside the namespace that the vocabulary cannot interpret blocks as
	// unsupported proof: it is not ignored for being incomplete.
	if len(records.unusable) > 0 {
		assessment.blocker(ReasonUnsupportedProof, records.unusable)
	}
	// The global inspection covers every domain record of the target scope,
	// whether or not a rule selects it and whether or not it is pertinent: a
	// contradiction cannot be hidden by omitting the rule of its branch.
	for _, record := range index.records {
		assessment.globalRefs = append(assessment.globalRefs, record.refs...)
	}
	assessment.globalRefs = append(assessment.globalRefs, assessment.unknownDomain...)
	sortReferencesInPlace(assessment.globalRefs)

	finding, image := resolver.findingRow(), resolver.boundImage()
	assessment.resolveMapping(records, finding)
	assessment.resolveArtifact(records, finding, image)
	assessment.resolveVendorProofs(records, finding, image)
	assessment.resolvePins(context)
	assessment.resolveTime(context, resolver, finding, image)
	return assessment
}

// findingFacts are the scanner columns of the target row that the domain
// predicates compare against.
type findingFacts struct {
	ok              bool
	vulnerabilityID string
	packageName     string
	packageType     string
	packageID       string
	observedAt      contract.Timestamp
	refs            []EvidenceReference
}

// imageFacts are the observed identity facts of the target container.
type imageFacts struct {
	ok               bool
	normalizedDigest string
	os               string
	architecture     string
	observedAt       contract.Timestamp
	refs             []EvidenceReference
}

// findingRow reads the target row through the existing requirement resolution,
// so the domain predicates rest on the same identity rules as the legacy ones.
func (resolver *resolver) findingRow() findingFacts {
	row := resolver.outcome(rulepack.RequirementFindingRow)
	if !row.satisfied || row.value == nil {
		return findingFacts{}
	}
	facts := findingFacts{
		ok:              true,
		vulnerabilityID: *row.value,
		observedAt:      resolver.target.ObservedAt,
		refs:            row.refs,
	}
	for _, field := range []struct {
		id     rulepack.FieldID
		target *string
	}{
		{rulepack.FieldPackageName, &facts.packageName},
		{rulepack.FieldPackageType, &facts.packageType},
		{rulepack.FieldPackageID, &facts.packageID},
	} {
		outcome := resolver.fieldOutcome(field.id, nil)
		if !outcome.satisfied || outcome.value == nil {
			facts.ok = false
			return facts
		}
		*field.target = *outcome.value
		facts.refs = append(facts.refs, outcome.refs...)
	}
	facts.refs = sortReferences(facts.refs)
	return facts
}

// boundImage reads the accredited image identity of the target container.
func (resolver *resolver) boundImage() imageFacts {
	bound := resolver.outcome(rulepack.RequirementImageBoundDigest)
	if !bound.satisfied {
		return imageFacts{}
	}
	platform := resolver.outcome(rulepack.RequirementImageKnownPlatform)
	if !platform.satisfied || platform.platform == nil {
		return imageFacts{}
	}
	image, unique := resolver.uniqueImage()
	if !unique || image.NormalizedDigest == nil || image.ObservedAt == nil {
		return imageFacts{}
	}
	refs := append(append([]EvidenceReference{}, bound.refs...), platform.refs...)
	return imageFacts{
		ok:               true,
		normalizedDigest: string(*image.NormalizedDigest),
		os:               image.Platform.OS,
		architecture:     image.Platform.Architecture,
		observedAt:       *image.ObservedAt,
		refs:             sortReferences(refs),
	}
}

// resolveMapping selects the mapping candidates that match the CVE and the three
// scanner package fields, and requires one single identity (ADR-0015 §6.1/§6.4).
func (assessment *domainAssessment) resolveMapping(records domainRecords, finding findingFacts) {
	if !finding.ok {
		assessment.blocker(ReasonMissing, nil)
		return
	}
	var matched []mappingRecord
	for _, mapping := range records.mappings {
		if mapping.vulnerabilityID != finding.vulnerabilityID {
			continue
		}
		if mapping.scannerName != finding.packageName ||
			mapping.scannerID != finding.packageID ||
			mapping.scannerType != finding.packageType {
			continue
		}
		matched = append(matched, mapping)
	}
	assessment.mappingCandidates = matched
	switch len(matched) {
	case 0:
		assessment.blocker(ReasonMissing, nil)
	case 1:
		assessment.mapping = &matched[0]
		assessment.mappingOK = true
	default:
		first := matched[0]
		equivalent := true
		for _, mapping := range matched[1:] {
			if mapping.productID != first.productID || mapping.productRelease != first.productRelease ||
				mapping.os != first.os || mapping.architecture != first.architecture ||
				mapping.componentID != first.componentID || mapping.packageName != first.packageName ||
				mapping.packageArch != first.packageArch {
				equivalent = false
			}
		}
		if !equivalent {
			assessment.blocker(ReasonConflict, refsOfMappings(matched))
			return
		}
		// Equivalent duplicates describe the same identity: the selected record
		// keeps every occurrence of all of them as its references.
		merged := first
		merged.refs = refsOfMappings(matched)
		assessment.mapping = &merged
		assessment.mappingOK = true
	}
}

// resolveArtifact binds the artifact record to the observed manifest digest, the
// platform of the image and the mapped identity (ADR-0015 §6.2/§6.4). A
// candidate of the component with an incompatible digest or identity blocks; it
// is never discarded to save another candidate.
func (assessment *domainAssessment) resolveArtifact(records domainRecords, finding findingFacts, image imageFacts) {
	if assessment.mapping == nil || !image.ok {
		assessment.blocker(ReasonMissing, nil)
		return
	}
	// The pertinent artifacts are those of the mapped component; every other
	// component is not considered for this target and neither blocks nor is
	// charged to the source policy.
	var pertinent []artifactRecord
	for _, artifact := range records.artifacts {
		if artifact.componentID == assessment.mapping.componentID {
			pertinent = append(pertinent, artifact)
		}
	}
	assessment.artifactCandidates = pertinent

	var matched []artifactRecord
	for _, artifact := range pertinent {
		// ADR-0015 §6.2: the platform and product/component fields must agree with
		// the observation and with the mapping. The component fields include the
		// package identity, so a build whose package contradicts the mapping is
		// incompatible, not a valid alternative.
		if artifact.artifactDigest != image.normalizedDigest ||
			artifact.productID != assessment.mapping.productID ||
			artifact.productRelease != assessment.mapping.productRelease ||
			artifact.os != image.os || artifact.architecture != image.architecture ||
			artifact.os != assessment.mapping.os ||
			artifact.architecture != assessment.mapping.architecture ||
			artifact.packageName != assessment.mapping.packageName ||
			artifact.packageArch != assessment.mapping.packageArch {
			assessment.blocker(ReasonMismatch, artifact.refs)
			continue
		}
		matched = append(matched, artifact)
	}
	switch len(matched) {
	case 0:
		if len(assessment.blockers[ReasonMismatch]) == 0 {
			assessment.blocker(ReasonMissing, nil)
		}
	case 1:
		assessment.artifact = &matched[0]
		assessment.artifactOK = true
	default:
		first := matched[0]
		equivalent := true
		for _, artifact := range matched[1:] {
			if artifact.epoch != first.epoch || artifact.version != first.version ||
				artifact.packageRelease != first.packageRelease || artifact.packageName != first.packageName ||
				artifact.packageArch != first.packageArch {
				equivalent = false
			}
		}
		if !equivalent {
			assessment.blocker(ReasonConflict, refsOfArtifacts(matched))
			return
		}
		merged := first
		merged.refs = refsOfArtifacts(matched)
		assessment.artifact = &merged
		assessment.artifactOK = true
	}
}

// resolveVendorProofs collects the applicable proofs of the exact build. A
// record whose identity is explicitly foreign is not applicable; an incomplete
// one keeps blocking, because nothing proves it is foreign (ADR-0015 §6.4).
func (assessment *domainAssessment) resolveVendorProofs(records domainRecords, finding findingFacts, image imageFacts) {
	if assessment.mapping == nil || assessment.artifact == nil {
		return
	}
	for _, proof := range records.vendors {
		if proof.vulnerabilityID != finding.vulnerabilityID {
			continue
		}
		if proof.componentID != assessment.mapping.componentID {
			continue
		}
		if !assessment.identityMatches(proof) {
			// A decodable record whose identity is explicitly foreign is not
			// applicable: it neither sustains a state nor blocks one, and it is not
			// charged to the source policy or to the age policy either. Only an
			// uninterpretable record keeps blocking, because nothing proves it
			// foreign.
			continue
		}
		assessment.proofs = append(assessment.proofs, proof)
		assessment.supported = append(assessment.supported, supportedState{
			status: statusForProof(proof.kind),
			kind:   proof.kind,
			refs:   proof.refs,
		})
	}
}

// identityMatches compares a vendor record with the mapped identity and the
// observed build. The three records must agree on the complete tuple, so a proof
// cannot rest on a platform or a package the mapping and the artifact do not
// share.
func (assessment *domainAssessment) identityMatches(proof vendorProof) bool {
	mapping, artifact := assessment.mapping, assessment.artifact
	if mapping == nil || artifact == nil {
		return false
	}
	return proof.productID == mapping.productID &&
		proof.productRelease == mapping.productRelease &&
		proof.os == mapping.os &&
		proof.architecture == mapping.architecture &&
		proof.packageName == artifact.packageName &&
		proof.packageArch == artifact.packageArch &&
		proof.epoch == artifact.epoch &&
		proof.version == artifact.version &&
		proof.packageRelease == artifact.packageRelease
}

func statusForProof(kind proofKind) contract.ProductStatus {
	switch kind {
	case proofVulnerableBuild:
		return contract.ProductAffected
	case proofFixedBuild:
		return contract.ProductFixed
	case proofCodeExcludedBuild:
		return contract.ProductNotAffected
	}
	return contract.ProductUnderInvestigation
}

// resolvePins checks the exact correspondence between candidates and pins in
// both directions (ADR-0015 §7.1).
func (assessment *domainAssessment) resolvePins(context DomainContext) {
	// Pins are compared by value, never by address: their advisory members are
	// pointers, so a map or struct comparison would silently mismatch.
	used := make([]SourcePin, 0, len(context.SourcePins))
	approve := func(pin SourcePin, refs []EvidenceReference) {
		for _, authorized := range context.SourcePins {
			if sameSourcePin(authorized, pin) {
				used = append(used, authorized)
				return
			}
		}
		assessment.pinsApproved = false
		assessment.blocker(ReasonUnapprovedSource, refs)
	}
	// Only the pertinent candidates are charged to the source policy: a record of
	// another CVE, product or component is not a proof of this target and cannot
	// make its source unauthorized (ADR-0015 §7.1).
	for _, mapping := range assessment.mappingCandidates {
		approve(SourcePin{Role: SourceRoleMapping, Source: mapping.record.key.source, SourceHash: mapping.record.key.sourceHash}, mapping.refs)
	}
	for _, artifact := range assessment.artifactCandidates {
		approve(SourcePin{Role: SourceRoleArtifact, Source: artifact.record.key.source, SourceHash: artifact.record.key.sourceHash}, artifact.refs)
	}
	for _, proof := range assessment.proofs {
		advisoryID := proof.advisoryID
		revision := proof.advisoryRevision
		approve(SourcePin{
			Role:             SourceRoleVendor,
			Source:           proof.record.key.source,
			SourceHash:       proof.record.key.sourceHash,
			AdvisoryID:       &advisoryID,
			AdvisoryRevision: &revision,
		}, proof.refs)
	}
	// A pin without any candidate is a gap: it is never silently satisfied.
	for _, pin := range context.SourcePins {
		matched := false
		for _, seen := range used {
			if sameSourcePin(seen, pin) {
				matched = true
				break
			}
		}
		if !matched {
			assessment.pinsApproved = false
			assessment.blocker(ReasonUnapprovedSource, nil)
		}
	}
}

// resolveTime applies the age policy to every record used and to the finding and
// image observations (ADR-0015 §7.2).
func (assessment *domainAssessment) resolveTime(context DomainContext, resolver *resolver, finding findingFacts, image imageFacts) {
	evaluatedAt := resolver.evaluatedAt
	check := func(observedAt contract.Timestamp, refs []EvidenceReference) {
		current, reason := evidenceCurrent(observedAt, contract.Timestamp{Time: evaluatedAt}, context.MaximumEvidenceAgeSeconds)
		if current {
			return
		}
		assessment.current = false
		assessment.blocker(reason, refs)
	}
	// The age policy applies to the observations this target actually uses: the
	// pertinent candidates plus the finding and the image. An old record of
	// another CVE or component is not evidence of this target.
	for _, mapping := range assessment.mappingCandidates {
		check(mapping.record.key.observedAt, mapping.refs)
	}
	for _, artifact := range assessment.artifactCandidates {
		check(artifact.record.key.observedAt, artifact.refs)
	}
	for _, proof := range assessment.proofs {
		check(proof.record.key.observedAt, proof.refs)
	}
	if finding.ok {
		check(finding.observedAt, finding.refs)
	}
	if image.ok {
		check(image.observedAt, image.refs)
	}
}

func (assessment *domainAssessment) blocker(reason CheckReason, refs []EvidenceReference) {
	assessment.blocked[reason] = true
	assessment.blockers[reason] = append(assessment.blockers[reason], refs...)
}

// sustainedStates returns the distinct states sustained by valid proofs, ordered
// by state for a deterministic result.
func (assessment *domainAssessment) sustainedStates() []supportedState {
	byStatus := make(map[contract.ProductStatus][]supportedState)
	for _, state := range assessment.supported {
		byStatus[state.status] = append(byStatus[state.status], state)
	}
	statuses := make([]string, 0, len(byStatus))
	for status := range byStatus {
		statuses = append(statuses, string(status))
	}
	sort.Strings(statuses)
	ordered := make([]supportedState, 0, len(statuses))
	for _, status := range statuses {
		group := byStatus[contract.ProductStatus(status)]
		merged := group[0]
		for _, state := range group[1:] {
			merged.refs = append(merged.refs, state.refs...)
		}
		sortReferencesInPlace(merged.refs)
		ordered = append(ordered, merged)
	}
	return ordered
}

func (assessment *domainAssessment) hasProofKind(kind proofKind) bool {
	for _, proof := range assessment.proofs {
		if proof.kind == kind {
			return true
		}
	}
	return false
}

// complete reports whether the applicable set is fully interpretable: no unknown
// names, no blockers, a mapping and an artifact and at least one applicable
// proof. Only a complete set can turn a terminal into a real fail.
func (assessment *domainAssessment) complete() bool {
	return len(assessment.unknownDomain) == 0 && len(assessment.blocked) == 0 &&
		assessment.mappingOK && assessment.artifactOK && len(assessment.proofs) > 0
}

// orderedBlockers returns the blocker reasons in a deterministic order.
func (assessment *domainAssessment) orderedBlockers() []CheckReason {
	reasons := make([]CheckReason, 0, len(assessment.blocked))
	for reason := range assessment.blocked {
		reasons = append(reasons, reason)
	}
	sort.Slice(reasons, func(i, j int) bool { return reasons[i] < reasons[j] })
	return reasons
}

func refsOfMappings(mappings []mappingRecord) []EvidenceReference {
	var refs []EvidenceReference
	for _, mapping := range mappings {
		refs = append(refs, mapping.refs...)
	}
	sortReferencesInPlace(refs)
	return refs
}

func refsOfArtifacts(artifacts []artifactRecord) []EvidenceReference {
	var refs []EvidenceReference
	for _, artifact := range artifacts {
		refs = append(refs, artifact.refs...)
	}
	sortReferencesInPlace(refs)
	return refs
}

func sortReferencesInPlace(refs []EvidenceReference) {
	sort.Slice(refs, func(i, j int) bool { return refs[i].ItemIndex < refs[j].ItemIndex })
}
