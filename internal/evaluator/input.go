package evaluator

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"sort"
	"strings"
	"time"
	"unicode/utf8"

	canonical "github.com/d4rpell/Ariadne/internal/evidence"
	"github.com/d4rpell/Ariadne/internal/rulepack"
	contract "github.com/d4rpell/Ariadne/pkg/evidence"
)

// Admission limits of ADR-0013 §5.4.
const (
	MaxTargetStringBytes  = 16 << 10
	MaxTargetTotalBytes   = 64 << 10
	MaxContextTotalBytes  = 4 << 10
	MaxEvidenceItems      = 100000
	MaxImages             = 10000
	MaxCollectionElements = 500000
	MaxBundleStringBytes  = 64 << 20
	MaxResultReferences   = 100000
	MaxCandidateBudget    = 1000000
)

const sha256Prefix = "sha256:"

// referenceBudget bounds the references the Result stores. The budget counts
// every occurrence of every trace, as ADR-0013 §5.4 requires: a reference
// repeated by two checks, by the aggregated trace and by the global list is four
// occurrences. Each occurrence is admitted before it is stored, so the
// collections of the Result never grow past the limit.
//
// The requirement resolutions are intermediate: they are not occurrences of the
// Result, they are memoized once per requirement of the closed vocabulary (at
// most ten groups, each bounded by the evidence count and by the candidate
// budget that is enforced before the checks run), and they are never returned.
type referenceBudget struct {
	used uint64
	over bool
}

// admit reserves room for count references and reports whether they may be
// stored.
func (budget *referenceBudget) admit(count int) bool {
	if budget.over || count <= 0 {
		return !budget.over
	}
	budget.used += uint64(count)
	if budget.used > MaxResultReferences {
		budget.over = true
		return false
	}
	return true
}

// copyReferences admits and appends one occurrence of a set of references into a
// new collection.
func (resolver *resolver) copyReferences(refs, more []EvidenceReference) []EvidenceReference {
	if !resolver.budget.admit(len(more)) {
		return refs
	}
	return append(refs, more...)
}

// Evidence item types this profile recognises, exactly as ADR-0012 projects
// them. Any other type stays in the bundle and is never an operand.
const (
	TypeRequestedImage       = "prisma_v1.requested_image"
	TypeImageID              = "container_status.image_id"
	TypeNormalizedDigest     = "container_status.normalized_digest"
	TypePlatformOS           = "container_status.platform.os"
	TypePlatformArchitecture = "container_status.platform.architecture"
)

var findingFields = []rulepack.FieldID{
	rulepack.FieldVulnerabilityID,
	rulepack.FieldPackageName,
	rulepack.FieldInstalledVersion,
	rulepack.FieldPackageType,
	rulepack.FieldPackageID,
	rulepack.FieldFixStatus,
}

func itemTypeForField(field rulepack.FieldID) string {
	return "prisma_v1." + string(field)
}

func recognizedType(itemType string) bool {
	switch itemType {
	case TypeRequestedImage, TypeImageID, TypeNormalizedDigest, TypePlatformOS, TypePlatformArchitecture:
		return true
	}
	const prefix = "prisma_v1."
	if strings.HasPrefix(itemType, prefix) {
		return rulepack.FieldID(strings.TrimPrefix(itemType, prefix)).Valid()
	}
	return false
}

// expectedConfidence is the provenance kind ADR-0012 fixes for each recognised
// fact: declared columns and observations are observed, composed or normalised
// values are derived.
func expectedConfidence(itemType string) contract.ProvenanceKind {
	switch itemType {
	case TypeRequestedImage, TypeNormalizedDigest:
		return contract.ProvenanceDerived
	}
	return contract.ProvenanceObserved
}

// identifierOK mirrors the wire rule for identifiers: present, no surrounding
// whitespace and valid UTF-8. Nothing is trimmed or repaired.
func identifierOK(value string) bool {
	return value != "" && strings.TrimSpace(value) == value && utf8.ValidString(value)
}

func hashValue(value string) string {
	digest := sha256.Sum256([]byte(value))
	return sha256Prefix + hex.EncodeToString(digest[:])
}

func isSha256(value string) bool {
	if len(value) != len(sha256Prefix)+64 || !strings.HasPrefix(value, sha256Prefix) {
		return false
	}
	for index := len(sha256Prefix); index < len(value); index++ {
		digit := value[index]
		if (digit < '0' || digit > '9') && (digit < 'a' || digit > 'f') {
			return false
		}
	}
	return true
}

// validCVE is the grammar already ratified for prisma-v1.
func validCVE(value string) bool {
	if !strings.HasPrefix(value, "CVE-") {
		return false
	}
	rest := value[4:]
	if len(rest) < 9 || rest[4] != '-' {
		return false
	}
	for index := 0; index < len(rest); index++ {
		if index == 4 {
			continue
		}
		if rest[index] < '0' || rest[index] > '9' {
			return false
		}
	}
	return true
}

// checkInputLimits is the first phase: every input budget, in a fixed order and
// before any form or content rule.
func checkInputLimits(request Request) error {
	if len(request.PackBytes) > rulepack.MaxPackBytes {
		return problem(CodeInputLimit, -1)
	}
	targetStrings := []string{
		string(request.Target.SubjectUID),
		string(request.Target.ContainerClass),
		string(request.Target.ContainerName),
		request.Target.VulnerabilityID,
		request.Target.Source,
		string(request.Target.SourceHash),
		string(request.Target.Locator),
	}
	total := 0
	for index, value := range targetStrings {
		if len(value) > MaxTargetStringBytes {
			return problem(CodeInputLimit, index)
		}
		total += len(value)
	}
	if total > MaxTargetTotalBytes {
		return problem(CodeInputLimit, -1)
	}
	// The joint context budget of ADR-0015 §7.3 counts the typed strings of the
	// admission context and of the domain context together, every occurrence
	// included; null contributes zero. Each addition is compared against the
	// remaining room first, so the sum cannot overflow.
	contextBytes := len(request.Admission.ExpectedPackID) + len(request.Admission.ExpectedPackHash)
	if previous := request.Admission.Previous; previous != nil {
		contextBytes += len(previous.Hash)
	}
	if contextBytes > MaxContextTotalBytes {
		return problem(CodeInputLimit, -1)
	}
	if domain := request.Domain; domain != nil {
		// The cardinality is checked before any pin is walked, so an oversized
		// collection cannot cost work before its own limit applies (ADR-0018 §4.1).
		if len(domain.SourcePins) > MaxSourcePins {
			return problem(CodeInputLimit, -1)
		}
		for _, pin := range domain.SourcePins {
			for _, value := range []string{
				string(pin.Role), pin.Source, string(pin.SourceHash),
				optionalValue(pin.AdvisoryID), optionalValue(pin.AdvisoryRevision),
			} {
				if len(value) > MaxContextTotalBytes-contextBytes {
					return problem(CodeInputLimit, -1)
				}
				contextBytes += len(value)
			}
		}
	}
	return checkBundleLimits(request.Bundle)
}

// countBudget counts elements of one unit and stops at its limit: the sum can
// never overflow, because counting ends as soon as the limit is passed.
type countBudget struct {
	total uint64
	limit uint64
	over  bool
}

func (budget *countBudget) add(count int) {
	if budget.over || count <= 0 {
		return
	}
	budget.total += uint64(count)
	if budget.total > budget.limit {
		budget.over = true
	}
}

// stringBudget counts decoded UTF-8 bytes over every string the bundle carries,
// repeated values included, with the same early stop.
type stringBudget struct {
	total     uint64
	limit     uint64
	inspected int
	over      bool
}

func (budget *stringBudget) add(value string) {
	// inspected counts every string the inventory touches, whether or not its
	// bytes are still counted: the loops stop before reaching a collection, so a
	// rejected bundle never walks what it already refuses.
	budget.inspected++
	if budget.over {
		return
	}
	budget.total += uint64(len(value))
	if budget.total > budget.limit {
		budget.over = true
	}
}

func (budget *stringBudget) addWarning(warning contract.Warning) {
	budget.add(warning.Code)
	budget.add(string(warning.Class))
	budget.add(warning.Message)
}

func optionalValue[T ~string](value *T) string {
	if value == nil {
		return ""
	}
	return string(*value)
}

// bundleLimits are the admission budgets of one bundle, in their own units.
type bundleLimits struct {
	items    uint64
	images   uint64
	elements uint64
	bytes    uint64
}

func ratifiedBundleLimits() bundleLimits {
	return bundleLimits{
		items:    MaxEvidenceItems,
		images:   MaxImages,
		elements: MaxCollectionElements,
		bytes:    MaxBundleStringBytes,
	}
}

// bundleUsage is what one bundle consumes, with the unit each budget uses.
// Inspected counts how many string fields the inventory touched: it stays at zero
// when an earlier budget already rejected the bundle, so a rejected input cannot
// amplify the walk by aliasing collections.
type bundleUsage struct {
	items        uint64
	images       uint64
	elements     uint64
	bytes        uint64
	inspected    int
	overItems    bool
	overImages   bool
	overElements bool
	overBytes    bool
}

// rejected reports whether any budget is already exhausted.
func (usage bundleUsage) rejected() bool {
	return usage.overItems || usage.overImages || usage.overElements || usage.overBytes
}

// measureBundle applies the admission budgets of ADR-0013 §5.4 with separate
// units: evidence items, images, elements of every collection and decoded string
// bytes. Every string field is counted, including the operational metadata
// excluded from the projection hash, because the budget bounds the admission
// work, not the hash; counting stops at the limit, so the sums cannot overflow.
func measureBundle(bundle contract.Bundle, limits bundleLimits) bundleUsage {
	var usage bundleUsage

	items := &countBudget{limit: limits.items}
	items.add(len(bundle.Evidence))
	usage.items, usage.overItems = items.total, items.over

	images := &countBudget{limit: limits.images}
	images.add(len(bundle.Images))
	usage.images, usage.overImages = images.total, images.over

	elements := &countBudget{limit: limits.elements}
	elements.add(len(bundle.Images))
	elements.add(len(bundle.Evidence))
	elements.add(len(bundle.ObservedContainerClasses))
	elements.add(len(bundle.Provenance.ArgvSanitized))
	elements.add(len(bundle.Provenance.Inputs))
	elements.add(len(bundle.Provenance.APIScope.Namespaces))
	elements.add(len(bundle.Provenance.APIScope.Verbs))
	elements.add(len(bundle.Provenance.APIScope.Resources))
	elements.add(len(bundle.Provenance.Warnings))
	elements.add(len(bundle.Provenance.Errors))
	for _, item := range bundle.Evidence {
		elements.add(len(item.Warnings))
		if elements.over {
			break
		}
	}
	usage.elements, usage.overElements = elements.total, elements.over
	if usage.rejected() {
		// A bundle that is already over a count budget is not walked any further:
		// the string inventory would only repeat work the rejection discards.
		return usage
	}

	bytes := &stringBudget{limit: limits.bytes}
	bytes.add(bundle.SchemaVersion)
	bytes.add(string(bundle.Subject.ClusterAlias))
	bytes.add(string(bundle.Subject.Namespace))
	bytes.add(bundle.Subject.Kind)
	bytes.add(bundle.Subject.Name)
	bytes.add(string(bundle.Subject.UID))
	bytes.add(string(bundle.Subject.OwnerChain))
	for _, class := range bundle.ObservedContainerClasses {
		if bytes.over {
			break
		}
		bytes.add(string(class))
	}
	for _, image := range bundle.Images {
		if bytes.over {
			break
		}
		bytes.add(string(image.ContainerClass))
		bytes.add(string(image.ContainerName))
		bytes.add(optionalValue(image.RequestedImage))
		bytes.add(optionalValue(image.RawImageID))
		bytes.add(optionalValue(image.NormalizedDigest))
		bytes.add(image.Platform.OS)
		bytes.add(image.Platform.Architecture)
		bytes.add(string(image.Platform.Status))
	}
	for _, item := range bundle.Evidence {
		if bytes.over {
			break
		}
		bytes.add(item.Type)
		bytes.add(item.Source)
		bytes.add(string(item.SourceHash))
		bytes.add(string(item.Locator))
		bytes.add(optionalValue(item.Value))
		bytes.add(optionalValue(item.ValueHash))
		bytes.add(string(item.Confidence))
		bytes.add(string(item.Scope.SubjectUID))
		bytes.add(string(item.Scope.ContainerName))
		for _, warning := range item.Warnings {
			if bytes.over {
				break
			}
			bytes.addWarning(warning)
		}
	}
	bytes.add(bundle.Provenance.CollectorVersion)
	bytes.add(bundle.Provenance.ParserVersion)
	bytes.add(bundle.Provenance.Ruleset.Path)
	bytes.add(string(bundle.Provenance.Ruleset.Hash))
	bytes.add(bundle.Provenance.Ruleset.Version)
	for _, argument := range bundle.Provenance.ArgvSanitized {
		if bytes.over {
			break
		}
		bytes.add(argument)
	}
	for _, input := range bundle.Provenance.Inputs {
		if bytes.over {
			break
		}
		bytes.add(input.Path)
		bytes.add(string(input.Hash))
	}
	for _, namespace := range bundle.Provenance.APIScope.Namespaces {
		if bytes.over {
			break
		}
		bytes.add(string(namespace))
	}
	for _, verb := range bundle.Provenance.APIScope.Verbs {
		if bytes.over {
			break
		}
		bytes.add(verb)
	}
	for _, resource := range bundle.Provenance.APIScope.Resources {
		if bytes.over {
			break
		}
		bytes.add(resource)
	}
	bytes.add(bundle.Provenance.Budget.WallClock)
	bytes.add(string(bundle.Provenance.Coverage.Method))
	bytes.add(string(bundle.Provenance.Coverage.Termination))
	bytes.add(string(bundle.Provenance.Completeness))
	bytes.add(string(bundle.Provenance.Consistency))
	bytes.add(bundle.Provenance.RedactionPolicy)
	for _, warning := range bundle.Provenance.Warnings {
		if bytes.over {
			break
		}
		bytes.addWarning(warning)
	}
	for _, message := range bundle.Provenance.Errors {
		if bytes.over {
			break
		}
		bytes.add(message)
	}
	usage.bytes, usage.overBytes = bytes.total, bytes.over
	usage.inspected = bytes.inspected

	return usage
}

// checkBundleLimits rejects a bundle that exceeds any admission budget.
func checkBundleLimits(bundle contract.Bundle) error {
	usage := measureBundle(bundle, ratifiedBundleLimits())
	if usage.overItems || usage.overImages || usage.overElements || usage.overBytes {
		return problem(CodeInputLimit, -1)
	}
	return nil
}

// checkTargetForm validates the target's own shape. A malformed target or a
// target of another subject rejects the request; the engine never enumerates
// targets and never repairs one. The subject comparison reads the bundle field
// directly: the target phase precedes bundle validation, so a foreign target is
// reported as such instead of being masked by a later failure.
func checkTargetForm(request Request) error {
	target := request.Target
	if !identifierOK(string(target.SubjectUID)) || target.SubjectUID != request.Bundle.Subject.UID {
		return problem(CodeInvalidTarget, -1)
	}
	if !target.ContainerClass.Valid() {
		return problem(CodeInvalidTarget, -1)
	}
	if !identifierOK(string(target.ContainerName)) {
		return problem(CodeInvalidTarget, -1)
	}
	if !validCVE(target.VulnerabilityID) {
		return problem(CodeInvalidTarget, -1)
	}
	// A malformed path or reference is refused instead of being repaired: an
	// invalid UTF-8 target cannot be carried by the result encoding either.
	if !identifierOK(target.Source) || !isSha256(string(target.SourceHash)) || !identifierOK(string(target.Locator)) {
		return problem(CodeInvalidTarget, -1)
	}
	if target.ObservedAt.IsZero() || target.ObservedAt.Location() != time.UTC {
		return problem(CodeInvalidTarget, -1)
	}
	return nil
}

// projectionHash proves the expected hash of the bundle's canonical projection.
// The hash is recomputed from the bundle itself: a projection supplied by the
// caller is never accepted as a substitute.
func projectionHash(bundle contract.Bundle) (string, error) {
	computed, err := canonical.HashCanonicalJSON(bundle)
	if err != nil {
		return "", problem(CodeInvalidBundle, -1)
	}
	return computed, nil
}

// canonicalCopy returns the canonical-ordered copy every later phase reads. It
// is the authority on collection order, so reference indices are indices of the
// canonical arrays of ADR-0006. The caller's bundle is never mutated and never
// aliased.
func canonicalCopy(bundle contract.Bundle) (contract.Bundle, error) {
	encoded, err := canonical.CanonicalJSON(bundle)
	if err != nil {
		return contract.Bundle{}, problem(CodeInvalidBundle, -1)
	}
	var ordered contract.Bundle
	if err := json.Unmarshal(encoded, &ordered); err != nil {
		return contract.Bundle{}, problem(CodeInvalidBundle, -1)
	}
	return ordered, nil
}

// checkValueHashes revalidates the value hash of every recognised fact that
// carries a value. The domain types are handled in domain_admission.go, where
// the strict profile classification decides whether they are verified.

// requirementOutcome is the resolution of one requirement: whether the bundle
// substantiates it, the reasons when it does not, the canonical references it
// rests on and how many candidates the query examined for the work budget.
type requirementOutcome struct {
	satisfied  bool
	reasons    []CheckReason
	refs       []EvidenceReference
	candidates int
	value      *string
	platform   *contract.Platform
}

func unknownOutcome(candidates int, reasons ...CheckReason) requirementOutcome {
	return requirementOutcome{satisfied: false, reasons: orderReasons(reasons), candidates: candidates}
}

// resolver indexes one canonical bundle for the target. All reads happen on the
// canonical copy, so references are indices of the canonical arrays.
type resolver struct {
	bundle         contract.Bundle
	target         Target
	evaluatedAt    time.Time
	budget         *referenceBudget
	rowItems       []int
	scopeItems     []int
	images         []int
	classAmbiguous bool
}

func newResolver(bundle contract.Bundle, target Target, evaluatedAt time.Time, budget *referenceBudget) *resolver {
	built := &resolver{bundle: bundle, target: target, evaluatedAt: evaluatedAt, budget: budget}
	for index, item := range bundle.Evidence {
		if item.Scope.SubjectUID != target.SubjectUID || item.Scope.ContainerName != target.ContainerName {
			continue
		}
		built.scopeItems = append(built.scopeItems, index)
		if item.Source != target.Source || item.SourceHash != target.SourceHash || item.Locator != target.Locator {
			continue
		}
		if item.ObservedAt != nil && item.ObservedAt.Time.Equal(target.ObservedAt.Time) {
			built.rowItems = append(built.rowItems, index)
		}
	}
	for index, image := range bundle.Images {
		if image.ContainerName != target.ContainerName {
			continue
		}
		if image.ContainerClass == target.ContainerClass {
			built.images = append(built.images, index)
			continue
		}
		// The wire scope cannot distinguish classes, so the same container name in
		// another class makes the image evidence ambiguous instead of selectable.
		built.classAmbiguous = true
	}
	return built
}

func (resolver *resolver) outcome(requirement rulepack.Requirement) requirementOutcome {
	switch requirement {
	case rulepack.RequirementBundleComplete:
		return resolver.completenessOutcome()
	case rulepack.RequirementFindingRow:
		wanted := resolver.target.VulnerabilityID
		return resolver.fieldOutcome(rulepack.FieldVulnerabilityID, &wanted)
	case rulepack.RequirementImageBoundDigest:
		return resolver.boundDigestOutcome()
	case rulepack.RequirementImageKnownPlatform:
		return resolver.knownPlatformOutcome()
	}
	const prefix = "finding."
	if strings.HasPrefix(string(requirement), prefix) {
		field := rulepack.FieldID(strings.TrimPrefix(string(requirement), prefix))
		if field.Valid() {
			return resolver.fieldOutcome(field, nil)
		}
	}
	return unknownOutcome(0, ReasonMissing)
}

func (resolver *resolver) completenessOutcome() requirementOutcome {
	provenance := resolver.bundle.Provenance
	if provenance.Completeness != contract.CompletenessComplete ||
		provenance.Coverage.Termination != contract.TerminationFinished ||
		len(provenance.Errors) != 0 {
		return unknownOutcome(1, ReasonMissing)
	}
	return requirementOutcome{satisfied: true, reasons: []CheckReason{ReasonVerified}, candidates: 1}
}

func (resolver *resolver) fieldOutcome(field rulepack.FieldID, wanted *string) requirementOutcome {
	itemType := itemTypeForField(field)
	indices := make([]int, 0, len(resolver.rowItems))
	for _, index := range resolver.rowItems {
		if resolver.bundle.Evidence[index].Type == itemType {
			indices = append(indices, index)
		}
	}
	outcome := requirementOutcome{candidates: len(indices)}
	if len(indices) == 0 {
		outcome.reasons = []CheckReason{ReasonMissing}
		return outcome
	}
	var values []string
	for _, index := range indices {
		item := resolver.bundle.Evidence[index]
		// No hash-shape case is needed here: a row candidate is selected by the
		// exact (source, source_hash, locator, observed_at) key of the target, and
		// the target hash is validated as a sha256 digest, so an item of this group
		// cannot carry a malformed one.
		switch {
		case resolver.isFuture(item):
			outcome.reasons = append(outcome.reasons, ReasonFutureObservation)
		case item.Confidence != expectedConfidence(itemType):
			outcome.reasons = append(outcome.reasons, ReasonMismatch)
		case item.Value == nil:
			outcome.reasons = append(outcome.reasons, ReasonRedacted)
		default:
			values = append(values, *item.Value)
			outcome.refs = append(outcome.refs, EvidenceReference{ItemIndex: index})
		}
	}
	if len(outcome.reasons) > 0 {
		outcome.reasons = orderReasons(outcome.reasons)
		outcome.refs = nil
		return outcome
	}
	for _, value := range values[1:] {
		if value != values[0] {
			outcome.reasons = []CheckReason{ReasonConflict}
			outcome.refs = nil
			return outcome
		}
	}
	if wanted != nil && values[0] != *wanted {
		// A row whose vulnerability differs from the target does not
		// substantiate it; columns of different rows are never joined.
		outcome.reasons = []CheckReason{ReasonMismatch}
		outcome.refs = nil
		return outcome
	}
	unique := values[0]
	outcome.satisfied = true
	outcome.value = &unique
	outcome.reasons = []CheckReason{ReasonVerified}
	outcome.refs = sortReferences(outcome.refs)
	return outcome
}

func (resolver *resolver) isFuture(item contract.EvidenceItem) bool {
	return item.ObservedAt != nil && item.ObservedAt.Time.After(resolver.evaluatedAt)
}

// uniqueImage returns the single image identity of the target class and name, or
// false when candidates diverge.
func (resolver *resolver) uniqueImage() (contract.ImageIdentity, bool) {
	first := resolver.bundle.Images[resolver.images[0]]
	for _, index := range resolver.images[1:] {
		if !sameImage(first, resolver.bundle.Images[index]) {
			return contract.ImageIdentity{}, false
		}
	}
	return first, true
}

func sameImage(a, b contract.ImageIdentity) bool {
	if a.ContainerClass != b.ContainerClass || a.ContainerName != b.ContainerName {
		return false
	}
	if !sameOptionalString(pointerString(a.RequestedImage), pointerString(b.RequestedImage)) {
		return false
	}
	if !sameOptionalString(pointerString(a.RawImageID), pointerString(b.RawImageID)) {
		return false
	}
	if !sameOptionalString(pointerString(a.NormalizedDigest), pointerString(b.NormalizedDigest)) {
		return false
	}
	if a.Platform != b.Platform {
		return false
	}
	return sameOptionalTime(a.ObservedAt, b.ObservedAt)
}

func pointerString[T ~string](value *T) *string {
	if value == nil {
		return nil
	}
	converted := string(*value)
	return &converted
}

func sameOptionalString(a, b *string) bool {
	switch {
	case a == nil && b == nil:
		return true
	case a == nil || b == nil:
		return false
	}
	return *a == *b
}

func sameOptionalTime(a, b *contract.Timestamp) bool {
	switch {
	case a == nil && b == nil:
		return true
	case a == nil || b == nil:
		return false
	}
	return a.Time.Equal(b.Time)
}

// observationIndices lists the observation items of the image instant in the
// target scope.
func (resolver *resolver) observationIndices(observedAt *contract.Timestamp) []int {
	indices := make([]int, 0, len(resolver.scopeItems))
	for _, index := range resolver.scopeItems {
		item := resolver.bundle.Evidence[index]
		switch item.Type {
		case TypeImageID, TypeNormalizedDigest, TypePlatformOS, TypePlatformArchitecture:
		default:
			continue
		}
		if observedAt == nil || item.ObservedAt == nil || !item.ObservedAt.Time.Equal(observedAt.Time) {
			continue
		}
		indices = append(indices, index)
	}
	return indices
}

// boundDigestOutcome resolves image.bound_digest: one image identity of the
// target class and name, a well-formed proven digest and observation items
// coherent with it and with its own instant.
func (resolver *resolver) boundDigestOutcome() requirementOutcome {
	candidates := len(resolver.scopeItems) + len(resolver.images)
	if resolver.classAmbiguous {
		return unknownOutcome(candidates, ReasonConflict)
	}
	if len(resolver.images) == 0 {
		return unknownOutcome(candidates, ReasonMissing)
	}
	image, unique := resolver.uniqueImage()
	if !unique {
		return unknownOutcome(candidates, ReasonConflict)
	}
	if image.NormalizedDigest == nil || image.RawImageID == nil || !isSha256(string(*image.NormalizedDigest)) {
		// A tag or a raw id without a proven digest never satisfies the
		// requirement.
		return unknownOutcome(candidates, ReasonMissing)
	}
	if image.ObservedAt == nil {
		return unknownOutcome(candidates, ReasonMissing)
	}
	indices := resolver.observationIndices(image.ObservedAt)
	if len(indices) == 0 {
		return unknownOutcome(candidates, ReasonMissing)
	}
	// A coherent observation shares one provenance tuple; divergent ones leave
	// the identity ambiguous.
	first := resolver.bundle.Evidence[indices[0]]
	var reasons []CheckReason
	var refs []EvidenceReference
	for _, index := range indices {
		item := resolver.bundle.Evidence[index]
		if item.Source != first.Source || item.SourceHash != first.SourceHash || item.Locator != first.Locator {
			reasons = append(reasons, ReasonConflict)
		}
		if !isSha256(string(item.SourceHash)) {
			reasons = append(reasons, ReasonMismatch)
		}
		if resolver.isFuture(item) {
			reasons = append(reasons, ReasonFutureObservation)
		}
	}
	// ADR-0013 §6 requires both observation items: a digest without its image id
	// is not a traceable identity, so absence is refused, never assumed.
	digestRefs, digestReasons := resolver.itemValues(indices, TypeNormalizedDigest, string(*image.NormalizedDigest), true)
	imageRefs, imageReasons := resolver.itemValues(indices, TypeImageID, string(*image.RawImageID), true)
	reasons = append(reasons, digestReasons...)
	reasons = append(reasons, imageReasons...)
	refs = append(digestRefs, imageRefs...)
	if len(reasons) > 0 {
		return requirementOutcome{satisfied: false, reasons: orderReasons(reasons), candidates: candidates}
	}
	return requirementOutcome{
		satisfied:  true,
		reasons:    []CheckReason{ReasonVerified},
		refs:       sortReferences(refs),
		candidates: candidates,
	}
}

// itemValues checks the items of one type inside an observation: presence,
// expected confidence, a present value equal to the accredited one and no future
// observation.
func (resolver *resolver) itemValues(indices []int, itemType, accredited string, missing bool) ([]EvidenceReference, []CheckReason) {
	var refs []EvidenceReference
	var reasons []CheckReason
	found := false
	for _, index := range indices {
		item := resolver.bundle.Evidence[index]
		if item.Type != itemType {
			continue
		}
		found = true
		// The frontier hash grammar of ADR-0013 §4.2 is enforced once, by the
		// coherence check of the caller over the whole observation group: a second
		// guard here would be redundant and no mutation could isolate it.
		switch {
		case resolver.isFuture(item):
			reasons = append(reasons, ReasonFutureObservation)
		case item.Confidence != expectedConfidence(itemType):
			reasons = append(reasons, ReasonMismatch)
		case item.Value == nil:
			reasons = append(reasons, ReasonRedacted)
		case *item.Value != accredited:
			reasons = append(reasons, ReasonMismatch)
		default:
			refs = append(refs, EvidenceReference{ItemIndex: index})
		}
	}
	if missing && !found {
		reasons = append(reasons, ReasonMissing)
	}
	return refs, reasons
}

// knownPlatformOutcome resolves image.known_platform: the bound digest plus both
// platform items coherent with the accredited platform.
func (resolver *resolver) knownPlatformOutcome() requirementOutcome {
	bound := resolver.boundDigestOutcome()
	if !bound.satisfied {
		return bound
	}
	image, unique := resolver.uniqueImage()
	if !unique {
		return unknownOutcome(bound.candidates, ReasonConflict)
	}
	candidates := bound.candidates
	if image.ObservedAt == nil || image.Platform.Status != contract.PlatformKnown {
		return unknownOutcome(candidates, ReasonMissing)
	}
	indices := resolver.observationIndices(image.ObservedAt)
	candidates += len(indices)
	osRefs, osReasons := resolver.itemValues(indices, TypePlatformOS, image.Platform.OS, true)
	archRefs, archReasons := resolver.itemValues(indices, TypePlatformArchitecture, image.Platform.Architecture, true)
	reasons := append(append([]CheckReason{}, osReasons...), archReasons...)
	if len(reasons) > 0 {
		return requirementOutcome{satisfied: false, reasons: orderReasons(reasons), candidates: candidates}
	}
	platform := image.Platform
	refs := append(append(append([]EvidenceReference{}, bound.refs...), osRefs...), archRefs...)
	return requirementOutcome{
		satisfied:  true,
		reasons:    []CheckReason{ReasonVerified},
		refs:       sortReferences(refs),
		candidates: candidates,
		platform:   &platform,
	}
}

func sortReferences(refs []EvidenceReference) []EvidenceReference {
	ordered := append([]EvidenceReference{}, refs...)
	sort.Slice(ordered, func(i, j int) bool { return ordered[i].ItemIndex < ordered[j].ItemIndex })
	return ordered
}

func orderReasons(reasons []CheckReason) []CheckReason {
	if len(reasons) == 0 {
		return nil
	}
	ordered := append([]CheckReason{}, reasons...)
	sort.Slice(ordered, func(i, j int) bool { return ordered[i] < ordered[j] })
	unique := ordered[:1]
	for _, reason := range ordered[1:] {
		if reason != unique[len(unique)-1] {
			unique = append(unique, reason)
		}
	}
	return unique
}
