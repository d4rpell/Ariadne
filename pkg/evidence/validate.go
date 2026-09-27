package evidence

import (
	"errors"
	"fmt"
	"math"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
)

type enumValue interface {
	Valid() bool
}

// SchemaVersionSupported is the schema version this contract reads and writes:
// the MAJOR.MINOR grammar of ADR-0006 §6, without leading zeros. A version with
// another major or a newer minor fails closed; there is no downgrade and no
// implicit migration. ADR-0016 §6.1 raised the supported minor to 2 while
// keeping the numeric comparison, so the known versions accepted before
// (0.0, 0.1) stay accepted and 0.3 is the first unsupported minor.
const SchemaVersionSupported = "0.2"

func requireNonEmpty(field, value string) error {
	if value == "" {
		return fmt.Errorf("evidence: %s is empty", field)
	}
	if strings.TrimSpace(value) != value {
		return fmt.Errorf("evidence: %s has surrounding whitespace", field)
	}
	if !utf8.ValidString(value) {
		return fmt.Errorf("evidence: %s is not valid UTF-8", field)
	}
	return nil
}

func requireValidUTF8(field, value string) error {
	if !utf8.ValidString(value) {
		return fmt.Errorf("evidence: %s is not valid UTF-8", field)
	}
	return nil
}

// requireText validates free text carried on the wire: it must carry content and
// be valid UTF-8, but it keeps its whitespace because the bytes are hashed as
// written. Identifiers and paths keep the stricter rule of requireNonEmpty.
func requireText(field, value string) error {
	if strings.TrimSpace(value) == "" {
		return fmt.Errorf("evidence: %s is empty", field)
	}
	return requireValidUTF8(field, value)
}

func parseRequired(field, value string) (string, error) {
	if err := requireNonEmpty(field, value); err != nil {
		return "", err
	}
	return value, nil
}

func validateEnum[T enumValue](field string, value T) error {
	if !value.Valid() {
		return fmt.Errorf("evidence: %s is not a known value", field)
	}
	return nil
}

// requireCollection enforces the wire rule that contractual collections are
// arrays: a nil Go slice is invalid and is never collapsed into [].
func requireCollection[T any](field string, values []T) error {
	if values == nil {
		return fmt.Errorf("evidence: %s must be an array, never null", field)
	}
	return nil
}

func validateTimestamp(field string, value Timestamp) error {
	if value.IsZero() {
		return fmt.Errorf("evidence: %s is zero", field)
	}
	if value.Location() != time.UTC {
		return fmt.Errorf("evidence: %s is not in canonical UTC", field)
	}
	return nil
}

func validateOptionalString(field string, value *string) error {
	if value == nil {
		return nil
	}
	return requireNonEmpty(field, *value)
}

func ValidateSchemaVersion(value string) error {
	if err := requireNonEmpty("schema_version", value); err != nil {
		return err
	}
	major, minor, err := parseSchemaVersion(value)
	if err != nil {
		return err
	}
	supportedMajor, supportedMinor, err := parseSchemaVersion(SchemaVersionSupported)
	if err != nil {
		return err
	}
	if major != supportedMajor {
		return fmt.Errorf("evidence: schema_version major %d is not supported", major)
	}
	if minor > supportedMinor {
		return fmt.Errorf("evidence: schema_version %s is newer than the supported %s", value, SchemaVersionSupported)
	}
	return nil
}

func parseSchemaVersion(value string) (uint64, uint64, error) {
	parts := strings.Split(value, ".")
	if len(parts) != 2 {
		return 0, 0, fmt.Errorf("evidence: schema_version %q is not MAJOR.MINOR", value)
	}
	major, err := parseVersionNumber("schema_version major", parts[0])
	if err != nil {
		return 0, 0, err
	}
	minor, err := parseVersionNumber("schema_version minor", parts[1])
	if err != nil {
		return 0, 0, err
	}
	return major, minor, nil
}

func parseVersionNumber(field, digits string) (uint64, error) {
	if digits == "" {
		return 0, fmt.Errorf("evidence: %s is empty", field)
	}
	for index := 0; index < len(digits); index++ {
		if digits[index] < '0' || digits[index] > '9' {
			return 0, fmt.Errorf("evidence: %s is not a decimal number", field)
		}
	}
	if len(digits) > 1 && digits[0] == '0' {
		return 0, fmt.Errorf("evidence: %s has a leading zero", field)
	}
	number, err := strconv.ParseUint(digits, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("evidence: %s is out of range", field)
	}
	return number, nil
}

func ValidateBundle(bundle Bundle) error {
	if err := ValidateSchemaVersion(bundle.SchemaVersion); err != nil {
		return err
	}
	if err := validateSubject(bundle.Subject); err != nil {
		return err
	}
	if err := requireCollection("images", bundle.Images); err != nil {
		return err
	}
	for index, image := range bundle.Images {
		if err := validateImageIdentity(image); err != nil {
			return fmt.Errorf("images[%d]: %w", index, err)
		}
	}
	if err := requireCollection("evidence", bundle.Evidence); err != nil {
		return err
	}
	for index, item := range bundle.Evidence {
		if err := ValidateEvidenceItem(item, bundle.Subject); err != nil {
			return fmt.Errorf("evidence[%d]: %w", index, err)
		}
	}
	if err := requireCollection("observed_container_classes", bundle.ObservedContainerClasses); err != nil {
		return err
	}
	if err := validateRunProvenance(bundle.Provenance); err != nil {
		return err
	}
	return validateCoverageScope(bundle)
}

func validateSubject(subject Subject) error {
	if err := requireNonEmpty("subject.cluster_alias", string(subject.ClusterAlias)); err != nil {
		return err
	}
	if err := requireNonEmpty("subject.namespace", string(subject.Namespace)); err != nil {
		return err
	}
	if err := requireNonEmpty("subject.kind", subject.Kind); err != nil {
		return err
	}
	if err := requireNonEmpty("subject.name", subject.Name); err != nil {
		return err
	}
	if err := requireNonEmpty("subject.uid", string(subject.UID)); err != nil {
		return err
	}
	if subject.OwnerChain != "" {
		if err := requireNonEmpty("subject.owner_chain", string(subject.OwnerChain)); err != nil {
			return err
		}
	}
	return nil
}

func validateImageIdentity(image ImageIdentity) error {
	if err := validateEnum("container_class", image.ContainerClass); err != nil {
		return err
	}
	if err := requireNonEmpty("container_name", string(image.ContainerName)); err != nil {
		return err
	}
	if err := validateOptionalString("requested_image", pointerString(image.RequestedImage)); err != nil {
		return err
	}
	if err := validateOptionalString("raw_image_id", pointerString(image.RawImageID)); err != nil {
		return err
	}
	if err := validateOptionalString("normalized_digest", pointerString(image.NormalizedDigest)); err != nil {
		return err
	}
	if err := validateEnum("platform.status", image.Platform.Status); err != nil {
		return err
	}
	if image.Platform.Status == PlatformKnown {
		if err := requireNonEmpty("platform.os", image.Platform.OS); err != nil {
			return err
		}
		if err := requireNonEmpty("platform.architecture", image.Platform.Architecture); err != nil {
			return err
		}
	} else if image.Platform.OS != "" || image.Platform.Architecture != "" {
		// The wire can only emit null here, so an observed value would be lost.
		return errors.New("evidence: platform unknown cannot carry an observed os or architecture")
	}
	if image.NormalizedDigest == nil && image.Platform.Status == PlatformKnown {
		return errors.New("evidence: platform.status known requires a normalized_digest proven by the parser")
	}
	if image.ObservedAt != nil {
		if err := validateTimestamp("observed_at", *image.ObservedAt); err != nil {
			return err
		}
	}
	return nil
}

func ValidateEvidenceItem(item EvidenceItem, subject Subject) error {
	if err := requireNonEmpty("evidence.type", item.Type); err != nil {
		return err
	}
	if err := requireNonEmpty("evidence.source", item.Source); err != nil {
		return err
	}
	if err := requireNonEmpty("evidence.source_hash", string(item.SourceHash)); err != nil {
		return err
	}
	if err := requireNonEmpty("evidence.locator", string(item.Locator)); err != nil {
		return err
	}
	if err := validateEnum("evidence.confidence", item.Confidence); err != nil {
		return err
	}
	if err := validateOptionalString("evidence.value", item.Value); err != nil {
		return err
	}
	if item.ValueHash != nil {
		if err := requireNonEmpty("evidence.value_hash", string(*item.ValueHash)); err != nil {
			return err
		}
	}
	if item.Value != nil && item.ValueHash == nil {
		return errors.New("evidence: evidence.value requires evidence.value_hash")
	}
	if err := requireCollection("evidence.warnings", item.Warnings); err != nil {
		return err
	}
	for index, warning := range item.Warnings {
		if err := validateWarning(fmt.Sprintf("evidence.warnings[%d]", index), warning); err != nil {
			return err
		}
	}
	if item.ObservedAt == nil {
		return errors.New("evidence: evidence.observed_at is required")
	}
	if err := validateTimestamp("evidence.observed_at", *item.ObservedAt); err != nil {
		return err
	}
	if err := requireNonEmpty("scope.subject_uid", string(item.Scope.SubjectUID)); err != nil {
		return err
	}
	if err := requireNonEmpty("scope.container_name", string(item.Scope.ContainerName)); err != nil {
		return err
	}
	// Container affinity cannot be checked here: an item only knows its own
	// container. Callers that know the container of a conclusion must call
	// ValidateScope with it.
	if item.Scope.SubjectUID != subject.UID {
		return errors.New("evidence: scope subject uid does not match the subject")
	}
	return nil
}

func validateWarning(field string, warning Warning) error {
	if err := requireNonEmpty(field+".code", warning.Code); err != nil {
		return err
	}
	if err := validateEnum(field+".class", warning.Class); err != nil {
		return err
	}
	return requireText(field+".message", warning.Message)
}

func ValidateScope(scope Scope, subjectUID UID, containerName ContainerName) error {
	if err := requireNonEmpty("scope.subject_uid", string(subjectUID)); err != nil {
		return err
	}
	if err := requireNonEmpty("scope.container_name", string(containerName)); err != nil {
		return err
	}
	if scope.SubjectUID != subjectUID {
		return errors.New("evidence: scope subject uid does not match the subject")
	}
	if scope.ContainerName != containerName {
		return errors.New("evidence: scope container name does not match the container")
	}
	return nil
}

func validateRunProvenance(provenance RunProvenance) error {
	if err := validateEnum("provenance.completeness", provenance.Completeness); err != nil {
		return err
	}
	if err := validateEnum("provenance.consistency", provenance.Consistency); err != nil {
		return err
	}
	if err := requireNonEmpty("provenance.collector_version", provenance.CollectorVersion); err != nil {
		return err
	}
	if err := requireNonEmpty("provenance.parser_version", provenance.ParserVersion); err != nil {
		return err
	}
	if err := requireNonEmpty("provenance.redaction_policy", provenance.RedactionPolicy); err != nil {
		return err
	}
	if err := requireCollection("provenance.argv_sanitized", provenance.ArgvSanitized); err != nil {
		return err
	}
	for index, argument := range provenance.ArgvSanitized {
		if err := requireValidUTF8(fmt.Sprintf("provenance.argv_sanitized[%d]", index), argument); err != nil {
			return err
		}
	}
	if err := requireCollection("provenance.inputs", provenance.Inputs); err != nil {
		return err
	}
	for index, input := range provenance.Inputs {
		if err := requireNonEmpty(fmt.Sprintf("provenance.inputs[%d].path", index), input.Path); err != nil {
			return err
		}
		if err := requireNonEmpty(fmt.Sprintf("provenance.inputs[%d].hash", index), string(input.Hash)); err != nil {
			return err
		}
	}
	if provenance.Ruleset != (RulesetRef{}) {
		if err := requireNonEmpty("provenance.ruleset.path", provenance.Ruleset.Path); err != nil {
			return err
		}
		if err := requireNonEmpty("provenance.ruleset.hash", string(provenance.Ruleset.Hash)); err != nil {
			return err
		}
		if err := requireNonEmpty("provenance.ruleset.version", provenance.Ruleset.Version); err != nil {
			return err
		}
	}
	if err := requireCollection("provenance.api_scope.namespaces", provenance.APIScope.Namespaces); err != nil {
		return err
	}
	for index, namespace := range provenance.APIScope.Namespaces {
		if err := requireNonEmpty(fmt.Sprintf("provenance.api_scope.namespaces[%d]", index), string(namespace)); err != nil {
			return err
		}
	}
	if err := requireCollection("provenance.api_scope.verbs", provenance.APIScope.Verbs); err != nil {
		return err
	}
	for index, verb := range provenance.APIScope.Verbs {
		if err := requireNonEmpty(fmt.Sprintf("provenance.api_scope.verbs[%d]", index), verb); err != nil {
			return err
		}
	}
	if err := requireCollection("provenance.api_scope.resources", provenance.APIScope.Resources); err != nil {
		return err
	}
	for index, resource := range provenance.APIScope.Resources {
		if err := requireNonEmpty(fmt.Sprintf("provenance.api_scope.resources[%d]", index), resource); err != nil {
			return err
		}
	}
	if provenance.StartedAt != nil {
		if err := validateTimestamp("provenance.started_at", *provenance.StartedAt); err != nil {
			return err
		}
	}
	if provenance.EndedAt != nil {
		if err := validateTimestamp("provenance.ended_at", *provenance.EndedAt); err != nil {
			return err
		}
	}
	if provenance.StartedAt != nil && provenance.EndedAt != nil && provenance.StartedAt.After(provenance.EndedAt.Time) {
		return errors.New("evidence: provenance.started_at is after provenance.ended_at")
	}
	if err := requireValidUTF8("provenance.budget.wall_clock", provenance.Budget.WallClock); err != nil {
		return err
	}
	if err := requireCollection("provenance.warnings", provenance.Warnings); err != nil {
		return err
	}
	for index, warning := range provenance.Warnings {
		if err := validateWarning(fmt.Sprintf("provenance.warnings[%d]", index), warning); err != nil {
			return err
		}
	}
	if err := requireCollection("provenance.errors", provenance.Errors); err != nil {
		return err
	}
	for index, message := range provenance.Errors {
		if err := requireText(fmt.Sprintf("provenance.errors[%d]", index), message); err != nil {
			return err
		}
	}
	if err := validateCoverage(provenance.Coverage, provenance.Completeness, provenance.Errors); err != nil {
		return err
	}
	if provenance.Completeness != CompletenessComplete && len(provenance.Errors) == 0 {
		return errors.New("evidence: incomplete provenance requires visible errors")
	}
	return nil
}

// validateCoverage applies the per-method completeness rules of ADR-0006 §7(a).
func validateCoverage(coverage Coverage, completeness Completeness, messages []string) error {
	if err := validateEnum("provenance.coverage.method", coverage.Method); err != nil {
		return err
	}
	if err := validateEnum("provenance.coverage.termination", coverage.Termination); err != nil {
		return err
	}
	if coverage.Termination == TerminationUnknown && completeness != CompletenessUnknown {
		return errors.New("evidence: coverage termination unknown requires completeness unknown")
	}
	switch coverage.Method {
	case CoverageContainerObservation:
		if coverage.Rows != nil {
			return errors.New("evidence: a container observation declares coverage rows as null")
		}
	case CoverageFindingsImport:
		if coverage.Rows == nil {
			return errors.New("evidence: a findings import requires a coverage rows object")
		}
		rows := coverage.Rows
		if rows.Accepted > math.MaxUint64-rows.Rejected {
			return errors.New("evidence: coverage accepted plus rejected overflows")
		}
		counted := rows.Accepted + rows.Rejected
		if rows.Total != nil && counted > *rows.Total {
			return errors.New("evidence: coverage accepted plus rejected exceeds the total")
		}
		if coverage.Termination == TerminationFinished {
			if rows.Total == nil {
				return errors.New("evidence: a finished import requires a known coverage total")
			}
			if counted != *rows.Total {
				return errors.New("evidence: a finished import requires accepted plus rejected to equal the total")
			}
		}
	}
	if completeness == CompletenessComplete {
		if coverage.Termination != TerminationFinished {
			return errors.New("evidence: complete coverage requires a finished run")
		}
		if len(messages) != 0 {
			return errors.New("evidence: complete coverage requires no visible errors")
		}
		if coverage.Method == CoverageFindingsImport {
			rows := coverage.Rows
			if rows == nil || rows.Rejected != 0 || rows.Total == nil || rows.Accepted != *rows.Total {
				return errors.New("evidence: a complete import requires every row accepted")
			}
		}
	}
	return nil
}

// validateCoverageScope cross-checks coverage, observed classes, images and the
// API scope, which no single section can decide on its own.
func validateCoverageScope(bundle Bundle) error {
	observed := make(map[ContainerClass]struct{}, len(bundle.ObservedContainerClasses))
	for index, class := range bundle.ObservedContainerClasses {
		if err := validateEnum(fmt.Sprintf("observed_container_classes[%d]", index), class); err != nil {
			return err
		}
		if _, duplicate := observed[class]; duplicate {
			return fmt.Errorf("evidence: observed_container_classes[%d] duplicates %s", index, class)
		}
		observed[class] = struct{}{}
	}
	switch bundle.Provenance.Coverage.Method {
	case CoverageFindingsImport:
		if len(bundle.ObservedContainerClasses) != 0 {
			return errors.New("evidence: a findings import cannot declare observed container classes")
		}
		if len(bundle.Provenance.Inputs) != 1 {
			return errors.New("evidence: a findings import requires exactly one input")
		}
		if len(bundle.Provenance.APIScope.Namespaces) != 0 || len(bundle.Provenance.APIScope.Verbs) != 0 || len(bundle.Provenance.APIScope.Resources) != 0 {
			return errors.New("evidence: a findings import has no container API scope")
		}
	case CoverageContainerObservation:
		for index, image := range bundle.Images {
			if _, ok := observed[image.ContainerClass]; !ok {
				return fmt.Errorf("evidence: images[%d] belongs to a container class that was not observed", index)
			}
		}
		if bundle.Provenance.Completeness == CompletenessComplete {
			for _, required := range []ContainerClass{ContainerEphemeral, ContainerInit, ContainerRegular} {
				if _, ok := observed[required]; !ok {
					return fmt.Errorf("evidence: a complete observation requires the %s container class", required)
				}
			}
		}
	}
	// ADR-0006 §7(a): an abort is partial when progress is verifiable and unknown
	// when coverage cannot be established. Only "never complete" was enforced by
	// validateCoverage; the positive branch needs the bundle.
	if bundle.Provenance.Coverage.Termination == TerminationAborted {
		progress := coverageProgress(bundle)
		switch {
		case progress && bundle.Provenance.Completeness != CompletenessPartial:
			return errors.New("evidence: an aborted run with verifiable progress must be partial")
		case !progress && bundle.Provenance.Completeness != CompletenessUnknown:
			return errors.New("evidence: an aborted run without verifiable progress must be unknown")
		}
	}
	return nil
}

// coverageProgress reports whether an aborted run left verifiable progress: rows
// counted or a known file extent for an import, observed classes or inventoried
// images for a container observation.
func coverageProgress(bundle Bundle) bool {
	if bundle.Provenance.Coverage.Method == CoverageFindingsImport {
		rows := bundle.Provenance.Coverage.Rows
		if rows == nil {
			return false
		}
		return rows.Accepted+rows.Rejected > 0 || rows.Total != nil
	}
	return len(bundle.ObservedContainerClasses) > 0 || len(bundle.Images) > 0
}

func pointerString[T ~string](value *T) *string {
	if value == nil {
		return nil
	}
	converted := string(*value)
	return &converted
}
