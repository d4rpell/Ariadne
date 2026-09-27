package evaluator

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"

	bundle "github.com/d4rpell/Ariadne/internal/bundle"
	canonical "github.com/d4rpell/Ariadne/internal/evidence"
	"github.com/d4rpell/Ariadne/internal/ingest"
	"github.com/d4rpell/Ariadne/internal/normalize"
	"github.com/d4rpell/Ariadne/internal/rulepack"
	contract "github.com/d4rpell/Ariadne/pkg/evidence"
)

// The committed fixtures of F4b are entirely synthetic: identifiers, hashes,
// timestamps, packages and advisories are fabricated. No real cluster, customer
// or vendor data is used, and no source document carries authority beyond what
// the bundle itself declares.

const fixturesRoot = "../../fixtures"

type fixtureCandidate struct {
	RuleID        string `json:"rule_id"`
	ProductStatus string `json:"product_status"`
}

type fixtureCheck struct {
	CheckID string   `json:"check_id"`
	Outcome string   `json:"outcome"`
	Reasons []string `json:"reasons"`
}

type fixtureRule struct {
	RuleID              string         `json:"rule_id"`
	State               string         `json:"state"`
	MissingRequirements []string       `json:"missing_requirements"`
	Checks              []fixtureCheck `json:"checks"`
}

type fixtureExpectations struct {
	Profile           string             `json:"profile"`
	ProductStatus     string             `json:"product_status"`
	Exploitability    string             `json:"exploitability"`
	Reasons           []string           `json:"reasons"`
	Candidates        []fixtureCandidate `json:"candidates"`
	Rules             []fixtureRule      `json:"rules"`
	WarningReferences int                `json:"warning_references"`
}

type fixtureTarget struct {
	SubjectUID      string `json:"subject_uid"`
	ContainerClass  string `json:"container_class"`
	ContainerName   string `json:"container_name"`
	VulnerabilityID string `json:"vulnerability_id"`
	Source          string `json:"source"`
	SourceHash      string `json:"source_hash"`
	Locator         string `json:"locator"`
	ObservedAt      string `json:"observed_at"`
}

type fixtureAdmission struct {
	EvaluatedAt      string `json:"evaluated_at"`
	ExpectedPackID   string `json:"expected_pack_id"`
	ExpectedPackHash string `json:"expected_pack_hash"`
	MinimumVersion   int64  `json:"minimum_version"`
}

type fixturePin struct {
	Role             string  `json:"role"`
	Source           string  `json:"source"`
	SourceHash       string  `json:"source_hash"`
	AdvisoryID       *string `json:"advisory_id"`
	AdvisoryRevision *string `json:"advisory_revision"`
}

type fixtureDomainContext struct {
	MaximumEvidenceAgeSeconds int64        `json:"maximum_evidence_age_seconds"`
	SourcePins                []fixturePin `json:"source_pins"`
}

type fixtureFiles struct {
	bundle       contract.Bundle
	request      Request
	expectations fixtureExpectations
}

func readFixtureFile(t *testing.T, path string) []byte {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("fixture file %s: %v", path, err)
	}
	return data
}

// assertSourcesSupportBundle fails the test on the first source-support
// violation of the fixture.
func assertSourcesSupportBundle(t *testing.T, input string, source contract.Bundle) {
	t.Helper()
	if err := sourcesSupportBundle(input, source); err != nil {
		t.Fatal(err)
	}
}

// sourcesSupportBundle verifies that every evidence item is actually supported
// by the transcription it names: the source file exists, its SHA-256 is the
// item's source_hash, and the exact field the item attributes carries that value
// inside the record its locator resolves to. A substring search over the whole
// document would accept a fact the named record does not state, so the contrast
// is always resolved: CSV records through the production parser, JSON documents
// through the item locator. Fail-closed: an unknown item type or an unresolvable
// locator is an error, never a pass.
func sourcesSupportBundle(input string, source contract.Bundle) error {
	cache := map[string][]byte{}
	parsed := map[string]ingest.Result{}
	document := func(name string) ([]byte, error) {
		if cached, ok := cache[name]; ok {
			return cached, nil
		}
		body, err := os.ReadFile(filepath.Join(input, name))
		if err != nil {
			return nil, fmt.Errorf("fixture file %s: %w", filepath.Join(input, name), err)
		}
		cache[name] = body
		return body, nil
	}
	// The CSV transcription is read by the parser the ingest path uses, so the
	// contrast is anchored to the production reading of the source and the
	// locator must be the absolute stream interval of ADR-0008, never a
	// record-relative range.
	findings := func(name string) (ingest.Result, error) {
		if cached, ok := parsed[name]; ok {
			return cached, nil
		}
		body, err := document(name)
		if err != nil {
			return ingest.Result{}, err
		}
		result, err := ingest.ParsePrismaV1(bytes.NewReader(body))
		if err != nil {
			return ingest.Result{}, fmt.Errorf("fixture CSV %s does not parse: %w", name, err)
		}
		if len(result.Rejections) != 0 {
			return ingest.Result{}, fmt.Errorf("fixture CSV %s carries rejected records: %v", name, result.Rejections)
		}
		parsed[name] = result
		return result, nil
	}
	checked := 0
	for _, evidence := range source.Evidence {
		body, err := document(evidence.Source)
		if err != nil {
			return err
		}
		// The digest is computed by the producer's own hash function, so the
		// preimage of ADR-0012 is not reimplemented here.
		if want := string(bundle.HashSource(body)); string(evidence.SourceHash) != want {
			return fmt.Errorf("%s: source_hash %s does not match the file digest %s", evidence.Type, evidence.SourceHash, want)
		}
		// The item type and the source kind must agree: a prisma-v1 item reads a
		// CSV record, and a domain or observation item reads a JSON transcription.
		if strings.HasPrefix(evidence.Type, "prisma_v1.") != strings.HasSuffix(evidence.Source, ".csv") {
			return fmt.Errorf("%s: source %s is not the transcription kind this item type names", evidence.Type, evidence.Source)
		}
		var stated string
		if strings.HasSuffix(evidence.Source, ".csv") {
			result, err := findings(evidence.Source)
			if err != nil {
				return err
			}
			finding, err := csvFinding(result, string(evidence.Locator))
			if err != nil {
				return err
			}
			stated, err = statedPrismaField(finding, evidence.Type)
			if err != nil {
				return err
			}
		} else {
			steps, err := locatorSteps(string(evidence.Locator))
			if err != nil {
				return fmt.Errorf("%s: locator %q: %w", evidence.Type, evidence.Locator, err)
			}
			stated, err = statedJSONField(body, steps, evidence)
			if err != nil {
				return err
			}
		}
		if evidence.Value != nil && *evidence.Value != stated {
			return fmt.Errorf("%s = %q but the transcription states %q", evidence.Type, *evidence.Value, stated)
		}
		// An item may legitimately carry no value — the producer keeps a value the
		// wire cannot carry verbatim auditable by hash only (ADR-0012) — so the
		// preimage is contrasted against the transcription whenever a hash is
		// present, never only when a value is.
		if evidence.ValueHash != nil {
			if want := bundle.HashValue(stated); *evidence.ValueHash != want {
				return fmt.Errorf("%s: value_hash %s is not the digest %s of the transcription value %q", evidence.Type, *evidence.ValueHash, want, stated)
			}
		}
		if evidence.Value != nil || evidence.ValueHash != nil {
			checked++
		}
	}
	if checked == 0 {
		return errors.New("the fixture carries no value or value hash to check against its sources")
	}
	return nil
}

// csvFinding returns the parsed record the locator names and requires the
// locator to be exactly the absolute stream interval the parser reports for it
// (ADR-0008): a range relative to the record would identify the wrong bytes.
func csvFinding(result ingest.Result, locator string) (ingest.Finding, error) {
	parts := strings.Split(locator, "/")
	if len(parts) != 4 || parts[0] != "record" || parts[2] != "bytes" {
		return ingest.Finding{}, fmt.Errorf("locator %q is not a canonical record locator", locator)
	}
	ordinal, err := strconv.Atoi(parts[1])
	if err != nil {
		return ingest.Finding{}, fmt.Errorf("locator %q: %w", locator, err)
	}
	if ordinal < 1 || ordinal > len(result.Findings) {
		return ingest.Finding{}, fmt.Errorf("locator %q names a record outside the file", locator)
	}
	finding := result.Findings[ordinal-1]
	if reported := finding.Locator.String(); reported != locator {
		return ingest.Finding{}, fmt.Errorf("locator %q is not the absolute interval %s the parser reports for this record", locator, reported)
	}
	return finding, nil
}

// statedPrismaField returns the exact string the parsed record states for a
// prisma-v1 item. The fifteen declared columns of ADR-0007 are the vocabulary
// the producer projects (internal/bundle, TestBuildMapsEveryDeclaredColumn);
// requested_image is the one derived value and is composed by the production
// function, so the ADR-0009 grammar is enforced rather than imitated.
func statedPrismaField(finding ingest.Finding, itemType string) (string, error) {
	field, ok := strings.CutPrefix(itemType, "prisma_v1.")
	if !ok {
		return "", fmt.Errorf("item type %s is not a prisma-v1 record field", itemType)
	}
	if field == "requested_image" {
		composed, err := normalize.RequestedImage(normalize.DeclaredImage{
			Registry:   finding.ImageRegistry,
			Repository: finding.ImageRepository,
			Tag:        finding.ImageTag,
		})
		if err != nil {
			return "", fmt.Errorf("%s cannot be composed from the record columns: %w", itemType, err)
		}
		return string(composed), nil
	}
	stated, ok := prismaRecordFields[field]
	if !ok {
		return "", fmt.Errorf("item type %s matches no declared prisma-v1 column", itemType)
	}
	return stated(finding), nil
}

// prismaRecordFields maps an item type suffix to the parsed field it must equal.
// The names are exactly the canonical column names of ADR-0007 and the fifteen
// the producer projects.
var prismaRecordFields = map[string]func(ingest.Finding) string{
	"schema_version":    func(f ingest.Finding) string { return f.SchemaVersion },
	"vulnerability_id":  func(f ingest.Finding) string { return f.VulnerabilityID },
	"package_name":      func(f ingest.Finding) string { return f.PackageName },
	"installed_version": func(f ingest.Finding) string { return f.InstalledVersion },
	"fix_status":        func(f ingest.Finding) string { return f.FixStatus },
	"image_registry":    func(f ingest.Finding) string { return f.ImageRegistry },
	"image_repository":  func(f ingest.Finding) string { return f.ImageRepository },
	"image_tag":         func(f ingest.Finding) string { return f.ImageTag },
	"package_type":      func(f ingest.Finding) string { return f.PackageType },
	"package_id":        func(f ingest.Finding) string { return f.PackageID },
	"path":              func(f ingest.Finding) string { return f.Path },
	"severity":          func(f ingest.Finding) string { return f.Severity },
	"description":       func(f ingest.Finding) string { return f.Description },
	"published_date":    func(f ingest.Finding) string { return f.PublishedDate },
	"discovery_date":    func(f ingest.Finding) string { return f.DiscoveryDate },
}

// statedJSONField returns the exact string the JSON transcription states for an
// item, after validating that the locator is the carrier the item type declares.
// A locator that resolves to some other member, or to a nested object inside the
// named record, is rejected even when its value would match: the field and the
// structure are part of what the item attributes.
func statedJSONField(body []byte, steps []locatorStep, evidence contract.EvidenceItem) (string, error) {
	switch evidence.Type {
	case "container_status.image_id", "container_status.normalized_digest",
		"container_status.platform.os", "container_status.platform.architecture":
		status, imageID, err := containerStatusRecord(body, steps, evidence)
		if err != nil {
			return "", err
		}
		switch evidence.Type {
		case "container_status.image_id":
			return imageID, nil
		case "container_status.normalized_digest":
			// The normalized digest is derived: it is the digest component of the
			// observed image id, never an independent claim.
			at := strings.LastIndex(imageID, "@")
			if at < 0 {
				return "", fmt.Errorf("%s: the observed image id %q carries no digest component", evidence.Type, imageID)
			}
			return imageID[at+1:], nil
		default:
			platform, ok := status["platform"].(map[string]any)
			if !ok {
				return "", fmt.Errorf("%s: the container status carries no platform block", evidence.Type)
			}
			field := strings.TrimPrefix(evidence.Type, "container_status.platform.")
			stated, ok := platform[field].(string)
			if !ok {
				return "", fmt.Errorf("%s: the platform block states %v", evidence.Type, platform[field])
			}
			return stated, nil
		}
	default:
		collection, err := productRecordCollection(evidence.Type)
		if err != nil {
			return "", err
		}
		if len(steps) != 3 || steps[0].member != "records" || steps[1].member != collection || steps[2].index < 0 {
			return "", fmt.Errorf("%s: locator %q is not a direct element of the %s collection", evidence.Type, evidence.Locator, collection)
		}
		// The canonical string is required too: a variant that resolves to the
		// same node through another separator is not the locator the producer
		// writes, and accepting it would widen the format silently.
		if want := fmt.Sprintf("records/%s/%d", collection, steps[2].index); string(evidence.Locator) != want {
			return "", fmt.Errorf("%s: locator %q is not the canonical form %q", evidence.Type, evidence.Locator, want)
		}
		node, err := resolveSteps(body, steps)
		if err != nil {
			return "", fmt.Errorf("%s: locator %q does not resolve in the transcription: %w", evidence.Type, evidence.Locator, err)
		}
		record, ok := node.(map[string]any)
		if !ok {
			return "", fmt.Errorf("%s: locator %q does not resolve to a transcription record", evidence.Type, evidence.Locator)
		}
		field := evidence.Type[strings.LastIndex(evidence.Type, ".")+1:]
		stated, ok := record[field].(string)
		if !ok {
			return "", fmt.Errorf("%s: the record states %v, not a string", evidence.Type, record[field])
		}
		// A proof may not cite a basis that does not exist, that supports another
		// vulnerability or that is the proof itself.
		if field == "basis_locator" {
			if err := assertSupportDefinition(body, record, stated); err != nil {
				return "", err
			}
		}
		return stated, nil
	}
}

// containerStatusRecord validates the canonical observation path
// items[N].status.containerStatuses[M].imageID and returns the container status
// object together with the observed image id. A locator that names any other
// member is not the declared carrier of the observation facts.
func containerStatusRecord(body []byte, steps []locatorStep, evidence contract.EvidenceItem) (map[string]any, string, error) {
	if len(steps) != 6 ||
		steps[0].member != "items" || steps[1].index < 0 ||
		steps[2].member != "status" || steps[3].member != "containerStatuses" || steps[4].index < 0 ||
		steps[5].member != "imageID" {
		return nil, "", fmt.Errorf("%s: locator %q does not name items[N].status.containerStatuses[M].imageID", evidence.Type, evidence.Locator)
	}
	// The canonical string is required too: a variant that resolves to the same
	// node through another separator is not the locator the collector writes.
	if want := fmt.Sprintf("items[%d].status.containerStatuses[%d].imageID", steps[1].index, steps[4].index); string(evidence.Locator) != want {
		return nil, "", fmt.Errorf("%s: locator %q is not the canonical form %q", evidence.Type, evidence.Locator, want)
	}
	status, err := resolveSteps(body, steps[:5])
	if err != nil {
		return nil, "", fmt.Errorf("%s: locator %q does not resolve in the transcription: %w", evidence.Type, evidence.Locator, err)
	}
	record, ok := status.(map[string]any)
	if !ok {
		return nil, "", fmt.Errorf("%s: locator %q does not resolve to a container status", evidence.Type, evidence.Locator)
	}
	node, err := resolveSteps(body, steps)
	if err != nil {
		return nil, "", fmt.Errorf("%s: locator %q does not resolve in the transcription: %w", evidence.Type, evidence.Locator, err)
	}
	imageID, ok := node.(string)
	if !ok {
		return nil, "", fmt.Errorf("%s: the observed image id is %v, not a string", evidence.Type, node)
	}
	return record, imageID, nil
}

// productRecordCollection maps a product item type to the record collection its
// locator must name. Vendor proofs live in the proof collection: the type names
// the concept, the transcription names the record set.
func productRecordCollection(itemType string) (string, error) {
	rest, ok := strings.CutPrefix(itemType, "product_v1.")
	if !ok {
		return "", fmt.Errorf("item type %s is not a product transcription item", itemType)
	}
	family, _, _ := strings.Cut(rest, ".")
	switch family {
	case "mapping":
		return "mapping", nil
	case "artifact":
		return "artifact", nil
	case "vendor":
		return "proof", nil
	default:
		return "", fmt.Errorf("item type %s names no product transcription family", itemType)
	}
}

// assertSupportDefinition resolves the support definition a proof record cites
// and requires it to be identified as a definition — it lives in the
// definitions collection and carries the support member — and to agree with the
// record on the basis identifier and the supported vulnerability. A proof
// record cannot be its own definition: that would make the contrast a
// tautology.
func assertSupportDefinition(body []byte, record map[string]any, supportLocator string) error {
	steps, err := locatorSteps(supportLocator)
	if err != nil {
		return fmt.Errorf("basis_locator %q: %w", supportLocator, err)
	}
	if len(steps) != 3 || steps[0].member != "definitions" || steps[1].index < 0 || steps[2].member != "support" {
		return fmt.Errorf("basis_locator %q does not name a support definition of the definitions collection", supportLocator)
	}
	node, err := resolveSteps(body, steps)
	if err != nil {
		return fmt.Errorf("basis_locator %q does not resolve in the transcription: %w", supportLocator, err)
	}
	support, ok := node.(map[string]any)
	if !ok {
		return fmt.Errorf("basis_locator %q does not resolve to a support definition", supportLocator)
	}
	if _, self := support["proof_kind"]; self {
		return fmt.Errorf("basis_locator %q resolves to a proof record: a proof cannot be its own basis", supportLocator)
	}
	statedBasis, statedOK := support["basis_id"].(string)
	citedBasis, citedOK := record["basis_id"].(string)
	if !statedOK || !citedOK || statedBasis != citedBasis {
		return fmt.Errorf("support definition %q states basis_id %v, the record cites %v", supportLocator, support["basis_id"], record["basis_id"])
	}
	statedVulnerability, statedOK := support["vulnerability_id"].(string)
	citedVulnerability, citedOK := record["vulnerability_id"].(string)
	if !statedOK || !citedOK || statedVulnerability != citedVulnerability {
		return fmt.Errorf("support definition %q supports %v, the record cites %v", supportLocator, support["vulnerability_id"], record["vulnerability_id"])
	}
	return nil
}

// resolveSteps walks a decoded document along the locator steps.
func resolveSteps(body []byte, steps []locatorStep) (any, error) {
	var current any
	if err := json.Unmarshal(body, &current); err != nil {
		return nil, err
	}
	for _, step := range steps {
		if step.index >= 0 {
			array, ok := current.([]any)
			if !ok {
				return nil, fmt.Errorf("cannot index %T at [%d]", current, step.index)
			}
			if step.index >= len(array) {
				return nil, fmt.Errorf("array index [%d] is outside the document", step.index)
			}
			current = array[step.index]
			continue
		}
		object, ok := current.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("cannot read member %q from %T", step.member, current)
		}
		value, ok := object[step.member]
		if !ok {
			return nil, fmt.Errorf("missing object member %q", step.member)
		}
		current = value
	}
	return current, nil
}

// locatorStep is one path element: a named member, or an array index.
type locatorStep struct {
	member string
	index  int
}

// locatorSteps tokenizes a locator into members and indices, accepting "/" and
// "." as member separators and "[n]" as an index.
func locatorSteps(locator string) ([]locatorStep, error) {
	var steps []locatorStep
	member := strings.Builder{}
	flush := func() {
		if member.Len() == 0 {
			return
		}
		token := member.String()
		member.Reset()
		// A numeric member is an array index: records/mapping/0 names the first
		// element of records.mapping, matching the JSON Pointer convention.
		if position, err := strconv.Atoi(token); err == nil && position >= 0 {
			steps = append(steps, locatorStep{index: position})
			return
		}
		steps = append(steps, locatorStep{member: token, index: -1})
	}
	for position := 0; position < len(locator); position++ {
		switch symbol := locator[position]; {
		case symbol == '/' || symbol == '.':
			flush()
		case symbol == '[':
			flush()
			close := strings.IndexByte(locator[position:], ']')
			if close < 0 {
				return nil, fmt.Errorf("unbalanced bracket in %q", locator)
			}
			index, err := strconv.Atoi(locator[position+1 : position+close])
			if err != nil || index < 0 {
				return nil, fmt.Errorf("invalid index in %q", locator)
			}
			steps = append(steps, locatorStep{index: index})
			position += close
		default:
			member.WriteByte(symbol)
		}
	}
	flush()
	if len(steps) == 0 {
		return nil, fmt.Errorf("empty locator")
	}
	return steps, nil
}

// loadProductFixture reads one fixture directory, verifies the wire artifacts
// against the recomputed ones and assembles the request. Every verification is
// fail-closed: a fixture that does not match its own expected artifacts must
// fail here, never downstream.
func loadProductFixture(t *testing.T, slug string) fixtureFiles {
	t.Helper()
	root := filepath.Join(fixturesRoot, slug, "0.2")
	input := filepath.Join(root, "input")
	expected := filepath.Join(root, "expected")

	var loaded fixtureFiles
	if err := json.Unmarshal(readFixtureFile(t, filepath.Join(input, "bundle.json")), &loaded.bundle); err != nil {
		t.Fatalf("input bundle does not decode: %v", err)
	}
	if err := contract.ValidateBundle(loaded.bundle); err != nil {
		t.Fatalf("input bundle is invalid: %v", err)
	}
	if loaded.bundle.SchemaVersion != rulepack.ProductBundleSchemaVersion {
		t.Fatalf("fixture bundle schema is %s, want %s", loaded.bundle.SchemaVersion, rulepack.ProductBundleSchemaVersion)
	}
	// The input envelope must already be canonical: decoding and re-encoding
	// must reproduce the committed bytes exactly.
	canonicalBytes, err := canonical.CanonicalJSON(loaded.bundle)
	if err != nil {
		t.Fatalf("input bundle does not project: %v", err)
	}
	if string(canonicalBytes) != string(readFixtureFile(t, filepath.Join(input, "bundle.json"))) {
		t.Fatalf("input bundle.json is not the canonical form of its own content")
	}
	// The three expected artifacts must be exactly what the wire encoder
	// rebuilds from the input envelope.
	artifacts, err := bundle.Encode(loaded.bundle)
	if err != nil {
		t.Fatalf("expected artifacts cannot be rebuilt: %v", err)
	}
	if string(artifacts.Envelope) != string(readFixtureFile(t, filepath.Join(expected, "bundle.json"))) {
		t.Fatalf("expected bundle.json does not match the rebuilt envelope")
	}
	if string(artifacts.HashInput) != string(readFixtureFile(t, filepath.Join(expected, "bundle.hash-input.json"))) {
		t.Fatalf("expected bundle.hash-input.json does not match the rebuilt projection")
	}
	assertSourcesSupportBundle(t, input, loaded.bundle)
	wantHash := strings.TrimSpace(string(readFixtureFile(t, filepath.Join(expected, "bundle.sha256"))))
	if artifacts.Hash != wantHash {
		t.Fatalf("expected bundle.sha256 is %s, rebuilt %s", wantHash, artifacts.Hash)
	}

	var target fixtureTarget
	if err := json.Unmarshal(readFixtureFile(t, filepath.Join(input, "target.json")), &target); err != nil {
		t.Fatalf("target does not decode: %v", err)
	}
	var admission fixtureAdmission
	if err := json.Unmarshal(readFixtureFile(t, filepath.Join(input, "admission-context.json")), &admission); err != nil {
		t.Fatalf("admission context does not decode: %v", err)
	}
	var domain fixtureDomainContext
	if err := json.Unmarshal(readFixtureFile(t, filepath.Join(input, "domain-context.json")), &domain); err != nil {
		t.Fatalf("domain context does not decode: %v", err)
	}
	if err := json.Unmarshal(readFixtureFile(t, filepath.Join(expected, "expectations.json")), &loaded.expectations); err != nil {
		t.Fatalf("expectations do not decode: %v", err)
	}

	targetStamp := mustParseTime(t, target.ObservedAt)
	assertTargetRecord(t, filepath.Join(input, target.Source), target)
	admissionStamp := mustParseTime(t, admission.EvaluatedAt)
	packBytes := readFixtureFile(t, filepath.Join(input, "pack.json"))
	request := Request{
		Bundle:             loaded.bundle,
		ExpectedBundleHash: mustBundleHash(t, loaded.bundle),
		Target: Target{
			SubjectUID:      contract.UID(target.SubjectUID),
			ContainerClass:  contract.ContainerClass(target.ContainerClass),
			ContainerName:   contract.ContainerName(target.ContainerName),
			VulnerabilityID: target.VulnerabilityID,
			Source:          target.Source,
			SourceHash:      contract.SourceHash(target.SourceHash),
			Locator:         contract.SourceLocator(target.Locator),
			ObservedAt:      targetStamp,
		},
		PackBytes: packBytes,
		Admission: rulepack.AdmissionContext{
			EvaluatedAt:      admissionStamp,
			ExpectedPackID:   admission.ExpectedPackID,
			ExpectedPackHash: admission.ExpectedPackHash,
			MinimumVersion:   admission.MinimumVersion,
		},
	}
	domainContext := DomainContext{
		MaximumEvidenceAgeSeconds: domain.MaximumEvidenceAgeSeconds,
	}
	for _, pin := range domain.SourcePins {
		domainContext.SourcePins = append(domainContext.SourcePins, SourcePin{
			Role:             SourceRole(pin.Role),
			Source:           pin.Source,
			SourceHash:       contract.SourceHash(pin.SourceHash),
			AdvisoryID:       pin.AdvisoryID,
			AdvisoryRevision: pin.AdvisoryRevision,
		})
	}
	request.Domain = &domainContext
	loaded.request = request
	return loaded
}

// assertTargetRecord anchors the finding row of the fixture to the production
// parser: the target must name a record of the file by the exact absolute
// interval the parser reports, and that record must carry the selected
// vulnerability. A target pointing at the header or at another row is not a
// reproducible starting point.
func assertTargetRecord(t *testing.T, path string, target fixtureTarget) {
	t.Helper()
	body := readFixtureFile(t, path)
	if want := string(bundle.HashSource(body)); target.SourceHash != want {
		t.Fatalf("target source_hash %s does not match the file digest %s", target.SourceHash, want)
	}
	result, err := ingest.ParsePrismaV1(bytes.NewReader(body))
	if err != nil {
		t.Fatalf("target source %s does not parse: %v", path, err)
	}
	for _, finding := range result.Findings {
		if finding.Locator.String() == target.Locator && finding.VulnerabilityID == target.VulnerabilityID {
			return
		}
	}
	t.Fatalf("target locator %q and vulnerability %s match no parsed record", target.Locator, target.VulnerabilityID)
}

func mustParseTime(t *testing.T, value string) contract.Timestamp {
	t.Helper()
	var stamp contract.Timestamp
	if err := json.Unmarshal([]byte(`"`+value+`"`), &stamp); err != nil {
		t.Fatalf("timestamp %s: %v", value, err)
	}
	return stamp
}

// assertProductResult compares one Result against the fixture expectations.
func assertProductResult(t *testing.T, result Result, expectations fixtureExpectations) {
	t.Helper()
	if result.ProfileVersion != expectations.Profile {
		t.Errorf("profile %s, want %s", result.ProfileVersion, expectations.Profile)
	}
	if string(result.ProductStatus) != expectations.ProductStatus {
		t.Errorf("product_status %s, want %s", result.ProductStatus, expectations.ProductStatus)
	}
	if string(result.Exploitability) != expectations.Exploitability {
		t.Errorf("exploitability %s, want %s", result.Exploitability, expectations.Exploitability)
	}
	gotReasons := make([]string, 0, len(result.Reasons))
	for _, reason := range result.Reasons {
		gotReasons = append(gotReasons, string(reason))
	}
	if strings.Join(gotReasons, ",") != strings.Join(expectations.Reasons, ",") {
		t.Errorf("reasons %v, want %v", gotReasons, expectations.Reasons)
	}
	if len(result.Candidates) != len(expectations.Candidates) {
		t.Fatalf("candidates %d, want %d", len(result.Candidates), len(expectations.Candidates))
	}
	for index, candidate := range result.Candidates {
		wanted := expectations.Candidates[index]
		if candidate.RuleID != wanted.RuleID || string(candidate.ProductStatus) != wanted.ProductStatus {
			t.Errorf("candidate %d is %s/%s, want %s/%s", index, candidate.RuleID, candidate.ProductStatus, wanted.RuleID, wanted.ProductStatus)
		}
	}
	if len(result.WarningReferences) != expectations.WarningReferences {
		t.Errorf("warning references %d, want %d", len(result.WarningReferences), expectations.WarningReferences)
	}
	byRule := make(map[string]RuleTrace, len(result.Rules))
	for _, trace := range result.Rules {
		byRule[trace.RuleID] = trace
	}
	if len(result.Rules) != len(expectations.Rules) {
		t.Fatalf("rules %d, want %d", len(result.Rules), len(expectations.Rules))
	}
	for _, wanted := range expectations.Rules {
		trace, ok := byRule[wanted.RuleID]
		if !ok {
			t.Fatalf("rule %s missing from the result", wanted.RuleID)
		}
		if string(trace.State) != wanted.State {
			t.Errorf("rule %s state %s, want %s", wanted.RuleID, trace.State, wanted.State)
		}
		gotMissing := make([]string, 0, len(trace.MissingRequirements))
		for _, requirement := range trace.MissingRequirements {
			gotMissing = append(gotMissing, string(requirement))
		}
		if strings.Join(gotMissing, ",") != strings.Join(wanted.MissingRequirements, ",") {
			t.Errorf("rule %s missing requirements %v, want %v", wanted.RuleID, gotMissing, wanted.MissingRequirements)
		}
		if len(trace.Checks) != len(wanted.Checks) {
			t.Fatalf("rule %s checks %d, want %d", wanted.RuleID, len(trace.Checks), len(wanted.Checks))
		}
		for index, check := range trace.Checks {
			expectedCheck := wanted.Checks[index]
			if check.CheckID != expectedCheck.CheckID || string(check.Outcome) != expectedCheck.Outcome {
				t.Errorf("rule %s check %d is %s/%s, want %s/%s", wanted.RuleID, index, check.CheckID, check.Outcome, expectedCheck.CheckID, expectedCheck.Outcome)
			}
			gotCheckReasons := make([]string, 0, len(check.Reasons))
			for _, reason := range check.Reasons {
				gotCheckReasons = append(gotCheckReasons, string(reason))
			}
			if strings.Join(gotCheckReasons, ",") != strings.Join(expectedCheck.Reasons, ",") {
				t.Errorf("rule %s check %s reasons %v, want %v", wanted.RuleID, check.CheckID, gotCheckReasons, expectedCheck.Reasons)
			}
		}
	}
}

// TestProductFixtures runs the committed fixtures of F4b against the real
// engine: F09 proves that an unmapped package never concludes, F10 proves that
// an exact vendor proof concludes fixed despite an apparently old upstream
// version, and F13 proves that contradictory evidence blocks every affirmative
// publication.
func TestProductFixtures(t *testing.T) {
	t.Run("F09", func(t *testing.T) {
		files := loadProductFixture(t, "F09-unmapped-redhat-package")
		result, err := Evaluate(files.request)
		if err != nil {
			t.Fatalf("F09 must evaluate: %v", err)
		}
		assertProductResult(t, result, files.expectations)
	})

	t.Run("F10", func(t *testing.T) {
		files := loadProductFixture(t, "F10-redhat-backport")
		result, err := Evaluate(files.request)
		if err != nil {
			t.Fatalf("F10 must evaluate: %v", err)
		}
		assertProductResult(t, result, files.expectations)
		assertF10LinkNegatives(t, files)
	})

	t.Run("F13", func(t *testing.T) {
		files := loadProductFixture(t, "F13-contradictory-evidence")
		result, err := Evaluate(files.request)
		if err != nil {
			t.Fatalf("F13 must evaluate: %v", err)
		}
		assertProductResult(t, result, files.expectations)
		assertF13Variants(t, files)
	})
}

// TestProductFixtureTamperingIsRejected proves the source contrast is
// load-bearing, not a hash formality: a bundle that cites a record which does
// not state the attributed fact, or a proof whose support definition the
// transcription no longer carries, must be rejected even though every hash is
// current and every locator still resolves.
func TestProductFixtureTamperingIsRejected(t *testing.T) {
	t.Run("proof attributed to a record that does not state it", func(t *testing.T) {
		slug := "F13-contradictory-evidence"
		files := loadProductFixture(t, slug)
		tampered := cloneBundle(files.bundle)
		swapped := 0
		for index, evidence := range tampered.Evidence {
			if evidence.Type != "product_v1.vendor.proof_kind" {
				continue
			}
			switch string(evidence.Locator) {
			case "records/proof/0":
				tampered.Evidence[index].Locator = "records/proof/1"
				swapped++
			case "records/proof/1":
				tampered.Evidence[index].Locator = "records/proof/0"
				swapped++
			}
		}
		if swapped != 2 {
			t.Fatalf("expected one proof_kind item per record, swapped %d", swapped)
		}
		err := sourcesSupportBundle(filepath.Join(fixturesRoot, slug, "0.2", "input"), tampered)
		if err == nil {
			t.Fatal("a proof_kind attributed to the record of the other proof was accepted")
		}
		if !strings.Contains(err.Error(), "proof_kind") {
			t.Fatalf("rejection does not name the misattributed item: %v", err)
		}
	})

	t.Run("fact attributed to another record family", func(t *testing.T) {
		slug := "F10-redhat-backport"
		files := loadProductFixture(t, slug)
		tampered := cloneBundle(files.bundle)
		moved := 0
		for index, evidence := range tampered.Evidence {
			if evidence.Type == "product_v1.mapping.package_name" {
				// The artifact record states the same package name, so only the
				// collection the item type declares distinguishes the two.
				tampered.Evidence[index].Locator = "records/artifact/0"
				moved++
			}
		}
		if moved != 1 {
			t.Fatalf("expected one mapping package_name item, moved %d", moved)
		}
		err := sourcesSupportBundle(filepath.Join(fixturesRoot, slug, "0.2", "input"), tampered)
		if err == nil {
			t.Fatal("a mapping fact cited from the artifact record was accepted")
		}
		if !strings.Contains(err.Error(), "artifact") {
			t.Fatalf("rejection does not name the wrong collection: %v", err)
		}
	})

	t.Run("support definition removed from the transcription", func(t *testing.T) {
		slug := "F10-redhat-backport"
		files := loadProductFixture(t, slug)
		input := filepath.Join(fixturesRoot, slug, "0.2", "input")
		work := copyFixtureInput(t, input)
		var advisory map[string]json.RawMessage
		if err := json.Unmarshal(readFixtureFile(t, filepath.Join(input, "advisory.json")), &advisory); err != nil {
			t.Fatalf("advisory transcription does not decode: %v", err)
		}
		delete(advisory, "definitions")
		stripped, err := json.Marshal(advisory)
		if err != nil {
			t.Fatalf("strip definitions: %v", err)
		}
		if err := os.WriteFile(filepath.Join(work, "advisory.json"), stripped, 0o644); err != nil {
			t.Fatalf("write advisory transcription: %v", err)
		}
		tampered := retargetSourceHash(t, files.bundle, "advisory.json", stripped)
		err = sourcesSupportBundle(work, tampered)
		if err == nil {
			t.Fatal("a proof citing a support definition the transcription no longer carries was accepted")
		}
		if !strings.Contains(err.Error(), "basis_locator") {
			t.Fatalf("rejection does not name the lost support definition: %v", err)
		}
	})

	t.Run("observation fact cited from another member", func(t *testing.T) {
		slug := "F10-redhat-backport"
		files := loadProductFixture(t, slug)
		tampered := cloneBundle(files.bundle)
		moved := 0
		for index, evidence := range tampered.Evidence {
			if !strings.HasPrefix(evidence.Type, "container_status.") {
				continue
			}
			// The container name is a real string of the same record, so every
			// value stays true about the document: only the declared carrier is
			// wrong.
			tampered.Evidence[index].Locator = "items[0].status.containerStatuses[0].name"
			setItemValue(&tampered.Evidence[index], "app")
			moved++
		}
		if moved != 4 {
			t.Fatalf("expected four observation items, moved %d", moved)
		}
		err := sourcesSupportBundle(filepath.Join(fixturesRoot, slug, "0.2", "input"), tampered)
		if err == nil {
			t.Fatal("an observation fact cited from another member of the container status was accepted")
		}
		if !strings.Contains(err.Error(), "imageID") {
			t.Fatalf("rejection does not name the declared carrier: %v", err)
		}
	})

	t.Run("domain fact attributed to a nested object", func(t *testing.T) {
		slug := "F10-redhat-backport"
		files := loadProductFixture(t, slug)
		input := filepath.Join(fixturesRoot, slug, "0.2", "input")
		work := copyFixtureInput(t, input)
		var mapping map[string]any
		if err := json.Unmarshal(readFixtureFile(t, filepath.Join(input, "mapping.json")), &mapping); err != nil {
			t.Fatalf("mapping transcription does not decode: %v", err)
		}
		records, ok := mapping["records"].(map[string]any)
		if !ok {
			t.Fatal("mapping transcription has no records object")
		}
		list, ok := records["mapping"].([]any)
		if !ok || len(list) == 0 {
			t.Fatal("mapping transcription has no mapping record")
		}
		record, ok := list[0].(map[string]any)
		if !ok {
			t.Fatal("mapping record is not an object")
		}
		// The whole record is copied into a nested member and the outer statement
		// is changed: every value the items carry is still true, but of a nested
		// object rather than of an element of the mapping collection.
		nested := make(map[string]any, len(record))
		for key, value := range record {
			nested[key] = value
		}
		record["artifact"] = nested
		record["package_name"] = "other"
		rewritten, err := json.Marshal(mapping)
		if err != nil {
			t.Fatalf("rewrite mapping transcription: %v", err)
		}
		if err := os.WriteFile(filepath.Join(work, "mapping.json"), rewritten, 0o644); err != nil {
			t.Fatalf("write mapping transcription: %v", err)
		}
		tampered := retargetSourceHash(t, files.bundle, "mapping.json", rewritten)
		for index, evidence := range tampered.Evidence {
			if strings.HasPrefix(evidence.Type, "product_v1.mapping.") {
				tampered.Evidence[index].Locator = contract.SourceLocator(string(evidence.Locator) + "/artifact")
			}
		}
		err = sourcesSupportBundle(work, tampered)
		if err == nil {
			t.Fatal("a domain fact cited from a nested object was accepted")
		}
		if !strings.Contains(err.Error(), "direct element") {
			t.Fatalf("rejection does not name the nested locator: %v", err)
		}
	})

	t.Run("proof that presents itself as its own basis", func(t *testing.T) {
		slug := "F10-redhat-backport"
		files := loadProductFixture(t, slug)
		input := filepath.Join(fixturesRoot, slug, "0.2", "input")
		work := copyFixtureInput(t, input)
		var advisory map[string]any
		if err := json.Unmarshal(readFixtureFile(t, filepath.Join(input, "advisory.json")), &advisory); err != nil {
			t.Fatalf("advisory transcription does not decode: %v", err)
		}
		delete(advisory, "definitions")
		records, ok := advisory["records"].(map[string]any)
		if !ok {
			t.Fatal("advisory transcription has no records object")
		}
		proofs, ok := records["proof"].([]any)
		if !ok || len(proofs) == 0 {
			t.Fatal("advisory transcription has no proof record")
		}
		recited := 0
		for index := range proofs {
			record, ok := proofs[index].(map[string]any)
			if !ok {
				t.Fatal("proof record is not an object")
			}
			// The proof becomes its own basis: the record does carry a matching
			// basis_id and vulnerability_id, so only the fact that a proof is not
			// a definition rejects this.
			record["basis_locator"] = "records/proof/0"
			recited++
		}
		if recited == 0 {
			t.Fatal("the fixture carries no vendor proof to rewrite")
		}
		rewritten, err := json.Marshal(advisory)
		if err != nil {
			t.Fatalf("rewrite advisory transcription: %v", err)
		}
		if err := os.WriteFile(filepath.Join(work, "advisory.json"), rewritten, 0o644); err != nil {
			t.Fatalf("write advisory transcription: %v", err)
		}
		tampered := retargetSourceHash(t, files.bundle, "advisory.json", rewritten)
		for index, evidence := range tampered.Evidence {
			if evidence.Type == "product_v1.vendor.basis_locator" {
				setItemValue(&tampered.Evidence[index], "records/proof/0")
			}
		}
		err = sourcesSupportBundle(work, tampered)
		if err == nil {
			t.Fatal("a proof citing itself as its support definition was accepted")
		}
		if !strings.Contains(err.Error(), "definitions collection") {
			t.Fatalf("rejection does not name the missing definition: %v", err)
		}
	})

	t.Run("locator in a non canonical separator form", func(t *testing.T) {
		slug := "F10-redhat-backport"
		files := loadProductFixture(t, slug)
		tampered := cloneBundle(files.bundle)
		rewritten := 0
		for index, evidence := range tampered.Evidence {
			if strings.HasPrefix(evidence.Type, "product_v1.mapping.") {
				// The dotted form resolves to the same record, so only the
				// canonical-string requirement rejects it.
				tampered.Evidence[index].Locator = contract.SourceLocator(strings.ReplaceAll(string(evidence.Locator), "/", "."))
				rewritten++
			}
		}
		if rewritten == 0 {
			t.Fatal("the fixture carries no mapping item to rewrite")
		}
		err := sourcesSupportBundle(filepath.Join(fixturesRoot, slug, "0.2", "input"), tampered)
		if err == nil {
			t.Fatal("a locator with a non canonical separator was accepted")
		}
		if !strings.Contains(err.Error(), "canonical form") {
			t.Fatalf("rejection does not name the canonical form: %v", err)
		}
	})

	t.Run("value hash that covers no transcription value", func(t *testing.T) {
		slug := "F10-redhat-backport"
		files := loadProductFixture(t, slug)
		input := filepath.Join(fixturesRoot, slug, "0.2", "input")
		// The legitimate wire shape first: a value the wire cannot carry verbatim
		// is kept auditable by hash only (ADR-0012), and it must still pass.
		legitimate := cloneBundle(files.bundle)
		for index, evidence := range legitimate.Evidence {
			if evidence.Type == "prisma_v1.severity" {
				legitimate.Evidence[index].Value = nil
			}
		}
		if err := sourcesSupportBundle(input, legitimate); err != nil {
			t.Fatalf("the legitimate hash-only shape was rejected: %v", err)
		}
		tampered := cloneBundle(files.bundle)
		stale := contract.ValueHash("sha256:" + strings.Repeat("ab", 32))
		replaced := 0
		for index, evidence := range tampered.Evidence {
			if evidence.Type != "prisma_v1.severity" {
				continue
			}
			tampered.Evidence[index].Value = nil
			tampered.Evidence[index].ValueHash = &stale
			replaced++
		}
		if replaced != 1 {
			t.Fatalf("expected one severity item, replaced %d", replaced)
		}
		err := sourcesSupportBundle(input, tampered)
		if err == nil {
			t.Fatal("a value_hash that covers no transcription value was accepted")
		}
		if !strings.Contains(err.Error(), "value_hash") {
			t.Fatalf("rejection does not name the hash: %v", err)
		}
	})
}

// TestProductFixtureRequestedImageGrammar requires the harness to compose the
// reference with the production grammar of ADR-0009 instead of imitating its
// concatenation: a declaration the rule refuses cannot be presented as a
// composed reference.
func TestProductFixtureRequestedImageGrammar(t *testing.T) {
	finding := ingest.Finding{
		ImageRegistry:   "reg/example",
		ImageRepository: "app",
		ImageTag:        "release",
	}
	if _, err := statedPrismaField(finding, "prisma_v1.requested_image"); err == nil {
		t.Fatal("a registry that is not an authority was accepted as a composed reference")
	}
	finding.ImageTag = "1"
	if _, err := statedPrismaField(finding, "prisma_v1.requested_image"); err == nil {
		t.Fatal("a tag the canonical grammar refuses was accepted as a composed reference")
	}
	finding.ImageRegistry = "reg.example"
	finding.ImageTag = "release"
	stated, err := statedPrismaField(finding, "prisma_v1.requested_image")
	if err != nil {
		t.Fatalf("a canonical declaration was refused: %v", err)
	}
	if stated != "reg.example/app:release" {
		t.Fatalf("composed reference %q, want reg.example/app:release", stated)
	}
}

// TestProductFixturePrismaVocabularyCoversProducer requires the harness to
// accept every declared column the producer projects, plus the composed
// reference: the sixteen item types that internal/bundle pins in
// TestBuildMapsEveryDeclaredColumn. The fixture CSV is the source, so a column
// the producer would project cannot be rejected as unknown, and the stated
// value must be the one the committed bundle carries.
func TestProductFixturePrismaVocabularyCoversProducer(t *testing.T) {
	slug := "F10-redhat-backport"
	files := loadProductFixture(t, slug)
	body := readFixtureFile(t, filepath.Join(fixturesRoot, slug, "0.2", "input", "findings.csv"))
	result, err := ingest.ParsePrismaV1(bytes.NewReader(body))
	if err != nil {
		t.Fatalf("fixture CSV does not parse: %v", err)
	}
	if len(result.Findings) != 1 {
		t.Fatalf("findings = %d, want exactly one record", len(result.Findings))
	}
	finding := result.Findings[0]
	committed := map[string]string{}
	for _, evidence := range files.bundle.Evidence {
		if evidence.Value != nil {
			committed[evidence.Type] = *evidence.Value
		}
	}
	columns := []string{
		"schema_version", "vulnerability_id", "package_name", "installed_version", "fix_status",
		"image_registry", "image_repository", "image_tag", "package_type", "package_id", "path",
		"severity", "description", "published_date", "discovery_date",
	}
	for _, column := range columns {
		itemType := "prisma_v1." + column
		stated, err := statedPrismaField(finding, itemType)
		if err != nil {
			t.Fatalf("the harness rejects the declared column %s: %v", column, err)
		}
		want, ok := committed[itemType]
		if !ok {
			t.Fatalf("the committed fixture carries no %s item", itemType)
		}
		if stated != want {
			t.Fatalf("%s: the harness states %q, the fixture carries %q", itemType, stated, want)
		}
	}
	composed, err := statedPrismaField(finding, "prisma_v1.requested_image")
	if err != nil {
		t.Fatalf("the harness refuses the composed reference: %v", err)
	}
	if want := committed["prisma_v1.requested_image"]; composed != want {
		t.Fatalf("requested_image: the harness composes %q, the fixture carries %q", composed, want)
	}
}

// copyFixtureInput copies the input directory of a fixture to a temporary
// directory, so a tamper can rewrite a transcription without touching the
// repository.
func copyFixtureInput(t *testing.T, input string) string {
	t.Helper()
	work := t.TempDir()
	entries, err := os.ReadDir(input)
	if err != nil {
		t.Fatalf("read fixture input: %v", err)
	}
	for _, entry := range entries {
		body := readFixtureFile(t, filepath.Join(input, entry.Name()))
		if err := os.WriteFile(filepath.Join(work, entry.Name()), body, 0o644); err != nil {
			t.Fatalf("copy %s: %v", entry.Name(), err)
		}
	}
	return work
}

// retargetSourceHash points every item of one source at the digest of a
// rewritten transcription, so the tamper survives the digest check and reaches
// the contrast under test.
func retargetSourceHash(t *testing.T, source contract.Bundle, name string, body []byte) contract.Bundle {
	t.Helper()
	digest := bundle.HashSource(body)
	cloned := cloneBundle(source)
	for index, evidence := range cloned.Evidence {
		if evidence.Source == name {
			cloned.Evidence[index].SourceHash = digest
		}
	}
	return cloned
}

// setItemValue rewrites an item value and its hash together, so a tamper keeps
// the wire internally consistent instead of failing on an unrelated
// inconsistency.
func setItemValue(item *contract.EvidenceItem, value string) {
	item.Value = &value
	hash := bundle.HashValue(value)
	item.ValueHash = &hash
}

// assertF10LinkNegatives derives, in memory and per link of the identity chain,
// the negatives the handoff requires: every link that stops matching must drop
// the publication back to under_investigation. Each mutation recomputes the
// value hash and the bundle hash, so the rejection is semantic, never a wire
// integrity error.
func assertF10LinkNegatives(t *testing.T, files fixtureFiles) {
	t.Helper()
	negatives := []struct {
		name  string
		item  string
		value string
	}{
		{"artifact_digest", "product_v1.artifact.artifact_digest", "sha256:" + strings.Repeat("7e", 32)},
		{"mapping_product_release", "product_v1.mapping.product_release", "8"},
		{"vendor_version", "product_v1.vendor.version", "9.9.9"},
		{"mapping_package_name", "product_v1.mapping.package_name", "other"},
	}
	for _, negative := range negatives {
		t.Run("negative_"+negative.name, func(t *testing.T) {
			mutated := fixtureWithDomainValue(t, files.bundle, negative.item, negative.value)
			request := files.request
			request.Bundle = mutated
			request.ExpectedBundleHash = mustBundleHash(t, mutated)
			result, err := Evaluate(request)
			if err != nil {
				t.Fatalf("negative %s must evaluate: %v", negative.name, err)
			}
			if result.ProductStatus != contract.ProductUnderInvestigation {
				t.Errorf("negative %s status %s, want under_investigation", negative.name, result.ProductStatus)
			}
			if len(result.Candidates) != 0 {
				t.Errorf("negative %s published %d candidates", negative.name, len(result.Candidates))
			}
			if !slices.Contains(result.Reasons, ReasonRequirementsMissing) {
				t.Errorf("negative %s reasons %v lack requirements_missing", negative.name, result.Reasons)
			}
		})
	}
}

// fixtureWithDomainValue rewrites one domain value together with its value hash
// and recomputes nothing else: the caller reprojects the bundle hash.
func fixtureWithDomainValue(t *testing.T, source contract.Bundle, itemType, value string) contract.Bundle {
	t.Helper()
	mutated := cloneBundle(source)
	hash := independentValueHash(value)
	replaced := false
	for index := range mutated.Evidence {
		if mutated.Evidence[index].Type == itemType {
			mutated.Evidence[index].Value = strPointer(value)
			mutated.Evidence[index].ValueHash = &hash
			replaced = true
		}
	}
	if !replaced {
		t.Fatalf("fixture has no item of type %s", itemType)
	}
	return mutated
}

// assertF13Variants derives the controls the handoff requires: a single proof
// without warnings publishes fixed, a known informational warning does not
// block, and duplicates plus permutations conserve the semantic result.
func assertF13Variants(t *testing.T, files fixtureFiles) {
	t.Helper()
	t.Run("single_fixed_proof", func(t *testing.T) {
		bundle := fixtureWithoutWarnings(files.bundle)
		bundle = fixtureDropVendorProof(t, bundle, "vulnerable_build")
		request := files.request
		request.Bundle = bundle
		request.ExpectedBundleHash = mustBundleHash(t, bundle)
		request.PackBytes = []byte(fixturePackRuleFixed(t, files))
		request.Admission.ExpectedPackHash = independentDocumentHash(string(request.PackBytes))
		result, err := Evaluate(request)
		if err != nil {
			t.Fatalf("single fixed proof must evaluate: %v", err)
		}
		if result.ProductStatus != contract.ProductFixed {
			t.Errorf("status %s, want fixed", result.ProductStatus)
		}
		if len(result.Candidates) != 1 || result.Candidates[0].RuleID != "rule.fixed" {
			t.Errorf("candidates %v, want exactly rule.fixed", result.Candidates)
		}
		if len(result.Reasons) != 0 {
			t.Errorf("reasons %v, want none", result.Reasons)
		}
	})

	t.Run("informational_warning_does_not_block", func(t *testing.T) {
		bundle := fixtureWithoutWarnings(files.bundle)
		bundle = fixtureDropVendorProof(t, bundle, "vulnerable_build")
		for index := range bundle.Evidence {
			if bundle.Evidence[index].Type == "product_v1.artifact.digest_kind" {
				bundle.Evidence[index].Warnings = []contract.Warning{{
					Code:    "redaction_applied",
					Class:   contract.WarningInformational,
					Message: "synthetic informational warning",
				}}
			}
		}
		request := files.request
		request.Bundle = bundle
		request.ExpectedBundleHash = mustBundleHash(t, bundle)
		request.PackBytes = []byte(fixturePackRuleFixed(t, files))
		request.Admission.ExpectedPackHash = independentDocumentHash(string(request.PackBytes))
		result, err := Evaluate(request)
		if err != nil {
			t.Fatalf("informational variant must evaluate: %v", err)
		}
		if result.ProductStatus != contract.ProductFixed {
			t.Errorf("status %s, want fixed", result.ProductStatus)
		}
		if len(result.Reasons) != 0 {
			t.Errorf("reasons %v, want none", result.Reasons)
		}
	})

	t.Run("duplicates_and_permutations", func(t *testing.T) {
		bundle := fixtureWithoutWarnings(files.bundle)
		bundle = fixtureDropVendorProof(t, bundle, "vulnerable_build")
		// Duplication adds items, so the canonical bytes and the bundle hash
		// change; permutation only reorders the caller's array, and the canonical
		// order of ADR-0006 sorts it back, so the hash must not change. Both
		// effects conserve the semantic result.
		base := cloneBundle(bundle)
		bundle = fixtureDuplicateFixedProof(t, bundle)
		if mustBundleHash(t, bundle) == mustBundleHash(t, base) {
			t.Fatal("the duplication must change the bundle hash")
		}
		reversed := cloneBundle(bundle)
		for i, j := 0, len(reversed.Evidence)-1; i < j; i, j = i+1, j-1 {
			reversed.Evidence[i], reversed.Evidence[j] = reversed.Evidence[j], reversed.Evidence[i]
		}
		if mustBundleHash(t, reversed) != mustBundleHash(t, bundle) {
			t.Fatal("the permutation must preserve the canonical bytes of the same items")
		}
		request := files.request
		request.Bundle = reversed
		request.ExpectedBundleHash = mustBundleHash(t, reversed)
		request.PackBytes = []byte(fixturePackRuleFixed(t, files))
		request.Admission.ExpectedPackHash = independentDocumentHash(string(request.PackBytes))
		result, err := Evaluate(request)
		if err != nil {
			t.Fatalf("permutation variant must evaluate: %v", err)
		}
		if result.ProductStatus != contract.ProductFixed {
			t.Errorf("status %s, want fixed", result.ProductStatus)
		}
		if len(result.Candidates) != 1 || result.Candidates[0].RuleID != "rule.fixed" {
			t.Errorf("candidates %v, want exactly rule.fixed", result.Candidates)
		}
	})
}

func fixtureWithoutWarnings(source contract.Bundle) contract.Bundle {
	cleaned := cloneBundle(source)
	for index := range cleaned.Evidence {
		cleaned.Evidence[index].Warnings = []contract.Warning{}
	}
	cleaned.Provenance.Warnings = []contract.Warning{}
	return cleaned
}

// fixtureDropVendorProof removes every item of one vendor proof group: the
// group is identified by the locator of its proof_kind item.
func fixtureDropVendorProof(t *testing.T, source contract.Bundle, kind string) contract.Bundle {
	t.Helper()
	locator := ""
	for _, evidence := range source.Evidence {
		if evidence.Type == "product_v1.vendor.proof_kind" && evidence.Value != nil && *evidence.Value == kind {
			locator = string(evidence.Locator)
		}
	}
	if locator == "" {
		t.Fatalf("fixture has no vendor proof of kind %s", kind)
	}
	kept := make([]contract.EvidenceItem, 0, len(source.Evidence))
	for _, evidence := range source.Evidence {
		if string(evidence.Locator) == locator {
			continue
		}
		kept = append(kept, evidence)
	}
	dropped := cloneBundle(source)
	dropped.Evidence = kept
	return dropped
}

// fixtureDuplicateFixedProof appends a byte-identical copy of the fixed proof
// group: the domain layer must deduplicate the record by its provenance key.
func fixtureDuplicateFixedProof(t *testing.T, source contract.Bundle) contract.Bundle {
	t.Helper()
	var copies []contract.EvidenceItem
	for _, evidence := range source.Evidence {
		if evidence.Type == "product_v1.vendor.proof_kind" && evidence.Value != nil && *evidence.Value == "fixed_build" {
			copies = append(copies, evidence)
		}
	}
	if len(copies) == 0 {
		t.Fatal("fixture has no fixed vendor proof to duplicate")
	}
	locator := string(copies[0].Locator)
	duplicated := cloneBundle(source)
	for _, evidence := range source.Evidence {
		if string(evidence.Locator) == locator {
			duplicated.Evidence = append(duplicated.Evidence, evidence)
		}
	}
	return duplicated
}

// fixturePackRuleFixed rebuilds the F13 pack with only the fixed rule, so the
// variant isolates the publication path from the conflicting branches.
func fixturePackRuleFixed(t *testing.T, files fixtureFiles) string {
	t.Helper()
	cve := files.request.Target.VulnerabilityID
	document := `{"schema_version":"0.1","profile":"` + rulepack.ProductEvidenceProfile + `","pack_id":"` + files.request.Admission.ExpectedPackID + `",` +
		`"version":1,"valid_from":"2026-09-01T00:00:00Z","expires_at":"2026-12-31T23:59:59Z","rules":[` +
		`{"rule_id":"rule.fixed",` +
		`"selector":{"coverage_method":"findings_import","vulnerability_id":"` + cve + `"},` +
		`"requires":["bundle.complete","finding.row",` +
		`"finding.package_type","finding.package_name","finding.package_id",` +
		`"image.bound_digest","image.known_platform",` +
		`"domain.mapping","domain.artifact","domain.vendor_proof","domain.current"],` +
		`"checks":[{"check_id":"check.terminal","predicate":"redhat_build_fixed","params":{}}],` +
		`"on_missing_evidence":"under_investigation","emit":"fixed"}]}`
	return document
}
