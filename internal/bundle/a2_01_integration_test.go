package bundle_test

import (
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/d4rpell/Ariadne/internal/bundle"
	"github.com/d4rpell/Ariadne/internal/evaluator"
	"github.com/d4rpell/Ariadne/internal/ingest"
	"github.com/d4rpell/Ariadne/internal/normalize"
	"github.com/d4rpell/Ariadne/internal/report"
	"github.com/d4rpell/Ariadne/internal/rulepack"
	contract "github.com/d4rpell/Ariadne/pkg/evidence"
)

// Integration tests of the sanitized PodList adapter (ADR-0025 A.12.1 rows
// "Source and time", "Integration" and "Evaluator", A.12.3 F12 and A.13). They
// live in the external package bundle_test on purpose: the pipeline
// parse -> normalize -> build -> encode/write, and the evaluator and report
// consumers, are exercised through their exported surface only.
//
// Everything here is synthetic. The tests do not open a file, do not read a
// clock, do not run a collector and do not sanitize anything themselves.

// TestA201SourceAndValueHash is the row "Source and time" of A.12.1: the
// source hash is the SHA-256 of every byte of the admitted document, the value
// hash is the SHA-256 of the exact decoded value bytes, and the observation
// time is the declared instant, never a clock.
//
// What this acredits: the exact preimages of both hashes, computed here with
// crypto/sha256 and encoding/hex independently of the production helpers.
// What it does not acredita: any remote acquisition, any prefix or
// reserialization as a source hash (the prefix-hash control below shows the
// difference), or the authenticity of the declared instant.
func TestA201SourceAndValueHash(t *testing.T) {
	context := a201Context(t, a201ObservedMoment, contract.TerminationFinished)
	compact := a201CompleteDocument("uid-0001", "payments-api")
	// The same semantics with different whitespace between tokens: valid JSON,
	// different bytes.
	spaced := strings.ReplaceAll(compact, `","`, `", "`)
	if spaced == compact {
		t.Fatal("the whitespace variant must differ in bytes")
	}

	t.Run("whitespace changes the source hash and not the value hash", func(t *testing.T) {
		compactBundle, _ := a201BuildPipeline(t, compact, context)
		spacedBundle, _ := a201BuildPipeline(t, spaced, context)
		if len(compactBundle.Evidence) != 1 || len(spacedBundle.Evidence) != 1 {
			t.Fatalf("evidence = %d/%d, want one item per bundle", len(compactBundle.Evidence), len(spacedBundle.Evidence))
		}
		compactItem := compactBundle.Evidence[0]
		spacedItem := spacedBundle.Evidence[0]
		if compactItem.Value == nil || spacedItem.Value == nil || *compactItem.Value != a201ImageID {
			t.Fatalf("values = %v/%v, want the observed imageID", compactItem.Value, spacedItem.Value)
		}
		// Independent oracle: SHA-256 over the exact bytes of the whole document,
		// whitespace included.
		if got, want := string(compactItem.SourceHash), a201IndependentHash([]byte(compact)); got != want {
			t.Fatalf("compact source hash = %q, want the independent SHA-256 %q", got, want)
		}
		if got, want := string(spacedItem.SourceHash), a201IndependentHash([]byte(spaced)); got != want {
			t.Fatalf("spaced source hash = %q, want the independent SHA-256 %q", got, want)
		}
		if compactItem.SourceHash == spacedItem.SourceHash {
			t.Fatal("different whitespace must produce a different source hash")
		}
		if !a201IsSha256(string(compactItem.SourceHash)) {
			t.Fatalf("source hash %q is not sha256: plus 64 lowercase hex digits", compactItem.SourceHash)
		}
		if compactBundle.Provenance.Inputs[0].Hash != compactItem.SourceHash {
			t.Fatal("provenance inputs hash diverges from the item source hash")
		}
		// Independent oracle of the value preimage: the exact UTF-8 bytes of the
		// decoded value, without quoting and without a newline.
		if got, want := string(*compactItem.ValueHash), a201IndependentHash([]byte(a201ImageID)); got != want {
			t.Fatalf("value hash = %q, want the independent SHA-256 %q", got, want)
		}
		if *compactItem.ValueHash != *spacedItem.ValueHash {
			t.Fatal("the same decoded value must produce the same value hash")
		}
		// A prefix is not the source: hashing a truncated document differs.
		if a201IndependentHash([]byte(compact[:len(compact)-1])) == string(compactItem.SourceHash) {
			t.Fatal("a prefix hash must not equal the source hash of the whole document")
		}
	})

	t.Run("equivalent JSON escapes share the value hash and change the source hash", func(t *testing.T) {
		escapedImageID := "sha256:" + `\u0061` + strings.Repeat("a", 63)
		escaped := strings.Replace(compact, a201ImageID, escapedImageID, 1)
		if escaped == compact {
			t.Fatal("the escaped variant must differ in bytes")
		}
		escapedBundle, _ := a201BuildPipeline(t, escaped, context)
		compactBundle, _ := a201BuildPipeline(t, compact, context)
		if len(escapedBundle.Evidence) != 1 {
			t.Fatalf("evidence = %d, want one item", len(escapedBundle.Evidence))
		}
		item := escapedBundle.Evidence[0]
		if item.Value == nil || *item.Value != a201ImageID {
			t.Fatalf("value = %v, want the decoded value %q", item.Value, a201ImageID)
		}
		if got, want := string(*item.ValueHash), a201IndependentHash([]byte(a201ImageID)); got != want {
			t.Fatalf("value hash = %q, want %q", got, want)
		}
		if *item.ValueHash != *compactBundle.Evidence[0].ValueHash {
			t.Fatal("equivalent escapes must share the value hash")
		}
		if item.SourceHash == compactBundle.Evidence[0].SourceHash {
			t.Fatal("equivalent escapes may and must change the source hash of exact bytes")
		}
		if got, want := string(item.SourceHash), a201IndependentHash([]byte(escaped)); got != want {
			t.Fatalf("escaped source hash = %q, want %q", got, want)
		}
	})

	t.Run("observed_at is the declared instant and never a clock", func(t *testing.T) {
		parsed := a201Parse(t, compact, context)
		observation := a201Normalize(t, parsed)
		built, _ := a201Build(t, observation, 0)
		if len(built.Evidence) != 1 || built.Evidence[0].ObservedAt == nil {
			t.Fatalf("evidence = %+v, want one item with an observation time", built.Evidence)
		}
		declared := context.ObservedAt
		if !built.Evidence[0].ObservedAt.Time.Equal(declared) {
			t.Fatalf("observed_at = %v, want the declared context instant %v", built.Evidence[0].ObservedAt.Time, declared)
		}
		if got := built.Evidence[0].ObservedAt.UTC().Format(time.RFC3339); got != a201ObservedMoment {
			t.Fatalf("observed_at = %q, want the literal %q", got, a201ObservedMoment)
		}
		if built.Images[0].ObservedAt == nil || !built.Images[0].ObservedAt.Time.Equal(declared) {
			t.Fatalf("image observed_at = %v, want the declared instant", built.Images[0].ObservedAt)
		}
		// Two builds of the same input carry the identical instant: nothing here
		// reads the wall clock.
		second, _ := a201Build(t, observation, 0)
		if !second.Evidence[0].ObservedAt.Time.Equal(built.Evidence[0].ObservedAt.Time) {
			t.Fatal("two builds of the same input must not read a clock")
		}
		// The retained instant is the one the export declared: another instant
		// supplied by the caller is refused instead of replacing it, so nothing
		// here can be read from a clock or substituted after the fact.
		otherMoment := a201ObservedAt(t, "2026-09-29T08:30:00Z")
		otherStamp, err := contract.NewTimestamp(otherMoment)
		if err != nil {
			t.Fatalf("timestamp: %v", err)
		}
		input := a201ObservationInput(observation, 0)
		input.ObservedAt = &otherStamp
		if _, _, err := bundle.BuildObservation(input); err == nil {
			t.Fatal("a substituted observation time was accepted")
		}
		// The declared instant still builds, and it is the one that reaches the
		// evidence and the images.
		declaredInput := a201ObservationInput(observation, 0)
		declaredBuilt, _, err := bundle.BuildObservation(declaredInput)
		if err != nil {
			t.Fatalf("build with the declared instant: %v", err)
		}
		if got := declaredBuilt.Evidence[0].ObservedAt.UTC().Format(time.RFC3339); got != a201ObservedMoment {
			t.Fatalf("observed_at = %q, want the declared %q", got, a201ObservedMoment)
		}
	})
}

// TestA201AdapterIntegration is the row "Integration" of A.12.1: the whole
// parse -> normalize -> build path produces a wire 0.2 bundle with the fixed
// provenance of A.9.4, only container_status.image_id as emitted evidence, and
// a conservative image identity. Incoherent DTOs between stages are refused
// with a static error and a zero bundle.
//
// What this acredits: the projection of the adapter over its own carriers.
// What it does not acredita: any real capture, any RBAC, any manifest or
// platform proof, and any evaluator conclusion.
func TestA201AdapterIntegration(t *testing.T) {
	context := a201Context(t, a201ObservedMoment, contract.TerminationFinished)
	document := a201CompleteDocument("uid-0001", "payments-api")
	parsed := a201Parse(t, document, context)
	observation := a201Normalize(t, parsed)
	built, diagnostics, err := bundle.BuildObservation(a201ObservationInput(observation, 0))
	if err != nil {
		t.Fatalf("build observation: %v", err)
	}
	if len(diagnostics.Omitted) != 0 {
		t.Fatalf("omissions = %v, want none", diagnostics.Omitted)
	}

	if built.SchemaVersion != contract.SchemaVersionSupported {
		t.Fatalf("schema version = %q", built.SchemaVersion)
	}
	if built.Subject.UID != "uid-0001" || built.Subject.Namespace != a201Namespace || built.Subject.Kind != "Pod" {
		t.Fatalf("subject = %+v", built.Subject)
	}
	if built.Subject.OwnerChain != "" {
		t.Fatal("owner_chain must stay absent: a list of references is not a resolved chain")
	}
	provenance := built.Provenance
	if provenance.Coverage.Method != contract.CoverageContainerObservation {
		t.Fatalf("coverage method = %q", provenance.Coverage.Method)
	}
	if provenance.Coverage.Rows != nil {
		t.Fatal("coverage rows must stay null for a container observation")
	}
	if provenance.Consistency != contract.ConsistencyNotAtomic {
		t.Fatalf("consistency = %q, want not-atomic", provenance.Consistency)
	}
	if provenance.RedactionPolicy != "sanitized-podlist-v1/1.0" {
		t.Fatalf("redaction policy = %q", provenance.RedactionPolicy)
	}
	if provenance.CollectorVersion != "operator-export" {
		t.Fatalf("collector version = %q, want the declared static label", provenance.CollectorVersion)
	}
	if provenance.ParserVersion != a201Parser {
		t.Fatalf("parser version = %q", provenance.ParserVersion)
	}
	if provenance.ArgvSanitized == nil || len(provenance.ArgvSanitized) != 0 {
		t.Fatalf("argv_sanitized = %v, want an explicit empty array", provenance.ArgvSanitized)
	}
	if len(provenance.APIScope.Namespaces) != 1 || provenance.APIScope.Namespaces[0] != a201Namespace {
		t.Fatalf("api_scope.namespaces = %v", provenance.APIScope.Namespaces)
	}
	if len(provenance.APIScope.Resources) != 1 || provenance.APIScope.Resources[0] != "pods" {
		t.Fatalf("api_scope.resources = %v", provenance.APIScope.Resources)
	}
	if provenance.APIScope.Verbs == nil || len(provenance.APIScope.Verbs) != 0 {
		t.Fatal("no API call was executed or verified and no verb may be declared")
	}
	if len(provenance.Inputs) != 1 || provenance.Inputs[0].Path != a201SourceName {
		t.Fatalf("inputs = %+v, want exactly the admitted source alias", provenance.Inputs)
	}
	if string(provenance.Inputs[0].Hash) != a201IndependentHash([]byte(document)) {
		t.Fatal("the input hash must be the source hash of the exact admitted bytes")
	}

	if len(built.Images) != 1 {
		t.Fatalf("images = %d, want one", len(built.Images))
	}
	for _, image := range built.Images {
		if image.NormalizedDigest != nil {
			t.Fatal("a PodList never promotes a guaranteed digest")
		}
		if image.Platform.Status != contract.PlatformUnknown || image.Platform.OS != "" || image.Platform.Architecture != "" {
			t.Fatalf("platform = %+v, want unknown and no inferred values", image.Platform)
		}
	}
	if len(built.Evidence) != 1 {
		t.Fatalf("evidence = %d, want exactly the observed imageID item", len(built.Evidence))
	}
	item := built.Evidence[0]
	if item.Type != "container_status.image_id" {
		t.Fatalf("evidence type = %q, want the only emitted type", item.Type)
	}
	if item.Scope.SubjectUID != "uid-0001" || item.Scope.ContainerName != "api" {
		t.Fatalf("scope = %+v, want the subject UID and the container name", item.Scope)
	}
	if item.Locator != "items[0].status.containerStatuses[0].imageID" {
		t.Fatalf("locator = %q, want the original path", item.Locator)
	}
	if item.Value == nil || *item.Value != a201ImageID {
		t.Fatalf("value = %v, want the observed imageID", item.Value)
	}
	if got, want := string(*item.ValueHash), a201IndependentHash([]byte(a201ImageID)); got != want {
		t.Fatalf("value hash = %q, want %q", got, want)
	}
	if item.Confidence != contract.ProvenanceObserved {
		t.Fatalf("confidence = %q, want observed", item.Confidence)
	}

	t.Run("incoherent intermediate DTOs are refused with a zero bundle", func(t *testing.T) {
		cases := []struct {
			name   string
			mutate func(*bundle.ObservationInput)
		}{
			{"subject index out of range", func(input *bundle.ObservationInput) { input.SubjectIndex = 7 }},
			{"negative subject index", func(input *bundle.ObservationInput) { input.SubjectIndex = -1 }},
			{"source hash without the sha256 prefix", func(input *bundle.ObservationInput) {
				input.Result.Source.Hash = contract.SourceHash(strings.Repeat("a", 64))
			}},
			{"short source hash", func(input *bundle.ObservationInput) {
				input.Result.Source.Hash = contract.SourceHash("sha256:short")
			}},
			{"empty namespace", func(input *bundle.ObservationInput) { input.Result.Namespace = "" }},
		}
		for _, testCase := range cases {
			t.Run(testCase.name, func(t *testing.T) {
				input := a201ObservationInput(observation, 0)
				testCase.mutate(&input)
				refused, _, err := bundle.BuildObservation(input)
				if err == nil {
					t.Fatal("an incoherent DTO must be refused")
				}
				if !reflect.DeepEqual(refused, contract.Bundle{}) {
					t.Fatalf("a refused DTO produced a bundle: %+v", refused)
				}
			})
		}
	})
}

// TestA201EvaluatorConservative is the row "Evaluator" of A.12.1 and I-29:
// incomplete observations, a raw image id without a proven digest, a
// contradictory warning and an evidence reference outside the observed scope
// never sustain a favourable conclusion.
//
// The pack used here asks for "not_affected" through the product profile, so
// the cases are not vacuous: a favourable conclusion is the declared intent of
// the pack and the engine still refuses it with visible reasons.
//
// What this acredits: the evaluator never resolves these observation-derived
// bundles to a favourable state, and each case names its concrete blocker.
// What it does not acredita: that a favourable baseline with fabricated
// prisma_v1 findings and a proven digest would be accepted (no such control is
// built here), nor that any statement about the real workload was checked.
func TestA201EvaluatorConservative(t *testing.T) {
	finished := a201Context(t, a201ObservedMoment, contract.TerminationFinished)
	targetFor := func(built contract.Bundle, container string) evaluator.Target {
		locator := "items[0].status.containerStatuses[0].imageID"
		for _, item := range built.Evidence {
			if item.Scope.ContainerName == contract.ContainerName(container) {
				locator = string(item.Locator)
			}
		}
		observedAt := *built.Images[0].ObservedAt
		return a201Target(built, "CVE-2026-12345", container, locator, observedAt)
	}

	t.Run("an incomplete observation does not sustain a conclusion", func(t *testing.T) {
		aborted := a201Context(t, a201ObservedMoment, contract.TerminationAborted)
		completeDoc := a201CompleteDocument("uid-0001", "payments-api")
		abortedBundle, _ := a201BuildPipeline(t, completeDoc, aborted)
		result := a201Evaluate(t, abortedBundle, targetFor(abortedBundle, "api"))
		if result.ProductStatus != contract.ProductUnderInvestigation {
			t.Fatalf("product status = %q, want under_investigation", result.ProductStatus)
		}
		if len(result.Candidates) != 0 {
			t.Fatalf("candidates = %+v, want none", result.Candidates)
		}
		if !a201HasReason(result.Reasons, evaluator.ReasonIncompleteEvidence) {
			t.Fatalf("reasons = %v, want incomplete_evidence", result.Reasons)
		}
		a201RequireMissing(t, result, rulepack.RequirementBundleComplete)

		// The same rejection with a finished capture that omitted a category: the
		// init arrays are absent, never rewritten as empty ones.
		partialSpec := `{"containers":` + a201Array(a201SpecContainer("api", a201DefaultImage)) + `,"ephemeralContainers":` + a201EmptyArray() + `}`
		partialStatus := `{"containerStatuses":` + a201Array(a201StatusContainer("api", a201ImageID)) + `,"ephemeralContainerStatuses":` + a201EmptyArray() + `}`
		partialDoc := a201List(a201PodWithStatus("uid-0001", "payments-api", partialSpec, partialStatus))
		partialBundle, _ := a201BuildPipeline(t, partialDoc, finished)
		partialResult := a201Evaluate(t, partialBundle, targetFor(partialBundle, "api"))
		if partialResult.ProductStatus != contract.ProductUnderInvestigation {
			t.Fatalf("product status = %q, want under_investigation for an omitted category", partialResult.ProductStatus)
		}
		if !a201HasReason(partialResult.Reasons, evaluator.ReasonIncompleteEvidence) {
			t.Fatalf("reasons = %v, want incomplete_evidence", partialResult.Reasons)
		}
		a201RequireMissing(t, partialResult, rulepack.RequirementBundleComplete)
	})

	t.Run("a raw image id without a proven digest does not sustain a conclusion", func(t *testing.T) {
		built, _ := a201BuildPipeline(t, a201CompleteDocument("uid-0001", "payments-api"), finished)
		for _, image := range built.Images {
			if image.NormalizedDigest != nil || image.Platform.Status != contract.PlatformUnknown {
				t.Fatalf("image = %+v, want no digest and unknown platform from this producer", image)
			}
		}
		result := a201Evaluate(t, built, targetFor(built, "api"))
		if result.ProductStatus != contract.ProductUnderInvestigation {
			t.Fatalf("product status = %q, want under_investigation", result.ProductStatus)
		}
		if len(result.Candidates) != 0 {
			t.Fatalf("candidates = %+v, want none", result.Candidates)
		}
		if !a201HasReason(result.Reasons, evaluator.ReasonTargetUnsubstantiated) {
			t.Fatalf("reasons = %v, want target_unsubstantiated", result.Reasons)
		}
		a201RequireMissing(t, result, rulepack.RequirementImageBoundDigest)
	})

	t.Run("a contradictory warning does not sustain a conclusion", func(t *testing.T) {
		// One container name in two classes: the collided key is omitted and the
		// bundle carries the contradictory scope_mismatch warning.
		spec := a201Spec(
			a201Array(a201SpecContainer("api", a201DefaultImage), a201SpecContainer("worker", a201DefaultImage)),
			a201EmptyArray(),
			a201Array(a201SpecContainer("api", a201DefaultImage)),
		)
		status := a201StatusArrays(
			a201Array(a201StatusContainer("api", a201ImageID), a201StatusContainer("worker", a201ImageIDOther)),
			a201EmptyArray(),
			a201Array(a201StatusContainer("api", a201ImageID)),
		)
		document := a201List(a201PodWithStatus("uid-0001", "payments-api", spec, status))
		collided, _ := a201BuildPipeline(t, document, finished)
		if !a201HasWarning(collided, "scope_mismatch", contract.WarningContradictory) {
			t.Fatalf("warnings = %+v, want the contradictory scope_mismatch", collided.Provenance.Warnings)
		}
		result := a201Evaluate(t, collided, targetFor(collided, "worker"))
		if result.ProductStatus != contract.ProductUnderInvestigation {
			t.Fatalf("product status = %q, want under_investigation", result.ProductStatus)
		}
		if !a201HasReason(result.Reasons, evaluator.ReasonBlockingWarning) {
			t.Fatalf("reasons = %v, want blocking_warning", result.Reasons)
		}
		// The blocking warning is the scope_mismatch one and it is referenced.
		warningIndex := -1
		for index, warning := range collided.Provenance.Warnings {
			if warning.Code == "scope_mismatch" {
				warningIndex = index
			}
		}
		referenced := false
		for _, reference := range result.WarningReferences {
			if reference.Origin == evaluator.WarningFromProvenance && reference.WarningIndex == warningIndex {
				referenced = true
			}
		}
		if !referenced {
			t.Fatalf("warning references = %+v, want the scope_mismatch occurrence", result.WarningReferences)
		}
	})

	t.Run("an evidence reference outside the observed scope does not sustain a conclusion", func(t *testing.T) {
		spec := a201Spec(
			a201Array(a201SpecContainer("api", a201DefaultImage), a201SpecContainer("probe", a201DefaultImage)),
			a201EmptyArray(),
			a201EmptyArray(),
		)
		status := a201StatusArrays(
			a201Array(a201StatusContainer("api", a201ImageID), a201StatusContainer("probe", a201ImageIDOther)),
			a201EmptyArray(),
			a201EmptyArray(),
		)
		document := a201List(a201PodWithStatus("uid-0001", "payments-api", spec, status))
		built, _ := a201BuildPipeline(t, document, finished)
		if len(built.Evidence) != 2 {
			t.Fatalf("evidence = %d, want one item per container", len(built.Evidence))
		}
		// The target cites, byte by byte, a real row of the bundle: source, source
		// hash, locator and instant all resolve to the "api" item. Only the scope
		// differs: the target asks about the "probe" container.
		apiItem := built.Evidence[0]
		if apiItem.Scope.ContainerName != "api" {
			t.Fatalf("item scope = %+v, want the api container", apiItem.Scope)
		}
		target := a201Target(built, "CVE-2026-12345", "probe", string(apiItem.Locator), *apiItem.ObservedAt)
		if target.Locator != apiItem.Locator || target.Source != apiItem.Source || target.SourceHash != apiItem.SourceHash {
			t.Fatal("the citation must resolve to the real api item of the bundle")
		}
		result := a201Evaluate(t, built, target)
		if result.ProductStatus != contract.ProductUnderInvestigation {
			t.Fatalf("product status = %q, want under_investigation", result.ProductStatus)
		}
		if len(result.Candidates) != 0 {
			t.Fatalf("candidates = %+v, want none", result.Candidates)
		}
		// The engine admitted no operand at all: an item whose scope does not cover
		// the target is never an evidence reference, however exact its citation.
		if len(result.EvidenceReferences) != 0 {
			t.Fatalf("evidence references = %+v, want an out-of-scope item to stay out", result.EvidenceReferences)
		}
		if !a201HasReason(result.Reasons, evaluator.ReasonTargetUnsubstantiated) {
			t.Fatalf("reasons = %v, want target_unsubstantiated", result.Reasons)
		}
		a201RequireMissing(t, result, rulepack.RequirementImageBoundDigest)
	})
}

// a201BoundaryCase is one F12 rejection vector: a synthetic document (or
// reader) that carries a distinct marker inside a forbidden place, the context
// that must reject it and the exact sanitized message the parser owes.
type a201BoundaryCase struct {
	name      string
	document  string
	reader    readerFactory
	context   func(t *testing.T) ingest.PodListContext
	markers   []string
	wantError string
}

// readerFactory builds the reader of one case. Most cases deliver their
// document through a plain strings.Reader; the reader-error case needs a
// reader that fails with an unsanitized message.
type readerFactory func(t *testing.T, document string) readerWithCount

// readerWithCount is the minimal reader surface the harness needs: the parse
// call and, for the context case, the read counter.
type readerWithCount interface {
	Read(buffer []byte) (int, error)
	Reads() int
}

type a201PlainReader struct{ reader *strings.Reader }

func (reader *a201PlainReader) Read(buffer []byte) (int, error) { return reader.reader.Read(buffer) }
func (reader *a201PlainReader) Reads() int                      { return 0 }

type a201CountedErrorReader struct{ inner *a201ErrorReader }

func (reader *a201CountedErrorReader) Read(buffer []byte) (int, error) {
	return reader.inner.Read(buffer)
}
func (reader *a201CountedErrorReader) Reads() int { return 0 }

type a201CountedReader struct{ inner *a201CountingReader }

func (reader *a201CountedReader) Read(buffer []byte) (int, error) { return reader.inner.Read(buffer) }
func (reader *a201CountedReader) Reads() int                      { return reader.inner.reads }

// TestA201F12PersistenceBoundary is A.12.3: synthetic markers are placed in an
// env value, args, annotations, a status message, a Secret/ConfigMap data
// field, an unknown key, a reader error and an invalid context argument. Each
// vector must be rejected before the value is extracted, must leave no marker
// in the error, the diagnostics or the result, must publish no source hash, and
// must reach the real bundle and report write paths with zero write calls.
//
// What this acredits: the admission and output boundary of Ariadne. What it
// does not acredita: that an external sanitizer ran before a previous
// persistence, or that a marker hidden inside an admitted name or image
// reference would be detected.
func TestA201F12PersistenceBoundary(t *testing.T) {
	t.Run("markers never cross the rejection boundary", func(t *testing.T) {
		for _, testCase := range a201BoundaryCases() {
			t.Run(testCase.name, func(t *testing.T) {
				a201AssertBoundaryRejection(t, testCase)
			})
		}
	})

	t.Run("a properly sanitized document does cross the boundary", func(t *testing.T) {
		document := a201CompleteDocument("uid-0001", "payments-api")
		context := a201Context(t, a201ObservedMoment, contract.TerminationFinished)
		parsed := a201Parse(t, document, context)
		observation := a201Normalize(t, parsed)
		built, _ := a201Build(t, observation, 0)

		artifacts, err := bundle.Encode(built)
		if err != nil {
			t.Fatalf("encode: %v", err)
		}
		if len(artifacts.Envelope) == 0 || len(artifacts.HashInput) == 0 {
			t.Fatal("the sanitized control must produce artifact bytes")
		}
		if !a201IsSha256(artifacts.Hash) {
			t.Fatalf("hash = %q, want sha256: plus 64 lowercase hex digits", artifacts.Hash)
		}
		if a201IndependentHash(artifacts.HashInput) != artifacts.Hash {
			t.Fatal("the declared digest must be the SHA-256 of the projection bytes")
		}
		for _, testCase := range a201BoundaryCases() {
			for _, marker := range testCase.markers {
				if strings.Contains(string(artifacts.Envelope), marker) {
					t.Fatalf("marker %q from another case reached the artifacts", marker)
				}
			}
		}

		envelope := &a201SpyWriter{}
		hashInput := &a201SpyWriter{}
		hash := &a201SpyWriter{}
		if err := bundle.Write(built, bundle.Destinations{Envelope: envelope, HashInput: hashInput, Hash: hash}); err != nil {
			t.Fatalf("write: %v", err)
		}
		if envelope.calls != 1 || hashInput.calls != 1 || hash.calls != 1 {
			t.Fatalf("write calls = %d/%d/%d, want three real writes", envelope.calls, hashInput.calls, hash.calls)
		}
		if envelope.bytes == 0 || hashInput.bytes == 0 || hash.bytes == 0 {
			t.Fatal("the control must actually write artifact bytes")
		}
		if !reflect.DeepEqual(envelope.data, artifacts.Envelope) {
			t.Fatal("the written envelope diverges from Encode")
		}
		if string(hash.data) != artifacts.Hash+"\n" {
			t.Fatalf("hash artifact = %q, want the digest plus one LF", hash.data)
		}

		// Report arm: the same evaluation surface a CLI report uses.
		target := a201Target(built, "CVE-2026-12345", "api", "items[0].status.containerStatuses[0].imageID", *built.Evidence[0].ObservedAt)
		result := a201Evaluate(t, built, target)
		reportValue, err := report.Build(result, built)
		if err != nil {
			t.Fatalf("report build: %v", err)
		}
		reportBytes, err := report.JSON(reportValue)
		if err != nil {
			t.Fatalf("report json: %v", err)
		}
		if len(reportBytes) == 0 {
			t.Fatal("the sanitized control must produce report bytes")
		}
		reportWriter := &a201SpyWriter{}
		if _, err := reportWriter.Write(reportBytes); err != nil {
			t.Fatalf("report write: %v", err)
		}
		if reportWriter.calls != 1 || reportWriter.bytes == 0 {
			t.Fatalf("report writes = %d (%d bytes), want one real write", reportWriter.calls, reportWriter.bytes)
		}
	})
}

// a201BoundaryCases builds the F12 vectors. Markers are distinct per vector so
// a leak can be attributed. Every expectation is a literal of ADR-0025 A.10:
// `field_not_allowed` is anchored at the opening quote of the rejected key,
// `read_failed` at the bytes received with the failing read, and
// `invalid_context` at offset 0.
func a201BoundaryCases() []a201BoundaryCase {
	complete := func(spec, status string) string {
		return a201List(a201PodWithStatus("uid-0001", "payments-api", spec, status))
	}
	regularOnly := func(spec string) string {
		return complete(spec, a201StatusArrays(a201Array(a201StatusContainer("api", a201ImageID)), a201EmptyArray(), a201EmptyArray()))
	}
	envDocument := regularOnly(a201Spec(
		a201Array(`{"name":"api","image":"`+a201DefaultImage+`","env":[{"name":"TOKEN","value":"MARKER_ENV_VALUE"}]}`),
		a201EmptyArray(), a201EmptyArray(),
	))
	undecodableEnvDocument := regularOnly(a201Spec(
		a201Array(`{"name":"api","image":"`+a201DefaultImage+`","env":[{"name":"TOKEN","value":"\q MARKER_ENV_ESCAPE"}]}`),
		a201EmptyArray(), a201EmptyArray(),
	))
	argsDocument := regularOnly(a201Spec(
		a201Array(`{"name":"api","image":"`+a201DefaultImage+`","args":["MARKER_ARGS_VALUE"]}`),
		a201EmptyArray(), a201EmptyArray(),
	))
	annotationsDocument := `{"apiVersion":"v1","kind":"PodList","items":[{"apiVersion":"v1","kind":"Pod","metadata":{"uid":"uid-0001","namespace":"` + a201Namespace + `","name":"payments-api","annotations":{"note":"MARKER_ANNOTATION_VALUE"}},"spec":` + a201Spec(a201Array(a201SpecContainer("api", a201DefaultImage)), a201EmptyArray(), a201EmptyArray()) + `,"status":` + a201StatusArrays(a201Array(a201StatusContainer("api", a201ImageID)), a201EmptyArray(), a201EmptyArray()) + `}]}`
	stateDocument := complete(
		a201Spec(a201Array(a201SpecContainer("api", a201DefaultImage)), a201EmptyArray(), a201EmptyArray()),
		a201StatusArrays(a201Array(`{"name":"api","imageID":"`+a201ImageID+`","state":{"waiting":{"message":"MARKER_STATE_MESSAGE"}}}`), a201EmptyArray(), a201EmptyArray()),
	)
	secretDocument := a201List(`{"apiVersion":"v1","kind":"Secret","metadata":{"uid":"uid-0001","namespace":"` + a201Namespace + `","name":"payments-api"},"data":{"password":"MARKER_SECRET_VALUE"},"stringData":{"token":"MARKER_STRINGDATA_VALUE"}}`)
	configMapDocument := a201List(`{"apiVersion":"v1","kind":"ConfigMap","metadata":{"uid":"uid-0001","namespace":"` + a201Namespace + `","name":"payments-api"},"stringData":{"token":"MARKER_CONFIGMAP_VALUE"}}`)
	unknownKeyDocument := `{"apiVersion":"v1","kind":"PodList","items":[],"unknownField":"MARKER_UNKNOWN_VALUE"}`
	readerErrorDocument := `{"k`
	const (
		fieldNotAllowed = "field is not allowed by the redaction profile"
	)
	message := func(code string, offset int, text string) string {
		return "ingest: sanitized-podlist-v1: byte/" + itoaForBoundary(offset) + ": " + text
	}
	contextCase := func(name string, mutate func(*ingest.PodListContext), reader readerFactory, markers []string) a201BoundaryCase {
		return a201BoundaryCase{
			name:     name,
			document: "",
			reader:   reader,
			context: func(t *testing.T) ingest.PodListContext {
				context := a201Context(t, a201ObservedMoment, contract.TerminationFinished)
				mutate(&context)
				return context
			},
			markers:   markers,
			wantError: message("invalid_context", 0, "invalid observation context"),
		}
	}
	plain := func(document string) readerFactory {
		return func(t *testing.T, input string) readerWithCount {
			return &a201PlainReader{reader: strings.NewReader(input)}
		}
	}
	return []a201BoundaryCase{
		{
			name:     "env value",
			document: envDocument,
			reader:   plain(envDocument),
			context: func(t *testing.T) ingest.PodListContext {
				return a201Context(t, a201ObservedMoment, contract.TerminationFinished)
			},
			markers:   []string{"MARKER_ENV_VALUE"},
			wantError: message("field_not_allowed", strings.Index(envDocument, `"env"`), fieldNotAllowed),
		},
		{
			name:     "undecodable value behind a prohibited key",
			document: undecodableEnvDocument,
			reader:   plain(undecodableEnvDocument),
			context: func(t *testing.T) ingest.PodListContext {
				return a201Context(t, a201ObservedMoment, contract.TerminationFinished)
			},
			markers:   []string{"MARKER_ENV_ESCAPE"},
			wantError: message("field_not_allowed", strings.Index(undecodableEnvDocument, `"env"`), fieldNotAllowed),
		},
		{
			name:     "args",
			document: argsDocument,
			reader:   plain(argsDocument),
			context: func(t *testing.T) ingest.PodListContext {
				return a201Context(t, a201ObservedMoment, contract.TerminationFinished)
			},
			markers:   []string{"MARKER_ARGS_VALUE"},
			wantError: message("field_not_allowed", strings.Index(argsDocument, `"args"`), fieldNotAllowed),
		},
		{
			name:     "annotations",
			document: annotationsDocument,
			reader:   plain(annotationsDocument),
			context: func(t *testing.T) ingest.PodListContext {
				return a201Context(t, a201ObservedMoment, contract.TerminationFinished)
			},
			markers:   []string{"MARKER_ANNOTATION_VALUE"},
			wantError: message("field_not_allowed", strings.Index(annotationsDocument, `"annotations"`), fieldNotAllowed),
		},
		{
			name:     "status message",
			document: stateDocument,
			reader:   plain(stateDocument),
			context: func(t *testing.T) ingest.PodListContext {
				return a201Context(t, a201ObservedMoment, contract.TerminationFinished)
			},
			markers:   []string{"MARKER_STATE_MESSAGE"},
			wantError: message("field_not_allowed", strings.Index(stateDocument, `"message"`), fieldNotAllowed),
		},
		{
			name:     "Secret data",
			document: secretDocument,
			reader:   plain(secretDocument),
			context: func(t *testing.T) ingest.PodListContext {
				return a201Context(t, a201ObservedMoment, contract.TerminationFinished)
			},
			markers:   []string{"MARKER_SECRET_VALUE", "MARKER_STRINGDATA_VALUE"},
			wantError: message("field_not_allowed", strings.Index(secretDocument, `"data"`), fieldNotAllowed),
		},
		{
			name:     "ConfigMap stringData",
			document: configMapDocument,
			reader:   plain(configMapDocument),
			context: func(t *testing.T) ingest.PodListContext {
				return a201Context(t, a201ObservedMoment, contract.TerminationFinished)
			},
			markers:   []string{"MARKER_CONFIGMAP_VALUE"},
			wantError: message("field_not_allowed", strings.Index(configMapDocument, `"stringData"`), fieldNotAllowed),
		},
		{
			name:     "unknown key",
			document: unknownKeyDocument,
			reader:   plain(unknownKeyDocument),
			context: func(t *testing.T) ingest.PodListContext {
				return a201Context(t, a201ObservedMoment, contract.TerminationFinished)
			},
			markers:   []string{"MARKER_UNKNOWN_VALUE"},
			wantError: message("field_not_allowed", strings.Index(unknownKeyDocument, `"unknownField"`), fieldNotAllowed),
		},
		{
			name:     "reader error",
			document: readerErrorDocument,
			reader: func(t *testing.T, input string) readerWithCount {
				return &a201CountedErrorReader{inner: &a201ErrorReader{data: []byte(input), err: a201MarkerError("MARKER_READER_ERROR")}}
			},
			context: func(t *testing.T) ingest.PodListContext {
				return a201Context(t, a201ObservedMoment, contract.TerminationFinished)
			},
			markers:   []string{"MARKER_READER_ERROR"},
			wantError: message("read_failed", 3, "input read failed"),
		},
		contextCase("invalid context termination",
			func(context *ingest.PodListContext) {
				context.CaptureTermination = contract.CoverageTermination("MARKER_TERMINATION")
			},
			func(t *testing.T, input string) readerWithCount {
				return &a201CountedReader{inner: &a201CountingReader{}}
			},
			[]string{"MARKER_TERMINATION"}),
		contextCase("invalid source alias",
			func(context *ingest.PodListContext) { context.SourceName = "bad alias MARKER_ALIAS" },
			func(t *testing.T, input string) readerWithCount {
				return &a201CountedReader{inner: &a201CountingReader{}}
			},
			[]string{"MARKER_ALIAS"}),
	}
}

// a201AssertBoundaryRejection runs one F12 vector through the real pipeline and
// fails on the first published marker, the first write call or the first
// invented artifact. The downstream calls are the real ones and receive
// exactly what the pipeline produced: nothing publishable.
func a201AssertBoundaryRejection(t *testing.T, testCase a201BoundaryCase) {
	t.Helper()
	reader := testCase.reader(t, testCase.document)
	parsed, err := ingest.ParseSanitizedPodList(reader, testCase.context(t))
	if err == nil {
		t.Fatal("a forbidden placement must be rejected")
	}
	if err.Error() != testCase.wantError {
		t.Fatalf("error = %q, want the exact sanitized message %q", err, testCase.wantError)
	}
	for _, marker := range testCase.markers {
		if strings.Contains(err.Error(), marker) {
			t.Fatalf("marker %q leaked into the error", marker)
		}
	}
	// No publicable source: a rejected source has no hash, no observations and no
	// accounting for a prefix.
	if parsed.Source != nil {
		t.Fatal("a rejected source must not carry a publicable source or hash")
	}
	if len(parsed.Subjects) != 0 || parsed.Accepted != 0 || parsed.Rejected != 0 {
		t.Fatalf("rejected source published subjects/accounting: %+v", parsed)
	}
	for _, rendered := range a201FormattedDiagnostics(parsed) {
		for _, marker := range testCase.markers {
			if strings.Contains(rendered, marker) {
				t.Fatalf("marker %q leaked into a formatted diagnostic %q", marker, rendered)
			}
		}
	}
	// The reader of an invalid context is never consumed. The reader-error and
	// document vectors carry their own reader, so the check keys on the empty
	// document of the context vectors.
	if counted, ok := reader.(interface{ Reads() int }); ok && testCase.document == "" {
		if counted.Reads() != 0 {
			t.Fatalf("reader reads = %d, want zero for a rejected context", counted.Reads())
		}
	}

	// Downstream stages receive the empty result and refuse it.
	observation, normalizeErr := normalize.NormalizePodList(parsed)
	if normalizeErr == nil {
		t.Fatal("normalize must refuse a source that was not admitted")
	}
	if !a201ObservationIsEmpty(observation) {
		t.Fatalf("normalize published an observation: %+v", observation)
	}
	built, diagnostics, buildErr := bundle.BuildObservation(a201ObservationInput(observation, 0))
	if buildErr == nil {
		t.Fatal("build must refuse a zero observation")
	}
	if !reflect.DeepEqual(built, contract.Bundle{}) {
		t.Fatalf("build published a bundle: %+v", built)
	}
	if len(diagnostics.Omitted) != 0 {
		t.Fatalf("diagnostics = %+v, want none", diagnostics)
	}
	artifacts, encodeErr := bundle.Encode(built)
	if encodeErr == nil || len(artifacts.Envelope) != 0 || len(artifacts.HashInput) != 0 || artifacts.Hash != "" {
		t.Fatalf("a refused DTO produced artifacts: %+v, err = %v", artifacts, encodeErr)
	}
	envelope := &a201SpyWriter{}
	hashInput := &a201SpyWriter{}
	hash := &a201SpyWriter{}
	if writeErr := bundle.Write(built, bundle.Destinations{Envelope: envelope, HashInput: hashInput, Hash: hash}); writeErr == nil {
		t.Fatal("write must refuse a zero bundle")
	}
	// Report path: the same evaluation surface a caller would use next.
	reportValue, reportErr := report.Build(evaluator.Result{}, built)
	if reportErr == nil {
		t.Fatal("report building must refuse a zero result and bundle")
	}
	reportBytes, jsonErr := report.JSON(reportValue)
	if jsonErr == nil || len(reportBytes) != 0 {
		t.Fatalf("report JSON = %q, err = %v; want no bytes", reportBytes, jsonErr)
	}
	htmlBytes, htmlErr := report.HTML(reportValue)
	if htmlErr == nil || len(htmlBytes) != 0 {
		t.Fatalf("report HTML produced %d bytes, err = %v; want no bytes", len(htmlBytes), htmlErr)
	}
	if envelope.calls != 0 || hashInput.calls != 0 || hash.calls != 0 {
		t.Fatalf("write calls = %d/%d/%d, want zero after a rejection", envelope.calls, hashInput.calls, hash.calls)
	}
}

// itoaForBoundary renders a non-negative decimal offset for the expected
// message literal, computed independently of the parser.
func itoaForBoundary(value int) string {
	if value < 0 {
		panic("boundary offset is not a byte index")
	}
	if value == 0 {
		return "0"
	}
	digits := []byte{}
	for value > 0 {
		digits = append([]byte{byte('0' + value%10)}, digits...)
		value /= 10
	}
	return string(digits)
}

// TestA201FixtureSequences covers the F01-F08, F12, F13 and F15 sequences of
// A.13. Each subtest states in its own comment what it acredits and which
// limits stay declared: no collector, no real cluster, no external sanitizer
// and no exception lifecycle.
func TestA201FixtureSequences(t *testing.T) {
	t.Run("F01", func(t *testing.T) {
		// F01 acredits: two exports/subjects sharing namespace/name with different
		// UIDs stay separate, neither is merged and no order is read as
		// chronology; the container change per subject is preserved. Limit: no
		// real collector re-read and no ordering semantics.
		podOne := a201CompletePod("uid-0001", "payments-api")
		podTwoSpec := a201Spec(a201Array(a201SpecContainer("worker", a201DefaultImage)), a201EmptyArray(), a201EmptyArray())
		podTwoStatus := a201StatusArrays(a201Array(a201StatusContainer("worker", a201ImageIDOther)), a201EmptyArray(), a201EmptyArray())
		podTwo := a201PodWithStatus("uid-0002", "payments-api", podTwoSpec, podTwoStatus)
		document := a201List(podOne, podTwo)
		context := a201Context(t, a201ObservedMoment, contract.TerminationFinished)
		parsed := a201Parse(t, document, context)
		if parsed.TotalItems == nil || *parsed.TotalItems != 2 || parsed.Accepted != 2 || parsed.Rejected != 0 {
			t.Fatalf("accounting = total %v accepted %d rejected %d, want 2/2/0", parsed.TotalItems, parsed.Accepted, parsed.Rejected)
		}
		observation := a201Normalize(t, parsed)
		if len(observation.Subjects) != 2 {
			t.Fatalf("subjects = %d, want two separate subjects", len(observation.Subjects))
		}
		first, _ := a201Build(t, observation, 0)
		second, _ := a201Build(t, observation, 1)
		if first.Subject.UID != "uid-0001" || second.Subject.UID != "uid-0002" {
			t.Fatalf("uids = %q/%q, want each capture's own UID", first.Subject.UID, second.Subject.UID)
		}
		if first.Subject.Name != "payments-api" || second.Subject.Name != "payments-api" {
			t.Fatal("both subjects share namespace/name and must stay separate")
		}
		if len(first.Images) != 1 || string(first.Images[0].ContainerName) != "api" {
			t.Fatalf("first images = %+v, want only the api container", first.Images)
		}
		if len(second.Images) != 1 || string(second.Images[0].ContainerName) != "worker" {
			t.Fatalf("second images = %+v, want only the worker container", second.Images)
		}
		if first.Evidence[0].Value == nil || *first.Evidence[0].Value != a201ImageID {
			t.Fatalf("first evidence = %v", first.Evidence[0].Value)
		}
		if second.Evidence[0].Value == nil || *second.Evidence[0].Value != a201ImageIDOther {
			t.Fatalf("second evidence = %v", second.Evidence[0].Value)
		}
		for _, built := range []contract.Bundle{first, second} {
			if !a201HasWarning(built, "source_conflict", contract.WarningContradictory) {
				t.Fatalf("warnings = %+v, want source_conflict on both subjects", built.Provenance.Warnings)
			}
			found := false
			for _, failure := range built.Provenance.Errors {
				if strings.HasSuffix(failure, "source contains conflicting Pod identity context") {
					found = true
				}
			}
			if !found {
				t.Fatalf("errors = %v, want the subject_context_conflict diagnostic", built.Provenance.Errors)
			}
		}
	})

	t.Run("F02", func(t *testing.T) {
		// F02 acredits: spec.image is preserved as requested and imageID as raw,
		// independently; a divergent status.image stays internal context and is
		// never promoted. Limit: no proof of the deployed manifest digest.
		spec := a201Spec(a201Array(a201SpecContainer("api", "registry.example/app:release")), a201EmptyArray(), a201EmptyArray())
		status := a201StatusArrays(
			a201Array(`{"name":"api","imageID":"`+a201ImageID+`","image":"registry.example/app:other"}`),
			a201EmptyArray(), a201EmptyArray(),
		)
		document := a201List(a201PodWithStatus("uid-0001", "payments-api", spec, status))
		context := a201Context(t, a201ObservedMoment, contract.TerminationFinished)
		parsed := a201Parse(t, document, context)
		observation := a201Normalize(t, parsed)
		built, _ := a201Build(t, observation, 0)
		if len(observation.Subjects) != 1 || len(observation.Subjects[0].Containers) != 1 {
			t.Fatalf("observation = %+v, want one container", observation.Subjects)
		}
		container := observation.Subjects[0].Containers[0]
		if container.StatusImage == nil || *container.StatusImage != "registry.example/app:other" {
			t.Fatalf("status.image = %v, want the internal context value", container.StatusImage)
		}
		image := built.Images[0]
		if image.RequestedImage == nil || string(*image.RequestedImage) != "registry.example/app:release" {
			t.Fatalf("requested = %v, want the spec declaration", image.RequestedImage)
		}
		if image.RawImageID == nil || string(*image.RawImageID) != a201ImageID {
			t.Fatalf("raw = %v, want the imageID observation", image.RawImageID)
		}
		if string(*image.RequestedImage) == "registry.example/app:other" || string(*image.RawImageID) == "registry.example/app:other" {
			t.Fatal("status.image must never replace requested or raw")
		}
		if len(built.Evidence) != 1 || built.Evidence[0].Value == nil || *built.Evidence[0].Value != a201ImageID {
			t.Fatalf("evidence = %+v, want the imageID value", built.Evidence)
		}
	})

	t.Run("F03", func(t *testing.T) {
		// F03 acredits: an ambiguous or unparseable raw id is preserved verbatim
		// and normalized_digest stays null. Limit: PodList alone gives no
		// guaranteed-digest positive control.
		//
		// Known production finding (not fixed here, reported to the coordinator):
		// when spec.image is absent the ingest stage emits the
		// requested_image_unavailable diagnostic, but normalize.SubjectHasDefect
		// does not count it, so a finished capture with every category complete
		// reaches BuildObservation with completeness=complete and the canonical
		// validator then refuses the whole bundle with
		// "evidence: complete coverage requires no visible errors". Minimal
		// reproduction: a Pod whose spec container has no image and whose status
		// carries an imageID, all six category arrays explicit, termination
		// finished. The fixture below keeps spec.image present on purpose.
		raw := "registry.example/app:not-a-digest"
		document := a201List(a201PodWithStatus("uid-0001", "payments-api",
			a201Spec(a201Array(a201SpecContainer("api", a201DefaultImage)), a201EmptyArray(), a201EmptyArray()),
			a201StatusArrays(a201Array(a201StatusContainer("api", raw)), a201EmptyArray(), a201EmptyArray()),
		))
		context := a201Context(t, a201ObservedMoment, contract.TerminationFinished)
		built, _ := a201BuildPipeline(t, document, context)
		if built.Images[0].RawImageID == nil || string(*built.Images[0].RawImageID) != raw {
			t.Fatalf("raw = %v, want the ambiguous value preserved", built.Images[0].RawImageID)
		}
		if built.Images[0].NormalizedDigest != nil {
			t.Fatal("an ambiguous raw id must never be promoted to a digest")
		}
	})

	t.Run("F04", func(t *testing.T) {
		// F04 acredits: a digest-shaped raw id (and a spec image carrying a
		// digest) is never promoted to normalized_digest, and no platform is
		// inferred. Limit: no real manifest or platform observation.
		digestShaped := "registry.example/app@sha256:" + strings.Repeat("c", 64)
		document := a201List(a201PodWithStatus("uid-0001", "payments-api",
			a201Spec(a201Array(a201SpecContainer("api", digestShaped)), a201EmptyArray(), a201EmptyArray()),
			a201StatusArrays(a201Array(a201StatusContainer("api", digestShaped)), a201EmptyArray(), a201EmptyArray()),
		))
		context := a201Context(t, a201ObservedMoment, contract.TerminationFinished)
		built, _ := a201BuildPipeline(t, document, context)
		image := built.Images[0]
		if image.RawImageID == nil || string(*image.RawImageID) != digestShaped {
			t.Fatalf("raw = %v, want the digest-shaped value preserved", image.RawImageID)
		}
		if image.RequestedImage == nil || string(*image.RequestedImage) != digestShaped {
			t.Fatalf("requested = %v, want the declared string verbatim", image.RequestedImage)
		}
		if image.NormalizedDigest != nil {
			t.Fatal("a digest-shaped value is not a proven digest")
		}
		if image.Platform.Status != contract.PlatformUnknown || image.Platform.OS != "" || image.Platform.Architecture != "" {
			t.Fatalf("platform = %+v, want unknown with no inference", image.Platform)
		}
	})

	t.Run("F05", func(t *testing.T) {
		// F05 acredits: the three categories, the status join by name inside its
		// category, an explicitly empty category, and a collision that omits only
		// the ambiguous keys while preserving the rest. Limit: no runtime
		// compatibility and no sidecar classification.
		t.Run("name join and explicit empty category", func(t *testing.T) {
			spec := a201Spec(
				a201Array(a201SpecContainer("api", a201DefaultImage), a201SpecContainer("worker", a201DefaultImage)),
				a201EmptyArray(),
				a201EmptyArray(),
			)
			// The statuses are deliberately permuted: the join is by name, never
			// by index.
			status := a201StatusArrays(
				a201Array(a201StatusContainer("worker", a201ImageIDOther), a201StatusContainer("api", a201ImageID)),
				a201EmptyArray(), a201EmptyArray(),
			)
			document := a201List(a201PodWithStatus("uid-0001", "payments-api", spec, status))
			context := a201Context(t, a201ObservedMoment, contract.TerminationFinished)
			built, _ := a201BuildPipeline(t, document, context)
			if len(built.ObservedContainerClasses) != 3 {
				t.Fatalf("observed classes = %v, want the three explicit categories", built.ObservedContainerClasses)
			}
			if len(built.Images) != 2 || len(built.Evidence) != 2 {
				t.Fatalf("images/evidence = %d/%d, want two each", len(built.Images), len(built.Evidence))
			}
			byName := map[string]contract.ImageIdentity{}
			for _, image := range built.Images {
				byName[string(image.ContainerName)] = image
			}
			api := byName["api"]
			worker := byName["worker"]
			if api.RawImageID == nil || string(*api.RawImageID) != a201ImageID {
				t.Fatalf("api raw = %v, want its own status joined by name", api.RawImageID)
			}
			if worker.RawImageID == nil || string(*worker.RawImageID) != a201ImageIDOther {
				t.Fatalf("worker raw = %v, want its own status joined by name", worker.RawImageID)
			}
			for _, item := range built.Evidence {
				switch string(item.Scope.ContainerName) {
				case "api":
					if item.Locator != "items[0].status.containerStatuses[1].imageID" {
						t.Fatalf("api locator = %q, want the original status position", item.Locator)
					}
				case "worker":
					if item.Locator != "items[0].status.containerStatuses[0].imageID" {
						t.Fatalf("worker locator = %q, want the original status position", item.Locator)
					}
				default:
					t.Fatalf("unexpected evidence scope %+v", item.Scope)
				}
			}
		})
		t.Run("collision omits only the ambiguous key", func(t *testing.T) {
			spec := a201Spec(
				a201Array(a201SpecContainer("api", a201DefaultImage), a201SpecContainer("worker", a201DefaultImage)),
				a201EmptyArray(),
				a201Array(a201SpecContainer("api", a201DefaultImage)),
			)
			status := a201StatusArrays(
				a201Array(a201StatusContainer("api", a201ImageID), a201StatusContainer("worker", a201ImageIDOther)),
				a201EmptyArray(),
				a201Array(a201StatusContainer("api", a201ImageID)),
			)
			document := a201List(a201PodWithStatus("uid-0001", "payments-api", spec, status))
			context := a201Context(t, a201ObservedMoment, contract.TerminationFinished)
			parsed := a201Parse(t, document, context)
			observation := a201Normalize(t, parsed)
			built, diagnostics := a201Build(t, observation, 0)
			if len(diagnostics.Omitted) != 2 {
				t.Fatalf("omissions = %+v, want the two collided keys", diagnostics.Omitted)
			}
			for _, omission := range diagnostics.Omitted {
				if omission.Reason != bundle.OmissionCollision {
					t.Fatalf("omission reason = %q, want the static collision reason", omission.Reason)
				}
			}
			if len(built.Images) != 1 || string(built.Images[0].ContainerName) != "worker" {
				t.Fatalf("images = %+v, want only the non-collided container", built.Images)
			}
			if len(built.Evidence) != 1 || built.Evidence[0].Scope.ContainerName != "worker" {
				t.Fatalf("evidence = %+v, want only the non-collided item", built.Evidence)
			}
			if !a201HasWarning(built, "scope_mismatch", contract.WarningContradictory) {
				t.Fatalf("warnings = %+v, want scope_mismatch", built.Provenance.Warnings)
			}
			if !a201HasError(built, "bundle: scope collision omitted") {
				t.Fatalf("errors = %v, want the collision error", built.Provenance.Errors)
			}
			if len(built.ObservedContainerClasses) != 3 {
				t.Fatalf("observed classes = %v, want the categories preserved", built.ObservedContainerClasses)
			}
		})
	})

	t.Run("F06", func(t *testing.T) {
		// F06 acredits: two separate captures, the first with ephemeral explicitly
		// empty and the second with an ephemeral container and its status. Limit:
		// the first capture proves nothing about the future; there is no monitor,
		// no diff and no persisted timeline.
		firstSpec := a201Spec(a201Array(a201SpecContainer("api", a201DefaultImage)), a201EmptyArray(), a201EmptyArray())
		firstStatus := a201StatusArrays(a201Array(a201StatusContainer("api", a201ImageID)), a201EmptyArray(), a201EmptyArray())
		firstDoc := a201List(a201PodWithStatus("uid-0001", "payments-api", firstSpec, firstStatus))
		secondSpec := a201Spec(a201Array(a201SpecContainer("api", a201DefaultImage)), a201EmptyArray(), a201Array(a201SpecContainer("debug", a201DefaultImage)))
		secondStatus := a201StatusArrays(a201Array(a201StatusContainer("api", a201ImageID)), a201EmptyArray(), a201Array(a201StatusContainer("debug", a201ImageIDOther)))
		secondDoc := a201List(a201PodWithStatus("uid-0001", "payments-api", secondSpec, secondStatus))

		firstBundle, _ := a201BuildPipeline(t, firstDoc, a201Context(t, "2026-09-30T10:00:00Z", contract.TerminationFinished))
		secondBundle, _ := a201BuildPipeline(t, secondDoc, a201Context(t, "2026-09-30T14:00:00Z", contract.TerminationFinished))
		for _, image := range firstBundle.Images {
			if image.ContainerName == "debug" {
				t.Fatal("the first capture observed no ephemeral container")
			}
		}
		observed := false
		for _, class := range firstBundle.ObservedContainerClasses {
			if class == contract.ContainerEphemeral {
				observed = true
			}
		}
		if !observed {
			t.Fatal("the first capture observed the ephemeral category as explicitly empty")
		}
		found := false
		for _, image := range secondBundle.Images {
			if image.ContainerName == "debug" && image.RawImageID != nil && string(*image.RawImageID) == a201ImageIDOther {
				found = true
			}
		}
		if !found {
			t.Fatalf("second images = %+v, want the ephemeral container with its status", secondBundle.Images)
		}
		if firstBundle.Evidence[0].SourceHash == secondBundle.Evidence[0].SourceHash {
			t.Fatal("different captures must keep their own source hashes")
		}
		if firstBundle.Evidence[0].ObservedAt.Time.Equal(secondBundle.Evidence[0].ObservedAt.Time) {
			t.Fatal("each capture keeps its declared observation time")
		}
	})

	t.Run("F07", func(t *testing.T) {
		// F07 acredits: the declared time and resourceVersion are preserved per
		// capture and different UIDs stay separate. Limit: this does NOT acredita
		// real stale-status detection; F07 is not closed by this test.
		firstDoc := a201PodWithResourceVersion("uid-0001", "payments-api", "rv-7", a201Spec(a201Array(a201SpecContainer("api", a201DefaultImage)), a201EmptyArray(), a201EmptyArray()), a201StatusArrays(a201Array(a201StatusContainer("api", a201ImageID)), a201EmptyArray(), a201EmptyArray()))
		secondDoc := a201PodWithResourceVersion("uid-0002", "payments-api", "rv-8", a201Spec(a201Array(a201SpecContainer("api", a201DefaultImage)), a201EmptyArray(), a201EmptyArray()), a201StatusArrays(a201Array(a201StatusContainer("api", a201ImageIDOther)), a201EmptyArray(), a201EmptyArray()))
		firstContext := a201Context(t, "2026-09-30T10:00:00Z", contract.TerminationFinished)
		secondContext := a201Context(t, "2026-09-30T11:00:00Z", contract.TerminationFinished)
		firstParsed := a201Parse(t, a201List(firstDoc), firstContext)
		secondParsed := a201Parse(t, a201List(secondDoc), secondContext)
		firstObservation := a201Normalize(t, firstParsed)
		secondObservation := a201Normalize(t, secondParsed)
		if firstObservation.Subjects[0].ResourceVersion != "rv-7" || secondObservation.Subjects[0].ResourceVersion != "rv-8" {
			t.Fatalf("resourceVersion = %q/%q, want each capture's own opaque value", firstObservation.Subjects[0].ResourceVersion, secondObservation.Subjects[0].ResourceVersion)
		}
		firstBundle, _ := a201Build(t, firstObservation, 0)
		secondBundle, _ := a201Build(t, secondObservation, 0)
		if firstBundle.Subject.UID != "uid-0001" || secondBundle.Subject.UID != "uid-0002" {
			t.Fatal("captures of different UIDs must never be mixed")
		}
		if got := firstBundle.Evidence[0].ObservedAt.UTC().Format(time.RFC3339); got != "2026-09-30T10:00:00Z" {
			t.Fatalf("first observed_at = %q", got)
		}
		if got := secondBundle.Evidence[0].ObservedAt.UTC().Format(time.RFC3339); got != "2026-09-30T11:00:00Z" {
			t.Fatalf("second observed_at = %q", got)
		}
	})

	t.Run("F08", func(t *testing.T) {
		// F08 acredits: a declared aborted/unknown capture is preserved with and
		// without verifiable progress, and a local failure invents no bundle.
		// Limit: no real list/get failure, no RBAC and no remote budget failure
		// (those belong to A2-02/A2-03/A2-04).
		document := a201CompleteDocument("uid-0001", "payments-api")
		t.Run("aborted with progress is partial", func(t *testing.T) {
			built, _ := a201BuildPipeline(t, document, a201Context(t, a201ObservedMoment, contract.TerminationAborted))
			if built.Provenance.Coverage.Termination != contract.TerminationAborted {
				t.Fatalf("termination = %q, want the declared aborted", built.Provenance.Coverage.Termination)
			}
			if built.Provenance.Completeness != contract.CompletenessPartial {
				t.Fatalf("completeness = %q, want partial with verifiable progress", built.Provenance.Completeness)
			}
			if !a201HasError(built, "ingest: sanitized-podlist-v1: byte/0: export capture was aborted") {
				t.Fatalf("errors = %v, want the aborted capture diagnostic", built.Provenance.Errors)
			}
		})
		t.Run("unknown with progress stays unknown", func(t *testing.T) {
			built, _ := a201BuildPipeline(t, document, a201Context(t, a201ObservedMoment, contract.TerminationUnknown))
			if built.Provenance.Coverage.Termination != contract.TerminationUnknown {
				t.Fatalf("termination = %q, want the declared unknown", built.Provenance.Coverage.Termination)
			}
			if built.Provenance.Completeness != contract.CompletenessUnknown {
				t.Fatalf("completeness = %q, an unknown capture is never promoted by EOF", built.Provenance.Completeness)
			}
			if !a201HasError(built, "ingest: sanitized-podlist-v1: byte/0: export capture termination is unknown") {
				t.Fatalf("errors = %v, want the unknown capture diagnostic", built.Provenance.Errors)
			}
		})
		t.Run("aborted without progress stays unknown", func(t *testing.T) {
			noProgress := a201List(a201PodWithoutStatus("uid-0001", "payments-api", "{}"))
			built, _ := a201BuildPipeline(t, noProgress, a201Context(t, a201ObservedMoment, contract.TerminationAborted))
			if built.Provenance.Completeness != contract.CompletenessUnknown {
				t.Fatalf("completeness = %q, want unknown without verifiable progress", built.Provenance.Completeness)
			}
			if len(built.Images) != 0 || len(built.Evidence) != 0 {
				t.Fatalf("images/evidence = %d/%d, want no invented observation", len(built.Images), len(built.Evidence))
			}
			if !a201HasError(built, "ingest: sanitized-podlist-v1: byte/0: export capture was aborted") {
				t.Fatalf("errors = %v, want the aborted capture diagnostic", built.Provenance.Errors)
			}
			if !a201HasWarning(built, "partial_observation", contract.WarningContradictory) {
				t.Fatalf("warnings = %+v, want the incomplete observation warning", built.Provenance.Warnings)
			}
		})
		t.Run("a local failure invents no bundle", func(t *testing.T) {
			truncated := document[:len(document)-1]
			parsed, parseErr := ingest.ParseSanitizedPodList(strings.NewReader(truncated), a201Context(t, a201ObservedMoment, contract.TerminationFinished))
			if parseErr == nil {
				t.Fatal("a truncated document must fail locally")
			}
			if parsed.Source != nil {
				t.Fatal("a local failure must leave no admitted source")
			}
			observation, normalizeErr := normalize.NormalizePodList(parsed)
			if normalizeErr == nil || !a201ObservationIsEmpty(observation) {
				t.Fatalf("normalize = %+v, err = %v; want a refusal", observation, normalizeErr)
			}
			built, _, buildErr := bundle.BuildObservation(a201ObservationInput(observation, 0))
			if buildErr == nil || !reflect.DeepEqual(built, contract.Bundle{}) {
				t.Fatalf("build = %+v, err = %v; want no invented bundle", built, buildErr)
			}
		})
	})

	t.Run("F12", func(t *testing.T) {
		// F12 remits to TestA201F12PersistenceBoundary, which runs the whole
		// marker matrix and the positive control. This subtest repeats one
		// representative vector through the same harness so the sequence itself
		// stays covered even when only this test is selected. Limit: no external
		// sanitizer and no real collector are acredited.
		for _, testCase := range a201BoundaryCases() {
			if testCase.name == "env value" {
				a201AssertBoundaryRejection(t, testCase)
				return
			}
		}
		t.Fatal("the env vector is missing from the boundary cases")
	})

	t.Run("F13", func(t *testing.T) {
		// F13 acredits: identity conflicts and scope collisions stay visible and
		// the same source with the same context produces the same bundle bytes.
		// Limit: no extension of the product proof and no invented affirmative
		// evidence.
		podOne := a201PodWithStatus("uid-0001", "payments-api",
			a201Spec(
				a201Array(a201SpecContainer("api", a201DefaultImage), a201SpecContainer("worker", a201DefaultImage)),
				a201EmptyArray(),
				a201Array(a201SpecContainer("api", a201DefaultImage)),
			),
			a201StatusArrays(
				a201Array(a201StatusContainer("api", a201ImageID), a201StatusContainer("worker", a201ImageIDOther)),
				a201EmptyArray(),
				a201Array(a201StatusContainer("api", a201ImageID)),
			),
		)
		podTwo := a201CompletePod("uid-0002", "payments-api")
		document := a201List(podOne, podTwo)
		context := a201Context(t, a201ObservedMoment, contract.TerminationFinished)

		firstParsed := a201Parse(t, document, context)
		firstObservation := a201Normalize(t, firstParsed)
		if len(firstObservation.Subjects) != 2 {
			t.Fatalf("subjects = %d, want two", len(firstObservation.Subjects))
		}
		collided, _ := a201Build(t, firstObservation, 0)
		conflicted, _ := a201Build(t, firstObservation, 1)
		if !a201HasWarning(collided, "scope_mismatch", contract.WarningContradictory) {
			t.Fatalf("collided warnings = %+v, want scope_mismatch", collided.Provenance.Warnings)
		}
		if !a201HasError(collided, "bundle: scope collision omitted") {
			t.Fatalf("collided errors = %v, want the omission error", collided.Provenance.Errors)
		}
		for _, built := range []contract.Bundle{collided, conflicted} {
			if !a201HasWarning(built, "source_conflict", contract.WarningContradictory) {
				t.Fatalf("warnings = %+v, want the visible identity conflict", built.Provenance.Warnings)
			}
		}
		// Determinism: the same bytes and the same declared context canonicalize
		// to the same artifacts.
		firstArtifacts, err := bundle.Encode(collided)
		if err != nil {
			t.Fatalf("encode: %v", err)
		}
		secondParsed := a201Parse(t, document, context)
		secondObservation := a201Normalize(t, secondParsed)
		rebuilt, _ := a201Build(t, secondObservation, 0)
		secondArtifacts, err := bundle.Encode(rebuilt)
		if err != nil {
			t.Fatalf("encode: %v", err)
		}
		if !reflect.DeepEqual(firstArtifacts, secondArtifacts) {
			t.Fatal("the same source and context must produce the same artifacts")
		}
	})

	t.Run("F15", func(t *testing.T) {
		// F15 acredits: two captures with different raw ids stay separate, each
		// with its own hash. Limit: no guaranteed digest, no exception lifecycle,
		// no history and no supersedes (those belong to A3).
		firstRaw := "sha256:" + strings.Repeat("d", 64)
		secondRaw := "sha256:" + strings.Repeat("e", 64)
		firstDoc := a201List(a201PodWithStatus("uid-0001", "payments-api",
			a201Spec(a201Array(a201SpecContainer("api", a201DefaultImage)), a201EmptyArray(), a201EmptyArray()),
			a201StatusArrays(a201Array(a201StatusContainer("api", firstRaw)), a201EmptyArray(), a201EmptyArray()),
		))
		secondDoc := a201List(a201PodWithStatus("uid-0001", "payments-api",
			a201Spec(a201Array(a201SpecContainer("api", a201DefaultImage)), a201EmptyArray(), a201EmptyArray()),
			a201StatusArrays(a201Array(a201StatusContainer("api", secondRaw)), a201EmptyArray(), a201EmptyArray()),
		))
		firstBundle, _ := a201BuildPipeline(t, firstDoc, a201Context(t, "2026-09-30T10:00:00Z", contract.TerminationFinished))
		secondBundle, _ := a201BuildPipeline(t, secondDoc, a201Context(t, "2026-09-30T18:00:00Z", contract.TerminationFinished))
		if firstBundle.Images[0].RawImageID == nil || string(*firstBundle.Images[0].RawImageID) != firstRaw {
			t.Fatalf("first raw = %v, want %q", firstBundle.Images[0].RawImageID, firstRaw)
		}
		if secondBundle.Images[0].RawImageID == nil || string(*secondBundle.Images[0].RawImageID) != secondRaw {
			t.Fatalf("second raw = %v, want %q", secondBundle.Images[0].RawImageID, secondRaw)
		}
		if *firstBundle.Evidence[0].Value == *secondBundle.Evidence[0].Value {
			t.Fatal("separate captures must keep their own observed values")
		}
		if firstBundle.Evidence[0].SourceHash == secondBundle.Evidence[0].SourceHash {
			t.Fatal("separate captures must keep their own source hashes")
		}
	})
}

// TestA201RequestedImageUnavailablePipeline is the end-to-end regression of the
// incomplete-observation path: a finished capture whose container declaration
// carries no image keeps the diagnostic, stays partial and still produces a
// valid bundle. Before the fix, the subject was reported complete with a visible
// error and the wire validator refused the whole bundle, which annulled an
// observation the contract requires to survive as incomplete.
func TestA201RequestedImageUnavailablePipeline(t *testing.T) {
	// The status arrays are explicit and empty, so the three categories are
	// observed; only the requested reference is missing.
	document := a201List(`{"apiVersion":"v1","kind":"Pod","metadata":{"uid":"uid-0001","namespace":"payments","name":"payments-api"},` +
		`"spec":{"containers":[{"name":"api"}],"initContainers":[],"ephemeralContainers":[]},` +
		`"status":{"containerStatuses":[{"name":"api","imageID":"sha256:aaaa"}],"initContainerStatuses":[],"ephemeralContainerStatuses":[]}}`)
	built, observation := a201BuildPipeline(t, document, a201Context(t, "2026-09-30T12:00:00Z", contract.TerminationFinished))
	if len(observation.Subjects) != 1 {
		t.Fatalf("subjects = %d, want 1", len(observation.Subjects))
	}
	found := false
	for _, diagnostic := range observation.Subjects[0].Diagnostics {
		if diagnostic.Code == "requested_image_unavailable" {
			found = true
		}
	}
	if !found {
		t.Fatal("the missing requested image is not preserved as a diagnostic")
	}
	if built.Provenance.Completeness != contract.CompletenessPartial {
		t.Fatalf("completeness = %q, want partial", built.Provenance.Completeness)
	}
	if len(built.Provenance.Errors) == 0 {
		t.Fatal("an incomplete result must keep its visible errors")
	}
	if built.Images[0].RequestedImage != nil {
		t.Fatalf("requested image = %v, want null when the export did not carry it", built.Images[0].RequestedImage)
	}
	if built.Images[0].RawImageID == nil || string(*built.Images[0].RawImageID) != "sha256:aaaa" {
		t.Fatalf("raw image id = %v, want the observed value preserved", built.Images[0].RawImageID)
	}
	if _, err := bundle.Encode(built); err != nil {
		t.Fatalf("the incomplete bundle must stay encodable: %v", err)
	}
}

// TestA201ScopeCollisionsPipeline detects a scope collision through the real
// pipeline: the same container name declared in the three classes must produce a
// single warning whose class list is always in canonical order, and the rest of
// the subject must survive. A hand-built DTO would not exercise the collision
// detection of the normalization stage, which is what this test covers.
func TestA201ScopeCollisionsPipeline(t *testing.T) {
	spec := a201Spec(
		a201Array(a201SpecContainer("api", a201DefaultImage), a201SpecContainer("worker", a201DefaultImage)),
		a201Array(a201SpecContainer("api", a201DefaultImage)),
		a201Array(a201SpecContainer("api", a201DefaultImage)),
	)
	status := a201StatusArrays(
		a201Array(a201StatusContainer("api", a201ImageID), a201StatusContainer("worker", a201ImageIDOther)),
		a201Array(a201StatusContainer("api", a201ImageIDOther)),
		a201Array(a201StatusContainer("api", a201ImageID)),
	)
	document := a201List(a201PodWithStatus("uid-0001", "payments-api", spec, status))
	built, _ := a201BuildPipeline(t, document, a201Context(t, a201ObservedMoment, contract.TerminationFinished))

	warnings := []contract.Warning{}
	for _, warning := range built.Provenance.Warnings {
		if warning.Code == "scope_mismatch" {
			warnings = append(warnings, warning)
		}
	}
	if len(warnings) != 1 {
		t.Fatalf("scope_mismatch warnings = %d, want exactly 1", len(warnings))
	}
	if warnings[0].Message != "scope collision across container classes: regular, init, ephemeral" {
		t.Fatalf("warning message = %q, want the canonical class order", warnings[0].Message)
	}
	if warnings[0].Class != contract.WarningContradictory {
		t.Fatalf("warning class = %q, want contradictory", warnings[0].Class)
	}
	// Only the collided key is omitted; the unrelated container survives.
	if len(built.Images) != 1 || string(built.Images[0].ContainerName) != "worker" {
		t.Fatalf("images = %+v, want only the non-collided container", built.Images)
	}
	if !a201HasError(built, "bundle: scope collision omitted") {
		t.Fatalf("errors = %v, want the visible omission", built.Provenance.Errors)
	}
	if built.Provenance.Completeness != contract.CompletenessPartial {
		t.Fatalf("completeness = %q, want partial", built.Provenance.Completeness)
	}
}
