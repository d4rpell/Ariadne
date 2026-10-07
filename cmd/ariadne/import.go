package main

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/d4rpell/Ariadne/internal/bundle"
	"github.com/d4rpell/Ariadne/internal/identity"
	"github.com/d4rpell/Ariadne/internal/ingest"
	"github.com/d4rpell/Ariadne/internal/normalize"
	"github.com/d4rpell/Ariadne/internal/schema"
	contract "github.com/d4rpell/Ariadne/pkg/evidence"
)

// The CSV-to-case pipeline of ADR-0036 (task A3-09): findings CSV plus the
// explicit bindings document plus the declared observation instant produce one
// canonical evidence bundle and its three artifacts. The order follows the
// ratified shape of the other commands: reads first, then decodes, then the
// library pipeline in memory, then the artifact encoding, and only then the
// exclusive writes and the receipt. Nothing here reads a clock, a network or a
// second format: the bundle is the only persistent artifact of the pipeline.

const (
	// maxFindingsInputBytes mirrors the parser's own file bound: the CLI reads
	// the source once, hashes every byte and parses the same bytes, so the
	// transport bound and the parser bound must agree.
	maxFindingsInputBytes = int64(schema.PrismaV1MaxFileBytes)
	maxBindingsInputBytes = maxContextInputBytes

	// Declared run metadata of the import profile (ADR-0036 §4). These are
	// constants of the command, frozen by the record, never invented at run
	// time: no collector takes part in an offline import and the CLI has no
	// clock, so the run timestamps stay null.
	importCollectorVersion = "none"
	importRedactionPolicy  = "default-v1"
	importWallClock        = "none"
)

// canonicalTimestamp is the single timestamp rule of the import surface: the
// same canonical UTC spelling the context decoder enforces, rebuilt here so a
// validated instant never re-parses differently.
func canonicalTimestamp(text string) (contract.Timestamp, bool) {
	parsed, err := time.Parse(time.RFC3339Nano, text)
	if err != nil || parsed.Location() != time.UTC || parsed.Format(time.RFC3339Nano) != text {
		return contract.Timestamp{}, false
	}
	stamp, err := contract.NewTimestamp(parsed)
	if err != nil {
		return contract.Timestamp{}, false
	}
	return stamp, true
}

// runImport executes one import call end to end. argv travels because the
// declared run metadata copies it exactly; stdout receives the receipt only
// after the three artifacts are fully delivered.
func runImport(call invocation, argv []string, stdout io.Writer, cwd string) *cliError {
	findingsBytes, failure := readInput(call.value("findings"), stageFindingsRead, maxFindingsInputBytes, false, cwd)
	if failure != nil {
		return failure
	}
	bindingsBytes, failure := readInput(call.value("bindings"), stageBindingsRead, maxBindingsInputBytes, true, cwd)
	if failure != nil {
		return failure
	}

	// Phase 3: the same bytes are hashed and parsed (ADR-0012 G-2), the
	// bindings document is decoded with its own closed key sets, and only then
	// the two inputs join. A structural parser failure keeps its verified
	// progress and travels into the normalizer; a failure without progress is
	// an unusable source, never a bundle.
	sourceHash := bundle.HashSource(findingsBytes)
	parsed, parseErr := ingest.ParsePrismaV1(bytes.NewReader(findingsBytes))
	var structural *ingest.FileError
	if parseErr != nil {
		// A structural failure travels on only with verified progress: the
		// header was admitted and the record accounting is real. A failure
		// before that (BOM, unusable header) leaves nothing to evidence.
		if !errors.As(parseErr, &structural) || len(parsed.Header) == 0 {
			return newFailure(stageFindingsDecode, codeInvalidFindings)
		}
	}
	document, err := decodeBindings(bindingsBytes)
	if err != nil {
		return newFailure(stageBindingsDecode, codeInvalidBindings)
	}
	bindings, err := joinBindings(document, parsed)
	if err != nil {
		return newFailure(stageImport, codeInvalidBindings)
	}

	// Phase 4: the in-memory library pipeline. Normalize never infers identity;
	// every link came from the document. A normalization failure here can only
	// be an impossible combination the CLI already prevented: fail closed
	// instead of classifying by message.
	normalized, err := normalize.Normalize(normalize.Input{
		Import:          parsed,
		StructuralError: structural,
		Bindings:        bindings,
	})
	if err != nil {
		return newFailure(stageInternal, codeInternalFailure)
	}
	observedAt, _ := canonicalTimestamp(call.value("observed-at"))
	built, diagnostics, err := bundle.Build(bundle.Input{
		Normalized: normalized,
		Subject:    document.subject,
		Source: bundle.ImportSource{
			Path:       call.value("findings"),
			Hash:       sourceHash,
			ObservedAt: &observedAt,
		},
		Run: bundle.RunContext{
			CollectorVersion: importCollectorVersion,
			ParserVersion:    parserVersion,
			ArgvSanitized:    append([]string(nil), argv...),
			Budget: contract.Budget{
				WallClock: importWallClock,
				Requests:  0,
				Objects:   uint64(len(parsed.Findings) + len(parsed.Rejections)),
				Bytes:     uint64(len(findingsBytes)),
			},
			Consistency:     contract.ConsistencyPointObservation,
			RedactionPolicy: importRedactionPolicy,
		},
	})
	if err != nil {
		return newFailure(stageInternal, codeInternalFailure)
	}

	// Phase 5: the three artifacts are encoded and cross-checked before the
	// first byte is written. A failure here is an internal inconsistency of
	// the encoder, never a delivery problem.
	artifacts, err := bundle.Encode(built)
	if err != nil {
		return newFailure(stageInternal, codeInternalFailure)
	}

	// Phase 6: exclusive writes in the fixed order. A failure can leave a
	// partial delivery on disk; the receipt is never emitted for one, so the
	// diagnostics either reach the receipt or the failure is visible.
	if failure := writeOutput(call.value("out-envelope"), artifacts.Envelope, cwd); failure != nil {
		return failure
	}
	if failure := writeOutput(call.value("out-projection"), artifacts.HashInput, cwd); failure != nil {
		return failure
	}
	if failure := writeOutput(call.value("out-digest"), []byte(artifacts.Hash+"\n"), cwd); failure != nil {
		return failure
	}
	receipt := fmt.Sprintf(
		"{\"bundle_hash\":%q,\"rows_total\":%d,\"rows_accepted\":%d,\"rows_rejected\":%d,\"omissions\":%d,\"scope_collisions\":%d}\n",
		artifacts.Hash,
		len(parsed.Findings)+len(parsed.Rejections),
		len(parsed.Findings),
		len(parsed.Rejections),
		len(diagnostics.Omissions),
		diagnostics.CollisionCount,
	)
	return deliverStdout(stdout, receipt)
}

// joinBindings turns the decoded document into the explicit normalize input.
// Every cross-check between the document and the parsed import happens here,
// with the ratified exit path: an index that names no parsed row, a repeated
// row or a container that does not exist is a declared-input failure, not
// something the libraries guess around.
func joinBindings(document bindingsDocument, parsed ingest.Result) ([]normalize.Binding, error) {
	containers := make(map[identity.ContainerKey]identity.ImageBinding, len(document.containers))
	for _, container := range document.containers {
		containers[container.key] = container.image
	}
	seen := make(map[int]bool, len(document.links))
	bindings := make([]normalize.Binding, 0, len(document.links))
	for _, link := range document.links {
		if link.findingIndex >= len(parsed.Findings) {
			return nil, fmt.Errorf("finding_index out of range")
		}
		if seen[link.findingIndex] {
			return nil, fmt.Errorf("duplicate binding for finding_index")
		}
		seen[link.findingIndex] = true
		key := identity.ContainerKey{
			SubjectUID:     document.subject.UID,
			ContainerClass: link.containerClass,
			ContainerName:  link.containerName,
		}
		image, ok := containers[key]
		if !ok {
			return nil, fmt.Errorf("binding names an unobserved container")
		}
		bindings = append(bindings, normalize.Binding{
			FindingIndex: link.findingIndex,
			ContainerKey: key,
			Image:        image,
		})
	}
	return bindings, nil
}
