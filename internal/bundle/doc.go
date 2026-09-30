// Package bundle projects one normalized input into a subject-scoped evidence
// bundle: the frozen wire of internal/evidence, the provenance claims of its
// inputs and the diagnostics of the run. Two explicit routes exist and never
// mix: Build projects one normalized prisma-v1 findings import (ADR-0012), and
// BuildObservation projects one observation subject of the sanitized PodList
// adapter (ADR-0025). A bundle built here states facts; it never carries an
// evaluation, an exploitability profile or a risk decision.
package bundle
