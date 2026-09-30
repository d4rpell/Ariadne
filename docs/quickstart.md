# Quickstart

Run the offline CLI over a synthetic evidence bundle: evaluate it, render a
report, and replay the evaluation to verify the result fingerprint. Everything
runs locally on repository data — no cluster, no scanner account, no network.

**Status: PRE-ALPHA.** The CLI implements three commands over an existing
canonical bundle: `evaluate`, `report` and `verify`. There is no `import`,
`normalize` or `diff` yet, and no release. See [what this does not
do](#what-this-does-not-do) before reading the outputs as product claims.

## Requirements

- Go 1.23.4 or newer.
- A clone of this repository. Nothing else: the build is offline and the
  walkthrough uses the fixtures already in the tree.

## Build

From the repository root:

```bash
go build -o ariadne ./cmd/ariadne
```

On Windows the output is `ariadne.exe`; adjust the invocation accordingly
(`go build -o ariadne.exe ./cmd/ariadne`, then `.\ariadne`).

The binary has no configuration file, no environment variables and no implicit
files. Every flag shown below is required; paths are read relative to the
current directory.

## Step 1 — evaluate a bundle

Evaluation takes three inputs: the canonical bundle, the declarative rule pack
and an explicit context that names the evaluation target, the admission policy
and the domain policy. For fixture `F09-unmapped-redhat-package`:

```bash
./ariadne evaluate \
  --bundle fixtures/F09-unmapped-redhat-package/0.2/input/bundle.json \
  --bundle-hash sha256:37e7a55d6b3f2b5511995bbf1ef6d0c6d4c60ecd1f4cf851448beb8ae1489aff \
  --pack fixtures/F09-unmapped-redhat-package/0.2/input/pack.json \
  --context examples/synthetic-case/f09.context.json
```

The output is one compact receipt, the same bytes as
[`examples/synthetic-case/f09.receipt.json`](../examples/synthetic-case/f09.receipt.json):

```json
{"bundle_hash":"sha256:37e7a55d6b3f2b5511995bbf1ef6d0c6d4c60ecd1f4cf851448beb8ae1489aff","result_fingerprint":"sha256:b76d24e39160b662286ecc0a794f6311985c9981f017bc5ad369bfbc101a1773"}
```

- `bundle_hash` is the hash projection of the bundle (ADR-0006), the value the
  caller pinned with `--bundle-hash`.
- `result_fingerprint` is SHA-256 over the exact `result` member of the JSON
  report (ADR-0023). Keep it: it is the replay reference for `verify`.

F09 carries a finding whose product-to-component mapping is missing. The
evaluation ends `under_investigation` — insufficient evidence, never
`not_affected`. That conclusion is not printed by the receipt; it appears in the
report (next step) and in the fixture’s
[README](../fixtures/F09-unmapped-redhat-package/0.2/README.md).

## Step 2 — render a report

```bash
./ariadne report \
  --bundle fixtures/F09-unmapped-redhat-package/0.2/input/bundle.json \
  --bundle-hash sha256:37e7a55d6b3f2b5511995bbf1ef6d0c6d4c60ecd1f4cf851448beb8ae1489aff \
  --pack fixtures/F09-unmapped-redhat-package/0.2/input/pack.json \
  --context examples/synthetic-case/f09.context.json \
  --format html --out report-f09.html
```

`--format` accepts `json` or `html`. The report is written to `--out`, which
must be a new file in an existing directory: the CLI never overwrites and never
creates directories, and it opens the destination only after every byte has been
computed. A transport failure while writing can still leave a partial file
behind; the failure is reported as such, and the file is neither removed nor
described as an atomic delivery (ADR-0023). Successful generation prints
nothing — exit code `0` is the signal. The JSON report is requested the same
way:

```bash
./ariadne report \
  --bundle fixtures/F09-unmapped-redhat-package/0.2/input/bundle.json \
  --bundle-hash sha256:37e7a55d6b3f2b5511995bbf1ef6d0c6d4c60ecd1f4cf851448beb8ae1489aff \
  --pack fixtures/F09-unmapped-redhat-package/0.2/input/pack.json \
  --context examples/synthetic-case/f09.context.json \
  --format json --out report-f09.json
```

The JSON report is the machine-readable presentation: the technical status, the
exploitability layer, `risk_decision: null` (no human decision is recorded or
inferred), the rules that fired, and the evidence catalogue resolved from the
bundle. The HTML report is the same content for humans. Both are deterministic:
the same bundle, pack and context produce the same bytes.

> Report distribution is not authorized in pre-alpha. These files are local
> output, not deliverables to share.

## Step 3 — verify the replay

```bash
./ariadne verify \
  --bundle fixtures/F09-unmapped-redhat-package/0.2/input/bundle.json \
  --bundle-hash sha256:37e7a55d6b3f2b5511995bbf1ef6d0c6d4c60ecd1f4cf851448beb8ae1489aff \
  --pack fixtures/F09-unmapped-redhat-package/0.2/input/pack.json \
  --context examples/synthetic-case/f09.context.json \
  --result-fingerprint sha256:b76d24e39160b662286ecc0a794f6311985c9981f017bc5ad369bfbc101a1773
```

Success is exactly `verified` on stdout. `verify` recomputes the bundle hash
projection, repeats pack admission and evaluation with the same context, and
compares the result fingerprint with the reference you pass. A change to the
bundle or pack that alters what is hashed, or that changes the evaluation,
fails with `result_fingerprint_mismatch`, `bundle_hash_mismatch` or a pack
error on stderr, and a non-zero exit code. Operational metadata outside the
bundle hash projection can leave both hashes unchanged and is not detected
(ADR-0023); the context file is not bound by hash either, so a change that
survives the strict-JSON grammar with the same meaning (for example trailing
whitespace) may still verify, and only a change that alters the evaluated
result changes the fingerprint and fails the replay.

Replay is valid only under the same engine, profile and presentation semantics
(ADR-0023). The hash proves integrity of these bytes, not authenticity of their
origin, and the fingerprint is not a signature.

## Step 4 — try the other cases

Two more fixtures ship with precomposed contexts and captured receipts in
[`examples/synthetic-case/`](../examples/synthetic-case/):

| Fixture | What it shows | Expected outcome |
|---|---|---|
| `F10-redhat-backport` | Vendor proof, artifact inspection and mapping present | `fixed` |
| `F13-contradictory-evidence` | Two affirmative rules with conflicting evidence | `under_investigation` (conflict is never resolved by rule order) |

Run them with the same three commands, substituting the paths, the bundle hash
from `fixtures/<name>/0.2/expected/bundle.sha256` and the context file. Compare
your receipts with the published ones: `evaluate` must reproduce them byte for
byte.

## Errors and exit codes

Errors go to stderr as one compact JSON line, with no paths or input values:

```text
{"error":{"stage":"bundle_read","code":"not_found","message":"ariadne: not_found"}}
```

| Exit | Meaning |
|---|---|
| `0` | Completed — including an inconclusive (`under_investigation`) or `affected` result |
| `2` | Argument error |
| `3` | Malformed input, resource limit, or rejected evaluation or pack admission |
| `4` | File or stream transport error (missing file, permissions, timeout) |
| `5` | Bundle hash, pack hash or replay fingerprint mismatch |
| `6` | Renderer or internal consistency failure |

Run `./ariadne --help` for the exact usage; the help text is frozen by tests.

## What this does not do

- **No `import`.** The CLI does not read scanner CSVs, `kubectl`/`oc` exports or
  SBOMs yet. It consumes a canonical evidence bundle, which today is produced by
  the library layer of this repository (parser, normalization, bundle build).
  The deferred subcommands return `command_deferred`.
- **No cluster access.** Nothing here connects to Kubernetes or OpenShift.
- **No exception decision.** `risk_decision` is always `null`; the exception
  record does not exist yet.
- **No exploitability conclusion by default.** F09/F10/F13 keep
  `exploitability: not_assessed`.
- **No report or bundle distribution, and no release.** Pre-alpha.
- **No authenticity from hashes.** A matching hash proves the bytes are the ones
  that were hashed, not who produced them.

Full contract: [ADR-0023](adr/ADR-0023-offline-cli-and-replay-contract.md).
Fixture coverage and limits: [`fixtures/A1-08-coverage.md`](../fixtures/A1-08-coverage.md).
Wire specification: [`docs/spec/evidence-bundle/0.2.md`](spec/evidence-bundle/0.2.md).
