# ADR-0023: Offline CLI and deterministic replay

- **Status:** **ratified by delegated authority of the owner on 2026-09-28, transport and filesystem choices resolved, accepted by the owner on 2026-09-28, and implemented on 2026-09-28 (F2) under a separate explicit execution authorization of the owner; the independent review of the implementation closed with no open finding (0 P0, 0 P1, 0 P2, 0 P3); no release.** The owner delegated the choice of the best available options in writing and accepted the outcome; the coordinated session applied that ratification, selected the recommended transport bounds (R-01) and the recommended filesystem and process-boundary policy (R-02), and the reduced command surface was accepted. The implementation lives in `cmd/ariadne` (`evaluate`, `report`, `verify`), covered by tests; the end-to-end binary harness and transport goldens remain a pending step, as does the owner's acceptance review of the implementation. Release, distribution of reports and bundles, and any guarantee beyond what the tests demonstrate remain unauthorized.
- **Related records:** develops ADR-0003, ADR-0004, ADR-0011, ADR-0013, ADR-0014, ADR-0015, ADR-0016, ADR-0018 and ADR-0022. No accepted record is superseded. Evidence wire versions, decision states and the evaluator and renderer APIs remain unchanged. The design CLI examples in the architecture document are replaced by this record as of its ratification.
- **Accepted scope limitation:** implementation of this record does not demonstrate the full CSV-to-case workflow; `import`, `normalize` and `diff` remain deferred and the MVP completion review must account for that gap.

## Ratified decision

Start with `evaluate`, `report` and `verify` over an existing canonical evidence bundle. Defer the CLI forms of `import` and `normalize` until their input, identity-binding and persistence contracts are decided. Defer `diff` to the governance phase targeted at 0.3, under a separate contract.

The CLI owns explicit local file access. The evaluator, rule-pack admission and report renderer remain offline components receiving in-memory inputs. `report` evaluates the supplied inputs and writes the bytes returned by the existing renderer; it does not deserialize an arbitrary saved result. Report distribution remains unauthorized.

## Context

The repository has an evidence wire specification, pack admission, an evaluator and JSON/HTML presentation. These components do not establish a persisted normalization format, an external result decoder or an automatic safe binding from CSV records to workload UIDs. Earlier CLI examples were design sketches.

An import pipeline must preserve explicit UID and container identity, full-source provenance and declared coverage. Names and tags cannot supply missing identity. A smaller initial interface avoids inventing these contracts merely to connect commands. The cost is explicit: this delivery does not demonstrate the full CSV-to-case workflow or complete every MVP acceptance criterion.

## Interface

```text
ariadne evaluate --bundle PATH --bundle-hash H --pack PATH --context PATH
ariadne report --bundle PATH --bundle-hash H --pack PATH --context PATH --format json|html --out PATH
ariadne verify --bundle PATH --bundle-hash H --pack PATH --context PATH --result-fingerprint H
```

Every displayed flag is required. Flags are case-sensitive pairs of `--name value` in any order. Duplicate or unknown flags, empty or missing values, positional arguments, `--name=value`, short flags and the `--` terminator are rejected. A value cannot start with `--`; a path such as `./--name` remains usable. The exact value `-` does not select stdin or a file. No aliases, environment configuration, implicit files, process execution, URL resolution or shell expansion exist. Root `--help` and an implemented command followed only by `--help` succeed without file access. Deferred commands return `command_deferred`.

`--bundle` accepts only the exact canonical complete envelope of bundle wire `0.2`, verified by decoding, validation and byte comparison with re-encoding. It rejects alternate representations rather than silently repairing them. `--bundle-hash` binds the existing hash projection, not the entire envelope. Pack bytes are preserved exactly. Paths appearing inside evidence are never opened.

After bounded acquisition and typed decoding, the CLI checks the existing bundle item, image, collection-element and decoded-string budgets **before** validation, copying, sorting or canonical re-encoding. It uses the evaluator's existing constants and complete field inventory, stopping on excess without overflow. Repeated values and operational metadata count; JSON member names are not model string values. Failure is `bundle_decode/input_limit`, exit 3. This protects the adapter's own canonicalization and neither replaces the evaluator's checks nor changes its API. Raw-file bounds are not a substitute for these model budgets or a measured memory bound.

The explicit context argument contains exactly `target`, `admission` and `domain`. Target carries UID, container class/name, vulnerability ID, source/hash, locator and observation time. Admission carries evaluation time, independent pack ID/hash pins, minimum version and explicit previous version/hash or null. Domain is explicit null for the legacy profile, or the existing maximum evidence age and exact source pins for the product profile. All fields are required, including nullable ones. Strict JSON rejects duplicates, unknown fields, invalid Unicode, trailing tokens and invalid types. Existing semantic validation, limits and profile combinations remain authoritative. There is no clock, pin, TTL or previous-version default.

Hashes use `sha256:` followed by 64 lowercase hexadecimal digits. Timestamps use nonzero canonical UTC RFC3339Nano with `Z`. Integers use positive decimal representation up to 2^53−1, without fractions or exponent notation. These representations do not authorize new evidence or domain semantics.

## Replay and output

`evaluate` calls the evaluator once, builds the report in memory and emits a compact receipt with exactly `bundle_hash` and `result_fingerprint`, in that order, followed by LF. It does not persist or publish a result wire format.

The fingerprint is SHA-256 over the exact JSON object value of the root `result` member produced by `report.JSON`, excluding its key and the evidence/warning catalogues. It uses the existing complete result projection of ADR-0022, including the constant `risk_decision:null`. The digest is prefixed with `sha256:`. It is neither the bundle hash nor a hash of the complete report. No report API or report bytes change.

`report` repeats evaluation with the explicit inputs and renders JSON or HTML to one required new file. JSON bytes retain no final LF; HTML retains its existing final LF. Successful report generation writes nothing to stdout or stderr.

`verify` recomputes the bundle projection hash, repeats pack admission and evaluation with the same explicit context, and compares the result fingerprint against the caller's reference. Success is exactly `verified` plus LF on stdout. A changed bundle or result fingerprint fails without a success message. It does not reacquire evidence, compare histories or reassess freshness against the current clock.

Existing deterministic unit tests do not prove that this CLI exists or that replay works across platforms. Future CLI tests must exercise the actual binary. Replay requires the same engine, profile and presentation semantics; no cross-release fingerprint compatibility is promised. Hashes do not authenticate origin or policy. A change only to operational metadata outside the bundle hash projection can preserve both hashes.

## Errors and fail-closed behavior

Handled failures use one compact JSON line on stderr with exactly this shape and key order:

```text
{"error":{"stage":"bundle_read","code":"not_found","message":"ariadne: not_found"}}
```

`message` is always `ariadne: ` followed by the static code. No paths, input values, argv, raw operating-system messages or stack traces are added. Exit codes: 0 for completed operations (including inconclusive or affected results); 2 for argument errors; 3 for malformed inputs, resource limits or rejected evaluation/admission; 4 for file/stream transport errors; 5 for bundle, pack or replay-fingerprint mismatches; 6 for renderer or internal consistency failures.

CLI codes are `invalid_arguments`, `unknown_command`, `command_deferred`, `not_found`, `permission_denied`, `invalid_file`, `read_failure`, `already_exists`, `write_failure`, `timeout`, `result_fingerprint_mismatch` and `internal_failure`, plus the existing evaluator, pack and report codes. Stages are `arguments`, `bundle_read`, `context_read`, `pack_read`, `bundle_decode`, `context_decode`, `evaluate`, `report`, `verify`, `output_write`, `stdout_write` and `internal`. Unknown internal error codes fail as `internal_failure`, never success.

Order: validate arguments; read bundle, context and pack; decode the bundle, preflight its model budgets and validate/re-encode it; decode context; run the evaluator using its existing error precedence; render/fingerprint; compare or write. File acquisition errors precede semantic evaluation errors. An empty pack file reaches `missing_pack`; a missing file is `not_found`. Output paths are opened only after all bytes are computed. Invalid input, missing files, permissions and observed IO timeouts never become favorable conclusions. Valid incomplete evidence retains its existing inconclusive semantics.

There is no built-in deadline or `--timeout`. An observed IO timeout fails with exit 4. A supervisor kill, crash or OOM cannot promise a normal CLI error record. Partial stream delivery and a broken stderr also prevent a guarantee that the complete diagnostic is received.

The runtime's default SIGPIPE behavior remains unchanged. On Unix, writing stdout or stderr to a closed pipe can terminate the process by signal before returning an error. That case does not promise exit 4, JSON diagnostics or another stderr attempt; its observed status depends on the OS and supervisor. Writers that return an error retain the handled-error contract. Adding signal handling was considered but deferred because it adds platform policy and testing to the filesystem boundary. Tests must distinguish returned writer errors from a physical closed pipe with the real binary.

## Options considered and rationale

| Choice | Alternatives and trade-offs |
|---|---|
| Three initial commands | All six require additional persistence, identity and temporal contracts. Verify alone cannot create a reference or present a case. |
| Defer import/normalize | A CSV-only validation utility does not deliver the intended case pipeline. A new binding manifest requires its own review. Existing libraries remain useful. |
| Defer semantic diff | Textual JSON diff confuses operational metadata with technical changes. Semantic diff needs temporal and identity decisions and must not imply exception invalidation. |
| Receipt plus in-memory reevaluation for reports | Persisting and decoding Result introduces a new trust boundary. Reevaluation costs bounded work but reuses existing semantics. |
| Exact result-projection fingerprint | Bundle-only verification misses evaluation changes. Repeating twice without an external reference misses deterministic changes between versions. |
| Structured static errors | Free text loses testable fields and can expose sensitive input or platform-specific diagnostics. |
| File IO in the CLI | IO in the renderer contradicts ADR-0022. A general storage package and multi-file transactions add unnecessary policy. |
| No built-in deadline | An unmeasured default invents policy. Abandoning a goroutine cannot guarantee cancellation of evaluation or OS IO. |
| Transport/presentation golden tests | A new evaluation or decision-record wire would exceed the existing scope. Automatically regenerated expectations are not independent evidence. |

This is the smallest useful replay and presentation path supported by the existing components. Its limitations must remain visible when assessing the overall MVP.

## Resource and filesystem choices (resolved by the owner on 2026-09-28)

**R-01, ratified transport bounds:** at most 128 MiB of raw bundle bytes, 256 KiB of raw context bytes and JSON nesting depth 32 for both (root object/array depth 1). The pack keeps its existing 1 MiB limit and depth 8. The CLI reads at most N+1 bytes to detect excess before decoding. All evaluator limits remain intact. The existing 64 MiB aggregate string budget is not a raw-file limit; these are new bounds approved on 2026-09-28, not inherited from the evidence contract.

Alternatives considered were a streaming decoder with model-oriented limits (higher complexity and review cost) and postponing input acquisition until measurements and policy were agreed; both were discarded. Unbounded reads were rejected. The ratified raw limit can reject an otherwise valid bundle. No measured RSS ceiling, runtime deadline or output-byte cap is claimed.

The existing admission-and-domain string budget remains **4,096 bytes jointly**, counting every occurrence under the current evaluator contract, not 4,096 bytes per part. The new raw context-file bound does not widen that budget. Tests must include inputs whose two parts fit individually but exceed the joint budget.

**R-02, ratified IO policy:** local regular input files and a new output file in an existing operator-controlled directory. Observed symlink/reparse components, device paths, UNC paths, Windows alternate streams and special files are rejected. Output is created exclusively, requesting mode 0600, without overwriting, creating directories, temporary files, deletion, fsync or rename. Windows ACL privacy is the directory owner's responsibility; a POSIX mode is not an ACL guarantee. Filesystem races, remote mounts, atomic content publication, crash durability and cross-file snapshots are not guaranteed.

Alternatives considered were a platform-specific confined handle design with stronger race and access guarantees, at greater cost, and postponing file output and retaining stdout only; both were discarded. Implementation may not silently weaken the ratified policy when a platform cannot enforce it.

Production never invokes a shell or process. An additional local import-closure test from the CLI, plus API review for process-starting functions, complements the unchanged evaluator/report boundary gate. Test harnesses may launch the binary; production may not. Static checks are not a sandbox or universal proof of purity.

## Consequences and limits

Ratification alone did not authorize implementation, commits, release or distribution: implementation required a separate explicit execution authorization from the owner, granted on 2026-09-28. The ratified contract fixed the expected behaviour, so its expectations — the exact help, error, receipt and presentation bytes — served as the reference the implementation was built against. The implementation and its tests were produced in that authorized phase; this record certifies no test result and authorizes no release or distribution. Synthetic cases are used for pre-alpha validation.

No network, collector, Secret/log/environment/ConfigMap-data acquisition, new evidence producer, arbitrary report input, persistent anti-rollback store, signature, exception decision or lifecycle is included. The CLI is not a sanitizer or access-control system. On output failure a newly created partial file may remain; it is reported as failure, not removed or described as atomic delivery.

## Revisit if

Revisit when an import/binding contract is available; the complete CSV workflow is required; interoperable Result persistence or cross-release fingerprints are needed; temporal diff or governance is introduced; measured resources challenge the ratified bounds; stronger race/ACL/path guarantees or cancellable deadlines are required; or the engine, profile, result projection or dependency boundary changes. Accepted contracts must never be silently widened to accommodate implementation convenience.
