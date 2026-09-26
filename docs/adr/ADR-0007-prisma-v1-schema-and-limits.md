# ADR-0007 — `prisma-v1` input schema and hard limits

- **Status**: accepted (2026-09-25)
- **Decision owner**: project owner

## Decision

The first input format, `prisma-v1`, is a **format defined by this project**, not a claim of compatibility with any vendor export. It accepts exactly one shape: UTF-8 CSV without BOM and without compression, comma-delimited, with an exact canonical column set and version `1.0` in every row.

Hard limits: 64 MiB per file, 100,000 data records, 32 fields per row, 64 KiB per field, 256 KiB per record. Input is rejected fail-closed: NUL bytes, invalid UTF-8, invisible format characters, duplicate or unknown columns, and out-of-schema selectors. A row that cannot be interpreted is rejected with a diagnostic, never guessed.

Accounting is per delimited record: accepted plus rejected equals total, and completeness is only claimed when the whole file was accounted for and nothing was rejected. The imported image reference (registry, repository, tag) is a **declared** reference and is never turned into a verified digest.

## Context

The tool has to ingest findings produced by a scanner, but no public specification of a vendor CSV header could be verified, and using a real export as the contract would have tied the parser to undocumented behaviour and to data it must not carry.

At the same time, the input is untrusted data: it is the first attack surface of an offline tool that runs where other tools cannot (jump hosts, air-gapped environments), and a manipulated file must not be able to force a favourable conclusion.

## Options considered

1. **Ship a parser for the vendor export as-is.** Discarded: it would promise compatibility that could not be verified, and it would make undocumented vendor behaviour the contract.
2. **Accept a permissive CSV** (auto-detected dialects, alias columns, tab or semicolon separators). Discarded: permissiveness in an untrusted-input parser multiplies ambiguity, and ambiguous rows are how wrong conclusions are born.
3. **A canonical, versioned format of our own with hard limits and fail-closed rejection** — chosen.

## Why this was the best at the time

- A format we define is a format whose columns, types, limits and failure modes are all specified, testable and reviewable.
- Fail-closed rejection converts every ambiguity into a visible diagnostic instead of a silent guess, which is the only behaviour compatible with “insufficient evidence is `unknown`, never `not affected`”.
- Hard limits bound memory and CPU on a host we do not control, and they are enforced per file, per record, per field and per row count, each with its own boundary tests.
- Keeping the image reference *declared* protects the central invariant of the evidence model: a mutable tag is not proof of content, and the parser never fabricates identity.

## Consequences and limits

- A real vendor export requires an explicit transformation step outside this parser. That is a documented cost, not a hidden one.
- Duplicated data rows count as separate occurrences; duplicated **columns** are rejected. The distinction is explicit so that accounting cannot be argued after the fact.
- Formula injection (cells starting with `=`, `+`, `-`, `@`) is preserved inert on ingestion; neutralisation is the responsibility of every CSV/XLSX exporter. Ingesting a CSV does not make it safe to open in a spreadsheet.
- The format version is checked per row and there is no automatic downgrade or reinterpretation.

## Revisit if

A verifiable public specification or a synthetic example makes a compatible adapter possible; it would be a new adapter and a new record, not a modification of this format.
