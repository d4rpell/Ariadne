# ADR-0008 — `prisma-v1` lexical and accounting precisions

- **Status**: accepted (2026-09-25)
- **Decision owner**: project owner

## Decision

Six open points of the `prisma-v1` parser were fixed, without changing the column list, the numeric limits or the wire contract:

1. **Byte accounting**: field and record limits count raw CSV bytes consumed from the stream (quotes and escaped quotes included), not decoded content. Exceeding a field or field-count limit within budget discards the remainder of that record and counts one rejection; exhausting the record or file budget aborts the read.
2. **Terminators**: CRLF and LF are accepted as the outer record terminator. An isolated CR is not a terminator: it is a non-structural control character inside the record and is rejected. CR and LF inside a correctly quoted field are preserved byte for byte.
3. **Controls**: non-structural controls win over everything else — C0 controls (except CR/LF inside a quoted field), DEL, C1 controls and Unicode format characters (`Cf`, including the zero-width space) are rejected. Tab is rejected. Formula prefixes preceded by spaces are admissible literal content.
4. **Diagnostics**: the record locator is `record/<N>/bytes/<S>-<E>` with a 1-based ordinal over data records and a half-open byte range in the original stream. Reasons come from a closed allowlist; one reason per row, first offending byte, first field in header order.
5. **Golden scope**: for the parser, “golden” means byte-for-byte Go expectations approved explicitly — no invented JSON, hash or golden files, and no fabricated bundle. A serialized form of the parser output would need its own contract.
6. **Lexical extremes**: required fields reject empty values, whitespace-only values and values with surrounding whitespace, and are never trimmed. Vulnerabilities are matched by an anchored lexical pattern; dates are real calendar dates with no chronological relation imposed between them.

## Context

The schema decision left these points to implementation, and each of them is the kind of detail that different implementations of the same specification resolve differently. A parser that trims whitespace, or that treats a lone CR as a record separator, or that counts decoded instead of raw bytes, produces different accounting and different rejections from the same input — and accounting is exactly what a reviewer checks against the file.

## Options considered

- **Decoded-length limits** (simpler to reason about, but they make the limits unreproducible from the raw file: quoting and escapes shift them).
- **CR-only terminators accepted** (permissive, but a lone CR is indistinguishable from a stray control byte and hides malformed files).
- **Trimming required identifiers** (convenient, but trimming silently merges distinct values).
- **Letting formula-prefixed values through with a marker added**: rejected — the ingestion layer preserves values and never transforms them.

## Why this was the best at the time

- Raw-byte accounting makes every limit and every rejection reproducible by an independent tool that only reads the file, which is what makes the accounting auditable.
- Rejecting non-structural controls closes the case-folding and invisible-character tricks at the door rather than trying to detect them later.
- A closed reason vocabulary means diagnostics can never leak the input value they describe, so a rejected row cannot become a data-exfiltration channel in logs or reports.
- Refusing to trim preserves the identity rule: two identifiers that differ by a space are two different identifiers, not one.

## Consequences and limits

- Some malformed-but-harmless files are rejected instead of repaired. That is intended: repairing is guessing.
- “Golden” for the parser is byte-level Go expectations; there is no serialized golden artifact for it yet, and the record says so rather than implying one exists.
- Control-character rejection applies to this input format. Other future formats will state their own rules in their own record.

## Revisit if

A legitimate producer emits files that this grammar rejects for reasons that are demonstrably safe (for example a documented BOM), or a future format needs different accounting — both are new records.
