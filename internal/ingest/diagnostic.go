package ingest

import "strconv"

// Reason is the sanitized, allowlisted diagnostic vocabulary of the prisma-v1
// parser (ADR-0008 D4). Values are literals from the program, never input data.
type Reason string

const (
	ReasonInvalidInput          Reason = "invalid input"
	ReasonInvalidHeader         Reason = "invalid header"
	ReasonUnknownSelector       Reason = "unknown selector"
	ReasonDuplicateColumn       Reason = "duplicate column"
	ReasonMissingRequiredColumn Reason = "missing required column"
	ReasonInvalidCSV            Reason = "invalid CSV structure"
	ReasonReadFailure           Reason = "input read failed"
	ReasonFileLimit             Reason = "file byte limit exceeded"
	ReasonRecordLimit           Reason = "record byte limit exceeded"
	ReasonDataRecordLimit       Reason = "data record limit exceeded"
	ReasonFieldLimit            Reason = "field byte limit exceeded"
	ReasonFieldCountLimit       Reason = "field count limit exceeded"
	ReasonFieldCount            Reason = "unexpected field count"
	ReasonBOM                   Reason = "BOM is not allowed"
	ReasonNUL                   Reason = "NUL is not allowed"
	ReasonInvalidUTF8           Reason = "invalid UTF-8"
	ReasonForbiddenText         Reason = "forbidden text character"
	ReasonUnsupportedVersion    Reason = "unsupported schema version"
	ReasonInvalidVersion        Reason = "invalid schema version"
	ReasonRequiredValue         Reason = "required value is empty"
	ReasonInvalidCVE            Reason = "invalid vulnerability ID"
	ReasonInvalidDate           Reason = "invalid date"
)

func (r Reason) message() string {
	switch r {
	case ReasonInvalidInput, ReasonInvalidHeader, ReasonUnknownSelector,
		ReasonDuplicateColumn, ReasonMissingRequiredColumn, ReasonInvalidCSV,
		ReasonReadFailure, ReasonFileLimit, ReasonRecordLimit,
		ReasonDataRecordLimit, ReasonFieldLimit, ReasonFieldCountLimit,
		ReasonFieldCount, ReasonBOM, ReasonNUL, ReasonInvalidUTF8,
		ReasonForbiddenText, ReasonUnsupportedVersion, ReasonInvalidVersion,
		ReasonRequiredValue, ReasonInvalidCVE, ReasonInvalidDate:
		return string(r)
	default:
		return string(ReasonInvalidInput)
	}
}

// Locator identifies one data record by its logical ordinal (header excluded,
// accepted and rejected records counted) and its byte interval in the input
// stream. StartByte is inclusive and EndByte exclusive; the interval covers the
// CSV syntax of the record and excludes the outer terminator.
type Locator struct {
	Record    uint64
	StartByte uint64
	EndByte   uint64
}

func (l Locator) String() string {
	return "record/" + strconv.FormatUint(l.Record, 10) +
		"/bytes/" + strconv.FormatUint(l.StartByte, 10) +
		"-" + strconv.FormatUint(l.EndByte, 10)
}

// Rejection reports one delimited data record that failed validation. The
// reason is an allowlisted literal; input values are never included.
type Rejection struct {
	Locator Locator
	Reason  Reason
}

func (r Rejection) String() string {
	return "ingest: prisma-v1: " + r.Locator.String() + ": " + r.Reason.message()
}

// FileError reports a structural failure that stopped the import. Only the
// verified stream offset and an allowlisted reason are exposed; no raw reader
// error, input value or fragment is carried.
type FileError struct {
	Offset uint64
	Reason Reason
}

func (e *FileError) Error() string {
	if e == nil {
		return "ingest: prisma-v1: byte/0: " + string(ReasonInvalidInput)
	}
	return "ingest: prisma-v1: byte/" + strconv.FormatUint(e.Offset, 10) + ": " + e.Reason.message()
}
