package ingest

import (
	"errors"
	"io"

	"github.com/d4rpell/Ariadne/internal/schema"
	contract "github.com/d4rpell/Ariadne/pkg/evidence"
)

// Finding is one accepted prisma-v1 data record: declared source facts only. It
// carries no bundle identity, container, digest or observed timestamp.
type Finding struct {
	Locator          Locator
	SchemaVersion    string
	VulnerabilityID  string
	PackageName      string
	InstalledVersion string
	FixStatus        string
	ImageRegistry    string
	ImageRepository  string
	ImageTag         string
	PackageType      string
	PackageID        string
	Path             string
	Severity         string
	Description      string
	PublishedDate    string
	DiscoveryDate    string
}

// Result is the outcome of one import attempt: accepted findings, per-record
// rejections and the coverage and completeness the caller records in
// provenance. Coverage counters are relative to the input file, never to the
// scanner or the deployed workload.
type Result struct {
	Header       []string
	Findings     []Finding
	Rejections   []Rejection
	Coverage     contract.Coverage
	Completeness contract.Completeness
}

// ParsePrismaV1 parses one prisma-v1 CSV stream (ADR-0007). It never opens
// paths, resolves identity or emits a bundle: it delimits records, validates
// them fail-closed and reports exactly one classification per delimited record.
// A structural failure returns the verified progress together with *FileError;
// record rejections are reported in Result and do not abort the import.
func ParsePrismaV1(r io.Reader) (Result, error) {
	result := Result{
		Header:     []string{},
		Findings:   []Finding{},
		Rejections: []Rejection{},
		Coverage: contract.Coverage{
			Method:      contract.CoverageFindingsImport,
			Termination: contract.TerminationUnknown,
			Rows:        &contract.CoverageRows{},
		},
		Completeness: contract.CompletenessUnknown,
	}
	if r == nil {
		result.Coverage.Termination = contract.TerminationAborted
		return result, errors.New("ingest: prisma-v1: nil reader")
	}
	src := newSource(r)
	if src.hasBOM() {
		return abortResult(result, &FileError{Offset: 0, Reason: ReasonBOM})
	}
	header, ok, err := src.readRecord(true)
	if err != nil {
		return abortResult(result, src.fileError(err))
	}
	if !ok {
		return abortResult(result, &FileError{Offset: 0, Reason: ReasonInvalidHeader})
	}
	if header.hasLimit {
		return abortResult(result, &FileError{Offset: header.limitOffset, Reason: header.limitReason})
	}
	if offset, reason := headerTextProblem(header); reason != "" {
		return abortResult(result, &FileError{Offset: offset, Reason: reason})
	}
	indexes, fileErr := headerIndexes(header)
	if fileErr != nil {
		return abortResult(result, fileErr)
	}
	result.Header = make([]string, len(header.fields))
	for i, field := range header.fields {
		result.Header[i] = string(field)
	}

	records := uint64(0)
	for {
		if records >= uint64(schema.PrismaV1MaxDataRecords) {
			if _, more, err := src.peek(); err != nil {
				return abortResult(result, src.fileError(err))
			} else if more {
				return abortResult(result, &FileError{Offset: src.logical, Reason: ReasonDataRecordLimit})
			}
			break
		}
		record, ok, err := src.readRecord(false)
		if err != nil {
			return abortResult(result, src.fileError(err))
		}
		if !ok {
			break
		}
		records++
		locator := Locator{Record: records, StartByte: record.start, EndByte: record.end}
		if reason := rowProblem(record, indexes); reason != "" {
			result.Rejections = append(result.Rejections, Rejection{Locator: locator, Reason: reason})
			continue
		}
		result.Findings = append(result.Findings, findingFor(record, indexes, locator))
	}

	total := records
	result.Coverage.Rows.Total = &total
	result.Coverage.Rows.Accepted = uint64(len(result.Findings))
	result.Coverage.Rows.Rejected = uint64(len(result.Rejections))
	result.Coverage.Termination = contract.TerminationFinished
	if len(result.Rejections) == 0 {
		result.Completeness = contract.CompletenessComplete
	} else {
		result.Completeness = contract.CompletenessPartial
	}
	return result, nil
}

// abortResult records the verified progress before propagating a structural
// failure. Total stays unknown: a prefix is never the whole file.
func abortResult(result Result, err *FileError) (Result, error) {
	rows := result.Coverage.Rows
	rows.Accepted = uint64(len(result.Findings))
	rows.Rejected = uint64(len(result.Rejections))
	rows.Total = nil
	result.Coverage.Termination = contract.TerminationAborted
	if rows.Accepted+rows.Rejected > 0 {
		result.Completeness = contract.CompletenessPartial
	} else {
		result.Completeness = contract.CompletenessUnknown
	}
	return result, err
}

// findingFor maps one accepted record onto its canonical columns. Omitted
// optional columns and empty cells both stay as the empty, not-informanted
// value; nothing is inferred from other fields.
func findingFor(record rawRecord, indexes []int, locator Locator) Finding {
	finding := Finding{Locator: locator}
	for i, canonical := range indexes {
		value := string(record.fields[i])
		switch canonical {
		case 0:
			finding.SchemaVersion = value
		case 1:
			finding.VulnerabilityID = value
		case 2:
			finding.PackageName = value
		case 3:
			finding.InstalledVersion = value
		case 4:
			finding.FixStatus = value
		case 5:
			finding.ImageRegistry = value
		case 6:
			finding.ImageRepository = value
		case 7:
			finding.ImageTag = value
		case 8:
			finding.PackageType = value
		case 9:
			finding.PackageID = value
		case 10:
			finding.Path = value
		case 11:
			finding.Severity = value
		case 12:
			finding.Description = value
		case 13:
			finding.PublishedDate = value
		case 14:
			finding.DiscoveryDate = value
		}
	}
	return finding
}
