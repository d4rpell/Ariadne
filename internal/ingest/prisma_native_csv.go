package ingest

import (
	"unicode/utf8"

	"github.com/d4rpell/Ariadne/internal/schema"
)

// Private CSV reader of ADR-0027 §4.4, §4.5 and §7.6. It admits exactly the
// closed H39 header and the Ariadne dialect (comma separator, "" quote escape,
// LF or CRLF outer terminators, no comments or auto-detection), projects each
// row into the retained columns plus redaction witnesses for the excluded ones
// and keeps raw byte offsets independent of physical lines. encoding/csv is
// deliberately not used.

type csvCell struct {
	decoded string
	rawLen  int
	start   int
}

// parsePrismaNativeCSV admits one native H39 CSV document and returns the
// derived source, or a fatal diagnostic. The original bytes are never retained.
func parsePrismaNativeCSV(data []byte, ctx NativeContext) (NativeSource, *NativeError) {
	if len(data) == 0 {
		return NativeSource{}, nativeFailure(NativeCodeInvalidHeader, NativePhaseAdmission, NativeSpaceNative, 0)
	}
	if !utf8.Valid(data) {
		return NativeSource{}, nativeFailure(NativeCodeInvalidUTF8, NativePhaseAdmission, NativeSpaceNative, 0)
	}
	if len(data) >= 3 && data[0] == 0xEF && data[1] == 0xBB && data[2] == 0xBF {
		return NativeSource{}, nativeFailure(NativeCodeInvalidHeader, NativePhaseAdmission, NativeSpaceNative, 0)
	}
	p := &csvParser{data: data}
	header, _, _, next, err := p.readRecord(false)
	if err != nil {
		return NativeSource{}, err
	}
	if err := checkH39Header(header); err != nil {
		return NativeSource{}, err
	}
	p.pos = next
	columns := schema.NativeCSVColumns()
	var records []NativeRecord
	for p.pos < len(p.data) {
		if len(records) >= schema.NativeMaxCSVDataRecords {
			return NativeSource{}, nativeFailure(NativeCodeCollectionLimit, NativePhaseAdmission, NativeSpaceNative, uint64(p.pos))
		}
		cells, recStart, recEnd, next, err := p.readRecord(true)
		if err != nil {
			return NativeSource{}, err
		}
		if len(cells) != len(columns) {
			return NativeSource{}, p.failAt(recStart, NativeCodeFieldCount)
		}
		if recEnd-recStart > schema.NativeMaxCSVRecordBytes {
			return NativeSource{}, p.fail(NativeCodeRecordLimit)
		}
		obj, err := projectCSVRow(columns, cells)
		if err != nil {
			return NativeSource{}, err
		}
		records = append(records, NativeRecord{
			Ordinal:       len(records),
			OriginLocator: NativeOriginLocator("csv", len(records), uint64(recStart), uint64(recEnd)),
			OriginStart:   uint64(recStart),
			OriginEnd:     uint64(recEnd),
			Data:          obj,
		})
		p.pos = next
	}
	return NativeSource{
		Profile: csvProfile(),
		Context: nativeContextClone(ctx),
		Input:   NativeInput{SourceAlias: ctx.SourceAlias, NativeFormat: "csv", OriginalBytes: uint64(len(data))},
		Records: records,
	}, nil
}

// checkH39Header compares the decoded header cells with the closed H39 list.
func checkH39Header(cells []csvCell) *NativeError {
	want := schema.NativeCSVHeader()
	if len(cells) != len(want) {
		return nativeFailure(NativeCodeInvalidHeader, NativePhaseAdmission, NativeSpaceNative, 0)
	}
	for i, name := range want {
		if cells[i].decoded != name {
			return nativeFailure(NativeCodeInvalidHeader, NativePhaseAdmission, NativeSpaceNative, 0)
		}
	}
	return nil
}

// projectCSVRow builds the projected data object: retained columns keep their
// decoded string (even empty), excluded columns get a redaction witness.
func projectCSVRow(columns []schema.CSVColumn, cells []csvCell) (NativeValue, *NativeError) {
	obj := NativeObject{}
	for i, col := range columns {
		cell := cells[i]
		obj.Keys = append(obj.Keys, col.Name)
		if col.Disposition == schema.NativeExcludedValue {
			if hasNUL(cell.decoded) {
				return nil, nativeFailure(NativeCodeForbiddenText, NativePhaseAdmission, NativeSpaceNative, uint64(cell.start))
			}
			if cell.decoded == "" {
				obj.Values = append(obj.Values, NativeRedacted{Kind: "empty"})
			} else {
				obj.Values = append(obj.Values, NativeRedacted{Kind: "value"})
			}
			continue
		}
		if col.MaxBytes > 0 && len(cell.decoded) > col.MaxBytes {
			return nil, nativeFailure(NativeCodeStringLimit, NativePhaseAdmission, NativeSpaceNative, uint64(cell.start))
		}
		if forbiddenConservedRune(cell.decoded, false) {
			return nil, nativeFailure(NativeCodeForbiddenText, NativePhaseAdmission, NativeSpaceNative, uint64(cell.start))
		}
		obj.Values = append(obj.Values, NativeString(cell.decoded))
	}
	return obj, nil
}

func hasNUL(value string) bool {
	for i := 0; i < len(value); i++ {
		if value[i] == 0 {
			return true
		}
	}
	return false
}

type csvParser struct {
	data []byte
	pos  int
}

func (p *csvParser) fail(code string) *NativeError {
	return nativeFailure(code, NativePhaseAdmission, NativeSpaceNative, uint64(p.pos))
}

func (p *csvParser) failAt(offset int, code string) *NativeError {
	return nativeFailure(code, NativePhaseAdmission, NativeSpaceNative, uint64(offset))
}

// readRecord reads one CSV record. When data is false the record is the header:
// offsets are ignored. It returns the cells, the record's raw interval (start
// inclusive, end exclusive, terminator excluded) and the position after the
// terminator (or EOF).
func (p *csvParser) readRecord(data bool) (cells []csvCell, recStart, recEnd, next int, err *NativeError) {
	recStart = p.pos
	for {
		if data && p.pos-recStart > schema.NativeMaxCSVRecordBytes {
			return nil, 0, 0, 0, p.failAt(recStart, NativeCodeRecordLimit)
		}
		cell, ferr := p.readField()
		if ferr != nil {
			return nil, 0, 0, 0, ferr
		}
		if len(cells) >= schema.NativeMaxCSVStructuralFields {
			return nil, 0, 0, 0, p.fail(NativeCodeFieldLimit)
		}
		cells = append(cells, cell)
		if p.pos >= len(p.data) {
			return cells, recStart, p.pos, p.pos, nil
		}
		switch p.data[p.pos] {
		case ',':
			p.pos++
			continue
		case '\n':
			recEnd = p.pos
			p.pos++
			return cells, recStart, recEnd, p.pos, nil
		case '\r':
			if p.pos+1 < len(p.data) && p.data[p.pos+1] == '\n' {
				recEnd = p.pos
				p.pos += 2
				return cells, recStart, recEnd, p.pos, nil
			}
			return nil, 0, 0, 0, p.fail(NativeCodeInvalidCSV)
		default:
			return nil, 0, 0, 0, p.fail(NativeCodeInvalidCSV)
		}
	}
}

// readField reads one CSV field, honoring the "" escape inside quoted fields.
func (p *csvParser) readField() (csvCell, *NativeError) {
	start := p.pos
	if p.pos < len(p.data) && p.data[p.pos] == '"' {
		p.pos++
		var out []byte
		for {
			if p.pos >= len(p.data) {
				return csvCell{}, p.fail(NativeCodeInvalidCSV)
			}
			if p.pos-start > schema.NativeMaxCSVFieldBytes {
				return csvCell{}, p.failAt(start, NativeCodeFieldLimit)
			}
			c := p.data[p.pos]
			if c == '"' {
				if p.pos+1 < len(p.data) && p.data[p.pos+1] == '"' {
					out = append(out, '"')
					p.pos += 2
					continue
				}
				p.pos++
				break
			}
			out = append(out, c)
			p.pos++
		}
		if p.pos < len(p.data) {
			c := p.data[p.pos]
			if c != ',' && c != '\n' && c != '\r' {
				return csvCell{}, p.fail(NativeCodeInvalidCSV)
			}
		}
		if p.pos-start > schema.NativeMaxCSVFieldBytes {
			return csvCell{}, p.failAt(start, NativeCodeFieldLimit)
		}
		return csvCell{decoded: string(out), rawLen: p.pos - start, start: start}, nil
	}
	for p.pos < len(p.data) {
		c := p.data[p.pos]
		if c == ',' || c == '\n' || c == '\r' {
			break
		}
		if c == '"' {
			return csvCell{}, p.fail(NativeCodeInvalidCSV)
		}
		p.pos++
	}
	if p.pos-start > schema.NativeMaxCSVFieldBytes {
		return csvCell{}, p.failAt(start, NativeCodeFieldLimit)
	}
	return csvCell{decoded: string(p.data[start:p.pos]), rawLen: p.pos - start, start: start}, nil
}
