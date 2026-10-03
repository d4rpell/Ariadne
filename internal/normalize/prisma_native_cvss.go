package normalize

import (
	"strconv"
	"strings"

	"github.com/d4rpell/Ariadne/internal/ingest"
)

// Scalar interpretation of ADR-0027 §7.1.1 (INT20), §8.2 (CVSS score) and §8.3
// (vector). These helpers return the closed interpretation states that drive the
// diagnostics, losses and limitations of §12.5.3.

// intState is the INT20 interpretation state of §7.1.1.
type intState struct {
	state string // "uninterpretable", "invalid", "valid"
	value int64
}

// interpretINT20 applies the integer grammar of §7.1.1 to a JSON number token.
func interpretINT20(token string) intState {
	if strings.ContainsAny(token, ".eE") {
		return intState{state: "uninterpretable"}
	}
	value, err := strconv.ParseInt(token, 10, 64)
	if err != nil {
		return intState{state: "invalid"}
	}
	return intState{state: "valid", value: value}
}

// scoreState is the CVSS score interpretation state of §8.2.
type scoreState struct {
	state       string // "invalid", "uninterpretable", "valid"
	deciseconds int
}

// interpretScore applies the decimal, no-sign, tenths-precision rule of §8.2.
func interpretScore(token string) scoreState {
	if token == "" {
		return scoreState{state: "invalid"}
	}
	// Only a well-formed decimal or exponent encodes a score; anything else is
	// invalid, not uninterpretable.
	for i := 0; i < len(token); i++ {
		c := token[i]
		if c != '.' && c != 'e' && c != 'E' && c != '+' && c != '-' && !(c >= '0' && c <= '9') {
			return scoreState{state: "invalid"}
		}
	}
	if strings.ContainsAny(token, "eE") {
		if !validScoreExponent(token) {
			return scoreState{state: "invalid"}
		}
		return scoreState{state: "uninterpretable"}
	}
	if token[0] == '-' || token[0] == '+' {
		return scoreState{state: "invalid"}
	}
	intPart := token
	fracPart := ""
	if dot := strings.IndexByte(token, '.'); dot >= 0 {
		intPart = token[:dot]
		fracPart = token[dot+1:]
		if fracPart == "" {
			return scoreState{state: "invalid"}
		}
	}
	if intPart == "" {
		return scoreState{state: "invalid"}
	}
	for i := 0; i < len(intPart); i++ {
		if intPart[i] < '0' || intPart[i] > '9' {
			return scoreState{state: "invalid"}
		}
	}
	if len(intPart) > 1 && intPart[0] == '0' {
		return scoreState{state: "invalid"}
	}
	for i := 0; i < len(fracPart); i++ {
		if fracPart[i] < '0' || fracPart[i] > '9' {
			return scoreState{state: "invalid"}
		}
	}
	// Extra fractional digits are accepted only when they are zeros.
	for i := 1; i < len(fracPart); i++ {
		if fracPart[i] != '0' {
			return scoreState{state: "invalid"}
		}
	}
	whole, err := strconv.Atoi(intPart)
	if err != nil || whole > 10 {
		return scoreState{state: "invalid"}
	}
	deciseconds := whole * 10
	if fracPart != "" {
		deciseconds += int(fracPart[0] - '0')
	}
	if deciseconds > 100 {
		return scoreState{state: "invalid"}
	}
	return scoreState{state: "valid", deciseconds: deciseconds}
}

// Vector interpretation states of §8.3.
const (
	vectorInvalidSyntax    = "invalid_syntax"
	vectorVersionUnknown   = "version_unknown"
	vectorSemanticsChecked = "syntax_checked_semantics_unverified"
)

var nativeVectorPrefixes = []string{"CVSS:3.0/", "CVSS:3.1/", "CVSS:4.0/"}

// interpretVector performs the limited vector checks of §8.3: exact prefix,
// non-empty metric:value segments and no repeated metric.
func interpretVector(value string) string {
	prefix := ""
	for _, candidate := range nativeVectorPrefixes {
		if strings.HasPrefix(value, candidate) {
			prefix = candidate
			break
		}
	}
	if prefix == "" {
		return vectorVersionUnknown
	}
	seen := map[string]struct{}{}
	for _, segment := range strings.Split(value[len(prefix):], "/") {
		colon := strings.IndexByte(segment, ':')
		if colon <= 0 || colon == len(segment)-1 {
			return vectorInvalidSyntax
		}
		metric := segment[:colon]
		if _, dup := seen[metric]; dup {
			return vectorInvalidSyntax
		}
		seen[metric] = struct{}{}
	}
	return vectorSemanticsChecked
}

// interpretVulnerabilityScalars walks the retained scalar members of a finding
// and applies the §12.5.3 rows for integers, CVSS score, vector and procedure
// pairs.
func interpretVulnerabilityScalars(acc *nativeAccumulator, finding ingest.NativeObject, present map[string]ingest.NativeValue) {
	if value, ok := present["cvss"]; ok {
		if num, isNum := value.(ingest.NativeNumber); isNum {
			switch st := interpretScore(num.Token); st.state {
			case "invalid":
				acc.addLoss(nativeVulnerabilityPath+"/cvss", "invalid_value", 1)
				acc.activate("values_invalid")
			case "uninterpretable":
				acc.addLoss(nativeVulnerabilityPath+"/cvss", "semantics_unverified", 1)
				acc.activate("values_uninterpretable")
			}
		}
	}
	if value, ok := present["vecStr"]; ok {
		if s, isStr := value.(ingest.NativeString); isStr && s != "" {
			switch interpretVector(string(s)) {
			case vectorInvalidSyntax:
				acc.addLoss(nativeVulnerabilityPath+"/vecStr", "invalid_value", 1)
				acc.activate("values_invalid")
			case vectorVersionUnknown, vectorSemanticsChecked:
				acc.addLoss(nativeVulnerabilityPath+"/vecStr", "semantics_unverified", 1)
				acc.activate("values_uninterpretable")
			}
		}
	}
	for _, name := range []string{"published", "fixDate"} {
		value, ok := present[name]
		if !ok {
			continue
		}
		num, isNum := value.(ingest.NativeNumber)
		if !isNum {
			continue
		}
		switch interpretINT20(num.Token).state {
		case "invalid":
			acc.addLoss(nativeVulnerabilityPath+"/"+name, "invalid_value", 1)
			acc.activate("values_invalid")
		case "uninterpretable":
			acc.addLoss(nativeVulnerabilityPath+"/"+name, "semantics_unverified", 1)
			acc.activate("values_uninterpretable")
		}
	}
	interpretProcedurePairs(acc, present)
}

// interpretProcedurePairs applies the attribute/source conflict row of §12.5.3.
func interpretProcedurePairs(acc *nativeAccumulator, present map[string]ingest.NativeValue) {
	value, ok := present["vulnerabilityDataSources"]
	if !ok {
		return
	}
	arr, isArr := value.(ingest.NativeArray)
	if !isArr {
		return
	}
	byAttribute := map[int64][]int64{}
	for _, item := range arr.Items {
		pair, isObj := item.(ingest.NativeObject)
		if !isObj {
			continue
		}
		fields := indexObject(pair)
		for _, member := range []string{"attribute", "source"} {
			v, ok := fields[member]
			if !ok {
				acc.activate("fields_incomplete")
				continue
			}
			nativePresenceValue(acc, v)
			interpretINTNode(acc, nativeVulnerabilityPath+"/vulnerabilityDataSources/[]/"+member, v, false)
		}
		attribute, aok := asValidInt(fields["attribute"])
		source, sok := asValidInt(fields["source"])
		if !aok || !sok {
			continue
		}
		byAttribute[attribute] = append(byAttribute[attribute], source)
	}
	conflicts := uint64(0)
	for _, sources := range byAttribute {
		first := sources[0]
		for _, s := range sources[1:] {
			if s != first {
				conflicts++
				break
			}
		}
	}
	if conflicts > 0 {
		acc.addLoss(nativeVulnerabilityPath+"/vulnerabilityDataSources", "semantics_unverified", conflicts)
		acc.activate("attribute_source_conflict")
	}
}

// asValidInt returns the mathematical value of a valid INT20 node.
func asValidInt(value ingest.NativeValue) (int64, bool) {
	num, ok := value.(ingest.NativeNumber)
	if !ok {
		return 0, false
	}
	st := interpretINT20(num.Token)
	return st.value, st.state == "valid"
}

// interpretINTNode applies the §12.5.3 integer rows to an INT20 node. When
// requireNonNegative is set, a valid negative value is treated as invalid (the
// count family of §7.1.1).
func interpretINTNode(acc *nativeAccumulator, path string, value ingest.NativeValue, requireNonNegative bool) {
	num, ok := value.(ingest.NativeNumber)
	if !ok {
		return
	}
	st := interpretINT20(num.Token)
	if st.state == "invalid" || (requireNonNegative && st.state == "valid" && st.value < 0) {
		acc.addLoss(path, "invalid_value", 1)
		acc.activate("values_invalid")
		return
	}
	if st.state == "uninterpretable" {
		acc.addLoss(path, "semantics_unverified", 1)
		acc.activate("values_uninterpretable")
	}
}

// validScoreExponent reports whether token is a well-formed decimal with an
// exponent (mantissa digits[.digits], exponent [+-]?digits), so a non-numeric
// string containing e/E is classified invalid rather than uninterpretable.
func validScoreExponent(token string) bool {
	i := strings.IndexAny(token, "eE")
	mantissa := token[:i]
	exp := token[i+1:]
	if exp == "" {
		return false
	}
	if exp[0] == '+' || exp[0] == '-' {
		exp = exp[1:]
	}
	if exp == "" {
		return false
	}
	for i := 0; i < len(exp); i++ {
		if exp[i] < '0' || exp[i] > '9' {
			return false
		}
	}
	if mantissa == "" {
		return false
	}
	digits := 0
	dot := false
	for i := 0; i < len(mantissa); i++ {
		c := mantissa[i]
		switch {
		case c >= '0' && c <= '9':
			digits++
		case c == '.' && !dot:
			dot = true
		default:
			return false
		}
	}
	return digits > 0
}
