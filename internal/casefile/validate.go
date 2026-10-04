package casefile

import (
	"unicode"
	"unicode/utf8"
)

// Validation is fail-closed (ADR-0030 §5.2): every rule below rejects, none
// repairs. Whitespace is exactly the Unicode White_Space property, which
// unicode.IsSpace implements. Lengths of decoded values are checked before
// their content, and fields are checked in the wire order of §4.2.

func validateInput(input DecisionInput) error {
	if input.RiskDecision != DecisionAccepted &&
		input.RiskDecision != DecisionDeferred &&
		input.RiskDecision != DecisionRejected {
		return problem(CodeInvalidDecision)
	}
	if err := validateActor(input.Owner); err != nil {
		return err
	}
	if err := validateActor(input.Approver); err != nil {
		return err
	}
	if err := validateRationale(input.Rationale); err != nil {
		return err
	}
	if err := validateScope(input.Scope); err != nil {
		return err
	}
	if len(input.Controls) > MaxControls {
		return problem(CodeControlLimit)
	}
	for _, control := range input.Controls {
		if len(control) > MaxControlBytes {
			return problem(CodeFieldLimit)
		}
		if !utf8.ValidString(control) {
			return problem(CodeInvalidEncoding)
		}
		if err := validateActorContent(control); err != nil {
			return problem(CodeInvalidControl)
		}
	}
	if err := validateTimestamp(input.DecidedAt); err != nil {
		return err
	}
	if input.ExpiresAt != nil {
		if err := validateTimestamp(*input.ExpiresAt); err != nil {
			return err
		}
	}
	if input.Supersedes != nil && !isSha256(*input.Supersedes) {
		return problem(CodeInvalidReference)
	}
	return nil
}

func validateActor(value string) error {
	if len(value) == 0 {
		return problem(CodeInvalidActor)
	}
	if len(value) > MaxActorBytes {
		return problem(CodeFieldLimit)
	}
	return validateActorContent(value)
}

// validateActorContent applies the shape rules of an actor — no leading or
// trailing whitespace, no control or format characters — without the actor
// length limit, which controls replace with their own.
func validateActorContent(value string) error {
	if len(value) == 0 {
		return problem(CodeInvalidActor)
	}
	if !utf8.ValidString(value) {
		return problem(CodeInvalidEncoding)
	}
	if first, _ := utf8.DecodeRuneInString(value); unicode.IsSpace(first) {
		return problem(CodeInvalidActor)
	}
	if last, _ := utf8.DecodeLastRuneInString(value); unicode.IsSpace(last) {
		return problem(CodeInvalidActor)
	}
	for _, r := range value {
		if unicode.IsControl(r) || unicode.Is(unicode.Cf, r) {
			return problem(CodeInvalidActor)
		}
	}
	return nil
}

func validateRationale(value string) error {
	if len(value) > MaxRationaleBytes {
		return problem(CodeFieldLimit)
	}
	if !utf8.ValidString(value) {
		return problem(CodeInvalidEncoding)
	}
	hasContent := false
	for _, r := range value {
		switch {
		case r == '\n' || r == '\t':
		case unicode.IsControl(r) || unicode.Is(unicode.Cf, r):
			return problem(CodeInvalidRationale)
		case !unicode.IsSpace(r):
			hasContent = true
		}
	}
	if !hasContent {
		return problem(CodeInvalidRationale)
	}
	return nil
}

func validateScope(scope Scope) error {
	if !isSha256(scope.BundleHash) {
		return problem(CodeInvalidReference)
	}
	if err := validateIdentifier(scope.SubjectUID, MaxSubjectUIDBytes); err != nil {
		return err
	}
	if err := validateIdentifier(scope.ContainerName, MaxContainerNameBytes); err != nil {
		return err
	}
	switch scope.ContainerClass {
	case ContainerRegular, ContainerInit, ContainerEphemeral:
	default:
		return problem(CodeInvalidScope)
	}
	if len(scope.VulnerabilityID) == 0 {
		return problem(CodeInvalidScope)
	}
	if len(scope.VulnerabilityID) > MaxVulnerabilityIDBytes {
		return problem(CodeFieldLimit)
	}
	for index := 0; index < len(scope.VulnerabilityID); index++ {
		c := scope.VulnerabilityID[index]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9':
		case index > 0 && (c == '.' || c == '_' || c == ':' || c == '-'):
		default:
			return problem(CodeInvalidScope)
		}
	}
	if scope.ResultFingerprint != nil && !isSha256(*scope.ResultFingerprint) {
		return problem(CodeInvalidReference)
	}
	return nil
}

func validateIdentifier(value string, limit int) error {
	if len(value) == 0 {
		return problem(CodeInvalidScope)
	}
	if len(value) > limit {
		return problem(CodeFieldLimit)
	}
	if !utf8.ValidString(value) {
		return problem(CodeInvalidEncoding)
	}
	for _, r := range value {
		if unicode.IsSpace(r) || unicode.IsControl(r) || unicode.Is(unicode.Cf, r) {
			return problem(CodeInvalidScope)
		}
	}
	return nil
}

// validateTimestamp checks the exact profile YYYY-MM-DDTHH:MM:SSZ: twenty
// bytes, uppercase T and Z, years 0001–9999, a proleptic Gregorian calendar
// with no leap second, and nothing else. No offset, fraction or lowercase
// variant is converted or accepted.
func validateTimestamp(value string) error {
	if len(value) != 20 {
		return problem(CodeInvalidTimestamp)
	}
	digits := func(slice string) (int, bool) {
		number := 0
		for index := 0; index < len(slice); index++ {
			c := slice[index]
			if c < '0' || c > '9' {
				return 0, false
			}
			number = number*10 + int(c-'0')
		}
		return number, true
	}
	if value[4] != '-' || value[7] != '-' || value[10] != 'T' ||
		value[13] != ':' || value[16] != ':' || value[19] != 'Z' {
		return problem(CodeInvalidTimestamp)
	}
	year, ok := digits(value[0:4])
	if !ok || year < 1 {
		return problem(CodeInvalidTimestamp)
	}
	month, ok := digits(value[5:7])
	if !ok || month < 1 || month > 12 {
		return problem(CodeInvalidTimestamp)
	}
	day, ok := digits(value[8:10])
	if !ok {
		return problem(CodeInvalidTimestamp)
	}
	hour, ok := digits(value[11:13])
	if !ok || hour > 23 {
		return problem(CodeInvalidTimestamp)
	}
	minute, ok := digits(value[14:16])
	if !ok || minute > 59 {
		return problem(CodeInvalidTimestamp)
	}
	second, ok := digits(value[17:19])
	if !ok || second > 59 {
		return problem(CodeInvalidTimestamp)
	}
	leap := year%4 == 0 && (year%100 != 0 || year%400 == 0)
	daysInMonth := [12]int{31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31}
	if leap && month == 2 {
		daysInMonth[1] = 29
	}
	if day < 1 || day > daysInMonth[month-1] {
		return problem(CodeInvalidTimestamp)
	}
	return nil
}

// validateChain recomputes every relation of the stored chain: contiguous
// sequence, genesis null, exact predecessor link, stored hash equal to the
// recomputed hash and resolvable supersedes references. It is the same
// discipline Verify applies, so an in-memory book can never drift from an
// admitted one.
func validateChain(records []Record) error {
	for index := range records {
		record := &records[index]
		if record.Sequence != uint64(index+1) {
			return problem(CodeInvalidSequence)
		}
		if index == 0 {
			if record.PreviousHash != nil {
				return problem(CodeChainMismatch)
			}
		} else {
			if record.PreviousHash == nil || *record.PreviousHash != records[index-1].Hash {
				return problem(CodeChainMismatch)
			}
		}
		if record.Hash != recordHash(*record) {
			return problem(CodeHashMismatch)
		}
		if record.Decision.Supersedes != nil && !hashExists(records[:index], *record.Decision.Supersedes) {
			return problem(CodeInvalidReference)
		}
	}
	return nil
}
