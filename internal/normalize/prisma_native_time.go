package normalize

import (
	"time"

	"github.com/d4rpell/Ariadne/internal/ingest"
)

// Temporal interpretation of ADR-0027 §9 and §12.5.4. The instant is derived
// only from a strict RFC 3339 date-time or from a valid Unix integer; the
// acquisition of a copy never rejuvenates a scan, and an out-of-range or
// uninterpretable value stays declared, not repaired.

// parseNativeInstant validates and parses a strict RFC 3339 date-time of §9.2:
// real calendar, year 0001-9999, explicit zone, at most nine fractional digits,
// seconds 00-59, offset "-00:00" rejected.
func parseNativeInstant(value string) (time.Time, bool) {
	if len(value) < 20 {
		return time.Time{}, false
	}
	if value[4] != '-' || value[7] != '-' || value[10] != 'T' || value[13] != ':' || value[16] != ':' {
		return time.Time{}, false
	}
	digits := func(s string) bool {
		for i := 0; i < len(s); i++ {
			if s[i] < '0' || s[i] > '9' {
				return false
			}
		}
		return true
	}
	if !digits(value[0:4]) || !digits(value[5:7]) || !digits(value[8:10]) ||
		!digits(value[11:13]) || !digits(value[14:16]) || !digits(value[17:19]) {
		return time.Time{}, false
	}
	year := atoi2k(value[0:4])
	month := atoi2k(value[5:7])
	day := atoi2k(value[8:10])
	hour := atoi2k(value[11:13])
	minute := atoi2k(value[14:16])
	second := atoi2k(value[17:19])
	if year < 1 || year > 9999 || month < 1 || month > 12 || hour > 23 || minute > 59 || second > 59 {
		return time.Time{}, false
	}
	if day < 1 || day > daysInMonthNative(year, month) {
		return time.Time{}, false
	}
	rest := value[19:]
	if len(rest) > 0 && rest[0] == '.' {
		i := 1
		for i < len(rest) && rest[i] >= '0' && rest[i] <= '9' {
			i++
		}
		if i == 1 || i > 10 {
			return time.Time{}, false
		}
		rest = rest[i:]
	}
	if rest == "Z" {
		return parseGoInstant(value)
	}
	if len(rest) != 6 || (rest[0] != '+' && rest[0] != '-') || rest[3] != ':' {
		return time.Time{}, false
	}
	if !digits(rest[1:3]) || !digits(rest[4:6]) {
		return time.Time{}, false
	}
	offsetHour := atoi2k(rest[1:3])
	offsetMinute := atoi2k(rest[4:6])
	if offsetHour > 23 || offsetMinute > 59 {
		return time.Time{}, false
	}
	if rest[0] == '-' && offsetHour == 0 && offsetMinute == 0 {
		return time.Time{}, false // -00:00 unknown offset
	}
	return parseGoInstant(value)
}

func atoi2k(s string) int {
	value := 0
	for i := 0; i < len(s); i++ {
		value = value*10 + int(s[i]-'0')
	}
	return value
}

func daysInMonthNative(year, month int) int {
	switch month {
	case 1, 3, 5, 7, 8, 10, 12:
		return 31
	case 4, 6, 9, 11:
		return 30
	case 2:
		if year%4 == 0 && (year%100 != 0 || year%400 == 0) {
			return 29
		}
		return 28
	}
	return 0
}

// unixInstant converts a valid Unix-seconds value to an instant, or reports
// whether it falls outside years 0001-9999.
func unixInstant(seconds int64) (time.Time, bool) {
	instant := time.Unix(seconds, 0).UTC()
	if instant.Year() < 1 || instant.Year() > 9999 {
		return time.Time{}, false
	}
	return instant, true
}

// interpretTimeNode applies the §12.5.4 rows to a JSON date-time node.
func interpretTimeNode(acc *nativeAccumulator, path string, value ingest.NativeValue) {
	s, ok := value.(ingest.NativeString)
	if !ok || s == "" {
		return
	}
	if _, valid := parseNativeInstant(string(s)); !valid {
		acc.addLoss(path, "semantics_unverified", 1)
		acc.activate("values_uninterpretable")
	}
}

// interpretUnixNode applies the §12.5.4 rows to a valid Unix integer node.
func interpretUnixNode(acc *nativeAccumulator, path string, value ingest.NativeValue) {
	num, ok := value.(ingest.NativeNumber)
	if !ok {
		return
	}
	st := interpretINT20(num.Token)
	if st.state != "valid" {
		return // the §12.5.3 integer row already applied
	}
	if st.value == 0 {
		acc.addLoss(path, "semantics_unverified", 1)
		acc.activate("values_uninterpretable")
		return
	}
	if _, ok := unixInstant(st.value); !ok {
		acc.addLoss(path, "semantics_unverified", 1)
		acc.activate("values_uninterpretable")
	}
}

// parseGoInstant parses a previously validated date-time into an instant.
func parseGoInstant(value string) (time.Time, bool) {
	instant, err := time.Parse(time.RFC3339Nano, value)
	if err != nil {
		return time.Time{}, false
	}
	return instant, true
}
