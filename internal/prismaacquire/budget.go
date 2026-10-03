package prismaacquire

import "github.com/d4rpell/Ariadne/internal/ingest"

// Accumulated acquisition accounting of §7. Every guard is checked before the
// structure or counter it would exceed grows, and no consumed work is returned
// when a page is rejected.

type budget struct {
	attempts     int
	authAttempts int
	pageAttempts int
	bodyBytes    uint64
	images       uint64
	findings     uint64
	packages     uint64
	tokens       uint64
}

// reserveAttempt consumes one total HTTP attempt (§7.4). The limit (129) covers
// the authentication request and every image GET, including the terminal page.
func (b *budget) reserveAttempt() *AcquisitionError {
	if err := b.ensureAttempt(); err != nil {
		return err
	}
	b.attempts++
	return nil
}

// ensureAttempt reports whether another total attempt is available without
// consuming it, so the sequence does not wait for a request it cannot make.
func (b *budget) ensureAttempt() *AcquisitionError {
	if b.attempts >= maxTotalAttempts {
		return acquireErr(CodeRequestLimit, PhaseRequest)
	}
	return nil
}

// reserveAuth consumes the single authentication attempt of password_exchange.
func (b *budget) reserveAuth() *AcquisitionError {
	if b.authAttempts >= maxAuthAttempts {
		return acquireErr(CodeInternalInvariantFailed, PhaseAuth)
	}
	b.authAttempts++
	return nil
}

// reservePage consumes one image GET attempt (§7.4). The terminal empty page is
// also counted.
func (b *budget) reservePage() *AcquisitionError {
	if err := b.ensurePage(); err != nil {
		return err
	}
	b.pageAttempts++
	return nil
}

// ensurePage reports whether another image GET is available without consuming
// it (§8.14 step 7).
func (b *budget) ensurePage() *AcquisitionError {
	if b.pageAttempts >= maxImageGETAttempts {
		return acquireErr(CodePageLimit, PhasePagination)
	}
	return nil
}

// addBody adds read body bytes to the accumulated counter (§7.5).
func (b *budget) addBody(n uint64) { b.bodyBytes += n }

// bodyRemaining is the accumulated body budget still available.
func (b *budget) bodyRemaining() uint64 {
	if b.bodyBytes >= maxAccumulatedBodyBytes {
		return 0
	}
	return maxAccumulatedBodyBytes - b.bodyBytes
}

// imageRemaining, findingRemaining and packageRemaining return the accumulated
// occurrence budget still available.
func (b *budget) imageRemaining() uint64 {
	if b.images >= maxImageOccurrences {
		return 0
	}
	return maxImageOccurrences - b.images
}

func (b *budget) findingRemaining() uint64 {
	if b.findings >= maxFindingOccurrences {
		return 0
	}
	return maxFindingOccurrences - b.findings
}

func (b *budget) packageRemaining() uint64 {
	if b.packages >= maxPackageOccurrences {
		return 0
	}
	return maxPackageOccurrences - b.packages
}

func (b *budget) tokenRemaining() uint64 {
	if b.tokens >= maxNativeTokens {
		return 0
	}
	return maxNativeTokens - b.tokens
}

// addDraft adds the accounting of one admitted page and reports an accumulated
// overflow with the closed budget code of §7.14.
func (b *budget) addDraft(acc ingest.NativeAccounting) *AcquisitionError {
	if b.images+acc.Images > maxImageOccurrences ||
		b.findings+acc.Findings > maxFindingOccurrences ||
		b.packages+acc.Packages > maxPackageOccurrences {
		return acquireErr(CodeObjectLimit, PhaseAdmission)
	}
	if b.tokens+acc.Tokens > maxNativeTokens {
		return acquireErr(CodeTokenLimit, PhaseAdmission)
	}
	b.images += acc.Images
	b.findings += acc.Findings
	b.packages += acc.Packages
	b.tokens += acc.Tokens
	return nil
}

// nativeBudget lowers the F1 ceilings of one admission to the accumulated
// budget still available and to the per-page image ceiling (§7.7, §8.3). The
// acquisition ceilings are active and exact: a zero remaining budget is an
// active zero ceiling, so the next element is rejected before it grows. The
// structural per-page image cap is carried separately so a page over 50 records
// is reported as page_size_exceeded, not as an accumulated object_limit.
func (b *budget) nativeBudget() ingest.NativeBudget {
	return ingest.NativeBudget{
		LimitsActive: true,
		Tokens:       b.tokenRemaining(),
		Images:       b.imageRemaining(),
		Findings:     b.findingRemaining(),
		Packages:     b.packageRemaining(),
		PageImages:   maxImagesPerPage,
	}
}
