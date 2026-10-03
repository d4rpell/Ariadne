package prismaacquire

import "github.com/d4rpell/Ariadne/internal/ingest"

// Integration with the shared F1 admission of §3.3, §7.10 and §9.2. The
// connector never parses a page itself: it lowers the F1 ceilings to the
// accumulated budget still available, hands the bounded body to AdmitNativeJSON
// and maps the native diagnostic to the acquisition catalogue. No second parser
// exists.

// admitPage runs the shared admission for one page body and maps its failure.
func (a *acquirer) admitPage(body []byte) (ingest.NativeDraft, *AcquisitionError) {
	adm := ingest.NativeAdmission{
		Budget: a.budget.nativeBudget(),
		Done:   a.ctx.Done(),
	}
	draft, nativeErr := ingest.AdmitNativeJSON(body, adm)
	if nativeErr != nil {
		if ingest.IsNativeCancelled(nativeErr) {
			// The Done channel may close because the caller cancelled or because the
			// global budget expired; the connector classifies from its own state
			// rather than collapsing every closure into `cancelled` (§7.14, §11.4).
			return ingest.NativeDraft{}, a.contextFailure()
		}
		if ingest.IsNativePageSizeExceeded(nativeErr) {
			return ingest.NativeDraft{}, acquireErr(CodePageSizeExceeded, PhasePagination)
		}
		switch nativeErr.Code {
		case ingest.NativeCodeTokenLimit:
			return ingest.NativeDraft{}, acquireErr(CodeTokenLimit, PhaseAdmission)
		case ingest.NativeCodeCollectionLimit:
			return ingest.NativeDraft{}, acquireErr(CodeObjectLimit, PhaseAdmission)
		default:
			mapped := acquireErr(CodeNativeAdmissionFailed, PhaseAdmission)
			mapped.NativeCode = nativeErr.Code
			return ingest.NativeDraft{}, mapped
		}
	}
	return draft, nil
}

// pageSizeExcess reports the §8.3 page-size rule: a page of more than 50 records
// is rejected and aborts with page_size_exceeded, without being truncated.
func pageSizeExcess(records int) *AcquisitionError {
	if records > maxImagesPerPage {
		return acquireErr(CodePageSizeExceeded, PhasePagination)
	}
	return nil
}
