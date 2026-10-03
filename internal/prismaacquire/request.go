package prismaacquire

import (
	"net/http"
	"net/url"
	"strconv"
	"strings"
)

// Request construction and final guard of §§4.5, 6.5–6.6. Every request is
// built from the validated origin and the closed profile constants; the guard
// re-verifies method, authority, path, query, headers and body presence before
// the request is handed to the transport (§6.5).

const userAgent = "ariadne-prismaacquire/prisma-compute-images-api-v1"

// imageQuery builds the exact query of §4.5. The project parameter appears
// exactly once and only for project_selected; no other filter is added.
func (a *acquirer) imageQuery(offset int) url.Values {
	q := url.Values{}
	q.Set("offset", strconv.Itoa(offset))
	q.Set("limit", strconv.Itoa(pageLimit))
	q.Set("compact", "false")
	q.Set("normalizedSeverity", "false")
	q.Set("layers", "false")
	q.Set("filterBaseImage", "false")
	if a.cfg.ScopeMode == ScopeProjectSelect {
		q.Set("project", a.cfg.Project)
	}
	return q
}

// buildImageRequest builds one GET from the validated origin and the fixed
// query. The token is used only here, in the Authorization header.
func (a *acquirer) buildImageRequest(offset int) (*http.Request, *AcquisitionError) {
	raw := a.origin + imagesPath + "?" + a.imageQuery(offset).Encode()
	req, err := http.NewRequestWithContext(a.ctx, http.MethodGet, raw, nil)
	if err != nil {
		return nil, acquireErr(CodeRequestNotAllowed, PhaseRequest)
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Accept-Encoding", "identity")
	req.Header.Set("User-Agent", userAgent)
	req.Header.Set("Authorization", "Bearer "+a.token)
	return req, nil
}

// buildAuthRequest builds the single POST of password_exchange (§5.4).
func (a *acquirer) buildAuthRequest(body []byte) (*http.Request, *AcquisitionError) {
	raw := a.origin + authenticatePath
	req, err := http.NewRequestWithContext(a.ctx, http.MethodPost, raw, strings.NewReader(string(body)))
	if err != nil {
		return nil, acquireErr(CodeRequestNotAllowed, PhaseRequest)
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Accept-Encoding", "identity")
	req.Header.Set("User-Agent", userAgent)
	req.Header.Set("Content-Type", "application/json")
	return req, nil
}

// guardRequest re-verifies a built request against the closed allowlist before
// it is handed to the transport. A rejection is a local `request_not_allowed`
// and consumes no HTTP attempt (§6.5, §7.4). The guard verifies scheme,
// authority, method, path, the complete query, the mandatory header values and
// the authentication state of the sequence.
func (a *acquirer) guardRequest(req *http.Request, method, path string, bearer bool) *AcquisitionError {
	if req.URL == nil || req.URL.Scheme != "https" {
		return acquireErr(CodeRequestNotAllowed, PhaseRequest)
	}
	if req.URL.Host != a.authority {
		return acquireErr(CodeRequestNotAllowed, PhaseRequest)
	}
	if req.Method != method || req.URL.EscapedPath() != path {
		return acquireErr(CodeRequestNotAllowed, PhaseRequest)
	}
	if req.URL.Fragment != "" || req.URL.User != nil {
		return acquireErr(CodeRequestNotAllowed, PhaseRequest)
	}
	images := path == imagesPath
	if !a.allowedQuery(req.URL.Query(), images) {
		return acquireErr(CodeRequestNotAllowed, PhaseRequest)
	}
	if !a.allowedHeaders(req.Header, bearer) {
		return acquireErr(CodeRequestNotAllowed, PhaseRequest)
	}
	switch method {
	case http.MethodGet:
		if !images || !bearer {
			return acquireErr(CodeRequestNotAllowed, PhaseRequest)
		}
		if req.Body != nil {
			return acquireErr(CodeRequestNotAllowed, PhaseRequest)
		}
		if a.token == "" {
			return acquireErr(CodeRequestNotAllowed, PhaseRequest)
		}
	case http.MethodPost:
		if images || bearer {
			return acquireErr(CodeRequestNotAllowed, PhaseRequest)
		}
		if req.Body == nil || req.Header.Get("Content-Type") != "application/json" {
			return acquireErr(CodeRequestNotAllowed, PhaseRequest)
		}
		if a.cfg.AuthMode != AuthPasswordExchange || a.token != "" {
			return acquireErr(CodeRequestNotAllowed, PhaseRequest)
		}
	}
	return nil
}

// allowedQuery reports whether a query is exactly the admitted one of §4.5. For
// the images path every fixed parameter must be present exactly once with its
// fixed value, the offset must be a canonical non-negative integer and `project`
// must be present exactly once iff the scope is project_selected. The
// authentication path carries no query.
func (a *acquirer) allowedQuery(q url.Values, images bool) bool {
	if !images {
		return len(q) == 0
	}
	fixed := map[string]string{
		"limit": "50", "compact": "false", "normalizedSeverity": "false",
		"layers": "false", "filterBaseImage": "false",
	}
	for key, want := range fixed {
		values, ok := q[key]
		if !ok || len(values) != 1 || values[0] != want {
			return false
		}
	}
	offset, ok := q["offset"]
	if !ok || len(offset) != 1 || !canonicalOffset(offset[0]) {
		return false
	}
	project := a.cfg.ScopeMode == ScopeProjectSelect
	values, present := q["project"]
	if project {
		if !present || len(values) != 1 || values[0] != a.cfg.Project {
			return false
		}
	} else if present {
		return false
	}
	return len(q) == len(fixed)+1+boolToInt(project)
}

// canonicalOffset reports whether value is a canonical non-negative decimal
// integer (no leading zeros, no sign).
func canonicalOffset(value string) bool {
	if value == "" {
		return false
	}
	if value == "0" {
		return true
	}
	if value[0] == '0' {
		return false
	}
	for i := 0; i < len(value); i++ {
		if value[i] < '0' || value[i] > '9' {
			return false
		}
	}
	return true
}

func boolToInt(value bool) int {
	if value {
		return 1
	}
	return 0
}

// allowedHeaders reports whether a request carries exactly the mandatory
// headers of §6.6 with their exact values. The bearer GET must carry the exact
// Authorization value; the authentication POST must carry its Content-Type.
func (a *acquirer) allowedHeaders(h http.Header, bearer bool) bool {
	if len(h.Get("Accept")) == 0 || h.Get("Accept") != "application/json" {
		return false
	}
	if h.Get("Accept-Encoding") != "identity" {
		return false
	}
	if h.Get("User-Agent") != userAgent {
		return false
	}
	permitted := map[string]bool{
		"Accept": true, "Accept-Encoding": true, "User-Agent": true,
	}
	if bearer {
		if h.Get("Authorization") != "Bearer "+a.token || a.token == "" {
			return false
		}
		permitted["Authorization"] = true
	} else {
		if h.Get("Content-Type") != "application/json" {
			return false
		}
		permitted["Content-Type"] = true
	}
	for key, values := range h {
		if !permitted[key] || len(values) != 1 {
			return false
		}
	}
	return true
}
