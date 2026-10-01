package collector

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strconv"

	"github.com/d4rpell/Ariadne/internal/bundle"
	contract "github.com/d4rpell/Ariadne/pkg/evidence"
)

// Request construction and final guard (ADR-0026 A.2.1, A.7). The collector
// builds every path itself; the caller never supplies a route, and the
// continuation token is only ever appended as an opaque query value.

// operationSpec is the closed description of one allowed request.
type operationSpec struct {
	verb      string // "list" or "get"
	namespace contract.Namespace
	name      string // only for get
	page      uint64
	round     uint8
	cont      string // opaque continuation, list only
}

// newRequest builds the only route shapes of the profile.
func newRequest(ctx context.Context, config validatedConfig, operation operationSpec) (*http.Request, error) {
	if operation.verb != "list" && operation.verb != "get" {
		return nil, fmt.Errorf("%s", bundle.CollectionMessage(bundle.CodeRequestNotAllowed))
	}
	if !validNamespace(string(operation.namespace)) {
		return nil, fmt.Errorf("%s", bundle.CollectionMessage(bundle.CodeRequestNotAllowed))
	}
	route := listPathPrefix + url.PathEscape(string(operation.namespace)) + "/" + podsResourceSegment
	if operation.verb == "get" {
		if !validPodName(operation.name) {
			return nil, fmt.Errorf("%s", bundle.CollectionMessage(bundle.CodeRequestNotAllowed))
		}
		route += "/" + url.PathEscape(operation.name)
	}
	target := *config.endpoint
	parsed, err := url.Parse(route)
	if err != nil {
		return nil, fmt.Errorf("%s", bundle.CollectionMessage(bundle.CodeRequestNotAllowed))
	}
	target.Path = parsed.Path
	target.RawPath = ""
	if operation.verb == "list" {
		query := url.Values{}
		if operation.cont != "" {
			query.Set("continue", operation.cont)
		}
		query.Set("limit", strconv.Itoa(listPageLimit))
		target.RawQuery = query.Encode()
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, target.String(), nil)
	if err != nil {
		return nil, fmt.Errorf("%s", bundle.CollectionMessage(bundle.CodeRequestNotAllowed))
	}
	request.Header.Set("Accept", acceptHeader)
	request.Header.Set("User-Agent", userAgent)
	if config.bearer != "" {
		request.Header.Set("Authorization", "Bearer "+config.bearer)
	}
	if err := validateRequest(request, config, operation); err != nil {
		return nil, err
	}
	return request, nil
}

// validateRequest is the last guard before the transport: it re-checks method,
// scheme, authority, Host, path, query and the absence of a body against the
// operation that was planned.
func validateRequest(request *http.Request, config validatedConfig, operation operationSpec) error {
	fail := func() error {
		return fmt.Errorf("%s", bundle.CollectionMessage(bundle.CodeRequestNotAllowed))
	}
	if request == nil || request.Method != http.MethodGet {
		return fail()
	}
	if request.URL == nil || request.URL.Scheme != "https" {
		return fail()
	}
	if request.URL.Host != config.endpoint.Host || request.Host != config.endpoint.Host {
		return fail()
	}
	expectedPath := listPathPrefix + url.PathEscape(string(operation.namespace)) + "/" + podsResourceSegment
	if operation.verb == "get" {
		expectedPath += "/" + url.PathEscape(operation.name)
	}
	if request.URL.Path != expectedPath {
		return fail()
	}
	if request.URL.Fragment != "" || request.URL.User != nil {
		return fail()
	}
	if request.Body != nil {
		return fail()
	}
	switch operation.verb {
	case "list":
		query := request.URL.Query()
		if len(query) == 0 {
			return fail()
		}
		for key := range query {
			if key != "continue" && key != "limit" {
				return fail()
			}
		}
		if query.Get("limit") != strconv.Itoa(listPageLimit) || len(query["limit"]) != 1 {
			return fail()
		}
		if values := query["continue"]; len(values) > 1 {
			return fail()
		}
		if operation.cont != "" {
			if query.Get("continue") != operation.cont {
				return fail()
			}
		} else if query.Get("continue") != "" {
			return fail()
		}
	case "get":
		if request.URL.RawQuery != "" {
			return fail()
		}
	default:
		return fail()
	}
	return nil
}
